#!/usr/bin/env bash
# Fair /proc-vs-eBPF CPU-collection overhead benchmark.
#
# Measures each collector's OWN CPU cost while it collects the same per-CPU CPU
# stats at the same interval, then prints a comparison table. Run it on the
# Lima dev VM (or any systemd Linux with BTF). See README.md for the design.
#
#   sudo ./bench.sh
#   sudo DURATION=30 RUNS=10 INTERVAL_MS=1000 ./bench.sh   # override defaults
#
# Why this is "fair":
#  - User-space CPU of each collector is read from its own transient systemd
#    unit (CPUUsageNSec, nanosecond precision) — not coarse /proc tick sampling.
#  - The eBPF timer samples in SOFTIRQ, whose CPU is NOT in the reader's unit, so
#    the BPF callback self-times (bpf_ktime_get_ns) into the map and the collector
#    writes that cumulative ns to --kern-ns-file; we ADD it to the reader's CPU.
#    (bpf_timer callbacks don't update run_time_ns, so bpf_stats can't see them.)
#    Counting only the reader would undercount eBPF — that's the trap.
#  - Runs are interleaved and order-alternated; we report mean +/- stddev and the
#    steal time seen, so you can judge VM noise. A collector that fails to load,
#    dies, or burns no CPU is reported as a hard error — never a silent ~0%.
set -euo pipefail

INTERVAL_MS=${INTERVAL_MS:-1000}   # collection interval, both collectors
DURATION=${DURATION:-20}           # measured seconds per run
RUNS=${RUNS:-6}                    # recorded runs per operating point
WARMUP=${WARMUP:-1}                # seconds discarded before each measurement
DO_LOAD=${DO_LOAD:-1}              # also measure under a stress-ng CPU load
SCENARIO=${SCENARIO:-pids}         # pids = per-process CPU (eBPF wins) ; system = system CPU stats (~parity)

here="$(cd "$(dirname "$0")" && pwd)"
CLK_TCK=$(getconf CLK_TCK); NPROC=$(nproc)

die() { echo "ERROR: $*" >&2; exit 1; }
case "$SCENARIO" in
	pids)   PROC_BIN="$here/proc_pids";   EBPF_BIN="$here/ebpf_pids";      DESC="per-process CPU — scan /proc/<pid>/stat vs sched_switch->map" ;;
	system) PROC_BIN="$here/proc_poller"; EBPF_BIN="$here/ebpf_collector"; DESC="system CPU stats — /proc/stat vs BPF timer->map" ;;
	*) die "SCENARIO must be 'pids' or 'system'" ;;
esac
[ "$(id -u)" = 0 ] || die "run as root (eBPF + systemd accounting need it): sudo ./bench.sh"
command -v systemd-run >/dev/null || die "systemd-run not found (this harness expects systemd)"
[ -x "$PROC_BIN" ] || die "build first: make  (missing $PROC_BIN)"
[ -x "$EBPF_BIN" ] || die "build first: make  (missing $EBPF_BIN)"

cpu_ns()   { systemctl show "$1.service" -p CPUUsageNSec --value 2>/dev/null | grep -E '^[0-9]+$' || echo 0; }
# cumulative kernel-side ns the eBPF collector self-timed into its --kern-ns-file ("-" => 0, e.g. /proc)
read_kern() {
	if [ "$1" = - ]; then echo 0; return; fi
	local v; v=$(grep -E '^[0-9]+$' "$1" 2>/dev/null | tail -1) || true
	echo "${v:-0}"
}
stop_unit(){ systemctl stop "$1.service" >/dev/null 2>&1 || true; systemctl reset-failed "$1.service" >/dev/null 2>&1 || true; }
steal_ticks() { awk '/^cpu /{print $9; exit}' /proc/stat; }   # field 9 of the aggregate cpu line

# Measure one collector for DURATION. Echoes "<user_ns> <kernel_ns>" or "FAIL FAIL".
# (We don't `--collect`, so a unit that *fails* lingers for `journalctl -u <unit>`.)
measure() {
	local unit="$1" kernfile="$2"; shift 2
	local want_kern=0
	if [ "$kernfile" != - ]; then want_kern=1; fi

	stop_unit "$unit"
	if ! systemd-run -q --unit="$unit" -p CPUAccounting=yes -- "$@" >/dev/null 2>&1; then
		echo "FAIL FAIL"; echo "    └ $unit: systemd-run could not start it" >&2; return
	fi
	sleep "$WARMUP"                                   # discard one-time load/verify cost
	if ! systemctl is-active --quiet "$unit.service"; then
		echo "FAIL FAIL"
		{ echo "    └ $unit: exited during warmup — last log lines:"
		  journalctl -u "$unit.service" --no-pager -o cat 2>/dev/null | tail -6 | sed 's/^/        /' || true; } >&2
		return                                        # collector died (load/arm/verifier failure)
	fi

	local u0 k0 u1 k1
	u0=$(cpu_ns "$unit"); k0=$(read_kern "$kernfile")
	sleep "$DURATION"
	u1=$(cpu_ns "$unit"); k1=$(read_kern "$kernfile")
	stop_unit "$unit"

	if (( u1 - u0 <= 0 )) || { (( want_kern )) && (( k1 - k0 <= 0 )); }; then
		echo "FAIL FAIL"
		echo "    └ $unit: no measurable CPU (Δreader=$((u1-u0))ns Δkernel=$((k1-k0))ns) — CPUUsageNSec u0=$u0 u1=$u1" >&2
		return                                        # refuse to report a fake 0%
	fi
	echo "$(( u1 - u0 )) $(( k1 - k0 ))"
}

pct()   { awk -v ns="$1" -v d="$DURATION" 'BEGIN{ printf "%.4f", ns*100.0/(d*1e9) }'; }
stats() { awk '{x[NR]=$1; s+=$1} END{ if(NR==0){print "0 0"; exit} m=s/NR; for(i=1;i<=NR;i++) v+=(x[i]-m)^2; printf "%.4f %.4f", m, sqrt(v/NR) }'; }

# run RUNS interleaved/order-alternated pairs for one operating point.
# Sets globals: PROC_LIST, EBPF_LIST (newline lists of %), STEAL_PCT.
run_point() {
	local label="$1" i out p e ek pp ep st0 st1
	PROC_LIST=""; EBPF_LIST=""
	st0=$(steal_ticks)
	for ((i=1; i<=RUNS; i++)); do
		printf '  %-4s run %d/%d: sampling ~%ds (silent while measuring)…\n' \
			"$label" "$i" "$RUNS" "$(( (WARMUP + DURATION) * 2 ))"
		local kf; kf=$(mktemp)
		if (( i % 2 == 1 )); then
			out=$(measure "pvb-proc-$$-$i" - "$PROC_BIN" --interval-ms "$INTERVAL_MS" --quiet); read -r p _ <<<"$out"
			out=$(measure "pvb-ebpf-$$-$i" "$kf" "$EBPF_BIN" --interval-ms "$INTERVAL_MS" --quiet --kern-ns-file "$kf"); read -r e ek <<<"$out"
		else
			out=$(measure "pvb-ebpf-$$-$i" "$kf" "$EBPF_BIN" --interval-ms "$INTERVAL_MS" --quiet --kern-ns-file "$kf"); read -r e ek <<<"$out"
			out=$(measure "pvb-proc-$$-$i" - "$PROC_BIN" --interval-ms "$INTERVAL_MS" --quiet); read -r p _ <<<"$out"
		fi
		rm -f "$kf"
		if [ "$p" = FAIL ] || [ "$e" = FAIL ]; then
			die "collector failed on $label run $i — inspect: journalctl -u pvb-proc-$$-$i.service / pvb-ebpf-$$-$i.service"
		fi
		pp=$(pct "$p"); ep=$(pct "$(( e + ek ))")
		PROC_LIST+="$pp"$'\n'; EBPF_LIST+="$ep"$'\n'
		printf '  %-4s run %d/%d: /proc=%s%%  eBPF=%s%% (reader %s + kernel %s ns)\n' \
			"$label" "$i" "$RUNS" "$pp" "$ep" "$e" "$ek"
	done
	st1=$(steal_ticks)
	# Upper-bound proxy: numerator spans the whole phase (incl. warmups/teardown),
	# divisor models only the 2*RUNS measured DURATION windows.
	STEAL_PCT=$(awk -v d="$((st1-st0))" -v dur="$DURATION" -v hz="$CLK_TCK" -v np="$NPROC" -v r="$RUNS" \
		'BEGIN{ den=dur*hz*np*2*r; if(den<=0){print "0"} else printf "%.3f", d*100.0/den }')
}

ratio() { awk -v a="$1" -v b="$2" 'BEGIN{ if (b+0==0){print "n/a"} else printf "%.1fx", a/b }'; }

echo "== proc-vs-eBPF CPU-collection overhead =="
echo "scenario: $SCENARIO — $DESC"
echo "host: $(uname -sr) | $NPROC CPU | interval ${INTERVAL_MS}ms | ${DURATION}s x ${RUNS} runs | warmup ${WARMUP}s"
echo "overhead is % of ONE core (reader cgroup CPU; eBPF also + kernel-side ns)"
echo

echo "[idle] no extra load"
run_point idle
read -r PROC_IDLE_M PROC_IDLE_S <<<"$(printf '%s' "$PROC_LIST" | grep -E '^[0-9.]+$' | stats)"
read -r EBPF_IDLE_M EBPF_IDLE_S <<<"$(printf '%s' "$EBPF_LIST" | grep -E '^[0-9.]+$' | stats)"
IDLE_STEAL=$STEAL_PCT

LOAD_DONE=0
if [ "$DO_LOAD" = 1 ] && command -v stress-ng >/dev/null; then
	echo; echo "[load] stress-ng --cpu $NPROC in the background"
	stress-ng --cpu "$NPROC" >/dev/null 2>&1 &        # killed below; no --timeout race
	SPID=$!
	sleep 1
	run_point load
	kill "$SPID" >/dev/null 2>&1 || true; wait "$SPID" 2>/dev/null || true
	read -r PROC_LOAD_M PROC_LOAD_S <<<"$(printf '%s' "$PROC_LIST" | grep -E '^[0-9.]+$' | stats)"
	read -r EBPF_LOAD_M EBPF_LOAD_S <<<"$(printf '%s' "$EBPF_LIST" | grep -E '^[0-9.]+$' | stats)"
	LOAD_STEAL=$STEAL_PCT; LOAD_DONE=1
else
	echo; echo "[load] skipped (stress-ng not installed or DO_LOAD=0)"
fi

echo
echo "================ RESULTS (% of one core) ================"
printf '%-22s %-18s %-22s %-8s\n' "Operating point" "/proc (mean±sd)" "eBPF reader+kernel" "Δ"
printf '%-22s %-18s %-22s %-8s\n' "CPU overhead @ idle" \
	"${PROC_IDLE_M}±${PROC_IDLE_S}" "${EBPF_IDLE_M}±${EBPF_IDLE_S}" "$(ratio "$PROC_IDLE_M" "$EBPF_IDLE_M")"
if [ "$LOAD_DONE" = 1 ]; then
	printf '%-22s %-18s %-22s %-8s\n' "CPU overhead @ load" \
		"${PROC_LOAD_M}±${PROC_LOAD_S}" "${EBPF_LOAD_M}±${EBPF_LOAD_S}" "$(ratio "$PROC_LOAD_M" "$EBPF_LOAD_M")"
fi
echo "--------------------------------------------------------"
if [ "$LOAD_DONE" = 1 ]; then
	echo "steal (upper-bound proxy) — idle: ${IDLE_STEAL}% ; load: ${LOAD_STEAL}%"
else
	echo "steal (upper-bound proxy) — idle: ${IDLE_STEAL}%"
fi
echo "Note: numbers are this Lima VM, not a production node. If steal is non-trivial"
echo "or sd is comparable to the mean, treat the absolute figures as indicative only."
