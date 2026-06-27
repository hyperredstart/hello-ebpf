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
#    we ADD the BPF programs' run_time_ns (kernel.bpf_stats_enabled). Counting
#    only the reader would undercount eBPF — that's the trap.
#  - Runs are interleaved and order-alternated; we report mean +/- stddev and the
#    steal time seen, so you can judge VM noise. A collector that fails to load,
#    dies, or burns no CPU is reported as a hard error — never a silent ~0%.
set -euo pipefail

INTERVAL_MS=${INTERVAL_MS:-1000}   # collection interval, both collectors
DURATION=${DURATION:-20}           # measured seconds per run
RUNS=${RUNS:-6}                    # recorded runs per operating point
WARMUP=${WARMUP:-1}                # seconds discarded before each measurement
DO_LOAD=${DO_LOAD:-1}              # also measure under a stress-ng CPU load
OUR_PROGS="arm snapshot"           # bpf prog names whose run_time_ns we sum

here="$(cd "$(dirname "$0")" && pwd)"
CLK_TCK=$(getconf CLK_TCK); NPROC=$(nproc)

die() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (eBPF + systemd accounting need it): sudo ./bench.sh"
command -v systemd-run >/dev/null || die "systemd-run not found (this harness expects systemd)"
command -v bpftool     >/dev/null || die "bpftool not found (apt install linux-tools-\$(uname -r))"
command -v python3     >/dev/null || die "python3 not found"
[ -x "$here/proc_poller" ]   || die "build first: make"
[ -x "$here/ebpf_collector" ] || die "build first: make"

# Turn on per-program run_time_ns accounting.
sysctl -wq kernel.bpf_stats_enabled=1

# Sum run_time_ns over our loaded BPF programs (0 when none are loaded).
bpf_runtime_ns() {
	bpftool prog show -j 2>/dev/null | python3 - "$OUR_PROGS" <<'PY'
import sys, json
names = set(sys.argv[1].split())
try: data = json.load(sys.stdin)
except Exception: print(0); sys.exit()
print(sum(p.get("run_time_ns", 0) for p in data if p.get("name") in names))
PY
}

cpu_ns()   { systemctl show "$1.service" -p CPUUsageNSec --value 2>/dev/null | grep -E '^[0-9]+$' || echo 0; }
stop_unit(){ systemctl stop "$1.service" >/dev/null 2>&1 || true; systemctl reset-failed "$1.service" >/dev/null 2>&1 || true; }
steal_ticks() { awk '/^cpu /{print $9; exit}' /proc/stat; }   # field 9 of the aggregate cpu line

# Measure one collector for DURATION. Echoes "<user_ns> <kernel_ns>" or "FAIL FAIL".
# (We don't `--collect`, so a unit that *fails* lingers for `journalctl -u <unit>`.)
measure() {
	local unit="$1"; shift
	local want_kern=0
	if [[ "$unit" == *ebpf* ]]; then want_kern=1; fi

	stop_unit "$unit"
	if ! systemd-run -q --unit="$unit" -p CPUAccounting=yes -- "$@" >/dev/null 2>&1; then
		echo "FAIL FAIL"; return
	fi
	sleep "$WARMUP"                                   # discard one-time load/verify cost
	if ! systemctl is-active --quiet "$unit.service"; then
		echo "FAIL FAIL"; return                     # collector died (load/arm/verifier failure)
	fi

	local u0 k0 u1 k1
	u0=$(cpu_ns "$unit"); k0=$(bpf_runtime_ns)
	sleep "$DURATION"
	u1=$(cpu_ns "$unit"); k1=$(bpf_runtime_ns)
	stop_unit "$unit"

	if (( u1 - u0 <= 0 )) || { (( want_kern )) && (( k1 - k0 <= 0 )); }; then
		echo "FAIL FAIL"; return                     # no measurable work — refuse to report a fake 0%
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
		if (( i % 2 == 1 )); then
			out=$(measure "pvb-proc-$$-$i" "$here/proc_poller"   --interval-ms "$INTERVAL_MS" --quiet); read -r p _  <<<"$out"
			out=$(measure "pvb-ebpf-$$-$i" "$here/ebpf_collector" --interval-ms "$INTERVAL_MS" --quiet); read -r e ek <<<"$out"
		else
			out=$(measure "pvb-ebpf-$$-$i" "$here/ebpf_collector" --interval-ms "$INTERVAL_MS" --quiet); read -r e ek <<<"$out"
			out=$(measure "pvb-proc-$$-$i" "$here/proc_poller"   --interval-ms "$INTERVAL_MS" --quiet); read -r p _  <<<"$out"
		fi
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
echo "host: $(uname -sr) | $NPROC CPU | interval ${INTERVAL_MS}ms | ${DURATION}s x ${RUNS} runs | warmup ${WARMUP}s"
echo "kernel.bpf_stats_enabled=1 ; overhead is % of ONE core (reader cgroup CPU; eBPF also + run_time_ns)"
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
