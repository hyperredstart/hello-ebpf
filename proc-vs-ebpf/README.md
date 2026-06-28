# proc-vs-eBPF — what does monitoring overhead actually cost?

The runnable benchmark behind the article **"I Measured eBPF vs /proc Monitoring
Overhead in a Lima VM."** Two collectors gather the **same** per-CPU CPU stats at
the **same** interval; we measure each collector's **own** CPU cost and compare.

- **`proc_poller`** — the usual way: every interval, `open()`/`read()`/parse
  `/proc/stat` out of text.
- **`ebpf_collector`** + **`cpustat.bpf.c`** — a **BPF timer** fires in **softirq
  context** every interval and reads the kernel's `kernel_cpustat` percpu data
  *in-kernel* into a **BPF map**; user space just drains the map. No `/proc`, no
  text parsing. The win is **cheaper per sample**, not "fewer samples" — for a
  gauge, eBPF still samples on the clock.

> This is **gauge** collection (CPU%/state you sample periodically), *not* the
> event-driven `tracepoint → ring buffer` pattern. That one is a different post.

## Run it (on the Lima dev VM)

```bash
# On the Mac (host): start + enter the dev VM (Ubuntu 24.04, kernel 6.8, BTF).
# Lima mounts your code at the SAME absolute path inside the VM (not under ~).
limactl start --name=ebpf-dev /Users/corey_lai/Documents/article/ebpf/hello-ebpf/lima-ebpf-dev.yaml
limactl shell ebpf-dev

# Inside the VM (the mount is at the host path):
cd /Users/corey_lai/Documents/article/ebpf/hello-ebpf/proc-vs-ebpf
make                       # builds proc_poller + ebpf_collector
sudo ./bench.sh            # interleaved runs -> mean±sd table

# tune it:
sudo DURATION=30 RUNS=10 INTERVAL_MS=1000 ./bench.sh
sudo apt install -y stress-ng   # enables the "@ load" row
```

Watch a single collector by hand (no benchmark):

```bash
sudo ./ebpf_collector --interval-ms 1000     # busy% from the BPF-timer snapshot
./proc_poller         --interval-ms 1000     # busy% from /proc/stat
```

## How the measurement stays fair

| Concern | What the harness does |
|---|---|
| Precision | reads each collector's **`CPUUsageNSec`** from its own transient `systemd` unit (nanoseconds), not coarse `/proc` ticks |
| **The trap** | the BPF timer runs in **softirq**, so its CPU is *not* in the reader's unit. The callback **self-times** (`bpf_ktime_get_ns`) into the map; the collector writes that cumulative ns to `--kern-ns-file` and `bench.sh` adds it to the reader's CPU. (`bpf_timer` callbacks don't update `run_time_ns`, so `bpf_stats` can't see them.) Counting only the reader would flatter eBPF |
| Equal work | both collect the same per-CPU columns (user/nice/system/idle/iowait) at the same interval |
| Noise | runs are **interleaved + order-alternated**, a warm-up window is discarded, results are **mean ± stddev**, and **steal time** is reported |
| Operating point | measured **@ idle** and **@ load** (`stress-ng`) so you can see whether the gap holds |

**Honest caveat:** this runs in a Lima VM on an Apple-Silicon Mac (arm64). A laptop
VM is a noisy place to measure sub-1%-of-a-core overhead. Treat the absolute
numbers as direction/magnitude, not production figures — which is exactly what the
article says. The relative gap (eBPF cheaper per sample) is the robust part.

## Requirements

- Linux with **BTF**, kernel **5.15+** (BPF timer) — Ubuntu 24.04 / 6.8 is fine.
- `clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config linux-tools-$(uname -r) make`
  (all preinstalled by [`../lima-ebpf-dev.yaml`](../lima-ebpf-dev.yaml)); `bpftool`
  for the build; `systemd` for the harness; `stress-ng` optional for the load row.

## Files

| File | Role |
|---|---|
| `common.h` | per-CPU sample layout, shared by kernel + user sides |
| `cpustat.bpf.c` | eBPF: BPF timer → reads `kernel_cpustat` → `samples` map |
| `ebpf_collector.c` | loads the skeleton, arms the timer, drains the map |
| `proc_poller.c` | reads + parses `/proc/stat` each interval |
| `bench.sh` | the fair-measurement harness (table output) |
| `Makefile` | `make` builds both collectors |

## Troubleshooting

- **`load failed` / verifier error** — paste the output; the most version-sensitive
  bits are `bpf_per_cpu_ptr(&kernel_cpustat)` and the `bpf_timer`. Confirm
  `/sys/kernel/btf/vmlinux` exists and the kernel is 5.15+.
- **eBPF kernel ns reads 0** — the callback self-times into `--kern-ns-file`, so 0
  usually means the timer never fired. Run `sudo PVB_VERBOSE=1 ./ebpf_collector
  --interval-ms 1000` and confirm it prints changing `busy=…%` (timer firing) and
  that arming didn't fail.

MIT/GPL per file headers — use freely.
