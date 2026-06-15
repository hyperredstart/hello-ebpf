# eBPF Examples — for Traditional Industry & Cloud-Native

Runnable, minimal eBPF examples that accompany my hands-on eBPF article series
(which grew out of my **KubeSummit 2025** talk on using eBPF + Kubernetes to modernize
monitoring for traditional-industry ERP systems).

Everything here is **CO-RE + libbpf**, built to run on a modern Linux kernel (5.8+ with BTF).

## What's inside

| Path | What it is |
|------|------------|
| [`hello-ebpf/`](./hello-ebpf) | The "hello world" of eBPF — trace every `execve()` on the machine in real time (tracepoint → ring buffer → user space). Start here. |
| [`setup-ebpf-mac.sh`](./setup-ebpf-mac.sh) | One command to get a working eBPF dev VM on macOS (Multipass or Lima). `./setup-ebpf-mac.sh [multipass\|lima]` |

## Quick start

```bash
# On a Mac? Get a Linux VM with the toolchain + BTF, verified:
./setup-ebpf-mac.sh            # or: ./setup-ebpf-mac.sh lima

# Then, inside Linux:
cd hello-ebpf
make
sudo ./hello                   # open another shell, run `ls` — watch it appear
```

## Requirements

- Linux, kernel **5.8+**, built with **BTF** (`/sys/kernel/btf/vmlinux` exists) — Ubuntu 22.04/24.04 has this.
- Toolchain: `clang llvm libbpf-dev libelf-dev zlib1g-dev linux-tools-$(uname -r) make` (the Mac script installs these for you).

## License

MIT — use freely.
