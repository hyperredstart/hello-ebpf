# hello-ebpf — your first eBPF program (CO-RE + libbpf)

A minimal, runnable eBPF example that traces **every `execve()` on the machine** and prints
`PID / PPID / COMM / FILENAME` in real time. It exercises the whole pipeline the article describes:

> **C → bytecode → verifier → tracepoint hook → ring buffer → user space.**

```
hello.bpf.c   # kernel side: hooks the execve tracepoint, sends events via ring buffer
hello.c       # user side: loads + attaches the program, prints events
hello.h       # struct shared by both sides
Makefile      # vmlinux.h (BTF) -> clang -> bpftool skeleton -> link libbpf
```

---

## Requirements

- **Linux**, kernel **5.8+**, built with **BTF** (`CONFIG_DEBUG_INFO_BTF=y`) — Ubuntu 22.04/24.04 has this by default.
- Not on Linux? See **[Running on macOS](#running-on-macos-apple-silicon-or-intel)** below.

Install the toolchain (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                    linux-tools-common linux-tools-$(uname -r) make
```

Sanity-check (both should print a path / version):

```bash
ls -l /sys/kernel/btf/vmlinux      # BTF present?
bpftool version                    # bpftool available?
```

---

## Build & run

```bash
make
sudo ./hello
```

Leave it running, open **another terminal**, and run anything (`ls`, `date`, `uname -a`).
You'll see output like this:

```text
PID      PPID     COMM             FILENAME
12842    3310     bash             /usr/bin/ls
12843    3310     bash             /usr/bin/date
12844    3310     bash             /usr/bin/uname
```

> The numbers/paths will differ on your machine — that's the point: it's reading **real** events
> from the kernel as they happen. `Ctrl-C` to stop.

---

## The 60-second version (no build, instant verify)

Don't want to compile anything yet? `bpftrace` does the same thing as a one-liner:

```bash
sudo apt install -y bpftrace
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve {
    printf("%-6d %-16s %s\n", pid, comm, str(args->filename));
}'
```

Open another terminal, run `ls` — it appears instantly. Same idea, zero build. This is the fastest
way to *prove to yourself* eBPF works before diving into the C version.

---

## How to know it really worked (verification)

1. `sudo ./hello` (or the bpftrace one-liner) keeps running and prints a header.
2. In a second terminal, run a command (e.g. `ls /tmp`).
3. Within a split second, a new line for that command appears in the first terminal.

If you see your own commands show up, the eBPF program is loaded, passed the verifier, attached to
the kernel tracepoint, and is streaming events to user space. ✅

---

## Running on macOS (Apple Silicon or Intel)

eBPF is a **Linux kernel** technology — it can't run on macOS natively. Run it inside a quick Ubuntu VM
(this is the standard setup for eBPF dev on a Mac). Easiest is **Multipass**:

```bash
brew install --cask multipass
multipass launch 24.04 --name ebpf --cpus 2 --memory 2G --disk 10G
multipass transfer -r ./hello-ebpf ebpf:/home/ubuntu/   # copy this folder in
multipass shell ebpf
# --- now inside the Ubuntu VM ---
cd hello-ebpf
sudo apt update && sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                                       linux-tools-common linux-tools-$(uname -r) make
make
sudo ./hello
```

(Alternatives: **Lima**/**Colima** work the same way. Avoid Docker Desktop for this — its LinuxKit
kernel often ships without BTF, which breaks the `vmlinux.h` step.)

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `vmlinux.h` step fails / no such file | Kernel lacks BTF. Use Ubuntu 22.04+/24.04, or a VM (see above). |
| `bpftool: command not found` | `sudo apt install linux-tools-$(uname -r)` (must match `uname -r`). |
| `Failed to open/load BPF skeleton (need root?)` | Run with `sudo`. |
| `libbpf: ... permission denied` / load error | Old kernel (<5.8) — ring buffer needs 5.8+. Upgrade or use a newer VM image. |
| pkg-config can't find libbpf | `sudo apt install libbpf-dev`, or set `LIBBPF_LIBS=-lbpf`. |

---

## What to look at next

- `hello.bpf.c` — note `SEC("tracepoint/syscalls/sys_enter_execve")` (the hook) and the ring buffer.
- `hello.c` — `open_and_load` (verifier runs here) → `attach` → `ring_buffer__poll`.
- The grown-up version of this — with risk scoring — is the `execmon` post in this series.
