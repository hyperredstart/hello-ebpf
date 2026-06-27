# proc-vs-eBPF CPU-stat collection benchmark.
#
#   make                 # build proc_poller + ebpf_collector
#   sudo ./bench.sh       # run the fair comparison (see README)
#   make clean
#
# Requires (Ubuntu 24.04 / kernel 6.8 with BTF — e.g. the lima-ebpf-dev VM):
#   sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
#                       linux-tools-common linux-tools-$(uname -r) make

CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= cc

ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/arm.*/arm/')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs   libbpf 2>/dev/null || echo -lbpf)

.PHONY: all clean
all: proc_poller ebpf_collector

# --- the /proc poller (pure user space) ---
proc_poller: proc_poller.c common.h
	$(CC) -g -O2 -Wall $< -o $@

# --- the eBPF collector (CO-RE + libbpf) ---
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

cpustat.bpf.o: cpustat.bpf.c common.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(LIBBPF_CFLAGS) -c $< -o $@

cpustat.skel.h: cpustat.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

ebpf_collector: ebpf_collector.c cpustat.skel.h common.h
	$(CC) -g -O2 -Wall $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS) -lelf -lz

clean:
	rm -f proc_poller ebpf_collector cpustat.bpf.o cpustat.skel.h vmlinux.h
