# Minimal eBPF (CO-RE + libbpf) example — trace every execve().
#
#   make        # build everything
#   sudo ./hello
#   make clean
#
# Requires (Ubuntu 22.04+/24.04, kernel 5.8+ with BTF):
#   sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
#                       linux-tools-common linux-tools-$(uname -r) make

CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= cc

# normalise arch for the bpf target macro (x86 / arm64)
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/arm.*/arm/')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs   libbpf 2>/dev/null || echo -lbpf)

.PHONY: all clean run
all: hello

# 1) Dump the running kernel's BTF into a C header (this is what makes it CO-RE)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 2) Compile the eBPF C into BPF bytecode (an ELF .o)
hello.bpf.o: hello.bpf.c hello.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(LIBBPF_CFLAGS) -c $< -o $@

# 3) Generate the skeleton header from the bytecode
hello.skel.h: hello.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 4) Build the user-space loader and link against libbpf
hello: hello.c hello.skel.h hello.h
	$(CC) -g -Wall $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS) -lelf -lz

run: hello
	sudo ./hello

clean:
	rm -f hello hello.bpf.o hello.skel.h vmlinux.h
