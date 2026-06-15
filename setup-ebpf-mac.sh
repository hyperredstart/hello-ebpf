#!/usr/bin/env bash
#
# setup-ebpf-mac.sh — spin up a Linux VM on macOS for eBPF development.
#
# eBPF is a Linux kernel technology and cannot run natively on macOS.
# This launches a real Ubuntu VM (with BTF, required for CO-RE), installs
# the eBPF toolchain, and runs a quick smoke test to prove it works.
#
# Usage:
#   chmod +x setup-ebpf-mac.sh
#   ./setup-ebpf-mac.sh             # default: multipass
#   ./setup-ebpf-mac.sh multipass
#   ./setup-ebpf-mac.sh lima
#
# Works on Apple Silicon (arm64) and Intel. ~5–15 min on first run (downloads an Ubuntu image).

set -euo pipefail

PROVIDER="${1:-multipass}"
VM_NAME="ebpf-dev"

# --- commands that run INSIDE the Ubuntu VM ----------------------------------
# Quoted heredoc (<<'EOF') keeps $(uname -r) literal here; it's evaluated in the VM.
read -r -d '' VM_SETUP <<'EOF' || true
set -e
echo "[VM] kernel: $(uname -r)   arch: $(uname -m)"

echo "[VM] checking BTF (required for CO-RE)..."
if [ -r /sys/kernel/btf/vmlinux ]; then
  echo "[VM] BTF: OK"
else
  echo "[VM] BTF: MISSING — CO-RE won't work on this kernel"; exit 1
fi

echo "[VM] installing eBPF toolchain (this can take a few minutes)..."
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  clang llvm libbpf-dev libelf-dev zlib1g-dev make bpftrace git linux-tools-common
# bpftool ships per-kernel; try the exact match, fall back to generic
sudo apt-get install -y "linux-tools-$(uname -r)" || sudo apt-get install -y linux-tools-generic || true

echo "[VM] versions:"
clang --version | head -1
( bpftool version 2>/dev/null | head -1 ) || echo "[VM] note: bpftool not on PATH yet (bpftrace below still proves eBPF works)"

echo "[VM] eBPF smoke test — tracing execve() for 3s (run something in another shell to see more):"
sudo timeout 3 bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%-6d %-16s %s\n", pid, comm, str(args->filename)); }' || true

echo "[VM] ✅ eBPF dev environment is ready."
EOF
# ----------------------------------------------------------------------------

need_brew() {
  command -v brew >/dev/null 2>&1 || { echo "Homebrew not found — install it from https://brew.sh first."; exit 1; }
}

case "$PROVIDER" in
  multipass)
    need_brew
    command -v multipass >/dev/null 2>&1 || { echo "==> installing Multipass..."; brew install --cask multipass; }

    if ! multipass info "$VM_NAME" >/dev/null 2>&1; then
      echo "==> launching Ubuntu 24.04 VM '$VM_NAME' (2 CPU / 4G RAM / 20G disk)..."
      multipass launch 24.04 --name "$VM_NAME" --cpus 2 --memory 4G --disk 20G
    else
      echo "==> VM '$VM_NAME' already exists, reusing it."
    fi

    echo "==> configuring the VM..."
    multipass exec "$VM_NAME" -- bash -c "$VM_SETUP"

    cat <<NEXT

Next steps:
  Enter the VM:        multipass shell $VM_NAME
  Share this folder:   multipass mount "$PWD" $VM_NAME:/home/ubuntu/work   (edit on Mac, build in VM)
  Build the example:   cd /home/ubuntu/work/hello-ebpf && make && sudo ./hello
NEXT
    ;;

  lima)
    need_brew
    command -v limactl >/dev/null 2>&1 || { echo "==> installing Lima..."; brew install lima; }

    if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$VM_NAME"; then
      echo "==> starting Ubuntu LTS VM '$VM_NAME' (auto-mounts your home dir)..."
      limactl start --name="$VM_NAME" --tty=false template://ubuntu-lts
    else
      echo "==> VM '$VM_NAME' already exists, reusing it."
    fi

    echo "==> configuring the VM..."
    limactl shell "$VM_NAME" bash -c "$VM_SETUP"

    cat <<NEXT

Next steps:
  Enter the VM:        limactl shell $VM_NAME
  (Lima auto-mounts your home dir at the same path — just 'cd' to this project inside the VM.)
  Build the example:   cd $PWD/hello-ebpf && make && sudo ./hello
NEXT
    ;;

  *)
    echo "Unknown provider: '$PROVIDER' (use 'multipass' or 'lima')"; exit 1 ;;
esac
