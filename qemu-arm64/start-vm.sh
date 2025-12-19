#!/bin/bash
# Start QEMU ARM64 VM for BPF testing
#
# This script launches the ARM64 VM with:
# - 4 CPUs, 4GB RAM
# - UEFI boot
# - Virtio disk and network
# - SSH forwarding on port 2222
#
# Usage:
#   ./qemu-arm64/start-vm.sh              # Interactive mode (console)
#   ./qemu-arm64/start-vm.sh --daemon     # Background mode

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
VM_DISK="$SCRIPT_DIR/vm-disk.qcow2"
SEED_IMG="$SCRIPT_DIR/seed.img"
SSH_PORT=2222
CPUS=4
MEMORY=4096

# Find UEFI firmware
UEFI_PATHS=(
    "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"
    "/usr/share/edk2/aarch64/QEMU_EFI.fd"
    "/usr/share/AAVMF/AAVMF_CODE.fd"
    "/usr/share/qemu/edk2-aarch64-code.fd"
)

UEFI_FW=""
for path in "${UEFI_PATHS[@]}"; do
    if [[ -f "$path" ]]; then
        UEFI_FW="$path"
        break
    fi
done

if [[ -z "$UEFI_FW" ]]; then
    echo "Error: UEFI firmware not found. Install qemu-efi-aarch64 package."
    exit 1
fi

# Check if VM disk exists
if [[ ! -f "$VM_DISK" ]]; then
    echo "Error: VM disk not found: $VM_DISK"
    echo "Run ./qemu-arm64/setup-vm.sh first"
    exit 1
fi

# Parse arguments
DAEMON=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --daemon|-d)
            DAEMON=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --daemon, -d   Run VM in background"
            echo "  --help         Show this help message"
            echo ""
            echo "SSH access: ssh -p $SSH_PORT ubuntu@localhost"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "========================================"
echo "Starting QEMU ARM64 VM"
echo "========================================"
echo "CPUs: $CPUS"
echo "Memory: ${MEMORY}MB"
echo "SSH Port: $SSH_PORT"
echo "UEFI: $UEFI_FW"
echo "========================================"
echo ""

if [[ "$DAEMON" == "true" ]]; then
    echo "Starting VM in background..."
    echo "Use 'ssh -p $SSH_PORT ubuntu@localhost' to connect"
    echo "Use './qemu-arm64/stop-vm.sh' to stop"

    nohup qemu-system-aarch64 \
        -machine virt \
        -cpu cortex-a72 \
        -smp "$CPUS" \
        -m "$MEMORY" \
        -bios "$UEFI_FW" \
        -drive file="$VM_DISK",format=qcow2,if=virtio \
        -drive file="$SEED_IMG",format=raw,if=virtio \
        -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
        -device virtio-net-pci,netdev=net0 \
        -nographic \
        > "$SCRIPT_DIR/vm.log" 2>&1 &

    VM_PID=$!
    echo "$VM_PID" > "$SCRIPT_DIR/vm.pid"
    echo "VM started with PID: $VM_PID"
    echo "Log file: $SCRIPT_DIR/vm.log"
else
    echo "Starting VM in interactive mode..."
    echo "Press Ctrl+A, X to exit"
    echo ""

    qemu-system-aarch64 \
        -machine virt \
        -cpu cortex-a72 \
        -smp "$CPUS" \
        -m "$MEMORY" \
        -bios "$UEFI_FW" \
        -drive file="$VM_DISK",format=qcow2,if=virtio \
        -drive file="$SEED_IMG",format=raw,if=virtio \
        -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
        -device virtio-net-pci,netdev=net0 \
        -nographic
fi
