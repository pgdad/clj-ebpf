#!/bin/bash
# Stop the QEMU ARM64 VM
#
# Usage:
#   ./qemu-arm64/stop-vm.sh           # Graceful shutdown via SSH
#   ./qemu-arm64/stop-vm.sh --force   # Force kill the QEMU process

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_PORT=2222

# Parse arguments
FORCE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force, -f   Force kill the QEMU process"
            echo "  --help        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Stopping QEMU ARM64 VM..."

# Try graceful shutdown first (unless forced)
if [[ "$FORCE" != "true" ]]; then
    if ssh -p "$SSH_PORT" -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@localhost "sudo poweroff" 2>/dev/null; then
        echo "Shutdown command sent. Waiting for VM to stop..."
        sleep 10
    fi
fi

# Check for PID file
if [[ -f "$SCRIPT_DIR/vm.pid" ]]; then
    VM_PID=$(cat "$SCRIPT_DIR/vm.pid")
    if kill -0 "$VM_PID" 2>/dev/null; then
        echo "Killing QEMU process (PID: $VM_PID)..."
        kill "$VM_PID" 2>/dev/null || true
        sleep 2
        # Force kill if still running
        if kill -0 "$VM_PID" 2>/dev/null; then
            kill -9 "$VM_PID" 2>/dev/null || true
        fi
    fi
    rm -f "$SCRIPT_DIR/vm.pid"
fi

# Also try to find any stray QEMU processes
QEMU_PIDS=$(pgrep -f "qemu-system-aarch64.*vm-disk.qcow2" || true)
if [[ -n "$QEMU_PIDS" ]]; then
    echo "Found QEMU processes: $QEMU_PIDS"
    kill $QEMU_PIDS 2>/dev/null || true
fi

echo "VM stopped."
