#!/bin/bash
# Sync project files to the ARM64 VM
#
# This script uses rsync to copy the project to the VM, excluding:
# - .git directory (large, not needed for tests)
# - target directory (build artifacts)
# - VM disk images
#
# Usage:
#   ./qemu-arm64/sync-project.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SSH_PORT=2222
VM_USER="ubuntu"
VM_HOST="localhost"
VM_PATH="/home/ubuntu/clj-ebpf"

echo "========================================"
echo "Syncing project to ARM64 VM"
echo "========================================"
echo "Source: $PROJECT_ROOT"
echo "Target: $VM_USER@$VM_HOST:$VM_PATH"
echo "========================================"
echo ""

# Check if VM is reachable
if ! ssh -p "$SSH_PORT" -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" true 2>/dev/null; then
    echo "Error: Cannot connect to VM on port $SSH_PORT"
    echo "Is the VM running? Start it with: ./qemu-arm64/start-vm.sh"
    exit 1
fi

# Create target directory on VM
ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" "mkdir -p $VM_PATH"

# Sync project files
rsync -avz --progress \
    --exclude='.git' \
    --exclude='target' \
    --exclude='.cpcache' \
    --exclude='.nrepl-port' \
    --exclude='qemu-arm64/*.img' \
    --exclude='qemu-arm64/*.qcow2' \
    --exclude='qemu-arm64/*.log' \
    --exclude='qemu-arm64/*.pid' \
    --exclude='node_modules' \
    --exclude='*.class' \
    -e "ssh -p $SSH_PORT -o StrictHostKeyChecking=no" \
    "$PROJECT_ROOT/" \
    "$VM_USER@$VM_HOST:$VM_PATH/"

echo ""
echo "========================================"
echo "Sync complete!"
echo "========================================"
echo ""
echo "To run tests in the VM:"
echo "  ./qemu-arm64/run-tests-in-vm.sh"
echo ""
echo "Or SSH in and run manually:"
echo "  ssh -p $SSH_PORT $VM_USER@$VM_HOST"
echo "  cd $VM_PATH && sudo clojure -M:test"
