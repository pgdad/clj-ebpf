#!/bin/bash
# Run tests inside the ARM64 VM
#
# This script:
# 1. Connects to the VM via SSH
# 2. Runs the Clojure test suite
# 3. Reports results
#
# Usage:
#   ./qemu-arm64/run-tests-in-vm.sh           # Run all tests
#   ./qemu-arm64/run-tests-in-vm.sh --ci      # Run CI-safe tests only
#   ./qemu-arm64/run-tests-in-vm.sh --sync    # Sync project first, then run tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_PORT=2222
VM_USER="ubuntu"
VM_HOST="localhost"
VM_PATH="/home/ubuntu/clj-ebpf"

# Parse arguments
CI_ONLY=false
DO_SYNC=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --ci)
            CI_ONLY=true
            shift
            ;;
        --sync)
            DO_SYNC=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --ci      Run CI-safe tests only (no BPF privileges required)"
            echo "  --sync    Sync project files before running tests"
            echo "  --help    Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if VM is reachable
if ! ssh -p "$SSH_PORT" -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" true 2>/dev/null; then
    echo "Error: Cannot connect to VM on port $SSH_PORT"
    echo "Is the VM running? Start it with: ./qemu-arm64/start-vm.sh"
    exit 1
fi

# Sync project if requested
if [[ "$DO_SYNC" == "true" ]]; then
    echo "Syncing project to VM..."
    "$SCRIPT_DIR/sync-project.sh"
    echo ""
fi

# Determine test command
if [[ "$CI_ONLY" == "true" ]]; then
    TEST_CMD="clojure -M:test-ci"
    TEST_DESC="CI-safe tests"
else
    TEST_CMD="sudo clojure -M:test"
    TEST_DESC="full test suite"
fi

echo "========================================"
echo "ARM64 VM Test Execution"
echo "========================================"

# Run tests in VM
ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" << EOF
cd $VM_PATH

echo "========================================"
echo "Architecture: \$(uname -m)"
echo "Kernel: \$(uname -r)"
echo "Java: \$(java -version 2>&1 | head -n1)"
echo "========================================"
echo ""

echo "Running $TEST_DESC..."
echo ""

$TEST_CMD

echo ""
echo "========================================"
echo "ARM64 tests completed successfully!"
echo "========================================"
EOF
