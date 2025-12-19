#!/bin/bash
# Master test runner for clj-ebpf cross-architecture testing
#
# This script runs tests on:
# - Host PC (x86_64)
# - ARM64 QEMU VM
#
# Usage:
#   ./scripts/run-all-tests.sh              # Run on both (default)
#   ./scripts/run-all-tests.sh --host       # Run on host only
#   ./scripts/run-all-tests.sh --arm64      # Run on ARM64 VM only
#   ./scripts/run-all-tests.sh --all        # Run on both explicitly
#   ./scripts/run-all-tests.sh --ci         # Run CI-safe tests only
#   ./scripts/run-all-tests.sh --start-vm   # Start VM if not running

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================"
echo "clj-ebpf Cross-Architecture Test Suite"
echo "========================================"
echo ""

# Parse arguments
RUN_HOST=false
RUN_ARM64=false
START_VM=false
CI_ONLY=false
SYNC_FIRST=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            RUN_HOST=true
            shift
            ;;
        --arm64)
            RUN_ARM64=true
            shift
            ;;
        --all)
            RUN_HOST=true
            RUN_ARM64=true
            shift
            ;;
        --start-vm)
            START_VM=true
            shift
            ;;
        --ci)
            CI_ONLY=true
            shift
            ;;
        --no-sync)
            SYNC_FIRST=false
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host       Run tests on host PC only"
            echo "  --arm64      Run tests on ARM64 VM only"
            echo "  --all        Run tests on both host and ARM64 VM"
            echo "  --start-vm   Start the ARM64 VM if not running"
            echo "  --ci         Run CI-safe tests only (no BPF privileges)"
            echo "  --no-sync    Skip syncing project to VM"
            echo "  --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                      # Run all tests on both platforms"
            echo "  $0 --host               # Run on host only"
            echo "  $0 --arm64 --start-vm   # Start VM and run ARM64 tests"
            echo "  $0 --ci                 # Run CI-safe tests on both"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Default: run on both if nothing specified
if [[ "$RUN_HOST" == "false" && "$RUN_ARM64" == "false" ]]; then
    RUN_HOST=true
    RUN_ARM64=true
fi

# Track overall success
HOST_SUCCESS=true
ARM64_SUCCESS=true

# Determine test command based on CI flag
if [[ "$CI_ONLY" == "true" ]]; then
    HOST_TEST_CMD="clojure -M:test-ci"
    VM_TEST_FLAG="--ci"
else
    HOST_TEST_CMD="sudo clojure -M:test"
    VM_TEST_FLAG=""
fi

# Run host tests
if [[ "$RUN_HOST" == "true" ]]; then
    echo "========================================"
    echo "Running tests on HOST ($(uname -m))"
    echo "========================================"
    echo "Kernel: $(uname -r)"
    echo ""

    cd "$PROJECT_ROOT"

    if $HOST_TEST_CMD; then
        echo ""
        echo "✓ Host tests PASSED"
    else
        echo ""
        echo "✗ Host tests FAILED"
        HOST_SUCCESS=false
    fi
    echo ""
fi

# Run ARM64 VM tests
if [[ "$RUN_ARM64" == "true" ]]; then
    echo "========================================"
    echo "Running tests on ARM64 VM"
    echo "========================================"

    # Check if VM is running
    if ! ssh -p 2222 -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@localhost true 2>/dev/null; then
        if [[ "$START_VM" == "true" ]]; then
            echo "Starting ARM64 VM..."
            "$PROJECT_ROOT/qemu-arm64/start-vm.sh" --daemon

            echo "Waiting for VM to boot (this may take 1-2 minutes)..."
            ATTEMPTS=0
            MAX_ATTEMPTS=60
            while ! ssh -p 2222 -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@localhost true 2>/dev/null; do
                sleep 5
                ATTEMPTS=$((ATTEMPTS + 1))
                if [[ $ATTEMPTS -ge $MAX_ATTEMPTS ]]; then
                    echo "Error: VM failed to become accessible after 5 minutes"
                    exit 1
                fi
                echo "  Still waiting... (attempt $ATTEMPTS/$MAX_ATTEMPTS)"
            done

            echo "VM is ready!"
            echo ""

            # Wait a bit more for cloud-init to finish
            echo "Waiting for cloud-init provisioning..."
            sleep 30
        else
            echo "Error: ARM64 VM not running."
            echo ""
            echo "To start the VM, use one of:"
            echo "  1. $0 --arm64 --start-vm"
            echo "  2. ./qemu-arm64/start-vm.sh"
            exit 1
        fi
    fi

    # Sync project to VM
    if [[ "$SYNC_FIRST" == "true" ]]; then
        echo "Syncing project to VM..."
        "$PROJECT_ROOT/qemu-arm64/sync-project.sh"
        echo ""
    fi

    # Run tests in VM
    if "$PROJECT_ROOT/qemu-arm64/run-tests-in-vm.sh" $VM_TEST_FLAG; then
        echo ""
        echo "✓ ARM64 tests PASSED"
    else
        echo ""
        echo "✗ ARM64 tests FAILED"
        ARM64_SUCCESS=false
    fi
    echo ""
fi

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"

if [[ "$RUN_HOST" == "true" ]]; then
    if [[ "$HOST_SUCCESS" == "true" ]]; then
        echo "  Host ($(uname -m)): ✓ PASSED"
    else
        echo "  Host ($(uname -m)): ✗ FAILED"
    fi
fi

if [[ "$RUN_ARM64" == "true" ]]; then
    if [[ "$ARM64_SUCCESS" == "true" ]]; then
        echo "  ARM64 VM:          ✓ PASSED"
    else
        echo "  ARM64 VM:          ✗ FAILED"
    fi
fi

echo "========================================"

# Exit with error if any tests failed
if [[ "$HOST_SUCCESS" == "false" || "$ARM64_SUCCESS" == "false" ]]; then
    exit 1
fi

echo ""
echo "All tests completed successfully!"
