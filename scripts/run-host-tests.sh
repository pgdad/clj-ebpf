#!/bin/bash
# Run full test suite on host PC with proper privileges
#
# This script runs all clj-ebpf tests on the local host machine.
# Requires root/sudo for BPF-privileged tests.
#
# Usage:
#   ./scripts/run-host-tests.sh           # Run all tests
#   ./scripts/run-host-tests.sh --ci      # Run CI-safe tests only (no root needed)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================"
echo "Host PC Test Execution"
echo "========================================"
echo "Architecture: $(uname -m)"
echo "Kernel: $(uname -r)"
echo "Date: $(date)"
echo "========================================"
echo ""

cd "$PROJECT_ROOT"

# Parse arguments
CI_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --ci)
            CI_ONLY=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --ci      Run CI-safe tests only (no root required)"
            echo "  --help    Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ "$CI_ONLY" == "true" ]]; then
    echo "Running CI-safe tests (no BPF privileges required)..."
    clojure -M:test-ci
else
    echo "Running full test suite (requires root for BPF tests)..."
    if [[ $EUID -ne 0 ]]; then
        echo "Note: Running with sudo for BPF capabilities"
        sudo clojure -M:test
    else
        clojure -M:test
    fi
fi

echo ""
echo "========================================"
echo "Host tests completed successfully!"
echo "========================================"
