#!/bin/bash
# Run clj-ebpf tests on all architectures

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "========================================="
echo "Multi-Architecture Testing for clj-ebpf"
echo "========================================="

# Detect current architecture
CURRENT_ARCH=$(uname -m)
echo "Current architecture: $CURRENT_ARCH"

# Function to run tests
run_tests() {
    local arch=$1
    local use_docker=$2

    echo ""
    echo "========================================="
    echo "Testing on $arch"
    echo "========================================="

    if [[ "$use_docker" == "true" ]]; then
        echo "Running tests in Docker container..."
        cd "$PROJECT_ROOT/arm-testing/docker"

        if [[ "$arch" == "arm64" ]] || [[ "$arch" == "aarch64" ]]; then
            docker-compose run --rm clj-ebpf-arm64 bash -c "cd /workspace && clojure -M:test"
        else
            docker-compose run --rm clj-ebpf-amd64 bash -c "cd /workspace && clojure -M:test"
        fi
    else
        echo "Running tests natively..."
        cd "$PROJECT_ROOT"
        clojure -M:test
    fi

    echo ""
    echo "✓ Tests completed on $arch"
}

# Parse command line arguments
USE_DOCKER=false
TEST_ARM64=false
TEST_AMD64=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --docker)
            USE_DOCKER=true
            shift
            ;;
        --arm64)
            TEST_ARM64=true
            shift
            ;;
        --amd64)
            TEST_AMD64=true
            shift
            ;;
        --all)
            TEST_ARM64=true
            TEST_AMD64=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --docker      Use Docker containers for testing"
            echo "  --arm64       Test on ARM64 architecture"
            echo "  --amd64       Test on AMD64 architecture"
            echo "  --all         Test on all architectures"
            echo "  --help        Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --docker --arm64       # Test ARM64 in Docker"
            echo "  $0 --docker --all         # Test all architectures in Docker"
            echo "  $0                        # Test on current architecture natively"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# If no specific architecture selected, test current architecture
if [[ "$TEST_ARM64" == "false" ]] && [[ "$TEST_AMD64" == "false" ]]; then
    if [[ "$CURRENT_ARCH" == "aarch64" ]] || [[ "$CURRENT_ARCH" == "arm64" ]]; then
        TEST_ARM64=true
    else
        TEST_AMD64=true
    fi
fi

# Run tests on selected architectures
if [[ "$TEST_AMD64" == "true" ]]; then
    run_tests "amd64" "$USE_DOCKER"
fi

if [[ "$TEST_ARM64" == "true" ]]; then
    run_tests "arm64" "$USE_DOCKER"
fi

echo ""
echo "========================================="
echo "All tests completed successfully!"
echo "========================================="
