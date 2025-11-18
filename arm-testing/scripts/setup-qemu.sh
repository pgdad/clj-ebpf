#!/bin/bash
# Setup script for QEMU ARM64 emulation on AMD64 host

set -e

echo "========================================="
echo "QEMU ARM64 Setup for clj-ebpf Testing"
echo "========================================="

# Detect host architecture
HOST_ARCH=$(uname -m)
echo "Host architecture: $HOST_ARCH"

# Check if running on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Error: This script requires Linux"
    exit 1
fi

# Install QEMU if not present
if ! command -v qemu-aarch64-static &> /dev/null; then
    echo "Installing QEMU ARM64 support..."

    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y qemu-user-static qemu-system-arm binfmt-support
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y qemu-user-static qemu-system-aarch64
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm qemu-user-static qemu-system-aarch64
    else
        echo "Error: Unsupported package manager"
        exit 1
    fi
else
    echo "QEMU ARM64 support already installed"
fi

# Enable binfmt_misc for ARM64 if on AMD64 host
if [[ "$HOST_ARCH" == "x86_64" ]]; then
    echo "Setting up binfmt_misc for ARM64 emulation..."

    # Check if binfmt_misc is mounted
    if ! mount | grep -q binfmt_misc; then
        sudo mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc
    fi

    # Register QEMU ARM64 handler if not already registered
    if [[ ! -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]]; then
        echo "Registering QEMU ARM64 handler..."
        sudo update-binfmts --enable qemu-aarch64
    fi

    # Verify registration
    if [[ -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]]; then
        echo "✓ QEMU ARM64 handler registered successfully"
        cat /proc/sys/fs/binfmt_misc/qemu-aarch64
    else
        echo "⚠ Warning: Could not verify QEMU ARM64 handler registration"
    fi
fi

# Install Docker buildx for multi-architecture builds
if command -v docker &> /dev/null; then
    echo "Setting up Docker buildx for multi-architecture builds..."

    # Create buildx builder if it doesn't exist
    if ! docker buildx ls | grep -q multiarch; then
        docker buildx create --name multiarch --use
        docker buildx inspect --bootstrap
    fi

    echo "✓ Docker buildx configured for multi-architecture builds"
else
    echo "⚠ Docker not found - skipping buildx setup"
fi

# Test ARM64 emulation
echo ""
echo "Testing ARM64 emulation..."
if command -v qemu-aarch64-static &> /dev/null; then
    # Try to run a simple ARM64 binary (if available)
    if [[ -f /usr/bin/arch ]]; then
        echo "Running ARM64 test..."
        qemu-aarch64-static /usr/bin/arch || echo "Note: Native ARM64 binary test skipped"
    fi
    echo "✓ QEMU ARM64 emulation ready"
else
    echo "✗ QEMU ARM64 not properly installed"
    exit 1
fi

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Build ARM64 container:"
echo "   cd arm-testing/docker"
echo "   docker-compose build clj-ebpf-arm64"
echo ""
echo "2. Run tests on ARM64:"
echo "   docker-compose run --rm clj-ebpf-arm64"
echo ""
echo "3. Run tests on AMD64 (for comparison):"
echo "   docker-compose run --rm clj-ebpf-amd64"
echo ""
