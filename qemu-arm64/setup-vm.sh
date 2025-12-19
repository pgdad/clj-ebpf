#!/bin/bash
# One-time setup script for QEMU ARM64 VM
#
# This script:
# 1. Installs required QEMU packages
# 2. Downloads Ubuntu 22.04 ARM64 cloud image
# 3. Creates VM disk with backing file
# 4. Creates cloud-init seed image
#
# Usage:
#   ./qemu-arm64/setup-vm.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "QEMU ARM64 VM Setup for clj-ebpf"
echo "========================================"
echo ""

# Check if running on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Error: This script requires Linux"
    exit 1
fi

# Check architecture
HOST_ARCH=$(uname -m)
echo "Host architecture: $HOST_ARCH"

# Step 1: Install QEMU packages
echo ""
echo "Step 1: Installing QEMU packages..."
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y \
        qemu-system-aarch64 \
        qemu-efi-aarch64 \
        cloud-image-utils \
        rsync
elif command -v dnf &> /dev/null; then
    sudo dnf install -y \
        qemu-system-aarch64 \
        edk2-aarch64 \
        cloud-utils \
        rsync
elif command -v pacman &> /dev/null; then
    sudo pacman -S --noconfirm \
        qemu-system-aarch64 \
        edk2-ovmf \
        cloud-utils \
        rsync
else
    echo "Warning: Unknown package manager, please install packages manually:"
    echo "  - qemu-system-aarch64"
    echo "  - qemu-efi-aarch64 (or edk2-aarch64)"
    echo "  - cloud-image-utils (or cloud-utils)"
    echo "  - rsync"
fi
echo "✓ QEMU packages installed"

# Step 2: Download Ubuntu ARM64 cloud image
echo ""
echo "Step 2: Downloading Ubuntu 24.04 ARM64 cloud image (kernel 6.8+)..."
cd "$SCRIPT_DIR"

# Ubuntu 24.04 Noble has kernel 6.8+ which supports all BPF batch operations
IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"
IMAGE_FILE="noble-server-cloudimg-arm64.img"

if [[ -f "$IMAGE_FILE" ]]; then
    echo "Image already exists, checking for updates..."
    # Use wget with timestamping to only download if newer
    wget -N "$IMAGE_URL" || true
else
    wget "$IMAGE_URL"
fi
echo "✓ Cloud image ready: $IMAGE_FILE"

# Step 3: Create VM disk with backing file
echo ""
echo "Step 3: Creating VM disk (20GB)..."
VM_DISK="vm-disk.qcow2"

if [[ -f "$VM_DISK" ]]; then
    echo "Warning: VM disk already exists. Recreate? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -f "$VM_DISK"
        qemu-img create -f qcow2 -F qcow2 -b "$IMAGE_FILE" "$VM_DISK" 20G
    else
        echo "Keeping existing disk"
    fi
else
    qemu-img create -f qcow2 -F qcow2 -b "$IMAGE_FILE" "$VM_DISK" 20G
fi
echo "✓ VM disk ready: $VM_DISK"

# Step 4: Create cloud-init seed image
echo ""
echo "Step 4: Creating cloud-init seed image..."
SEED_IMG="seed.img"

if [[ ! -f "cloud-init/user-data" ]]; then
    echo "Error: cloud-init/user-data not found"
    exit 1
fi

if [[ ! -f "cloud-init/meta-data" ]]; then
    echo "Error: cloud-init/meta-data not found"
    exit 1
fi

# Create seed image
cloud-localds "$SEED_IMG" cloud-init/user-data cloud-init/meta-data
echo "✓ Cloud-init seed image ready: $SEED_IMG"

# Step 5: Verify UEFI firmware
echo ""
echo "Step 5: Verifying UEFI firmware..."
UEFI_PATHS=(
    "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"
    "/usr/share/edk2/aarch64/QEMU_EFI.fd"
    "/usr/share/AAVMF/AAVMF_CODE.fd"
    "/usr/share/qemu/edk2-aarch64-code.fd"
)

UEFI_FOUND=""
for path in "${UEFI_PATHS[@]}"; do
    if [[ -f "$path" ]]; then
        UEFI_FOUND="$path"
        break
    fi
done

if [[ -z "$UEFI_FOUND" ]]; then
    echo "Warning: UEFI firmware not found at standard locations."
    echo "You may need to update the BIOS path in start-vm.sh"
else
    echo "✓ UEFI firmware found: $UEFI_FOUND"
    # Update start-vm.sh with correct path if needed
    if [[ -f "start-vm.sh" ]]; then
        sed -i "s|/usr/share/qemu-efi-aarch64/QEMU_EFI.fd|$UEFI_FOUND|g" start-vm.sh
    fi
fi

# Summary
echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "Files created:"
echo "  - $VM_DISK (20GB VM disk)"
echo "  - $SEED_IMG (cloud-init configuration)"
echo ""
echo "Next steps:"
echo "  1. Start the VM:"
echo "     ./qemu-arm64/start-vm.sh"
echo ""
echo "  2. Wait for cloud-init to complete (~2-3 minutes)"
echo "     Watch for 'login:' prompt"
echo ""
echo "  3. SSH into the VM (from another terminal):"
echo "     ssh -p 2222 ubuntu@localhost"
echo ""
echo "  4. Run tests:"
echo "     ./scripts/run-all-tests.sh --arm64"
echo ""
echo "VM Resources: 4 CPUs, 4GB RAM"
echo "SSH Port: 2222 (localhost)"
echo ""
