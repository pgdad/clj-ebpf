# QEMU ARM64 Testing for clj-ebpf

This directory contains tools for running clj-ebpf tests on an ARM64 Linux virtual machine using QEMU system emulation.

## Overview

Unlike the Docker-based ARM testing in `arm-testing/`, this uses a full QEMU system VM which provides:
- **Real ARM64 Linux kernel** - BPF syscalls execute on ARM64 kernel
- **Full BPF support** - All privileged BPF operations work
- **Accurate testing** - True cross-architecture verification

## Quick Start

### 1. Setup (One-time)

```bash
# Install QEMU and download Ubuntu ARM64 image
./qemu-arm64/setup-vm.sh
```

This will:
- Install `qemu-system-aarch64` and dependencies
- Download Ubuntu 22.04 ARM64 cloud image (~600MB)
- Create a 20GB VM disk
- Generate cloud-init configuration

### 2. Start the VM

```bash
# Interactive mode (see console output)
./qemu-arm64/start-vm.sh

# Or daemon mode (background)
./qemu-arm64/start-vm.sh --daemon
```

First boot takes 2-3 minutes for cloud-init to:
- Install Java 21
- Install Clojure CLI
- Configure SSH access

### 3. Run Tests

```bash
# Run all tests on ARM64 VM
./scripts/run-all-tests.sh --arm64

# Run on both host and ARM64
./scripts/run-all-tests.sh --all

# Start VM automatically if needed
./scripts/run-all-tests.sh --arm64 --start-vm
```

### 4. Stop the VM

```bash
./qemu-arm64/stop-vm.sh
```

## Scripts

| Script | Description |
|--------|-------------|
| `setup-vm.sh` | One-time setup: install QEMU, download image, create disk |
| `start-vm.sh` | Launch the ARM64 VM (interactive or daemon mode) |
| `stop-vm.sh` | Stop the running VM |
| `sync-project.sh` | Copy project files to the VM via rsync |
| `run-tests-in-vm.sh` | Execute tests inside the VM via SSH |

## Manual Access

SSH into the VM:
```bash
ssh -p 2222 ubuntu@localhost
```

Run tests manually:
```bash
cd /home/ubuntu/clj-ebpf
sudo clojure -M:test      # Full test suite
clojure -M:test-ci        # CI-safe tests only
```

## VM Specifications

| Resource | Value |
|----------|-------|
| Architecture | ARM64 (aarch64) |
| CPU | Cortex-A72 (emulated) |
| CPUs | 4 |
| Memory | 4GB |
| Disk | 20GB |
| OS | Ubuntu 22.04 |
| Kernel | 5.15+ (Ubuntu default) |
| Java | OpenJDK 21 |
| SSH Port | 2222 |

## Cloud-Init Configuration

The VM is provisioned with `cloud-init/user-data`:
- User: `ubuntu` (passwordless sudo)
- SSH key: Your `~/.ssh/id_rsa.pub`
- Packages: Java 21, Clojure, git, bpftool

## Directory Structure

```
qemu-arm64/
├── README.md                 # This file
├── setup-vm.sh              # One-time setup script
├── start-vm.sh              # Launch VM
├── stop-vm.sh               # Stop VM
├── sync-project.sh          # Sync files to VM
├── run-tests-in-vm.sh       # Run tests in VM
├── cloud-init/
│   ├── user-data            # Cloud-init configuration
│   └── meta-data            # Instance metadata
├── jammy-server-cloudimg-arm64.img  # Base image (downloaded)
├── vm-disk.qcow2            # VM disk (created)
├── seed.img                 # Cloud-init seed (created)
├── vm.pid                   # PID file (when running)
└── vm.log                   # Console log (daemon mode)
```

## Performance

QEMU system emulation is slower than native:

| Environment | Test Time | Notes |
|-------------|-----------|-------|
| Native x86_64 | ~15s | Baseline |
| Native ARM64 | ~16s | ~6% slower |
| QEMU ARM64 | ~3-5min | 10-20x slower (emulation) |

For faster ARM64 testing, consider:
- Native ARM64 hardware (AWS Graviton, Oracle A1)
- Apple Silicon Macs (native ARM64)
- Raspberry Pi 4/5 (slower but native)

## Troubleshooting

### VM won't start

```bash
# Check UEFI firmware is installed
ls /usr/share/qemu-efi-aarch64/QEMU_EFI.fd

# If missing, install it
sudo apt-get install qemu-efi-aarch64
```

### Can't SSH to VM

```bash
# Check if VM is running
ps aux | grep qemu-system-aarch64

# Check if port 2222 is listening
ss -tlnp | grep 2222

# View VM console log
tail -f qemu-arm64/vm.log
```

### Cloud-init not completing

First boot takes 2-3 minutes. Check progress:
```bash
ssh -p 2222 ubuntu@localhost
sudo cloud-init status --wait
cat /var/log/cloud-init-output.log
```

### BPF tests failing

Ensure the VM kernel supports BPF:
```bash
ssh -p 2222 ubuntu@localhost
zgrep CONFIG_BPF /proc/config.gz
sudo bpftool prog list
```

### Out of disk space

The VM disk is 20GB. Check usage:
```bash
ssh -p 2222 ubuntu@localhost
df -h /
```

## Comparison with Docker Testing

| Feature | Docker (arm-testing/) | QEMU VM (qemu-arm64/) |
|---------|----------------------|----------------------|
| Kernel | Host kernel (x86_64) | ARM64 Linux kernel |
| BPF syscalls | Execute on host | Execute on ARM64 |
| Full BPF tests | No (kernel mismatch) | Yes |
| Startup time | Seconds | Minutes |
| Complexity | Lower | Higher |
| Use case | CI-safe tests, quick iteration | Full integration testing |

## See Also

- `arm-testing/` - Docker-based ARM64 testing (faster, limited BPF)
- `scripts/run-all-tests.sh` - Master test runner
- `scripts/run-host-tests.sh` - Host-only testing
