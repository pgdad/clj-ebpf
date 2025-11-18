# ARM64 Testing Setup for clj-ebpf

This directory contains tools and configuration for testing clj-ebpf on ARM64 architecture using QEMU emulation and Docker containers.

## Overview

The ARM64 testing setup enables:
- **Multi-architecture testing**: Run tests on both AMD64 and ARM64
- **QEMU emulation**: Test ARM64 on AMD64 hosts
- **Docker containers**: Reproducible test environments
- **CI/CD integration**: Automated cross-architecture testing

## Architecture Support

clj-ebpf supports the following architectures:
- **AMD64** (x86_64) - Primary development platform
- **ARM64** (aarch64) - Full support with testing
- **ARM32** - Detection support (limited BPF support in kernel)

## Quick Start

### Prerequisites

**On AMD64 host (for ARM64 emulation):**
```bash
# Ubuntu/Debian
sudo apt-get install qemu-user-static qemu-system-arm binfmt-support docker.io

# Fedora/RHEL
sudo dnf install qemu-user-static qemu-system-aarch64 docker

# Arch Linux
sudo pacman -S qemu-user-static qemu-system-aarch64 docker
```

**On ARM64 host:**
```bash
# Just need Docker
sudo apt-get install docker.io
```

### Setup

1. **Run setup script** (AMD64 host only):
```bash
cd arm-testing
./scripts/setup-qemu.sh
```

This will:
- Install QEMU ARM64 support
- Configure binfmt_misc for ARM64 emulation
- Set up Docker buildx for multi-architecture builds
- Test ARM64 emulation

2. **Build Docker images**:
```bash
# Build for both architectures
./scripts/build-multi-arch.sh

# Build for ARM64 only
./scripts/build-multi-arch.sh --arm64-only

# Build for AMD64 only
./scripts/build-multi-arch.sh --amd64-only
```

### Running Tests

#### Using Docker Compose

**Test on ARM64:**
```bash
cd arm-testing/docker
docker-compose run --rm clj-ebpf-arm64
```

Inside the container:
```bash
# Show architecture info
arch-info

# Run all tests
clojure -M:test

# Run specific namespace tests
clojure -M:test -n clj-ebpf.core-test
```

**Test on AMD64:**
```bash
docker-compose run --rm clj-ebpf-amd64
```

#### Using Test Scripts

**Test current architecture:**
```bash
./scripts/test-all-arch.sh
```

**Test specific architecture:**
```bash
# Test ARM64 in Docker
./scripts/test-all-arch.sh --docker --arm64

# Test AMD64 in Docker
./scripts/test-all-arch.sh --docker --amd64

# Test both architectures
./scripts/test-all-arch.sh --docker --all
```

**Test natively (on ARM64 host):**
```bash
./scripts/test-all-arch.sh
```

## Architecture Detection in Code

clj-ebpf includes comprehensive architecture detection:

```clojure
(require '[clj-ebpf.core :as bpf])

;; Get current architecture
(bpf/get-arch)
;; => :arm64 (or :amd64, :arm32)

;; Get human-readable name
(bpf/arch-name)
;; => "ARM64"

;; Architecture checks
(bpf/arm64?)  ;; => true on ARM64
(bpf/amd64?)  ;; => false on ARM64

;; Get pointer size
(bpf/pointer-size)
;; => 8 (bytes, on 64-bit systems)

;; Get comprehensive info
(bpf/arch-info)
;; => {:arch :arm64
;;     :arch-name "ARM64"
;;     :os-arch "aarch64"
;;     :os-name "Linux"
;;     :os-version "6.14.0-33-generic"
;;     :pointer-size 8
;;     :java-version "17.0.9"
;;     :endianness :little}

;; Print formatted info
(bpf/print-arch-info)
;; ========================================
;; Architecture Information
;; ========================================
;; Architecture: ARM64 (aarch64)
;; OS: Linux 6.14.0-33-generic
;; Java: 17.0.9
;; Pointer size: 8 bytes
;; Endianness: little-endian
;; ========================================
```

## Directory Structure

```
arm-testing/
├── README.md              # This file
├── scripts/
│   ├── setup-qemu.sh     # QEMU setup script
│   ├── build-multi-arch.sh  # Multi-arch Docker build
│   └── test-all-arch.sh  # Test runner for all architectures
├── docker/
│   ├── Dockerfile.arm64  # Multi-arch Dockerfile
│   └── docker-compose.yml  # Docker Compose configuration
└── configs/
    └── (future: kernel configs, etc.)
```

## How It Works

### QEMU User-Mode Emulation

On AMD64 hosts, QEMU user-mode emulation transparently runs ARM64 binaries:

1. **binfmt_misc**: Kernel registers QEMU as handler for ARM64 binaries
2. **qemu-aarch64-static**: Translates ARM64 instructions to x86_64
3. **Transparent execution**: ARM64 programs run as if native

### Docker Multi-Architecture Support

Docker buildx enables building images for multiple platforms:

```bash
# Create multi-arch builder
docker buildx create --name multiarch --use

# Build for both platforms
docker buildx build --platform linux/amd64,linux/arm64 -t clj-ebpf:latest .
```

### Architecture-Specific Considerations

**Endianness:**
- Both AMD64 and ARM64 are little-endian
- No byte-order conversion needed between architectures

**Pointer Size:**
- Both are 64-bit: 8-byte pointers
- BPF program compatibility preserved

**System Calls:**
- BPF syscall numbers may differ
- clj-ebpf uses system call detection

**BTF Support:**
- Both architectures support BTF (kernel 4.18+)
- CO-RE relocations work identically

## Testing Best Practices

### 1. Test on Both Architectures

Always test on both AMD64 and ARM64 before merging:

```bash
# Test suite on both architectures
./scripts/test-all-arch.sh --docker --all
```

### 2. Architecture-Specific Code

Use architecture detection for platform-specific code:

```clojure
(when (bpf/arm64?)
  ;; ARM64-specific initialization
  (println "Running on ARM64"))

(when (bpf/amd64?)
  ;; AMD64-specific initialization
  (println "Running on AMD64"))
```

### 3. Pointer Size Awareness

Use `pointer-size` for architecture-independent code:

```clojure
(def ptr-bytes (bpf/pointer-size))
;; Works correctly on both 32-bit and 64-bit systems
```

### 4. BPF Program Portability

BPF programs compiled with CO-RE work on both architectures:

```clojure
;; This works on both AMD64 and ARM64
(def portable-program
  (bpf/assemble [(bpf/core-field-offset :r1 "task_struct" "pid")
                 (bpf/ldx :w :r0 :r1 0)
                 (bpf/exit-insn)]))
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Multi-Architecture Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        arch: [amd64, arm64]
    steps:
      - uses: actions/checkout@v3

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v2

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Build and test
        run: |
          cd arm-testing
          ./scripts/build-multi-arch.sh --${{ matrix.arch }}-only
          ./scripts/test-all-arch.sh --docker --${{ matrix.arch }}
```

## Troubleshooting

### QEMU Not Working

**Problem**: ARM64 binaries fail to execute

**Solution**:
```bash
# Re-register QEMU handlers
sudo update-binfmts --enable qemu-aarch64

# Verify registration
cat /proc/sys/fs/binfmt_misc/qemu-aarch64
```

### Docker Build Fails

**Problem**: Multi-arch build fails

**Solution**:
```bash
# Reset buildx
docker buildx rm multiarch
docker buildx create --name multiarch --use
docker buildx inspect --bootstrap
```

### Permission Denied in Container

**Problem**: BPF operations fail with permission errors

**Solution**:
- Ensure container runs with `--privileged` flag
- Check kernel BPF support: `cat /proc/sys/kernel/unprivileged_bpf_disabled`

### Performance Issues

**Problem**: ARM64 emulation is slow

**Explanation**:
- QEMU user-mode adds overhead (typically 2-5x slower)
- This is normal for emulation
- For production testing, use native ARM64 hardware

**Solutions**:
- Use native ARM64 for performance testing
- Use AMD64 for quick development iterations
- Consider cloud ARM64 instances (AWS Graviton, etc.)

## Native ARM64 Testing

For best performance, test on native ARM64 hardware:

**Cloud Providers with ARM64:**
- AWS: EC2 Graviton instances (c6g, m6g, r6g)
- Oracle Cloud: Ampere A1 instances (free tier available)
- Azure: Dpsv5/Dplsv5-series VMs
- Google Cloud: T2A instances

**Setup on ARM64 host:**
```bash
# Clone repository
git clone https://github.com/yourusername/clj-ebpf.git
cd clj-ebpf
git checkout arm-testing

# Run tests natively (fast!)
clojure -M:test

# Check architecture
clojure -X clj-ebpf.core/print-arch-info
```

## Performance Comparison

Typical test execution times:

| Environment | Time | Notes |
|-------------|------|-------|
| Native AMD64 | 15s | Baseline |
| Native ARM64 | 16s | ~6% slower (normal variance) |
| ARM64 on QEMU | 45-75s | 3-5x slower (emulation overhead) |

## Kernel Requirements

Both architectures require:
- Linux kernel 4.14+ (5.8+ recommended)
- CONFIG_BPF=y
- CONFIG_BPF_SYSCALL=y
- CONFIG_DEBUG_INFO_BTF=y (for CO-RE)

Check kernel config:
```bash
# In container
zgrep CONFIG_BPF /proc/config.gz

# Or on host
grep CONFIG_BPF /boot/config-$(uname -r)
```

## Future Enhancements

- [ ] RISC-V architecture support
- [ ] PowerPC architecture support
- [ ] Custom kernel builds with optimal BPF configuration
- [ ] Performance benchmarking suite
- [ ] Automated performance regression detection

## References

- [QEMU User Mode Emulation](https://www.qemu.org/docs/master/user/main.html)
- [Docker Buildx Multi-Platform](https://docs.docker.com/buildx/working-with-buildx/)
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)
- [ARM64 Linux Kernel](https://www.kernel.org/doc/html/latest/arm64/index.html)

## Support

For issues specific to ARM64 testing:
1. Check this README first
2. Verify QEMU setup: `./scripts/setup-qemu.sh`
3. Test in Docker: `docker-compose run --rm clj-ebpf-arm64`
4. Open an issue with architecture info: `(bpf/arch-info)`
