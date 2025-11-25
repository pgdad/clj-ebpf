# clj-ebpf Introduction

clj-ebpf is a pure Clojure library for working with Linux eBPF (Extended Berkeley Packet Filter). It provides a high-level DSL for writing BPF programs, manages BPF maps, and handles program loading and attachment - all without requiring external C toolchains.

## Requirements

- **Java 25+** with Panama Foreign Function & Memory API
- **Linux kernel 5.8+** (for ring buffer support, earlier kernels have partial support)
- **Appropriate capabilities** (CAP_BPF, CAP_SYS_ADMIN, or root)

## Quick Start

```clojure
(require '[clj-ebpf.core :as bpf]
         '[clj-ebpf.dsl.core :as dsl])

;; Initialize the library
(bpf/init!)

;; Create a simple XDP program that passes all packets
(def pass-all
  (dsl/assemble
    [(dsl/mov :r0 2)      ; XDP_PASS = 2
     (dsl/exit-insn)]))

;; Load the program
(def prog-fd (bpf/load-program pass-all :xdp))

;; Clean up when done
(bpf/close-program prog-fd)
```

## Core Modules

### High-Level API

| Module | Description |
|--------|-------------|
| `clj-ebpf.core` | Main entry point, initialization |
| `clj-ebpf.maps` | BPF map creation and manipulation |
| `clj-ebpf.programs` | Program loading and attachment |
| `clj-ebpf.events` | Ring buffer and perf event handling |

### DSL (Domain Specific Language)

| Module | Description |
|--------|-------------|
| `clj-ebpf.dsl.core` | Unified DSL API |
| `clj-ebpf.dsl.alu` | Arithmetic operations |
| `clj-ebpf.dsl.mem` | Memory operations |
| `clj-ebpf.dsl.jump` | Control flow |
| `clj-ebpf.dsl.atomic` | Atomic operations |
| `clj-ebpf.dsl.instructions` | Low-level encoding |

### Program Types

| Module | Description |
|--------|-------------|
| `clj-ebpf.xdp` | XDP program attachment |
| `clj-ebpf.tc` | Traffic Control (TC) programs |
| `clj-ebpf.cgroup` | Cgroup programs |
| `clj-ebpf.lsm` | Linux Security Modules |
| `clj-ebpf.perf` | Perf event programs |

### Utilities

| Module | Description |
|--------|-------------|
| `clj-ebpf.helpers` | BPF helper function metadata |
| `clj-ebpf.errors` | Structured error handling |
| `clj-ebpf.arch` | Multi-architecture support |
| `clj-ebpf.constants` | BPF constants and flags |
| `clj-ebpf.utils` | Memory utilities |

## Architecture Support

clj-ebpf supports multiple CPU architectures:

- **x86_64** (AMD64)
- **aarch64** (ARM64)
- **riscv64** (RISC-V 64-bit)
- **loongarch64** (LoongArch 64-bit)

The library automatically detects the architecture and uses appropriate syscall numbers.

## Further Reading

- [Tutorial: Getting Started](../../tutorials/README.md)
- [API Reference](../api/index.html)
- [Architecture Decision Records](../../docs/adr/)
