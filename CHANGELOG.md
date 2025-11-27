# Changelog

All notable changes to clj-ebpf will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Nothing yet

## [0.1.1] - 2025-11-27

### Fixed
- Fixed ENOENT errno handling in map operations - map-keys, map-values,
  map-entries, and map-count now work correctly on empty maps and when
  iterating to the end of a map. Previously checked for :noent instead
  of the correct :enoent errno keyword.

### Added
- Added test-enoent-handling test to verify ENOENT handling in map operations

## [0.1.0] - 2025-11-26

### Changed - Migrated to Panama FFI
- **BREAKING**: Migrated from JNA to Java's Panama Foreign Function & Memory API
- Requires Java 21+ (previously Java 11+)
- **Zero external dependencies** - removed JNA dependency entirely
- Uses MemorySegment instead of JNA Pointer/Memory
- More efficient native memory management with automatic cleanup
- Better performance through direct foreign function access

### Benefits
- No external dependencies - uses only Java standard library
- Better integration with modern Java features
- Improved memory safety with scoped allocations
- More efficient native calls through method handles
- Future-proof: Panama FFI is the official Java native interface going forward

### Added - Initial MVP Release

#### Core Infrastructure
- Direct `bpf()` syscall interface using Panama FFI (Java 21+)
- Complete BPF constants and enumerations from `linux/bpf.h`
- Memory management utilities for native interactions
- Kernel version detection and compatibility checking
- BPF filesystem operations

#### Map Operations
- Hash map support (BPF_MAP_TYPE_HASH)
- Array map support (BPF_MAP_TYPE_ARRAY)
- Ring buffer map support (BPF_MAP_TYPE_RINGBUF)
- Map lifecycle management (create, close)
- Core operations (lookup, update, delete)
- Map iteration (keys, values, entries)
- Map pinning/unpinning to BPF filesystem
- Custom key/value serializers and deserializers
- Resource management macros (`with-map`)
- Convenience constructors for common map types

#### Program Loading and Attachment
- BPF program loading with verifier log capture
- Kprobe attachment (function entry)
- Kretprobe attachment (function return)
- Tracepoint attachment
- Raw tracepoint attachment
- Program pinning/unpinning
- Program lifecycle management (load, close)
- Resource management macros (`with-program`)
- Automatic attachment cleanup on program close

#### Event Processing
- Ring buffer consumer framework
- Event serialization/deserialization helpers
- Struct packing/unpacking utilities
- Event polling infrastructure

#### Developer Experience
- Idiomatic Clojure APIs
- Comprehensive error handling with errno translation
- Detailed verifier log capture and reporting
- System capability checking
- Kernel version compatibility checks
- Extensive documentation and examples
- REPL-friendly development workflow

#### Testing
- Unit tests for constants and utilities
- Integration tests for maps (requires Linux + BPF)
- Integration tests for programs (requires root)
- Example programs demonstrating key features

#### Examples
- Simple kprobe example
- Execve tracer example
- Map operations example

### Dependencies
- Clojure 1.12.0
- tools.logging 1.3.0
- Java 21+ (for Panama FFI)
- **Zero external dependencies!**

### System Requirements
- Linux kernel 4.14+ (5.8+ recommended)
- CAP_BPF and CAP_PERFMON capabilities (or root)
- BPF filesystem mounted
- Tracefs mounted (for kprobes/tracepoints)

### Known Limitations
- Ring buffer memory-mapping not yet implemented (basic polling only)
- Perf event buffers not fully implemented
- ELF object file parsing not implemented
- BTF support not yet available
- XDP, TC, cgroup, LSM attachments not yet implemented
- Batch map operations not yet available

### Future Plans
See README.md for complete roadmap of planned features.
