# Changelog

All notable changes to clj-ebpf will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Nothing yet

## [0.7.8] - 2025-12-29

### Added
- **BPF STRUCT_OPS Support** for implementing TCP congestion control:
  - Allows BPF programs to replace kernel function pointers in structures
  - Full tcp_congestion_ops callback support (ssthresh, cong_avoid, init, release, etc.)
  - STRUCT_OPS map creation and BPF link registration
- **STRUCT_OPS DSL Helpers** (`clj-ebpf.dsl.struct-ops`):
  - `struct-ops-prologue`, `struct-ops-prologue-2arg`, `struct-ops-prologue-3arg` - Callback prologues
  - `tcp-sock-load-*` - TCP socket field access (cwnd, ssthresh, srtt, ca-state, etc.)
  - `tcp-sock-store-*` - TCP socket field modification
  - `aimd-ssthresh` - Classic AIMD slow start threshold calculation
  - `slow-start-check`, `increment-cwnd` - Congestion avoidance patterns
  - `struct-ops-return-*` - Return patterns for different callback types
  - `ssthresh-prologue`, `cong-avoid-prologue`, etc. - Callback-specific prologues
  - `minimal-*-program` - Ready-to-use program templates
  - `struct-ops-section-name`, `tcp-cong-ops-section-name` - ELF section names
  - `make-struct-ops-info`, `make-tcp-cong-ops-info` - Program metadata
  - TCP congestion control constants (ca-states, ca-events, ack-flags)
- **STRUCT_OPS High-Level API** (`clj-ebpf.programs`):
  - `StructOpsProgram`, `StructOps` records for lifecycle management
  - `load-struct-ops-program` - Load callback programs
  - `register-struct-ops`, `unregister-struct-ops` - Registration lifecycle
  - `close-struct-ops` - Resource cleanup
  - `with-struct-ops` macro - Automatic cleanup
  - `tcp-congestion-ops-callbacks` - Callback metadata and validation
- **STRUCT_OPS Map Support** (`clj-ebpf.maps`):
  - `StructOpsMap` record for struct_ops maps
  - `create-struct-ops-map` - Create STRUCT_OPS maps with BTF support
- **STRUCT_OPS Syscall Support** (`clj-ebpf.syscall`):
  - `bpf-link-create-struct-ops` - Create BPF link for struct_ops
  - Added `:struct-ops` attach type constant (44)
- **STRUCT_OPS Tutorial** (`tutorials/quick-start-struct-ops.md`):
  - TCP congestion control concepts and architecture
  - Callback implementation patterns
  - TCP socket field access
  - AIMD and custom algorithm patterns
  - Registration workflow
- STRUCT_OPS example (`examples/struct_ops_tcp_cc.clj`)
- 64 new tests for STRUCT_OPS with 331 assertions (CI-safe)
- Updated `tutorials/README.md` with STRUCT_OPS section
- Updated `README.md` with STRUCT_OPS feature

### Note
- Requires kernel 5.6+ for basic STRUCT_OPS support
- Requires kernel 5.13+ for TCP congestion control in BPF
- Requires BTF support and CAP_BPF + CAP_NET_ADMIN capabilities

## [0.7.7] - 2025-12-29

### Added
- **BPF Iterators (bpf_iter) Support** for dumping kernel data structures:
  - `bpf-link-create-iter` - Create BPF link for iterator programs
  - `bpf-iter-create` - Create iterator file descriptor from link
  - Iterator types: task, bpf_map, bpf_map_elem, tcp, udp, bpf_prog, bpf_link
  - Reading from iterator FD triggers BPF program for each element
- **BPF Iterator DSL Helpers** (`clj-ebpf.dsl.iter`):
  - `iter-prologue`, `iter-prologue-with-meta` - Standard iterator prologues
  - `iter-load-ctx-ptr`, `iter-load-meta-field` - Context field access
  - `iter-check-null`, `iter-check-null-and-exit` - NULL pointer handling
  - `seq-write` - Write raw bytes to output (bpf_seq_write helper)
  - `seq-printf-simple` - Write formatted output (bpf_seq_printf helper)
  - `probe-read-kernel`, `probe-read-kernel-str` - Safe kernel memory access
  - `alloc-stack-buffer` - Stack buffer allocation helper
  - `iter-return-continue`, `iter-return-stop` - Return patterns
  - `task-load-pid`, `task-load-tgid` - Task struct field helpers
  - `build-iter-program` - Complete iterator program builder
  - `iter-section-name`, `make-iter-info` - ELF section and metadata
  - `minimal-task-iterator`, `task-null-check-template` - Templates
- **BPF Iterator High-Level API** (`clj-ebpf.programs`):
  - `BpfIterator` record for iterator lifecycle management
  - `create-iterator`, `close-iterator` - Iterator lifecycle
  - `with-iterator` macro - Automatic cleanup
  - `load-iterator-program` - Load and prepare iterator programs
- **BPF Iterator Tutorial** (`tutorials/quick-start-iterators.md`):
  - Iterator architecture and workflow
  - Context structures for different iterator types
  - NULL handling and return patterns
  - Output with seq_write and seq_printf
  - Program building and templates
- **BPF Iterator Guide** (`docs/guides/iterators-guide.md`):
  - Reference documentation for iterator operations
  - DSL function reference tables
  - Context offsets and BTF type names
  - Kernel version requirements (5.8+)
- BPF iterator example (`examples/iter_task_dump.clj`)
- 55 new tests for BPF iterators with 289 assertions (CI-safe)
- Updated `tutorials/README.md` with BPF Iterators section
- Updated `docs/README.md` with BPF Iterators guide entry

## [0.7.6] - 2025-12-29

### Added
- **FLOW_DISSECTOR Support** for custom packet parsing:
  - `attach-flow-dissector` - Attach FLOW_DISSECTOR programs to network namespace
  - `detach-flow-dissector` - Detach FLOW_DISSECTOR programs
  - Enables custom flow hashing for RSS and ECMP routing
- **FLOW_DISSECTOR DSL Helpers** (`clj-ebpf.dsl.flow-dissector`):
  - `flow-dissector-prologue` - Standard prologue for FLOW_DISSECTOR programs
  - `flow-dissector-get-flow-keys-ptr` - Get flow_keys output pointer
  - `flow-keys-set-nhoff`, `flow-keys-set-thoff` - Set header offsets
  - `flow-keys-set-addr-proto`, `flow-keys-set-ip-proto` - Set protocol info
  - `flow-keys-set-ports`, `flow-keys-set-ipv4-addrs` - Set 5-tuple fields
  - `flow-dissector-parse-ethernet` - Parse Ethernet header
  - `flow-dissector-parse-ipv4` - Parse IPv4 header
  - `flow-dissector-parse-tcp-ports`, `flow-dissector-parse-udp-ports` - Parse transport ports
  - `flow-dissector-bounds-check` - Packet bounds checking pattern
  - `flow-dissector-ok`, `flow-dissector-drop` - Return patterns
  - `build-flow-dissector-program` - Program builder
- **FLOW_DISSECTOR Tutorial** (`tutorials/quick-start-flow-dissector.md`):
  - Comprehensive guide covering FLOW_DISSECTOR architecture
  - bpf_flow_keys structure and field access
  - Parsing patterns for Ethernet, IPv4, TCP/UDP
  - Bounds checking and program building
- **FLOW_DISSECTOR Guide** (`docs/guides/flow-dissector-guide.md`):
  - Reference documentation for FLOW_DISSECTOR operations
  - DSL function reference tables
  - Protocol constants and header sizes
  - Kernel version requirements (4.2+, 5.0+ for BPF link)
- FLOW_DISSECTOR example (`examples/flow_dissector_custom.clj`)
- 64 new tests for FLOW_DISSECTOR with 308 assertions (CI-safe)
- Updated `tutorials/README.md` with FLOW_DISSECTOR section
- Updated `docs/README.md` with FLOW_DISSECTOR guide entry

## [0.7.5] - 2025-12-29

### Added
- **SK_LOOKUP Support** for programmable socket lookup:
  - `attach-sk-lookup` - Attach SK_LOOKUP programs to network namespace
  - `detach-sk-lookup` - Detach SK_LOOKUP programs
  - Enables custom socket dispatch and multi-tenant routing
- **SK_LOOKUP DSL Helpers** (`clj-ebpf.dsl.sk-lookup`):
  - `sk-lookup-prologue` - Standard prologue for SK_LOOKUP programs
  - `sk-lookup-get-local-port`, `sk-lookup-get-remote-port` - Load port fields
  - `sk-lookup-get-protocol`, `sk-lookup-get-family` - Load connection info
  - `sk-lookup-get-local-ip4`, `sk-lookup-get-remote-ip4` - Load IPv4 addresses
  - `sk-lookup-check-port`, `sk-lookup-check-protocol` - Common check patterns
  - `sk-assign` - Assign socket to handle connection (helper 124)
  - `sk-lookup-tcp`, `sk-lookup-udp` - Lookup sockets (helpers 84, 85)
  - `sk-release` - Release socket reference (helper 86)
  - `sk-lookup-pass`, `sk-lookup-drop` - Return patterns
  - `build-sk-lookup-program` - Program builder
- **BPF Link for Network Namespace** (`syscall/bpf-link-create-netns`):
  - Create BPF links to network namespaces
  - Used for SK_LOOKUP program attachment
- **SK_LOOKUP Tutorial** (`tutorials/quick-start-sk-lookup.md`):
  - Comprehensive guide covering SK_LOOKUP architecture
  - Context structure and field access
  - Port and protocol filtering patterns
  - Socket assignment with bpf_sk_assign
- **SK_LOOKUP Guide** (`docs/guides/sk-lookup-guide.md`):
  - Reference documentation for SK_LOOKUP operations
  - DSL function reference tables
  - Context field offsets and byte order notes
  - Kernel version requirements (5.9+)
- SK_LOOKUP example (`examples/sk_lookup_steering.clj`)
- 42 new tests for SK_LOOKUP with 150 assertions (CI-safe)
- Updated `tutorials/README.md` with SK_LOOKUP section
- Updated `docs/README.md` with SK_LOOKUP guide entry

## [0.7.4] - 2025-12-29

### Added
- **XSKMAP Support** for AF_XDP zero-copy packet processing:
  - `create-xsk-map` - XDP Socket Map for AF_XDP (XSK) file descriptors
  - Maps queue indices to AF_XDP socket file descriptors
  - Enables zero-copy packet delivery to userspace
- **XDP Redirect to XSK Helpers** (`clj-ebpf.dsl.xdp`):
  - `xdp-redirect-to-xsk` - Redirect packets to AF_XDP socket in XSKMAP
  - `xdp-redirect-to-xsk-by-queue` - Redirect based on rx_queue_index (common pattern)
  - Supports both immediate queue index and register-based lookup
- **XSKMAP Tutorial** (`tutorials/quick-start-xskmap.md`):
  - Comprehensive guide covering AF_XDP architecture
  - UMEM and ring buffer concepts
  - XDP program building patterns
  - Performance optimization tips
- **XSKMAP Guide** (`docs/guides/xskmap-guide.md`):
  - Reference documentation for XSKMAP operations
  - DSL function reference table
  - xdp_md context field offsets
  - Kernel version requirements (4.18+)
- XSKMAP example (`examples/xdp_xsk_redirect.clj`)
- 22 new tests for XSKMAP with 84 assertions (CI-safe)
- Updated `tutorials/README.md` with XSKMAP section
- Updated `docs/README.md` with XSKMAP guide entry

## [0.7.3] - 2025-12-29

### Added
- **SOCKMAP/SOCKHASH Tutorial** (`tutorials/quick-start-sockmap.md`):
  - Comprehensive guide covering SOCKMAP vs SOCKHASH map types
  - SK_SKB programs (stream parser and verdict)
  - SK_MSG programs for sendmsg redirection
  - Redirect helpers DSL reference
  - Complete echo server and TCP proxy examples
  - Best practices and troubleshooting
- **Socket Redirection Guide** (`docs/guides/sockmap-guide.md`):
  - Reference documentation for socket redirect operations
  - DSL function reference table
  - BPF helper function ID table
  - Kernel version requirements
  - Complete code examples
- Updated `tutorials/README.md` with SOCKMAP section
- Updated `docs/README.md` with socket redirection guide entry

## [0.7.2] - 2025-12-29

### Added
- **SOCKMAP and SOCKHASH Support** for socket redirection:
  - `create-sock-map` - Array-based socket storage for SK_SKB/SK_MSG programs
  - `create-sock-hash` - Hash-based socket storage with custom keys
- **SK_SKB Program Support** (`clj-ebpf.dsl.socket`):
  - `sk-skb-prologue` - Standard prologue for SK_SKB programs
  - `sk-redirect-map` - Redirect stream data to socket in SOCKMAP
  - `sk-redirect-hash` - Redirect stream data to socket in SOCKHASH
  - `sk-skb-pass`, `sk-skb-drop` - Return patterns
- **SK_MSG Program Support** (`clj-ebpf.dsl.socket`):
  - `sk-msg-prologue` - Standard prologue for SK_MSG programs
  - `msg-redirect-map` - Redirect message to socket in SOCKMAP
  - `msg-redirect-hash` - Redirect message to socket in SOCKHASH
  - `sk-msg-pass`, `sk-msg-drop` - Return patterns
- **Socket Map Update Helpers**:
  - `sock-map-update` - Add socket to SOCKMAP from BPF program
  - `sock-hash-update` - Add socket to SOCKHASH from BPF program
- **Program Attachment Functions** (`clj-ebpf.programs`):
  - `attach-sk-skb` - Attach SK_SKB program to SOCKMAP/SOCKHASH
  - `attach-sk-msg` - Attach SK_MSG program to SOCKMAP/SOCKHASH
  - `detach-sk-skb`, `detach-sk-msg` - Detach programs from maps
- New BPF helper IDs in DSL:
  - `msg-redirect-map` (60), `sock-hash-update` (70)
  - `msg-redirect-hash` (71), `sk-redirect-hash` (72)
- SOCKMAP redirect example (`examples/sockmap_redirect.clj`)
- 35 new tests for SOCKMAP/SOCKHASH (CI-safe)

## [0.7.1] - 2025-12-29

### Added
- **DEVMAP and CPUMAP Support** for XDP packet redirection:
  - `create-dev-map` - Array-based interface redirect map for L2 forwarding
  - `create-dev-map-hash` - Hash-based interface redirect map for sparse mappings
  - `create-cpu-map` - CPU steering map for custom RSS (Receive Side Scaling)
- **XDP Redirect DSL Helpers** (`clj-ebpf.dsl.xdp`):
  - `xdp-redirect` - Direct interface index redirect
  - `xdp-redirect-map` - Map-based redirect for DEVMAP/CPUMAP/XSKMAP
  - `xdp-redirect-to-interface` - Convenience helper for DEVMAP
  - `xdp-redirect-to-cpu` - Convenience helper for CPUMAP
- New BPF helper IDs in DSL:
  - `redirect-map` (51), `sk-redirect-map` (52), `sock-map-update` (53), `xdp-adjust-meta` (54)
- XDP redirect example (`examples/xdp_redirect_devmap.clj`)
- 20 new tests for DEVMAP/CPUMAP with 55 assertions (CI-safe)

## [0.7.0] - 2025-12-29

### Added
- **High-Level Declarative Macros** (`clj-ebpf.macros`) - New macro system that
  reduces boilerplate by 60% and provides a more Clojure-idiomatic API:
  - `defmap-spec` - Define reusable BPF map specifications with sensible defaults
  - `defprogram` - Define BPF programs declaratively with DSL instructions
  - `with-bpf-script` - Complete lifecycle management for maps, programs, and
    attachments with automatic cleanup
  - `load-defprogram` - Convenience function to load a defprogram spec
  - `create-defmap` - Convenience function to create a map from defmap-spec
- Macros re-exported from `clj-ebpf.core` for convenient access
- Support for all attachment types in `with-bpf-script`:
  - XDP (`:xdp`) with mode and flags options
  - TC (`:tc`) with direction and priority
  - Kprobe/Kretprobe (`:kprobe`, `:kretprobe`)
  - Tracepoint (`:tracepoint`) with category and event
  - Uprobe/Uretprobe (`:uprobe`, `:uretprobe`) with binary and symbol/offset
  - Cgroup (`:cgroup-skb`, `:cgroup-sock`) with cgroup path and direction
  - LSM (`:lsm`) with hook name
- Comprehensive macro documentation (`docs/guides/macros.md`)
- Macro tutorial (`tutorials/quick-start-macros.md`)
- Macro examples (`examples/macro_dsl.clj`)
- Updated `examples/simple_kprobe.clj` to demonstrate both traditional and
  macro approaches
- 30 new tests for macros with 81 assertions (CI-safe, no BPF privileges required)

## [0.6.8] - 2025-12-28

### Fixed
- Fixed Java 25 compatibility issue reading `/proc` filesystem files. The
  `get-current-cgroup` function now uses `java.nio.file.Files/readString`
  instead of `slurp`, which fails on `/proc` files in Java 25 due to
  `FileInputStream.available()` returning EINVAL for special filesystem files.
- Fixed batch operations fallback logic checking wrong errno keyword.
  The code was checking for `:inval` but the syscall layer returns `:einval`.
  Now `map-lookup-batch`, `map-update-batch`, `map-delete-batch`, and
  `map-lookup-and-delete-batch` correctly fall back to individual operations
  when the kernel doesn't support batch syscalls.

### Added
- Comprehensive BPF helper functions library documentation in README
- Helper functions tutorial (`examples/helpers_tutorial.clj`)
- Helper functions guide (`docs/guides/helpers-guide.md`)

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
- Requires Java 25+ (previously Java 11+)
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
- Direct `bpf()` syscall interface using Panama FFI (Java 25+)
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
- Java 25+ (for Panama FFI)
- **Zero external dependencies!**

### System Requirements
- Linux kernel 4.14+ (5.8+ recommended)
- CAP_BPF and CAP_PERFMON capabilities (or root)
- BPF filesystem mounted
- Tracefs mounted (for kprobes/tracepoints)

### Known Limitations (v0.1.0)
- Ring buffer memory-mapping not yet implemented (basic polling only)
- Perf event buffers not fully implemented
- ELF object file parsing not implemented
- BTF support not yet available
- XDP, TC, cgroup, LSM attachments not yet implemented

Note: Many of these limitations have been addressed in later releases. See the
full changelog for current capabilities.

### Future Plans
See README.md for complete roadmap of planned features.
