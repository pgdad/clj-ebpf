# clj-ebpf

Complete eBPF (Extended Berkeley Packet Filter) programming library for Clojure with minimal dependencies.

## Overview

clj-ebpf provides idiomatic Clojure APIs for loading, managing, and interacting with eBPF programs and maps. It uses direct syscall interface via Java's Panama Foreign Function & Memory API (FFI) for zero external dependencies and maximum control.

## Features

### Current (MVP)
- ✅ Direct `bpf()` syscall interface using Panama FFI (Java 21+)
- ✅ BPF map operations (create, lookup, update, delete, iterate)
  - Hash maps
  - Array maps
  - Ring buffer maps
- ✅ BPF program loading
- ✅ Kprobe/Kretprobe attachment
- ✅ Tracepoint attachment
- ✅ Raw tracepoint attachment
- ✅ Ring buffer event reading (basic)
- ✅ Map pinning to BPF filesystem
- ✅ Program pinning
- ✅ Idiomatic Clojure APIs
- ✅ Resource management macros (`with-map`, `with-program`)
- ✅ Comprehensive error handling

### Planned (Future Phases)
- ⏳ All remaining map types (LRU, per-CPU, etc.)
- ⏳ XDP (eXpress Data Path) support
- ⏳ TC (Traffic Control) support
- ⏳ Cgroup attachment
- ⏳ LSM (Linux Security Modules) hooks
- ⏳ BTF (BPF Type Format) support
- ⏳ CO-RE (Compile Once - Run Everywhere)
- ⏳ ELF object file parsing
- ⏳ C compilation integration
- ⏳ BPF assembly DSL
- ⏳ Perf event buffers
- ⏳ Batch map operations

## Requirements

### System Requirements
- **Linux kernel**: 4.14+ (5.8+ recommended for full features)
- **Capabilities**: `CAP_BPF` and `CAP_PERFMON` (or root)
- **BPF filesystem**: Mounted at `/sys/fs/bpf`
- **Tracefs**: Mounted at `/sys/kernel/debug/tracing` (for kprobes/tracepoints)

### Dependencies
- **Clojure**: 1.12.0+
- **Java**: 21+ (required for Panama FFI)
- **Zero external dependencies!** Uses Java's built-in Panama FFI

### Mounting Required Filesystems

```bash
# Mount BPF filesystem (if not already mounted)
sudo mount -t bpf bpf /sys/fs/bpf

# Mount tracefs (if not already mounted)
sudo mount -t tracefs tracefs /sys/kernel/debug/tracing
```

## Installation

Add to your `deps.edn`:

```clojure
{:deps {clj-ebpf {:git/url "https://github.com/yourusername/clj-ebpf"
                  :sha "..."}}}
```

Or for Leiningen `project.clj`:

```clojure
[clj-ebpf "0.1.0-SNAPSHOT"]
```

## Quick Start

```clojure
(require '[clj-ebpf.core :as bpf])

;; Check BPF availability
(bpf/init!)
;; => {:kernel-version 0x050f00, :bpf-fs-mounted true, :has-cap-bpf false}

;; Create and use a BPF hash map
(bpf/with-map [m {:map-type :hash
                  :key-size 4
                  :value-size 4
                  :max-entries 100
                  :map-name "my_map"}]
  ;; Insert values
  (bpf/map-update m 1 100)
  (bpf/map-update m 2 200)

  ;; Lookup values
  (println "Key 1:" (bpf/map-lookup m 1))  ;; => 100

  ;; Iterate
  (doseq [[k v] (bpf/map-entries m)]
    (println k "=>" v)))
```

## Usage Examples

### Working with Maps

```clojure
(require '[clj-ebpf.core :as bpf]
         '[clj-ebpf.utils :as utils])

;; Create a hash map with custom serializers
(bpf/with-map [m {:map-type :hash
                  :key-size 4
                  :value-size 8
                  :max-entries 1024
                  :map-name "counter_map"
                  :key-serializer utils/int->bytes
                  :key-deserializer utils/bytes->int
                  :value-serializer utils/long->bytes
                  :value-deserializer utils/bytes->long}]

  ;; Update with flags
  (bpf/map-update m 1 100 :flags :noexist)  ; Create only
  (bpf/map-update m 1 200 :flags :exist)    ; Update only

  ;; Delete
  (bpf/map-delete m 1)

  ;; Iteration
  (println "Keys:" (bpf/map-keys m))
  (println "Count:" (bpf/map-count m))

  ;; Clear all
  (bpf/map-clear m))

;; Convenience constructors
(def hash-map (bpf/create-hash-map 100 :map-name "my_hash"))
(def array-map (bpf/create-array-map 50 :map-name "my_array"))
```

### Loading and Attaching Programs

```clojure
(require '[clj-ebpf.core :as bpf]
         '[clj-ebpf.programs :as programs])

;; Simple BPF program bytecode (just returns 0)
(def simple-program
  (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00  ; mov r0, 0
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

;; Load and attach a kprobe
(bpf/with-program [prog {:prog-type :kprobe
                         :insns simple-program
                         :license "GPL"
                         :prog-name "my_kprobe"}]
  (println "Program loaded, FD:" (:fd prog))

  ;; Attach to a kernel function
  (let [attached (bpf/attach-kprobe prog {:function "__x64_sys_clone"})]
    (println "Attached to sys_clone")
    (Thread/sleep 10000) ; Run for 10 seconds
    (println "Detaching...")))
;; Program automatically detached and closed

;; Attach to tracepoint
(bpf/with-program [prog {:prog-type :tracepoint
                         :insns simple-program
                         :license "GPL"
                         :prog-name "execve_trace"}]
  (bpf/attach-tracepoint prog {:category "syscalls"
                               :name "sys_enter_execve"}))
```

### Pinning Objects

```clojure
;; Pin a map for reuse across processes
(def m (bpf/create-hash-map 100 :map-name "shared_map"))
(bpf/pin-map m "/sys/fs/bpf/my_shared_map")

;; Later, in another process:
(def m2 (bpf/get-pinned-map "/sys/fs/bpf/my_shared_map"
                            {:map-type :hash
                             :key-size 4
                             :value-size 4
                             :max-entries 100}))
;; Access the same map!
```

### Working with Structured Data

```clojure
(require '[clj-ebpf.utils :as utils])

;; Define event structure: [pid:u32, timestamp:u64, count:u32]
(def event-spec [:u32 :u64 :u32])

;; Create parser and serializer
(def parse-event (utils/make-event-parser event-spec))
(def pack-event (utils/make-event-serializer event-spec))

;; Pack data
(def event-bytes (pack-event [1234 9876543210 42]))

;; Unpack data
(def [pid timestamp count] (parse-event event-bytes))
```

## API Reference

### Core Functions

#### Maps
- `create-map` - Create a BPF map with options
- `create-hash-map` - Create hash map (convenience)
- `create-array-map` - Create array map (convenience)
- `create-ringbuf-map` - Create ring buffer map (convenience)
- `close-map` - Close map and release resources
- `map-lookup` - Look up value by key
- `map-update` - Insert or update key-value pair
- `map-delete` - Delete entry by key
- `map-keys` - Get all keys (lazy seq)
- `map-entries` - Get all key-value pairs (lazy seq)
- `map-values` - Get all values (lazy seq)
- `map-count` - Count entries
- `map-clear` - Delete all entries
- `pin-map` - Pin map to BPF filesystem
- `get-pinned-map` - Retrieve pinned map
- `dump-map` - Pretty print map contents

#### Programs
- `load-program` - Load BPF program into kernel
- `close-program` - Unload program and detach
- `attach-kprobe` - Attach to kernel function entry
- `attach-kretprobe` - Attach to kernel function return
- `attach-tracepoint` - Attach to tracepoint
- `attach-raw-tracepoint` - Attach to raw tracepoint
- `pin-program` - Pin program to BPF filesystem
- `get-pinned-program` - Retrieve pinned program

#### Events
- `create-ringbuf-consumer` - Create ring buffer consumer
- `start-ringbuf-consumer` - Start consuming events
- `stop-ringbuf-consumer` - Stop consuming events
- `process-events` - Process events synchronously

#### Utilities
- `check-bpf-available` - Check system compatibility
- `get-kernel-version` - Get kernel version
- `bpf-fs-mounted?` - Check if BPF FS is mounted
- `ensure-bpf-fs` - Get BPF FS path or throw

#### Macros
- `with-map` - Create map with automatic cleanup
- `with-program` - Load program with automatic cleanup
- `with-ringbuf-consumer` - Manage ring buffer consumer

## Examples

See the `examples/` directory for complete examples:

- `examples/simple_kprobe.clj` - Basic kprobe attachment
- `examples/execve_tracer.clj` - Trace execve system calls

Run examples:

```bash
# Simple map operations (no root required)
clj -M -m examples.execve-tracer map

# Trace execve (requires root)
sudo clj -M -m examples.execve-tracer trace
```

## Testing

```bash
# Run unit tests (no root required)
clj -M:test

# Run integration tests (requires root and BPF support)
sudo clj -M:test
```

## Architecture

clj-ebpf uses a layered architecture:

1. **Syscall Layer** (`clj-ebpf.syscall`) - Direct Panama FFI wrappers around `bpf()` syscall
2. **Utils Layer** (`clj-ebpf.utils`) - Memory management, serialization, system utilities
3. **Domain Layer** - High-level abstractions:
   - `clj-ebpf.maps` - Map operations
   - `clj-ebpf.programs` - Program loading and attachment
   - `clj-ebpf.events` - Event reading
4. **Core API** (`clj-ebpf.core`) - Public API facade

### Why Direct Syscalls?

We use direct `bpf()` syscalls via Panama FFI instead of wrapping libbpf because:
- **Zero dependencies**: Uses Java's built-in Panama FFI (Java 21+)
- **Full control**: Access to all BPF features
- **No C compilation**: Pure Clojure + Java interop
- **Better errors**: Direct access to kernel errors and verifier logs

## Troubleshooting

### Permission Denied

```
Error: :acces (errno 13)
```

**Solution**: Run with sudo or add capabilities:
```bash
sudo setcap cap_bpf,cap_perfmon+ep $(which java)
```

### BPF Filesystem Not Mounted

```
Error: BPF filesystem not mounted
```

**Solution**:
```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

### Kernel Too Old

```
Error: Kernel version too old, need at least 4.14
```

**Solution**: Upgrade your kernel to 4.14+ (5.8+ recommended)

### Program Load Failed

Check the verifier log in the exception data:
```clojure
(catch clojure.lang.ExceptionInfo e
  (when-let [log (:verifier-log (ex-data e))]
    (println "Verifier log:\n" log)))
```

### Tracepoint Not Found

```
Error: Failed to get tracepoint ID
```

**Solution**: Ensure tracefs is mounted and tracepoint exists:
```bash
sudo mount -t tracefs tracefs /sys/kernel/debug/tracing
ls /sys/kernel/debug/tracing/events/syscalls/
```

## Performance Considerations

- Use batch operations when available (future feature)
- Ring buffers are more efficient than perf buffers for modern kernels
- Per-CPU maps reduce contention
- Pin maps/programs for cross-process reuse
- Use array maps for small, dense key spaces (faster than hash)

## Security Considerations

- eBPF programs require elevated privileges (CAP_BPF, CAP_PERFMON, or root)
- Programs are verified by the kernel before loading
- Infinite loops are prevented by the verifier
- Helper function access is restricted by program type
- Always validate input data from untrusted sources

## Contributing

Contributions welcome! Areas for improvement:

- Full ELF parsing for loading compiled BPF objects
- BTF support for CO-RE
- More map types (LRU, per-CPU, etc.)
- XDP and TC support
- Improved ring buffer implementation
- More examples
- Better documentation

## License

Copyright © 2024

Distributed under the Eclipse Public License version 1.0.

## References

- [BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf](https://github.com/libbpf/libbpf)
- [BPF Features by Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [eBPF Summit](https://ebpf.io/summit-2024/)

## Acknowledgments

Inspired by:
- [libbpf](https://github.com/libbpf/libbpf) - The C library for BPF
- [aya](https://github.com/aya-rs/aya) - Rust BPF library
- [bcc](https://github.com/iovisor/bcc) - BPF Compiler Collection
- [gobpf](https://github.com/iovisor/gobpf) - Go BPF library
