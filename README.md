# clj-ebpf

Complete eBPF (Extended Berkeley Packet Filter) programming library for Clojure with minimal dependencies.

## Overview

clj-ebpf provides idiomatic Clojure APIs for loading, managing, and interacting with eBPF programs and maps. It uses direct syscall interface via Java's Panama Foreign Function & Memory API (FFI) for zero external dependencies and maximum control.

## Features

### Current (MVP)
- ✅ Direct `bpf()` syscall interface using Panama FFI (Java 25+)
- ✅ BPF map operations (create, lookup, update, delete, iterate)
  - Hash maps
  - Array maps
  - Ring buffer maps
  - **LRU (Least Recently Used) hash maps**
  - **Per-CPU maps** (hash, array, LRU for zero-contention multi-core performance)
  - **Stack maps** (LIFO semantics)
  - **Queue maps** (FIFO semantics)
  - **LPM Trie maps** (Longest Prefix Match for routing/CIDR lookups)
- ✅ BPF program loading
- ✅ Kprobe/Kretprobe attachment
- ✅ Tracepoint attachment
- ✅ Raw tracepoint attachment (fully working alternative to kprobes)
- ✅ **Enhanced ring buffer event processing**
  - Memory-mapped ring buffers for zero-copy event reading
  - Epoll-based event notification (efficient waiting)
  - Batch event reading
  - Event filtering and transformation pipelines
  - Real-time statistics and monitoring
  - Consumer lifecycle management with automatic cleanup
- ✅ Map pinning to BPF filesystem (with data persistence)
- ✅ Program pinning
- ✅ Idiomatic Clojure APIs
- ✅ Resource management macros (`with-map`, `with-program`)
- ✅ Comprehensive error handling
- ✅ **Batch map operations** (lookup, update, delete with graceful fallback)
- ✅ **Per-CPU value aggregation helpers** (sum, max, min, avg)
- ✅ **ELF object file parsing** (extract programs and maps from compiled .o files)
- ✅ **TC (Traffic Control) support**
  - Clsact qdisc management
  - TC filter attachment (ingress/egress)
  - TC program loading (:sched-cls, :sched-act)
  - Priority-based filter management
  - Automatic resource cleanup with macros
- ✅ **Cgroup (Control Groups) attachment**
  - BPF program attachment to cgroups (v2)
  - Support for all cgroup program types (skb, sock, device, sysctl)
  - Container and process-level control
  - Cgroup FD management and utilities
  - High-level convenience functions and macros
- ✅ **Perf event buffers**
  - Legacy event streaming mechanism (compatible with all kernels)
  - Per-CPU perf event buffers with memory mapping
  - perf_event_open syscall wrapper
  - Event record parsing (PERF_RECORD_SAMPLE, PERF_RECORD_LOST)
  - Polling-based event consumption with statistics
  - Integration with BPF perf event array maps
- ✅ **LSM (Linux Security Modules) hooks**
  - BPF program attachment to LSM hook points
  - 30+ LSM hooks across categories (file-system, process, network, credentials, mount)
  - BPF_LINK_CREATE for LSM attachment
  - Hook categorization and introspection utilities
  - High-level convenience functions and macros
  - Security policy enforcement at kernel level
- ✅ **BTF (BPF Type Format) support**
  - Complete BTF file parsing (/sys/kernel/btf/vmlinux)
  - All 19 BTF type kinds supported (INT, PTR, ARRAY, STRUCT, UNION, ENUM, FUNC, etc.)
  - Type introspection (find types by name/ID, get struct members, enum values)
  - Type resolution through typedef/const/volatile indirections
  - Function signature discovery
  - Foundation for CO-RE (Compile Once - Run Everywhere)
- ✅ **BPF DSL (Domain-Specific Language)**
  - Idiomatic Clojure syntax for BPF programming
  - Complete instruction set support (ALU, ALU64, JMP, JMP32, LD, LDX, ST, STX)
  - 50+ instruction builder functions (mov, add, sub, jmp, ldx, stx, etc.)
  - Register abstraction (r0-r10 with symbolic names)
  - Helper function IDs (40+ helpers)
  - XDP and TC action codes
  - Compile DSL to BPF bytecode at runtime
  - Rapid prototyping and dynamic code generation
  - CO-RE helpers for portable code generation
- ✅ **CO-RE (Compile Once - Run Everywhere)**
  - Full support for all 13 CO-RE relocation kinds
  - Field offset, size, existence, and signedness relocations
  - Type-based relocations (exists, size, matches)
  - Enum value relocations
  - BTF-based field resolution
  - DSL helpers for generating relocatable code
  - Portable BPF programs across kernel versions
- ✅ **285+ tests with comprehensive assertions - all passing**

### Planned (Future Phases)
- ✅ **XDP (eXpress Data Path) support** (network interface utilities, attachment/detachment)
- ✅ **ELF object file parsing** (load compiled BPF programs from .o files)
- ✅ **TC (Traffic Control) support** (complete)
- ✅ **Cgroup attachment** (complete)
- ✅ **Perf event buffers** (complete)
- ✅ **LSM (Linux Security Modules) hooks** (complete)
- ✅ **BTF (BPF Type Format) support** (complete)
- ✅ **BPF assembly DSL** (complete)
- ✅ **CO-RE (Compile Once - Run Everywhere)** (complete)
- ⏳ C compilation integration

## Requirements

### System Requirements
- **Linux kernel**: 4.14+ (5.8+ recommended for full features)
- **Capabilities**: `CAP_BPF` and `CAP_PERFMON` (or root)
- **BPF filesystem**: Mounted at `/sys/fs/bpf`
- **Tracefs**: Mounted at `/sys/kernel/debug/tracing` (for kprobes/tracepoints)

### Dependencies
- **Clojure**: 1.12.0+
- **Java**: 25+ (required for Panama FFI)
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
(def lru-map (bpf/create-lru-hash-map 100 :map-name "my_lru")) ; Auto-evicts LRU entries
```

### Batch Operations

```clojure
(require '[clj-ebpf.core :as bpf])

(bpf/with-map [m (bpf/create-hash-map 1000 :map-name "batch_demo")]
  ;; Batch update - more efficient than individual updates
  (let [entries (for [i (range 100)] [i (* i 2)])]
    (bpf/map-update-batch m entries))

  ;; Batch lookup - retrieve multiple keys at once
  (let [keys (range 10 20)
        results (bpf/map-lookup-batch m keys)]
    (doseq [[k v] results]
      (println k "=>" v)))

  ;; Batch delete - remove multiple keys efficiently
  (bpf/map-delete-batch m (range 50 60))

  ;; Batch lookup and delete - atomic operation
  (let [keys (range 0 10)
        results (bpf/map-lookup-and-delete-batch m keys)]
    ;; Returns values and deletes keys in one operation
    (println "Deleted:" (count results) "entries")))

;; Note: Batch operations automatically fall back to individual operations
;; on kernels that don't support batch APIs (< 5.6)
```

### Per-CPU Maps

```clojure
(require '[clj-ebpf.core :as bpf])

;; Per-CPU maps eliminate contention on multi-core systems
;; Each CPU has its own independent value for each key

;; Per-CPU hash map
(bpf/with-map [m (bpf/create-percpu-hash-map 100 :map-name "percpu_counters")]
  ;; Insert a single value (replicated to all CPUs)
  (bpf/map-update m 1 0)

  ;; Or insert per-CPU values (vector, one per CPU)
  (let [num-cpus (bpf/get-cpu-count)
        percpu-values (vec (range num-cpus))]
    (bpf/map-update m 2 percpu-values))

  ;; Lookup returns a vector of values (one per CPU)
  (let [values (bpf/map-lookup m 1)]
    (println "Per-CPU values:" values)

    ;; Aggregate across CPUs
    (println "Sum across CPUs:" (bpf/percpu-sum values))
    (println "Max across CPUs:" (bpf/percpu-max values))
    (println "Min across CPUs:" (bpf/percpu-min values))
    (println "Avg across CPUs:" (bpf/percpu-avg values))))

;; Per-CPU array map
(bpf/with-map [arr (bpf/create-percpu-array-map 10 :map-name "percpu_array")]
  ;; Array indices are 0 to max-entries-1
  (bpf/map-update arr 0 100)
  (println "CPU values:" (bpf/map-lookup arr 0)))

;; Per-CPU LRU hash map (automatic eviction)
(bpf/with-map [lru (bpf/create-lru-percpu-hash-map 100 :map-name "percpu_lru")]
  (bpf/map-update lru 1 42)
  (println "LRU per-CPU:" (bpf/map-lookup lru 1)))
```

**Note:** Per-CPU maps on systems with very high CPU counts (>16) may encounter memory management issues with Panama FFI. The library automatically handles this gracefully.

### Stack and Queue Maps

```clojure
(require '[clj-ebpf.core :as bpf])

;; Stack maps (LIFO - Last In First Out)
(bpf/with-map [stack (bpf/create-stack-map 100 :map-name "my_stack")]
  ;; Push values onto stack
  (bpf/stack-push stack 10)
  (bpf/stack-push stack 20)
  (bpf/stack-push stack 30)

  ;; Peek at top value without removing it
  (println "Top value:" (bpf/stack-peek stack))  ; => 30

  ;; Pop values in LIFO order
  (println (bpf/stack-pop stack))  ; => 30
  (println (bpf/stack-pop stack))  ; => 20
  (println (bpf/stack-pop stack))  ; => 10
  (println (bpf/stack-pop stack))) ; => nil (empty)

;; Queue maps (FIFO - First In First Out)
(bpf/with-map [queue (bpf/create-queue-map 100 :map-name "my_queue")]
  ;; Push values onto queue
  (bpf/queue-push queue 10)
  (bpf/queue-push queue 20)
  (bpf/queue-push queue 30)

  ;; Peek at front value without removing it
  (println "Front value:" (bpf/queue-peek queue))  ; => 10

  ;; Pop values in FIFO order
  (println (bpf/queue-pop queue))  ; => 10
  (println (bpf/queue-pop queue))  ; => 20
  (println (bpf/queue-pop queue))  ; => 30
  (println (bpf/queue-pop queue))) ; => nil (empty)
```

### LPM Trie Maps

```clojure
(require '[clj-ebpf.core :as bpf])

;; LPM Trie maps for longest prefix matching (e.g., IP routing)
(bpf/with-map [trie (bpf/create-lpm-trie-map 100 :map-name "routing_table")]
  ;; LPM tries have special key format:
  ;; - First 4 bytes: prefix length in bits
  ;; - Remaining bytes: prefix data (e.g., IP address)

  ;; Note: LPM trie operations currently require custom key serialization
  ;; for the prefix-length + data format. Full LPM examples coming soon!

  ;; Basic creation and configuration is supported
  (println "LPM trie created with" (:max-entries trie) "max entries"))
```

### XDP (eXpress Data Path)

XDP provides high-performance packet processing at the network interface driver level:

```clojure
(require '[clj-ebpf.xdp :as xdp]
         '[clj-ebpf.programs :as programs])

;; Get network interface information
(xdp/interface-name->index "eth0")
;; => 2

(xdp/interface-index->name 2)
;; => "eth0"

;; Simple XDP program that passes all packets
;; Returns XDP_PASS (2)
(def xdp-bytecode
  (byte-array [0xb7 0x00 0x00 0x00 0x02 0x00 0x00 0x00  ; mov r0, 2 (XDP_PASS)
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

;; Load XDP program
(def prog-fd (xdp/load-xdp-program xdp-bytecode
                                   :prog-name "xdp_pass"
                                   :license "GPL"))

;; Attach to network interface
;; Modes: :skb-mode (generic), :drv-mode (native), :hw-mode (hardware offload)
(xdp/attach-xdp "eth0" prog-fd [:drv-mode])

;; Later, detach the program
(xdp/detach-xdp "eth0" [:drv-mode])
(syscall/close-fd prog-fd)

;; Or use the convenience macro for automatic cleanup:
(xdp/with-xdp [ifindex (xdp/attach-xdp "eth0" prog-fd [:drv-mode])]
  ;; XDP program is active on interface
  (println "XDP program attached to interface" ifindex)
  ;; Do packet processing...
  )
;; Program automatically detached when leaving scope
```

**XDP Action Codes:**
- `XDP_ABORTED` (0) - Error occurred, drop packet
- `XDP_DROP` (1) - Drop packet
- `XDP_PASS` (2) - Pass packet to network stack
- `XDP_TX` (3) - Transmit packet back out same interface
- `XDP_REDIRECT` (4) - Redirect to different interface

**Note:** XDP attachment requires `CAP_NET_ADMIN` capability. Generic XDP (`:skb-mode`) works on all network interfaces, while native XDP (`:drv-mode`) requires driver support.

### TC (Traffic Control)

TC provides flexible packet filtering and traffic shaping at the Linux kernel level, with both ingress and egress attachment points:

```clojure
(require '[clj-ebpf.tc :as tc]
         '[clj-ebpf.programs :as programs])

;; Simple TC program that passes all packets
;; Returns TC_ACT_OK (0)
(def tc-bytecode
  (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00  ; mov r0, 0 (TC_ACT_OK)
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

;; Load TC program
(def prog-fd (tc/load-tc-program tc-bytecode :sched-cls
                                 :prog-name "tc_filter"
                                 :license "GPL"))

;; Add clsact qdisc to interface (required once per interface)
(tc/add-clsact-qdisc "eth0")

;; Attach filter to ingress (incoming packets)
(def ingress-info (tc/attach-tc-filter "eth0" prog-fd :ingress
                                       :prog-name "ingress_filter"
                                       :priority 1))
;; => {:ifindex 2 :direction :ingress :priority 1}

;; Attach filter to egress (outgoing packets)
(def egress-info (tc/attach-tc-filter "eth0" prog-fd :egress
                                      :prog-name "egress_filter"
                                      :priority 1))

;; Later, detach filters
(tc/detach-tc-filter (:ifindex ingress-info) (:direction ingress-info) (:priority ingress-info))
(tc/detach-tc-filter (:ifindex egress-info) (:direction egress-info) (:priority egress-info))

;; Remove clsact qdisc (removes all filters)
(tc/remove-clsact-qdisc "eth0")
(syscall/close-fd prog-fd)

;; Or use the convenience macro for automatic cleanup:
(tc/with-tc-filter [info (tc/attach-tc-filter "eth0" prog-fd :ingress)]
  ;; TC filter is active on interface
  (println "TC filter attached to interface" (:ifindex info))
  ;; Do packet processing...
  )
;; Filter automatically detached when leaving scope

;; High-level convenience functions:
(def setup (tc/setup-tc-ingress "eth0" tc-bytecode
                                :prog-name "my_ingress"
                                :priority 1))
;; => {:prog-fd 5 :filter-info {:ifindex 2 :direction :ingress :priority 1}}

;; Process packets...
(Thread/sleep 5000)

;; Cleanup
(tc/teardown-tc-filter setup)
```

**TC Action Codes:**
- `TC_ACT_UNSPEC` (-1) - Continue with next rule
- `TC_ACT_OK` (0) - Pass packet
- `TC_ACT_RECLASSIFY` (1) - Reclassify packet
- `TC_ACT_SHOT` (2) - Drop packet
- `TC_ACT_PIPE` (3) - Continue with next action
- `TC_ACT_STOLEN` (4) - Consume packet
- `TC_ACT_QUEUED` (5) - Packet queued
- `TC_ACT_REPEAT` (6) - Repeat action
- `TC_ACT_REDIRECT` (7) - Redirect packet

**TC vs XDP:**
- **XDP**: Runs at driver level, highest performance, ingress only
- **TC**: Runs after driver, more flexible, supports both ingress and egress
- **Use XDP** for: High-speed packet filtering, DDoS mitigation
- **Use TC** for: More complex filtering, packet modification, QoS, egress filtering

**Note:** TC attachment requires `CAP_NET_ADMIN` capability. The `clsact` qdisc must be added before attaching filters, but `attach-tc-filter` does this automatically by default.

### Cgroup (Control Groups)

Attach BPF programs to cgroups for container and process-level control:

```clojure
(require '[clj-ebpf.cgroup :as cgroup]
         '[clj-ebpf.programs :as programs])

;; Check current process cgroup
(cgroup/get-current-cgroup)
;; => "/user.slice/user-1000.slice/session-3.scope"

;; Check if cgroup exists
(cgroup/cgroup-exists? "/sys/fs/cgroup")
;; => true

;; Simple cgroup SKB program (allow all incoming traffic)
;; Returns 1 (allow)
(def cgroup-bytecode
  (byte-array [0xb7 0x00 0x00 0x00 0x01 0x00 0x00 0x00  ; mov r0, 1 (allow)
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

;; Load cgroup SKB program
(def prog-fd (cgroup/load-cgroup-skb-program cgroup-bytecode :ingress
                                            :prog-name "cgroup_ingress"
                                            :license "GPL"))

;; Attach to a cgroup (e.g., Docker container cgroup)
(def info (cgroup/attach-cgroup-program "/sys/fs/cgroup/docker/container-id"
                                       prog-fd
                                       :cgroup-inet-ingress
                                       :flags :override))
;; => {:cgroup-path "/sys/fs/cgroup/docker/container-id"
;;     :attach-type :cgroup-inet-ingress
;;     :prog-fd 5}

;; Later, detach the program
(cgroup/detach-cgroup-program (:cgroup-path info)
                             (:attach-type info)
                             :prog-fd prog-fd)
(syscall/close-fd prog-fd)

;; Or use the convenience macro for automatic cleanup:
(cgroup/with-cgroup-program [info (cgroup/attach-cgroup-program
                                   "/sys/fs/cgroup"
                                   prog-fd
                                   :cgroup-inet-ingress)]
  ;; Program is attached to cgroup
  (println "Program attached to" (:cgroup-path info))
  ;; Do work...
  )
;; Program automatically detached when leaving scope

;; High-level convenience functions:
(def setup (cgroup/setup-cgroup-skb "/sys/fs/cgroup/my-container"
                                   cgroup-bytecode
                                   :ingress
                                   :prog-name "ingress_filter"
                                   :flags :override))
;; => {:prog-fd 5 :attach-info {...}}

;; Process traffic...
(Thread/sleep 5000)

;; Cleanup
(cgroup/teardown-cgroup-program setup)

;; Other cgroup program types:

;; Socket creation control
(def sock-prog (cgroup/load-cgroup-sock-program bytecode
                                               :prog-name "sock_filter"
                                               :license "GPL"))
(cgroup/attach-cgroup-program "/sys/fs/cgroup" sock-prog
                             :cgroup-inet-sock-create)

;; Device access control
(def device-prog (cgroup/load-cgroup-device-program bytecode
                                                   :prog-name "device_filter"
                                                   :license "GPL"))
(cgroup/attach-cgroup-program "/sys/fs/cgroup" device-prog
                             :cgroup-device)

;; Sysctl access control
(def sysctl-prog (cgroup/load-cgroup-sysctl-program bytecode
                                                   :prog-name "sysctl_filter"
                                                   :license "GPL"))
(cgroup/attach-cgroup-program "/sys/fs/cgroup" sysctl-prog
                             :cgroup-sysctl)

;; List child cgroups
(cgroup/list-cgroup-children "/sys/fs/cgroup")
;; => ["user.slice" "system.slice" "init.scope" ...]
```

**Cgroup Program Types:**
- **cgroup-skb** - Network packet filtering (ingress/egress)
- **cgroup-sock** - Socket creation, bind, connect control
- **cgroup-device** - Device access control (character/block devices)
- **cgroup-sysctl** - Sysctl parameter access control
- **cgroup-sockopt** - getsockopt/setsockopt control

**Common Attach Types:**
- `:cgroup-inet-ingress` - Incoming network packets
- `:cgroup-inet-egress` - Outgoing network packets
- `:cgroup-inet-sock-create` - Socket creation
- `:cgroup-device` - Device access
- `:cgroup-sysctl` - Sysctl access
- `:cgroup-inet4-bind` / `:cgroup-inet6-bind` - Socket bind operations
- `:cgroup-inet4-connect` / `:cgroup-inet6-connect` - Socket connect operations

**Use Cases:**
- **Container networking**: Filter/monitor traffic per container
- **Security policies**: Control device access, socket operations
- **Resource isolation**: Enforce network/device policies per cgroup
- **Multi-tenancy**: Different policies for different user groups
- **Compliance**: Audit and control system calls per process group

**Note:** Cgroup attachment requires `CAP_BPF` and `CAP_NET_ADMIN` capabilities. Cgroup v2 must be enabled (default on modern Linux systems).

### Enhanced Ring Buffer Event Processing

Efficient event reading from BPF ring buffers with memory mapping, epoll, and statistics:

```clojure
(require '[clj-ebpf.core :as bpf]
         '[clj-ebpf.events :as events])

;; Create a ring buffer map (4KB)
(def ringbuf (bpf/create-ringbuf-map (* 4 1024) :map-name "events"))

;; Define event structure (pid:u32, timestamp:u64, data:u32)
(def parse-event (bpf/make-event-parser [:u32 :u64 :u32]))

;; Create an event handler with filtering and transformation
(def handle-event
  (bpf/make-event-handler
    :parser parse-event
    :filter (fn [[pid ts data]] (> pid 1000))      ; Filter system pids
    :transform (fn [[pid ts data]]                  ; Transform to map
                {:pid pid
                 :timestamp ts
                 :data data})
    :handler println))                              ; Print events

;; Start a ring buffer consumer with automatic cleanup
(bpf/with-ringbuf-consumer [consumer {:map ringbuf
                                       :callback handle-event
                                       :deserializer identity}]
  ;; Consumer is running in background thread
  (println "Consumer started, waiting for events...")
  (Thread/sleep 5000)

  ;; Check statistics
  (let [stats (bpf/get-consumer-stats consumer)]
    (println "Events processed:" (:events-processed stats))
    (println "Events/sec:" (:events-per-second stats))
    (println "Batches read:" (:batches-read stats))
    (println "Errors:" (:errors stats))))
;; Consumer automatically stopped and cleaned up

;; Synchronous event processing
(def event-count
  (bpf/process-events ringbuf
                      #(println "Event:" %)
                      :max-events 100
                      :timeout-ms 5000
                      :deserializer parse-event))
(println "Processed" event-count "events")

;; Peek at events without consuming them
(let [events (bpf/peek-ringbuf-events ringbuf
                                      :max-events 10
                                      :deserializer parse-event)]
  (println "Next events in buffer:" events))
```

**Key Features:**
- **Memory-mapped ring buffers** - Zero-copy event reading directly from kernel memory
- **Epoll-based notification** - Efficient event waiting without busy polling
- **Batch reading** - Read multiple events in a single operation
- **Event pipelines** - Parser → Filter → Transform → Handler chains
- **Real-time statistics** - Track throughput, errors, and performance
- **Automatic resource management** - `with-ringbuf-consumer` macro ensures cleanup

### Perf Event Buffers

Alternative event streaming mechanism using Linux perf events (compatible with legacy BPF programs):

```clojure
(require '[clj-ebpf.perf :as perf]
         '[clj-ebpf.core :as bpf])

;; Create perf event array map (one entry per CPU)
(def cpu-count (bpf/get-cpu-count))
(def perf-map (perf/create-perf-event-array cpu-count
                                            :map-name "perf_events"))

;; Define event parser
(def parse-event (bpf/make-event-parser [:u32 :u64 :u32]))

;; Create perf event consumer
(def consumer (perf/create-perf-consumer
               :map perf-map
               :callback (fn [event]
                          (let [[pid ts data] (parse-event event)]
                            (println "Event:" {:pid pid :ts ts :data data})))
               :buffer-pages 64))  ; 64 pages per CPU (must be power of 2)

;; Start consuming events
(perf/start-perf-consumer consumer 100)  ; Poll every 100ms

;; BPF program can now send events using bpf_perf_event_output helper
;; (from BPF C code):
;; bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &data, sizeof(data));

;; Check statistics
(perf/get-perf-stats consumer)
;; => {:events-read 1000
;;     :events-processed 995
;;     :polls 50
;;     :errors 5
;;     :uptime-ms 5000
;;     :events-per-second 199.0}

;; Stop consumer and cleanup
(perf/stop-perf-consumer consumer)
(bpf/close-map perf-map)

;; Or use the convenience macro:
(perf/with-perf-consumer [consumer {:map perf-map :callback println}]
  (perf/start-perf-consumer consumer)
  (Thread/sleep 5000)
  (println "Stats:" (perf/get-perf-stats consumer)))
;; Consumer automatically stopped and cleaned up
```

**Perf vs Ring Buffers:**
- **Ring Buffers** (modern, kernel 5.8+):
  - Zero-copy design
  - Single producer, single consumer per CPU
  - Memory mapped for efficiency
  - Preferred for new programs

- **Perf Event Buffers** (legacy, all kernels):
  - Compatible with older kernels
  - Widely used in existing BPF programs
  - Per-CPU circular buffers
  - Poll-based event consumption
  - Use for compatibility with legacy code

**Key Features:**
- Per-CPU perf event buffers
- Memory-mapped buffer access
- Event record parsing (PERF_RECORD_SAMPLE, PERF_RECORD_LOST)
- Polling-based event consumption
- Real-time statistics tracking
- Automatic buffer management

**Note:** Perf event operations require `CAP_PERFMON` or `CAP_SYS_ADMIN` capability.

### LSM (Linux Security Modules) Hooks

Implement security policies by attaching BPF programs to LSM hook points in the Linux kernel:

```clojure
(require '[clj-ebpf.lsm :as lsm]
         '[clj-ebpf.core :as bpf])

;; Check if LSM BPF is available on the system
(lsm/lsm-available?)
;; => true (if kernel 5.7+ with LSM BPF enabled)

;; List all available LSM hook points
(lsm/list-lsm-hooks)
;; => [:file-open :file-permission :bprm-check-security :socket-create ...]

;; List hooks by category
(lsm/list-hooks-by-category :file-system)
;; => [:file-open :file-permission :inode-create :inode-unlink ...]

(lsm/list-hooks-by-category :network)
;; => [:socket-create :socket-bind :socket-connect :socket-listen ...]

;; Get category for a specific hook
(lsm/get-hook-category :file-open)
;; => :file-system

;; Simple LSM program that allows all operations
;; Returns 0 (allow)
(def lsm-bytecode
  (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00  ; mov r0, 0 (allow)
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

;; Load LSM program for file_open hook
(def prog-fd (lsm/load-lsm-program lsm-bytecode :file-open
                                   :prog-name "file_open_monitor"
                                   :license "GPL"))

;; Attach LSM program to hook point
(def link-info (lsm/attach-lsm-program prog-fd))
;; => {:prog-fd 5 :link-fd 6}

;; LSM program is now active, monitoring file open operations

;; Later, detach the program
(lsm/detach-lsm-program link-info)
(bpf/close-program {:fd prog-fd})

;; Or use the convenience macro for automatic cleanup:
(lsm/with-lsm-program [info (lsm/attach-lsm-program prog-fd)]
  ;; LSM program is active
  (println "LSM program attached")
  ;; Do work...
  (Thread/sleep 5000))
;; Program automatically detached when leaving scope

;; High-level convenience function (load + attach):
(def setup (lsm/setup-lsm-hook lsm-bytecode :file-open
                              :prog-name "file_monitor"))
;; => {:prog-fd 5 :link-fd 6 :hook :file-open}

;; Monitor file operations for 10 seconds
(Thread/sleep 10000)

;; Cleanup
(lsm/teardown-lsm-hook setup)

;; Or use with-lsm-hook macro:
(lsm/with-lsm-hook [setup (lsm/setup-lsm-hook bytecode :socket-create
                                              :prog-name "socket_monitor")]
  ;; LSM hook is active
  (println "Monitoring socket creation")
  (Thread/sleep 10000))
;; Automatically detached and cleaned up
```

**LSM Hook Categories:**

- **File System** (`:file-system`):
  - `:file-open`, `:file-permission`, `:file-ioctl`, `:file-lock`
  - `:inode-create`, `:inode-link`, `:inode-unlink`, `:inode-mkdir`
  - `:inode-rename`, `:inode-permission`, `:inode-setattr`

- **Process** (`:process`):
  - `:bprm-check-security` - Program execution security check
  - `:task-kill` - Signal sending control
  - `:task-setpgid`, `:task-getpgid` - Process group operations
  - `:task-alloc`, `:task-free` - Task lifecycle

- **Network** (`:network`):
  - `:socket-create`, `:socket-bind`, `:socket-connect`
  - `:socket-listen`, `:socket-accept`
  - `:socket-sendmsg`, `:socket-recvmsg`

- **Credentials** (`:credentials`):
  - `:cred-prepare` - Credential preparation

- **Mount** (`:mount`):
  - `:sb-mount`, `:sb-umount`, `:sb-pivotroot`

**LSM Return Codes:**
```clojure
;; From your BPF program, return:
0   ; Allow the operation (lsm/lsm-return-code :allow)
-1  ; Deny the operation (lsm/lsm-return-code :deny) - returns EPERM
```

**Use Cases:**
- **Security monitoring**: Audit file access, socket operations
- **Access control**: Block unauthorized file/network operations
- **Compliance**: Enforce security policies at kernel level
- **Container security**: Monitor/restrict container operations
- **Threat detection**: Real-time detection of suspicious behavior
- **Policy enforcement**: MAC (Mandatory Access Control) policies

**Example - File Access Monitor:**
```clojure
;; BPF program that logs all file open attempts (in C):
;; SEC("lsm/file_open")
;; int BPF_PROG(file_open_monitor, struct file *file)
;; {
;;     // Log file path, process info
;;     bpf_printk("File opened: %s\n", file->f_path.dentry->d_name.name);
;;     return 0; // Allow
;; }

;; Load and attach from Clojure:
(def file-monitor (lsm/setup-lsm-hook compiled-bytecode :file-open
                                     :prog-name "file_access_audit"))
;; Now monitoring all file opens system-wide
```

**Example - Socket Creation Control:**
```clojure
;; Deny socket creation for specific protocols
;; (compile with clang -target bpf -O2 -c)
(def socket-filter (lsm/setup-lsm-hook bytecode :socket-create
                                      :prog-name "socket_policy"))
;; Enforce socket creation policy
```

**Important Notes:**
- Requires kernel 5.7+ with LSM BPF enabled (`CONFIG_BPF_LSM=y`)
- Requires `CAP_BPF` and `CAP_SYS_ADMIN` capabilities
- LSM programs run on every security check - keep them efficient
- Use BPF_LINK_CREATE for attachment (automatic with this library)
- Programs must return 0 (allow) or negative errno (deny)
- Test thoroughly - incorrect LSM programs can break system operations

**Checking LSM BPF Support:**
```bash
# Check if LSM BPF is enabled
cat /sys/kernel/security/lsm
# Should include "bpf" in the list

# Check kernel config
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
# Should show CONFIG_BPF_LSM=y
```

### BTF (BPF Type Format)

Parse and introspect kernel type information using BTF for type-aware BPF programs:

```clojure
(require '[clj-ebpf.btf :as btf])

;; Check if BTF is available on the system
(btf/btf-available?)
;; => true (if kernel has BTF support)

;; Load BTF data from kernel
(def btf-data (btf/load-btf-file))
;; Or from custom path:
;; (def btf-data (btf/load-btf-file "/path/to/btf/file"))

;; Explore loaded BTF data
(println "Total types:" (count (:types btf-data)))
;; => Total types: 15234

(println "String table entries:" (count (:strings btf-data)))
;; => String table entries: 8421

;; Find a kernel struct by name
(def task-struct (btf/find-type-by-name btf-data "task_struct"))
(println "task_struct:" task-struct)
;; => {:kind :struct :id 1234 :name-off 5678 :size 9024 :members [...]}

;; Get struct members with names
(def members (btf/get-struct-members btf-data task-struct))
(doseq [member (take 5 members)]
  (println "  " (:name member) "- type" (:type member) "offset" (:bit-offset member)))
;; =>   state - type 42 offset 0
;;      usage - type 128 offset 64
;;      flags - type 31 offset 128
;;      ...

;; Get type size in bytes
(btf/get-type-size btf-data (:id task-struct))
;; => 9024

;; List all types of a specific kind
(def all-structs (btf/list-types btf-data :struct))
(println "Number of structs:" (count all-structs))
;; => Number of structs: 2341

(def all-funcs (btf/list-types btf-data :func))
(println "Number of functions:" (count all-funcs))
;; => Number of functions: 15678

;; Find and inspect a kernel function
(def schedule-func (btf/find-function btf-data "schedule"))
(println "Function:" (btf/get-type-name btf-data schedule-func))
;; => Function: schedule

;; Get function signature
(def sig (btf/get-function-signature btf-data schedule-func))
(println "Return type:" (:return-type sig))
(println "Parameters:" (:params sig))
;; => Return type: 0 (void)
;;    Parameters: []

;; Get enum values
(def enums (btf/list-types btf-data :enum))
(when (seq enums)
  (let [enum-type (first enums)
        values (btf/get-enum-values btf-data enum-type)]
    (println "Enum:" (btf/get-type-name btf-data enum-type))
    (doseq [v (take 3 values)]
      (println "  " (:name v) "=" (:val v)))))

;; Resolve types through typedef/const/volatile indirections
(def typedef-id 500)
(def resolved-id (btf/resolve-type btf-data typedef-id))
(println "Typedef" typedef-id "resolves to" resolved-id)

;; Get type by ID
(def type-info (btf/get-type-by-id btf-data 42))
(println "Type kind:" (:kind type-info))
(println "Type name:" (btf/get-type-name btf-data type-info))
```

**BTF Type Kinds (19 total):**
- **INT**: Integer types (signed, unsigned, char, bool)
- **PTR**: Pointer types
- **ARRAY**: Array types
- **STRUCT**: Structure definitions
- **UNION**: Union types
- **ENUM**: 32-bit enumerations
- **ENUM64**: 64-bit enumerations
- **FWD**: Forward declarations
- **TYPEDEF**: Type aliases
- **VOLATILE**: Volatile qualifiers
- **CONST**: Const qualifiers
- **RESTRICT**: Restrict qualifiers
- **FUNC**: Function definitions
- **FUNC_PROTO**: Function prototypes
- **VAR**: Variable declarations
- **DATASEC**: Data sections
- **FLOAT**: Floating-point types
- **DECL_TAG**: Declaration tags
- **TYPE_TAG**: Type tags

**Use Cases:**
- **Type-aware debugging**: Understand kernel data structures
- **CO-RE (Compile Once - Run Everywhere)**: Portable BPF programs
- **Struct layout introspection**: Field offsets and sizes
- **Function signature discovery**: Parameter and return types
- **Automatic code generation**: Generate bindings from BTF
- **BPF verifier hints**: Provide type information for verification

**Example - Inspect task_struct:**
```clojure
(def btf-data (btf/load-btf-file))

;; Find task_struct
(def task-struct (btf/find-type-by-name btf-data "task_struct"))
(println "task_struct size:" (btf/get-type-size btf-data (:id task-struct)) "bytes")

;; Get all members
(def members (btf/get-struct-members btf-data task-struct))
(println "task_struct has" (count members) "members")

;; Find specific member
(def state-member (first (filter #(= "state" (:name %)) members)))
(println "state field:")
(println "  Type ID:" (:type state-member))
(println "  Bit offset:" (:bit-offset state-member))
(println "  Byte offset:" (/ (:bit-offset state-member) 8))
```

**Example - Find all network-related structs:**
```clojure
(def btf-data (btf/load-btf-file))

;; Find all structs with "sock" in the name
(def sock-structs
  (filter #(and (= :struct (:kind %))
               (when-let [name (btf/get-type-name btf-data %)]
                 (re-find #"sock" name)))
          (:types btf-data)))

(println "Found" (count sock-structs) "socket-related structs:")
(doseq [s (take 10 sock-structs)]
  (println "  -" (btf/get-type-name btf-data s)
           "size:" (btf/get-type-size btf-data (:id s)) "bytes"))
```

**Important Notes:**
- BTF requires kernel 4.18+ with `CONFIG_DEBUG_INFO_BTF=y`
- BTF data is typically available at `/sys/kernel/btf/vmlinux`
- File size is typically 5-10MB (compressed type information)
- BTF enables CO-RE (Compile Once - Run Everywhere) for portable BPF programs
- Use BTF to make your BPF programs kernel-version independent

**Checking BTF Support:**
```bash
# Check if BTF is available
ls -lh /sys/kernel/btf/vmlinux
# Should show a file (typically 5-10MB)

# Check kernel config
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
# Should show CONFIG_DEBUG_INFO_BTF=y

# View BTF information with bpftool (if available)
bpftool btf dump file /sys/kernel/btf/vmlinux format c | head -n 50
```

### CO-RE (Compile Once - Run Everywhere)

CO-RE enables BPF programs to be portable across different kernel versions by using BTF information to relocate field accesses and type information at load time. This eliminates the need to recompile BPF programs for each kernel version.

#### How CO-RE Works

1. **Compile**: Write BPF program using kernel structures (e.g., `task_struct->pid`)
2. **Relocate**: At load time, BTF info from target kernel adjusts field offsets
3. **Run**: Program works on any kernel with BTF support, regardless of struct layout

```clojure
(require '[clj-ebpf.relocate :as relocate]
         '[clj-ebpf.btf :as btf]
         '[clj-ebpf.dsl :as dsl])

;; Check if CO-RE is supported on this system
(relocate/core-read-supported?)
;; => true (if kernel BTF is available)

;; Load kernel BTF for relocations
(def kernel-btf (relocate/get-kernel-btf))
(println "Loaded" (count (:types kernel-btf)) "kernel types")
```

#### CO-RE Relocation Types

**Field-based relocations:**
```clojure
;; Get all relocation kinds
relocate/relocation-kind
;; => {:field-byte-offset 0    ; Field offset in bytes
;;     :field-byte-size 1      ; Field size in bytes
;;     :field-exists 2         ; Field existence (0 or 1)
;;     :field-signed 3         ; Field signedness
;;     :field-lshift-u64 4     ; Bitfield left shift
;;     :field-rshift-u64 5     ; Bitfield right shift
;;     ...}

;; Create a CO-RE relocation record
(def relo (relocate/create-relocation
            24        ; Instruction offset
            42        ; BTF type ID
            "0:1"     ; Field access path
            :field-byte-offset))
```

**Type-based relocations:**
```clojure
;; Type-related relocation kinds:
;; :type-id-local (6)    - Local BTF type ID
;; :type-id-target (7)   - Target kernel BTF type ID
;; :type-exists (8)      - Type existence check
;; :type-size (9)        - Type size in bytes
;; :type-matches (12)    - Type layout compatibility
```

**Enum-based relocations:**
```clojure
;; Enum relocation kinds:
;; :enumval-exists (10)  - Enum value existence
;; :enumval-value (11)   - Enum value integer value
```

#### DSL CO-RE Helpers

The DSL provides high-level helpers for generating relocatable code:

```clojure
(require '[clj-ebpf.dsl :as dsl])

;; Generate placeholder for field offset (relocated at load time)
(dsl/core-field-offset :r1 "task_struct" "pid")
;; => Generates MOV instruction with placeholder that gets relocated

;; Check if field exists in target kernel
(dsl/core-field-exists :r0 "task_struct" "new_field")
;; => Returns 1 if exists, 0 if not (at load time)

;; Get field size
(dsl/core-field-size :r1 "task_struct" "comm")
;; => Gets actual size of field in target kernel

;; Check type existence
(dsl/core-type-exists :r0 "struct bpf_map")
;; => Returns 1 if type exists in kernel, 0 otherwise

;; Get type size
(dsl/core-type-size :r1 "task_struct")
;; => Gets sizeof(task_struct) in target kernel

;; Get enum value
(dsl/core-enum-value :r0 "task_state" "TASK_RUNNING")
;; => Gets actual integer value of enum constant
```

#### Example: Portable Field Access

```clojure
;; Read task PID with CO-RE (portable across kernel versions)
(def portable-pid-reader
  (dsl/assemble [;; r1 = current task pointer (from context)
                 ;; Get offset of 'pid' field (relocated at load time)
                 (dsl/core-field-offset :r2 "task_struct" "pid")
                 ;; Add offset to task pointer: r1 = r1 + r2
                 (dsl/add-reg :r1 :r2)
                 ;; Load PID value: r0 = *(r1 + 0)
                 (dsl/ldx :w :r0 :r1 0)
                 (dsl/exit-insn)]))

;; This program works on any kernel with BTF, regardless of where
;; the 'pid' field is located in task_struct!
```

#### Example: Feature Detection

```clojure
;; Conditional code based on field existence
(def conditional-program
  (dsl/assemble [;; Check if new field exists
                 (dsl/core-field-exists :r0 "task_struct" "new_field")
                 ;; if r0 == 0 (field doesn't exist), use fallback
                 (dsl/jmp-imm :jeq :r0 0 2)
                 ;; New field exists - use it
                 (dsl/core-field-offset :r1 "task_struct" "new_field")
                 (dsl/ja 1)  ; Jump over fallback
                 ;; Fallback for older kernels
                 (dsl/core-field-offset :r1 "task_struct" "old_field")
                 ;; Continue with program
                 (dsl/ldx :w :r0 :r1 0)
                 (dsl/exit-insn)]))
```

#### Applying CO-RE Relocations

```clojure
;; Example: Apply relocations to BPF program at load time
(def local-btf (btf/load-btf-file "/path/to/program.btf"))  ; From compiler
(def target-btf (relocate/get-kernel-btf))  ; From target kernel

;; Create relocation records (normally from compiler/ELF)
(def relocations
  [(relocate/create-relocation 24 42 "0" :field-byte-offset)
   (relocate/create-relocation 32 42 "1" :field-byte-offset)])

;; Apply all relocations to program bytecode
(def relocated-insns
  (relocate/apply-relocations program-bytecode
                             relocations
                             local-btf
                             target-btf))

;; Now load the relocated program
(def prog-fd (bpf/load-program relocated-insns
                              :prog-type :kprobe
                              :license "GPL"))
```

#### Example: BPF_CORE_READ Pattern

```clojure
;; Generate safe nested field access with CO-RE
(def core-read-seq
  (dsl/generate-core-read :r0  ; Destination register
                          :r1  ; Source pointer register
                          {:struct-name "task_struct"
                           :field-name "pid"}))

;; Expands to:
;; - Save source pointer
;; - Get field offset (relocated)
;; - Add offset to pointer
;; - Load value
(def program (dsl/assemble core-read-seq))
```

#### CO-RE Use Cases

**1. Kernel Version Independence:**
- Write once, run on any kernel with BTF (4.18+)
- No need for kernel headers at runtime
- Automatic struct layout adaptation

**2. Feature Detection:**
- Check field/type existence at load time
- Gracefully handle kernel variations
- Support multiple kernel configurations

**3. Debugging & Development:**
- Faster development cycle (no recompilation)
- Single binary for multiple kernels
- Easier distribution and deployment

**4. Production Deployment:**
- Deploy same BPF program across fleet
- Support kernel upgrades without redeployment
- Reduce maintenance burden

#### CO-RE Limitations

- **Requires BTF**: Kernel must be compiled with `CONFIG_DEBUG_INFO_BTF=y`
- **Field semantics**: CO-RE relocates offsets, not field meaning
- **Type changes**: Cannot handle semantic type changes (e.g., field type change)
- **Struct reorganization**: Works for field movement, not complete restructuring

#### Example: Production CO-RE Program

```clojure
(defn create-portable-tracer
  "Create a tracer that works across kernel versions using CO-RE."
  []
  (let [program
        (dsl/assemble [;; Check if we have the new field
                       (dsl/core-field-exists :r6 "task_struct" "pids")
                       (dsl/jmp-imm :jne :r6 0 3)  ; If exists, use new path

                       ;; Old kernel path (pre-4.x)
                       (dsl/core-field-offset :r2 "task_struct" "pid")
                       (dsl/add-reg :r1 :r2)
                       (dsl/ja 2)  ; Skip new path

                       ;; New kernel path (4.x+)
                       (dsl/core-field-offset :r2 "task_struct" "pids")
                       (dsl/add-reg :r1 :r2)

                       ;; Common path: r1 now points to PID location
                       (dsl/ldx :w :r0 :r1 0)
                       (dsl/exit-insn)])]

    ;; Apply relocations if BTF is available
    (if (relocate/core-read-supported?)
      (let [kernel-btf (relocate/get-kernel-btf)
            ;; In real code, local-btf would come from compiler
            local-btf kernel-btf]
        ;; Apply relocations (in real code, get relocations from ELF)
        program)
      ;; Fall back to non-CO-RE program
      (throw (ex-info "BTF not available for CO-RE"
                     {:available (relocate/core-read-supported?)})))))

;; Use the tracer
(def tracer (create-portable-tracer))
```

**Key Points:**
- CO-RE requires kernel BTF (4.18+)
- Enables true "compile once, run everywhere" for BPF
- Relocations happen at program load time
- Supports field offsets, sizes, existence checks, and more
- Essential for production BPF deployments

### BPF DSL (Domain-Specific Language)

Write BPF programs using idiomatic Clojure syntax instead of raw bytecode:

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.core :as bpf])

;; Simple XDP program that passes all packets
(def xdp-pass-program
  (dsl/assemble [(dsl/mov :r0 (:pass dsl/xdp-action))
                 (dsl/exit-insn)]))

;; Load and attach the program
(def prog-fd (bpf/load-program xdp-pass-program
                              :prog-type :xdp
                              :license "GPL"))
(bpf/attach-xdp "eth0" prog-fd [:drv-mode])

;; Example: XDP program that drops all packets
(def xdp-drop-all
  (dsl/assemble [(dsl/mov :r0 (:drop dsl/xdp-action))
                 (dsl/exit-insn)]))

;; Example: Arithmetic operations
(def arithmetic-program
  (dsl/assemble [;; r0 = 100
                 (dsl/mov :r0 100)
                 ;; r1 = 50
                 (dsl/mov :r1 50)
                 ;; r0 += r1 (r0 = 150)
                 (dsl/add-reg :r0 :r1)
                 ;; return r0
                 (dsl/exit-insn)]))

;; Example: Bitwise operations
(def bitwise-program
  (dsl/assemble [;; r0 = 0xFF
                 (dsl/mov :r0 0xFF)
                 ;; r0 &= 0x0F (mask lower 4 bits)
                 (dsl/and-op :r0 0x0F)
                 ;; r0 <<= 4 (shift left 4 bits)
                 (dsl/lsh :r0 4)
                 (dsl/exit-insn)]))

;; Example: Load from memory
(def load-store-program
  (dsl/assemble [;; Load 8 bytes from r10-8 into r0
                 (dsl/ldx :dw :r0 :r10 -8)
                 ;; Increment r0
                 (dsl/add :r0 1)
                 ;; Store r0 back to r10-8
                 (dsl/stx :dw :r10 :r0 -8)
                 (dsl/exit-insn)]))

;; Example: Conditional jump
(def conditional-program
  (dsl/assemble [;; r0 = 10
                 (dsl/mov :r0 10)
                 ;; if r0 == 10 jump forward 1 instruction
                 (dsl/jmp-imm :jeq :r0 10 1)
                 ;; This instruction is skipped
                 (dsl/mov :r0 0)
                 ;; return
                 (dsl/exit-insn)]))

;; Example: BPF helper function call
(def helper-call-program
  (dsl/assemble [;; Call ktime_get_ns() helper
                 (dsl/call (:ktime-get-ns dsl/bpf-helpers))
                 ;; Result is in r0, return it
                 (dsl/exit-insn)]))

;; Example: 64-bit immediate load (wide instruction)
(def wide-immediate-program
  (dsl/assemble [;; Load 64-bit value into r0
                 (dsl/lddw :r0 0x123456789ABCDEF0)
                 (dsl/exit-insn)]))

;; Example: TC program that allows all packets
(def tc-pass-program
  (dsl/assemble [(dsl/mov :r0 (:ok dsl/tc-action))
                 (dsl/exit-insn)]))

;; Example: TC program that drops all packets
(def tc-drop-program
  (dsl/assemble [(dsl/mov :r0 (:shot dsl/tc-action))
                 (dsl/exit-insn)]))
```

**Available Instructions:**

**ALU Operations (64-bit):**
- `(mov :r0 42)` - Move immediate to register
- `(mov-reg :r0 :r1)` - Move register to register
- `(add :r0 10)` - Add immediate
- `(add-reg :r0 :r1)` - Add register
- `(sub :r0 5)` - Subtract immediate
- `(sub-reg :r0 :r1)` - Subtract register
- `(mul :r0 2)` - Multiply by immediate
- `(mul-reg :r0 :r1)` - Multiply by register
- `(and-op :r0 0xFF)` - Bitwise AND
- `(and-reg :r0 :r1)` - Bitwise AND with register
- `(or-op :r0 0x10)` - Bitwise OR
- `(or-reg :r0 :r1)` - Bitwise OR with register
- `(xor-op :r0 0xFF)` - Bitwise XOR
- `(xor-reg :r0 :r1)` - Bitwise XOR with register
- `(lsh :r0 8)` - Left shift
- `(lsh-reg :r0 :r1)` - Left shift by register
- `(rsh :r0 8)` - Right shift (logical)
- `(rsh-reg :r0 :r1)` - Right shift by register
- `(arsh :r0 8)` - Arithmetic right shift
- `(neg-reg :r0)` - Negate

**Jump Operations:**
- `(ja offset)` - Unconditional jump
- `(jmp-imm :jeq :r0 0 offset)` - Jump if equal (immediate)
- `(jmp-reg :jeq :r0 :r1 offset)` - Jump if equal (register)
- `(jmp-imm :jgt :r0 100 offset)` - Jump if greater (unsigned)
- `(jmp-imm :jge :r0 100 offset)` - Jump if greater or equal
- `(jmp-imm :jlt :r0 100 offset)` - Jump if less than
- `(jmp-imm :jle :r0 100 offset)` - Jump if less or equal
- `(jmp-imm :jne :r0 0 offset)` - Jump if not equal
- `(jmp-imm :jset :r0 0x10 offset)` - Jump if bitwise AND non-zero
- `(call helper-id)` - Call BPF helper function
- `(exit-insn)` - Exit program

**Load/Store Operations:**
- `(ldx :dw :r0 :r1 4)` - Load 8 bytes: r0 = *(u64*)(r1 + 4)
- `(ldx :w :r0 :r1 0)` - Load 4 bytes: r0 = *(u32*)(r1 + 0)
- `(ldx :h :r0 :r1 0)` - Load 2 bytes: r0 = *(u16*)(r1 + 0)
- `(ldx :b :r0 :r1 0)` - Load 1 byte: r0 = *(u8*)(r1 + 0)
- `(stx :dw :r1 :r0 4)` - Store 8 bytes: *(u64*)(r1 + 4) = r0
- `(stx :w :r1 :r0 0)` - Store 4 bytes: *(u32*)(r1 + 0) = r0
- `(st :dw :r1 4 42)` - Store immediate: *(u64*)(r1 + 4) = 42
- `(lddw :r0 0x123...)` - Load 64-bit immediate (wide instruction)

**Registers:**
- `:r0` - Return value / exit code
- `:r1` - `:r5` - Function arguments (scratch)
- `:r6` - `:r9` - Callee-saved
- `:r10` - Read-only frame pointer

**Action Codes:**
- XDP: `:aborted`, `:drop`, `:pass`, `:tx`, `:redirect`
- TC: `:unspec`, `:ok`, `:reclassify`, `:shot`, `:pipe`, `:stolen`, `:queued`, `:repeat`, `:redirect`

**BPF Helpers:**
Access via `dsl/bpf-helpers`:
- `:map-lookup-elem`, `:map-update-elem`, `:map-delete-elem`
- `:ktime-get-ns`, `:trace-printk`
- `:get-current-pid-tgid`, `:get-current-uid-gid`, `:get-current-comm`
- `:perf-event-output`
- And 40+ more helpers

**Example - Complete XDP Packet Filter:**
```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.xdp :as xdp])

;; XDP program that passes packets > 60 bytes, drops others
(def xdp-size-filter
  (dsl/assemble [;; r2 = ctx->data_end
                 (dsl/ldx :w :r2 :r1 4)
                 ;; r3 = ctx->data
                 (dsl/ldx :w :r3 :r1 0)
                 ;; r3 = data_end - data (packet size)
                 (dsl/sub-reg :r2 :r3)
                 ;; if size > 60 goto pass
                 (dsl/jmp-imm :jgt :r2 60 1)
                 ;; Drop (r0 = XDP_DROP)
                 (dsl/mov :r0 (:drop dsl/xdp-action))
                 (dsl/exit-insn)
                 ;; Pass (r0 = XDP_PASS)
                 (dsl/mov :r0 (:pass dsl/xdp-action))
                 (dsl/exit-insn)]))

;; Load and attach
(def prog-fd (load-program xdp-size-filter
                          :prog-type :xdp
                          :license "GPL"))
(xdp/attach-xdp "eth0" prog-fd [:drv-mode])
```

**Use Cases:**
- **Rapid prototyping**: Write BPF programs interactively in REPL
- **Dynamic program generation**: Generate BPF code at runtime
- **Learning**: Understand BPF instructions with readable syntax
- **Testing**: Create test programs easily
- **Macro generation**: Build higher-level abstractions on top of DSL

#### Comprehensive DSL Examples

The `clj-ebpf.examples` namespace provides 25+ ready-to-use example programs demonstrating the full DSL capabilities. All examples are production-quality with detailed documentation.

```clojure
(require '[clj-ebpf.examples :as examples])

;; List all available examples
(examples/list-examples)

;; Get bytecode for a specific example
(def bytecode (examples/get-example :xdp-tcp-port-filter))

;; Load and use an example
(def prog-fd (bpf/load-program (examples/get-example :xdp-pass-all)
                               :prog-type :xdp
                               :license "GPL"))
```

**Available Example Categories:**

**Basic XDP Examples:**
- `:xdp-pass-all` - Pass all packets (simplest XDP program)
- `:xdp-drop-all` - Drop all packets at driver level
- `:xdp-packet-size-filter` - Filter packets by size (>60 bytes)
- `:xdp-aborted-on-error` - Return XDP_ABORTED for error signaling

**Packet Parsing Examples:**
- `:xdp-ethernet-parser` - Parse and validate Ethernet headers
- `:xdp-ethertype-filter` - Filter by EtherType (IPv4 only)
- `:xdp-ipv4-parser` - Parse and validate IPv4 headers
- `:xdp-ip-protocol-filter` - Filter by IP protocol (TCP only)

**Port Filtering Examples:**
- `:xdp-tcp-port-filter` - Filter HTTP traffic (port 80)
- `:xdp-udp-port-range` - Filter UDP ports 1024-2048

**BPF Map Operations:**
- `:xdp-map-lookup` - Demonstrate map lookup pattern
- `:xdp-map-counter` - Increment packet counters in map

**Traffic Control (TC) Examples:**
- `:tc-ok-all` - Allow all packets
- `:tc-shot-all` - Drop all packets
- `:tc-classifier` - Classify packets by size with different actions

**Tracing and Debugging:**
- `:kprobe-trace-printk` - Use bpf_trace_printk for debugging
- `:kprobe-timestamp` - Log timestamps with bpf_ktime_get_ns

**Arithmetic and Logic:**
- `:arithmetic-demo` - Demonstrate ADD, SUB, MUL, DIV operations
- `:bitwise-demo` - Demonstrate AND, OR, XOR, shift operations
- `:conditional-demo` - Demonstrate conditional jumps and branching

**Real-World Security Examples:**
- `:syn-flood-protection` - SYN flood protection pattern
- `:icmp-rate-limiter` - ICMP rate limiting to prevent floods
- `:ip-allowlist` - IP allowlist filtering with map lookup

**Helper Function Examples:**
- `:perf-event-output` - Send data to userspace via perf events
- `:get-cpu-id` - Get current CPU ID

**Example: Using the TCP Port Filter**
```clojure
(require '[clj-ebpf.examples :as examples]
         '[clj-ebpf.core :as bpf]
         '[clj-ebpf.xdp :as xdp])

;; Get the pre-built TCP port 80 filter
(def http-filter (examples/get-example :xdp-tcp-port-filter))

;; Load the program
(def prog {:prog-type :xdp
           :insns http-filter
           :license "GPL"
           :prog-name "http_filter"})

(bpf/with-program [loaded prog]
  (println "Loaded program, FD:" (:fd loaded))

  ;; Attach to network interface
  (xdp/with-xdp ["eth0" loaded {:mode :skb}]
    (println "HTTP filter active on eth0")
    (println "Only HTTP traffic (port 80) will pass")
    (Thread/sleep 60000)))  ; Run for 60 seconds
```

**Example: IP Allowlist with Map Integration**
```clojure
;; Create a map to store allowed IPs
(def allowlist-map
  (bpf/create-hash-map 4 4 1000  ; key-size, value-size, max-entries
                      "ip_allowlist"
                      bpf/utils/int->bytes
                      bpf/utils/bytes->int
                      bpf/utils/int->bytes
                      bpf/utils/bytes->int))

;; Add some allowed IPs (in host byte order)
(bpf/map-update allowlist-map (bit-or (bit-shift-left 192 24)
                                     (bit-shift-left 168 16)
                                     (bit-shift-left 1 8)
                                     100) 1)  ; 192.168.1.100

;; Get the allowlist filter program
(def ip-filter (examples/get-example :ip-allowlist))

;; Note: In a real implementation, you would need to patch the map FD
;; into the program bytecode before loading
;; (see ELF loading for automatic map FD patching)
```

**Note:** The DSL generates raw BPF bytecode that must pass kernel verifier checks. Complex programs may need careful register management and bounds checking.

### ELF Object File Parsing

Load compiled BPF programs from ELF (.o) files created with clang:

```clojure
(require '[clj-ebpf.core :as bpf])

;; Inspect an ELF file to see what it contains
(def info (bpf/inspect-elf "filter.o"))
(println "Programs:" (:programs info))
;; => [{:name "xdp_filter" :type :xdp :size 256}
;;     {:name "kprobe/sys_clone" :type :kprobe :size 128}]

(println "Maps:" (:maps info))
;; => [{:name "packet_count" :type 1 :key-size 4 :value-size 8 :max-entries 1024}]

(println "License:" (:license info))
;; => "GPL"

;; Load a specific program from ELF file
(def prog-fd (bpf/load-program-from-elf "filter.o" "xdp_filter"))
(println "Loaded program FD:" prog-fd)

;; Create all maps defined in ELF file
(def maps (bpf/create-maps-from-elf "filter.o"))
(println "Created maps:" (keys maps))
;; => ("packet_count" "allowed_ips")

;; Load program and create maps in one call
(let [{:keys [program-fd maps]} (bpf/load-elf-program-and-maps "filter.o" "xdp_filter")]
  (println "Program FD:" program-fd)
  (println "Maps:" (keys maps))

  ;; Use the loaded program and maps
  (bpf/map-update (get maps "packet_count") 0 0)
  (bpf/attach-xdp "eth0" program-fd [:drv-mode]))

;; Parse ELF file for detailed inspection
(def elf-file (bpf/parse-elf-file "filter.o"))
(def programs (bpf/list-programs elf-file))
(def maps (bpf/list-maps elf-file))

;; Get specific program by name
(def prog (bpf/get-program elf-file "xdp_filter"))
(println "Program type:" (:type prog))
(println "Section:" (:section prog))
(println "Bytecode size:" (alength (:insns prog)))
```

**Supported ELF Features:**
- **Program extraction** - Automatically detect program type from section names
- **Map definitions** - Parse `struct bpf_map_def` from maps section
- **License detection** - Extract GPL/dual license strings
- **Symbol tables** - Parse symbol information
- **Relocations** - RELA relocation entries
- **Section types** - Kprobe, tracepoint, XDP, TC, socket filter, etc.

**Section Name Conventions:**
- `kprobe/function_name` → Kprobe program
- `kretprobe/function_name` → Kretprobe program
- `tracepoint/category/name` → Tracepoint program
- `xdp` or `xdp_*` → XDP program
- `tc` or `classifier` → TC classifier
- `socket*` → Socket filter

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
- `create-lru-hash-map` - Create LRU hash map (auto-evicts least recently used)
- `create-percpu-hash-map` - Create per-CPU hash map (zero-contention)
- `create-percpu-array-map` - Create per-CPU array map
- `create-lru-percpu-hash-map` - Create per-CPU LRU hash map
- `create-stack-map` - Create stack map (LIFO semantics)
- `create-queue-map` - Create queue map (FIFO semantics)
- `create-lpm-trie-map` - Create LPM trie map (longest prefix matching)
- `create-ringbuf-map` - Create ring buffer map (convenience)
- `close-map` - Close map and release resources
- `map-from-fd` - Create map from existing file descriptor (for pinned maps)
- `map-lookup` - Look up value by key
- `map-update` - Insert or update key-value pair
- `map-delete` - Delete entry by key
- `map-keys` - Get all keys (lazy seq)
- `map-entries` - Get all key-value pairs (lazy seq)
- `map-values` - Get all values (lazy seq)
- `stack-push` - Push value onto stack map
- `stack-pop` - Pop value from stack map (LIFO)
- `stack-peek` - Peek at top value without removing
- `queue-push` - Push value onto queue map (enqueue)
- `queue-pop` - Pop value from queue map (FIFO)
- `queue-peek` - Peek at front value without removing
- `map-count` - Count entries
- `map-clear` - Delete all entries
- `map-lookup-batch` - Batch lookup multiple keys
- `map-update-batch` - Batch update key-value pairs
- `map-delete-batch` - Batch delete multiple keys
- `map-lookup-and-delete-batch` - Atomic batch lookup and delete
- `percpu-sum` - Sum per-CPU values
- `percpu-max` - Get maximum per-CPU value
- `percpu-min` - Get minimum per-CPU value
- `percpu-avg` - Calculate average per-CPU value
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
- `get-cpu-count` - Get number of CPUs (for per-CPU maps)
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
- `examples/custom_helpers.clj` - Adding custom BPF helper functions

Run examples:

```bash
# Simple map operations (no root required)
clj -M -m examples.execve-tracer map

# Trace execve (requires root)
sudo clj -M -m examples.execve-tracer trace

# Custom helpers example (shows how to extend clj-ebpf)
clj -M:examples -m custom-helpers
```

## Extending clj-ebpf

### Adding New BPF Helper Functions

clj-ebpf makes it easy to add support for new BPF helper functions as they're introduced in newer kernel versions:

```clojure
;; Add to src/clj_ebpf/helpers.clj
(def helper-metadata
  {;; Your new helper
   :ktime-get-real-ns
   {:id 212
    :name "bpf_ktime_get_real_ns"
    :signature {:return :u64 :args []}
    :min-kernel "6.3"
    :prog-types :all
    :category :time
    :description "Get real (wall-clock) time in nanoseconds."}})

;; Query helper information
(require '[clj-ebpf.helpers :as helpers])

(helpers/get-helper-info :ktime-get-real-ns)
(helpers/helper-compatible? :ktime-get-real-ns :xdp "6.3")
(helpers/available-helpers :xdp "6.4")

;; Use in BPF programs
(require '[clj-ebpf.dsl :as dsl])

(def program
  (dsl/assemble [(dsl/call 212)  ; Call new helper
                 (dsl/exit-insn)]))
```

**Resources:**
- **Full Guide**: `docs/adding-new-helpers.md` - Comprehensive guide to extending helpers
- **Example Code**: `examples/custom_helpers.clj` - Runnable examples and utilities
- **Helper Metadata**: `src/clj_ebpf/helpers.clj` - Complete helper registry (200+ helpers)

The helper system provides:
- Type-safe helper definitions with metadata
- Kernel version compatibility checking
- Program type compatibility validation
- Category-based organization (map, network, trace, time, etc.)
- Introspection and discovery APIs
- Automatic documentation generation

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
- **Zero dependencies**: Uses Java's built-in Panama FFI (Java 25+)
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

- **Use batch operations** for bulk map updates/lookups/deletes (reduces syscall overhead)
- Batch operations automatically fall back to individual ops on kernels < 5.6
- Ring buffers are more efficient than perf buffers for modern kernels
- **Per-CPU maps eliminate contention** on multi-core systems (each CPU has independent values)
  - Best for high-frequency counters and statistics
  - Particularly effective with 2-16 CPUs
  - Use aggregation helpers to combine per-CPU values
- Pin maps/programs for cross-process reuse to avoid reload overhead
- Use array maps for small, dense key spaces (faster than hash)
- LRU maps for bounded caches (automatic eviction)
- Stack/queue maps for LIFO/FIFO data structures (efficient push/pop operations)
- LPM trie maps for IP routing and prefix matching (optimized for longest prefix match)

## Security Considerations

- eBPF programs require elevated privileges (CAP_BPF, CAP_PERFMON, or root)
- Programs are verified by the kernel before loading
- Infinite loops are prevented by the verifier
- Helper function access is restricted by program type
- Always validate input data from untrusted sources

## Contributing

Contributions welcome! Priority areas for improvement:

- Full ELF parsing for loading compiled BPF objects
- BTF support for CO-RE
- XDP and TC support
- Improved ring buffer implementation
- More examples and tutorials
- Performance benchmarks
- Additional specialized map types (devmap, cpumap, sockmap, etc.)
- Per-CPU map support for very high CPU counts (>16 cores)

## License

Copyright © 2025

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
