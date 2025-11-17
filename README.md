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
- ✅ **150+ tests with comprehensive assertions - all passing**

### Planned (Future Phases)
- ✅ **XDP (eXpress Data Path) support** (network interface utilities, attachment/detachment)
- ✅ **ELF object file parsing** (load compiled BPF programs from .o files)
- ✅ **TC (Traffic Control) support** (complete)
- ⏳ Cgroup attachment
- ⏳ LSM (Linux Security Modules) hooks
- ⏳ BTF (BPF Type Format) support
- ⏳ CO-RE (Compile Once - Run Everywhere)
- ⏳ C compilation integration
- ⏳ BPF assembly DSL
- ⏳ Perf event buffers

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
