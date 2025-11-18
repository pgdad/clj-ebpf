# Chapter 2: BPF Maps

**Duration**: 2-3 hours | **Difficulty**: Beginner

## Learning Objectives

By the end of this chapter, you will:
- Understand BPF map types and their use cases
- Create and manage maps from userspace
- Access maps from BPF programs
- Share data between kernel and userspace
- Implement counters, histograms, and caches with maps

## Prerequisites

- Completed [Chapter 1: Introduction to eBPF](../chapter-01/README.md)
- Understanding of data structures (hash tables, arrays)
- Basic knowledge of concurrent data access

## 2.1 What are BPF Maps?

### Purpose

BPF maps are the primary mechanism for:
1. **Kernel ↔ Userspace Communication**: Share data between BPF programs and userspace
2. **BPF ↔ BPF Communication**: Share data between multiple BPF programs
3. **State Storage**: Persist state across BPF program invocations
4. **Configuration**: Pass configuration from userspace to BPF programs

### Architecture

```
┌─────────────────────────────────────────┐
│           Userspace Program              │
│  ┌────────────────────────────────────┐ │
│  │  Map Operations API                │ │
│  │  - map_create()                    │ │
│  │  - map_lookup()                    │ │
│  │  - map_update()                    │ │
│  │  - map_delete()                    │ │
│  └────────────────────────────────────┘ │
└─────────────────┬───────────────────────┘
                  │ syscall (bpf)
                  ▼
┌─────────────────────────────────────────┐
│              Kernel Space                │
│  ┌────────────────────────────────────┐ │
│  │         BPF Map Storage            │ │
│  │  ┌──────────┐  ┌──────────┐      │ │
│  │  │ Hash Map │  │Array Map │ ...  │ │
│  │  └──────────┘  └──────────┘      │ │
│  └────────────────────────────────────┘ │
│                  ▲                       │
│                  │ helper functions      │
│  ┌───────────────────────────────────┐  │
│  │       BPF Program                 │  │
│  │  - bpf_map_lookup_elem()         │  │
│  │  - bpf_map_update_elem()         │  │
│  │  - bpf_map_delete_elem()         │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Map Lifecycle

```
┌──────────────┐
│ Create Map   │  1. Userspace creates map with bpf() syscall
│ (userspace)  │     Returns file descriptor
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Load BPF    │  2. BPF program compiled with map reference
│  Program     │     Map FD embedded in program
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Access     │  3. BPF program accesses map via helpers
│   from BPF   │     Kernel validates access
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Access     │  4. Userspace reads/writes map data
│ from User    │     Via map FD and bpf() syscall
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Close/Pin    │  5. Close FD or pin to BPF filesystem
│    Map       │     Pinned maps persist after program exit
└──────────────┘
```

## 2.2 Map Types

### Hash Map (BPF_MAP_TYPE_HASH)

**Use Case**: Key-value lookups with arbitrary keys

**Characteristics**:
- O(1) average lookup/insert/delete
- Arbitrary key and value sizes
- Dynamic number of elements (up to max_entries)
- Good for: Process tracking, connection tracking, caching

**Example**:
```clojure
;; Track process execution counts
;; Key: PID (u32), Value: count (u64)
(def pid-counter-map
  (bpf/create-map :hash
    {:key-size 4        ; sizeof(u32)
     :value-size 8      ; sizeof(u64)
     :max-entries 10000}))
```

### Array Map (BPF_MAP_TYPE_ARRAY)

**Use Case**: Fast index-based lookups

**Characteristics**:
- O(1) lookup by index
- Fixed number of elements (all pre-allocated)
- Index must be 0 to (max_entries - 1)
- Good for: Histograms, per-CPU statistics, fixed configuration

**Example**:
```clojure
;; Histogram of packet sizes (buckets of 256 bytes)
;; Key: bucket index (u32), Value: count (u64)
(def packet-histogram
  (bpf/create-map :array
    {:key-size 4
     :value-size 8
     :max-entries 64}))  ; 64 buckets = 0-16KB packets
```

### Per-CPU Array (BPF_MAP_TYPE_PERCPU_ARRAY)

**Use Case**: Per-CPU statistics without locking

**Characteristics**:
- Separate value per CPU core
- No locking needed (each CPU has its own value)
- Userspace sees array of values (one per CPU)
- Good for: High-performance counters, latency tracking

**Example**:
```clojure
;; Per-CPU syscall counters
(def percpu-syscall-count
  (bpf/create-map :percpu-array
    {:key-size 4
     :value-size 8
     :max-entries 400}))  ; 400 syscall numbers
```

### Per-CPU Hash Map (BPF_MAP_TYPE_PERCPU_HASH)

**Use Case**: Per-CPU key-value storage

**Characteristics**:
- Combines hash map flexibility with per-CPU performance
- Each CPU has its own value for each key
- No contention between CPUs
- Good for: Per-CPU connection tracking, per-CPU caches

### LRU Hash Map (BPF_MAP_TYPE_LRU_HASH)

**Use Case**: Bounded caches with automatic eviction

**Characteristics**:
- Least-recently-used eviction policy
- Automatically evicts oldest entries when full
- Good for: Connection tracking, DNS caches

**Example**:
```clojure
;; Track last 1000 active connections
(def connection-cache
  (bpf/create-map :lru-hash
    {:key-size 16      ; IP + port
     :value-size 64    ; Connection metadata
     :max-entries 1000}))
```

### Stack Trace Map (BPF_MAP_TYPE_STACK_TRACE)

**Use Case**: Store kernel/user stack traces

**Characteristics**:
- Stores instruction pointer arrays
- Key is stack ID, value is array of IPs
- Used with `bpf_get_stackid()` helper
- Good for: Profiling, tracing

### Ring Buffer (BPF_MAP_TYPE_RINGBUF)

**Use Case**: High-performance event streaming

**Characteristics**:
- Single producer, single consumer ring buffer
- More efficient than perf buffers
- Variable-length records
- Memory-efficient
- Good for: Event logging, tracing (kernel 5.8+)

### Comparison Table

| Map Type | Lookup | Concurrency | Memory | Use Case |
|----------|--------|-------------|--------|----------|
| Hash | O(1) avg | Lock | Dynamic | General KV |
| Array | O(1) | Lock | Fixed | Indexed data |
| Per-CPU Array | O(1) | Lock-free | Fixed × CPUs | Counters |
| Per-CPU Hash | O(1) avg | Lock-free | Dynamic × CPUs | Per-CPU KV |
| LRU Hash | O(1) avg | Lock | Bounded | Caches |
| Stack Trace | O(1) | Lock | Dynamic | Profiling |
| Ring Buffer | - | Lock-free | Circular | Events |

## 2.3 Map Operations

### Creating Maps

```clojure
(require '[clj-ebpf.core :as bpf])

;; Basic hash map
(def my-map
  (bpf/create-map :hash
    {:key-size 4
     :value-size 8
     :max-entries 1024}))

;; With flags
(def shared-map
  (bpf/create-map :hash
    {:key-size 4
     :value-size 8
     :max-entries 1024
     :flags #{:no-prealloc}}))  ; Allocate on demand

;; Per-CPU map
(def percpu-map
  (bpf/create-map :percpu-hash
    {:key-size 4
     :value-size 8
     :max-entries 1024}))
```

### Lookup

```clojure
;; From userspace
(let [key (bpf/u32 1000)  ; PID
      value (bpf/map-lookup my-map key)]
  (if value
    (println "Count:" (bpf/read-u64 value 0))
    (println "Key not found")))

;; From BPF program (using helpers)
(def lookup-code
  (bpf/assemble
    (vec (concat
      ;; r1 = map pointer (passed as argument in r1)
      ;; r2 = stack pointer (key location)
      [(bpf/store-mem :dw :r10 -8 1000)]  ; Store PID on stack
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      ;; r0 now contains pointer to value or NULL
      [(bpf/mov-reg :r6 :r0)]  ; Save result
      [(bpf/jmp-imm :jeq :r6 0 2)]  ; Jump if NULL
      ;; Value found, read it
      [(bpf/load-mem :dw :r0 :r6 0)]  ; Load value into r0
      [(bpf/exit-insn)]
      ;; Value not found
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))
```

### Update

```clojure
;; From userspace
(let [key (bpf/u32 1000)
      value (bpf/u64 42)]
  (bpf/map-update my-map key value :any))
  ;; Flags: :any (create or update)
  ;;        :noexist (create only)
  ;;        :exist (update only)

;; From BPF program
(def update-code
  (bpf/assemble
    (vec (concat
      ;; Prepare key on stack
      [(bpf/store-mem :dw :r10 -8 1000)]
      ;; Prepare value on stack
      [(bpf/store-mem :dw :r10 -16 42)]
      ;; Call helper
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]   ; r2 = key pointer
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]  ; r3 = value pointer
      [(bpf/mov :r4 0)]    ; r4 = flags (BPF_ANY)
      (bpf/helper-map-update-elem :r1 :r2 :r3)
      [(bpf/exit-insn)]))))
```

### Delete

```clojure
;; From userspace
(let [key (bpf/u32 1000)]
  (bpf/map-delete my-map key))

;; From BPF program
(def delete-code
  (bpf/assemble
    (vec (concat
      [(bpf/store-mem :dw :r10 -8 1000)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-delete-elem :r1 :r2)
      [(bpf/exit-insn)]))))
```

### Iteration (Userspace Only)

```clojure
;; Iterate all keys
(bpf/map-for-each my-map
  (fn [key value]
    (println "Key:" (bpf/read-u32 key 0)
             "Value:" (bpf/read-u64 value 0))))

;; Get all entries as sequence
(let [entries (bpf/map-get-all my-map)]
  (doseq [[k v] entries]
    (println k "->" v)))
```

## 2.4 Map Pinning

Maps can be pinned to the BPF filesystem for persistence and sharing:

```clojure
;; Create and pin a map
(def my-map (bpf/create-map :hash {...}))
(bpf/pin-map my-map "/sys/fs/bpf/my_shared_map")

;; In another process, open the pinned map
(def shared-map (bpf/open-pinned-map "/sys/fs/bpf/my_shared_map"))

;; Use it normally
(bpf/map-lookup shared-map key)

;; Unpin when done
(bpf/unpin-map "/sys/fs/bpf/my_shared_map")
```

## 2.5 Atomic Operations

BPF supports atomic operations on map values (kernel 5.12+):

```clojure
;; Atomic add (from BPF program)
(def atomic-add-code
  (bpf/assemble
    (vec (concat
      ;; r1 = map, r2 = key (setup omitted)
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 2)]  ; Skip if NULL
      ;; Atomic add 1 to value
      [(bpf/atomic-xadd :dw :r0 0 1)]
      [(bpf/exit-insn)]))))

;; Atomic operations available:
;; - xadd: atomic add
;; - xchg: atomic exchange
;; - cmpxchg: compare and exchange
```

## 2.6 clj-ebpf Map API

### Creating Maps

```clojure
(bpf/create-map map-type opts)
;; map-type: :hash, :array, :percpu-array, :percpu-hash, :lru-hash, :stack-trace, :ringbuf
;; opts: {:key-size N :value-size N :max-entries N :flags #{...}}
```

### Operations

```clojure
;; Lookup
(bpf/map-lookup map-fd key) ;=> ByteBuffer or nil

;; Update
(bpf/map-update map-fd key value flags)
;; flags: :any, :noexist, :exist

;; Delete
(bpf/map-delete map-fd key) ;=> true/false

;; Batch operations
(bpf/map-lookup-batch map-fd keys) ;=> [values]
(bpf/map-update-batch map-fd key-value-pairs)
(bpf/map-delete-batch map-fd keys)

;; Iteration
(bpf/map-for-each map-fd f)
(bpf/map-get-all map-fd) ;=> [[key value] ...]

;; Pinning
(bpf/pin-map map-fd path)
(bpf/unpin-map path)
(bpf/open-pinned-map path) ;=> map-fd
```

### Convenience Functions

```clojure
;; Type wrappers
(bpf/u32 n) ;=> ByteBuffer with u32
(bpf/u64 n) ;=> ByteBuffer with u64
(bpf/bytes data) ;=> ByteBuffer

;; Readers
(bpf/read-u32 buf offset) ;=> long
(bpf/read-u64 buf offset) ;=> long
(bpf/read-bytes buf offset len) ;=> byte-array
```

## 2.7 Common Patterns

### Counter

```clojure
(defn increment-counter [map-fd key]
  (let [key-buf (bpf/u32 key)
        current (bpf/map-lookup map-fd key-buf)
        new-value (if current
                    (inc (bpf/read-u64 current 0))
                    1)]
    (bpf/map-update map-fd key-buf (bpf/u64 new-value) :any)))
```

### Histogram

```clojure
(defn update-histogram [map-fd value bucket-size]
  (let [bucket (quot value bucket-size)
        key-buf (bpf/u32 bucket)]
    (increment-counter map-fd bucket)))

(defn get-histogram [map-fd]
  (into (sorted-map)
    (for [[k v] (bpf/map-get-all map-fd)]
      [(bpf/read-u32 k 0) (bpf/read-u64 v 0)])))
```

### Cache with Timeout

```clojure
(defn cache-with-timeout [map-fd key value timeout-ns]
  (let [now (System/nanoTime)
        entry {:value value :timestamp now}
        entry-buf (bpf/serialize entry)]
    (bpf/map-update map-fd (bpf/u32 key) entry-buf :any)))

(defn cache-lookup [map-fd key timeout-ns]
  (when-let [entry-buf (bpf/map-lookup map-fd (bpf/u32 key))]
    (let [entry (bpf/deserialize entry-buf)
          now (System/nanoTime)]
      (when (< (- now (:timestamp entry)) timeout-ns)
        (:value entry)))))
```

## Labs

This chapter includes three hands-on labs:

### Lab 2.1: Process Counter
Track process execution using a hash map

### Lab 2.2: Network Packet Histogram
Create packet size distribution using array maps

### Lab 2.3: Stack Trace Collector
Collect and display stack traces using stack maps

## Navigation

- **Next**: [Lab 2.1 - Process Counter](labs/lab-2-1-process-counter.md)
- **Previous**: [Chapter 1 - Introduction](../chapter-01/README.md)
- **Up**: [Part I - Fundamentals](../../part-1-fundamentals/)
- **Home**: [Tutorial Home](../../README.md)

## Additional Resources

- [Kernel BPF Map Documentation](https://www.kernel.org/doc/html/latest/bpf/maps.html)
- [BPF Map Types](https://ebpf.io/what-is-ebpf/#maps)
- [libbpf API Guide](https://libbpf.readthedocs.io/en/latest/api.html)
