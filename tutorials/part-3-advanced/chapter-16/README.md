# Chapter 16: Performance Optimization

**Duration**: 3-4 hours | **Difficulty**: Advanced

This chapter covers techniques for optimizing BPF program performance, from instruction-level optimization to data structure selection and cache efficiency.

## Learning Objectives

By the end of this chapter, you will:
- Understand BPF program performance characteristics
- Optimize instruction sequences for speed
- Select appropriate data structures for workloads
- Minimize lock contention with per-CPU structures
- Use batch operations for bulk data transfer
- Profile and benchmark BPF programs

## Prerequisites

- Completed Chapters 10-15
- Understanding of CPU cache behavior
- Familiarity with concurrent programming concepts

---

## 16.1 Understanding BPF Performance

### Performance Factors

BPF program performance depends on several factors:

1. **Instruction Count**: More instructions = more CPU cycles
2. **Memory Access**: Cache misses are expensive (100+ cycles)
3. **Helper Calls**: Some helpers are more expensive than others
4. **Map Operations**: Hash lookups vs array indexing
5. **Lock Contention**: Concurrent map updates from multiple CPUs

### Performance Budget

Each BPF hook has different performance requirements:

| Hook Type | Budget | Typical Latency |
|-----------|--------|-----------------|
| XDP | ~100ns | Ultra-low latency |
| TC | ~1μs | Low latency |
| kprobe | ~10μs | Moderate |
| tracepoint | ~10μs | Moderate |
| cgroup | ~100μs | Relaxed |

### Measuring Performance

```clojure
(require '[clj-ebpf.core :as bpf]
         '[clj-ebpf.programs :as programs])

;; Use test-run for benchmarking
(let [prog (programs/load-program bytecode :xdp)
      packet (generate-test-packet)]

  ;; Run 10000 iterations
  (let [result (programs/test-run-program prog
                 {:data-in packet
                  :repeat 10000})]

    ;; Average latency
    (println "Avg latency:"
             (/ (:duration-ns result) 10000.0) "ns")))
```

---

## 16.2 Instruction-Level Optimization

### Register Usage

BPF has 10 registers (R0-R9) plus R10 (frame pointer). Efficient register use avoids memory spills:

```clojure
;; Bad: Excessive stack spills
[(bpf/store-mem :dw :r10 -8 :r1)]   ; Spill r1
[(bpf/store-mem :dw :r10 -16 :r2)]  ; Spill r2
[(bpf/store-mem :dw :r10 -24 :r3)]  ; Spill r3
;; ... do work ...
[(bpf/load-mem :dw :r1 :r10 -8)]    ; Reload r1
[(bpf/load-mem :dw :r2 :r10 -16)]   ; Reload r2

;; Good: Keep values in registers
[(bpf/mov-reg :r6 :r1)]  ; Use callee-saved r6
[(bpf/mov-reg :r7 :r2)]  ; Use callee-saved r7
;; ... do work ...
;; r6, r7 still available
```

### Minimize Branches

Branch mispredictions cost ~10-20 cycles:

```clojure
;; Bad: Many conditional branches
[(bpf/jmp-imm :jeq :r1 1 :case-1)]
[(bpf/jmp-imm :jeq :r1 2 :case-2)]
[(bpf/jmp-imm :jeq :r1 3 :case-3)]
[(bpf/jmp-imm :jeq :r1 4 :case-4)]

;; Good: Use array lookup for dispatch
;; Store function pointers in array map
;; Jump to computed address
```

### Inline Common Operations

BPF doesn't support function calls (except tail calls), but you can inline:

```clojure
;; Define reusable instruction sequences as macros
(defn inline-bounds-check
  "Generate bounds check instructions"
  [data-reg end-reg offset exit-label]
  [[(bpf/mov-reg :r11 data-reg)]
   [(bpf/add :r11 offset)]
   [(bpf/jmp-reg :jgt :r11 end-reg exit-label)]])

;; Use in program
(concat
  (inline-bounds-check :r2 :r3 14 :drop)
  [[(bpf/load-mem :h :r1 :r2 12)]]  ; Read ethertype
  ...)
```

---

## 16.3 Map Selection and Optimization

### Map Type Selection

| Map Type | Lookup | Insert | Delete | Use Case |
|----------|--------|--------|--------|----------|
| Array | O(1) | O(1) | N/A | Fixed keys 0..N |
| Hash | O(1)* | O(1)* | O(1)* | Dynamic keys |
| LRU Hash | O(1) | O(1) | Auto | Bounded cache |
| Per-CPU | O(1) | O(1) | - | Counter/stats |
| LPM Trie | O(log N) | O(log N) | O(log N) | IP routing |

*Average case, assuming low collision rate

### Array vs Hash Maps

```clojure
;; For small, dense key ranges: use arrays
(def protocol-stats
  {:type :percpu_array
   :key-type :u32
   :value-type :u64
   :max-entries 256})  ; Protocol numbers 0-255

;; For sparse or large keys: use hash
(def connection-table
  {:type :hash
   :key-type [:struct {:saddr :u32 :daddr :u32 :sport :u16 :dport :u16}]
   :value-type :u64
   :max-entries 65536})
```

### Pre-allocation

Pre-allocate entries to avoid runtime allocation cost:

```clojure
;; Pre-populate array with zeros
(defn preallocate-array [map-ref max-entries]
  (dotimes [i max-entries]
    (bpf/map-update map-ref i 0)))

;; Use BPF_F_NO_PREALLOC flag for large maps
;; that don't need all entries
(def sparse-map
  {:type :hash
   :flags #{:no-prealloc}
   :max-entries 1000000})
```

---

## 16.4 Per-CPU Data Structures

### Why Per-CPU?

Regular maps require locking for concurrent access. Per-CPU maps eliminate lock contention:

```
Regular Map:
CPU0 ──┐
CPU1 ──┼── Lock ──► Single Value
CPU2 ──┘

Per-CPU Map:
CPU0 ──────────────► Value[0]
CPU1 ──────────────► Value[1]
CPU2 ──────────────► Value[2]
```

### Per-CPU Counters

```clojure
(def packet-counters
  {:type :percpu_array
   :key-type :u32
   :value-type :u64
   :max-entries 1})

;; In BPF: atomic increment (lock-free)
[(bpf/mov :r1 0)]  ; key = 0
[(bpf/mov-reg :r2 (bpf/map-ref packet-counters))]
[(bpf/call (bpf/helper :map_lookup_elem))]
[(bpf/jmp-imm :jeq :r0 0 :skip)]
[(bpf/atomic-add :dw :r0 1 0)]  ; Atomic add
[:skip]

;; In userspace: sum all CPUs
(defn get-total-packets []
  (let [per-cpu-values (bpf/map-lookup-percpu packet-counters 0)]
    (reduce + per-cpu-values)))
```

### Per-CPU Hash Maps

```clojure
(def flow-stats
  {:type :percpu_hash
   :key-type [:struct {:src :u32 :dst :u32}]
   :value-type [:struct {:packets :u64 :bytes :u64}]
   :max-entries 10000})

;; Aggregate in userspace
(defn aggregate-flow-stats []
  (into {}
    (for [[flow-key per-cpu-vals] (bpf/map-get-all-percpu flow-stats)]
      [flow-key
       {:packets (reduce + (map :packets per-cpu-vals))
        :bytes (reduce + (map :bytes per-cpu-vals))}])))
```

---

## 16.5 Batch Operations

### Why Batch?

Each map operation has syscall overhead. Batch operations amortize this:

```
Individual: N operations × syscall overhead
Batch: 1 syscall + N operations (much faster)
```

### Batch Lookup

```clojure
(require '[clj-ebpf.maps :as maps])

;; Individual lookups (slow)
(defn lookup-individual [map-ref keys]
  (doall (map #(maps/lookup map-ref %) keys)))

;; Batch lookup (fast)
(defn lookup-batch [map-ref keys]
  (maps/batch-lookup map-ref keys))

;; Performance comparison
(let [keys (range 10000)]
  (time (lookup-individual my-map keys))  ; ~500ms
  (time (lookup-batch my-map keys)))       ; ~10ms
```

### Batch Update

```clojure
;; Batch update multiple entries
(defn update-batch [map-ref entries]
  (maps/batch-update map-ref entries))

;; Example: Initialize many entries
(let [entries (for [i (range 1000)]
                {:key i :value {:count 0 :timestamp 0}})]
  (update-batch my-map entries))
```

### Batch Delete

```clojure
;; Delete entries matching criteria
(defn cleanup-old-entries [map-ref max-age-ms]
  (let [cutoff (- (System/currentTimeMillis) max-age-ms)
        old-keys (for [[k v] (maps/batch-lookup-all map-ref)
                       :when (< (:timestamp v) cutoff)]
                   k)]
    (when (seq old-keys)
      (maps/batch-delete map-ref old-keys))))
```

---

## 16.6 Cache Optimization

### Data Structure Layout

BPF map values should be cache-line friendly (64 bytes):

```clojure
;; Bad: Sparse access pattern
(def bad-struct
  {:type :hash
   :value-type [:struct
                {:field1 :u64    ; offset 0
                 :padding1 [56 :u8]  ; 56 bytes padding
                 :field2 :u64    ; offset 64 - different cache line!
                 :padding2 [56 :u8]
                 :field3 :u64}]})  ; offset 128

;; Good: Dense packing
(def good-struct
  {:type :hash
   :value-type [:struct
                {:field1 :u64   ; offset 0
                 :field2 :u64   ; offset 8
                 :field3 :u64   ; offset 16
                 :field4 :u64   ; offset 24
                 :field5 :u64   ; offset 32
                 :field6 :u64   ; offset 40
                 :field7 :u64   ; offset 48
                 :field8 :u64}]})  ; offset 56 - all in one cache line!
```

### Prefetching

For sequential access patterns, prefetch next entry:

```clojure
;; BPF doesn't have explicit prefetch, but sequential
;; array access benefits from hardware prefetching

;; Process array sequentially (good for cache)
[(bpf/mov :r6 0)]  ; index
[:loop]
[(bpf/jmp-imm :jge :r6 MAX_ENTRIES :done)]
;; Lookup array[r6]
[(bpf/mov-reg :r1 (bpf/map-ref my-array))]
[(bpf/mov-reg :r2 :r6)]
[(bpf/call (bpf/helper :map_lookup_elem))]
;; Process...
[(bpf/add :r6 1)]  ; Sequential access
[(bpf/jmp :loop)]
[:done]
```

---

## 16.7 Helper Function Optimization

### Helper Cost Hierarchy

| Helper | Cost | Notes |
|--------|------|-------|
| `get_smp_processor_id` | Very Low | Just reads CPU ID |
| `ktime_get_ns` | Low | VDSO optimized |
| `map_lookup_elem` | Medium | Hash/array dependent |
| `map_update_elem` | Medium-High | May need lock |
| `probe_read_kernel` | High | Memory access + safety |
| `send_signal` | Very High | Context switch |

### Minimize Expensive Helpers

```clojure
;; Bad: Multiple probe_read calls
[(bpf/call (bpf/helper :probe_read_kernel))]  ; Read field 1
[(bpf/call (bpf/helper :probe_read_kernel))]  ; Read field 2
[(bpf/call (bpf/helper :probe_read_kernel))]  ; Read field 3

;; Good: Single read of entire struct
[(bpf/call (bpf/helper :probe_read_kernel))]  ; Read whole struct once
;; Access fields from local copy
```

### Cache Helper Results

```clojure
;; Bad: Repeated timestamp calls
[(bpf/call (bpf/helper :ktime_get_ns))]
[(bpf/store-mem :dw :r10 -8 :r0)]   ; store timestamp 1
;; ... some code ...
[(bpf/call (bpf/helper :ktime_get_ns))]
[(bpf/store-mem :dw :r10 -16 :r0)]  ; store timestamp 2

;; Good: Single call, reuse value
[(bpf/call (bpf/helper :ktime_get_ns))]
[(bpf/mov-reg :r6 :r0)]  ; Save in callee-saved register
;; Use r6 wherever timestamp needed
```

---

## 16.8 Profiling and Benchmarking

### Using test-run for Benchmarking

```clojure
(defn benchmark-program [prog packet iterations]
  (let [result (programs/test-run-program prog
                 {:data-in packet
                  :repeat iterations})]
    {:iterations iterations
     :total-ns (:duration-ns result)
     :avg-ns (/ (:duration-ns result) iterations)
     :avg-us (/ (:duration-ns result) iterations 1000.0)
     :ops-per-sec (/ (* iterations 1e9) (:duration-ns result))}))

;; Run benchmark
(let [stats (benchmark-program my-xdp-prog test-packet 100000)]
  (println "Average latency:" (:avg-ns stats) "ns")
  (println "Throughput:" (:ops-per-sec stats) "ops/sec"))
```

### Comparative Benchmarking

```clojure
(defn compare-implementations [implementations packet iterations]
  (println "\n=== Performance Comparison ===\n")
  (println (format "%-20s %12s %12s %15s"
                   "Implementation" "Avg (ns)" "Avg (μs)" "Ops/sec"))
  (println (apply str (repeat 60 "-")))

  (doseq [[name prog] implementations]
    (let [stats (benchmark-program prog packet iterations)]
      (println (format "%-20s %12.1f %12.3f %15.0f"
                       name
                       (:avg-ns stats)
                       (:avg-us stats)
                       (:ops-per-sec stats))))))

;; Compare array vs hash map implementation
(compare-implementations
  {"Array-based" array-prog
   "Hash-based" hash-prog
   "Per-CPU Array" percpu-prog}
  test-packet
  100000)
```

### Profiling Map Operations

```clojure
(defn profile-map-ops [map-ref operations]
  (let [results (atom {})]

    ;; Profile lookups
    (let [start (System/nanoTime)]
      (dotimes [_ operations]
        (maps/lookup map-ref (rand-int 1000)))
      (swap! results assoc :lookup-ns
             (/ (- (System/nanoTime) start) operations)))

    ;; Profile updates
    (let [start (System/nanoTime)]
      (dotimes [i operations]
        (maps/update map-ref (mod i 1000) {:value i}))
      (swap! results assoc :update-ns
             (/ (- (System/nanoTime) start) operations)))

    @results))
```

---

## 16.9 Real-World Optimization Case Study

### Problem: High-Volume Packet Counter

Goal: Count packets by protocol at 10Gbps line rate.

### Naive Implementation

```clojure
(def naive-counter
  {:maps {:stats {:type :hash
                  :key-type :u32
                  :value-type :u64
                  :max-entries 256}}
   :program
   [;; Get protocol from packet
    [(bpf/load-ctx :dw :r2 0)]      ; data
    [(bpf/load-ctx :dw :r3 8)]      ; data_end
    [(bpf/mov-reg :r4 :r2)]
    [(bpf/add :r4 14)]               ; IP header offset
    [(bpf/jmp-reg :jgt :r4 :r3 :pass)]
    [(bpf/load-mem :b :r1 :r2 23)]   ; Protocol field

    ;; Lookup and increment (NOT atomic!)
    [(bpf/mov-reg :r2 (bpf/map-ref :stats))]
    [(bpf/call (bpf/helper :map_lookup_elem))]
    [(bpf/jmp-imm :jeq :r0 0 :pass)]
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]  ; Race condition!

    [:pass]
    [(bpf/mov :r0 2)]  ; XDP_PASS
    [(bpf/exit)]]})
```

**Problems**:
1. Hash map lookup overhead
2. Race condition on increment
3. Lock contention on update

### Optimized Implementation

```clojure
(def optimized-counter
  {:maps {:stats {:type :percpu_array
                  :key-type :u32
                  :value-type :u64
                  :max-entries 256}}
   :program
   [;; Get protocol from packet
    [(bpf/load-ctx :dw :r2 0)]      ; data
    [(bpf/load-ctx :dw :r3 8)]      ; data_end
    [(bpf/mov-reg :r4 :r2)]
    [(bpf/add :r4 14)]
    [(bpf/jmp-reg :jgt :r4 :r3 :pass)]
    [(bpf/load-mem :b :r1 :r2 23)]   ; Protocol = key

    ;; Array lookup (O(1), no hash)
    [(bpf/mov-reg :r2 (bpf/map-ref :stats))]
    [(bpf/call (bpf/helper :map_lookup_elem))]
    [(bpf/jmp-imm :jeq :r0 0 :pass)]

    ;; Atomic increment (lock-free per-CPU)
    [(bpf/atomic-add :dw :r0 1 0)]

    [:pass]
    [(bpf/mov :r0 2)]
    [(bpf/exit)]]})
```

**Improvements**:
1. Array lookup: O(1), no hashing
2. Per-CPU: No lock contention
3. Atomic add: Single instruction

**Result**: 10x throughput improvement

---

## Labs

### Lab 16.1: Map Performance Comparison

Benchmark different map types and analyze performance characteristics.

[Go to Lab 16.1](labs/lab-16-1-map-performance.md)

### Lab 16.2: Per-CPU Counter System

Build a high-performance counter system using per-CPU data structures.

[Go to Lab 16.2](labs/lab-16-2-percpu-counters.md)

### Lab 16.3: Batch Operations

Implement efficient bulk data transfer using batch operations.

[Go to Lab 16.3](labs/lab-16-3-batch-operations.md)

---

## Key Takeaways

1. **Profile First**: Measure before optimizing
2. **Right Data Structure**: Array for dense keys, hash for sparse
3. **Per-CPU**: Eliminate lock contention for counters
4. **Batch Operations**: Amortize syscall overhead
5. **Cache Efficiency**: Pack data structures, sequential access
6. **Register Allocation**: Avoid unnecessary stack spills
7. **Helper Selection**: Know the cost of each helper

## References

- [BPF Performance Tools](https://www.brendangregg.com/bpf-performance-tools-book.html)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [XDP Performance Guide](https://github.com/xdp-project/xdp-tutorial)
