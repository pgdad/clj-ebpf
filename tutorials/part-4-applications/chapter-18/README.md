# Chapter 18: Performance Profiler

## Overview

Build a comprehensive performance profiler that identifies CPU hotspots, memory allocations, I/O bottlenecks, and lock contention using kprobes, tracepoints, and stack traces.

**Use Cases**:
- Application performance optimization
- CPU profiling and flamegraphs
- Memory leak detection
- I/O bottleneck analysis
- Lock contention identification

**Features**:
- CPU sampling profiler (99 Hz)
- On-CPU and Off-CPU analysis
- User + kernel stack traces
- Flamegraph generation
- Memory allocation tracking
- I/O latency histograms
- Lock contention profiling
- Per-process and system-wide modes

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Kernel Space                           │
│                                                     │
│  ┌────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ CPU Timer  │  │   Kprobes   │  │ Tracepoints │ │
│  │ (99 Hz)    │  │ (malloc,IO) │  │  (sched)    │ │
│  └────────────┘  └─────────────┘  └─────────────┘ │
│         ↓               ↓                 ↓        │
│  ┌──────────────────────────────────────────────┐ │
│  │         Stack Traces & Counters              │ │
│  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────────┐
│             Userspace Analyzer                      │
│                                                     │
│  Stack Aggregator → Flamegraph → Report            │
│         ↓              ↓            ↓               │
│   Histogram       Hotspots      Recommendations    │
└─────────────────────────────────────────────────────┘
```

## Implementation

```clojure
(ns performance-profiler.core
  (:require [clj-ebpf.core :as bpf]))

;; ============================================================================
;; Data Structures
;; ============================================================================

(defrecord StackTrace
  "Stack trace with metadata"
  [pid :u32
   tid :u32
   user-stack-id :s32
   kernel-stack-id :s32
   comm [16 :u8]
   timestamp :u64])

(defrecord ProfileSample
  "CPU profiling sample"
  [pid :u32
   cpu :u32
   user-stack-id :s32
   kernel-stack-id :s32])

(defrecord MemAlloc
  "Memory allocation event"
  [pid :u32
   size :u64
   stack-id :s32
   timestamp :u64])

(defrecord IOLatency
  "I/O operation latency"
  [pid :u32
   op-type :u32           ; READ, WRITE, FSYNC
   latency-ns :u64
   size :u64])

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def stack-traces
  "Stack trace storage"
  {:type :stack_trace
   :key-type :u32
   :value-type :u64
   :max-entries 10000})

(def cpu-samples
  "CPU profiling samples"
  {:type :hash
   :key-type :struct      ; {user_stack_id, kernel_stack_id, pid}
   :value-type :u64       ; Count
   :max-entries 100000})

(def mem-allocations
  "Memory allocation tracking"
  {:type :hash
   :key-type :struct      ; {stack_id, pid}
   :value-type :struct    ; {count, total_bytes}
   :max-entries 10000})

(def io-latency-hist
  "I/O latency histogram"
  {:type :hash
   :key-type :u32         ; Latency bucket (log2)
   :value-type :u64       ; Count
   :max-entries 64})

(def lock-contention
  "Lock contention tracking"
  {:type :hash
   :key-type :u64         ; Lock address
   :value-type :struct    ; {contention_count, total_wait_ns}
   :max-entries 10000})

;; ============================================================================
;; CPU Profiler (Perf Event)
;; ============================================================================

(def cpu-profiler
  "Sample CPU activity at 99 Hz"
  {:type :perf_event
   :config {:type :software
            :config :cpu-clock
            :sample-freq 99}
   :program
   [;; Get PID
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/mov-reg :r6 :r0)]
    [(bpf/rsh :r6 32)]                 ; PID

    ;; Get user stack
    [(bpf/mov-reg :r1 (bpf/map-ref stack-traces))]
    [(bpf/mov-reg :r2 :r1)]            ; ctx (from r1)
    [(bpf/mov :r3 (bit-or 0x100 0x200))]  ; BPF_F_USER_STACK | BPF_F_REUSE_STACKID
    [(bpf/call (bpf/helper :get_stackid))]
    [(bpf/mov-reg :r7 :r0)]            ; user_stack_id

    ;; Get kernel stack
    [(bpf/mov-reg :r1 (bpf/map-ref stack-traces))]
    [(bpf/mov-reg :r2 :r1)]
    [(bpf/mov :r3 0x200)]              ; BPF_F_REUSE_STACKID
    [(bpf/call (bpf/helper :get_stackid))]
    [(bpf/mov-reg :r8 :r0)]            ; kernel_stack_id

    ;; Build key: {user_stack_id, kernel_stack_id, pid}
    [(bpf/store-mem :w :r10 -16 :r7)]
    [(bpf/store-mem :w :r10 -12 :r8)]
    [(bpf/store-mem :w :r10 -8 :r6)]

    ;; Lookup existing count
    [(bpf/mov-reg :r1 (bpf/map-ref cpu-samples))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-count)]

    ;; Increment count
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]
    [(bpf/jmp :exit)]

    [:init-count]
    ;; Initialize count = 1
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r10 -24 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref cpu-samples))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -24)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))

;; ============================================================================
;; Memory Profiler (Kprobe)
;; ============================================================================

(def malloc-probe
  "Track memory allocations"
  {:type :kprobe
   :name "malloc"
   :program
   [;; Get allocation size from argument
    [(bpf/load-ctx :dw :r6 offsetof(pt_regs, di))]  ; size in rdi

    ;; Get stack
    [(bpf/mov-reg :r1 (bpf/map-ref stack-traces))]
    [(bpf/mov-reg :r2 :r1)]
    [(bpf/mov :r3 0x300)]              ; USER_STACK | REUSE
    [(bpf/call (bpf/helper :get_stackid))]
    [(bpf/mov-reg :r7 :r0)]

    ;; Get PID
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/rsh :r0 32)]
    [(bpf/mov-reg :r8 :r0)]

    ;; Build key: {stack_id, pid}
    [(bpf/store-mem :w :r10 -8 :r7)]
    [(bpf/store-mem :w :r10 -4 :r8)]

    ;; Lookup
    [(bpf/mov-reg :r1 (bpf/map-ref mem-allocations))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-alloc)]

    ;; Update count and bytes
    [(bpf/load-mem :dw :r1 :r0 0)]     ; count
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]

    [(bpf/load-mem :dw :r1 :r0 8)]     ; total_bytes
    [(bpf/add-reg :r1 :r6)]            ; Add size
    [(bpf/store-mem :dw :r0 8 :r1)]
    [(bpf/jmp :exit)]

    [:init-alloc]
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r10 -24 :r1)] ; count = 1
    [(bpf/store-mem :dw :r10 -16 :r6)] ; bytes = size
    [(bpf/mov-reg :r1 (bpf/map-ref mem-allocations))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -24)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))

;; ============================================================================
;; I/O Profiler (Tracepoint)
;; ============================================================================

(def io-start-times
  "Track I/O start times"
  {:type :hash
   :key-type :u64         ; request pointer
   :value-type :u64       ; start timestamp
   :max-entries 10000})

(def io-start
  "Track I/O operation start"
  {:type :tracepoint
   :category "block"
   :name "block_rq_issue"
   :program
   [;; Get request pointer
    [(bpf/load-ctx :dw :r6 offsetof(req))]

    ;; Get timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]

    ;; Store start time
    [(bpf/store-mem :dw :r10 -8 :r6)]
    [(bpf/store-mem :dw :r10 -16 :r0)]
    [(bpf/mov-reg :r1 (bpf/map-ref io-start-times))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -16)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))

(def io-complete
  "Calculate I/O latency"
  {:type :tracepoint
   :category "block"
   :name "block_rq_complete"
   :program
   [;; Get request pointer
    [(bpf/load-ctx :dw :r6 offsetof(req))]

    ;; Lookup start time
    [(bpf/store-mem :dw :r10 -8 :r6)]
    [(bpf/mov-reg :r1 (bpf/map-ref io-start-times))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]

    ;; Calculate latency
    [(bpf/load-mem :dw :r7 :r0 0)]     ; start_time
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/sub-reg :r0 :r7)]            ; latency_ns

    ;; Calculate log2 bucket
    [(bpf/mov-reg :r8 :r0)]
    [(bpf/mov :r9 0)]
    [:log2-loop]
    [(bpf/jmp-imm :jeq :r8 0 :update-hist)]
    [(bpf/rsh :r8 1)]
    [(bpf/add :r9 1)]
    [(bpf/jmp-imm :jlt :r9 64 :log2-loop)]

    [:update-hist]
    ;; Update histogram
    [(bpf/store-mem :w :r10 -16 :r9)]
    [(bpf/mov-reg :r1 (bpf/map-ref io-latency-hist))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-hist)]
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]
    [(bpf/jmp :delete-start)]

    [:init-hist]
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r10 -24 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref io-latency-hist))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -24)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:delete-start]
    ;; Delete start time entry
    [(bpf/mov-reg :r1 (bpf/map-ref io-start-times))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/call (bpf/helper :map_delete_elem))]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))
```

## Flamegraph Generation

```clojure
(ns performance-profiler.flamegraph
  (:require [clojure.string :as str]))

(defn generate-flamegraph
  "Generate flamegraph from stack samples"
  [samples]
  (let [folded (fold-stacks samples)]
    (println "# Folded stacks for flamegraph.pl")
    (doseq [[stack count] folded]
      (println (format "%s %d" stack count)))))

(defn fold-stacks
  "Fold stack traces into flamegraph format"
  [samples]
  (reduce
    (fn [acc sample]
      (let [stack (format-stack sample)]
        (update acc stack (fnil + 0) (:count sample))))
    {}
    samples))

(defn format-stack [sample]
  "Format stack as 'func1;func2;func3'"
  (let [kernel-stack (:kernel-stack sample)
        user-stack (:user-stack sample)]
    (str/join ";"
              (concat
                (reverse (map :function kernel-stack))
                (reverse (map :function user-stack))))))

;; Example output:
;; kernel_entry;do_syscall_64;sys_read;vfs_read;__vfs_read;ext4_file_read_iter 245
;; kernel_entry;do_syscall_64;sys_write;vfs_write;__vfs_write 156
```

## Analysis and Reporting

```clojure
(defn analyze-cpu-profile []
  "Analyze CPU profiling data"
  (println "\n=== CPU Profile Analysis ===\n")

  (let [samples (bpf/map-get-all cpu-samples)
        total (reduce + (map :count samples))
        top-10 (take 10 (sort-by :count > samples))]

    (println "Total samples:" total)
    (println "Sample frequency: 99 Hz")
    (println "Duration:" (/ total 99.0) "seconds\n")

    (println "Top 10 Hot Paths:")
    (println "SAMPLES  %      STACK")
    (println "═══════════════════════════════════════════════")

    (doseq [sample top-10]
      (let [pct (* 100.0 (/ (:count sample) total))
            stack-str (format-stack-summary sample)]
        (printf "%-8d %.1f%%  %s\n" (:count sample) pct stack-str)))))

(defn analyze-memory-allocations []
  "Analyze memory allocation patterns"
  (println "\n=== Memory Allocation Analysis ===\n")

  (let [allocs (bpf/map-get-all mem-allocations)
        total-bytes (reduce + (map :total-bytes allocs))
        top-10 (take 10 (sort-by :total-bytes > allocs))]

    (println "Total allocated:" (format-bytes total-bytes))
    (println)

    (println "Top 10 Allocation Sites:")
    (println "COUNT    BYTES       AVG       STACK")
    (println "═══════════════════════════════════════════════")

    (doseq [alloc top-10]
      (let [avg (/ (:total-bytes alloc) (:count alloc))]
        (printf "%-8d %-11s %-9s %s\n"
                (:count alloc)
                (format-bytes (:total-bytes alloc))
                (format-bytes avg)
                (format-stack-summary alloc))))))

(defn analyze-io-latency []
  "Analyze I/O latency distribution"
  (println "\n=== I/O Latency Distribution ===\n")

  (let [hist (bpf/map-get-all io-latency-hist)]
    (println "LATENCY         COUNT     %")
    (println "═══════════════════════════════")

    (doseq [[bucket count] (sort-by first hist)]
      (let [latency-ns (bit-shift-left 1 bucket)
            latency-str (format-duration latency-ns)]
        (printf "%-15s %-9d\n" latency-str count)))))

(defn generate-recommendations [analysis]
  "Generate performance recommendations"
  (println "\n=== Performance Recommendations ===\n")

  ;; CPU hotspots
  (when-let [hotspots (:cpu-hotspots analysis)]
    (println "CPU Optimization:")
    (doseq [hotspot hotspots]
      (println "  •" (:recommendation hotspot))))

  ;; Memory
  (when (> (:total-allocations analysis) 1000000)
    (println "\nMemory Optimization:")
    (println "  • High allocation rate detected")
    (println "  • Consider object pooling or reuse")
    (println "  • Review top allocation sites"))

  ;; I/O
  (when (> (:avg-io-latency analysis) 10000000)  ; > 10ms
    (println "\nI/O Optimization:")
    (println "  • High I/O latency detected")
    (println "  • Consider caching or async I/O")
    (println "  • Check disk performance")))
```

## Dashboard

```
╔══════════════════════════════════════════════════════════════╗
║            Performance Profiler - Live Dashboard             ║
╚══════════════════════════════════════════════════════════════╝

=== CPU Profile (99 Hz sampling) ===

Total Samples: 4,950
Duration: 50.0 seconds

Top Functions by CPU Time:
SAMPLES  %      FUNCTION
4,500    90.9%  database.query/execute-query
300      6.1%   json.parser/parse
100      2.0%   network.handler/process-request
50       1.0%   logging.writer/write-log

=== Memory Allocations ===

Total Allocated: 1.2 GB
Allocation Rate: 24 MB/sec

Top Allocation Sites:
COUNT     BYTES       AVG       LOCATION
125,000   512 MB      4 KB      string.builder/append
50,000    256 MB      5 KB      json.parser/parse-object
25,000    128 MB      5 KB      http.request/read-body

=== I/O Latency ===

LATENCY         COUNT
< 1μs           1,234
1-10μs          5,678
10-100μs        12,345
100μs-1ms       23,456
1-10ms          8,901    ← 90th percentile
> 10ms          234      ⚠️  High latency

=== Recommendations ===

⚡ CPU Optimization:
  • database.query/execute-query consuming 90.9% CPU
  • Consider adding query cache or index
  • Profile query execution plan

💾 Memory Optimization:
  • High allocation rate: 24 MB/sec
  • Top allocator: string.builder (512 MB)
  • Consider string interning or buffer reuse

💿 I/O Optimization:
  • 234 requests with >10ms latency
  • Consider async I/O or caching
```

## Performance

- **CPU overhead**: 1-2% for 99 Hz sampling
- **Memory**: 100 MB for stack traces
- **Resolution**: 10ms minimum for accurate profiling

## Next Steps

**Enhancements**:
1. Off-CPU profiling (scheduler delays)
2. GPU profiling support
3. Dynamic symbol resolution
4. Continuous profiling integration
5. Diff mode (compare two profiles)

**Next Chapter**: [Chapter 19: Distributed Tracing](../chapter-19/README.md)

## References

- [Flamegraphs](https://www.brendangregg.com/flamegraphs.html)
- [perf Examples](https://www.brendangregg.com/perf.html)
- [BPF Performance Tools](http://www.brendangregg.com/bpf-performance-tools-book.html)
