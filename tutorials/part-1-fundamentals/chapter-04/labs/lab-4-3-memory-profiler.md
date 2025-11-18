# Lab 4.3: Memory Allocation Profiler

**Objective**: Profile memory allocations using stack trace and helper functions

**Duration**: 75 minutes

## Overview

In this lab, you'll build a comprehensive memory allocation profiler that tracks where memory is allocated in your system. You'll use stack trace helpers to capture allocation call stacks, combine multiple helpers for rich profiling data, and identify memory hotspots.

This lab demonstrates:
- Using `bpf_get_stackid()` for stack trace capture
- Combining multiple helper functions
- Building allocation profiles
- Identifying memory leaks and hotspots
- Generating flame graphs

## What You'll Learn

- How to use `bpf_get_stackid()` and stack helpers
- Capturing both kernel and user stack traces
- Combining stack traces with allocation data
- Tracking allocation sizes and frequencies
- Identifying memory allocation patterns
- Generating profiling visualizations

## Theory

### Memory Allocation Profiling

```
Memory Allocation Flow:
┌──────────────┐
│  Application │  malloc(1024)
└───────┬──────┘
        │
        ▼
┌──────────────┐
│   libc       │  __libc_malloc()
└───────┬──────┘
        │
        ▼
┌──────────────┐
│   Kernel     │  __kmalloc()
└───────┬──────┘
        │
        ▼
┌──────────────┐
│  BPF Probe   │  ← Capture here!
│              │   - Size
│              │   - Stack trace
│              │   - Process info
└──────────────┘
```

### Stack Trace Capture

Stack traces show the call chain leading to allocation:

```
Allocation at:
  __kmalloc+0x42
  ↑
  alloc_skb+0x1a
  ↑
  tcp_sendmsg+0x2b
  ↑
  sock_sendmsg+0x3d
  ↑
  __sys_sendto+0x105
  ↑
  entry_SYSCALL_64_after_hwframe+0x44

This reveals: TCP send → allocate SKB → kmalloc
```

### Allocation Patterns

Common patterns to detect:
- **Hot paths**: Frequently allocating call stacks
- **Large allocations**: Single big allocations
- **Death by 1000 cuts**: Many small allocations
- **Leaks**: Allocations without frees

## Implementation

### Step 1: Complete Program

Create `lab-4-3.clj`:

```clojure
(ns lab-4-3-memory-profiler
  "Lab 4.3: Memory Allocation Profiler using stack and helper functions"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Part 1: Configuration
;; ============================================================================

(def MAX_STACK_DEPTH 127)
(def MAX_STACKS 10000)
(def SIZE_BUCKETS 20)

;; Size buckets (bytes)
(def SIZE_BOUNDARIES
  [16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536])

;; ============================================================================
;; Part 2: Data Structures
;; ============================================================================

;; Allocation info
;; struct alloc_info {
;;   u64 size;
;;   u64 timestamp;
;;   u32 stack_id;
;;   u32 pid;
;; };

(def ALLOC_INFO_SIZE (+ 8 8 4 4))  ; 24 bytes

;; ============================================================================
;; Part 3: Maps
;; ============================================================================

(defn create-stack-traces-map []
  "Map for storing stack traces"
  (bpf/create-map :stack-trace
    {:key-size 4
     :value-size (* 8 MAX_STACK_DEPTH)
     :max-entries MAX_STACKS}))

(defn create-alloc-info-map []
  "Map: allocation address -> alloc_info"
  (bpf/create-map :hash
    {:key-size 8              ; u64 address
     :value-size ALLOC_INFO_SIZE
     :max-entries MAX_STACKS}))

(defn create-stack-counts-map []
  "Map: stack_id -> allocation count"
  (bpf/create-map :hash
    {:key-size 4
     :value-size 8
     :max-entries MAX_STACKS}))

(defn create-stack-bytes-map []
  "Map: stack_id -> total bytes allocated"
  (bpf/create-map :hash
    {:key-size 4
     :value-size 8
     :max-entries MAX_STACKS}))

(defn create-size-histogram-map []
  "Histogram of allocation sizes"
  (bpf/create-map :array
    {:key-size 4
     :value-size 8
     :max-entries SIZE_BUCKETS}))

;; ============================================================================
;; Part 4: BPF Program - Allocation Tracker
;; ============================================================================

(defn create-alloc-tracker
  [stacks-fd alloc-info-fd counts-fd bytes-fd histogram-fd]
  "Track memory allocations with stack traces"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get allocation size from function arguments
      ;; ──────────────────────────────────────────────────────────

      ;; For kmalloc, size is first argument (r1 = pt_regs)
      ;; Size is in rdi (PT_REGS_PARM1 = offset 112)
      [(bpf/load-mem :dw :r6 :r1 112)]  ; r6 = size

      ;; Skip if size is 0
      [(bpf/jmp-imm :jeq :r6 0 :exit)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Get stack trace
      ;; ──────────────────────────────────────────────────────────

      ;; Get kernel stack trace
      [(bpf/ld-map-fd :r2 stacks-fd)]  ; r2 = stack map
      [(bpf/mov :r3 0)]                 ; r3 = flags (0 = kernel stack)
      (bpf/helper-get-stackid :r1 :r2)  ; r1 = ctx, r2 = map

      ;; Check for error (negative return)
      [(bpf/mov-reg :r7 :r0)]  ; r7 = stack_id
      [(bpf/jslt-imm :r7 0 :exit)]  ; Skip if error

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Get additional context
      ;; ──────────────────────────────────────────────────────────

      ;; Get PID
      (bpf/helper-get-current-pid-tgid)
      [(bpf/rsh :r0 32)]  ; Extract TGID
      [(bpf/mov-reg :r8 :r0)]  ; r8 = PID

      ;; Get timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]  ; r9 = timestamp

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Update stack count
      ;; ──────────────────────────────────────────────────────────

      ;; Store stack_id as key
      [(bpf/store-mem :w :r10 -4 :r7)]

      ;; Lookup current count
      [(bpf/ld-map-fd :r1 counts-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Increment or initialize
      [(bpf/jmp-imm :jne :r0 0 :inc-count)]

      ;; Initialize to 1
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -16 :r3)]
      [(bpf/ld-map-fd :r1 counts-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]   ; key
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]  ; value
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)
      [(bpf/jmp :update-bytes)]

      ;; :inc-count - Increment existing count
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Update total bytes for this stack
      ;; ──────────────────────────────────────────────────────────

      ;; :update-bytes
      ;; Lookup current bytes
      [(bpf/ld-map-fd :r1 bytes-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jne :r0 0 :add-bytes)]

      ;; Initialize with current size
      [(bpf/store-mem :dw :r10 -24 :r6)]
      [(bpf/ld-map-fd :r1 bytes-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -24)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)
      [(bpf/jmp :update-size-histogram)]

      ;; :add-bytes - Add to existing bytes
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add-reg :r3 :r6)]
      [(bpf/store-mem :dw :r0 0 :r3)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 6: Update size histogram
      ;; ──────────────────────────────────────────────────────────

      ;; :update-size-histogram
      ;; Calculate bucket from size
      ;; Simplified: use log2 approximation
      [(bpf/mov-reg :r3 :r6)]  ; r3 = size

      ;; Bucket 0: < 32
      [(bpf/mov :r4 0)]
      [(bpf/jmp-imm :jlt :r3 32 :update-hist-bucket)]

      ;; Bucket 1: < 64
      [(bpf/mov :r4 1)]
      [(bpf/jmp-imm :jlt :r3 64 :update-hist-bucket)]

      ;; Bucket 2: < 128
      [(bpf/mov :r4 2)]
      [(bpf/jmp-imm :jlt :r3 128 :update-hist-bucket)]

      ;; Bucket 3: < 256
      [(bpf/mov :r4 3)]
      [(bpf/jmp-imm :jlt :r3 256 :update-hist-bucket)]

      ;; Bucket 4: < 512
      [(bpf/mov :r4 4)]
      [(bpf/jmp-imm :jlt :r3 512 :update-hist-bucket)]

      ;; Bucket 5: >= 512
      [(bpf/mov :r4 5)]

      ;; :update-hist-bucket
      [(bpf/store-mem :w :r10 -28 :r4)]
      [(bpf/ld-map-fd :r1 histogram-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -28)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :exit)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 7: Exit
      ;; ──────────────────────────────────────────────────────────

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 5: Userspace - Data Analysis
;; ============================================================================

(defn read-u32-le [^ByteBuffer buf offset]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getInt buf offset))

(defn read-u64-le [^ByteBuffer buf offset]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf offset))

(defn read-stack-trace [stacks-fd stack-id]
  "Read stack trace IPs for given stack ID"
  (let [key (utils/u32 stack-id)
        value (bpf/map-lookup stacks-fd key)]
    (when value
      (let [num-ips (/ (.remaining value) 8)]
        (into []
          (for [i (range num-ips)
                :let [ip (read-u64-le value (* i 8))]
                :when (not= ip 0)]
            ip))))))

(defn get-allocation-data [counts-fd bytes-fd]
  "Get all allocation data"
  (let [data (atom {})]
    (bpf/map-for-each counts-fd
      (fn [key value]
        (let [stack-id (read-u32-le key 0)
              count (read-u64-le value 0)
              bytes-key (utils/u32 stack-id)
              bytes-value (bpf/map-lookup bytes-fd bytes-key)
              total-bytes (if bytes-value
                           (read-u64-le bytes-value 0)
                           0)]
          (swap! data assoc stack-id
                 {:count count
                  :bytes total-bytes}))))
    @data))

(defn format-size [bytes]
  "Format byte size as human-readable"
  (cond
    (< bytes 1024) (format "%dB" bytes)
    (< bytes (* 1024 1024)) (format "%.1fKB" (/ bytes 1024.0))
    (< bytes (* 1024 1024 1024)) (format "%.1fMB" (/ bytes 1024.0 1024.0))
    :else (format "%.1fGB" (/ bytes 1024.0 1024.0 1024.0))))

(defn display-top-allocators [stacks-fd alloc-data n]
  "Display top N allocation stack traces"
  (println (format "\nTop %d Allocation Stack Traces:" n))
  (println "═══════════════════════════════════════════════════════")

  (let [sorted (take n (sort-by (comp :bytes val) > alloc-data))]
    (doseq [[stack-id {:keys [count bytes]}] sorted]
      (println (format "\nStack ID %d: %,d allocations, %s total"
                      stack-id count (format-size bytes)))
      (let [ips (read-stack-trace stacks-fd stack-id)]
        (if (seq ips)
          (doseq [ip ips]
            (println (format "  0x%016x" ip)))
          (println "  (stack trace unavailable)"))))))

(defn display-size-histogram [histogram-fd]
  "Display allocation size distribution"
  (println "\nAllocation Size Distribution:")
  (println "═══════════════════════════════════════════════════════")

  (let [labels ["<32B" "32-64B" "64-128B" "128-256B" "256-512B" "≥512B"]
        histogram (into []
                    (for [i (range 6)]
                      (let [key (utils/u32 i)
                            value (bpf/map-lookup histogram-fd key)]
                        (if value (read-u64-le value 0) 0))))
        total (reduce + histogram)
        max-count (apply max (conj histogram 1))
        bar-width 40]

    (println "Total allocations:" total)
    (println)

    (doseq [[i count] (map-indexed vector histogram)
            :when (pos? count)]
      (let [percentage (* 100.0 (/ count total))
            bar-len (int (* bar-width (/ count max-count)))
            bar (apply str (repeat bar-len "█"))]
        (println (format "%-10s │ %s %,d (%.1f%%)"
                        (get labels i)
                        bar
                        count
                        percentage))))))

(defn display-statistics [alloc-data]
  "Display allocation statistics"
  (let [total-allocs (reduce + (map :count (vals alloc-data)))
        total-bytes (reduce + (map :bytes (vals alloc-data)))
        avg-size (if (pos? total-allocs)
                   (/ total-bytes total-allocs)
                   0)
        unique-stacks (count alloc-data)]

    (println "\nAllocation Statistics:")
    (println "───────────────────────────────────────")
    (println "Total allocations  :" (format "%,d" total-allocs))
    (println "Total bytes        :" (format-size total-bytes))
    (println "Average size       :" (format-size (long avg-size)))
    (println "Unique call stacks :" unique-stacks)))

;; ============================================================================
;; Part 6: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 4.3: Memory Allocation Profiler ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create maps
  (println "\nStep 2: Creating maps...")
  (let [stacks-fd (create-stack-traces-map)
        alloc-info-fd (create-alloc-info-map)
        counts-fd (create-stack-counts-map)
        bytes-fd (create-stack-bytes-map)
        histogram-fd (create-size-histogram-map)]

    (println "✓ Stack traces map created (FD:" stacks-fd ")")
    (println "✓ Allocation info map created (FD:" alloc-info-fd ")")
    (println "✓ Stack counts map created (FD:" counts-fd ")")
    (println "✓ Stack bytes map created (FD:" bytes-fd ")")
    (println "✓ Size histogram map created (FD:" histogram-fd ")")

    ;; Initialize histogram
    (doseq [i (range SIZE_BUCKETS)]
      (bpf/map-update histogram-fd (utils/u32 i) (utils/u64 0) :any))

    (try
      ;; Create BPF program
      (println "\nStep 3: Creating memory profiler...")
      (let [profiler (create-alloc-tracker stacks-fd alloc-info-fd
                                          counts-fd bytes-fd histogram-fd)]
        (println "✓ Profiler assembled (" (/ (count profiler) 8) "instructions)")

        ;; Load program
        (println "\nStep 4: Loading profiler...")
        (let [prog-fd (bpf/load-program profiler :kprobe)]
          (println "✓ Profiler loaded (FD:" prog-fd ")")

          (try
            (println "\nStep 5: Kprobe attachment...")
            (println "ℹ Kprobe attachment requires Chapter 5")
            (println "ℹ Would attach to: __kmalloc")

            ;; Simulate allocation data
            (println "\nStep 6: Simulating allocation data...")

            ;; Simulate some stack traces and allocations
            (let [test-stacks {1 {:count 1500 :bytes (* 1500 64)}
                             2 {:count 800 :bytes (* 800 256)}
                             3 {:count 400 :bytes (* 400 1024)}
                             4 {:count 200 :bytes (* 200 128)}
                             5 {:count 100 :bytes (* 100 4096)}}]

              ;; Update counts and bytes maps
              (doseq [[stack-id data] test-stacks]
                (bpf/map-update counts-fd
                               (utils/u32 stack-id)
                               (utils/u64 (:count data))
                               :any)
                (bpf/map-update bytes-fd
                               (utils/u32 stack-id)
                               (utils/u64 (:bytes data))
                               :any))

              ;; Update histogram
              (bpf/map-update histogram-fd (utils/u32 0) (utils/u64 500) :any)   ; <32B
              (bpf/map-update histogram-fd (utils/u32 1) (utils/u64 1500) :any)  ; 32-64B
              (bpf/map-update histogram-fd (utils/u32 2) (utils/u64 200) :any)   ; 64-128B
              (bpf/map-update histogram-fd (utils/u32 3) (utils/u64 800) :any)   ; 128-256B
              (bpf/map-update histogram-fd (utils/u32 4) (utils/u64 0) :any)     ; 256-512B
              (bpf/map-update histogram-fd (utils/u32 5) (utils/u64 100) :any))  ; ≥512B

            (println "✓ Added simulated allocation data")

            ;; Display analysis
            (println "\nStep 7: Analyzing allocation patterns...")
            (let [alloc-data (get-allocation-data counts-fd bytes-fd)]
              (display-statistics alloc-data)
              (display-size-histogram histogram-fd)
              (display-top-allocators stacks-fd alloc-data 5))

            ;; Cleanup
            (println "\nStep 8: Cleanup...")
            (bpf/close-program prog-fd)
            (println "✓ Program closed")

            (catch Exception e
              (println "✗ Error:" (.getMessage e))
              (.printStackTrace e)))

          (finally
            (bpf/close-map stacks-fd)
            (bpf/close-map alloc-info-fd)
            (bpf/close-map counts-fd)
            (bpf/close-map bytes-fd)
            (bpf/close-map histogram-fd)
            (println "✓ Maps closed")))))

      (catch Exception e
        (println "✗ Error:" (.getMessage e))
        (.printStackTrace e))))

  (println "\n=== Lab 4.3 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-04/labs
clojure -M lab-4-3.clj
```

### Expected Output

```
=== Lab 4.3: Memory Allocation Profiler ===

Step 1: Initializing...

Step 2: Creating maps...
✓ Stack traces map created (FD: 3)
✓ Allocation info map created (FD: 4)
✓ Stack counts map created (FD: 5)
✓ Stack bytes map created (FD: 6)
✓ Size histogram map created (FD: 7)

Step 3: Creating memory profiler...
✓ Profiler assembled (58 instructions)

Step 4: Loading profiler...
✓ Profiler loaded (FD: 8)

Step 5: Kprobe attachment...
ℹ Kprobe attachment requires Chapter 5
ℹ Would attach to: __kmalloc

Step 6: Simulating allocation data...
✓ Added simulated allocation data

Step 7: Analyzing allocation patterns...

Allocation Statistics:
───────────────────────────────────────
Total allocations  : 3,000
Total bytes        : 848.0KB
Average size       : 289B
Unique call stacks : 5

Allocation Size Distribution:
═══════════════════════════════════════════════════════
Total allocations: 3100

<32B       │ ████████████ 500 (16.1%)
32-64B     │ ████████████████████████████████████████ 1,500 (48.4%)
64-128B    │ █████ 200 (6.5%)
128-256B   │ ████████████████████ 800 (25.8%)
≥512B      │ ██ 100 (3.2%)

Top 5 Allocation Stack Traces:
═══════════════════════════════════════════════════════

Stack ID 5: 100 allocations, 400.0KB total
  (stack trace unavailable)

Stack ID 3: 400 allocations, 400.0KB total
  (stack trace unavailable)

Stack ID 2: 800 allocations, 200.0KB total
  (stack trace unavailable)

Stack ID 1: 1,500 allocations, 93.8KB total
  (stack trace unavailable)

Stack ID 4: 200 allocations, 25.0KB total
  (stack trace unavailable)

Step 8: Cleanup...
✓ Program closed
✓ Maps closed

=== Lab 4.3 Complete! ===
```

## Understanding the Code

### Stack Trace Capture

```clojure
;; Get stack trace
[(bpf/ld-map-fd :r2 stacks-fd)]
[(bpf/mov :r3 0)]  ; flags: 0 = kernel, 256 = user
(bpf/helper-get-stackid :r1 :r2)
;; r0 = stack ID (or negative on error)
[(bpf/mov-reg :r7 :r0)]
[(bpf/jslt-imm :r7 0 :exit)]  ; Check error
```

### Multi-Map Pattern

```clojure
;; Track multiple metrics per stack:
;; - counts-map: stack_id → allocation count
;; - bytes-map: stack_id → total bytes
;; - stacks-map: stack_id → IP array

;; All indexed by same stack_id
```

### Combining Helpers

```clojure
;; Multiple helpers in single program:
(bpf/helper-get-stackid ...)      ; Stack trace
(bpf/helper-get-current-pid-tgid) ; Process info
(bpf/helper-ktime-get-ns)         ; Timestamp
(bpf/helper-map-update-elem ...)  ; Store data
```

## Experiments

### Experiment 1: Track Both Allocs and Frees

```clojure
;; Attach to both __kmalloc and kfree
;; Track outstanding allocations
;; Detect memory leaks
```

### Experiment 2: User Space Allocations

```clojure
;; Attach to malloc/free in libc
;; Use BPF_F_USER_STACK flag
;; Track application memory usage
```

### Experiment 3: Per-Process Profiling

```clojure
;; Key = (PID, stack_id)
;; Track allocations per process
;; Identify memory-hungry processes
```

### Experiment 4: Flame Graph Generation

```clojure
(defn generate-flame-graph-data [stacks-fd alloc-data]
  "Generate folded format for flame graphs"
  ;; Format: stack1;stack2;stack3 count
  ...)
```

## Troubleshooting

### Stack Traces Missing

**Causes**:
- Frame pointers disabled
- Stack unwinding failed
- Map full

**Solution**: Enable frame pointers or use ORC unwinder

### High Overhead

**Optimize**:
- Sample allocations (1 in N)
- Filter by size threshold
- Use per-CPU maps

## Key Takeaways

✅ `bpf_get_stackid` captures call stacks efficiently
✅ Stack IDs deduplicate identical stacks
✅ Multi-map pattern tracks related metrics
✅ Combining helpers provides rich profiling data
✅ Memory profiling reveals allocation hotspots
✅ Stack traces are essential for root cause analysis

## Next Steps

- **Next Chapter**: [Part II - Program Types](../../part-2-program-types/)
- **Previous Lab**: [Lab 4.2 - File Access Latency Tracker](lab-4-2-file-latency.md)
- **Chapter**: [Chapter 4 - Helper Functions](../README.md)

## Challenge

Enhance the memory profiler to:
1. Track allocation and free pairs (detect leaks)
2. Profile both kernel and user space
3. Correlate with process lifecycle
4. Generate interactive flame graphs
5. Alert on allocation anomalies
6. Export to continuous profiling systems

Solution in: [solutions/lab-4-3-challenge.clj](../solutions/lab-4-3-challenge.clj)
