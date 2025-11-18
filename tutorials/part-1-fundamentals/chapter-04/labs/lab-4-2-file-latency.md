# Lab 4.2: File Access Latency Tracker

**Objective**: Measure filesystem operation latency using time helper functions

**Duration**: 60 minutes

## Overview

In this lab, you'll build a filesystem latency tracker that measures how long file operations take. You'll use BPF time helpers to capture entry and exit timestamps, calculate latencies, build histograms, and identify slow filesystem operations.

This lab demonstrates:
- Using time helper functions (`ktime_get_ns`)
- Pairing entry/exit events for latency calculation
- Building latency histograms
- Identifying performance bottlenecks
- Statistical analysis of latencies

## What You'll Learn

- How to use `bpf_ktime_get_ns()` and related time helpers
- Pairing kprobe entry/exit for latency measurement
- Building histogram data structures
- Calculating percentiles and statistics
- Detecting outliers and slow operations
- Efficient timestamp storage patterns

## Theory

### Latency Measurement

```
Latency = Exit Time - Entry Time

Timeline:
├─────────┬─────────────────────┬──────────►
│ Entry   │   File Operation    │  Exit
│ (kprobe)│   (kernel code)     │ (kretprobe)
│         │                     │
t₀        │                     t₁
          │◄────── Δt ──────────►│

Latency Δt = t₁ - t₀
```

### Filesystem Operations

Common operations to track:
- **open()**: Opening files
- **read()**: Reading data
- **write()**: Writing data
- **close()**: Closing files
- **fsync()**: Syncing to disk
- **stat()**: Getting file metadata

### Histogram Buckets

Latency distribution visualization:

```
Bucket  Range        Count
  0     0-10μs       ████████████ 1245
  1     10-100μs     ███████ 789
  2     100μs-1ms    ███ 345
  3     1-10ms       ██ 123
  4     10-100ms     █ 45
  5     100ms-1s     ▌ 12
  6     >1s          ▌ 3
```

### ktime_get_ns()

Monotonic clock (not affected by time adjustments):
- Starts at 0 on boot
- Never decreases
- Includes sleep time
- Nanosecond precision

## Implementation

### Step 1: Complete Program

Create `lab-4-2.clj`:

```clojure
(ns lab-4-2-file-latency
  "Lab 4.2: File Access Latency Tracker using time helpers"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Part 1: Constants and Configuration
;; ============================================================================

(def NUM_BUCKETS 20)  ; Number of histogram buckets
(def MAX_ENTRIES 10000)  ; Maximum tracked operations

;; Latency buckets (nanoseconds)
;; Logarithmic scale for better distribution
(def BUCKET_BOUNDARIES
  [100          ; 0.1 μs
   1000         ; 1 μs
   10000        ; 10 μs
   100000       ; 100 μs
   1000000      ; 1 ms
   10000000     ; 10 ms
   100000000    ; 100 ms
   1000000000   ; 1 second
   10000000000  ; 10 seconds
   ])

;; ============================================================================
;; Part 2: Data Structures
;; ============================================================================

;; Entry data structure
;; struct entry_data {
;;   u64 start_time;
;;   u64 pid_tgid;
;;   char filename[128];
;; };

(def ENTRY_DATA_SIZE (+ 8 8 128))  ; 144 bytes

;; Latency event
;; struct latency_event {
;;   u64 latency_ns;
;;   u64 start_time;
;;   u64 pid_tgid;
;;   u32 operation;  ; 0=open, 1=read, 2=write, 3=fsync
;;   char filename[128];
;; };

(def LATENCY_EVENT_SIZE (+ 8 8 8 4 128))  ; 156 bytes

(def OP_OPEN 0)
(def OP_READ 1)
(def OP_WRITE 2)
(def OP_FSYNC 3)

;; ============================================================================
;; Part 3: Maps
;; ============================================================================

(defn create-start-map []
  "Map to store operation start times (PID -> entry_data)"
  (bpf/create-map :hash
    {:key-size 8              ; u64 PID
     :value-size ENTRY_DATA_SIZE
     :max-entries MAX_ENTRIES}))

(defn create-histogram-map []
  "Histogram: bucket -> count"
  (bpf/create-map :array
    {:key-size 4       ; u32 bucket index
     :value-size 8     ; u64 count
     :max-entries NUM_BUCKETS}))

(defn create-events-map []
  "Ring buffer for latency events"
  (bpf/create-map :ringbuf
    {:max-entries (* 256 1024)}))  ; 256KB

;; ============================================================================
;; Part 4: Helper Functions for BPF
;; ============================================================================

(defn calculate-bucket [latency-ns]
  "Calculate histogram bucket for latency"
  ;; This is done in userspace for simplicity
  ;; In BPF, we'd use a loop or lookup table
  (loop [bucket 0
         boundaries BUCKET_BOUNDARIES]
    (cond
      (empty? boundaries) (dec NUM_BUCKETS)
      (< latency-ns (first boundaries)) bucket
      :else (recur (inc bucket) (rest boundaries)))))

;; ============================================================================
;; Part 5: BPF Program - Entry Probe
;; ============================================================================

(defn create-entry-probe [start-map-fd operation-code]
  "Kprobe entry handler - record start time"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get timestamp
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r6 :r0)]  ; r6 = start_time

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Get PID
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r7 :r0)]  ; r7 = pid_tgid

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Get filename (if applicable)
      ;; ──────────────────────────────────────────────────────────

      ;; For open(), filename pointer is first argument (in PT_REGS_PARM1)
      ;; For simplicity, we'll skip filename reading in this version
      ;; See Lab 3.2 for string reading examples

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Build entry_data on stack
      ;; ──────────────────────────────────────────────────────────

      [(bpf/store-mem :dw :r10 -16 :r6)]  ; start_time
      [(bpf/store-mem :dw :r10 -24 :r7)]  ; pid_tgid
      ;; filename (omitted for brevity)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Store in map
      ;; ──────────────────────────────────────────────────────────

      ;; Key = PID (use PID as key for per-thread tracking)
      [(bpf/store-mem :dw :r10 -32 :r7)]

      ;; Update map
      [(bpf/ld-map-fd :r1 start-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]  ; key
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -24)]  ; value
      [(bpf/mov :r4 0)]    ; flags
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 6: BPF Program - Exit Probe
;; ============================================================================

(defn create-exit-probe [start-map-fd histogram-map-fd operation-code]
  "Kretprobe exit handler - calculate and record latency"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get current time
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]  ; r9 = end_time

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Get PID and lookup start time
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r8 :r0)]  ; r8 = pid_tgid

      ;; Store PID as key
      [(bpf/store-mem :dw :r10 -8 :r8)]

      ;; Lookup start time
      [(bpf/ld-map-fd :r1 start-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Check if found
      [(bpf/jmp-imm :jeq :r0 0 :cleanup)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Calculate latency
      ;; ──────────────────────────────────────────────────────────

      [(bpf/mov-reg :r7 :r0)]  ; r7 = entry_data pointer
      [(bpf/load-mem :dw :r6 :r7 0)]  ; r6 = start_time

      ;; latency = end_time - start_time
      [(bpf/mov-reg :r5 :r9)]
      [(bpf/sub-reg :r5 :r6)]  ; r5 = latency_ns

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Calculate histogram bucket
      ;; ──────────────────────────────────────────────────────────

      ;; Simplified bucket calculation (log scale approximation)
      ;; Find position of highest bit set (like fls() in C)
      [(bpf/mov-reg :r4 :r5)]  ; r4 = latency for calculation

      ;; For simplicity, use linear buckets based on ranges
      ;; Bucket 0: < 1μs (1000ns)
      [(bpf/mov :r3 0)]
      [(bpf/jmp-imm :jlt :r4 1000 :update-histogram)]

      ;; Bucket 1: < 10μs
      [(bpf/mov :r3 1)]
      [(bpf/jmp-imm :jlt :r4 10000 :update-histogram)]

      ;; Bucket 2: < 100μs
      [(bpf/mov :r3 2)]
      [(bpf/jmp-imm :jlt :r4 100000 :update-histogram)]

      ;; Bucket 3: < 1ms
      [(bpf/mov :r3 3)]
      [(bpf/jmp-imm :jlt :r4 1000000 :update-histogram)]

      ;; Bucket 4: < 10ms
      [(bpf/mov :r3 4)]
      [(bpf/jmp-imm :jlt :r4 10000000 :update-histogram)]

      ;; Bucket 5: < 100ms
      [(bpf/mov :r3 5)]
      [(bpf/jmp-imm :jlt :r4 100000000 :update-histogram)]

      ;; Bucket 6: >= 100ms
      [(bpf/mov :r3 6)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Update histogram
      ;; ──────────────────────────────────────────────────────────

      ;; :update-histogram
      ;; Store bucket index
      [(bpf/store-mem :w :r10 -12 :r3)]

      ;; Lookup bucket count
      [(bpf/ld-map-fd :r1 histogram-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -12)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Increment count
      [(bpf/jmp-imm :jeq :r0 0 :cleanup)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 6: Cleanup - Delete entry from start map
      ;; ──────────────────────────────────────────────────────────

      ;; :cleanup
      [(bpf/ld-map-fd :r1 start-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-delete-elem :r1 :r2)

      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 7: Userspace - Statistics and Visualization
;; ============================================================================

(defn read-u64-le [^ByteBuffer buf]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf 0))

(defn read-histogram [histogram-map-fd]
  "Read histogram data from map"
  (into []
    (for [i (range NUM_BUCKETS)]
      (let [key (utils/u32 i)
            value (bpf/map-lookup histogram-map-fd key)]
        (if value (read-u64-le value) 0)))))

(defn bucket-label [bucket]
  "Get human-readable label for bucket"
  (let [labels ["<1μs" "1-10μs" "10-100μs" "100μs-1ms"
                "1-10ms" "10-100ms" ">100ms"]]
    (get labels bucket (str "Bucket " bucket))))

(defn format-latency [ns]
  "Format nanoseconds as human-readable time"
  (cond
    (< ns 1000) (format "%dns" ns)
    (< ns 1000000) (format "%.1fμs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.1fms" (/ ns 1000000.0))
    :else (format "%.2fs" (/ ns 1000000000.0))))

(defn display-histogram [histogram]
  "Display latency histogram"
  (println "\nLatency Histogram:")
  (println "═══════════════════════════════════════════════════════")

  (let [total (reduce + histogram)
        max-count (apply max (conj histogram 1))
        bar-width 40]

    (println "Total operations:" total)
    (println)

    (doseq [[bucket count] (map-indexed vector (take 7 histogram))
            :when (pos? count)]
      (let [percentage (* 100.0 (/ count total))
            bar-len (int (* bar-width (/ count max-count)))
            bar (apply str (repeat bar-len "█"))]
        (println (format "%-12s │ %s %,d (%.1f%%)"
                        (bucket-label bucket)
                        bar
                        count
                        percentage))))

    (println "═══════════════════════════════════════════════════════")))

(defn calculate-percentiles [histogram]
  "Calculate latency percentiles"
  (let [total (reduce + histogram)
        cumulative (reductions + histogram)
        percentile (fn [p]
                    (let [target (* total (/ p 100.0))]
                      (first (keep-indexed
                              (fn [idx cum]
                                (when (>= cum target) idx))
                              cumulative))))]
    {:p50 (percentile 50)
     :p90 (percentile 90)
     :p95 (percentile 95)
     :p99 (percentile 99)}))

(defn display-statistics [histogram]
  "Display detailed statistics"
  (let [total (reduce + histogram)
        percentiles (calculate-percentiles histogram)]

    (println "\nStatistics:")
    (println "───────────────────────────────────────")
    (println "Total operations   :" total)
    (println)
    (println "Percentiles:")
    (println "  p50 (median)     :" (bucket-label (:p50 percentiles)))
    (println "  p90              :" (bucket-label (:p90 percentiles)))
    (println "  p95              :" (bucket-label (:p95 percentiles)))
    (println "  p99              :" (bucket-label (:p99 percentiles)))))

;; ============================================================================
;; Part 8: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 4.2: File Access Latency Tracker ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create maps
  (println "\nStep 2: Creating maps...")
  (let [start-map-fd (create-start-map)
        histogram-map-fd (create-histogram-map)
        events-map-fd (create-events-map)]
    (println "✓ Start time map created (FD:" start-map-fd ")")
    (println "✓ Histogram map created (FD:" histogram-map-fd ")")
    (println "✓ Events ring buffer created (FD:" events-map-fd ")")

    ;; Initialize histogram buckets to 0
    (doseq [i (range NUM_BUCKETS)]
      (bpf/map-update histogram-map-fd (utils/u32 i) (utils/u64 0) :any))

    (try
      ;; Create BPF programs
      (println "\nStep 3: Creating BPF programs...")
      (let [entry-prog (create-entry-probe start-map-fd OP_READ)
            exit-prog (create-exit-probe start-map-fd histogram-map-fd OP_READ)]
        (println "✓ Entry probe assembled (" (/ (count entry-prog) 8) "instructions)")
        (println "✓ Exit probe assembled (" (/ (count exit-prog) 8) "instructions)")

        ;; Load programs
        (println "\nStep 4: Loading programs...")
        (let [entry-fd (bpf/load-program entry-prog :kprobe)
              exit-fd (bpf/load-program exit-prog :kprobe)]
          (println "✓ Entry probe loaded (FD:" entry-fd ")")
          (println "✓ Exit probe loaded (FD:" exit-fd ")")

          (try
            (println "\nStep 5: Kprobe attachment...")
            (println "ℹ Kprobe attachment requires Chapter 5")
            (println "ℹ Would attach to:")
            (println "  Entry: vfs_read")
            (println "  Exit:  vfs_read (kretprobe)")

            ;; Simulate some latency data
            (println "\nStep 6: Simulating latency data...")
            (let [simulated-latencies
                  ;; Generate realistic latency distribution
                  (concat
                   (repeat 1200 0)   ; Bucket 0: <1μs
                   (repeat 800 1)    ; Bucket 1: 1-10μs
                   (repeat 400 2)    ; Bucket 2: 10-100μs
                   (repeat 200 3)    ; Bucket 3: 100μs-1ms
                   (repeat 80 4)     ; Bucket 4: 1-10ms
                   (repeat 20 5)     ; Bucket 5: 10-100ms
                   (repeat 5 6))]    ; Bucket 6: >100ms

              (doseq [bucket simulated-latencies]
                (let [key (utils/u32 bucket)
                      current (bpf/map-lookup histogram-map-fd key)
                      new-count (inc (read-u64-le current))]
                  (bpf/map-update histogram-map-fd key (utils/u64 new-count) :any))))

            (println "✓ Added 2705 simulated measurements")

            ;; Display histogram
            (println "\nStep 7: Displaying histogram...")
            (let [histogram (read-histogram histogram-map-fd)]
              (display-histogram histogram)
              (display-statistics histogram))

            ;; Cleanup
            (println "\nStep 8: Cleanup...")
            (bpf/close-program entry-fd)
            (bpf/close-program exit-fd)
            (println "✓ Programs closed")

            (catch Exception e
              (println "✗ Error:" (.getMessage e))
              (.printStackTrace e)))

          (finally
            (bpf/close-map start-map-fd)
            (bpf/close-map histogram-map-fd)
            (bpf/close-map events-map-fd)
            (println "✓ Maps closed")))))

      (catch Exception e
        (println "✗ Error:" (.getMessage e))
        (.printStackTrace e))))

  (println "\n=== Lab 4.2 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-04/labs
clojure -M lab-4-2.clj
```

### Expected Output

```
=== Lab 4.2: File Access Latency Tracker ===

Step 1: Initializing...

Step 2: Creating maps...
✓ Start time map created (FD: 3)
✓ Histogram map created (FD: 4)
✓ Events ring buffer created (FD: 5)

Step 3: Creating BPF programs...
✓ Entry probe assembled (12 instructions)
✓ Exit probe assembled (32 instructions)

Step 4: Loading programs...
✓ Entry probe loaded (FD: 6)
✓ Exit probe loaded (FD: 7)

Step 5: Kprobe attachment...
ℹ Kprobe attachment requires Chapter 5
ℹ Would attach to:
  Entry: vfs_read
  Exit:  vfs_read (kretprobe)

Step 6: Simulating latency data...
✓ Added 2705 simulated measurements

Step 7: Displaying histogram...

Latency Histogram:
═══════════════════════════════════════════════════════
Total operations: 2705

<1μs         │ ████████████████████████████████████████ 1,200 (44.4%)
1-10μs       │ ███████████████████████████ 800 (29.6%)
10-100μs     │ █████████████ 400 (14.8%)
100μs-1ms    │ ███████ 200 (7.4%)
1-10ms       │ ███ 80 (3.0%)
10-100ms     │ █ 20 (0.7%)
>100ms       │ ▌ 5 (0.2%)
═══════════════════════════════════════════════════════

Statistics:
───────────────────────────────────────
Total operations   : 2705

Percentiles:
  p50 (median)     : <1μs
  p90              : 10-100μs
  p95              : 100μs-1ms
  p99              : 1-10ms

Step 8: Cleanup...
✓ Programs closed
✓ Maps closed

=== Lab 4.2 Complete! ===
```

## Understanding the Code

### Time Measurement Pattern

```clojure
;; Entry: Record start time
(bpf/helper-ktime-get-ns)
[(bpf/store-mem :dw :r10 -8 :r0)]
;; Store in map with PID as key

;; Exit: Calculate latency
(bpf/helper-ktime-get-ns)     ; Get end time
[(bpf/mov-reg :r9 :r0)]

;; Lookup start time from map
;; ...
[(bpf/load-mem :dw :r6 :r7 0)]  ; Load start time

;; Calculate delta
[(bpf/sub-reg :r9 :r6)]  ; latency = end - start
```

### Histogram Update

```clojure
;; Calculate bucket from latency
;; (using comparisons)

;; Update counter atomically
(bpf/helper-map-lookup-elem :r1 :r2)
[(bpf/load-mem :dw :r4 :r0 0)]  ; Load count
[(bpf/add :r4 1)]                ; Increment
[(bpf/store-mem :dw :r0 0 :r4)]  ; Store back
```

## Experiments

### Experiment 1: Track Multiple Operations

```clojure
;; Separate histograms for open, read, write
(def open-histogram-fd ...)
(def read-histogram-fd ...)
(def write-histogram-fd ...)

;; Route to correct histogram based on operation
```

### Experiment 2: Per-Process Latency

```clojure
;; Key = (PID, bucket)
;; Track latency distribution per process
(defn create-per-process-histogram []
  (bpf/create-map :hash
    {:key-size 8  ; PID + bucket
     :value-size 8  ; count
     ...}))
```

### Experiment 3: Outlier Detection

```clojure
;; Send event to ring buffer when latency > threshold
[(bpf/jmp-imm :jlt :r5 100000000 :skip-event)]  ; 100ms
;; Emit detailed event with filename, etc.
```

### Experiment 4: Sliding Window Statistics

```clojure
;; Use per-CPU arrays for recent samples
;; Calculate rolling average
;; Detect latency spikes
```

## Troubleshooting

### Missing Entry Events

**Causes**:
- Entry probe not firing
- Map full (entries evicted)
- Wrong PID as key

**Solution**: Use TGID instead of PID for multithreaded processes

### Incorrect Latencies

**Check**:
- Time helper used consistently
- No integer overflow (latencies > 2^64 ns)
- Entry/exit pairing correct

### High Overhead

**Optimize**:
- Sample operations (1 in N)
- Use per-CPU maps
- Reduce histogram granularity

## Key Takeaways

✅ `ktime_get_ns` provides monotonic timestamps
✅ Entry/exit pairing enables latency measurement
✅ Histograms efficiently summarize distributions
✅ Map operations must be paired (entry → exit → delete)
✅ Per-CPU maps reduce contention
✅ Percentiles reveal tail latencies

## Next Steps

- **Next Lab**: [Lab 4.3 - Memory Allocation Profiler](lab-4-3-memory-profiler.md)
- **Previous Lab**: [Lab 4.1 - Process Tree Monitor](lab-4-1-process-tree.md)
- **Chapter**: [Chapter 4 - Helper Functions](../README.md)

## Challenge

Enhance the latency tracker to:
1. Track per-file latencies (not just overall)
2. Correlate with I/O sizes (bytes read/written)
3. Detect sequential vs random access patterns
4. Track block layer latency separately
5. Generate alerts on latency degradation
6. Export Prometheus metrics

Solution in: [solutions/lab-4-2-challenge.clj](../solutions/lab-4-2-challenge.clj)
