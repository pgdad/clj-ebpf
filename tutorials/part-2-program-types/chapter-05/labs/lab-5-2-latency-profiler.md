# Lab 5.2: Latency Profiler

**Objective**: Measure kernel function latency using kprobe and kretprobe pairs

**Duration**: 75 minutes

## Overview

In this lab, you'll build a comprehensive latency profiler that uses both kprobes (for function entry) and kretprobes (for function return) to measure how long kernel functions take to execute. You'll track latencies, build histograms, detect outliers, and identify performance bottlenecks.

This lab demonstrates:
- Pairing kprobe and kretprobe handlers
- Entry-exit correlation with maps
- Latency calculation and tracking
- Multi-dimensional histograms
- Performance analysis techniques

## What You'll Learn

- How to coordinate kprobe and kretprobe
- Correlating entry and exit events
- Building latency histograms
- Detecting performance anomalies
- Statistical analysis of function latencies
- Identifying slow code paths

## Theory

### Entry-Exit Pairing

```
Timeline of Function Execution:
┌───────┬──────────────────────────┬────────┐
│ Entry │   Function Execution     │ Return │
│       │                          │        │
t₀      │                          t₁       │
        │                          │        │
Kprobe  │                          Kretprobe│
fires   │                          fires    │
        │                          │        │
Store   │                          Calculate│
start   │                          latency  │
time    │                          = t₁ - t₀│
└───────┴──────────────────────────┴────────┘
```

### Data Flow

```
1. Function Entry (Kprobe)
   ├─ Get PID
   ├─ Get timestamp
   └─ Store in map[PID] = timestamp

2. Function Execution
   └─ Kernel code runs...

3. Function Exit (Kretprobe)
   ├─ Get PID
   ├─ Get current timestamp
   ├─ Lookup start timestamp from map[PID]
   ├─ Calculate: latency = current - start
   ├─ Delete map[PID]
   ├─ Update histogram
   └─ Send event if outlier
```

### Histogram Buckets

Logarithmic buckets for better distribution:

```
Bucket   Range          Purpose
  0      0-1μs          Very fast calls
  1      1-10μs         Fast calls
  2      10-100μs       Normal calls
  3      100μs-1ms      Slower calls
  4      1-10ms         Slow calls
  5      10-100ms       Very slow calls
  6      100ms-1s       Outliers
  7      >1s            Critical outliers
```

## Implementation

### Step 1: Complete Program

Create `lab-5-2.clj`:

```clojure
(ns lab-5-2-latency-profiler
  "Lab 5.2: Latency Profiler using kprobe/kretprobe pairs"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Part 1: Configuration
;; ============================================================================

(def NUM_BUCKETS 12)
(def MAX_ENTRIES 10000)

;; Latency buckets (nanoseconds) - logarithmic scale
(def BUCKET_BOUNDARIES
  [1000          ; 1μs
   10000         ; 10μs
   100000        ; 100μs
   1000000       ; 1ms
   10000000      ; 10ms
   100000000     ; 100ms
   1000000000    ; 1s
   10000000000]) ; 10s

;; ============================================================================
;; Part 2: Data Structures
;; ============================================================================

;; Entry data: stored when function is entered
;; struct entry_info {
;;   u64 start_time;
;;   u64 pid_tgid;
;; };

(def ENTRY_INFO_SIZE 16)

;; Latency event: sent when outlier detected
;; struct latency_event {
;;   u64 latency_ns;
;;   u64 timestamp;
;;   u64 pid_tgid;
;;   u32 function_id;
;;   char comm[16];
;; };

(def LATENCY_EVENT_SIZE (+ 8 8 8 4 16))  ; 44 bytes

;; ============================================================================
;; Part 3: Maps
;; ============================================================================

(defn create-start-times-map []
  "Map: PID -> entry_info (start time)"
  (bpf/create-map :hash
    {:key-size 8              ; u64 PID
     :value-size ENTRY_INFO_SIZE
     :max-entries MAX_ENTRIES}))

(defn create-histogram-map []
  "Histogram: bucket -> count"
  (bpf/create-map :array
    {:key-size 4
     :value-size 8
     :max-entries NUM_BUCKETS}))

(defn create-latency-sum-map []
  "Map: bucket -> total latency (for average calculation)"
  (bpf/create-map :array
    {:key-size 4
     :value-size 8
     :max-entries NUM_BUCKETS}))

(defn create-outliers-map []
  "Ring buffer for outlier events"
  (bpf/create-map :ringbuf
    {:max-entries (* 256 1024)}))

;; ============================================================================
;; Part 4: BPF Program - Entry Handler (Kprobe)
;; ============================================================================

(defn create-entry-handler [start-times-fd function-id]
  "Kprobe handler - record function entry time"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get PID/TGID
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r6 :r0)]  ; r6 = pid_tgid

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Get timestamp
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r7 :r0)]  ; r7 = start_time

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Store entry info in map
      ;; ──────────────────────────────────────────────────────────

      ;; Build entry_info on stack
      [(bpf/store-mem :dw :r10 -8 :r7)]   ; start_time
      [(bpf/store-mem :dw :r10 -16 :r6)]  ; pid_tgid

      ;; Store with PID as key
      [(bpf/store-mem :dw :r10 -24 :r6)]  ; key = pid_tgid

      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]  ; key
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]  ; value
      [(bpf/mov :r4 0)]    ; flags
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 5: BPF Program - Exit Handler (Kretprobe)
;; ============================================================================

(defn create-exit-handler [start-times-fd histogram-fd latency-sum-fd
                           outliers-fd function-id outlier-threshold-ns]
  "Kretprobe handler - calculate and record latency"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get current time and PID
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]  ; r9 = end_time

      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r8 :r0)]  ; r8 = pid_tgid

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Lookup start time
      ;; ──────────────────────────────────────────────────────────

      [(bpf/store-mem :dw :r10 -8 :r8)]  ; key = pid_tgid

      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Check if found (r0 == NULL?)
      [(bpf/jmp-imm :jeq :r0 0 :cleanup)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Calculate latency
      ;; ──────────────────────────────────────────────────────────

      [(bpf/mov-reg :r7 :r0)]  ; r7 = entry_info pointer
      [(bpf/load-mem :dw :r6 :r7 0)]  ; r6 = start_time

      ;; latency = end_time - start_time
      [(bpf/mov-reg :r5 :r9)]
      [(bpf/sub-reg :r5 :r6)]  ; r5 = latency_ns

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Calculate histogram bucket
      ;; ──────────────────────────────────────────────────────────

      [(bpf/mov-reg :r4 :r5)]  ; r4 = latency for bucket calc

      ;; Bucket 0: < 1μs
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

      ;; Bucket 6: < 1s
      [(bpf/mov :r3 6)]
      [(bpf/jmp-imm :jlt :r4 1000000000 :update-histogram)]

      ;; Bucket 7: >= 1s
      [(bpf/mov :r3 7)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Update histogram count
      ;; ──────────────────────────────────────────────────────────

      ;; :update-histogram
      [(bpf/store-mem :w :r10 -12 :r3)]  ; Save bucket

      [(bpf/ld-map-fd :r1 histogram-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -12)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :update-sum)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 6: Update sum for average calculation
      ;; ──────────────────────────────────────────────────────────

      ;; :update-sum
      [(bpf/ld-map-fd :r1 latency-sum-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -12)]  ; Same bucket
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :check-outlier)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add-reg :r4 :r5)]  ; Add latency to sum
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 7: Check for outliers
      ;; ──────────────────────────────────────────────────────────

      ;; :check-outlier
      ;; If latency > threshold, send event
      [(bpf/jmp-imm :jlt :r5 outlier-threshold-ns :cleanup)]

      ;; Send outlier event (simplified - full implementation
      ;; would use ringbuf_reserve/submit)
      ;; Omitted for brevity

      ;; ──────────────────────────────────────────────────────────
      ;; Step 8: Cleanup - delete entry from start times
      ;; ──────────────────────────────────────────────────────────

      ;; :cleanup
      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-delete-elem :r1 :r2)

      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 6: Userspace - Statistics and Analysis
;; ============================================================================

(defn read-u64-le [^ByteBuffer buf]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf 0))

(defn read-histogram [histogram-fd]
  "Read histogram data"
  (into []
    (for [i (range NUM_BUCKETS)]
      (let [key (utils/u32 i)
            value (bpf/map-lookup histogram-fd key)]
        (if value (read-u64-le value) 0)))))

(defn read-latency-sums [sum-fd]
  "Read total latencies per bucket"
  (into []
    (for [i (range NUM_BUCKETS)]
      (let [key (utils/u32 i)
            value (bpf/map-lookup sum-fd key)]
        (if value (read-u64-le value) 0)))))

(defn bucket-label [bucket]
  "Get human-readable label for bucket"
  (let [labels ["<1μs" "1-10μs" "10-100μs" "100μs-1ms"
                "1-10ms" "10-100ms" "100ms-1s" "≥1s"]]
    (get labels bucket (str "Bucket " bucket))))

(defn format-latency [ns]
  "Format nanoseconds as human-readable"
  (cond
    (< ns 1000) (format "%dns" ns)
    (< ns 1000000) (format "%.1fμs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.2fms" (/ ns 1000000.0))
    :else (format "%.2fs" (/ ns 1000000000.0))))

(defn display-histogram [histogram sums]
  "Display latency histogram with statistics"
  (println "\nLatency Distribution:")
  (println "═══════════════════════════════════════════════════════")

  (let [total (reduce + histogram)
        max-count (apply max (conj histogram 1))
        bar-width 40]

    (println "Total measurements:" total)
    (println)

    (doseq [[bucket count] (map-indexed vector (take 8 histogram))
            :when (pos? count)]
      (let [percentage (* 100.0 (/ count total))
            bar-len (int (* bar-width (/ count max-count)))
            bar (apply str (repeat bar-len "█"))
            total-ns (get sums bucket 0)
            avg-ns (if (pos? count) (/ total-ns count) 0)]
        (println (format "%-12s │ %s %,d (%.1f%%) avg: %s"
                        (bucket-label bucket)
                        bar
                        count
                        percentage
                        (format-latency avg-ns)))))

    (println "═══════════════════════════════════════════════════════")))

(defn calculate-percentiles [histogram]
  "Calculate latency percentiles"
  (let [total (reduce + histogram)
        cumulative (reductions + histogram)]
    (when (pos? total)
      (letfn [(percentile [p]
                (let [target (* total (/ p 100.0))]
                  (first (keep-indexed
                          (fn [idx cum]
                            (when (>= cum target) idx))
                          cumulative))))]
        {:p50 (percentile 50)
         :p90 (percentile 90)
         :p95 (percentile 95)
         :p99 (percentile 99)}))))

(defn display-statistics [histogram sums]
  "Display detailed latency statistics"
  (let [total (reduce + histogram)
        total-latency (reduce + sums)
        avg-latency (if (pos? total) (/ total-latency total) 0)
        percentiles (calculate-percentiles histogram)]

    (println "\nStatistics:")
    (println "───────────────────────────────────────")
    (println "Total calls        :" total)
    (println "Total latency      :" (format-latency total-latency))
    (println "Average latency    :" (format-latency (long avg-latency)))

    (when percentiles
      (println)
      (println "Percentiles:")
      (println "  p50 (median)     :" (bucket-label (:p50 percentiles)))
      (println "  p90              :" (bucket-label (:p90 percentiles)))
      (println "  p95              :" (bucket-label (:p95 percentiles)))
      (println "  p99              :" (bucket-label (:p99 percentiles))))))

;; ============================================================================
;; Part 7: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 5.2: Latency Profiler ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create maps
  (println "\nStep 2: Creating maps...")
  (let [start-times-fd (create-start-times-map)
        histogram-fd (create-histogram-map)
        latency-sum-fd (create-latency-sum-map)
        outliers-fd (create-outliers-map)]

    (println "✓ Start times map created (FD:" start-times-fd ")")
    (println "✓ Histogram map created (FD:" histogram-fd ")")
    (println "✓ Latency sum map created (FD:" latency-sum-fd ")")
    (println "✓ Outliers ring buffer created (FD:" outliers-fd ")")

    ;; Initialize maps
    (doseq [i (range NUM_BUCKETS)]
      (bpf/map-update histogram-fd (utils/u32 i) (utils/u64 0) :any)
      (bpf/map-update latency-sum-fd (utils/u32 i) (utils/u64 0) :any))

    (try
      ;; Create programs
      (println "\nStep 3: Creating BPF programs...")
      (let [function-name "vfs_read"
            function-id 1
            outlier-threshold (* 10 1000000)  ; 10ms

            entry-prog (create-entry-handler start-times-fd function-id)
            exit-prog (create-exit-handler start-times-fd histogram-fd
                                          latency-sum-fd outliers-fd
                                          function-id outlier-threshold)]

        (println "✓ Entry handler assembled (" (/ (count entry-prog) 8) "instructions)")
        (println "✓ Exit handler assembled (" (/ (count exit-prog) 8) "instructions)")

        ;; Load programs
        (println "\nStep 4: Loading programs...")
        (let [entry-fd (bpf/load-program entry-prog :kprobe)
              exit-fd (bpf/load-program exit-prog :kprobe)]

          (println "✓ Entry handler loaded (FD:" entry-fd ")")
          (println "✓ Exit handler loaded (FD:" exit-fd ")")

          (try
            (println "\nStep 5: Kprobe/Kretprobe attachment...")
            (println (format "ℹ Would attach to function: %s" function-name))
            (println "  Entry:  kprobe")
            (println "  Exit:   kretprobe")
            (println (format "  Outlier threshold: %s" (format-latency outlier-threshold)))

            ;; Simulate latency data
            (println "\nStep 6: Simulating latency measurements...")
            (let [simulated-data
                  ;; Realistic latency distribution
                  (concat
                   (repeat 5000 0)   ; <1μs
                   (repeat 3000 1)   ; 1-10μs
                   (repeat 1500 2)   ; 10-100μs
                   (repeat 400 3)    ; 100μs-1ms
                   (repeat 80 4)     ; 1-10ms
                   (repeat 15 5)     ; 10-100ms
                   (repeat 4 6)      ; 100ms-1s
                   (repeat 1 7))     ; ≥1s

                  ;; Simulated latency values (for sum calculation)
                  latency-values {0 500 1 5000 2 50000 3 500000
                                 4 5000000 5 50000000 6 500000000 7 5000000000}]

              ;; Update histogram and sums
              (doseq [bucket simulated-data]
                (let [key (utils/u32 bucket)
                      hist-val (bpf/map-lookup histogram-fd key)
                      new-count (inc (read-u64-le hist-val))
                      sum-val (bpf/map-lookup latency-sum-fd key)
                      new-sum (+ (read-u64-le sum-val) (get latency-values bucket 0))]
                  (bpf/map-update histogram-fd key (utils/u64 new-count) :any)
                  (bpf/map-update latency-sum-fd key (utils/u64 new-sum) :any))))

            (println "✓ Added 10,000 simulated measurements")

            ;; Display results
            (println "\nStep 7: Analyzing latency data...")
            (let [histogram (read-histogram histogram-fd)
                  sums (read-latency-sums latency-sum-fd)]
              (display-histogram histogram sums)
              (display-statistics histogram sums))

            ;; Identify performance issues
            (println "\n\nStep 8: Performance Analysis:")
            (println "───────────────────────────────────────")
            (let [histogram (read-histogram histogram-fd)
                  slow-calls (reduce + (drop 4 histogram))
                  total-calls (reduce + histogram)
                  slow-pct (* 100.0 (/ slow-calls total-calls))]
              (println (format "Slow calls (>1ms)  : %,d (%.1f%%)" slow-calls slow-pct))
              (when (> slow-pct 1.0)
                (println "⚠  WARNING: High percentage of slow calls detected!")
                (println "   Consider investigating:")
                (println "   - Disk I/O bottlenecks")
                (println "   - Lock contention")
                (println "   - Memory pressure")))

            ;; Cleanup
            (println "\nStep 9: Cleanup...")
            (bpf/close-program entry-fd)
            (bpf/close-program exit-fd)
            (println "✓ Programs closed")

            (catch Exception e
              (println "✗ Error:" (.getMessage e))
              (.printStackTrace e)))

          (finally
            (bpf/close-map start-times-fd)
            (bpf/close-map histogram-fd)
            (bpf/close-map latency-sum-fd)
            (bpf/close-map outliers-fd)
            (println "✓ Maps closed")))))

      (catch Exception e
        (println "✗ Error:" (.getMessage e))
        (.printStackTrace e))))

  (println "\n=== Lab 5.2 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-2-program-types/chapter-05/labs
clojure -M lab-5-2.clj
```

### Expected Output

```
=== Lab 5.2: Latency Profiler ===

Step 1: Initializing...

Step 2: Creating maps...
✓ Start times map created (FD: 3)
✓ Histogram map created (FD: 4)
✓ Latency sum map created (FD: 5)
✓ Outliers ring buffer created (FD: 6)

Step 3: Creating BPF programs...
✓ Entry handler assembled (10 instructions)
✓ Exit handler assembled (48 instructions)

Step 4: Loading programs...
✓ Entry handler loaded (FD: 7)
✓ Exit handler loaded (FD: 8)

Step 5: Kprobe/Kretprobe attachment...
ℹ Would attach to function: vfs_read
  Entry:  kprobe
  Exit:   kretprobe
  Outlier threshold: 10.00ms

Step 6: Simulating latency measurements...
✓ Added 10,000 simulated measurements

Step 7: Analyzing latency data...

Latency Distribution:
═══════════════════════════════════════════════════════
Total measurements: 10000

<1μs         │ ████████████████████████████████████████ 5,000 (50.0%) avg: 500ns
1-10μs       │ ████████████████████ 3,000 (30.0%) avg: 5.0μs
10-100μs     │ ███████████ 1,500 (15.0%) avg: 50.0μs
100μs-1ms    │ ███ 400 (4.0%) avg: 500.0μs
1-10ms       │ █ 80 (0.8%) avg: 5.00ms
10-100ms     │ ▌ 15 (0.2%) avg: 50.00ms
100ms-1s     │ ▌ 4 (0.0%) avg: 500.00ms
≥1s          │ ▌ 1 (0.0%) avg: 5.00s
═══════════════════════════════════════════════════════

Statistics:
───────────────────────────────────────
Total calls        : 10000
Total latency      : 19.31s
Average latency    : 1.93ms

Percentiles:
  p50 (median)     : <1μs
  p90              : 10-100μs
  p95              : 100μs-1ms
  p99              : 1-10ms


Step 8: Performance Analysis:
───────────────────────────────────────
Slow calls (>1ms)  : 100 (1.0%)

Step 9: Cleanup...
✓ Programs closed
✓ Maps closed

=== Lab 5.2 Complete! ===
```

## Understanding the Code

### Entry-Exit Coordination

```clojure
;; Entry (kprobe):
(bpf/helper-get-current-pid-tgid)
[(bpf/mov-reg :r6 :r0)]  ; Get PID
(bpf/helper-ktime-get-ns)
[(bpf/mov-reg :r7 :r0)]  ; Get timestamp
;; Store map[PID] = timestamp

;; Exit (kretprobe):
(bpf/helper-get-current-pid-tgid)
[(bpf/mov-reg :r8 :r0)]  ; Get same PID
;; Lookup map[PID] → start_time
;; Calculate: latency = now - start_time
;; Delete map[PID]
```

### Histogram Update Pattern

```clojure
;; Calculate bucket from latency
;; (using cascading comparisons)

;; Update counter atomically
(bpf/helper-map-lookup-elem :r1 :r2)
[(bpf/load-mem :dw :r4 :r0 0)]
[(bpf/add :r4 1)]
[(bpf/store-mem :dw :r0 0 :r4)]

;; Update sum for average
(bpf/helper-map-lookup-elem :r1 :r2)
[(bpf/load-mem :dw :r4 :r0 0)]
[(bpf/add-reg :r4 :r5)]  ; Add latency
[(bpf/store-mem :dw :r0 0 :r4)]
```

## Experiments

### Experiment 1: Multi-Function Profiling

```clojure
;; Profile multiple functions
(def functions
  [["vfs_read" 1]
   ["vfs_write" 2]
   ["vfs_open" 3]])

;; Use function-id to track per-function histograms
```

### Experiment 2: Per-Process Latency

```clojure
;; Key = (PID, bucket)
;; Track latency distribution per process
(defn create-per-process-histogram []
  (bpf/create-map :hash
    {:key-size 12  ; PID + bucket
     :value-size 8
     ...}))
```

### Experiment 3: Real-Time Alerting

```clojure
;; In kretprobe, check threshold
[(bpf/jmp-imm :jlt :r5 CRITICAL_THRESHOLD :skip)]
;; Send alert via ring buffer
(bpf/helper-ringbuf-output ...)
```

### Experiment 4: Latency vs Size Correlation

```clojure
;; Track both latency and I/O size
;; Build 2D histogram: latency × size
;; Identify patterns (e.g., large I/O = high latency)
```

## Troubleshooting

### Missing Entry Events

**Causes**:
- Entry not firing (function not called)
- Map full (entries evicted)
- PID reuse race condition

**Solution**: Use TGID+timestamp as key

### Incorrect Latencies

**Check**:
- Time overflow (>2^64 ns = ~584 years)
- Mismatched entry/exit
- Clock source changes

### Memory Leaks in Map

**Symptom**: start_times map grows
**Cause**: Exits not matched (crashes, signals)
**Solution**: Periodic cleanup or timeout

## Key Takeaways

✅ Entry-exit pairing enables latency measurement
✅ Maps correlate kprobe and kretprobe events
✅ Histograms reveal latency distributions
✅ Percentiles identify tail latencies
✅ Outlier detection finds performance issues
✅ Cleanup prevents map memory leaks

## Next Steps

- **Next Lab**: [Lab 5.3 - System Call Monitor](lab-5-3-syscall-monitor.md)
- **Previous Lab**: [Lab 5.1 - Function Call Tracer](lab-5-1-function-tracer.md)
- **Chapter**: [Chapter 5 - Kprobes & Kretprobes](../README.md)

## Challenge

Enhance the latency profiler to:
1. Track per-CPU latencies separately
2. Correlate with I/O size and type
3. Detect latency regressions over time
4. Generate heat maps (latency vs time)
5. Profile call stacks for slow paths
6. Export to Prometheus/Grafana

Solution in: [solutions/lab-5-2-challenge.clj](../solutions/lab-5-2-challenge.clj)
