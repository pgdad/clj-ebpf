# Lab 6.2: Block I/O Latency Monitor

**Duration**: 45-60 minutes | **Difficulty**: Intermediate

## Learning Objectives

In this lab, you will:
- Monitor block device I/O operations
- Measure I/O latency from request to completion
- Track read vs write operations separately
- Analyze I/O patterns and performance
- Build I/O latency histograms
- Identify slow storage operations

## Prerequisites

- Completed [Lab 6.1](lab-6-1-scheduler-tracer.md)
- Understanding of Linux block I/O layer
- Familiarity with storage performance concepts

## Introduction

The Linux block layer manages I/O requests to block devices (hard drives, SSDs, NVMe devices). Two key tracepoints allow us to measure I/O latency:

1. **block_rq_issue**: Request sent to device driver
2. **block_rq_complete**: Request completed by device

Latency = completion_time - issue_time

## Block Tracepoint Formats

### block_rq_issue

```bash
$ sudo cat /sys/kernel/debug/tracing/events/block/block_rq_issue/format

name: block_rq_issue
ID: 1156
format:
    field:unsigned short common_type;      offset:0;  size:2;
    field:unsigned char common_flags;      offset:2;  size:1;
    field:unsigned char common_preempt_count; offset:3; size:1;
    field:int common_pid;                  offset:4;  size:4;

    field:dev_t dev;                       offset:8;  size:4;
    field:sector_t sector;                 offset:16; size:8;
    field:unsigned int nr_sector;          offset:24; size:4;
    field:unsigned int bytes;              offset:28; size:4;
    field:char rwbs[8];                    offset:32; size:8;
    field:char comm[16];                   offset:40; size:16;
    field:__data_loc char[] cmd;           offset:56; size:4;
```

### block_rq_complete

```bash
$ sudo cat /sys/kernel/debug/tracing/events/block/block_rq_complete/format

name: block_rq_complete
ID: 1155
format:
    field:unsigned short common_type;      offset:0;  size:2;
    field:unsigned char common_flags;      offset:2;  size:1;
    field:unsigned char common_preempt_count; offset:3; size:1;
    field:int common_pid;                  offset:4;  size:4;

    field:dev_t dev;                       offset:8;  size:4;
    field:sector_t sector;                 offset:16; size:8;
    field:unsigned int nr_sector;          offset:24; size:4;
    field:int error;                       offset:28; size:4;
    field:char rwbs[8];                    offset:32; size:8;
    field:__data_loc char[] cmd;           offset:40; size:4;
```

**Key Fields**:
- `dev`: Device ID (major:minor)
- `sector`: Starting sector number
- `nr_sector`: Number of sectors
- `bytes`: Number of bytes
- `rwbs`: Operation type ('R' = read, 'W' = write, 'S' = sync, 'M' = metadata)
- `error`: Error code (0 = success)

## Part 1: Basic I/O Request Tracker

Let's start by tracking I/O requests and completions.

### Implementation

```clojure
(ns lab-6-2-block-io-monitor
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.asm-dsl :refer :all]))

;; Tracepoint context offsets
(def BLOCK_RQ_ISSUE_OFFSETS
  {:dev 8         ; dev_t (4 bytes)
   :sector 16     ; sector_t (8 bytes)
   :nr-sector 24  ; unsigned int (4 bytes)
   :bytes 28      ; unsigned int (4 bytes)
   :rwbs 32       ; char[8]
   :comm 40})     ; char[16]

(def BLOCK_RQ_COMPLETE_OFFSETS
  {:dev 8         ; dev_t (4 bytes)
   :sector 16     ; sector_t (8 bytes)
   :nr-sector 24  ; unsigned int (4 bytes)
   :error 28      ; int (4 bytes)
   :rwbs 32})     ; char[8]

;; Request key structure: dev + sector
;; This uniquely identifies a request
(defn create-request-key [dev sector]
  "Create unique key for I/O request"
  ;; Use first 16 bytes of stack: dev (4) + pad (4) + sector (8)
  [(bpf/store-mem :w :r10 -4 dev)]
  [(bpf/mov :r6 0)]
  [(bpf/store-mem :w :r10 -8 :r6)]  ; padding
  [(bpf/store-mem :dw :r10 -16 sector)])

(defn create-io-issue-handler
  "Track I/O request issue time"
  [inflight-fd]
  (bpf/assemble
    (vec (concat
      ;; r8 = ctx pointer
      [(bpf/mov-reg :r8 :r1)]

      ;; Get current timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r7 :r0)]  ; r7 = issue_time

      ;; Read device ID
      [(bpf/load-mem :w :r2 :r8 (:dev BLOCK_RQ_ISSUE_OFFSETS))]
      [(bpf/mov-reg :r6 :r2)]  ; r6 = dev

      ;; Read sector
      [(bpf/load-mem :dw :r3 :r8 (:sector BLOCK_RQ_ISSUE_OFFSETS))]
      [(bpf/mov-reg :r5 :r3)]  ; r5 = sector

      ;; Create key: dev + sector
      [(bpf/store-mem :w :r10 -4 :r6)]   ; dev
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -8 :r4)]   ; padding
      [(bpf/store-mem :dw :r10 -16 :r5)] ; sector

      ;; Store issue_time in inflight map
      [(bpf/store-mem :dw :r10 -24 :r7)] ; value = timestamp

      [(bpf/ld-map-fd :r1 inflight-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -16)]  ; key pointer
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -24)]  ; value pointer
      [(bpf/mov :r4 0)]    ; BPF_ANY
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn create-io-complete-handler
  "Track I/O request completion and calculate latency"
  [inflight-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; r8 = ctx pointer
      [(bpf/mov-reg :r8 :r1)]

      ;; Get current timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]  ; r9 = complete_time

      ;; Read device ID
      [(bpf/load-mem :w :r2 :r8 (:dev BLOCK_RQ_COMPLETE_OFFSETS))]
      [(bpf/mov-reg :r6 :r2)]  ; r6 = dev

      ;; Read sector
      [(bpf/load-mem :dw :r3 :r8 (:sector BLOCK_RQ_COMPLETE_OFFSETS))]
      [(bpf/mov-reg :r5 :r3)]  ; r5 = sector

      ;; Create key: dev + sector
      [(bpf/store-mem :w :r10 -4 :r6)]
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -8 :r4)]
      [(bpf/store-mem :dw :r10 -16 :r5)]

      ;; Lookup issue_time
      [(bpf/ld-map-fd :r1 inflight-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -16)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If not found, exit (missed issue event)
      [(bpf/jmp-imm :jeq :r0 0 :exit)]

      ;; Calculate latency
      [(bpf/load-mem :dw :r3 :r0 0)]  ; issue_time
      [(bpf/sub-reg :r9 :r3)]         ; latency = complete - issue
      [(bpf/mov-reg :r7 :r9)]         ; r7 = latency

      ;; Determine operation type (read or write)
      ;; rwbs[0] == 'R' -> read, rwbs[0] == 'W' -> write
      [(bpf/load-mem :b :r4 :r8 (:rwbs BLOCK_RQ_COMPLETE_OFFSETS))]

      ;; Check for 'R' (0x52)
      [(bpf/jmp-imm :jeq :r4 0x52 :is-read)]
      ;; Check for 'W' (0x57)
      [(bpf/jmp-imm :jeq :r4 0x57 :is-write)]
      [(bpf/jmp :cleanup)]  ; Unknown, skip

      ;; :is-read - Update read stats
      [(bpf/mov :r6 0)]  ; key = 0 (read)
      [(bpf/jmp :update-stats)]

      ;; :is-write - Update write stats
      [(bpf/mov :r6 1)]  ; key = 1 (write)

      ;; :update-stats
      [(bpf/store-mem :w :r10 -24 :r6)]  ; key

      ;; Lookup current stats
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If exists, update
      [(bpf/jmp-imm :jeq :r0 0 :init-stats)]

      ;; Update: count++, total_latency += latency
      [(bpf/load-mem :dw :r3 :r0 0)]   ; count
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]

      [(bpf/load-mem :dw :r3 :r0 8)]   ; total_latency
      [(bpf/add-reg :r3 :r7)]
      [(bpf/store-mem :dw :r0 8 :r3)]

      ;; Check if this is max latency
      [(bpf/load-mem :dw :r3 :r0 16)]  ; max_latency
      [(bpf/jmp-reg :jge :r3 :r7 :cleanup)]  ; if max >= latency, skip
      [(bpf/store-mem :dw :r0 16 :r7)] ; update max
      [(bpf/jmp :cleanup)]

      ;; :init-stats - First operation
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -32 :r3)]  ; count = 1
      [(bpf/store-mem :dw :r10 -40 :r7)]  ; total_latency = latency
      [(bpf/store-mem :dw :r10 -48 :r7)]  ; max_latency = latency

      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -48)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; :cleanup - Delete inflight entry
      [(bpf/ld-map-fd :r1 inflight-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -16)]
      (bpf/helper-map-delete-elem :r1 :r2)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn run-basic-io-tracker []
  (println "Creating basic I/O latency tracker...")

  ;; Map: (dev, sector) -> issue_timestamp
  (let [inflight-fd (bpf/create-map :hash
                                     {:key-size 16  ; dev(4) + pad(4) + sector(8)
                                      :value-size 8  ; timestamp
                                      :max-entries 10240})

        ;; Map: op_type (0=read, 1=write) -> {count, total_latency, max_latency}
        stats-fd (bpf/create-map :hash
                                  {:key-size 4
                                   :value-size 24  ; 3 * u64
                                   :max-entries 2})]

    ;; Load and attach programs
    (let [issue-prog (create-io-issue-handler inflight-fd)
          complete-prog (create-io-complete-handler inflight-fd stats-fd)

          issue-fd (bpf/load-program issue-prog :tracepoint)
          complete-fd (bpf/load-program complete-prog :tracepoint)

          issue-link (bpf/attach-tracepoint issue-fd "block/block_rq_issue")
          complete-link (bpf/attach-tracepoint complete-fd "block/block_rq_complete")]

      (println "Tracking block I/O operations for 10 seconds...")
      (println "Generate some I/O with: dd if=/dev/sda of=/dev/null bs=4k count=1000\n")

      (Thread/sleep 10000)

      ;; Read and display stats
      (println "\nBlock I/O Statistics:")
      (println "----------------------------------------")

      (doseq [[op-name op-key] [["Reads" 0] ["Writes" 1]]]
        (when-let [stats (bpf/map-lookup stats-fd (int-array [op-key]))]
          (let [count (aget stats 0)
                total-latency (aget stats 1)
                max-latency (aget stats 2)
                avg-latency (if (> count 0) (/ total-latency count) 0)
                avg-latency-us (/ avg-latency 1000.0)
                max-latency-us (/ max-latency 1000.0)]
            (println (format "%s:" op-name))
            (println (format "  Count:        %d" count))
            (println (format "  Avg Latency:  %.2f μs" avg-latency-us))
            (println (format "  Max Latency:  %.2f μs" max-latency-us))
            (println))))

      ;; Cleanup
      (bpf/detach-tracepoint issue-link)
      (bpf/detach-tracepoint complete-link)
      (bpf/close-program issue-fd)
      (bpf/close-program complete-fd)
      (bpf/close-map inflight-fd)
      (bpf/close-map stats-fd))))
```

### Expected Output

```
Creating basic I/O latency tracker...
Tracking block I/O operations for 10 seconds...
Generate some I/O with: dd if=/dev/sda of=/dev/null bs=4k count=1000

Block I/O Statistics:
----------------------------------------
Reads:
  Count:        1523
  Avg Latency:  234.56 μs
  Max Latency:  1245.78 μs

Writes:
  Count:        892
  Avg Latency:  456.78 μs
  Max Latency:  3456.89 μs
```

## Part 2: I/O Latency Histogram

Now let's build a detailed latency histogram to understand the distribution.

### Implementation

```clojure
(def HIST_BUCKETS 20)

(defn calculate-log-bucket [latency-ns]
  "Calculate logarithmic bucket index for latency"
  ;; Buckets: <1us, 1-2us, 2-4us, 4-8us, ..., >1s
  (vec (concat
    ;; r7 = latency in nanoseconds
    ;; Convert to microseconds for bucketing
    [(bpf/mov-reg :r6 :r7)]
    [(bpf/rsh :r6 10)]  ; Divide by 1024 ≈ 1000 (us)

    ;; Bucket 0: < 1us
    [(bpf/jmp-imm :jlt :r6 1 :bucket-0)]

    ;; Bucket 1: 1-2us
    [(bpf/jmp-imm :jlt :r6 2 :bucket-1)]

    ;; Bucket 2: 2-4us
    [(bpf/jmp-imm :jlt :r6 4 :bucket-2)]

    ;; Bucket 3: 4-8us
    [(bpf/jmp-imm :jlt :r6 8 :bucket-3)]

    ;; Bucket 4: 8-16us
    [(bpf/jmp-imm :jlt :r6 16 :bucket-4)]

    ;; Bucket 5: 16-32us
    [(bpf/jmp-imm :jlt :r6 32 :bucket-5)]

    ;; Bucket 6: 32-64us
    [(bpf/jmp-imm :jlt :r6 64 :bucket-6)]

    ;; Bucket 7: 64-128us
    [(bpf/jmp-imm :jlt :r6 128 :bucket-7)]

    ;; Bucket 8: 128-256us
    [(bpf/jmp-imm :jlt :r6 256 :bucket-8)]

    ;; Bucket 9: 256-512us
    [(bpf/jmp-imm :jlt :r6 512 :bucket-9)]

    ;; Bucket 10: 512-1024us (1ms)
    [(bpf/jmp-imm :jlt :r6 1024 :bucket-10)]

    ;; Bucket 11: 1-2ms
    [(bpf/jmp-imm :jlt :r6 2048 :bucket-11)]

    ;; Bucket 12: 2-4ms
    [(bpf/jmp-imm :jlt :r6 4096 :bucket-12)]

    ;; Bucket 13: 4-8ms
    [(bpf/jmp-imm :jlt :r6 8192 :bucket-13)]

    ;; Bucket 14: 8-16ms
    [(bpf/jmp-imm :jlt :r6 16384 :bucket-14)]

    ;; Bucket 15: 16-32ms
    [(bpf/jmp-imm :jlt :r6 32768 :bucket-15)]

    ;; Bucket 16: 32-64ms
    [(bpf/jmp-imm :jlt :r6 65536 :bucket-16)]

    ;; Bucket 17: 64-128ms
    [(bpf/jmp-imm :jlt :r6 131072 :bucket-17)]

    ;; Bucket 18: 128-256ms
    [(bpf/jmp-imm :jlt :r6 262144 :bucket-18)]

    ;; Bucket 19: >256ms
    [(bpf/mov :r6 19)]
    [(bpf/jmp :bucket-done)]

    [(bpf/mov :r6 0)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 1)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 2)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 3)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 4)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 5)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 6)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 7)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 8)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 9)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 10)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 11)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 12)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 13)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 14)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 15)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 16)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 17)] [(bpf/jmp :bucket-done)]
    [(bpf/mov :r6 18)]

    ;; :bucket-done
    ;; r6 now contains bucket index
    )))

(defn create-histogram-complete-handler
  "Track I/O completion with histogram"
  [inflight-fd histogram-fd op-type]
  (bpf/assemble
    (vec (concat
      ;; r8 = ctx pointer
      [(bpf/mov-reg :r8 :r1)]

      ;; Get timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]

      ;; Read device and sector (same as before)
      [(bpf/load-mem :w :r6 :r8 (:dev BLOCK_RQ_COMPLETE_OFFSETS))]
      [(bpf/load-mem :dw :r5 :r8 (:sector BLOCK_RQ_COMPLETE_OFFSETS))]

      ;; Create key
      [(bpf/store-mem :w :r10 -4 :r6)]
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -8 :r4)]
      [(bpf/store-mem :dw :r10 -16 :r5)]

      ;; Lookup issue time
      [(bpf/ld-map-fd :r1 inflight-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -16)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :exit)]

      ;; Calculate latency
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/sub-reg :r9 :r3)]
      [(bpf/mov-reg :r7 :r9)]  ; r7 = latency

      ;; Calculate bucket (inlined for simplicity)
      (calculate-log-bucket :r7)
      ;; r6 = bucket index

      ;; Update histogram[bucket]
      [(bpf/store-mem :w :r10 -24 :r6)]
      [(bpf/ld-map-fd :r1 histogram-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Increment
      [(bpf/jmp-imm :jeq :r0 0 :init-bucket)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]
      [(bpf/jmp :cleanup)]

      ;; :init-bucket
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -32 :r3)]
      [(bpf/ld-map-fd :r1 histogram-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -32)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; :cleanup
      [(bpf/ld-map-fd :r1 inflight-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -16)]
      (bpf/helper-map-delete-elem :r1 :r2)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn print-histogram [histogram-fd title]
  (println (format "\n%s:" title))
  (println "Latency Range    | Count     | Distribution")
  (println "-----------------|-----------|----------------------------------------")

  (let [bucket-labels ["< 1us" "1-2us" "2-4us" "4-8us" "8-16us" "16-32us"
                       "32-64us" "64-128us" "128-256us" "256-512us"
                       "512us-1ms" "1-2ms" "2-4ms" "4-8ms" "8-16ms"
                       "16-32ms" "32-64ms" "64-128ms" "128-256ms" "> 256ms"]
        total (atom 0)]

    ;; First pass: calculate total
    (doseq [bucket (range HIST_BUCKETS)]
      (when-let [count (bpf/map-lookup histogram-fd (int-array [bucket]))]
        (swap! total + (aget count 0))))

    ;; Second pass: print histogram
    (doseq [bucket (range HIST_BUCKETS)]
      (when-let [count (bpf/map-lookup histogram-fd (int-array [bucket]))]
        (let [cnt (aget count 0)
              pct (if (> @total 0) (* 100.0 (/ cnt @total)) 0.0)
              bar-len (int (/ pct 2))  ; Scale to 50 chars max
              bar (apply str (repeat bar-len "█"))]
          (when (> cnt 0)
            (println (format "%-16s | %9d | %s %.1f%%"
                            (nth bucket-labels bucket)
                            cnt
                            bar
                            pct))))))))

(defn run-io-histogram []
  (println "Creating I/O latency histogram monitor...")

  (let [inflight-fd (bpf/create-map :hash
                                     {:key-size 16
                                      :value-size 8
                                      :max-entries 10240})
        histogram-fd (bpf/create-map :hash
                                      {:key-size 4
                                       :value-size 8
                                       :max-entries HIST_BUCKETS})]

    ;; For this example, track all I/O (not separated by read/write)
    (let [issue-prog (create-io-issue-handler inflight-fd)
          complete-prog (create-histogram-complete-handler inflight-fd histogram-fd :all)

          issue-fd (bpf/load-program issue-prog :tracepoint)
          complete-fd (bpf/load-program complete-prog :tracepoint)

          issue-link (bpf/attach-tracepoint issue-fd "block/block_rq_issue")
          complete-link (bpf/attach-tracepoint complete-fd "block/block_rq_complete")]

      (println "Monitoring I/O latency for 10 seconds...")
      (Thread/sleep 10000)

      (print-histogram histogram-fd "Block I/O Latency Distribution")

      ;; Cleanup
      (bpf/detach-tracepoint issue-link)
      (bpf/detach-tracepoint complete-link)
      (bpf/close-program issue-fd)
      (bpf/close-program complete-fd)
      (bpf/close-map inflight-fd)
      (bpf/close-map histogram-fd))))
```

### Expected Output

```
Creating I/O latency histogram monitor...
Monitoring I/O latency for 10 seconds...

Block I/O Latency Distribution:
Latency Range    | Count     | Distribution
-----------------|-----------|----------------------------------------
64-128us         |        45 | ████ 3.2%
128-256us        |       234 | ████████████████ 16.7%
256-512us        |       456 | ████████████████████████████████ 32.6%
512us-1ms        |       389 | ████████████████████████████ 27.8%
1-2ms            |       178 | ████████████ 12.7%
2-4ms            |        67 | ████ 4.8%
4-8ms            |        23 | █ 1.6%
8-16ms           |         6 | ▌ 0.4%
16-32ms          |         2 | ▌ 0.1%
```

## Exercises

### Exercise 1: Per-Device Statistics

Modify the monitor to track statistics per block device:
- Separate histograms for each device (sda, sdb, nvme0n1, etc.)
- Display device major:minor numbers
- Calculate per-device throughput

### Exercise 2: Operation Size Tracking

Track I/O operation sizes:
- Create histogram of operation sizes (4K, 8K, 16K, etc.)
- Calculate average operation size
- Correlate size with latency

### Exercise 3: Slow I/O Detection

Detect and log slow I/O operations:
- Define threshold (e.g., > 10ms)
- Log full details: device, sector, size, latency
- Use ring buffer for real-time alerts

### Exercise 4: Queue Depth Monitoring

Track I/O queue depth:
- Count pending requests per device
- Monitor queue saturation
- Correlate queue depth with latency

## Summary

In this lab, you learned:
- How to track block layer I/O operations
- Correlating issue and completion events
- Measuring I/O latency distributions
- Building latency histograms in BPF
- Analyzing storage performance patterns

## Navigation

- **Next**: [Lab 6.3 - System Call Frequency Analyzer](lab-6-3-syscall-analyzer.md)
- **Previous**: [Lab 6.1 - CPU Scheduler Tracer](lab-6-1-scheduler-tracer.md)
- **Home**: [Tutorial Home](../../../README.md)
