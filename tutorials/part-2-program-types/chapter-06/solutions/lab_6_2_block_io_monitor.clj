(ns lab-6-2-block-io-monitor
  "Lab 6.2: Block I/O Latency Monitor using Tracepoints

   This solution demonstrates:
   - Monitoring block device I/O operations
   - Measuring I/O latency from request to completion
   - Tracking read vs write operations separately
   - Analyzing I/O patterns and performance
   - Building I/O latency histograms

   Run with: sudo clojure -M -m lab-6-2-block-io-monitor
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; Tracepoint context offsets for block_rq_issue
(def BLOCK_RQ_ISSUE_OFFSETS
  {:dev 8         ; dev_t (4 bytes)
   :sector 16     ; sector_t (8 bytes)
   :nr-sector 24  ; unsigned int (4 bytes)
   :bytes 28      ; unsigned int (4 bytes)
   :rwbs 32       ; char[8]
   :comm 40})     ; char[16]

;; Tracepoint context offsets for block_rq_complete
(def BLOCK_RQ_COMPLETE_OFFSETS
  {:dev 8         ; dev_t (4 bytes)
   :sector 16     ; sector_t (8 bytes)
   :nr-sector 24  ; unsigned int (4 bytes)
   :error 28      ; int (4 bytes)
   :rwbs 32})     ; char[8]

(def MAX_ENTRIES 10000)
(def NUM_BUCKETS 20)

;; Latency histogram bucket labels
(def BUCKET_LABELS
  ["<1μs" "1-2μs" "2-4μs" "4-8μs" "8-16μs" "16-32μs"
   "32-64μs" "64-128μs" "128-256μs" "256-512μs"
   "512μs-1ms" "1-2ms" "2-4ms" "4-8ms" "8-16ms"
   "16-32ms" "32-64ms" "64-128ms" "128-256ms" ">256ms"])

;;; ============================================================================
;;; Part 2: Data Structures
;;; ============================================================================

(defn read-u32-le [^bytes buf offset]
  (let [bb (ByteBuffer/wrap buf)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getInt bb offset)))

(defn read-u64-le [^bytes buf offset]
  (let [bb (ByteBuffer/wrap buf)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getLong bb offset)))

;;; ============================================================================
;;; Part 3: Maps
;;; ============================================================================

(defn create-inflight-map
  "Hash map: pid_tgid -> issue_timestamp"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8              ; pid_tgid (simplified)
                   :value-size 8            ; timestamp
                   :max-entries MAX_ENTRIES
                   :map-name "inflight_io"}))

(defn create-read-stats-map
  "Array map for read statistics:
   [0] = count
   [1] = total_latency
   [2] = max_latency"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4
                   :map-name "read_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-write-stats-map
  "Array map for write statistics"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4
                   :map-name "write_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-histogram-map
  "Array map for latency histogram"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries NUM_BUCKETS
                   :map-name "io_histogram"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: BPF Program - Issue Handler
;;; ============================================================================

(defn create-io-issue-handler
  "Create BPF program to track I/O request issue time.

   This simplified program demonstrates:
   - Reading device ID and sector from tracepoint context
   - Getting timestamp with ktime_get_ns()
   - Storing inflight request info

   Instruction layout:
   0: mov-reg r8, r1        ; save ctx
   1: call ktime_get_ns
   2: mov-reg r7, r0        ; r7 = timestamp
   3-6: store key/value on stack
   7-11: map update
   12: mov r0, 0
   13: exit"
  [inflight-fd]
  (bpf/assemble
    [;; Save ctx pointer
     (bpf/mov-reg :r8 :r1)

     ;; Get timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r7 :r0)      ; r7 = issue_time

     ;; Store key on stack: just use PID as simplified key
     ;; (full implementation would use dev + sector)
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r6 :r0)      ; r6 = pid_tgid

     (bpf/store-mem :dw :r10 -8 :r6)   ; key = pid_tgid
     (bpf/store-mem :dw :r10 -16 :r7)  ; value = timestamp

     ;; Update inflight map
     (bpf/ld-map-fd :r1 inflight-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)           ; r2 = &key
     (bpf/mov-reg :r3 :r10)
     (bpf/add :r3 -16)          ; r3 = &value
     (bpf/mov :r4 0)            ; flags = BPF_ANY
     (bpf/call 2)               ; BPF_FUNC_map_update_elem

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: BPF Program - Completion Handler
;;; ============================================================================

(defn create-io-complete-handler
  "Create BPF program to handle I/O completion.

   This simplified program demonstrates:
   - Looking up issue time
   - Calculating latency
   - Updating statistics

   Instruction layout:
   0: mov-reg r8, r1
   1: call ktime_get_ns
   2: mov-reg r9, r0
   3: call get_current_pid_tgid
   4-7: map lookup
   8: mov r0, 0
   9: exit"
  [inflight-fd read-stats-fd]
  (bpf/assemble
    [;; Save ctx pointer
     (bpf/mov-reg :r8 :r1)

     ;; Get current timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r9 :r0)      ; r9 = complete_time

     ;; Get PID as key
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r6 :r0)

     ;; Lookup issue time
     (bpf/store-mem :dw :r10 -8 :r6)
     (bpf/ld-map-fd :r1 inflight-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)
     (bpf/call 1)               ; BPF_FUNC_map_lookup_elem

     ;; Note: Full implementation would:
     ;; 1. Calculate latency = complete_time - issue_time
     ;; 2. Determine if read or write from rwbs[0]
     ;; 3. Update appropriate stats map
     ;; 4. Delete inflight entry

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 6: Userspace - Statistics and Visualization
;;; ============================================================================

(defn format-latency [ns]
  "Format nanoseconds as human-readable time"
  (cond
    (< ns 1000) (format "%dns" ns)
    (< ns 1000000) (format "%.1fμs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.1fms" (/ ns 1000000.0))
    :else (format "%.2fs" (/ ns 1000000000.0))))

(defn format-bytes [bytes]
  "Format bytes as human-readable size"
  (cond
    (< bytes 1024) (format "%dB" bytes)
    (< bytes (* 1024 1024)) (format "%.1fKB" (/ bytes 1024.0))
    (< bytes (* 1024 1024 1024)) (format "%.1fMB" (/ bytes 1048576.0))
    :else (format "%.2fGB" (/ bytes 1073741824.0))))

(defn display-io-stats [read-stats-map write-stats-map]
  "Display I/O statistics"
  (println "\nBlock I/O Statistics:")
  (println "═══════════════════════════════════════════════════════")

  (doseq [[op-name stats-map] [["READS" read-stats-map]
                                ["WRITES" write-stats-map]]]
    (let [count (or (bpf/map-lookup stats-map 0) 0)
          total-latency (or (bpf/map-lookup stats-map 1) 0)
          max-latency (or (bpf/map-lookup stats-map 2) 0)]

      (println (format "\n%s:" op-name))
      (println (format "  Count:         %,d operations" count))
      (when (pos? count)
        (let [avg-latency (quot total-latency count)]
          (println (format "  Avg Latency:   %s" (format-latency avg-latency)))
          (println (format "  Max Latency:   %s" (format-latency max-latency)))
          (println (format "  Total Latency: %s" (format-latency total-latency)))))))

  (println "\n═══════════════════════════════════════════════════════"))

(defn display-histogram [histogram-map]
  "Display latency histogram"
  (println "\nI/O Latency Histogram:")
  (println "═══════════════════════════════════════════════════════")
  (println "Latency Range    │ Count     │ Distribution")
  (println "─────────────────┼───────────┼─────────────────────────")

  (let [counts (into []
                 (for [i (range NUM_BUCKETS)]
                   (or (bpf/map-lookup histogram-map i) 0)))
        total (reduce + counts)
        max-count (apply max (conj counts 1))]

    (doseq [[bucket cnt] (map-indexed vector counts)
            :when (pos? cnt)]
      (let [percentage (if (pos? total)
                        (* 100.0 (/ cnt total))
                        0.0)
            bar-len (int (* 25 (/ cnt max-count)))
            bar (apply str (repeat bar-len "█"))]
        (println (format "%-16s │ %,9d │ %s %.1f%%"
                        (get BUCKET_LABELS bucket)
                        cnt
                        bar
                        percentage))))

    (println "═══════════════════════════════════════════════════════")
    (println (format "Total: %,d I/O operations" total))))

;;; ============================================================================
;;; Part 7: Simulation
;;; ============================================================================

(defn simulate-io-data
  "Simulate I/O monitoring data"
  [read-stats-map write-stats-map histogram-map]
  (println "\n  Simulating I/O data...")

  ;; Simulate read statistics
  (let [read-count 1523
        read-avg-latency-us 234.56
        read-max-latency-us 1245.78
        read-total-latency (* read-count read-avg-latency-us 1000)]
    (bpf/map-update read-stats-map 0 read-count)
    (bpf/map-update read-stats-map 1 (long read-total-latency))
    (bpf/map-update read-stats-map 2 (long (* read-max-latency-us 1000))))

  ;; Simulate write statistics
  (let [write-count 892
        write-avg-latency-us 456.78
        write-max-latency-us 3456.89
        write-total-latency (* write-count write-avg-latency-us 1000)]
    (bpf/map-update write-stats-map 0 write-count)
    (bpf/map-update write-stats-map 1 (long write-total-latency))
    (bpf/map-update write-stats-map 2 (long (* write-max-latency-us 1000))))

  ;; Simulate histogram with realistic distribution
  ;; Most I/O should be in the 100μs - 1ms range
  (let [histogram-data
        {6  45      ; 32-64μs
         7  120     ; 64-128μs
         8  350     ; 128-256μs
         9  580     ; 256-512μs
         10 420     ; 512μs-1ms
         11 230     ; 1-2ms
         12 85      ; 2-4ms
         13 40      ; 4-8ms
         14 25      ; 8-16ms
         15 12      ; 16-32ms
         16 5       ; 32-64ms
         17 2       ; 64-128ms
         18 1}]     ; 128-256ms

    (doseq [[bucket cnt] histogram-data]
      (bpf/map-update histogram-map bucket cnt)))

  (println "  Simulated 2415 I/O operations (1523 reads, 892 writes)"))

(defn display-simulated-events
  "Display simulated I/O events"
  []
  (println "\nRecent Block I/O Events:")
  (println "═══════════════════════════════════════════════════════════════════════════")
  (println "TIME(ms) │ DEV     │ TYPE  │ SECTOR       │ SIZE   │ LATENCY")
  (println "─────────┼─────────┼───────┼──────────────┼────────┼─────────")

  (let [events [{:time 0.12 :dev "sda" :type "R" :sector 123456 :size 4096 :latency 234500}
                {:time 0.34 :dev "sda" :type "W" :sector 789012 :size 8192 :latency 456780}
                {:time 0.56 :dev "nvme0n1" :type "R" :sector 345678 :size 16384 :latency 45200}
                {:time 0.78 :dev "sda" :type "R" :sector 901234 :size 4096 :latency 567890}
                {:time 1.00 :dev "nvme0n1" :type "W" :sector 567890 :size 32768 :latency 123400}
                {:time 1.23 :dev "sda" :type "RS" :sector 234567 :size 4096 :latency 890120}]]

    (doseq [{:keys [time dev type sector size latency]} events]
      (println (format "%8.2f │ %-7s │ %-5s │ %,12d │ %6s │ %s"
                       time dev type sector
                       (format-bytes size)
                       (format-latency latency)))))

  (println "═══════════════════════════════════════════════════════════════════════════"))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 6.2: Block I/O Latency Monitor ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [inflight-map (create-inflight-map)
        read-stats-map (create-read-stats-map)
        write-stats-map (create-write-stats-map)
        histogram-map (create-histogram-map)]
    (println "  Inflight map created (FD:" (:fd inflight-map) ")")
    (println "  Read stats map created (FD:" (:fd read-stats-map) ")")
    (println "  Write stats map created (FD:" (:fd write-stats-map) ")")
    (println "  Histogram map created (FD:" (:fd histogram-map) ")")

    ;; Initialize maps
    (doseq [i (range 4)]
      (bpf/map-update read-stats-map i 0)
      (bpf/map-update write-stats-map i 0))
    (doseq [i (range NUM_BUCKETS)]
      (bpf/map-update histogram-map i 0))

    (try
      ;; Step 3: Create BPF programs
      (println "\nStep 3: Creating BPF programs...")
      (let [issue-prog (create-io-issue-handler (:fd inflight-map))
            complete-prog (create-io-complete-handler (:fd inflight-map)
                                                       (:fd read-stats-map))]
        (println "  Issue handler assembled (" (/ (count issue-prog) 8) "instructions)")
        (println "  Complete handler assembled (" (/ (count complete-prog) 8) "instructions)")

        ;; Step 4: Load programs
        (println "\nStep 4: Loading programs into kernel...")
        (let [issue-loaded (bpf/load-program {:prog-type :tracepoint
                                              :insns issue-prog})
              complete-loaded (bpf/load-program {:prog-type :tracepoint
                                                  :insns complete-prog})]
          (println "  Issue handler loaded (FD:" (:fd issue-loaded) ")")
          (println "  Complete handler loaded (FD:" (:fd complete-loaded) ")")

          (try
            ;; Step 5: Explain tracepoint attachment
            (println "\nStep 5: Block tracepoint info...")
            (println "  Would attach to:")
            (println "    - block/block_rq_issue (request issued to device)")
            (println "    - block/block_rq_complete (request completed)")
            (println)
            (println "  Key fields in tracepoint context:")
            (println "    ┌────────────────────────────────────────┐")
            (println "    │ Field        │ Offset │ Description    │")
            (println "    ├──────────────┼────────┼────────────────┤")
            (println "    │ dev          │     8  │ Device ID      │")
            (println "    │ sector       │    16  │ Start sector   │")
            (println "    │ nr_sector    │    24  │ Sector count   │")
            (println "    │ bytes        │    28  │ Request size   │")
            (println "    │ rwbs         │    32  │ R/W/S flags    │")
            (println "    └────────────────────────────────────────┘")

            ;; Step 6: Explain RWBS flags
            (println "\nStep 6: RWBS operation flags:")
            (println "    R = Read")
            (println "    W = Write")
            (println "    S = Sync (FUA/FLUSH)")
            (println "    M = Metadata")
            (println "    D = Discard")
            (println "    A = Read-ahead")
            (println "    F = Force Unit Access")

            ;; Step 7: Simulate I/O data
            (println "\nStep 7: Simulating I/O data...")
            (simulate-io-data read-stats-map write-stats-map histogram-map)

            ;; Step 8: Display simulated events
            (println "\nStep 8: Recent events...")
            (display-simulated-events)

            ;; Step 9: Display statistics
            (println "\nStep 9: Statistics...")
            (display-io-stats read-stats-map write-stats-map)

            ;; Step 10: Display histogram
            (println "\nStep 10: Histogram...")
            (display-histogram histogram-map)

            ;; Step 11: Cleanup
            (println "\nStep 11: Cleanup...")
            (bpf/close-program issue-loaded)
            (bpf/close-program complete-loaded)
            (println "  Programs closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map inflight-map)
        (bpf/close-map read-stats-map)
        (bpf/close-map write-stats-map)
        (bpf/close-map histogram-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 6.2 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test formatting
  (format-latency 123456789)
  (format-bytes 1234567)
  )
