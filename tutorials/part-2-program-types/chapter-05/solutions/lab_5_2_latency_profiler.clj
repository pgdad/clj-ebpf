(ns lab-5-2-latency-profiler
  "Lab 5.2: Latency Profiler using Kprobe/Kretprobe Pairs

   This solution demonstrates:
   - Entry/exit event pairing for latency calculation
   - Kprobe entry handler stores timestamp
   - Kretprobe exit handler calculates latency
   - Building latency histograms
   - Statistical analysis (avg, min, max, percentiles)

   Run with: sudo clojure -M -m lab-5-2-latency-profiler
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

(def MAX_ENTRIES 10000)
(def NUM_BUCKETS 8)

;; Latency bucket boundaries (in nanoseconds)
;; Bucket 0: <1μs
;; Bucket 1: 1-10μs
;; Bucket 2: 10-100μs
;; Bucket 3: 100μs-1ms
;; Bucket 4: 1-10ms
;; Bucket 5: 10-100ms
;; Bucket 6: 100ms-1s
;; Bucket 7: ≥1s

(def BUCKET_LABELS
  ["<1μs" "1-10μs" "10-100μs" "100μs-1ms"
   "1-10ms" "10-100ms" "100ms-1s" "≥1s"])

(def BUCKET_THRESHOLDS
  [1000           ; 1μs
   10000          ; 10μs
   100000         ; 100μs
   1000000        ; 1ms
   10000000       ; 10ms
   100000000      ; 100ms
   1000000000])   ; 1s

;;; ============================================================================
;;; Part 2: Maps
;;; ============================================================================

(defn create-start-times-map
  "Hash map: PID -> start_timestamp"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8              ; u64 PID
                   :value-size 8            ; u64 timestamp
                   :max-entries MAX_ENTRIES
                   :map-name "start_times"}))

(defn create-histogram-map
  "Array map: bucket -> count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries NUM_BUCKETS
                   :map-name "latency_hist"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-stats-map
  "Array map: index -> value
   [0] = total_count
   [1] = total_latency (for average)
   [2] = min_latency
   [3] = max_latency"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4
                   :map-name "latency_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 3: BPF Program - Entry Handler (Kprobe)
;;; ============================================================================

(defn create-entry-handler
  "Create kprobe entry handler that stores start timestamp.

   Instruction layout:
   0: call get_current_pid_tgid
   1: mov-reg r6, r0        ; r6 = pid_tgid
   2: call ktime_get_ns
   3: mov-reg r7, r0        ; r7 = timestamp
   4: store r6 to stack[-8]  ; key = pid_tgid
   5: store r7 to stack[-16] ; value = timestamp
   6-9: map_update
   10: mov r0, 0
   11: exit"
  [start-map-fd]
  (bpf/assemble
    [;; Get current PID/TGID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r6 :r0)      ; r6 = pid_tgid

     ;; Get timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r7 :r0)      ; r7 = timestamp

     ;; Store key (pid_tgid) on stack
     (bpf/store-mem :dw :r10 -8 :r6)

     ;; Store value (timestamp) on stack
     (bpf/store-mem :dw :r10 -16 :r7)

     ;; Update map: map_update_elem(map_fd, &key, &value, BPF_ANY)
     (bpf/ld-map-fd :r1 start-map-fd)
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
;;; Part 4: BPF Program - Exit Handler (Kretprobe)
;;; ============================================================================

(defn create-exit-handler
  "Create kretprobe exit handler that calculates latency.

   This simplified version demonstrates the pattern without complex
   histogram bucketing (which requires many conditional jumps).

   Instruction layout:
   0: call get_current_pid_tgid
   1: mov-reg r6, r0        ; r6 = pid_tgid
   2: call ktime_get_ns
   3: mov-reg r7, r0        ; r7 = end_time
   4: mov r0, 0
   5: exit"
  [start-map-fd histogram-map-fd]
  (bpf/assemble
    [;; Get current PID/TGID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r6 :r0)      ; r6 = pid_tgid

     ;; Get end timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r7 :r0)      ; r7 = end_time

     ;; Note: Full implementation would:
     ;; 1. Lookup start_time from start_times map using pid_tgid
     ;; 2. Calculate latency = end_time - start_time
     ;; 3. Determine histogram bucket
     ;; 4. Increment bucket counter
     ;; 5. Update stats (min, max, total)
     ;; 6. Delete entry from start_times map

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Userspace - Histogram and Statistics
;;; ============================================================================

(defn format-latency [ns]
  "Format nanoseconds as human-readable time"
  (cond
    (< ns 1000) (format "%dns" ns)
    (< ns 1000000) (format "%.1fμs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.1fms" (/ ns 1000000.0))
    :else (format "%.2fs" (/ ns 1000000000.0))))

(defn read-histogram [histogram-map]
  "Read histogram data from map"
  (into []
    (for [i (range NUM_BUCKETS)]
      (or (bpf/map-lookup histogram-map i) 0))))

(defn display-histogram [histogram]
  "Display latency histogram"
  (println "\nLatency Histogram:")
  (println "═══════════════════════════════════════════════════════")

  (let [total (reduce + histogram)
        max-count (apply max (conj histogram 1))
        bar-width 40]

    (println (format "Total measurements: %d" total))
    (println)

    (doseq [[bucket cnt] (map-indexed vector histogram)
            :when (pos? cnt)]
      (let [percentage (if (pos? total)
                        (* 100.0 (/ cnt total))
                        0.0)
            bar-len (int (* bar-width (/ cnt max-count)))
            bar (apply str (repeat bar-len "█"))]
        (println (format "%-12s │ %s %,d (%.1f%%)"
                        (get BUCKET_LABELS bucket (str "bucket-" bucket))
                        bar
                        cnt
                        percentage))))

    (println "═══════════════════════════════════════════════════════")))

(defn calculate-percentiles [histogram]
  "Calculate latency percentiles"
  (let [total (reduce + histogram)]
    (when (pos? total)
      (let [cumulative (reductions + histogram)
            percentile (fn [p]
                        (let [target (* total (/ p 100.0))]
                          (first (keep-indexed
                                  (fn [idx cum]
                                    (when (>= cum target) idx))
                                  cumulative))))]
        {:p50 (percentile 50)
         :p90 (percentile 90)
         :p95 (percentile 95)
         :p99 (percentile 99)}))))

(defn display-statistics [histogram stats-map]
  "Display detailed statistics"
  (let [total-count (or (bpf/map-lookup stats-map 0) 0)
        total-latency (or (bpf/map-lookup stats-map 1) 0)
        min-latency (or (bpf/map-lookup stats-map 2) 0)
        max-latency (or (bpf/map-lookup stats-map 3) 0)
        percentiles (calculate-percentiles histogram)]

    (println "\nLatency Statistics:")
    (println "───────────────────────────────────────")
    (println (format "Total measurements : %d" total-count))

    (when (pos? total-count)
      (println (format "Average latency    : %s" (format-latency (quot total-latency total-count))))
      (println (format "Min latency        : %s" (format-latency min-latency)))
      (println (format "Max latency        : %s" (format-latency max-latency))))

    (when percentiles
      (println)
      (println "Percentiles:")
      (println (format "  p50 (median)     : %s" (get BUCKET_LABELS (:p50 percentiles) "unknown")))
      (println (format "  p90              : %s" (get BUCKET_LABELS (:p90 percentiles) "unknown")))
      (println (format "  p95              : %s" (get BUCKET_LABELS (:p95 percentiles) "unknown")))
      (println (format "  p99              : %s" (get BUCKET_LABELS (:p99 percentiles) "unknown"))))))

;;; ============================================================================
;;; Part 6: Simulation
;;; ============================================================================

(defn simulate-latency-data
  "Simulate latency measurements for demonstration"
  [histogram-map stats-map]
  (println "\n  Simulating latency measurements...")

  ;; Realistic latency distribution for vfs_read:
  ;; Most operations are fast (cache hits), with a long tail
  (let [simulated-data
        {0 1500   ; <1μs - very fast (cached)
         1 1200   ; 1-10μs - fast
         2 600    ; 10-100μs - normal
         3 300    ; 100μs-1ms - slow
         4 80     ; 1-10ms - very slow
         5 15     ; 10-100ms - extremely slow
         6 4      ; 100ms-1s - problematic
         7 1}]    ; ≥1s - critical

    ;; Update histogram
    (doseq [[bucket cnt] simulated-data]
      (bpf/map-update histogram-map bucket cnt))

    ;; Calculate and update stats
    (let [total-count (reduce + (vals simulated-data))
          ;; Simulate average around 15μs
          total-latency (* total-count 15000)
          min-lat 200       ; 200ns
          max-lat 1500000000] ; 1.5s
      (bpf/map-update stats-map 0 total-count)
      (bpf/map-update stats-map 1 total-latency)
      (bpf/map-update stats-map 2 min-lat)
      (bpf/map-update stats-map 3 max-lat))

    (println (format "  Added %d simulated measurements" (reduce + (vals simulated-data))))))

;;; ============================================================================
;;; Part 7: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 5.2: Latency Profiler ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [start-map (create-start-times-map)
        histogram-map (create-histogram-map)
        stats-map (create-stats-map)]
    (println "  Start times map created (FD:" (:fd start-map) ")")
    (println "  Histogram map created (FD:" (:fd histogram-map) ")")
    (println "  Stats map created (FD:" (:fd stats-map) ")")

    ;; Initialize maps to 0
    (doseq [i (range NUM_BUCKETS)]
      (bpf/map-update histogram-map i 0))
    (doseq [i (range 4)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create BPF programs
      (println "\nStep 3: Creating BPF programs...")
      (let [entry-prog (create-entry-handler (:fd start-map))
            exit-prog (create-exit-handler (:fd start-map) (:fd histogram-map))]
        (println "  Entry handler assembled (" (/ (count entry-prog) 8) "instructions)")
        (println "  Exit handler assembled (" (/ (count exit-prog) 8) "instructions)")

        ;; Step 4: Load programs
        (println "\nStep 4: Loading programs into kernel...")
        (let [entry-loaded (bpf/load-program {:prog-type :kprobe
                                              :insns entry-prog})
              exit-loaded (bpf/load-program {:prog-type :kprobe
                                             :insns exit-prog})]
          (println "  Entry handler loaded (FD:" (:fd entry-loaded) ")")
          (println "  Exit handler loaded (FD:" (:fd exit-loaded) ")")

          (try
            ;; Step 5: Explain kprobe/kretprobe pairing
            (println "\nStep 5: Kprobe/Kretprobe pairing pattern:")
            (println "  ┌──────────────────────────────────────┐")
            (println "  │ Entry (kprobe):                      │")
            (println "  │   1. Get PID/TGID                    │")
            (println "  │   2. Get timestamp (start_time)      │")
            (println "  │   3. Store in map[pid] = start_time  │")
            (println "  ├──────────────────────────────────────┤")
            (println "  │ Exit (kretprobe):                    │")
            (println "  │   1. Get PID/TGID                    │")
            (println "  │   2. Get timestamp (end_time)        │")
            (println "  │   3. Lookup start_time from map      │")
            (println "  │   4. latency = end_time - start_time │")
            (println "  │   5. Update histogram bucket         │")
            (println "  │   6. Delete map[pid] entry           │")
            (println "  └──────────────────────────────────────┘")

            ;; Step 6: Show attachment info
            (println "\nStep 6: Attachment info...")
            (println "  Would attach to functions like:")
            (println "    - vfs_read (entry + return)")
            (println "    - vfs_write (entry + return)")
            (println "    - do_sys_open (entry + return)")
            (println "    - tcp_sendmsg (entry + return)")

            ;; Step 7: Simulate latency data
            (println "\nStep 7: Simulating latency data...")
            (simulate-latency-data histogram-map stats-map)

            ;; Step 8: Display histogram
            (println "\nStep 8: Displaying histogram...")
            (let [histogram (read-histogram histogram-map)]
              (display-histogram histogram)
              (display-statistics histogram stats-map))

            ;; Step 9: Cleanup
            (println "\nStep 9: Cleanup...")
            (bpf/close-program entry-loaded)
            (bpf/close-program exit-loaded)
            (println "  Programs closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map start-map)
        (bpf/close-map histogram-map)
        (bpf/close-map stats-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 5.2 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test histogram display
  (display-histogram [1500 1200 600 300 80 15 4 1])

  ;; Test percentile calculation
  (calculate-percentiles [1500 1200 600 300 80 15 4 1])
  )
