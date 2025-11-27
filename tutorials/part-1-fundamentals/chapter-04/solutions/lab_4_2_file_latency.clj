(ns lab-4-2-file-latency
  "Lab 4.2: File Access Latency Tracker using time helper functions

   This solution demonstrates:
   - Using time helper functions (ktime_get_ns)
   - Pairing entry/exit events for latency calculation
   - Building latency histograms
   - Identifying performance bottlenecks
   - Statistical analysis of latencies

   Run with: sudo clojure -M -m lab-4-2-file-latency
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

(def NUM_BUCKETS 10)  ; Number of histogram buckets
(def MAX_ENTRIES 10000)  ; Maximum tracked operations

;; Latency bucket labels
(def BUCKET_LABELS
  ["<1us" "1-10us" "10-100us" "100us-1ms"
   "1-10ms" "10-100ms" "100ms-1s" "1-10s" ">10s" "overflow"])

;; Operation types
(def OP_OPEN 0)
(def OP_READ 1)
(def OP_WRITE 2)
(def OP_FSYNC 3)

(def OP_NAMES ["open" "read" "write" "fsync"])

;;; ============================================================================
;;; Part 2: Data Structures
;;; ============================================================================

;; Entry data structure (stored in start-time map)
;; struct entry_data {
;;   u64 start_time;   // offset 0
;;   u64 pid_tgid;     // offset 8
;; };

(def ENTRY_DATA_SIZE 16)

;;; ============================================================================
;;; Part 3: Maps
;;; ============================================================================

(defn create-start-map
  "Map to store operation start times (PID -> entry_data)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8              ; u64 PID
                   :value-size ENTRY_DATA_SIZE
                   :max-entries MAX_ENTRIES
                   :map-name "start_times"}))

(defn create-histogram-map
  "Histogram: bucket -> count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4       ; u32 bucket index
                   :value-size 8     ; u64 count
                   :max-entries NUM_BUCKETS
                   :map-name "latency_hist"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-total-map
  "Track total latency and count for average calculation"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4   ; [total_count, total_latency_ns, min_latency, max_latency]
                   :map-name "latency_totals"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: BPF Program - Entry Probe
;;; ============================================================================

(defn create-entry-probe
  "Kprobe entry handler - record start time

   This simplified version demonstrates:
   - bpf_ktime_get_ns() for timestamp
   - bpf_get_current_pid_tgid() for process ID
   - Storing entry data in hash map

   Instruction layout:
   0: call bpf_ktime_get_ns (helper 5)
   1: mov-reg r6, r0           ; r6 = start_time
   2: call bpf_get_current_pid_tgid (helper 14)
   3: mov-reg r7, r0           ; r7 = pid_tgid
   4: store r6 to stack[-16]   ; entry_data.start_time
   5: store r7 to stack[-8]    ; entry_data.pid_tgid
   6: store r7 to stack[-24]   ; key = pid_tgid
   7-10: map update
   11: mov r0, 0
   12: exit"
  [start-map-fd]
  (bpf/assemble
    [;; Step 1: Get timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r6 :r0)      ; r6 = start_time

     ;; Step 2: Get PID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r7 :r0)      ; r7 = pid_tgid

     ;; Step 3: Build entry_data on stack
     (bpf/store-mem :dw :r10 -16 :r6)  ; start_time at stack[-16]
     (bpf/store-mem :dw :r10 -8 :r7)   ; pid_tgid at stack[-8]

     ;; Step 4: Store PID as key
     (bpf/store-mem :dw :r10 -24 :r7)

     ;; Step 5: Update map (r1=map_fd, r2=key, r3=value, r4=flags)
     (bpf/ld-map-fd :r1 start-map-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -24)          ; r2 = &key
     (bpf/mov-reg :r3 :r10)
     (bpf/add :r3 -16)          ; r3 = &value
     (bpf/mov :r4 0)            ; flags = BPF_ANY
     (bpf/call 2)               ; BPF_FUNC_map_update_elem

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: BPF Program - Exit Probe
;;; ============================================================================

(defn create-exit-probe
  "Kretprobe exit handler - calculate and record latency

   This simplified version demonstrates time measurement concepts.
   The entry/exit pairing pattern is the key concept.

   Instruction layout:
   0: call bpf_ktime_get_ns
   1: mov-reg r9, r0 (end_time)
   2: call bpf_get_current_pid_tgid
   3: mov-reg r8, r0 (pid_tgid)
   4: mov r0, 0
   5: exit"
  [start-map-fd histogram-map-fd]
  (bpf/assemble
    [;; Step 1: Get current time (demonstrates ktime_get_ns)
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r9 :r0)      ; r9 = end_time

     ;; Step 2: Get PID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r8 :r0)      ; r8 = pid_tgid

     ;; Return 0 (simplified - full version would do map lookup/update)
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 6: Userspace - Statistics and Visualization
;;; ============================================================================

(defn read-histogram [histogram-map]
  "Read histogram data from map"
  (into []
    (for [i (range NUM_BUCKETS)]
      (or (bpf/map-lookup histogram-map i) 0))))

(defn format-latency [ns]
  "Format nanoseconds as human-readable time"
  (cond
    (< ns 1000) (format "%dns" ns)
    (< ns 1000000) (format "%.1fus" (/ ns 1000.0))
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

(defn display-statistics [histogram totals-map]
  "Display detailed statistics"
  (let [total (reduce + histogram)
        percentiles (calculate-percentiles histogram)
        total-count (or (bpf/map-lookup totals-map 0) 0)
        total-latency (or (bpf/map-lookup totals-map 1) 0)
        min-latency (or (bpf/map-lookup totals-map 2) 0)
        max-latency (or (bpf/map-lookup totals-map 3) 0)]

    (println "\nStatistics:")
    (println "───────────────────────────────────────")
    (println "Total operations   :" total)
    (when (and percentiles (pos? total))
      (println)
      (println "Percentiles:")
      (println "  p50 (median)     :" (get BUCKET_LABELS (:p50 percentiles) "unknown"))
      (println "  p90              :" (get BUCKET_LABELS (:p90 percentiles) "unknown"))
      (println "  p95              :" (get BUCKET_LABELS (:p95 percentiles) "unknown"))
      (println "  p99              :" (get BUCKET_LABELS (:p99 percentiles) "unknown")))
    (when (pos? total-count)
      (println)
      (println "Detailed metrics:")
      (println "  Average latency  :" (format-latency (quot total-latency total-count)))
      (println "  Min latency      :" (format-latency min-latency))
      (println "  Max latency      :" (format-latency max-latency)))))

;;; ============================================================================
;;; Part 7: Simulation
;;; ============================================================================

(defn simulate-latency-data
  "Simulate latency data for demonstration"
  [histogram-map totals-map]
  (println "\n  Simulating latency measurements...")

  ;; Generate realistic latency distribution
  ;; Most operations are fast, with a long tail
  (let [simulated-data
        {0 1200   ; <1us - cache hits
         1 800    ; 1-10us - fast disk
         2 400    ; 10-100us - SSD
         3 200    ; 100us-1ms - spinning disk
         4 80     ; 1-10ms - slow I/O
         5 20     ; 10-100ms - very slow
         6 5      ; 100ms-1s - timeouts
         7 2      ; 1-10s - severe issues
         8 0      ; >10s
         9 0}]    ; overflow

    ;; Update histogram
    (doseq [[bucket cnt] simulated-data]
      (bpf/map-update histogram-map bucket cnt))

    ;; Update totals
    (let [total-count (reduce + (vals simulated-data))
          ;; Simulate average latency around 50us
          total-latency (* total-count 50000)
          min-lat 100       ; 100ns
          max-lat 5000000000] ; 5 seconds
      (bpf/map-update totals-map 0 total-count)
      (bpf/map-update totals-map 1 total-latency)
      (bpf/map-update totals-map 2 min-lat)
      (bpf/map-update totals-map 3 max-lat))

    (println "  Added" (reduce + (vals simulated-data)) "simulated measurements")))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 4.2: File Access Latency Tracker ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [start-map (create-start-map)
        histogram-map (create-histogram-map)
        totals-map (create-total-map)]
    (println "  Start time map created (FD:" (:fd start-map) ")")
    (println "  Histogram map created (FD:" (:fd histogram-map) ")")
    (println "  Totals map created (FD:" (:fd totals-map) ")")

    ;; Initialize histogram buckets to 0
    (doseq [i (range NUM_BUCKETS)]
      (bpf/map-update histogram-map i 0))

    ;; Initialize totals
    (doseq [i (range 4)]
      (bpf/map-update totals-map i 0))

    (try
      ;; Step 3: Create BPF programs
      (println "\nStep 3: Creating BPF programs...")
      (let [entry-prog (create-entry-probe (:fd start-map))
            exit-prog (create-exit-probe (:fd start-map) (:fd histogram-map))]
        (println "  Entry probe assembled (" (/ (count entry-prog) 8) "instructions)")
        (println "  Exit probe assembled (" (/ (count exit-prog) 8) "instructions)")

        ;; Step 4: Load programs
        (println "\nStep 4: Loading programs...")
        (let [entry-loaded (bpf/load-program {:prog-type :kprobe
                                              :insns entry-prog})
              exit-loaded (bpf/load-program {:prog-type :kprobe
                                             :insns exit-prog})]
          (println "  Entry probe loaded (FD:" (:fd entry-loaded) ")")
          (println "  Exit probe loaded (FD:" (:fd exit-loaded) ")")

          (try
            ;; Step 5: Explain kprobe attachment
            (println "\nStep 5: Kprobe attachment info...")
            (println "  Note: Kprobe attachment requires Chapter 5")
            (println "  Would attach to:")
            (println "    Entry: vfs_read")
            (println "    Exit:  vfs_read (kretprobe)")

            ;; Step 6: Simulate latency data
            (println "\nStep 6: Simulating latency data...")
            (simulate-latency-data histogram-map totals-map)

            ;; Step 7: Display histogram
            (println "\nStep 7: Displaying histogram...")
            (let [histogram (read-histogram histogram-map)]
              (display-histogram histogram)
              (display-statistics histogram totals-map))

            ;; Step 8: Explain latency measurement
            (println "\nStep 8: Latency measurement pattern...")
            (println "  Entry probe:")
            (println "    1. Call bpf_ktime_get_ns()")
            (println "    2. Store timestamp with PID as key")
            (println)
            (println "  Exit probe:")
            (println "    1. Call bpf_ktime_get_ns()")
            (println "    2. Lookup start time by PID")
            (println "    3. Calculate: latency = end - start")
            (println "    4. Update histogram bucket")
            (println "    5. Delete entry from start map")

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
        (bpf/close-map totals-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 4.2 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test histogram display
  (display-histogram [1200 800 400 200 80 20 5 2 0 0])

  ;; Test percentile calculation
  (calculate-percentiles [1200 800 400 200 80 20 5 2 0 0])
  )
