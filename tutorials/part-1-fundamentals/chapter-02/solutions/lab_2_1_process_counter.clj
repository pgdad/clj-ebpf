(ns lab-2-1-process-counter
  "Lab 2.1: Process Counter using BPF hash maps

   This solution demonstrates:
   - Creating hash maps for process tracking
   - Map operations: lookup, update, delete
   - Iterating over map entries
   - Reading process names from /proc

   Run with: clojure -M -m lab-2-1-process-counter
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.java.io :as io])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Configuration
;;; ============================================================================

(def max-processes 10000)

;;; ============================================================================
;;; Part 2: Map Creation
;;; ============================================================================

(defn create-process-map
  "Create a hash map to track process execution counts.
   Key: u32 (PID), Value: u64 (count)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4           ; u32 for PID
                   :value-size 8         ; u64 for counter
                   :max-entries max-processes
                   :map-name "process_counts"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 3: Process Information
;;; ============================================================================

(defn get-process-name
  "Get process name from /proc/PID/comm"
  [pid]
  (try
    (let [path (str "/proc/" pid "/comm")
          name (slurp path)]
      (clojure.string/trim name))
    (catch Exception _
      "<unknown>")))

(defn get-process-cmdline
  "Get process command line from /proc/PID/cmdline"
  [pid]
  (try
    (let [path (str "/proc/" pid "/cmdline")
          cmdline (slurp path)]
      (-> cmdline
          (clojure.string/replace #"\u0000" " ")
          clojure.string/trim))
    (catch Exception _
      "")))

;;; ============================================================================
;;; Part 4: Map Operations
;;; ============================================================================

;; Track PIDs we've seen (workaround for map iteration bug in clj-ebpf 0.1.0)
(def ^:private tracked-pids (atom #{}))

(defn increment-process-count
  "Increment the execution count for a process"
  [process-map pid]
  (swap! tracked-pids conj pid)  ; Track this PID
  (let [current (try
                  (bpf/map-lookup process-map pid)
                  (catch clojure.lang.ExceptionInfo e
                    (if (= :enoent (:errno-keyword (ex-data e)))
                      nil  ; Key doesn't exist yet
                      (throw e))))
        new-count (if current (inc current) 1)]
    (bpf/map-update process-map pid new-count)))

(defn safe-map-lookup
  "Map lookup that returns nil for missing keys instead of throwing"
  [process-map pid]
  (try
    (bpf/map-lookup process-map pid)
    (catch clojure.lang.ExceptionInfo e
      (if (= :enoent (:errno-keyword (ex-data e)))
        nil
        (throw e)))))

(defn read-process-counts
  "Read all process counts from map using tracked PIDs.
   Note: Uses tracked-pids atom since map iteration has a bug in clj-ebpf 0.1.0"
  [process-map]
  (into {}
        (for [pid @tracked-pids
              :let [cnt (safe-map-lookup process-map pid)]
              :when cnt]
          [pid {:name (get-process-name pid)
                :count cnt}])))

(defn display-top-processes
  "Display top N processes by execution count"
  [counts n]
  (println (format "\nTop %d Processes by Execution Count:" n))
  (println (apply str (repeat 50 "-")))
  (println (format "%-8s %-20s %s" "PID" "NAME" "COUNT"))
  (println (apply str (repeat 50 "-")))
  (let [sorted (take n (sort-by (comp - :count val) counts))]
    (doseq [[pid {:keys [name count]}] sorted]
      (println (format "%-8d %-20s %d" pid name count)))))

;;; ============================================================================
;;; Part 5: BPF Program (for demonstration - actual attachment requires kprobe)
;;; ============================================================================

(defn create-counter-program
  "Create a simple BPF program that returns 0.
   Note: Actual process tracking would attach to sched_process_exec tracepoint.
   This is simplified for demonstration of map operations."
  [map-fd]
  (bpf/assemble
    [(bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 6: Simulation for Testing
;;; ============================================================================

(defn simulate-process-executions
  "Simulate process executions for testing map operations"
  [process-map]
  (println "\nSimulating process executions...")

  ;; Simulate executions with various frequencies
  (let [simulated-pids [[1000 4] [1001 2] [1002 1] [1003 7] [1004 3]]]
    (doseq [[pid exec-count] simulated-pids]
      (dotimes [_ exec-count]
        (increment-process-count process-map pid))))

  (println "  Simulated 17 total executions across 5 processes"))

;;; ============================================================================
;;; Part 7: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 2.1: Process Counter ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Reset tracked PIDs for fresh run
  (reset! tracked-pids #{})

  ;; Step 2: Create map
  (println "\nStep 2: Creating process counter map...")
  (let [process-map (create-process-map)]
    (println "  Map created (FD:" (:fd process-map) ")")
    (println "  Key size:" (:key-size process-map) "bytes (u32)")
    (println "  Value size:" (:value-size process-map) "bytes (u64)")
    (println "  Max entries:" (:max-entries process-map))

    (try
      ;; Step 3: Create BPF program
      (println "\nStep 3: Creating BPF program...")
      (let [program (create-counter-program (:fd process-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :socket-filter :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          ;; Step 5: Simulate process executions
          (println "\nStep 5: Simulating process executions...")
          (println "  Note: Tracepoint attachment requires additional setup")
          (println "  Demonstrating map operations with simulated data...")
          (simulate-process-executions process-map)

          ;; Step 6: Display results
          (println "\nStep 6: Reading and displaying results...")
          (let [counts (read-process-counts process-map)]
            (println "\nTotal processes tracked:" (count counts))
            (display-top-processes counts 10))

          ;; Step 7: Test individual lookup
          (println "\nStep 7: Testing individual lookup...")
          (let [test-pid 1003
                cnt (bpf/map-lookup process-map test-pid)]
            (if cnt
              (println (format "  PID %d: %d executions" test-pid cnt))
              (println (format "  PID %d not found" test-pid))))

          ;; Step 8: Test deletion
          (println "\nStep 8: Testing deletion...")
          (let [test-pid 1002]
            (bpf/map-delete process-map test-pid)
            (swap! tracked-pids disj test-pid)  ; Remove from tracking
            (let [value (safe-map-lookup process-map test-pid)]
              (if value
                (println "  Deletion failed")
                (println (format "  PID %d deleted successfully" test-pid)))))

          ;; Step 9: Final state
          (println "\nStep 9: Final map state...")
          (let [counts (read-process-counts process-map)]
            (display-top-processes counts 10))

          ;; Step 10: Map statistics
          (println "\nStep 10: Map statistics...")
          (let [counts (read-process-counts process-map)
                total-execs (reduce + (map :count (vals counts)))]
            (println "  Unique processes:" (count counts))
            (println "  Total executions:" total-execs)
            (println "  Average per process:" (format "%.1f" (/ (double total-execs) (max 1 (count counts))))))

          ;; Cleanup
          (println "\nStep 11: Cleanup...")
          (bpf/close-program prog)
          (println "  Program closed")))

      (catch Exception e
        (println "Error:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map process-map)
        (println "  Map closed"))))

  (println "\n=== Lab 2.1 Complete! ===")
  true)

;;; ============================================================================
;;; Part 8: Challenge - Extended Process Stats
;;; ============================================================================

(defn run-challenge []
  (println "\n=== Lab 2.1 Challenge: Extended Process Stats ===\n")

  ;; Create a map with larger values to store multiple metrics
  (println "Creating extended stats map...")
  (let [stats-map (bpf/create-map {:map-type :hash
                                    :key-size 4     ; PID
                                    :value-size 24  ; exec_count (8) + last_exec_time (8) + total_runtime (8)
                                    :max-entries 1000
                                    :map-name "process_stats"})]

    (println "  Map created with 24-byte values for extended stats")
    (println "  Fields: exec_count (u64), last_exec_time (u64), total_runtime (u64)")

    ;; Simulate some data
    (let [bb (ByteBuffer/allocate 24)]
      (.order bb ByteOrder/LITTLE_ENDIAN)
      ;; PID 1000: 5 execs, time 12345678, runtime 100000
      (.putLong bb 0 5)
      (.putLong bb 8 12345678)
      (.putLong bb 16 100000)
      (let [key-bytes (utils/int->bytes 1000)]
        (bpf/map-update stats-map key-bytes (.array bb))))

    (println "  Added sample extended stats")

    ;; Read back
    (let [key-bytes (utils/int->bytes 1000)
          value (bpf/map-lookup stats-map key-bytes)]
      (when value
        (let [bb (ByteBuffer/wrap value)]
          (.order bb ByteOrder/LITTLE_ENDIAN)
          (println "\n  PID 1000 extended stats:")
          (println (format "    Exec count:   %d" (.getLong bb 0)))
          (println (format "    Last exec:    %d ns" (.getLong bb 8)))
          (println (format "    Total runtime: %d ns" (.getLong bb 16))))))

    (bpf/close-map stats-map)
    (println "\n  Challenge map closed"))

  (println "\n=== Challenge Complete! ==="))

(defn -main [& args]
  (run-lab)
  (run-challenge)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)
  (run-challenge)

  ;; Experiment: Use LRU hash map
  (def lru-map (bpf/create-map {:map-type :lru-hash
                                 :key-size 4
                                 :value-size 8
                                 :max-entries 10
                                 :map-name "lru_process"}))

  ;; Only keeps 10 most recently updated entries
  (doseq [pid (range 20)]
    (bpf/map-update lru-map (utils/int->bytes pid) (utils/long->bytes 1)))

  (count (bpf/map-keys lru-map))  ; Should be 10

  (bpf/close-map lru-map)
  )
