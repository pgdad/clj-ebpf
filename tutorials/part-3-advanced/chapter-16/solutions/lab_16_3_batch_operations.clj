;; Lab 16.3 Solution: Batch Operations
;; Implement efficient bulk data transfer using batch operations
;;
;; Learning Goals:
;; - Understand syscall overhead
;; - Implement batch lookup, update, and delete
;; - Find optimal batch sizes

(ns lab-16-3-batch-operations
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps])
  (:import [java.util HashMap]
           [java.time Instant]))

;; ============================================================================
;; Batch Map Implementation
;; ============================================================================

(defrecord BatchMap [^HashMap storage batch-size max-entries])

(defn create-batch-map
  "Create a map that supports batch operations"
  [max-entries]
  (->BatchMap (HashMap. max-entries) 256 max-entries))

;; Simulate syscall overhead (in real BPF, each operation is a syscall)
(defn simulate-syscall-overhead []
  ;; Simulate ~100-200ns syscall overhead
  (dotimes [_ 10] (Math/sqrt (rand))))

;; ============================================================================
;; Individual Operations (with simulated syscall overhead)
;; ============================================================================

(defn lookup-individual
  "Lookup a single key (simulates syscall per operation)"
  [^BatchMap batch-map key]
  (simulate-syscall-overhead)
  (.get ^HashMap (:storage batch-map) key))

(defn update-individual!
  "Update a single key (simulates syscall per operation)"
  [^BatchMap batch-map key value]
  (simulate-syscall-overhead)
  (.put ^HashMap (:storage batch-map) key value))

(defn delete-individual!
  "Delete a single key (simulates syscall per operation)"
  [^BatchMap batch-map key]
  (simulate-syscall-overhead)
  (.remove ^HashMap (:storage batch-map) key))

;; ============================================================================
;; Batch Operations (single syscall for all)
;; ============================================================================

(defn batch-lookup
  "Lookup multiple keys in a single batch (one syscall)"
  [^BatchMap batch-map keys]
  (simulate-syscall-overhead)
  (mapv #(.get ^HashMap (:storage batch-map) %) keys))

(defn batch-update!
  "Update multiple entries in a single batch (one syscall)"
  [^BatchMap batch-map entries]
  (simulate-syscall-overhead)
  (doseq [[k v] entries]
    (.put ^HashMap (:storage batch-map) k v)))

(defn batch-delete!
  "Delete multiple keys in a single batch (one syscall)"
  [^BatchMap batch-map keys]
  (simulate-syscall-overhead)
  (doseq [k keys]
    (.remove ^HashMap (:storage batch-map) k)))

(defn batch-lookup-all
  "Get all entries in batches"
  [^BatchMap batch-map]
  (simulate-syscall-overhead)
  (into {} (.entrySet ^HashMap (:storage batch-map))))

;; ============================================================================
;; Benchmark Utilities
;; ============================================================================

(defn benchmark-individual-lookups
  "Benchmark individual lookup operations"
  [batch-map keys]
  (let [start (System/nanoTime)]
    (doseq [k keys]
      (lookup-individual batch-map k))
    (let [elapsed (- (System/nanoTime) start)]
      {:operations (count keys)
       :total-ns elapsed
       :avg-ns (double (/ elapsed (count keys)))
       :ops-per-sec (/ (* (count keys) 1e9) elapsed)})))

(defn benchmark-batch-lookups
  "Benchmark batch lookup operations"
  [batch-map keys batch-size]
  (let [batches (partition-all batch-size keys)
        start (System/nanoTime)]
    (doseq [batch batches]
      (batch-lookup batch-map batch))
    (let [elapsed (- (System/nanoTime) start)]
      {:operations (count keys)
       :batches (count batches)
       :batch-size batch-size
       :total-ns elapsed
       :avg-ns (double (/ elapsed (count keys)))
       :ops-per-sec (/ (* (count keys) 1e9) elapsed)})))

(defn benchmark-individual-updates
  "Benchmark individual update operations"
  [batch-map entries]
  (let [start (System/nanoTime)]
    (doseq [[k v] entries]
      (update-individual! batch-map k v))
    (let [elapsed (- (System/nanoTime) start)]
      {:operations (count entries)
       :total-ns elapsed
       :avg-ns (double (/ elapsed (count entries)))
       :ops-per-sec (/ (* (count entries) 1e9) elapsed)})))

(defn benchmark-batch-updates
  "Benchmark batch update operations"
  [batch-map entries batch-size]
  (let [batches (partition-all batch-size entries)
        start (System/nanoTime)]
    (doseq [batch batches]
      (batch-update! batch-map batch))
    (let [elapsed (- (System/nanoTime) start)]
      {:operations (count entries)
       :batches (count batches)
       :batch-size batch-size
       :total-ns elapsed
       :avg-ns (double (/ elapsed (count entries)))
       :ops-per-sec (/ (* (count entries) 1e9) elapsed)})))

;; ============================================================================
;; Performance Comparison
;; ============================================================================

(defn compare-lookup-performance
  "Compare individual vs batch lookup performance"
  [num-keys]
  (let [batch-map (create-batch-map num-keys)
        keys (range num-keys)]

    ;; Initialize data
    (doseq [k keys]
      (.put ^HashMap (:storage batch-map) k {:value k}))

    (println (format "\n=== Lookup Performance (%d keys) ===" num-keys))
    (println (format "%-20s %12s %15s %12s"
                     "Method" "Ops" "Avg (ns)" "Ops/sec"))
    (println (apply str (repeat 62 "-")))

    (let [individual (benchmark-individual-lookups batch-map keys)
          batch-64 (benchmark-batch-lookups batch-map keys 64)
          batch-256 (benchmark-batch-lookups batch-map keys 256)
          batch-1024 (benchmark-batch-lookups batch-map keys 1024)]

      (println (format "%-20s %12d %15.1f %,12.0f"
                       "Individual"
                       (:operations individual)
                       (:avg-ns individual)
                       (:ops-per-sec individual)))

      (println (format "%-20s %12d %15.1f %,12.0f"
                       "Batch (64)"
                       (:operations batch-64)
                       (:avg-ns batch-64)
                       (:ops-per-sec batch-64)))

      (println (format "%-20s %12d %15.1f %,12.0f"
                       "Batch (256)"
                       (:operations batch-256)
                       (:avg-ns batch-256)
                       (:ops-per-sec batch-256)))

      (println (format "%-20s %12d %15.1f %,12.0f"
                       "Batch (1024)"
                       (:operations batch-1024)
                       (:avg-ns batch-1024)
                       (:ops-per-sec batch-1024)))

      (println)
      (println (format "Speedup (batch-256 vs individual): %.1fx"
                       (/ (:ops-per-sec batch-256)
                          (:ops-per-sec individual)))))))

(defn compare-update-performance
  "Compare individual vs batch update performance"
  [num-entries]
  (let [batch-map (create-batch-map num-entries)
        entries (for [i (range num-entries)]
                  [i {:value i :timestamp (System/currentTimeMillis)}])]

    (println (format "\n=== Update Performance (%d entries) ===" num-entries))
    (println (format "%-20s %12s %15s %12s"
                     "Method" "Ops" "Avg (ns)" "Ops/sec"))
    (println (apply str (repeat 62 "-")))

    (let [individual (benchmark-individual-updates batch-map entries)
          batch-256 (benchmark-batch-updates batch-map entries 256)]

      (println (format "%-20s %12d %15.1f %,12.0f"
                       "Individual"
                       (:operations individual)
                       (:avg-ns individual)
                       (:ops-per-sec individual)))

      (println (format "%-20s %12d %15.1f %,12.0f"
                       "Batch (256)"
                       (:operations batch-256)
                       (:avg-ns batch-256)
                       (:ops-per-sec batch-256)))

      (println)
      (println (format "Speedup: %.1fx"
                       (/ (:ops-per-sec batch-256)
                          (:ops-per-sec individual)))))))

;; ============================================================================
;; Optimal Batch Size Analysis
;; ============================================================================

(defn find-optimal-batch-size
  "Find the optimal batch size through experimentation"
  [batch-map keys]
  (println "\n=== Optimal Batch Size Analysis ===\n")
  (println (format "%-12s %12s %15s" "Batch Size" "Batches" "Ops/sec"))
  (println (apply str (repeat 42 "-")))

  (let [results
        (for [batch-size [8 16 32 64 128 256 512 1024 2048 4096]]
          (let [result (benchmark-batch-lookups batch-map keys batch-size)]
            (println (format "%-12d %12d %,15.0f"
                             batch-size
                             (:batches result)
                             (:ops-per-sec result)))
            [batch-size (:ops-per-sec result)]))]

    (let [[optimal-size optimal-ops] (apply max-key second results)]
      (println)
      (println (format "Optimal batch size: %d (%,.0f ops/sec)"
                       optimal-size optimal-ops))
      optimal-size)))

;; ============================================================================
;; Connection Table Management
;; ============================================================================

(defrecord Connection [src-ip dst-ip src-port dst-port
                       packets bytes last-seen])

(defn generate-connection []
  (->Connection (rand-int 0xFFFFFFFF)
                (rand-int 0xFFFFFFFF)
                (rand-int 65536)
                (rand-int 65536)
                (rand-int 1000000)
                (rand-int 100000000)
                (System/currentTimeMillis)))

(defn connection-key [conn]
  [(:src-ip conn) (:dst-ip conn) (:src-port conn) (:dst-port conn)])

(defn batch-insert-connections
  "Insert multiple connections in a batch"
  [batch-map connections]
  (let [entries (for [conn connections]
                  [(connection-key conn) conn])]
    (batch-update! batch-map entries)
    (count entries)))

(defn batch-query-connections
  "Query multiple connections in a batch"
  [batch-map keys]
  (batch-lookup batch-map keys))

(defn batch-cleanup-old
  "Clean up connections older than max-age-ms"
  [batch-map max-age-ms]
  (let [cutoff (- (System/currentTimeMillis) max-age-ms)
        all-entries (batch-lookup-all batch-map)
        old-keys (for [[k v] all-entries
                       :when (and (instance? Connection v)
                                  (< (:last-seen v) cutoff))]
                   k)]
    (when (seq old-keys)
      (batch-delete! batch-map old-keys))
    (count old-keys)))

(defn demonstrate-connection-table []
  (println "\n=== Connection Table Demo ===\n")

  (let [batch-map (create-batch-map 10000)
        connections (repeatedly 1000 generate-connection)]

    ;; Batch insert
    (println "Inserting 1000 connections...")
    (let [start (System/nanoTime)
          count (batch-insert-connections batch-map connections)
          elapsed (/ (- (System/nanoTime) start) 1e6)]
      (println (format "Inserted %d connections in %.2f ms" count elapsed)))

    ;; Batch query
    (println "\nQuerying 500 connections...")
    (let [keys (take 500 (map connection-key connections))
          start (System/nanoTime)
          results (batch-query-connections batch-map keys)
          elapsed (/ (- (System/nanoTime) start) 1e6)]
      (println (format "Found %d connections in %.2f ms"
                       (count (filter some? results)) elapsed)))

    ;; Statistics
    (println "\nConnection Statistics:")
    (let [all-conns (vals (batch-lookup-all batch-map))
          total-packets (reduce + (map :packets all-conns))
          total-bytes (reduce + (map :bytes all-conns))]
      (println (format "  Total connections: %d" (count all-conns)))
      (println (format "  Total packets: %,d" total-packets))
      (println (format "  Total bytes: %,d" total-bytes)))))

;; ============================================================================
;; Batch Iterator
;; ============================================================================

(defn batch-iterator
  "Iterate over map in batches"
  [batch-map batch-size]
  (let [all-keys (keys (batch-lookup-all batch-map))
        batches (partition-all batch-size all-keys)]
    (map (fn [key-batch]
           (batch-lookup batch-map key-batch))
         batches)))

(defn process-map-in-batches
  "Process entire map in batches with a function"
  [batch-map batch-size process-fn]
  (doseq [batch (batch-iterator batch-map batch-size)]
    (process-fn batch)))

(defn demonstrate-batch-iteration []
  (println "\n=== Batch Iteration Demo ===\n")

  (let [batch-map (create-batch-map 1000)]
    ;; Initialize
    (batch-update! batch-map (for [i (range 1000)] [i {:value i}]))

    ;; Process in batches
    (println "Processing 1000 entries in batches of 100...")
    (let [total (atom 0)
          start (System/nanoTime)]
      (process-map-in-batches batch-map 100
        (fn [batch]
          (swap! total + (count batch))))
      (let [elapsed (/ (- (System/nanoTime) start) 1e6)]
        (println (format "Processed %d entries in %.2f ms" @total elapsed))))))

;; ============================================================================
;; Parallel Batch Processing
;; ============================================================================

(defn parallel-batch-process
  "Process batches in parallel"
  [batch-map batch-size process-fn]
  (let [all-keys (keys (batch-lookup-all batch-map))
        batches (partition-all batch-size all-keys)]
    (->> batches
         (pmap (fn [key-batch]
                 (let [values (batch-lookup batch-map key-batch)]
                   (process-fn values))))
         (doall))))

(defn demonstrate-parallel-batch []
  (println "\n=== Parallel Batch Processing ===\n")

  (let [batch-map (create-batch-map 10000)]
    ;; Initialize
    (batch-update! batch-map (for [i (range 10000)] [i {:value i}]))

    ;; Sequential
    (print "Sequential: ")
    (let [start (System/nanoTime)]
      (process-map-in-batches batch-map 256 (fn [_] (Thread/sleep 1)))
      (println (format "%.2f ms" (/ (- (System/nanoTime) start) 1e6))))

    ;; Parallel
    (print "Parallel:   ")
    (let [start (System/nanoTime)]
      (parallel-batch-process batch-map 256 (fn [_] (Thread/sleep 1)))
      (println (format "%.2f ms" (/ (- (System/nanoTime) start) 1e6))))))

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-filtered-delete
  "Exercise 1: Batch delete with filtering"
  []
  (println "\n=== Exercise 1: Filtered Delete ===\n")

  (let [batch-map (create-batch-map 1000)]
    ;; Initialize with connections
    (doseq [i (range 1000)]
      (let [last-seen (- (System/currentTimeMillis)
                         (rand-int 120000))]  ; 0-120 seconds ago
        (.put ^HashMap (:storage batch-map) i
              {:id i :last-seen last-seen})))

    (println (format "Initial entries: %d" (.size ^HashMap (:storage batch-map))))

    ;; Delete entries older than 60 seconds
    (let [cutoff (- (System/currentTimeMillis) 60000)
          all-entries (batch-lookup-all batch-map)
          old-keys (for [[k v] all-entries
                         :when (< (:last-seen v) cutoff)]
                     k)]
      (println (format "Entries to delete (older than 60s): %d" (count old-keys)))
      (batch-delete! batch-map old-keys))

    (println (format "Remaining entries: %d" (.size ^HashMap (:storage batch-map))))))

(defn exercise-batch-upsert
  "Exercise 2: Batch upsert (update or insert)"
  []
  (println "\n=== Exercise 2: Batch Upsert ===\n")

  (let [batch-map (create-batch-map 1000)
        insert-count (atom 0)
        update-count (atom 0)]

    ;; Initialize with some entries
    (batch-update! batch-map (for [i (range 500)] [i {:value i :version 1}]))
    (println (format "Initial entries: %d" (.size ^HashMap (:storage batch-map))))

    ;; Upsert: some updates, some inserts
    (let [entries (for [i (range 300 800)]
                    [i {:value i :version 2}])]
      (doseq [[k v] entries]
        (if (.containsKey ^HashMap (:storage batch-map) k)
          (swap! update-count inc)
          (swap! insert-count inc)))
      (batch-update! batch-map entries))

    (println (format "Updates: %d, Inserts: %d" @update-count @insert-count))
    (println (format "Final entries: %d" (.size ^HashMap (:storage batch-map))))))

;; ============================================================================
;; Tests
;; ============================================================================

(defn test-batch-operations []
  (println "Testing batch operations...")

  (let [batch-map (create-batch-map 1000)]
    ;; Test batch update
    (let [entries (for [i (range 100)] [i {:value i}])]
      (batch-update! batch-map entries)
      (assert (= 100 (.size ^HashMap (:storage batch-map)))
              "Should have 100 entries"))

    ;; Test batch lookup
    (let [keys (range 50)
          results (batch-lookup batch-map keys)]
      (assert (= 50 (count results)) "Should return 50 results")
      (assert (every? some? results) "All results should be non-nil"))

    ;; Test batch delete
    (let [keys-to-delete (range 25)]
      (batch-delete! batch-map keys-to-delete)
      (assert (= 75 (.size ^HashMap (:storage batch-map)))
              "Should have 75 entries after delete"))

    ;; Test batch lookup all
    (let [all (batch-lookup-all batch-map)]
      (assert (= 75 (count all)) "Should have 75 entries"))

    (println "Batch operation tests passed!")))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the batch operations lab"
  [& args]
  (println "Lab 16.3: Batch Operations")
  (println "==========================\n")

  (let [command (first args)]
    (case command
      "test"
      (test-batch-operations)

      "compare"
      (do
        (compare-lookup-performance 10000)
        (compare-update-performance 10000))

      "optimal"
      (let [batch-map (create-batch-map 10000)
            keys (range 10000)]
        (batch-update! batch-map (for [k keys] [k {:value k}]))
        (find-optimal-batch-size batch-map keys))

      "connection"
      (demonstrate-connection-table)

      "iterate"
      (do
        (demonstrate-batch-iteration)
        (demonstrate-parallel-batch))

      "exercises"
      (do
        (exercise-filtered-delete)
        (exercise-batch-upsert))

      ;; Default: full demo
      (do
        (test-batch-operations)
        (compare-lookup-performance 5000)
        (compare-update-performance 5000)

        (let [batch-map (create-batch-map 10000)
              keys (range 10000)]
          (batch-update! batch-map (for [k keys] [k {:value k}]))
          (find-optimal-batch-size batch-map keys))

        (demonstrate-connection-table)
        (demonstrate-batch-iteration)
        (exercise-filtered-delete)
        (exercise-batch-upsert)

        (println "\n=== Key Takeaways ===")
        (println "1. Batch operations reduce syscall overhead significantly")
        (println "2. Optimal batch size is typically 256-1024 entries")
        (println "3. Use batch iteration for processing large maps")
        (println "4. Parallel batch processing can further improve throughput")))))

;; Run with: clj -M -m lab-16-3-batch-operations
