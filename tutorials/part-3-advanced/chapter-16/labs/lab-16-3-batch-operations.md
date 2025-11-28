# Lab 16.3: Batch Operations

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Implement efficient bulk data transfer using batch operations to minimize syscall overhead and maximize throughput.

## Prerequisites

- Completed Labs 16.1 and 16.2
- Understanding of syscall overhead
- Familiarity with bulk data processing

## Scenario

You're managing a connection tracking table with millions of entries. Individual map operations are too slow for bulk updates and queries. This lab shows how batch operations can provide 10-100x speedup.

---

## Part 1: Understanding Batch Operations

### Step 1.1: The Syscall Overhead Problem

```clojure
(ns lab-16-3.batch-operations
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps])
  (:import [java.util HashMap]
           [java.util.concurrent ConcurrentHashMap]))

;; Each map operation requires a syscall
;; Syscall overhead: ~100-200ns minimum
;; For 1 million entries:
;;   Individual: 1M syscalls × 200ns = 200ms
;;   Batch: ~10 syscalls × 200ns + processing = ~10ms

(defn demonstrate-syscall-overhead []
  (println "\n=== Syscall Overhead Analysis ===\n")
  (println "Individual operation model:")
  (println "  - Each lookup/update = 1 syscall")
  (println "  - Syscall overhead: ~100-200ns")
  (println "  - 1M operations = 100-200ms just in syscalls")
  (println)
  (println "Batch operation model:")
  (println "  - N operations = 1 syscall")
  (println "  - Syscall overhead amortized across N")
  (println "  - 1M operations = ~1-10ms total"))
```

### Step 1.2: Mock Batch Map Implementation

```clojure
(defrecord BatchMap [storage batch-size]
  clojure.lang.ILookup
  (valAt [_ key]
    (.get ^HashMap storage key))
  (valAt [this key not-found]
    (or (.valAt this key) not-found)))

(defn create-batch-map [max-entries]
  (->BatchMap (HashMap. max-entries) 256))

;; Simulate syscall overhead
(defn simulate-syscall []
  (Thread/sleep 0 100))  ; ~100ns

;; Individual operations (with simulated syscall each)
(defn lookup-individual [^BatchMap batch-map key]
  (simulate-syscall)
  (.get ^HashMap (:storage batch-map) key))

(defn update-individual [^BatchMap batch-map key value]
  (simulate-syscall)
  (.put ^HashMap (:storage batch-map) key value))

;; Batch operations (single syscall for all)
(defn batch-lookup [^BatchMap batch-map keys]
  (simulate-syscall)
  (mapv #(.get ^HashMap (:storage batch-map) %) keys))

(defn batch-update [^BatchMap batch-map entries]
  (simulate-syscall)
  (doseq [[k v] entries]
    (.put ^HashMap (:storage batch-map) k v)))

(defn batch-delete [^BatchMap batch-map keys]
  (simulate-syscall)
  (doseq [k keys]
    (.remove ^HashMap (:storage batch-map) k)))
```

---

## Part 2: Benchmarking Individual vs Batch

### Step 2.1: Lookup Benchmark

```clojure
(defn benchmark-individual-lookups [batch-map keys]
  (let [start (System/nanoTime)]
    (doseq [k keys]
      (lookup-individual batch-map k))
    (let [elapsed (- (System/nanoTime) start)]
      {:operations (count keys)
       :total-ns elapsed
       :avg-ns (/ elapsed (count keys))
       :ops-per-sec (/ (* (count keys) 1e9) elapsed)})))

(defn benchmark-batch-lookups [batch-map keys batch-size]
  (let [batches (partition-all batch-size keys)
        start (System/nanoTime)]
    (doseq [batch batches]
      (batch-lookup batch-map batch))
    (let [elapsed (- (System/nanoTime) start)]
      {:operations (count keys)
       :batches (count batches)
       :total-ns elapsed
       :avg-ns (/ elapsed (count keys))
       :ops-per-sec (/ (* (count keys) 1e9) elapsed)})))

(defn compare-lookup-performance [num-keys]
  (let [batch-map (create-batch-map num-keys)
        keys (range num-keys)]

    ;; Initialize data
    (doseq [k keys]
      (.put ^HashMap (:storage batch-map) k {:value k}))

    (println (format "\n=== Lookup Performance (%d keys) ===" num-keys))
    (println (format "%-15s %12s %15s %12s"
                     "Method" "Ops" "Avg (ns)" "Ops/sec"))
    (println (apply str (repeat 55 "-")))

    (let [individual (benchmark-individual-lookups batch-map keys)
          batch-256 (benchmark-batch-lookups batch-map keys 256)
          batch-1000 (benchmark-batch-lookups batch-map keys 1000)]

      (println (format "%-15s %12d %15.1f %12.0f"
                       "Individual"
                       (:operations individual)
                       (:avg-ns individual)
                       (:ops-per-sec individual)))

      (println (format "%-15s %12d %15.1f %12.0f"
                       "Batch (256)"
                       (:operations batch-256)
                       (:avg-ns batch-256)
                       (:ops-per-sec batch-256)))

      (println (format "%-15s %12d %15.1f %12.0f"
                       "Batch (1000)"
                       (:operations batch-1000)
                       (:avg-ns batch-1000)
                       (:ops-per-sec batch-1000)))

      (println)
      (println (format "Speedup (256):  %.1fx"
                       (/ (:ops-per-sec batch-256)
                          (:ops-per-sec individual))))
      (println (format "Speedup (1000): %.1fx"
                       (/ (:ops-per-sec batch-1000)
                          (:ops-per-sec individual)))))))
```

### Step 2.2: Update Benchmark

```clojure
(defn benchmark-individual-updates [batch-map entries]
  (let [start (System/nanoTime)]
    (doseq [[k v] entries]
      (update-individual batch-map k v))
    (let [elapsed (- (System/nanoTime) start)]
      {:operations (count entries)
       :total-ns elapsed
       :avg-ns (/ elapsed (count entries))
       :ops-per-sec (/ (* (count entries) 1e9) elapsed)})))

(defn benchmark-batch-updates [batch-map entries batch-size]
  (let [batches (partition-all batch-size entries)
        start (System/nanoTime)]
    (doseq [batch batches]
      (batch-update batch-map batch))
    (let [elapsed (- (System/nanoTime) start)]
      {:operations (count entries)
       :batches (count batches)
       :total-ns elapsed
       :avg-ns (/ elapsed (count entries))
       :ops-per-sec (/ (* (count entries) 1e9) elapsed)})))

(defn compare-update-performance [num-entries]
  (let [batch-map (create-batch-map num-entries)
        entries (for [i (range num-entries)]
                  [i {:value i :timestamp (System/currentTimeMillis)}])]

    (println (format "\n=== Update Performance (%d entries) ===" num-entries))
    (println (format "%-15s %12s %15s %12s"
                     "Method" "Ops" "Avg (ns)" "Ops/sec"))
    (println (apply str (repeat 55 "-")))

    (let [individual (benchmark-individual-updates batch-map entries)
          batch-256 (benchmark-batch-updates batch-map entries 256)]

      (println (format "%-15s %12d %15.1f %12.0f"
                       "Individual"
                       (:operations individual)
                       (:avg-ns individual)
                       (:ops-per-sec individual)))

      (println (format "%-15s %12d %15.1f %12.0f"
                       "Batch (256)"
                       (:operations batch-256)
                       (:avg-ns batch-256)
                       (:ops-per-sec batch-256)))

      (println)
      (println (format "Speedup: %.1fx"
                       (/ (:ops-per-sec batch-256)
                          (:ops-per-sec individual)))))))
```

---

## Part 3: Practical Batch Operations

### Step 3.1: Connection Table Management

```clojure
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

(defn create-connection-table [max-entries]
  (->BatchMap (HashMap. max-entries) 256))

;; Batch insert connections
(defn batch-insert-connections [table connections]
  (let [entries (for [conn connections]
                  [(connection-key conn) conn])]
    (batch-update table entries)))

;; Batch query connections
(defn batch-query-connections [table keys]
  (batch-lookup table keys))

;; Batch cleanup old connections
(defn batch-cleanup-old [table max-age-ms]
  (let [cutoff (- (System/currentTimeMillis) max-age-ms)
        old-keys (for [[k v] (.entrySet ^HashMap (:storage table))
                       :when (< (:last-seen v) cutoff)]
                   k)]
    (when (seq old-keys)
      (batch-delete table old-keys)
      (count old-keys))))
```

### Step 3.2: Bulk Statistics Collection

```clojure
(defn collect-statistics [table]
  "Collect aggregate statistics from connection table"
  (let [all-values (vals (.entrySet ^HashMap (:storage table)))]
    {:total-connections (count all-values)
     :total-packets (reduce + (map :packets all-values))
     :total-bytes (reduce + (map :bytes all-values))
     :avg-packets-per-conn (if (empty? all-values) 0
                             (/ (reduce + (map :packets all-values))
                                (count all-values)))
     :avg-bytes-per-conn (if (empty? all-values) 0
                           (/ (reduce + (map :bytes all-values))
                              (count all-values)))}))

(defn demonstrate-connection-table []
  (println "\n=== Connection Table Demo ===\n")

  (let [table (create-connection-table 10000)
        connections (repeatedly 1000 generate-connection)]

    ;; Batch insert
    (println "Inserting 1000 connections...")
    (let [start (System/nanoTime)]
      (batch-insert-connections table connections)
      (println (format "Insert time: %.2f ms"
                       (/ (- (System/nanoTime) start) 1e6))))

    ;; Batch query
    (println "\nQuerying 500 connections...")
    (let [keys (take 500 (map connection-key connections))
          start (System/nanoTime)
          results (batch-query-connections table keys)]
      (println (format "Query time: %.2f ms" (/ (- (System/nanoTime) start) 1e6)))
      (println (format "Found: %d connections" (count (filter some? results)))))

    ;; Statistics
    (println "\nStatistics:")
    (let [stats (collect-statistics table)]
      (println (format "  Total connections: %d" (:total-connections stats)))
      (println (format "  Total packets: %,d" (:total-packets stats)))
      (println (format "  Total bytes: %,d" (:total-bytes stats))))))
```

---

## Part 4: Batch Size Optimization

### Step 4.1: Finding Optimal Batch Size

```clojure
(defn find-optimal-batch-size [batch-map keys]
  (println "\n=== Optimal Batch Size Analysis ===\n")
  (println (format "%-12s %12s %15s" "Batch Size" "Batches" "Ops/sec"))
  (println (apply str (repeat 42 "-")))

  (let [results
        (for [batch-size [16 32 64 128 256 512 1024 2048]]
          (let [result (benchmark-batch-lookups batch-map keys batch-size)]
            (println (format "%-12d %12d %15.0f"
                             batch-size
                             (:batches result)
                             (:ops-per-sec result)))
            [batch-size (:ops-per-sec result)]))]

    (let [[optimal-size optimal-ops] (apply max-key second results)]
      (println)
      (println (format "Optimal batch size: %d (%.0f ops/sec)"
                       optimal-size optimal-ops)))))

(defn batch-size-analysis []
  (let [num-keys 10000
        batch-map (create-batch-map num-keys)
        keys (range num-keys)]

    ;; Initialize
    (doseq [k keys]
      (.put ^HashMap (:storage batch-map) k {:value k}))

    (find-optimal-batch-size batch-map keys)))
```

### Step 4.2: Memory vs Throughput Trade-off

```clojure
(defn memory-throughput-analysis []
  (println "\n=== Memory vs Throughput Trade-off ===\n")
  (println "Larger batch sizes:")
  (println "  + Higher throughput (fewer syscalls)")
  (println "  - More memory for batch buffers")
  (println "  - Higher latency for first result")
  (println)
  (println "Smaller batch sizes:")
  (println "  + Lower memory usage")
  (println "  + Lower latency per batch")
  (println "  - More syscall overhead")
  (println)
  (println "Recommendation:")
  (println "  - Default: 256-512 entries per batch")
  (println "  - High throughput: 1024-4096 entries")
  (println "  - Low latency: 64-128 entries"))
```

---

## Part 5: Iterator Pattern for Large Maps

### Step 5.1: Batch Iterator

```clojure
(defn batch-iterator
  "Iterate over map in batches"
  [batch-map batch-size]
  (let [all-keys (keys (.entrySet ^HashMap (:storage batch-map)))
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
    (doseq [i (range 1000)]
      (.put ^HashMap (:storage batch-map) i {:value i}))

    ;; Process in batches
    (println "Processing 1000 entries in batches of 100...")
    (let [total (atom 0)]
      (process-map-in-batches batch-map 100
        (fn [batch]
          (swap! total + (count batch))))
      (println (format "Processed: %d entries" @total)))))
```

### Step 5.2: Parallel Batch Processing

```clojure
(defn parallel-batch-process
  "Process batches in parallel"
  [batch-map batch-size process-fn]
  (let [all-keys (keys (.entrySet ^HashMap (:storage batch-map)))
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
    (doseq [i (range 10000)]
      (.put ^HashMap (:storage batch-map) i {:value i}))

    ;; Sequential
    (print "Sequential: ")
    (let [start (System/nanoTime)]
      (process-map-in-batches batch-map 256 identity)
      (println (format "%.2f ms" (/ (- (System/nanoTime) start) 1e6))))

    ;; Parallel
    (print "Parallel:   ")
    (let [start (System/nanoTime)]
      (parallel-batch-process batch-map 256 identity)
      (println (format "%.2f ms" (/ (- (System/nanoTime) start) 1e6))))))
```

---

## Part 6: Exercises

### Exercise 1: Batch Delete with Filtering

Implement batch delete with a filter predicate:

```clojure
(defn exercise-filtered-delete []
  ;; TODO: Implement batch delete with filter
  ;; 1. Iterate map in batches
  ;; 2. Apply filter predicate to each entry
  ;; 3. Collect keys to delete
  ;; 4. Batch delete collected keys
  ;; 5. Return count of deleted entries
  )
```

### Exercise 2: Batch Upsert

Implement batch upsert (update or insert):

```clojure
(defn exercise-batch-upsert []
  ;; TODO: Implement batch upsert
  ;; 1. For each entry: update if exists, insert if not
  ;; 2. Track insert vs update counts
  ;; 3. Return statistics
  )
```

### Exercise 3: Streaming Batch Export

Export map contents in streaming batches:

```clojure
(defn exercise-streaming-export []
  ;; TODO: Implement streaming export
  ;; 1. Create lazy sequence of batches
  ;; 2. Each batch is fetched on demand
  ;; 3. Serialize and write to output
  ;; 4. Support resume from checkpoint
  )
```

---

## Part 7: Testing Your Implementation

### Test Script

```clojure
(defn test-batch-operations []
  (println "Testing batch operations...")

  (let [batch-map (create-batch-map 1000)]
    ;; Test batch update
    (let [entries (for [i (range 100)]
                    [i {:value i}])]
      (batch-update batch-map entries)
      (assert (= 100 (.size ^HashMap (:storage batch-map)))
              "Should have 100 entries"))

    ;; Test batch lookup
    (let [keys (range 50)
          results (batch-lookup batch-map keys)]
      (assert (= 50 (count results))
              "Should return 50 results")
      (assert (every? some? results)
              "All results should be non-nil"))

    ;; Test batch delete
    (let [keys-to-delete (range 25)]
      (batch-delete batch-map keys-to-delete)
      (assert (= 75 (.size ^HashMap (:storage batch-map)))
              "Should have 75 entries after delete"))

    (println "All batch operation tests passed!")))

(defn run-all-tests []
  (println "\nLab 16.3: Batch Operations")
  (println "==========================\n")

  (test-batch-operations)

  (demonstrate-syscall-overhead)
  (compare-lookup-performance 1000)
  (compare-update-performance 1000)
  (batch-size-analysis)
  (demonstrate-connection-table)
  (demonstrate-batch-iteration)
  (demonstrate-parallel-batch)
  (memory-throughput-analysis)

  (println "\n=== Summary ===\n")
  (println "Key takeaways:")
  (println "1. Batch operations reduce syscall overhead significantly")
  (println "2. Optimal batch size is typically 256-1024 entries")
  (println "3. Use batch iteration for processing large maps")
  (println "4. Parallel batch processing can further improve throughput"))
```

---

## Summary

In this lab you learned:
- Why batch operations are faster than individual operations
- How to implement batch lookup, update, and delete
- Finding the optimal batch size for your workload
- Using batch iteration for large map processing
- Parallel batch processing for maximum throughput

## Next Steps

- Apply batch operations to your BPF map management code
- Implement batch export/import for map snapshots
- Explore combining batch operations with per-CPU maps
