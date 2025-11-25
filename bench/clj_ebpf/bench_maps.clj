(ns clj-ebpf.bench-maps
  "Benchmarks for BPF map operations.

   Tests performance of:
   - Map creation/destruction
   - Single element operations (get, put, delete)
   - Batch operations
   - Iteration patterns"
  (:require [clj-ebpf.bench-core :as bench]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils]
            [criterium.core :as crit]))

;; ============================================================================
;; Test Data Generation
;; ============================================================================

(defn generate-keys
  "Generate n keys of the given size using sequential integers"
  [n key-size]
  (vec (repeatedly n #(utils/int->bytes (rand-int Integer/MAX_VALUE)))))

(defn generate-values
  "Generate n values of the given size"
  [n value-size]
  (vec (repeatedly n #(utils/long->bytes (rand-int Integer/MAX_VALUE)))))

(defn generate-kv-pairs
  "Generate n key-value pairs"
  [n key-size value-size]
  (mapv vector (generate-keys n key-size) (generate-values n value-size)))

;; ============================================================================
;; Map Creation Benchmarks
;; ============================================================================

(defn bench-map-creation
  "Benchmark map creation and destruction"
  []
  (println "\n=== Map Creation Benchmarks ===")
  (println "Testing map creation overhead for different map types and sizes\n")

  (let [results
        [(bench/bench "Hash map (1K entries, 4B key, 8B value)"
                      (let [m (maps/create-map :hash 1000 4 8)]
                        (maps/close-map m)))

         (bench/bench "Hash map (10K entries, 4B key, 8B value)"
                      (let [m (maps/create-map :hash 10000 4 8)]
                        (maps/close-map m)))

         (bench/bench "Hash map (100K entries, 4B key, 8B value)"
                      (let [m (maps/create-map :hash 100000 4 8)]
                        (maps/close-map m)))

         (bench/bench "Array map (1K entries, 8B value)"
                      (let [m (maps/create-map :array 1000 4 8)]
                        (maps/close-map m)))

         (bench/bench "Per-CPU hash (1K entries, 4B key, 8B value)"
                      (let [m (maps/create-map :percpu-hash 1000 4 8)]
                        (maps/close-map m)))]]

    (bench/run-benchmark-suite "Map Creation" results)))

;; ============================================================================
;; Single Operation Benchmarks
;; ============================================================================

(defn bench-single-ops
  "Benchmark single element operations"
  []
  (println "\n=== Single Operation Benchmarks ===")
  (println "Testing individual map operations (lookup, update, delete)\n")

  (let [m (maps/create-map :hash 10000 4 8)
        key-seg (utils/int->segment 42)
        val-seg (utils/long->segment 123456789)
        ;; Pre-populate map
        _ (maps/map-update m key-seg val-seg)]

    (try
      (let [results
            [(bench/bench "map-lookup (existing key)"
                          (maps/map-lookup m key-seg))

             (bench/bench "map-update (BPF_ANY)"
                          (do
                            (maps/map-update m (utils/int->segment (rand-int 10000))
                                             val-seg)))

             (bench/bench "map-update (BPF_EXIST)"
                          (maps/map-update m key-seg val-seg :flags :exist))]]

        (bench/run-benchmark-suite "Single Operations" results))
      (finally
        (maps/close-map m)))))

;; ============================================================================
;; Batch Operation Benchmarks
;; ============================================================================

(defn bench-batch-ops
  "Benchmark batch operations"
  []
  (println "\n=== Batch Operation Benchmarks ===")
  (println "Comparing single vs batch operations at different scales\n")

  (let [m (maps/create-map :hash 100000 4 8)
        batch-sizes [10 100 500 1000]]

    (try
      (doseq [batch-size batch-sizes]
        (let [keys (generate-keys batch-size 4)
              values (generate-values batch-size 8)]
          (println (format "\n--- Batch Size: %d ---" batch-size))

          ;; Single operations baseline
          (let [single-results
                (crit/quick-benchmark
                 (doseq [i (range batch-size)]
                   (let [key-seg (utils/bytes->segment (nth keys i))
                         val-seg (utils/bytes->segment (nth values i))]
                     (maps/map-update m key-seg val-seg)))
                 {})
                single-time (first (:mean single-results))]
            (println (format "Single ops (%d updates):  %s  (%s per op)"
                             batch-size
                             (bench/format-time single-time)
                             (bench/format-time (/ single-time batch-size)))))

          ;; Batch operation
          (let [batch-results
                (crit/quick-benchmark
                 (maps/map-update-batch m keys values)
                 {})
                batch-time (first (:mean batch-results))]
            (println (format "Batch update (%d entries): %s  (%s per op)"
                             batch-size
                             (bench/format-time batch-time)
                             (bench/format-time (/ batch-time batch-size)))))))
      (finally
        (maps/close-map m)))))

;; ============================================================================
;; Iteration Benchmarks
;; ============================================================================

(defn bench-iteration
  "Benchmark map iteration patterns"
  []
  (println "\n=== Iteration Benchmarks ===")
  (println "Testing different iteration approaches\n")

  (let [m (maps/create-map :hash 10000 4 8)
        ;; Pre-populate map
        _ (dotimes [i 10000]
            (let [key-seg (utils/int->segment i)
                  val-seg (utils/long->segment (* i 100))]
              (maps/map-update m key-seg val-seg)))]

    (try
      (let [results
            [(bench/bench "map-entries (10K entries)"
                          (count (maps/map-entries m)))

             (bench/bench "reduce-map (sum values, 10K entries)"
                          (maps/reduce-map m
                                           (fn [acc _ v]
                                             (+ acc (utils/segment->long v)))
                                           0))

             (bench/bench "map-keys (10K entries)"
                          (count (maps/map-keys m)))

             (bench/bench "map-entries-chunked (chunk=1000, 10K entries)"
                          (count (doall (maps/map-entries-chunked m 1000))))]]

        (bench/run-benchmark-suite "Iteration" results))
      (finally
        (maps/close-map m)))))

;; ============================================================================
;; Memory Layout Benchmarks
;; ============================================================================

(defn bench-key-value-sizes
  "Benchmark impact of different key/value sizes"
  []
  (println "\n=== Key/Value Size Impact ===")
  (println "Testing performance across different key and value sizes\n")

  (let [configurations [[4 8 "4B key, 8B value"]
                        [4 64 "4B key, 64B value"]
                        [4 256 "4B key, 256B value"]
                        [8 8 "8B key, 8B value"]
                        [16 64 "16B key, 64B value"]
                        [32 128 "32B key, 128B value"]]]

    (doseq [[key-size value-size desc] configurations]
      (let [m (maps/create-map :hash 10000 key-size value-size)
            key-bytes (byte-array key-size)
            val-bytes (byte-array value-size)]
        (try
          (let [results (crit/quick-benchmark
                         (let [key-seg (utils/bytes->segment key-bytes)
                               val-seg (utils/bytes->segment val-bytes)]
                           (maps/map-update m key-seg val-seg)
                           (maps/map-lookup m key-seg))
                         {})
                mean-time (first (:mean results))]
            (println (format "%-25s %s" desc (bench/format-time mean-time))))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn run-all-benchmarks
  "Run all map benchmarks"
  []
  (println)
  (println "=========================================")
  (println "       BPF Map Performance Benchmarks    ")
  (println "=========================================")
  (println)
  (println "Note: Requires root/CAP_BPF capabilities")
  (println)

  (bench-map-creation)
  (bench-single-ops)
  (bench-batch-ops)
  (bench-iteration)
  (bench-key-value-sizes)

  (println)
  (println "Benchmarks complete."))

(defn -main [& args]
  (run-all-benchmarks))
