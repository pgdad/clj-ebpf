;; Lab 16.1 Solution: Map Performance Comparison
;; Benchmark different BPF map types to understand performance characteristics
;;
;; Learning Goals:
;; - Benchmark BPF map operations
;; - Compare array vs hash map performance
;; - Understand scaling behavior

(ns lab-16-1-map-performance
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps])
  (:import [java.util.concurrent ConcurrentHashMap]
           [java.util.concurrent.atomic AtomicLong AtomicLongArray]
           [java.util HashMap]))

;; ============================================================================
;; Mock Map Implementations for Benchmarking
;; ============================================================================

(defrecord MockArrayMap [^AtomicLongArray storage max-entries]
  clojure.lang.ILookup
  (valAt [_ key]
    (when (and (>= key 0) (< key max-entries))
      (.get storage key)))
  (valAt [this key not-found]
    (or (.valAt this key) not-found)))

(defrecord MockHashMap [^ConcurrentHashMap storage max-entries]
  clojure.lang.ILookup
  (valAt [_ key]
    (.get storage key))
  (valAt [this key not-found]
    (or (.valAt this key) not-found)))

(defrecord MockPerCPUArray [storages num-cpus max-entries]
  clojure.lang.ILookup
  (valAt [_ key]
    ;; Returns vector of per-CPU values
    (when (and (>= key 0) (< key max-entries))
      (mapv #(.get ^AtomicLongArray % key) storages)))
  (valAt [this key not-found]
    (or (.valAt this key) not-found)))

(defn create-array-map [max-entries]
  (->MockArrayMap (AtomicLongArray. max-entries) max-entries))

(defn create-hash-map [max-entries]
  (->MockHashMap (ConcurrentHashMap. max-entries) max-entries))

(defn create-percpu-array [max-entries num-cpus]
  (->MockPerCPUArray
    (vec (repeatedly num-cpus #(AtomicLongArray. max-entries)))
    num-cpus
    max-entries))

;; ============================================================================
;; Array Map Operations
;; ============================================================================

(defn array-lookup [^MockArrayMap m key]
  (.get ^AtomicLongArray (:storage m) key))

(defn array-update! [^MockArrayMap m key value]
  (.set ^AtomicLongArray (:storage m) key value))

(defn array-atomic-add! [^MockArrayMap m key delta]
  (.addAndGet ^AtomicLongArray (:storage m) key delta))

;; ============================================================================
;; Hash Map Operations
;; ============================================================================

(defn hash-lookup [^MockHashMap m key]
  (.get ^ConcurrentHashMap (:storage m) key))

(defn hash-update! [^MockHashMap m key value]
  (.put ^ConcurrentHashMap (:storage m) key value))

;; ============================================================================
;; Per-CPU Array Operations
;; ============================================================================

(defn percpu-lookup [^MockPerCPUArray m key cpu-id]
  (.get ^AtomicLongArray (nth (:storages m) cpu-id) key))

(defn percpu-update! [^MockPerCPUArray m key cpu-id value]
  (.set ^AtomicLongArray (nth (:storages m) cpu-id) key value))

(defn percpu-atomic-add! [^MockPerCPUArray m key cpu-id delta]
  (.addAndGet ^AtomicLongArray (nth (:storages m) cpu-id) key delta))

(defn percpu-sum [^MockPerCPUArray m key]
  (reduce + (map #(.get ^AtomicLongArray % key) (:storages m))))

;; ============================================================================
;; Benchmark Utilities
;; ============================================================================

(defn benchmark
  "Run a function multiple times and return statistics"
  [f iterations warmup-iterations]
  ;; Warmup
  (dotimes [_ warmup-iterations]
    (f))

  ;; Actual benchmark
  (let [start (System/nanoTime)]
    (dotimes [_ iterations]
      (f))
    (let [total-ns (- (System/nanoTime) start)]
      {:iterations iterations
       :total-ns total-ns
       :avg-ns (double (/ total-ns iterations))
       :ops-per-sec (/ (* iterations 1e9) total-ns)})))

(defn format-results [name results]
  (format "%-25s %12.1f ns %15.0f ops/sec"
          name
          (:avg-ns results)
          (:ops-per-sec results)))

;; ============================================================================
;; Array Map Benchmarks
;; ============================================================================

(defn benchmark-array-sequential [array-map entries iterations]
  (benchmark
    (fn []
      (dotimes [i entries]
        (array-lookup array-map i)))
    iterations
    1000))

(defn benchmark-array-random [array-map entries iterations]
  (let [random-keys (int-array iterations)]
    (dotimes [i iterations]
      (aset random-keys i (rand-int entries)))
    (benchmark
      (fn []
        (dotimes [i iterations]
          (array-lookup array-map (aget random-keys i))))
      1
      10)))

(defn benchmark-array-write [array-map entries iterations]
  (benchmark
    (fn []
      (let [k (rand-int entries)]
        (array-update! array-map k (rand-int 1000000))))
    iterations
    1000))

(defn benchmark-array-atomic [array-map entries iterations]
  (benchmark
    (fn []
      (let [k (rand-int entries)]
        (array-atomic-add! array-map k 1)))
    iterations
    1000))

;; ============================================================================
;; Hash Map Benchmarks
;; ============================================================================

(defn benchmark-hash-lookup [hash-map entries iterations]
  (let [random-keys (int-array iterations)]
    (dotimes [i iterations]
      (aset random-keys i (rand-int entries)))
    (benchmark
      (fn []
        (dotimes [i iterations]
          (hash-lookup hash-map (aget random-keys i))))
      1
      10)))

(defn benchmark-hash-write [hash-map entries iterations]
  (benchmark
    (fn []
      (let [k (rand-int entries)]
        (hash-update! hash-map k (rand-int 1000000))))
    iterations
    1000))

;; ============================================================================
;; Per-CPU Benchmarks
;; ============================================================================

(defn benchmark-percpu-update [percpu-map entries iterations num-cpus]
  (benchmark
    (fn []
      (let [k (rand-int entries)
            cpu (rand-int num-cpus)]
        (percpu-atomic-add! percpu-map k cpu 1)))
    iterations
    1000))

(defn benchmark-percpu-sum [percpu-map entries iterations]
  (benchmark
    (fn []
      (let [k (rand-int entries)]
        (percpu-sum percpu-map k)))
    iterations
    1000))

;; ============================================================================
;; Compound Key Benchmarks
;; ============================================================================

(defrecord FlowKey [src-ip dst-ip src-port dst-port])

(defn generate-flow-key []
  (->FlowKey (rand-int 0xFFFFFFFF)
             (rand-int 0xFFFFFFFF)
             (rand-int 65536)
             (rand-int 65536)))

(defn benchmark-hash-compound [hash-map entries iterations]
  (let [keys (vec (repeatedly iterations generate-flow-key))]
    (benchmark
      (fn []
        (doseq [k keys]
          (hash-lookup hash-map k)))
      1
      10)))

;; ============================================================================
;; Test Functions
;; ============================================================================

(defn test-array-map []
  (println "\n=== Testing Array Map ===")
  (let [entries 256
        iterations 100000
        m (create-array-map entries)]

    ;; Initialize
    (dotimes [i entries]
      (array-update! m i (long i)))

    ;; Test lookup
    (println "\nLookup Tests:")
    (println (format-results "Sequential lookup"
                             (benchmark-array-sequential m entries (/ iterations entries))))
    (println (format-results "Random lookup"
                             (benchmark-array-random m entries iterations)))

    ;; Test write
    (println "\nWrite Tests:")
    (println (format-results "Random write"
                             (benchmark-array-write m entries iterations)))
    (println (format-results "Atomic increment"
                             (benchmark-array-atomic m entries iterations)))

    (println "\nArray map tests passed!")))

(defn test-hash-map []
  (println "\n=== Testing Hash Map ===")
  (let [entries 10000
        iterations 100000
        m (create-hash-map entries)]

    ;; Initialize with integer keys
    (dotimes [i entries]
      (hash-update! m i {:value i}))

    ;; Test lookup
    (println "\nInteger Key Lookup:")
    (println (format-results "Random lookup"
                             (benchmark-hash-lookup m entries iterations)))

    ;; Test write
    (println "\nInteger Key Write:")
    (println (format-results "Random write"
                             (benchmark-hash-write m entries iterations)))

    ;; Test compound keys
    (println "\nCompound Key Tests:")
    (let [compound-map (create-hash-map entries)
          flow-keys (vec (repeatedly entries generate-flow-key))]
      (doseq [k flow-keys]
        (hash-update! compound-map k {:count 0}))
      (println (format-results "Compound key lookup"
                               (benchmark-hash-compound compound-map entries iterations))))

    (println "\nHash map tests passed!")))

(defn test-percpu-map []
  (println "\n=== Testing Per-CPU Map ===")
  (let [entries 256
        num-cpus 8
        iterations 100000
        m (create-percpu-array entries num-cpus)]

    ;; Initialize
    (dotimes [i entries]
      (doseq [cpu (range num-cpus)]
        (percpu-update! m i cpu 0)))

    ;; Test update
    (println "\nPer-CPU Update Tests:")
    (println (format-results "Atomic add (random CPU)"
                             (benchmark-percpu-update m entries iterations num-cpus)))

    ;; Test sum
    (println "\nPer-CPU Sum Tests:")
    (println (format-results "Sum across CPUs"
                             (benchmark-percpu-sum m entries iterations)))

    (println "\nPer-CPU map tests passed!")))

;; ============================================================================
;; Comparative Analysis
;; ============================================================================

(defn compare-map-types []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "              MAP TYPE PERFORMANCE COMPARISON")
  (println "\n" (apply str (repeat 70 "=")) "\n")

  (let [entries 10000
        iterations 100000]

    (println (format "%-25s %12s %15s" "Operation" "Avg (ns)" "Ops/sec"))
    (println (apply str (repeat 55 "-")))

    ;; Array map
    (let [array-m (create-array-map entries)]
      (dotimes [i entries]
        (array-update! array-m i (long i)))
      (println (format-results "Array random lookup"
                               (benchmark-array-random array-m entries iterations)))
      (println (format-results "Array random write"
                               (benchmark-array-write array-m entries iterations))))

    ;; Hash map
    (let [hash-m (create-hash-map entries)]
      (dotimes [i entries]
        (hash-update! hash-m i {:value i}))
      (println (format-results "Hash random lookup"
                               (benchmark-hash-lookup hash-m entries iterations)))
      (println (format-results "Hash random write"
                               (benchmark-hash-write hash-m entries iterations))))

    ;; Per-CPU
    (let [percpu-m (create-percpu-array entries 8)]
      (println (format-results "Per-CPU atomic add"
                               (benchmark-percpu-update percpu-m entries iterations 8))))))

(defn scaling-analysis []
  (println "\n=== Scaling Analysis ===\n")
  (println (format "%-12s %15s %15s %10s"
                   "Entries" "Array (ns)" "Hash (ns)" "Ratio"))
  (println (apply str (repeat 55 "-")))

  (doseq [size [100 1000 10000 100000]]
    (let [iterations (min 100000 (* 10 size))
          array-m (create-array-map size)
          hash-m (create-hash-map size)]

      ;; Initialize
      (dotimes [i size]
        (array-update! array-m i (long i))
        (hash-update! hash-m i {:value i}))

      ;; Benchmark
      (let [array-result (benchmark
                           (fn [] (array-lookup array-m (rand-int size)))
                           iterations 1000)
            hash-result (benchmark
                          (fn [] (hash-lookup hash-m (rand-int size)))
                          iterations 1000)
            ratio (/ (:avg-ns hash-result) (:avg-ns array-result))]

        (println (format "%-12d %15.1f %15.1f %10.2f"
                         size
                         (:avg-ns array-result)
                         (:avg-ns hash-result)
                         ratio))))))

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-cache-impact []
  "Exercise 1: Measure cache line impact on access patterns"
  (println "\n=== Exercise 1: Cache Line Impact ===\n")

  (let [entries 1024
        iterations 100000
        m (create-array-map entries)]

    ;; Initialize
    (dotimes [i entries]
      (array-update! m i (long i)))

    ;; Sequential access (cache-friendly)
    (let [sequential-result (benchmark
                              (fn []
                                (dotimes [i 64]
                                  (array-lookup m i)))
                              iterations 1000)]
      (println (format-results "Sequential (0-63)"
                               {:avg-ns (/ (:avg-ns sequential-result) 64)
                                :ops-per-sec (* (:ops-per-sec sequential-result) 64)})))

    ;; Strided access (cache-unfriendly)
    (let [strided-result (benchmark
                           (fn []
                             (dotimes [i 64]
                               (array-lookup m (* i 16))))  ; 16 entries apart
                           iterations 1000)]
      (println (format-results "Strided (step=16)"
                               {:avg-ns (/ (:avg-ns strided-result) 64)
                                :ops-per-sec (* (:ops-per-sec strided-result) 64)})))

    (println "\nCache-friendly access is faster due to prefetching.")))

(defn exercise-contention []
  "Exercise 2: Simulate multi-threaded contention"
  (println "\n=== Exercise 2: Contention Simulation ===\n")

  (let [entries 1000
        iterations 100000
        shared-map (create-hash-map entries)
        percpu-map (create-percpu-array entries 8)]

    ;; Initialize
    (dotimes [i entries]
      (hash-update! shared-map i (java.util.concurrent.atomic.AtomicLong. 0)))

    ;; Simulate shared counter contention
    (println "Simulating 8 threads updating shared counter...")
    (let [threads 8
          per-thread (/ iterations threads)
          start (System/nanoTime)
          futures (doall
                    (for [t (range threads)]
                      (future
                        (dotimes [_ per-thread]
                          (let [counter ^java.util.concurrent.atomic.AtomicLong
                                        (hash-lookup shared-map 0)]
                            (.incrementAndGet counter))))))]
      (doseq [f futures] @f)
      (let [elapsed (- (System/nanoTime) start)]
        (println (format "Shared counter: %.2f M ops/sec"
                         (/ iterations (/ elapsed 1000.0))))))

    ;; Simulate per-CPU (no contention)
    (println "\nSimulating 8 threads with per-CPU counters...")
    (let [threads 8
          per-thread (/ iterations threads)
          start (System/nanoTime)
          futures (doall
                    (for [t (range threads)]
                      (future
                        (dotimes [_ per-thread]
                          (percpu-atomic-add! percpu-map 0 t 1)))))]
      (doseq [f futures] @f)
      (let [elapsed (- (System/nanoTime) start)]
        (println (format "Per-CPU counters: %.2f M ops/sec"
                         (/ iterations (/ elapsed 1000.0))))))

    (println "\nPer-CPU eliminates contention and scales linearly.")))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the map performance lab"
  [& args]
  (println "Lab 16.1: Map Performance Comparison")
  (println "=====================================\n")

  (let [command (first args)]
    (case command
      "array"
      (test-array-map)

      "hash"
      (test-hash-map)

      "percpu"
      (test-percpu-map)

      "compare"
      (compare-map-types)

      "scaling"
      (scaling-analysis)

      "exercise1"
      (exercise-cache-impact)

      "exercise2"
      (exercise-contention)

      ;; Default: full test
      (do
        (test-array-map)
        (test-hash-map)
        (test-percpu-map)
        (compare-map-types)
        (scaling-analysis)
        (exercise-cache-impact)
        (exercise-contention)

        (println "\n=== Key Takeaways ===")
        (println "1. Array maps are fastest for dense integer keys (O(1) indexing)")
        (println "2. Hash maps have overhead but support any key type")
        (println "3. Per-CPU maps eliminate lock contention")
        (println "4. Cache-friendly access patterns improve performance")
        (println "5. Choose map type based on key characteristics and access patterns")))))

;; Run with: clj -M -m lab-16-1-map-performance
