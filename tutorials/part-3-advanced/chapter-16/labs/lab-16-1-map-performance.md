# Lab 16.1: Map Performance Comparison

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Benchmark different BPF map types to understand their performance characteristics and make informed data structure decisions.

## Prerequisites

- Completed Chapter 16 reading
- Understanding of BPF map types
- Familiarity with benchmarking concepts

## Scenario

You're building a network monitoring system and need to choose the right map type for storing connection statistics. This lab helps you understand the performance trade-offs between different map types.

---

## Part 1: Setting Up the Benchmark Infrastructure

### Step 1.1: Create Mock Map Implementations

```clojure
(ns lab-16-1.map-performance
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps])
  (:import [java.util.concurrent ConcurrentHashMap]
           [java.util.concurrent.atomic AtomicLong AtomicLongArray]))

;; Mock implementations for benchmarking without root

(defrecord MockArrayMap [^AtomicLongArray storage max-entries]
  clojure.lang.ILookup
  (valAt [_ key]
    (when (< key max-entries)
      (.get storage key)))
  (valAt [this key not-found]
    (or (.valAt this key) not-found)))

(defrecord MockHashMap [^ConcurrentHashMap storage max-entries]
  clojure.lang.ILookup
  (valAt [_ key]
    (.get storage key))
  (valAt [this key not-found]
    (or (.valAt this key) not-found)))

(defn create-array-map [max-entries]
  (->MockArrayMap (AtomicLongArray. max-entries) max-entries))

(defn create-hash-map [max-entries]
  (->MockHashMap (ConcurrentHashMap. max-entries) max-entries))
```

### Step 1.2: Benchmark Utilities

```clojure
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
       :avg-ns (/ total-ns iterations)
       :ops-per-sec (/ (* iterations 1e9) total-ns)})))

(defn format-results [name results]
  (format "%-20s %12.1f ns %12.0f ops/sec"
          name
          (:avg-ns results)
          (:ops-per-sec results)))
```

---

## Part 2: Array Map Performance

### Step 2.1: Sequential Access Pattern

```clojure
(defn benchmark-array-sequential [array-map entries iterations]
  (benchmark
    (fn []
      (dotimes [i entries]
        (.valAt array-map i)))
    iterations
    1000))

(defn test-array-sequential []
  (let [entries 256
        array-map (create-array-map entries)]
    ;; Initialize
    (dotimes [i entries]
      (.set (:storage array-map) i (long i)))

    (println "\n=== Array Map - Sequential Access ===")
    (let [results (benchmark-array-sequential array-map entries 10000)]
      (println (format-results "Sequential" results))
      results)))
```

### Step 2.2: Random Access Pattern

```clojure
(defn benchmark-array-random [array-map entries iterations]
  (let [random-keys (int-array (repeatedly iterations #(rand-int entries)))]
    (benchmark
      (fn []
        (doseq [k random-keys]
          (.valAt array-map k)))
      1
      10)))

(defn test-array-random []
  (let [entries 256
        array-map (create-array-map entries)]
    (dotimes [i entries]
      (.set (:storage array-map) i (long i)))

    (println "\n=== Array Map - Random Access ===")
    (let [results (benchmark-array-random array-map entries 10000)]
      (println (format-results "Random" results))
      results)))
```

---

## Part 3: Hash Map Performance

### Step 3.1: Integer Keys

```clojure
(defn benchmark-hash-integer [hash-map entries iterations]
  (let [random-keys (int-array (repeatedly iterations #(rand-int entries)))]
    (benchmark
      (fn []
        (doseq [k random-keys]
          (.valAt hash-map k)))
      1
      10)))

(defn test-hash-integer []
  (let [entries 256
        hash-map (create-hash-map entries)]
    ;; Initialize
    (dotimes [i entries]
      (.put (:storage hash-map) i (long i)))

    (println "\n=== Hash Map - Integer Keys ===")
    (let [results (benchmark-hash-integer hash-map entries 10000)]
      (println (format-results "Integer Keys" results))
      results)))
```

### Step 3.2: Compound Keys (Simulated Tuple)

```clojure
(defrecord FlowKey [src-ip dst-ip src-port dst-port])

(defn generate-flow-key []
  (->FlowKey (rand-int 0xFFFFFFFF)
             (rand-int 0xFFFFFFFF)
             (rand-int 65536)
             (rand-int 65536)))

(defn benchmark-hash-compound [hash-map entries iterations]
  (let [keys (repeatedly iterations generate-flow-key)]
    (benchmark
      (fn []
        (doseq [k keys]
          (.valAt hash-map k)))
      1
      10)))

(defn test-hash-compound []
  (let [entries 10000
        hash-map (create-hash-map entries)
        test-keys (repeatedly entries generate-flow-key)]
    ;; Initialize
    (doseq [k test-keys]
      (.put (:storage hash-map) k (rand-int 1000000)))

    (println "\n=== Hash Map - Compound Keys ===")
    (let [results (benchmark-hash-compound hash-map entries 10000)]
      (println (format-results "Compound Keys" results))
      results)))
```

---

## Part 4: Comparative Analysis

### Step 4.1: Side-by-Side Comparison

```clojure
(defn run-all-benchmarks []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "       BPF Map Performance Comparison")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (let [results (atom {})]
    ;; Array benchmarks
    (swap! results assoc :array-seq (test-array-sequential))
    (swap! results assoc :array-rand (test-array-random))

    ;; Hash benchmarks
    (swap! results assoc :hash-int (test-hash-integer))
    (swap! results assoc :hash-compound (test-hash-compound))

    ;; Summary
    (println "\n" (apply str (repeat 60 "-")) "\n")
    (println "Summary: Array vs Hash Map")
    (println "\n")

    (let [array-rand (:array-rand @results)
          hash-int (:hash-int @results)]
      (when (and array-rand hash-int)
        (let [speedup (/ (:avg-ns hash-int) (:avg-ns array-rand))]
          (println (format "Array is %.2fx faster than Hash for integer keys" speedup)))))

    @results))
```

### Step 4.2: Scaling Analysis

```clojure
(defn scaling-analysis []
  (println "\n=== Scaling Analysis ===\n")
  (println (format "%-12s %15s %15s %10s"
                   "Entries" "Array (ns)" "Hash (ns)" "Ratio"))
  (println (apply str (repeat 55 "-")))

  (doseq [size [100 1000 10000 100000]]
    (let [array-map (create-array-map size)
          hash-map (create-hash-map size)]

      ;; Initialize
      (dotimes [i size]
        (.set (:storage array-map) i (long i))
        (.put (:storage hash-map) i (long i)))

      ;; Benchmark
      (let [iterations (min 100000 (* 10 size))
            array-results (benchmark
                           (fn [] (.valAt array-map (rand-int size)))
                           iterations 1000)
            hash-results (benchmark
                          (fn [] (.valAt hash-map (rand-int size)))
                          iterations 1000)
            ratio (/ (:avg-ns hash-results) (:avg-ns array-results))]

        (println (format "%-12d %15.1f %15.1f %10.2f"
                         size
                         (:avg-ns array-results)
                         (:avg-ns hash-results)
                         ratio))))))
```

---

## Part 5: Write Performance

### Step 5.1: Update Benchmarks

```clojure
(defn benchmark-array-write [array-map entries iterations]
  (benchmark
    (fn []
      (let [k (rand-int entries)]
        (.set (:storage array-map) k (long (rand-int 1000000)))))
    iterations
    1000))

(defn benchmark-hash-write [hash-map entries iterations]
  (benchmark
    (fn []
      (let [k (rand-int entries)]
        (.put (:storage hash-map) k (long (rand-int 1000000)))))
    iterations
    1000))

(defn test-write-performance []
  (println "\n=== Write Performance ===\n")
  (let [entries 10000
        iterations 100000
        array-map (create-array-map entries)
        hash-map (create-hash-map entries)]

    ;; Initialize
    (dotimes [i entries]
      (.set (:storage array-map) i 0)
      (.put (:storage hash-map) i 0))

    (let [array-write (benchmark-array-write array-map entries iterations)
          hash-write (benchmark-hash-write hash-map entries iterations)]

      (println (format-results "Array Write" array-write))
      (println (format-results "Hash Write" hash-write))

      {:array array-write :hash hash-write})))
```

---

## Part 6: Exercises

### Exercise 1: Cache Line Impact

Measure the impact of cache line alignment on access patterns:

```clojure
(defn exercise-cache-impact []
  ;; TODO: Compare access patterns that hit same vs different cache lines
  ;; 1. Create array with values at indices 0, 1, 2, 3 (same cache line)
  ;; 2. Create array with values at indices 0, 64, 128, 192 (different lines)
  ;; 3. Benchmark access patterns
  ;; 4. Calculate speedup from cache-friendly access
  )
```

### Exercise 2: Contention Simulation

Simulate multi-threaded contention:

```clojure
(defn exercise-contention []
  ;; TODO: Measure performance under concurrent access
  ;; 1. Create shared map
  ;; 2. Launch N threads accessing same keys
  ;; 3. Measure throughput vs thread count
  ;; 4. Compare with per-CPU simulation
  )
```

### Exercise 3: LRU Cache Behavior

Implement and benchmark LRU-like behavior:

```clojure
(defn exercise-lru-behavior []
  ;; TODO: Implement simple LRU cache
  ;; 1. Track access order
  ;; 2. Evict oldest when full
  ;; 3. Benchmark hit rate vs cache size
  ;; 4. Compare overhead of LRU tracking
  )
```

---

## Part 7: Testing Your Implementation

### Test Script

```clojure
(defn run-all-tests []
  (println "Lab 16.1: Map Performance Comparison")
  (println "=====================================\n")

  ;; Run benchmarks
  (run-all-benchmarks)

  ;; Scaling analysis
  (scaling-analysis)

  ;; Write performance
  (test-write-performance)

  (println "\n=== Recommendations ===\n")
  (println "1. Use Array maps when:")
  (println "   - Keys are dense integers (0 to N)")
  (println "   - Key range is known at compile time")
  (println "   - Maximum performance is required")
  (println)
  (println "2. Use Hash maps when:")
  (println "   - Keys are sparse or unpredictable")
  (println "   - Keys are compound (tuples, structs)")
  (println "   - Dynamic insertion/deletion needed")
  (println)
  (println "3. Use LRU Hash when:")
  (println "   - Bounded memory usage required")
  (println "   - Cache semantics desired")
  (println "   - Automatic eviction needed"))
```

---

## Summary

In this lab you learned:
- How to benchmark BPF map operations
- Performance characteristics of array vs hash maps
- Impact of key types on lookup performance
- Scaling behavior of different map types
- When to choose each map type for your use case

## Next Steps

- Try Lab 16.2 to learn about per-CPU counter systems
- Experiment with real BPF maps using `sudo`
- Profile your existing BPF programs for map bottlenecks
