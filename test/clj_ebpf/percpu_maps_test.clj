(ns clj-ebpf.percpu-maps-test
  "Tests for per-CPU BPF maps"
  (:require [clojure.test :refer :all]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils]))

(defn linux-with-bpf?
  "Check if we're on Linux with BPF available"
  []
  (and (= "Linux" (System/getProperty "os.name"))
       (try
         (utils/check-bpf-available)
         true
         (catch Exception _ false))))

(defn suitable-for-percpu-tests?
  "Check if system is suitable for per-CPU tests.

  Per-CPU maps with very high CPU counts (>16) can cause memory issues
  with Panama FFI on some systems. Skip tests on such systems."
  []
  (and (linux-with-bpf?)
       (<= (utils/get-cpu-count) 16)))

;; ============================================================================
;; Per-CPU Hash Map Tests
;; ============================================================================

(deftest test-create-percpu-hash-map
  (when (suitable-for-percpu-tests?)
    (testing "Create a per-CPU hash map"
      (let [m (maps/create-percpu-hash-map 100 :map-name "test_percpu_hash")
            num-cpus (utils/get-cpu-count)]
        (try
          (is (some? m))
          (is (pos? (:fd m)))
          (is (= :percpu-hash (:type m)))
          (is (= 100 (:max-entries m)))
          (is (:percpu? m))
          (is (= 4 (:percpu-value-size m)))
          ;; Total value size should be value-size * num-cpus
          (is (= (* 4 num-cpus) (:value-size m)))
          (finally
            (maps/close-map m)))))))

(deftest test-percpu-hash-basic-operations
  (when (suitable-for-percpu-tests?)
    (testing "Per-CPU hash map basic insert and lookup"
      (let [m (maps/create-percpu-hash-map 100 :map-name "test_percpu_ops")
            num-cpus (utils/get-cpu-count)]
        (try
          ;; Insert a single value (replicated to all CPUs)
          (maps/map-update m 1 100)

          ;; Lookup should return a vector of values (one per CPU)
          (let [values (maps/map-lookup m 1)]
            (is (vector? values))
            (is (= num-cpus (count values)))
            ;; All CPUs should have the same value
            (is (every? #(= 100 %) values)))

          ;; Insert per-CPU values (different value for each CPU)
          (let [percpu-values (vec (range num-cpus))]
            (maps/map-update m 2 percpu-values)

            ;; Lookup should return the per-CPU values
            (let [retrieved (maps/map-lookup m 2)]
              (is (= percpu-values retrieved))))
          (finally
            (maps/close-map m)))))))

(deftest test-percpu-hash-multiple-keys
  (when (suitable-for-percpu-tests?)
    (testing "Per-CPU hash map with multiple keys"
      (let [m (maps/create-percpu-hash-map 100 :map-name "test_percpu_multi")]
        (try
          ;; Insert multiple keys with different values
          (maps/map-update m 1 100)
          (maps/map-update m 2 200)
          (maps/map-update m 3 300)

          ;; Verify all keys can be looked up
          (is (every? #(= 100 %) (maps/map-lookup m 1)))
          (is (every? #(= 200 %) (maps/map-lookup m 2)))
          (is (every? #(= 300 %) (maps/map-lookup m 3)))
          (finally
            (maps/close-map m)))))))

(deftest test-percpu-hash-delete
  (when (suitable-for-percpu-tests?)
    (testing "Delete from per-CPU hash map"
      (let [m (maps/create-percpu-hash-map 100 :map-name "test_percpu_delete")]
        (try
          ;; Insert and verify
          (maps/map-update m 1 100)
          (is (some? (maps/map-lookup m 1)))

          ;; Delete
          (maps/map-delete m 1)

          ;; Should not be found
          (is (nil? (maps/map-lookup m 1)))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Per-CPU Array Map Tests
;; ============================================================================

(deftest test-create-percpu-array-map
  (when (suitable-for-percpu-tests?)
    (testing "Create a per-CPU array map"
      (let [m (maps/create-percpu-array-map 10 :map-name "test_percpu_array")
            num-cpus (utils/get-cpu-count)]
        (try
          (is (some? m))
          (is (pos? (:fd m)))
          (is (= :percpu-array (:type m)))
          (is (= 10 (:max-entries m)))
          (is (:percpu? m))
          (is (= 4 (:percpu-value-size m)))
          (is (= (* 4 num-cpus) (:value-size m)))
          (finally
            (maps/close-map m)))))))

(deftest test-percpu-array-operations
  (when (suitable-for-percpu-tests?)
    (testing "Per-CPU array map operations"
      (let [m (maps/create-percpu-array-map 10 :map-name "test_percpu_array_ops")
            num-cpus (utils/get-cpu-count)]
        (try
          ;; Array maps are initialized with zeros
          (let [initial-values (maps/map-lookup m 0)]
            (is (= num-cpus (count initial-values)))
            (is (every? zero? initial-values)))

          ;; Update index 0
          (maps/map-update m 0 42)
          (is (every? #(= 42 %) (maps/map-lookup m 0)))

          ;; Update index 5 with per-CPU values
          (let [percpu-values (vec (map #(* % 10) (range num-cpus)))]
            (maps/map-update m 5 percpu-values)
            (is (= percpu-values (maps/map-lookup m 5))))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Per-CPU LRU Hash Map Tests
;; ============================================================================

(deftest test-create-lru-percpu-hash-map
  (when (suitable-for-percpu-tests?)
    (testing "Create a per-CPU LRU hash map"
      (let [m (maps/create-lru-percpu-hash-map 10 :map-name "test_lru_percpu")
            num-cpus (utils/get-cpu-count)]
        (try
          (is (some? m))
          (is (pos? (:fd m)))
          (is (= :lru-percpu-hash (:type m)))
          (is (= 10 (:max-entries m)))
          (is (:percpu? m))
          (finally
            (maps/close-map m)))))))

(deftest test-lru-percpu-operations
  (when (suitable-for-percpu-tests?)
    (testing "Per-CPU LRU hash map operations"
      (let [m (maps/create-lru-percpu-hash-map 3 :map-name "test_lru_percpu_ops")]
        (try
          ;; Fill to capacity
          (maps/map-update m 1 100)
          (maps/map-update m 2 200)
          (maps/map-update m 3 300)

          ;; Verify all present
          (is (every? #(= 100 %) (maps/map-lookup m 1)))
          (is (every? #(= 200 %) (maps/map-lookup m 2)))
          (is (every? #(= 300 %) (maps/map-lookup m 3)))

          ;; Add beyond capacity (should evict LRU entry)
          (maps/map-update m 4 400)

          ;; Map should not exceed capacity
          (is (<= (maps/map-count m) 3))

          ;; Newest entry should exist
          (is (some? (maps/map-lookup m 4)))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Aggregation Helper Tests
;; ============================================================================

(deftest test-percpu-sum
  (testing "Sum per-CPU values"
    (let [values [10 20 30 40]]
      (is (= 100 (maps/percpu-sum values))))))

(deftest test-percpu-max
  (testing "Maximum per-CPU value"
    (let [values [10 50 30 40]]
      (is (= 50 (maps/percpu-max values))))))

(deftest test-percpu-min
  (testing "Minimum per-CPU value"
    (let [values [10 50 5 40]]
      (is (= 5 (maps/percpu-min values))))))

(deftest test-percpu-avg
  (testing "Average per-CPU value"
    (let [values [10 20 30 40]]
      (is (= 25 (maps/percpu-avg values))))))

(deftest test-percpu-aggregation-with-map
  (when (suitable-for-percpu-tests?)
    (testing "Aggregate values from per-CPU map"
      (let [m (maps/create-percpu-hash-map 100 :map-name "test_percpu_agg")
            num-cpus (utils/get-cpu-count)]
        (try
          ;; Insert per-CPU values
          (let [percpu-values (vec (repeat num-cpus 10))]
            (maps/map-update m 1 percpu-values)

            ;; Lookup and aggregate
            (let [values (maps/map-lookup m 1)]
              (is (= (* 10 num-cpus) (maps/percpu-sum values)))
              (is (= 10 (maps/percpu-max values)))
              (is (= 10 (maps/percpu-min values)))
              (is (= 10 (maps/percpu-avg values)))))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Serialization Helper Tests
;; ============================================================================

(deftest test-percpu-serialization
  (testing "Per-CPU value serialization and deserialization"
    (let [num-cpus 4
          values [100 200 300 400]
          value-size 4]
      ;; Serialize
      (let [bytes (utils/percpu-values->bytes values utils/int->bytes value-size :num-cpus num-cpus)]
        (is (= (* value-size num-cpus) (alength bytes)))

        ;; Deserialize
        (let [deserialized (utils/bytes->percpu-values bytes utils/bytes->int value-size :num-cpus num-cpus)]
          (is (= values deserialized)))))))

(deftest test-percpu-serialization-single-value
  (testing "Per-CPU serialization with single value (replicate)"
    (let [num-cpus 4
          value 42
          value-size 4]
      ;; Serialize single value (should replicate)
      (let [bytes (utils/percpu-values->bytes value utils/int->bytes value-size :num-cpus num-cpus)]
        (is (= (* value-size num-cpus) (alength bytes)))

        ;; Deserialize - all values should be the same
        (let [deserialized (utils/bytes->percpu-values bytes utils/bytes->int value-size :num-cpus num-cpus)]
          (is (= num-cpus (count deserialized)))
          (is (every? #(= 42 %) deserialized)))))))

;; ============================================================================
;; Edge Cases
;; ============================================================================

(deftest test-percpu-map-iteration
  (when (suitable-for-percpu-tests?)
    (testing "Iterate over per-CPU map entries"
      (let [m (maps/create-percpu-hash-map 100 :map-name "test_percpu_iter")]
        (try
          ;; Insert some entries
          (doseq [i (range 5)]
            (maps/map-update m i (* i 10)))

          ;; Iterate and verify
          (let [entries (maps/map-entries m)]
            (is (= 5 (count entries)))
            (doseq [[k v] entries]
              ;; Each value should be a vector
              (is (vector? v))
              (is (every? #(= (* k 10) %) v))))
          (finally
            (maps/close-map m)))))))

(deftest test-cpu-count-detection
  (testing "CPU count detection"
    (let [cpu-count (utils/get-cpu-count)]
      (is (pos? cpu-count))
      (is (integer? cpu-count))
      (println "Detected" cpu-count "CPUs"))))
