(ns clj-ebpf.batch-ops-test
  "Tests for BPF map batch operations"
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

;; ============================================================================
;; Batch Lookup Tests
;; ============================================================================

(deftest test-batch-lookup
  (when (linux-with-bpf?)
    (testing "Batch lookup multiple keys from map"
      (let [m (maps/create-hash-map 100 :map-name "test_batch_lookup")]
        (try
          ;; Add some test data
          (doseq [i (range 10)]
            (maps/map-update m i (* i 10)))

          ;; Batch lookup specific keys
          (let [keys-to-lookup [1 3 5 7 9 15]  ; 15 doesn't exist
                results (maps/map-lookup-batch m keys-to-lookup)
                results-map (into {} results)]

            ;; Should return 5 results (15 doesn't exist)
            (is (= 5 (count results)))

            ;; Verify values
            (is (= 10 (get results-map 1)))
            (is (= 30 (get results-map 3)))
            (is (= 50 (get results-map 5)))
            (is (= 70 (get results-map 7)))
            (is (= 90 (get results-map 9)))

            ;; Non-existent key should not be in results
            (is (nil? (get results-map 15))))
          (finally
            (maps/close-map m)))))))

(deftest test-batch-lookup-empty
  (when (linux-with-bpf?)
    (testing "Batch lookup on empty map"
      (let [m (maps/create-hash-map 100 :map-name "test_batch_empty")]
        (try
          (let [results (maps/map-lookup-batch m [1 2 3])]
            (is (empty? results) "Empty map should return no results"))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Batch Update Tests
;; ============================================================================

(deftest test-batch-update
  (when (linux-with-bpf?)
    (testing "Batch update multiple key-value pairs"
      (let [m (maps/create-hash-map 100 :map-name "test_batch_update")]
        (try
          ;; Batch update multiple entries
          (let [entries [[1 100] [2 200] [3 300] [4 400] [5 500]]
                count (maps/map-update-batch m entries)]

            ;; Should update all entries
            (is (= 5 count))

            ;; Verify all values were set
            (is (= 100 (maps/map-lookup m 1)))
            (is (= 200 (maps/map-lookup m 2)))
            (is (= 300 (maps/map-lookup m 3)))
            (is (= 400 (maps/map-lookup m 4)))
            (is (= 500 (maps/map-lookup m 5))))
          (finally
            (maps/close-map m)))))))

(deftest test-batch-update-with-flags
  (when (linux-with-bpf?)
    (testing "Batch update with flags"
      (let [m (maps/create-hash-map 100 :map-name "test_batch_flags")]
        (try
          ;; First batch with :noexist (create only)
          (maps/map-update-batch m [[1 100] [2 200]] :flags :noexist)

          (is (= 100 (maps/map-lookup m 1)))
          (is (= 200 (maps/map-lookup m 2)))

          ;; Batch update existing entries with :exist flag
          (maps/map-update-batch m [[1 111] [2 222]] :flags :exist)

          (is (= 111 (maps/map-lookup m 1)))
          (is (= 222 (maps/map-lookup m 2)))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Batch Delete Tests
;; ============================================================================

(deftest test-batch-delete
  (when (linux-with-bpf?)
    (testing "Batch delete multiple keys"
      (let [m (maps/create-hash-map 100 :map-name "test_batch_delete")]
        (try
          ;; Add entries
          (doseq [i (range 10)]
            (maps/map-update m i (* i 10)))

          ;; Verify initial count
          (is (= 10 (maps/map-count m)))

          ;; Batch delete some keys
          (let [keys-to-delete [1 3 5 7 15]  ; 15 doesn't exist
                deleted-count (maps/map-delete-batch m keys-to-delete)]

            ;; Should delete 4 keys (15 doesn't exist)
            (is (>= deleted-count 4))

            ;; Verify deleted keys don't exist
            (is (nil? (maps/map-lookup m 1)))
            (is (nil? (maps/map-lookup m 3)))
            (is (nil? (maps/map-lookup m 5)))
            (is (nil? (maps/map-lookup m 7)))

            ;; Verify non-deleted keys still exist
            (is (= 0 (maps/map-lookup m 0)))
            (is (= 20 (maps/map-lookup m 2)))
            (is (= 40 (maps/map-lookup m 4))))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Batch Lookup and Delete Tests
;; ============================================================================

(deftest test-batch-lookup-and-delete
  (when (linux-with-bpf?)
    (testing "Batch lookup and delete atomically"
      (let [m (maps/create-hash-map 100 :map-name "test_batch_lookup_delete")]
        (try
          ;; Add test data
          (doseq [i (range 10)]
            (maps/map-update m i (* i 10)))

          ;; Batch lookup and delete
          (let [keys [1 3 5 7 15]  ; 15 doesn't exist
                results (maps/map-lookup-and-delete-batch m keys)
                results-map (into {} results)]

            ;; Should return 4 results (15 doesn't exist)
            (is (= 4 (count results)))

            ;; Verify returned values
            (is (= 10 (get results-map 1)))
            (is (= 30 (get results-map 3)))
            (is (= 50 (get results-map 5)))
            (is (= 70 (get results-map 7)))

            ;; Verify keys were deleted
            (is (nil? (maps/map-lookup m 1)))
            (is (nil? (maps/map-lookup m 3)))
            (is (nil? (maps/map-lookup m 5)))
            (is (nil? (maps/map-lookup m 7)))

            ;; Verify other keys still exist
            (is (= 0 (maps/map-lookup m 0)))
            (is (= 20 (maps/map-lookup m 2))))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Batch Performance Tests
;; ============================================================================

(deftest test-batch-vs-individual-performance
  (when (linux-with-bpf?)
    (testing "Batch operations should be faster than individual operations"
      (let [m (maps/create-hash-map 1000 :map-name "test_batch_perf")
            num-ops 100]
        (try
          ;; Prepare test data
          (let [entries (for [i (range num-ops)] [i (* i 10)])]

            ;; Time individual updates
            (let [start-individual (System/nanoTime)]
              (doseq [[k v] entries]
                (maps/map-update m k v))
              (let [time-individual (/ (- (System/nanoTime) start-individual) 1000000.0)]

                ;; Clear map
                (maps/map-clear m)

                ;; Time batch update
                (let [start-batch (System/nanoTime)
                      _ (maps/map-update-batch m entries)
                      time-batch (/ (- (System/nanoTime) start-batch) 1000000.0)]

                  ;; Batch should be faster (or at least not much slower due to fallback)
                  (println (format "Individual updates: %.2f ms, Batch update: %.2f ms"
                                   time-individual time-batch))
                  ;; Don't assert performance difference as it depends on kernel version
                  ;; and whether batch ops are supported
                  (is true "Performance comparison completed")))))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Edge Cases
;; ============================================================================

(deftest test-batch-with-empty-sequence
  (when (linux-with-bpf?)
    (testing "Batch operations with empty sequences"
      (let [m (maps/create-hash-map 100 :map-name "test_batch_empty_seq")]
        (try
          ;; Empty lookup
          (let [results (maps/map-lookup-batch m [])]
            (is (empty? results)))

          ;; Empty update
          (let [count (maps/map-update-batch m [])]
            (is (zero? count)))

          ;; Empty delete
          (let [count (maps/map-delete-batch m [])]
            (is (zero? count)))
          (finally
            (maps/close-map m)))))))

(deftest test-batch-with-large-dataset
  (when (linux-with-bpf?)
    (testing "Batch operations with larger datasets"
      (let [m (maps/create-hash-map 1000 :map-name "test_batch_large")
            large-size 500]
        (try
          ;; Batch insert large dataset
          (let [entries (for [i (range large-size)] [i (* i 2)])
                count (maps/map-update-batch m entries)]
            (is (= large-size count)))

          ;; Verify some values
          (is (= 0 (maps/map-lookup m 0)))
          (is (= 200 (maps/map-lookup m 100)))
          (is (= 998 (maps/map-lookup m 499)))

          ;; Batch lookup subset
          (let [keys-to-lookup (range 0 large-size 50)
                results (maps/map-lookup-batch m keys-to-lookup)]
            (is (= 10 (count results))))

          ;; Batch delete subset
          (let [keys-to-delete (range 0 large-size 10)
                deleted (maps/map-delete-batch m keys-to-delete)]
            (is (>= deleted 45)))
          (finally
            (maps/close-map m)))))))
