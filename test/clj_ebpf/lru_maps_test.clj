(ns clj-ebpf.lru-maps-test
  "Tests for LRU (Least Recently Used) BPF maps"
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
;; LRU Hash Map Tests
;; ============================================================================

(deftest test-create-lru-hash-map
  (when (linux-with-bpf?)
    (testing "Create and use LRU hash map"
      (let [m (maps/create-lru-hash-map 10 :map-name "test_lru")]
        (try
          (is (some? m))
          (is (pos? (:fd m)))
          (is (= :lru-hash (:type m)))
          (is (= 10 (:max-entries m)))

          ;; Add some entries
          (maps/map-update m 1 100)
          (maps/map-update m 2 200)
          (maps/map-update m 3 300)

          ;; Verify lookups
          (is (= 100 (maps/map-lookup m 1)))
          (is (= 200 (maps/map-lookup m 2)))
          (is (= 300 (maps/map-lookup m 3)))
          (finally
            (maps/close-map m)))))))

(deftest test-lru-eviction
  (when (linux-with-bpf?)
    (testing "LRU eviction when exceeding max entries"
      (let [m (maps/create-lru-hash-map 10 :map-name "test_lru_evict")]
        (try
          ;; Fill the map to capacity
          (doseq [i (range 10)]
            (maps/map-update m i (* i 10)))

          ;; Verify we have entries
          (let [initial-count (maps/map-count m)]
            (is (pos? initial-count)))

          ;; Add more entries beyond capacity
          ;; The LRU entries should be evicted automatically
          (maps/map-update m 20 200)

          ;; Map should not grow beyond capacity
          (is (<= (maps/map-count m) 10))

          ;; The most recently added entry should exist
          (is (= 200 (maps/map-lookup m 20)))
          (finally
            (maps/close-map m)))))))

(deftest test-lru-basic-eviction-behavior
  (when (linux-with-bpf?)
    (testing "LRU map basic eviction behavior"
      (let [m (maps/create-lru-hash-map 3 :map-name "test_lru_access")]
        (try
          ;; Add 3 entries
          (maps/map-update m 1 100)
          (maps/map-update m 2 200)
          (maps/map-update m 3 300)

          ;; All 3 should exist
          (is (= 3 (maps/map-count m)))

          ;; Add a new entry, which should evict one entry
          (maps/map-update m 4 400)

          ;; Map should still have at most 3 entries
          (is (<= (maps/map-count m) 3))

          ;; The newest entry should exist
          (is (= 400 (maps/map-lookup m 4)))
          (finally
            (maps/close-map m)))))))

(deftest test-lru-update-preserves-entry
  (when (linux-with-bpf?)
    (testing "Updating an entry's value marks it as recently used"
      (let [m (maps/create-lru-hash-map 3 :map-name "test_lru_update")]
        (try
          ;; Add 3 entries
          (maps/map-update m 1 100)
          (maps/map-update m 2 200)
          (maps/map-update m 3 300)

          ;; Update entry 1's value
          (maps/map-update m 1 111)

          ;; Add new entries
          (maps/map-update m 4 400)
          (maps/map-update m 5 500)

          ;; Entry 1 should still exist with updated value
          (is (= 111 (maps/map-lookup m 1))
              "Updated entry should not be evicted and should have new value")
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; LRU Per-CPU Hash Map Tests
;; ============================================================================

;; NOTE: Per-CPU maps (including LRU per-CPU) are not yet fully implemented
;; KNOWN ISSUE: Per-CPU maps have different memory layout requirements
;; They store one value per CPU core, requiring special handling for:
;; - Memory allocation (value-size * num_cpus)
;; - Value serialization/deserialization across CPU arrays
;; - Proper memory alignment
;; TODO: Implement per-CPU value handling in maps.clj
;; TODO: Add create-percpu-hash-map and create-lru-percpu-hash-map tests

;; ============================================================================
;; Comparison with Regular Hash Maps
;; ============================================================================

(deftest test-lru-vs-hash-behavior
  (when (linux-with-bpf?)
    (testing "LRU maps behave differently from regular hash maps when full"
      ;; Regular hash map - update fails when full (with :noexist flag)
      (let [regular (maps/create-hash-map 3 :map-name "test_regular")]
        (try
          (maps/map-update regular 1 100)
          (maps/map-update regular 2 200)
          (maps/map-update regular 3 300)

          ;; Attempting to add beyond capacity with :noexist should fail
          (is (thrown? Exception
                      (maps/map-update regular 4 400 :flags :noexist))
              "Regular hash map rejects new entries when full")
          (finally
            (maps/close-map regular))))

      ;; LRU hash map - automatically evicts when full
      (let [lru (maps/create-lru-hash-map 3 :map-name "test_lru")]
        (try
          (maps/map-update lru 1 100)
          (maps/map-update lru 2 200)
          (maps/map-update lru 3 300)

          ;; Adding beyond capacity succeeds (evicts LRU entry)
          (maps/map-update lru 4 400)
          (is (= 400 (maps/map-lookup lru 4))
              "LRU hash map accepts new entries by evicting LRU")

          ;; Map should still have at most 3 entries
          (is (<= (maps/map-count lru) 3))
          (finally
            (maps/close-map lru)))))))
