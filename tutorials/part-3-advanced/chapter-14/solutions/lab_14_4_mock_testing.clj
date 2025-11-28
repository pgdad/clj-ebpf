(ns lab-14-4-mock-testing
  "Lab 14.4: Mock Testing Infrastructure

   This solution demonstrates:
   - Mock BPF syscall layer for unprivileged testing
   - In-memory map simulation
   - Test fixtures and utilities
   - Failure injection for error path testing
   - Fast unit testing without kernel dependencies

   Note: Real mock testing would intercept BPF syscalls.
   This solution provides a complete simulation layer.

   Run with: clojure -M -m lab-14-4-mock-testing test"
  (:require [clj-ebpf.core :as ebpf]
            [clojure.test :as t :refer [deftest testing is are use-fixtures]]
            [clojure.string :as str])
  (:import [java.util.concurrent ConcurrentHashMap]
           [java.util.concurrent.atomic AtomicLong AtomicInteger]
           [java.nio ByteBuffer ByteOrder]
           [java.util Arrays]))

;;; ============================================================================
;;; Part 1: Mock Mode Control
;;; ============================================================================

(def ^:dynamic *mock-enabled* false)
(def ^:dynamic *mock-failures* {})
(def ^:dynamic *failure-counts* (atom {}))

(defmacro with-mock-bpf
  "Execute body with mock BPF infrastructure"
  [& body]
  `(binding [*mock-enabled* true
             *mock-failures* {}
             *failure-counts* (atom {})]
     ~@body))

(defmacro with-mock-failure
  "Execute body with injected failures"
  [operation failure-spec & body]
  `(binding [*mock-enabled* true
             *mock-failures* {~operation ~failure-spec}
             *failure-counts* (atom {})]
     ~@body))

(defmacro with-mock-failures
  "Execute body with multiple injected failures"
  [failures-map & body]
  `(binding [*mock-enabled* true
             *mock-failures* ~failures-map
             *failure-counts* (atom {})]
     ~@body))

;;; ============================================================================
;;; Part 2: Mock Map Implementation
;;; ============================================================================

(defrecord MockMap [map-type key-size value-size max-entries data access-times fd])

(def mock-map-counter (AtomicLong. 1000))
(def mock-maps (ConcurrentHashMap.))

(defn create-mock-map
  "Create a mock BPF map"
  [{:keys [map-type key-size value-size max-entries]
    :or {map-type :hash key-size 4 value-size 8 max-entries 100}}]
  (let [fd (.incrementAndGet mock-map-counter)
        mock-map (->MockMap map-type key-size value-size max-entries
                           (ConcurrentHashMap.) (ConcurrentHashMap.) fd)]
    (.put mock-maps fd mock-map)
    mock-map))

(defn get-mock-map [fd]
  (.get mock-maps fd))

(defn destroy-mock-map [mock-map]
  (.remove mock-maps (:fd mock-map)))

(defn clear-all-mock-maps []
  (.clear mock-maps))

;;; ============================================================================
;;; Part 3: Failure Injection
;;; ============================================================================

(def errno-codes
  {:eperm 1
   :enoent 2
   :esrch 3
   :eintr 4
   :eio 5
   :enxio 6
   :ebadf 9
   :eagain 11
   :enomem 12
   :eacces 13
   :efault 14
   :ebusy 16
   :eexist 17
   :einval 22
   :enospc 28
   :enotsupp 95})

(defn check-for-failure
  "Check if a failure should be injected for this operation"
  [operation]
  (when-let [failure-spec (get *mock-failures* operation)]
    (let [count-key operation
          current-count (get @*failure-counts* count-key 0)]
      (cond
        ;; Permanent failure
        (:permanent failure-spec)
        (throw (ex-info (format "Mock %s failure: %s"
                               (name operation)
                               (name (:errno failure-spec)))
                       {:errno (get errno-codes (:errno failure-spec) 1)
                        :operation operation}))

        ;; Transient failure (limited count)
        (and (:count failure-spec) (< current-count (:count failure-spec)))
        (do
          (swap! *failure-counts* update count-key (fnil inc 0))
          (throw (ex-info (format "Mock %s failure: %s (transient %d/%d)"
                                 (name operation)
                                 (name (:errno failure-spec))
                                 (inc current-count)
                                 (:count failure-spec))
                         {:errno (get errno-codes (:errno failure-spec) 1)
                          :operation operation
                          :transient true
                          :count (inc current-count)
                          :max-count (:count failure-spec)})))))))

;;; ============================================================================
;;; Part 4: Mock Map Operations
;;; ============================================================================

(defn normalize-key
  "Normalize key to vector for consistent comparison"
  [key-bytes]
  (cond
    (vector? key-bytes) key-bytes
    (bytes? key-bytes) (vec key-bytes)
    (instance? java.nio.ByteBuffer key-bytes)
    (let [arr (byte-array (.remaining ^ByteBuffer key-bytes))]
      (.get ^ByteBuffer key-bytes arr)
      (vec arr))
    :else (vec (byte-array [(bit-and key-bytes 0xFF)]))))

(defn mock-map-lookup
  "Lookup value in mock map"
  [mock-map key-bytes]
  (check-for-failure :map-lookup)
  (let [key (normalize-key key-bytes)
        data (:data mock-map)]
    ;; Update access time for LRU
    (when (= :lru-hash (:map-type mock-map))
      (.put ^ConcurrentHashMap (:access-times mock-map) key (System/nanoTime)))
    ;; Return value
    (when-let [val (.get ^ConcurrentHashMap data key)]
      (byte-array val))))

(defn mock-map-update
  "Update/insert value in mock map"
  [mock-map key-bytes val-bytes]
  (check-for-failure :map-update)
  (let [key (normalize-key key-bytes)
        val (vec val-bytes)
        data (:data mock-map)
        current-size (.size ^ConcurrentHashMap data)]

    ;; Check if key already exists
    (if (.containsKey ^ConcurrentHashMap data key)
      ;; Update existing
      (do
        (.put ^ConcurrentHashMap data key val)
        (.put ^ConcurrentHashMap (:access-times mock-map) key (System/nanoTime))
        true)

      ;; Insert new - check capacity
      (if (>= current-size (:max-entries mock-map))
        ;; Handle based on map type
        (case (:map-type mock-map)
          ;; LRU: evict oldest
          :lru-hash
          (let [access-times (:access-times mock-map)
                oldest-key (first (sort-by #(.get ^ConcurrentHashMap access-times %)
                                          (keys data)))]
            (.remove ^ConcurrentHashMap data oldest-key)
            (.remove ^ConcurrentHashMap access-times oldest-key)
            (.put ^ConcurrentHashMap data key val)
            (.put ^ConcurrentHashMap access-times key (System/nanoTime))
            true)

          ;; Other types: return error
          (throw (ex-info "Map full" {:errno (:enospc errno-codes)
                                     :operation :map-update})))

        ;; Have space, insert
        (do
          (.put ^ConcurrentHashMap data key val)
          (.put ^ConcurrentHashMap (:access-times mock-map) key (System/nanoTime))
          true)))))

(defn mock-map-delete
  "Delete entry from mock map"
  [mock-map key-bytes]
  (check-for-failure :map-delete)
  (let [key (normalize-key key-bytes)
        data (:data mock-map)]
    (if (.containsKey ^ConcurrentHashMap data key)
      (do
        (.remove ^ConcurrentHashMap data key)
        (.remove ^ConcurrentHashMap (:access-times mock-map) key)
        true)
      (throw (ex-info "Key not found" {:errno (:enoent errno-codes)
                                      :operation :map-delete})))))

(defn mock-map-get-all
  "Get all entries from mock map"
  [mock-map]
  (into {} (for [[k v] (:data mock-map)]
             [k (byte-array v)])))

(defn mock-map-clear
  "Clear all entries in mock map"
  [mock-map]
  (.clear ^ConcurrentHashMap (:data mock-map))
  (.clear ^ConcurrentHashMap (:access-times mock-map))
  true)

(defn mock-map-size
  "Get number of entries in mock map"
  [mock-map]
  (.size ^ConcurrentHashMap (:data mock-map)))

;;; ============================================================================
;;; Part 5: Test Utilities
;;; ============================================================================

(defn make-key
  "Create a key byte array"
  ([value] (make-key value 4))
  ([value size]
   (let [buf (ByteBuffer/allocate size)]
     (.order buf ByteOrder/LITTLE_ENDIAN)
     (case size
       4 (.putInt buf (int value))
       8 (.putLong buf (long value))
       (dotimes [i size]
         (.put buf (byte (bit-and (bit-shift-right value (* 8 i)) 0xFF)))))
     (.array buf))))

(defn make-value
  "Create a value byte array"
  ([value] (make-value value 8))
  ([value size]
   (let [buf (ByteBuffer/allocate size)]
     (.order buf ByteOrder/LITTLE_ENDIAN)
     (case size
       4 (.putInt buf (int value))
       8 (.putLong buf (long value))
       (dotimes [i size]
         (.put buf (byte (bit-and (bit-shift-right value (* 8 i)) 0xFF)))))
     (.array buf))))

(defn value->long
  "Convert byte array value to long"
  [bytes]
  (when bytes
    (let [buf (ByteBuffer/wrap bytes)]
      (.order buf ByteOrder/LITTLE_ENDIAN)
      (if (>= (count bytes) 8)
        (.getLong buf)
        (.getInt buf)))))

(defn bytes-equal?
  "Check if two byte arrays are equal"
  [a b]
  (Arrays/equals ^bytes a ^bytes b))

(defn random-key
  "Generate random key"
  [size]
  (let [arr (byte-array size)]
    (dotimes [i size]
      (aset-byte arr i (unchecked-byte (rand-int 256))))
    arr))

(defn random-value
  "Generate random value"
  [size]
  (random-key size))

;;; ============================================================================
;;; Part 6: Test Fixtures
;;; ============================================================================

(defn mock-fixture
  "Test fixture that enables mock mode"
  [f]
  (with-mock-bpf
    (try
      (f)
      (finally
        (clear-all-mock-maps)))))

(defmacro with-temp-map
  "Create a temporary mock map for testing"
  [[name config] & body]
  `(let [~name (create-mock-map ~config)]
     (try
       ~@body
       (finally
         (destroy-mock-map ~name)))))

;;; ============================================================================
;;; Part 7: Performance Measurement
;;; ============================================================================

(defn benchmark-op
  "Benchmark an operation"
  [iterations op-fn]
  (let [times (atom [])]
    (dotimes [_ iterations]
      (let [start (System/nanoTime)]
        (op-fn)
        (swap! times conj (- (System/nanoTime) start))))
    (let [sorted-times (sort @times)]
      {:min (first sorted-times)
       :max (last sorted-times)
       :mean (double (/ (reduce + sorted-times) (count sorted-times)))
       :median (nth sorted-times (quot (count sorted-times) 2))
       :samples iterations})))

(defn format-ns
  "Format nanoseconds for display"
  [ns]
  (cond
    (< ns 1000) (format "%.0f ns" (double ns))
    (< ns 1000000) (format "%.2f µs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.2f ms" (/ ns 1000000.0))
    :else (format "%.2f s" (/ ns 1000000000.0))))

;;; ============================================================================
;;; Part 8: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 14.4 Tests ===\n")

  ;; Test 1: Basic mock map operations
  (println "Test 1: Basic Mock Map Operations")
  (with-mock-bpf
    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (let [key (make-key 1)
            val (make-value 42)]
        ;; Insert
        (mock-map-update m key val)
        ;; Lookup
        (let [result (mock-map-lookup m key)]
          (assert (= 42 (value->long result)) "Should read back 42"))
        ;; Delete
        (mock-map-delete m key)
        (assert (nil? (mock-map-lookup m key)) "Should be deleted"))))
  (println "  Insert, lookup, delete all work")
  (println "  PASSED")

  ;; Test 2: Map capacity limits
  (println "\nTest 2: Map Capacity Limits (Hash Map)")
  (with-mock-bpf
    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 3}]
      ;; Fill map
      (mock-map-update m (make-key 1) (make-value 10))
      (mock-map-update m (make-key 2) (make-value 20))
      (mock-map-update m (make-key 3) (make-value 30))
      ;; Should fail on 4th entry
      (let [threw (atom false)]
        (try
          (mock-map-update m (make-key 4) (make-value 40))
          (catch Exception e
            (reset! threw true)
            (assert (= (:enospc errno-codes) (:errno (ex-data e))) "Should be ENOSPC")))
        (assert @threw "Should throw on overflow"))))
  (println "  Hash map correctly rejects overflow")
  (println "  PASSED")

  ;; Test 3: LRU eviction
  (println "\nTest 3: LRU Map Eviction")
  (with-mock-bpf
    (with-temp-map [m {:map-type :lru-hash :key-size 4 :value-size 8 :max-entries 3}]
      ;; Fill map
      (mock-map-update m (make-key 1) (make-value 10))
      (Thread/sleep 10)
      (mock-map-update m (make-key 2) (make-value 20))
      (Thread/sleep 10)
      (mock-map-update m (make-key 3) (make-value 30))
      ;; Access key 1 to make it recent
      (mock-map-lookup m (make-key 1))
      (Thread/sleep 10)
      ;; Add key 4 - should evict key 2 (LRU)
      (mock-map-update m (make-key 4) (make-value 40))
      ;; Key 1 should still exist
      (assert (mock-map-lookup m (make-key 1)) "Key 1 should exist")
      ;; Key 2 should be evicted
      (assert (nil? (mock-map-lookup m (make-key 2))) "Key 2 should be evicted")))
  (println "  LRU eviction works correctly")
  (println "  PASSED")

  ;; Test 4: Transient failure injection
  (println "\nTest 4: Transient Failure Injection")
  (with-mock-failure :map-lookup {:errno :eagain :count 2}
    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (let [key (make-key 1)
            val (make-value 100)]
        (mock-map-update m key val)
        ;; First two lookups should fail
        (let [fail1 (try (mock-map-lookup m key) nil (catch Exception _ true))
              fail2 (try (mock-map-lookup m key) nil (catch Exception _ true))
              ;; Third should succeed
              result (mock-map-lookup m key)]
          (assert fail1 "First lookup should fail")
          (assert fail2 "Second lookup should fail")
          (assert (= 100 (value->long result)) "Third lookup should succeed")))))
  (println "  Transient failures work (2 failures then success)")
  (println "  PASSED")

  ;; Test 5: Permanent failure injection
  (println "\nTest 5: Permanent Failure Injection")
  (with-mock-failure :map-update {:errno :eperm :permanent true}
    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (let [key (make-key 1)
            val (make-value 100)
            threw (atom false)]
        (try
          (mock-map-update m key val)
          (catch Exception e
            (reset! threw true)
            (assert (= (:eperm errno-codes) (:errno (ex-data e))) "Should be EPERM")))
        (assert @threw "Should throw on every attempt"))))
  (println "  Permanent failures work")
  (println "  PASSED")

  ;; Test 6: Multiple map operations
  (println "\nTest 6: Multiple Maps")
  (with-mock-bpf
    (with-temp-map [hash-map {:map-type :hash :key-size 4 :value-size 8 :max-entries 50}]
      (with-temp-map [array-map {:map-type :array :key-size 4 :value-size 8 :max-entries 10}]
        (mock-map-update hash-map (make-key 1) (make-value 100))
        (mock-map-update array-map (make-key 0) (make-value 200))
        (assert (= 100 (value->long (mock-map-lookup hash-map (make-key 1)))))
        (assert (= 200 (value->long (mock-map-lookup array-map (make-key 0))))))))
  (println "  Multiple maps work independently")
  (println "  PASSED")

  ;; Test 7: Key normalization
  (println "\nTest 7: Key Normalization")
  (with-mock-bpf
    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (let [key-arr (make-key 42)
            key-vec (vec key-arr)
            val (make-value 999)]
        ;; Insert with array
        (mock-map-update m key-arr val)
        ;; Lookup with vector should work
        (assert (= 999 (value->long (mock-map-lookup m key-vec)))
                "Should find with vector key"))))
  (println "  Key normalization (array/vector) works")
  (println "  PASSED")

  ;; Test 8: Benchmark mock performance
  (println "\nTest 8: Mock Performance Benchmark")
  (with-mock-bpf
    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 10000}]
      (let [stats (benchmark-op 1000
                   (fn []
                     (let [key (random-key 4)
                           val (random-value 8)]
                       (mock-map-update m key val))))]
        (println (format "  Mean: %s, Min: %s, Max: %s"
                        (format-ns (:mean stats))
                        (format-ns (:min stats))
                        (format-ns (:max stats))))
        ;; Mock should be fast (< 1ms per operation)
        (assert (< (:mean stats) 1000000) "Mock ops should be < 1ms"))))
  (println "  PASSED")

  (println "\n=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 9: Example Application Logic Tests
;;; ============================================================================

(defn rate-limiter-check
  "Example: Rate limiter logic using mock map"
  [rate-map client-id max-requests]
  (let [key (make-key client-id)
        current (mock-map-lookup rate-map key)]
    (if (nil? current)
      ;; First request
      (do
        (mock-map-update rate-map key (make-value 1))
        :allow)
      ;; Check count
      (let [count (value->long current)]
        (if (>= count max-requests)
          :deny
          (do
            (mock-map-update rate-map key (make-value (inc count)))
            :allow))))))

(defn test-rate-limiter
  "Test rate limiter logic"
  []
  (println "\n=== Rate Limiter Logic Test ===\n")
  (with-mock-bpf
    (with-temp-map [rate-map {:map-type :hash :key-size 4 :value-size 8 :max-entries 1000}]
      (let [client-id 12345
            max-requests 5]
        ;; First 5 should be allowed
        (println "Testing first 5 requests:")
        (dotimes [i 5]
          (let [result (rate-limiter-check rate-map client-id max-requests)]
            (println (format "  Request %d: %s" (inc i) (name result)))
            (assert (= :allow result))))
        ;; 6th should be denied
        (println "Testing 6th request:")
        (let [result (rate-limiter-check rate-map client-id max-requests)]
          (println (format "  Request 6: %s" (name result)))
          (assert (= :deny result)))
        (println "\nRate limiter test PASSED")))))

;;; ============================================================================
;;; Part 10: Demo
;;; ============================================================================

(defn run-demo
  "Run interactive demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 14.4: Mock Testing Infrastructure")
  (println (str/join "" (repeat 60 "=")) "\n")

  (println "This lab demonstrates mock BPF testing without CAP_BPF.\n")

  ;; Show basic usage
  (println "=== Basic Mock Map Usage ===\n")
  (with-mock-bpf
    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (println "Created mock hash map (max 100 entries)")

      (println "\nInserting key=1, value=42...")
      (mock-map-update m (make-key 1) (make-value 42))

      (println "Looking up key=1...")
      (let [result (mock-map-lookup m (make-key 1))]
        (println (format "  Result: %d" (value->long result))))

      (println "\nInserting key=2, value=100...")
      (mock-map-update m (make-key 2) (make-value 100))

      (println "Map size:" (mock-map-size m))))

  ;; Show failure injection
  (println "\n=== Failure Injection Demo ===\n")
  (println "Injecting 2 transient EAGAIN failures on lookup...")
  (with-mock-failure :map-lookup {:errno :eagain :count 2}
    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (mock-map-update m (make-key 1) (make-value 42))
      (dotimes [i 4]
        (let [result (try
                       (mock-map-lookup m (make-key 1))
                       (format "Success! Value=%d" (value->long (mock-map-lookup m (make-key 1))))
                       (catch Exception e
                         (format "Failed: %s" (.getMessage e))))]
          (println (format "  Attempt %d: %s" (inc i) result))))))

  ;; Test application logic
  (test-rate-limiter)

  ;; Performance benchmark
  (println "\n=== Performance Benchmark ===\n")
  (with-mock-bpf
    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 10000}]
      (let [insert-stats (benchmark-op 1000
                          (fn []
                            (mock-map-update m (random-key 4) (random-value 8))))]
        (println "Insert performance (1000 ops):")
        (println (format "  Min: %s" (format-ns (:min insert-stats))))
        (println (format "  Max: %s" (format-ns (:max insert-stats))))
        (println (format "  Mean: %s" (format-ns (:mean insert-stats))))
        (println (format "  Median: %s" (format-ns (:median insert-stats))))))))

;;; ============================================================================
;;; Part 11: Main
;;; ============================================================================

(defn -main
  "Main entry point"
  [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      "rate-limiter" (test-rate-limiter)
      "benchmark" (with-mock-bpf
                    (with-temp-map [m {:map-type :hash :key-size 4 :value-size 8 :max-entries 10000}]
                      (let [n (Integer/parseInt (or (second args) "10000"))
                            stats (benchmark-op n
                                   (fn []
                                     (mock-map-update m (random-key 4) (random-value 8))))]
                        (println (format "Benchmark (%d operations):" n))
                        (println (format "  Mean: %s" (format-ns (:mean stats))))
                        (println (format "  Min: %s" (format-ns (:min stats))))
                        (println (format "  Max: %s" (format-ns (:max stats)))))))
      ;; Default: run demo
      (run-demo))))
