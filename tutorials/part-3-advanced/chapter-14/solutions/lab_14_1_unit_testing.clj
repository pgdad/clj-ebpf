;; Lab 14.1 Solution: Unit Testing Framework
;; Comprehensive testing framework for BPF programs
;;
;; Learning Goals:
;; - Use mock syscall layer for unprivileged testing
;; - Leverage test utilities for common patterns
;; - Design testable BPF programs
;; - Create reusable test fixtures
;; - Implement BPF-specific assertions

(ns lab-14-1-unit-testing
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils]
            [clojure.test :as t :refer [deftest testing is are]])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Mock Infrastructure (Simulation Layer)
;; ============================================================================

(def ^:dynamic *mock-mode* false)

(defn with-mock-bpf
  "Execute body with mock BPF infrastructure"
  [f]
  (binding [*mock-mode* true]
    (f)))

(defmacro mock-fixture
  "Test fixture that enables mock mode"
  [f]
  `(with-mock-bpf ~f))

;; ============================================================================
;; Mock Map Implementation
;; ============================================================================

(defrecord MockMap [type key-size value-size max-entries data])

(defn create-mock-map
  "Create a mock BPF map"
  [type key-size value-size max-entries]
  (->MockMap type key-size value-size max-entries (atom {})))

(defn mock-map-update!
  "Update mock map entry"
  [mock-map key-bytes val-bytes]
  (let [key (vec key-bytes)]
    (if (and (>= (count @(:data mock-map)) (:max-entries mock-map))
             (nil? (get @(:data mock-map) key)))
      (throw (ex-info "Map full" {:error :enospc}))
      (do
        (swap! (:data mock-map) assoc key (vec val-bytes))
        true))))

(defn mock-map-lookup
  "Lookup mock map entry"
  [mock-map key-bytes]
  (let [key (vec key-bytes)]
    (when-let [val (get @(:data mock-map) key)]
      (byte-array val))))

(defn mock-map-delete!
  "Delete mock map entry"
  [mock-map key-bytes]
  (let [key (vec key-bytes)]
    (swap! (:data mock-map) dissoc key)
    true))

(defn mock-map-clear!
  "Clear all mock map entries"
  [mock-map]
  (reset! (:data mock-map) {})
  true)

(defn mock-map-size
  "Get mock map size"
  [mock-map]
  (count @(:data mock-map)))

(defn mock-map-entries
  "Get all mock map entries"
  [mock-map]
  @(:data mock-map))

;; ============================================================================
;; Test Utilities
;; ============================================================================

(defn make-key
  "Create a key byte array"
  ([value] (make-key value 4))
  ([value size]
   (let [buf (ByteBuffer/allocate size)]
     (.order buf ByteOrder/LITTLE_ENDIAN)
     (case size
       4 (.putInt buf (int value))
       8 (.putLong buf (long value))
       (dotimes [i (min size 4)]
         (.put buf (byte (bit-and (bit-shift-right (int value) (* i 8)) 0xFF)))))
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
       (dotimes [i (min size 8)]
         (.put buf (byte (bit-and (bit-shift-right (long value) (* i 8)) 0xFF)))))
     (.array buf))))

(defn bytes->int
  "Convert bytes to int"
  [bytes]
  (let [buf (ByteBuffer/wrap bytes)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.getInt buf)))

(defn bytes->long
  "Convert bytes to long"
  [bytes]
  (let [buf (ByteBuffer/wrap bytes)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.getLong buf)))

(defn make-entries
  "Generate N test entries"
  [n key-size value-size]
  (mapv (fn [i]
          [(make-key i key-size) (make-value (* i i) value-size)])
        (range n)))

(defn random-key
  "Generate random key"
  [size]
  (let [bytes (byte-array size)]
    (dotimes [i size]
      (aset bytes i (unchecked-byte (rand-int 256))))
    bytes))

(defn random-value
  "Generate random value"
  [size]
  (random-key size))

;; ============================================================================
;; BPF-Specific Assertions
;; ============================================================================

(defn assert-bytes-equal
  "Assert two byte arrays are equal"
  [expected actual & [message]]
  (let [msg (or message "Byte arrays should be equal")]
    (is (= (vec expected) (vec actual)) msg)))

(defn assert-map-contains
  "Assert map contains key"
  [mock-map key-bytes]
  (is (some? (mock-map-lookup mock-map key-bytes))
      (format "Map should contain key %s" (vec key-bytes))))

(defn assert-map-not-contains
  "Assert map does not contain key"
  [mock-map key-bytes]
  (is (nil? (mock-map-lookup mock-map key-bytes))
      (format "Map should not contain key %s" (vec key-bytes))))

(defn assert-map-size
  "Assert map has expected size"
  [mock-map expected-size]
  (is (= expected-size (mock-map-size mock-map))
      (format "Map size should be %d" expected-size)))

(defn assert-map-empty
  "Assert map is empty"
  [mock-map]
  (assert-map-size mock-map 0))

(defn assert-counter-value
  "Assert counter has expected value"
  [mock-map key-bytes expected-value]
  (let [actual-bytes (mock-map-lookup mock-map key-bytes)
        actual-value (when actual-bytes (bytes->long actual-bytes))]
    (is (= expected-value actual-value)
        (format "Counter should be %d, was %s" expected-value actual-value))))

(defn assert-throws-error
  "Assert operation throws expected error"
  [error-type f]
  (is (thrown-with-msg? Exception
                        (re-pattern (name error-type))
                        (f))
      (format "Should throw %s error" error-type)))

;; ============================================================================
;; Packet Building Utilities
;; ============================================================================

(defn build-eth-header
  "Build Ethernet header"
  [& {:keys [src-mac dst-mac eth-type]
      :or {src-mac (byte-array [0x00 0x11 0x22 0x33 0x44 0x55])
           dst-mac (byte-array [0xFF 0xFF 0xFF 0xFF 0xFF 0xFF])
           eth-type 0x0800}}]
  (let [header (byte-array 14)]
    (System/arraycopy dst-mac 0 header 0 6)
    (System/arraycopy src-mac 0 header 6 6)
    (aset header 12 (unchecked-byte (bit-shift-right eth-type 8)))
    (aset header 13 (unchecked-byte (bit-and eth-type 0xFF)))
    header))

(defn build-ipv4-header
  "Build IPv4 header"
  [& {:keys [src-ip dst-ip protocol ttl]
      :or {src-ip (byte-array [192 168 1 1])
           dst-ip (byte-array [10 0 0 1])
           protocol 6
           ttl 64}}]
  (let [header (byte-array 20)]
    (aset header 0 (unchecked-byte 0x45))  ; Version + IHL
    (aset header 1 (unchecked-byte 0x00))  ; DSCP/ECN
    (aset header 2 (unchecked-byte 0x00))  ; Total length (high)
    (aset header 3 (unchecked-byte 0x28))  ; Total length (low) = 40
    ;; Identification, flags, fragment offset (bytes 4-7)
    (aset header 8 (unchecked-byte ttl))
    (aset header 9 (unchecked-byte protocol))
    ;; Checksum (bytes 10-11)
    (System/arraycopy src-ip 0 header 12 4)
    (System/arraycopy dst-ip 0 header 16 4)
    header))

(defn build-tcp-header
  "Build TCP header"
  [& {:keys [src-port dst-port flags seq-num ack-num]
      :or {src-port 12345
           dst-port 80
           flags 0x02  ; SYN
           seq-num 0
           ack-num 0}}]
  (let [header (byte-array 20)]
    (aset header 0 (unchecked-byte (bit-shift-right src-port 8)))
    (aset header 1 (unchecked-byte (bit-and src-port 0xFF)))
    (aset header 2 (unchecked-byte (bit-shift-right dst-port 8)))
    (aset header 3 (unchecked-byte (bit-and dst-port 0xFF)))
    ;; Sequence number (bytes 4-7)
    ;; Ack number (bytes 8-11)
    (aset header 12 (unchecked-byte 0x50))  ; Data offset (5 * 4 = 20 bytes)
    (aset header 13 (unchecked-byte flags))
    (aset header 14 (unchecked-byte 0xFF))  ; Window (high)
    (aset header 15 (unchecked-byte 0xFF))  ; Window (low)
    ;; Checksum, urgent pointer (bytes 16-19)
    header))

(defn build-test-packet
  "Build complete test packet"
  [& {:keys [protocol src-ip dst-ip src-port dst-port]
      :or {protocol :tcp
           src-ip (byte-array [192 168 1 1])
           dst-ip (byte-array [10 0 0 1])
           src-port 12345
           dst-port 80}}]
  (let [proto-num (case protocol :tcp 6 :udp 17 :icmp 1 6)
        eth (build-eth-header)
        ip (build-ipv4-header :src-ip src-ip :dst-ip dst-ip :protocol proto-num)
        transport (build-tcp-header :src-port src-port :dst-port dst-port)
        packet (byte-array (+ (count eth) (count ip) (count transport)))]
    (System/arraycopy eth 0 packet 0 (count eth))
    (System/arraycopy ip 0 packet (count eth) (count ip))
    (System/arraycopy transport 0 packet (+ (count eth) (count ip)) (count transport))
    packet))

;; ============================================================================
;; Performance Benchmarking
;; ============================================================================

(defn benchmark-op
  "Benchmark an operation"
  [iterations operation]
  (let [times (atom [])]
    (dotimes [_ iterations]
      (let [start (System/nanoTime)]
        (operation)
        (let [end (System/nanoTime)]
          (swap! times conj (- end start)))))

    (let [sorted-times (sort @times)
          total (reduce + sorted-times)
          count (count sorted-times)]
      {:min (first sorted-times)
       :max (last sorted-times)
       :mean (/ total count)
       :median (nth sorted-times (quot count 2))
       :p99 (nth sorted-times (int (* count 0.99)))
       :total total
       :count count})))

(defn format-ns
  "Format nanoseconds for display"
  [ns]
  (cond
    (< ns 1000) (format "%d ns" ns)
    (< ns 1000000) (format "%.2f µs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.2f ms" (/ ns 1000000.0))
    :else (format "%.2f s" (/ ns 1000000000.0))))

;; ============================================================================
;; Test Fixtures
;; ============================================================================

(defmacro with-temp-map
  "Create a temporary map for testing"
  [[sym config] & body]
  `(let [~sym (create-mock-map
               (or (:type ~config) :hash)
               (or (:key-size ~config) 4)
               (or (:value-size ~config) 8)
               (or (:max-entries ~config) 100))]
     ~@body))

;; ============================================================================
;; Unit Tests
;; ============================================================================

(deftest test-hash-map-basic-operations
  (testing "Hash map basic operations"
    (with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (let [key (make-key 42)
            val (make-value 12345)]

        (testing "Insert and lookup"
          (mock-map-update! m key val)
          (assert-bytes-equal val (mock-map-lookup m key)))

        (testing "Update existing"
          (let [new-val (make-value 99999)]
            (mock-map-update! m key new-val)
            (assert-bytes-equal new-val (mock-map-lookup m key))))

        (testing "Delete"
          (mock-map-delete! m key)
          (assert-map-not-contains m key))))))

(deftest test-array-map-operations
  (testing "Array map operations"
    (with-temp-map [m {:type :array :key-size 4 :value-size 8 :max-entries 10}]
      (testing "Sequential insert and lookup"
        (doseq [i (range 10)]
          (mock-map-update! m (make-key i) (make-value (* i i))))

        (doseq [i (range 10)]
          (let [expected (make-value (* i i))
                actual (mock-map-lookup m (make-key i))]
            (assert-bytes-equal expected actual)))))))

(deftest test-map-overflow
  (testing "Map overflow behavior"
    (with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 5}]
      (testing "Fill the map"
        (doseq [i (range 5)]
          (mock-map-update! m (make-key i) (make-value i)))
        (assert-map-size m 5))

      (testing "Overflow should throw"
        (is (thrown? Exception
                     (mock-map-update! m (make-key 99) (make-value 99))))))))

(deftest test-counter-operations
  (testing "Counter increment patterns"
    (with-temp-map [m {:type :array :key-size 4 :value-size 8 :max-entries 256}]
      (let [tcp-key (make-key 6)
            udp-key (make-key 17)]

        ;; Initialize counters
        (mock-map-update! m tcp-key (make-value 0))
        (mock-map-update! m udp-key (make-value 0))

        ;; Simulate packet counting
        (dotimes [_ 100]
          (let [current (bytes->long (mock-map-lookup m tcp-key))]
            (mock-map-update! m tcp-key (make-value (inc current)))))

        (dotimes [_ 50]
          (let [current (bytes->long (mock-map-lookup m udp-key))]
            (mock-map-update! m udp-key (make-value (inc current)))))

        (assert-counter-value m tcp-key 100)
        (assert-counter-value m udp-key 50)))))

(deftest test-packet-building
  (testing "Packet building utilities"
    (testing "Ethernet header"
      (let [eth (build-eth-header)]
        (is (= 14 (count eth)) "Ethernet header should be 14 bytes")))

    (testing "IPv4 header"
      (let [ip (build-ipv4-header)]
        (is (= 20 (count ip)) "IPv4 header should be 20 bytes")
        (is (= 0x45 (bit-and (aget ip 0) 0xFF)) "Version 4, IHL 5")))

    (testing "TCP header"
      (let [tcp (build-tcp-header :src-port 8080 :dst-port 443)]
        (is (= 20 (count tcp)) "TCP header should be 20 bytes")))

    (testing "Complete packet"
      (let [packet (build-test-packet :protocol :tcp :dst-port 80)]
        (is (= 54 (count packet)) "TCP packet should be 54 bytes")
        ;; Check EtherType (IPv4 = 0x0800)
        (is (= 0x08 (bit-and (aget packet 12) 0xFF)))
        (is (= 0x00 (bit-and (aget packet 13) 0xFF)))))))

(deftest test-firewall-logic
  (testing "Firewall blacklist logic"
    (with-temp-map [blacklist {:type :hash :key-size 4 :value-size 4 :max-entries 1000}]
      (let [blocked-ip (byte-array [192 168 1 100])
            allowed-ip (byte-array [192 168 1 1])
            block-marker (make-value 1 4)]

        ;; Add IP to blacklist
        (mock-map-update! blacklist blocked-ip block-marker)

        (testing "Blocked IP should be in blacklist"
          (assert-map-contains blacklist blocked-ip))

        (testing "Allowed IP should not be in blacklist"
          (assert-map-not-contains blacklist allowed-ip))))))

(deftest test-performance-benchmarks
  (testing "Map operation performance"
    (with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 10000}]
      (testing "Insert performance"
        (let [stats (benchmark-op 1000
                                  (fn []
                                    (let [key (random-key 4)
                                          val (random-value 8)]
                                      (mock-map-update! m key val))))]

          (println "\n=== Insert Performance ===")
          (println (format "Min:    %s" (format-ns (:min stats))))
          (println (format "Max:    %s" (format-ns (:max stats))))
          (println (format "Mean:   %s" (format-ns (:mean stats))))
          (println (format "Median: %s" (format-ns (:median stats))))
          (println (format "P99:    %s" (format-ns (:p99 stats))))

          ;; Assert reasonable performance (mock should be fast)
          (is (< (:mean stats) 1000000) "Insert should be sub-millisecond"))))))

;; ============================================================================
;; Test Runner
;; ============================================================================

(defn run-test-suite
  "Run all tests"
  []
  (println "=== BPF Unit Test Suite ===")
  (println "Using mock infrastructure for unprivileged testing\n")

  (let [start-time (System/currentTimeMillis)
        results (t/run-tests 'lab-14-1-unit-testing)
        duration (- (System/currentTimeMillis) start-time)]

    (println "\n=== Test Summary ===")
    (println (format "Total tests:  %d" (+ (:pass results 0)
                                           (:fail results 0)
                                           (:error results 0))))
    (println (format "Passed:       %d" (:pass results 0)))
    (println (format "Failed:       %d" (:fail results 0)))
    (println (format "Errors:       %d" (:error results 0)))
    (println (format "Duration:     %dms" duration))

    (if (and (zero? (:fail results 0))
             (zero? (:error results 0)))
      (do
        (println "\nAll tests passed!")
        0)
      (do
        (println "\nSome tests failed!")
        1))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the unit testing framework lab"
  [& args]
  (let [command (first args)]
    (case command
      "run"
      (System/exit (run-test-suite))

      "bench"
      (do
        (println "Running benchmarks...")
        (with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 100000}]
          (let [insert-stats (benchmark-op 10000
                                           (fn []
                                             (mock-map-update! m (random-key 4) (random-value 8))))]
            (println "\n=== Benchmark Results ===")
            (println (format "Inserts: %d ops in %s"
                             (:count insert-stats)
                             (format-ns (:total insert-stats))))
            (println (format "Mean latency: %s" (format-ns (:mean insert-stats)))))))

      ;; Default: show usage
      (do
        (println "Lab 14.1: Unit Testing Framework")
        (println "=================================")
        (println "\nUsage:")
        (println "  run        - Run test suite")
        (println "  bench      - Run benchmarks")
        (println)

        ;; Run tests by default
        (run-test-suite)

        (println "\n=== Key Takeaways ===")
        (println "1. Mock mode enables testing without CAP_BPF")
        (println "2. Use fixtures for consistent test setup")
        (println "3. BPF-specific assertions improve test clarity")
        (println "4. Benchmark utilities help track performance")))))

;; Run with: clj -M -m lab-14-1-unit-testing
;; Or:       clj -M -m lab-14-1-unit-testing run
