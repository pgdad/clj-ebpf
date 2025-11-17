(ns clj-ebpf.enhanced-ringbuf-test
  "Tests for enhanced ring buffer event processing"
  (:require [clojure.test :refer :all]
            [clj-ebpf.events :as events]
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
;; Event Parser/Serializer Tests
;; ============================================================================

(deftest test-event-parser
  (testing "Event parser creation and usage"
    (let [parser (events/make-event-parser [:u32 :u64 :u32])
          data (utils/pack-struct [[:u32 123] [:u64 456789] [:u32 42]])]
      (is (= [123 456789 42] (parser data))))))

(deftest test-event-serializer
  (testing "Event serializer creation and usage"
    (let [serializer (events/make-event-serializer [:u32 :u64 :u32])
          data (serializer [123 456789 42])
          parser (events/make-event-parser [:u32 :u64 :u32])]
      (is (= [123 456789 42] (parser data))))))

(deftest test-event-handler
  (testing "Event handler with filtering and transformation"
    (let [collected (atom [])
          handler (events/make-event-handler
                   :parser (events/make-event-parser [:u32 :u32])
                   :filter (fn [[a b]] (> a 100))
                   :transform (fn [[a b]] {:first a :second b})
                   :handler #(swap! collected conj %))
          event1 (utils/pack-struct [[:u32 50] [:u32 100]])
          event2 (utils/pack-struct [[:u32 150] [:u32 200]])]

      ;; Process events
      (handler event1) ; Filtered out (50 < 100)
      (handler event2) ; Passes filter

      (is (= 1 (count @collected)))
      (is (= {:first 150 :second 200} (first @collected))))))

;; ============================================================================
;; Ring Buffer Memory Mapping Tests (require BPF)
;; ============================================================================

(deftest test-ringbuf-map-creation
  (when (linux-with-bpf?)
    (testing "Create ring buffer map for testing"
      (let [m (maps/create-ringbuf-map (* 4 1024) :map-name "test_ringbuf")]
        (try
          (is (some? m))
          (is (= :ringbuf (:type m)))
          (is (= (* 4 1024) (:max-entries m)))
          (finally
            (maps/close-map m)))))))

;; Note: Full ring buffer tests require:
;; 1. A BPF program to write events to the ring buffer
;; 2. Memory mapping requires root/CAP_BPF
;; 3. Proper ring buffer data format

;; These would be integration tests that:
;; - Load a BPF program that writes events to ringbuf
;; - Attach the program to a tracepoint
;; - Trigger the tracepoint
;; - Read events from the ring buffer
;; - Verify event data

;; ============================================================================
;; Statistics Tests
;; ============================================================================

(deftest test-consumer-stats-structure
  (testing "Consumer stats structure"
    (let [stats {:events-read 100
                :events-processed 95
                :batches-read 10
                :errors 5
                :start-time 1000
                :last-event-time 2000}
          ;; Simulate uptime calculation
          uptime-ms (- 2000 1000)
          events-per-sec (/ (* 95 1000.0) uptime-ms)]

      (is (= 1000 uptime-ms))
      (is (= 95.0 events-per-sec)))))

;; ============================================================================
;; Helper Function Tests
;; ============================================================================

(deftest test-pack-unpack-roundtrip
  (testing "Pack/unpack roundtrip for various types"
    (let [test-cases [[[:u8 :u8] [1 2]]
                     [[:u16 :u16] [300 400]]
                     [[:u32 :u32] [100000 200000]]
                     [[:u64 :u64] [10000000000 20000000000]]
                     [[:u32 :u64 :u32] [123 456789 42]]]]

      (doseq [[spec values] test-cases]
        (let [serializer (events/make-event-serializer spec)
              parser (events/make-event-parser spec)
              packed (serializer values)
              unpacked (parser packed)]
          (is (= values unpacked)
              (str "Roundtrip failed for spec " spec " with values " values)))))))

(deftest test-event-filtering
  (testing "Event filtering logic"
    (let [events [[1 100] [50 200] [200 300] [150 400]]
          filter-fn (fn [[pid _]] (> pid 100))
          filtered (filter filter-fn events)]

      (is (= 2 (count filtered)))
      (is (= [[200 300] [150 400]] filtered)))))

;; ============================================================================
;; Performance Estimation Tests
;; ============================================================================

(deftest test-events-per-second-calculation
  (testing "Events per second calculation"
    (let [events-processed 1000
          uptime-ms 1000 ; 1 second
          eps (/ (* events-processed 1000.0) uptime-ms)]
      (is (= 1000.0 eps) "Should process 1000 events/sec")))

  (testing "Events per second with longer uptime"
    (let [events-processed 5000
          uptime-ms 2000 ; 2 seconds
          eps (/ (* events-processed 1000.0) uptime-ms)]
      (is (= 2500.0 eps) "Should process 2500 events/sec"))))

;; ============================================================================
;; Error Handling Tests
;; ============================================================================

(deftest test-malformed-event-handling
  (testing "Handling malformed events"
    (let [parser (events/make-event-parser [:u32 :u64 :u32])
          ;; Event too short
          bad-data (byte-array 4)]

      (is (thrown? Exception (parser bad-data))))))

(deftest test-event-handler-with-exceptions
  (testing "Event handler error propagation"
    (let [error-count (atom 0)
          handler (events/make-event-handler
                   :parser (events/make-event-parser [:u32])
                   :handler (fn [_] (swap! error-count inc) (throw (Exception. "Handler error"))))
          event (utils/pack-struct [[:u32 123]])]

      (is (thrown? Exception (handler event)))
      (is (= 1 @error-count)))))
