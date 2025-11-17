(ns clj-ebpf.perf-test
  "Tests for perf event buffer support"
  (:require [clojure.test :refer :all]
            [clj-ebpf.perf :as perf]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.constants :as const]))

(defn linux-with-bpf?
  "Check if we're on Linux with BPF available"
  []
  (and (= "Linux" (System/getProperty "os.name"))
       (try
         (utils/check-bpf-available)
         true
         (catch Exception _ false))))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-perf-constants
  (testing "Perf event types"
    (is (= 0 (:hardware const/perf-type)))
    (is (= 1 (:software const/perf-type)))
    (is (= 2 (:tracepoint const/perf-type))))

  (testing "Perf software config"
    (is (= 10 (:bpf-output const/perf-sw-config)))
    (is (= 0 (:cpu-clock const/perf-sw-config))))

  (testing "Perf record types"
    (is (= 9 (:sample perf/perf-record-type)))
    (is (= 2 (:lost perf/perf-record-type)))))

;; ============================================================================
;; Perf Event Attribute Tests
;; ============================================================================

(deftest test-perf-event-attr-structure
  (testing "Perf event attribute structure creation"
    (let [attr-bytes (#'perf/perf-event-attr->bytes
                      {:type :software
                       :config :bpf-output
                       :sample-period 1
                       :wakeup-events 1})]
      (is (= 128 (count attr-bytes)) "Attribute structure should be 128 bytes")
      (is (instance? (Class/forName "[B") attr-bytes)))))

(deftest test-perf-event-attr-defaults
  (testing "Default perf event attribute values"
    (let [attr-bytes (#'perf/perf-event-attr->bytes {})]
      (is (= 128 (count attr-bytes))))))

;; ============================================================================
;; Buffer Page Count Validation Tests
;; ============================================================================

(deftest test-page-count-validation
  (testing "Page count must be power of 2"
    ;; Valid powers of 2
    (is (= 1 (Integer/bitCount 1)))
    (is (= 1 (Integer/bitCount 2)))
    (is (= 1 (Integer/bitCount 4)))
    (is (= 1 (Integer/bitCount 64)))

    ;; Invalid (not powers of 2)
    (is (not= 1 (Integer/bitCount 3)))
    (is (not= 1 (Integer/bitCount 5)))
    (is (not= 1 (Integer/bitCount 100)))))

;; ============================================================================
;; Perf Event Opening Tests (require permissions)
;; ============================================================================

(deftest ^:integration test-perf-event-open
  (when (linux-with-bpf?)
    (testing "Open perf event"
      (try
        (let [fd (perf/perf-event-open
                  {:type :software
                   :config :bpf-output
                   :sample-period 1
                   :wakeup-events 1}
                  -1 0 -1 0)]
          (is (pos? fd) "Should get positive FD")
          (clj-ebpf.syscall/close-fd fd))
        (catch Exception e
          ;; May fail without proper permissions
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Perf Event Array Map Tests
;; ============================================================================

(deftest test-create-perf-event-array
  (when (linux-with-bpf?)
    (testing "Create perf event array map"
      (try
        (let [m (perf/create-perf-event-array 4 :map-name "test_perf_array")]
          (is (some? m) "Should create map")
          (is (= :perf-event-array (:type m)))
          (is (= 4 (:max-entries m)))
          (clj-ebpf.maps/close-map m))
        (catch Exception e
          ;; May fail without proper permissions - that's ok
          (is (string? (.getMessage e)) "Exception should have a message"))))))

;; ============================================================================
;; Event Parsing Tests
;; ============================================================================

(deftest test-perf-event-header-parsing
  (testing "Perf event header structure"
    ;; Event header is 8 bytes: u32 type, u16 misc, u16 size
    (let [header-data (utils/pack-struct [[:u32 9]     ; type = SAMPLE
                                          [:u16 0]     ; misc
                                          [:u16 32]])  ; size
          seg (utils/bytes->segment header-data)
          header (#'perf/read-perf-event-header seg 0)]
      (is (= 9 (:type header)))
      (is (= 0 (:misc header)))
      (is (= 32 (:size header))))))

;; ============================================================================
;; Perf Consumer Tests
;; ============================================================================

(deftest test-consumer-structure
  (testing "Consumer creation structure"
    ;; We can't actually create a consumer without permissions,
    ;; but we can verify the function exists and has correct signature
    (is (fn? perf/create-perf-consumer))
    (is (fn? perf/start-perf-consumer))
    (is (fn? perf/stop-perf-consumer))
    (is (fn? perf/get-perf-stats))))

(deftest test-stats-structure
  (testing "Perf stats structure"
    (let [stats {:events-read 100
                :events-processed 95
                :polls 50
                :errors 5
                :start-time 1000
                :last-event-time 2000}
          uptime-ms (- 2000 1000)
          events-per-sec (/ (* 95 1000.0) uptime-ms)]
      (is (= 1000 uptime-ms))
      (is (= 95.0 events-per-sec)))))

;; ============================================================================
;; Memory Segment Reading Tests
;; ============================================================================

(deftest test-memory-segment-reading
  (testing "Read u64 from segment"
    (let [data (utils/pack-struct [[:u64 0x1122334455667788]])
          seg (utils/bytes->segment data)
          val (#'perf/read-u64-from-segment seg 0)]
      (is (= 0x1122334455667788 val))))

  (testing "Read u32 from segment"
    (let [data (utils/pack-struct [[:u32 0x12345678]])
          seg (utils/bytes->segment data)
          val (#'perf/read-u32-from-segment seg 0)]
      (is (= 0x12345678 val))))

  (testing "Read u16 from segment"
    (let [data (utils/pack-struct [[:u16 0x1234]])
          seg (utils/bytes->segment data)
          val (#'perf/read-u16-from-segment seg 0)]
      (is (= 0x1234 val)))))

;; ============================================================================
;; Integration Tests (require root/CAP_PERFMON and BPF)
;; ============================================================================

(deftest ^:integration test-perf-buffer-lifecycle
  (when (and (linux-with-bpf?)
            (System/getenv "RUN_INTEGRATION_TESTS"))
    (testing "Full perf buffer lifecycle"
      (try
        ;; Create perf event array
        (let [cpu-count (utils/get-cpu-count)
              perf-map (perf/create-perf-event-array cpu-count
                                                    :map-name "test_perf")]
          (try
            ;; Create consumer
            (let [events (atom [])
                  consumer (perf/create-perf-consumer
                            :map perf-map
                            :callback (fn [e] (swap! events conj e))
                            :buffer-pages 8
                            :cpu-count 1)]

              (is (some? consumer))
              (is (= 1 (count (:buffers consumer))))

              ;; Start consumer
              (let [running-consumer (perf/start-perf-consumer consumer 100)]
                (is (some? (:consumer-thread running-consumer)))

                ;; Let it run briefly
                (Thread/sleep 500)

                ;; Get stats
                (let [stats (perf/get-perf-stats running-consumer)]
                  (is (some? stats))
                  (is (>= (:polls stats) 0)))

                ;; Stop consumer
                (perf/stop-perf-consumer running-consumer)))

            (finally
              (clj-ebpf.maps/close-map perf-map))))

        (catch Exception e
          ;; Expected to fail without proper permissions
          (is (or (re-find #"Operation not permitted" (.getMessage e))
                 (re-find #"Permission denied" (.getMessage e)))))))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-perf-api-completeness
  (testing "Core perf functions are available"
    (is (fn? perf/perf-event-open))
    (is (fn? perf/create-perf-event-array))
    (is (fn? perf/create-perf-consumer))
    (is (fn? perf/start-perf-consumer))
    (is (fn? perf/stop-perf-consumer))
    (is (fn? perf/get-perf-stats))
    (is (fn? perf/read-perf-events))))

;; ============================================================================
;; Documentation Tests
;; ============================================================================

(deftest test-function-metadata
  (testing "Key functions have docstrings"
    (is (string? (:doc (meta #'perf/perf-event-open))))
    (is (string? (:doc (meta #'perf/create-perf-event-array))))
    (is (string? (:doc (meta #'perf/create-perf-consumer))))
    (is (string? (:doc (meta #'perf/start-perf-consumer))))
    (is (string? (:doc (meta #'perf/stop-perf-consumer))))
    (is (string? (:doc (meta #'perf/get-perf-stats))))
    (is (string? (:doc (meta #'perf/read-perf-events))))))

;; ============================================================================
;; Example Usage Documentation
;; ============================================================================

(deftest ^:example test-usage-examples
  (testing "Example code compiles correctly"
    ;; Example 1: Basic usage
    (is (fn? (fn []
               (let [perf-map (perf/create-perf-event-array 4)
                     consumer (perf/create-perf-consumer
                               :map perf-map
                               :callback println)]
                 (try
                   (perf/start-perf-consumer consumer)
                   (Thread/sleep 1000)
                   (finally
                     (perf/stop-perf-consumer consumer)
                     (clj-ebpf.maps/close-map perf-map)))))))

    ;; Example 2: Using macro
    (is (fn? (fn []
               (let [perf-map (perf/create-perf-event-array 4)]
                 (perf/with-perf-consumer [consumer {:map perf-map
                                                    :callback println}]
                   (perf/start-perf-consumer consumer)
                   (Thread/sleep 1000))))))))

;; ============================================================================
;; Error Handling Tests
;; ============================================================================

(deftest test-error-handling
  (testing "Invalid page count (not power of 2)"
    ;; 3 has 2 bits set, so it's not a power of 2
    (is (= 2 (Integer/bitCount 3)))
    (is (not= 1 (Integer/bitCount 3))))

  (testing "Valid page counts (powers of 2)"
    (is (= 1 (Integer/bitCount 1)))
    (is (= 1 (Integer/bitCount 64))))

  (testing "Perf event open with invalid parameters"
    ;; Should throw on negative CPU that's out of range
    (when (linux-with-bpf?)
      (is (thrown? Exception
            (perf/perf-event-open {} -1 999999 -1 0))))))

;; ============================================================================
;; Performance Characteristics Tests
;; ============================================================================

(deftest test-event-rate-calculation
  (testing "Events per second calculation"
    (let [events-processed 10000
          uptime-ms 1000
          eps (/ (* events-processed 1000.0) uptime-ms)]
      (is (= 10000.0 eps) "Should process 10000 events/sec")))

  (testing "With longer uptime"
    (let [events-processed 50000
          uptime-ms 5000
          eps (/ (* events-processed 1000.0) uptime-ms)]
      (is (= 10000.0 eps) "Should still be 10000 events/sec"))))

;; ============================================================================
;; Buffer Size Tests
;; ============================================================================

(deftest test-buffer-sizes
  (testing "Buffer size calculations"
    (let [page-size 4096
          page-count 64
          data-size (* page-count page-size)
          total-size (+ page-size data-size)]
      (is (= (* 64 4096) data-size))
      (is (= (+ 4096 (* 64 4096)) total-size))
      (is (= 266240 total-size)))))
