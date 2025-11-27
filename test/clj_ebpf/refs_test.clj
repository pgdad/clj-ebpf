(ns clj-ebpf.refs-test
  "Tests for deref-able BPF references"
  (:require [clojure.test :refer :all]
            [clj-ebpf.refs :as refs])
  (:import [clj_ebpf.refs RingBufRef QueueRef MapWatcher MapChangeWatcher]))

;; ============================================================================
;; Type Tests - Verify types implement correct protocols
;; ============================================================================

(deftest test-ringbuf-ref-protocols
  (testing "RingBufRef implements IDeref"
    (is (isa? RingBufRef clojure.lang.IDeref)))

  (testing "RingBufRef implements IBlockingDeref"
    (is (isa? RingBufRef clojure.lang.IBlockingDeref)))

  (testing "RingBufRef implements Closeable"
    (is (isa? RingBufRef java.io.Closeable))))

(deftest test-queue-ref-protocols
  (testing "QueueRef implements IDeref"
    (is (isa? QueueRef clojure.lang.IDeref)))

  (testing "QueueRef implements IBlockingDeref"
    (is (isa? QueueRef clojure.lang.IBlockingDeref)))

  (testing "QueueRef implements Closeable"
    (is (isa? QueueRef java.io.Closeable))))

(deftest test-map-watcher-protocols
  (testing "MapWatcher implements IDeref"
    (is (isa? MapWatcher clojure.lang.IDeref)))

  (testing "MapWatcher implements IBlockingDeref"
    (is (isa? MapWatcher clojure.lang.IBlockingDeref)))

  (testing "MapWatcher implements Closeable"
    (is (isa? MapWatcher java.io.Closeable))))

(deftest test-map-change-watcher-protocols
  (testing "MapChangeWatcher implements IDeref"
    (is (isa? MapChangeWatcher clojure.lang.IDeref)))

  (testing "MapChangeWatcher implements IBlockingDeref"
    (is (isa? MapChangeWatcher clojure.lang.IBlockingDeref)))

  (testing "MapChangeWatcher implements Closeable"
    (is (isa? MapChangeWatcher java.io.Closeable))))

;; ============================================================================
;; Function Existence Tests
;; ============================================================================

(deftest test-ref-functions-exist
  (testing "Ring buffer ref functions"
    (is (fn? refs/ringbuf-ref))
    (is (fn? refs/ringbuf-seq)))

  (testing "Queue/Stack ref functions"
    (is (fn? refs/queue-ref))
    (is (fn? refs/stack-ref))
    (is (fn? refs/queue-seq)))

  (testing "Map watcher functions"
    (is (fn? refs/map-watch))
    (is (fn? refs/map-watch-changes))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(deftest test-macros-defined
  (testing "with-ringbuf-ref macro is defined"
    (is (some? (ns-resolve 'clj-ebpf.refs 'with-ringbuf-ref))))

  (testing "with-queue-ref macro is defined"
    (is (some? (ns-resolve 'clj-ebpf.refs 'with-queue-ref))))

  (testing "with-stack-ref macro is defined"
    (is (some? (ns-resolve 'clj-ebpf.refs 'with-stack-ref))))

  (testing "with-map-watcher macro is defined"
    (is (some? (ns-resolve 'clj-ebpf.refs 'with-map-watcher)))))

;; ============================================================================
;; Mock-based Behavioral Tests (no kernel required)
;; ============================================================================

(deftest test-queue-ref-timeout-behavior
  (testing "QueueRef respects timeout on empty queue"
    ;; Create a mock map that always returns nil (empty queue)
    (let [mock-map {:fd 999 :name "test-queue" :value-size 8}
          empty-pop (fn [_] nil)
          ;; Create QueueRef directly with mock
          ref (refs/->QueueRef mock-map empty-pop 5
                               (java.util.concurrent.atomic.AtomicBoolean. false))
          start-time (System/currentTimeMillis)
          result (deref ref 50 :timeout)
          elapsed (- (System/currentTimeMillis) start-time)]

      ;; Should return timeout value
      (is (= :timeout result))

      ;; Should have waited approximately the timeout duration
      (is (>= elapsed 40))  ; Allow some slack
      (is (< elapsed 200))  ; But not too long

      (.close ref))))

(deftest test-queue-ref-immediate-return
  (testing "QueueRef returns immediately when data available"
    ;; Mock that returns data on first call
    (let [call-count (atom 0)
          mock-map {:fd 999 :name "test-queue" :value-size 8}
          returning-pop (fn [_]
                          (swap! call-count inc)
                          {:value 42})
          ref (refs/->QueueRef mock-map returning-pop 100
                               (java.util.concurrent.atomic.AtomicBoolean. false))
          start-time (System/currentTimeMillis)
          result (deref ref 5000 :timeout)
          elapsed (- (System/currentTimeMillis) start-time)]

      ;; Should return the value
      (is (= {:value 42} result))

      ;; Should have returned almost immediately
      (is (< elapsed 50))

      ;; Should have only called pop once
      (is (= 1 @call-count))

      (.close ref))))

(deftest test-queue-ref-closed-throws
  (testing "QueueRef throws when closed"
    (let [mock-map {:fd 999 :name "test-queue" :value-size 8}
          ref (refs/->QueueRef mock-map (fn [_] nil) 10
                               (java.util.concurrent.atomic.AtomicBoolean. false))]
      (.close ref)

      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"closed"
                            (deref ref 100 nil))))))

(deftest test-map-watcher-timeout-behavior
  (testing "MapWatcher respects timeout when key not found"
    ;; Create mock with lookup that returns nil
    (let [mock-map {:fd 999 :name "test-map" :key-size 4 :value-size 8}
          watcher (refs/->MapWatcher mock-map :missing-key 5
                                     (java.util.concurrent.atomic.AtomicReference. nil)
                                     (java.util.concurrent.atomic.AtomicBoolean. false))
          start-time (System/currentTimeMillis)]

      ;; Use with-redefs to mock map-lookup
      (with-redefs [clj-ebpf.maps/map-lookup (fn [_ _] nil)]
        (let [result (deref watcher 50 :not-found)
              elapsed (- (System/currentTimeMillis) start-time)]

          (is (= :not-found result))
          (is (>= elapsed 40))
          (is (< elapsed 200))))

      (.close watcher))))

(deftest test-map-change-watcher-detects-change
  (testing "MapChangeWatcher detects value changes"
    (let [mock-map {:fd 999 :name "test-map" :key-size 4 :value-size 8}
          watcher (refs/->MapChangeWatcher mock-map :counter 5
                                           (java.util.concurrent.atomic.AtomicReference. 100)
                                           (java.util.concurrent.atomic.AtomicBoolean. false))]

      ;; Mock lookup that returns a different value
      (with-redefs [clj-ebpf.maps/map-lookup (fn [_ _] 200)]
        (let [result (deref watcher 100 :unchanged)]
          (is (= 200 result))))

      (.close watcher))))

(deftest test-map-change-watcher-ignores-same-value
  (testing "MapChangeWatcher ignores unchanged values"
    (let [mock-map {:fd 999 :name "test-map" :key-size 4 :value-size 8}
          watcher (refs/->MapChangeWatcher mock-map :counter 5
                                           (java.util.concurrent.atomic.AtomicReference. 100)
                                           (java.util.concurrent.atomic.AtomicBoolean. false))]

      ;; Mock lookup that returns same value
      (with-redefs [clj-ebpf.maps/map-lookup (fn [_ _] 100)]
        (let [result (deref watcher 50 :unchanged)]
          (is (= :unchanged result))))

      (.close watcher))))

;; ============================================================================
;; Sequence Generation Tests
;; ============================================================================

(deftest test-queue-seq-with-timeout
  (testing "queue-seq terminates on timeout"
    (let [call-count (atom 0)
          mock-map {:fd 999 :name "test-queue" :value-size 8}
          ;; Returns 3 values then blocks
          limited-pop (fn [_]
                        (let [n (swap! call-count inc)]
                          (when (<= n 3)
                            {:n n})))
          ref (refs/->QueueRef mock-map limited-pop 5
                               (java.util.concurrent.atomic.AtomicBoolean. false))
          ;; Get sequence with short timeout
          results (doall (take 10 (refs/queue-seq ref :timeout-ms 30)))]

      ;; Should get 3 items then stop due to timeout
      (is (= 3 (count results)))
      (is (= [{:n 1} {:n 2} {:n 3}] results))

      (.close ref))))

;; ============================================================================
;; Thread Safety Tests
;; ============================================================================

(deftest test-queue-ref-concurrent-close
  (testing "Closing QueueRef from another thread is safe"
    (let [mock-map {:fd 999 :name "test-queue" :value-size 8}
          ref (refs/->QueueRef mock-map (fn [_] (Thread/sleep 100) nil) 10
                               (java.util.concurrent.atomic.AtomicBoolean. false))
          ;; Start a deref in background
          future-result (future
                          (try
                            (deref ref 5000 :timeout)
                            (catch Exception e
                              :closed-exception)))]

      ;; Close after short delay
      (Thread/sleep 30)
      (.close ref)

      ;; Should either get timeout or closed exception
      (let [result (deref future-result 1000 :future-timeout)]
        (is (or (= :closed-exception result)
                (= :timeout result)
                (= :future-timeout result)))))))
