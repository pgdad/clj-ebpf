(ns clj-ebpf.refs-test
  "Tests for deref-able BPF references - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.refs :as refs])
  (:import [clj_ebpf.refs RingBufRef QueueRef MapWatcher MapChangeWatcher
            MapEntryRef QueueWriter StackWriter QueueChannel StackChannel]))

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
;; Writable Reference Protocol Tests
;; ============================================================================

(deftest test-map-entry-ref-protocols
  (testing "MapEntryRef implements IDeref"
    (is (isa? MapEntryRef clojure.lang.IDeref)))

  (testing "MapEntryRef implements IAtom"
    (is (isa? MapEntryRef clojure.lang.IAtom)))

  (testing "MapEntryRef implements IRef"
    (is (isa? MapEntryRef clojure.lang.IRef)))

  (testing "MapEntryRef implements Closeable"
    (is (isa? MapEntryRef java.io.Closeable))))

(deftest test-queue-writer-protocols
  (testing "QueueWriter implements IDeref"
    (is (isa? QueueWriter clojure.lang.IDeref)))

  (testing "QueueWriter implements ITransientCollection"
    (is (isa? QueueWriter clojure.lang.ITransientCollection)))

  (testing "QueueWriter implements Closeable"
    (is (isa? QueueWriter java.io.Closeable))))

(deftest test-stack-writer-protocols
  (testing "StackWriter implements IDeref"
    (is (isa? StackWriter clojure.lang.IDeref)))

  (testing "StackWriter implements ITransientCollection"
    (is (isa? StackWriter clojure.lang.ITransientCollection)))

  (testing "StackWriter implements Closeable"
    (is (isa? StackWriter java.io.Closeable))))

(deftest test-queue-channel-protocols
  (testing "QueueChannel implements IDeref"
    (is (isa? QueueChannel clojure.lang.IDeref)))

  (testing "QueueChannel implements IBlockingDeref"
    (is (isa? QueueChannel clojure.lang.IBlockingDeref)))

  (testing "QueueChannel implements ITransientCollection"
    (is (isa? QueueChannel clojure.lang.ITransientCollection)))

  (testing "QueueChannel implements Closeable"
    (is (isa? QueueChannel java.io.Closeable))))

(deftest test-stack-channel-protocols
  (testing "StackChannel implements IDeref"
    (is (isa? StackChannel clojure.lang.IDeref)))

  (testing "StackChannel implements IBlockingDeref"
    (is (isa? StackChannel clojure.lang.IBlockingDeref)))

  (testing "StackChannel implements ITransientCollection"
    (is (isa? StackChannel clojure.lang.ITransientCollection)))

  (testing "StackChannel implements Closeable"
    (is (isa? StackChannel java.io.Closeable))))

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
    (is (fn? refs/map-watch-changes)))

  (testing "Writable ref functions"
    (is (fn? refs/map-entry-ref))
    (is (fn? refs/queue-writer))
    (is (fn? refs/stack-writer))
    (is (fn? refs/queue-channel))
    (is (fn? refs/stack-channel))))

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

;; ============================================================================
;; MapEntryRef Behavioral Tests
;; ============================================================================

(deftest test-map-entry-ref-deref
  (testing "MapEntryRef deref reads value"
    (let [mock-map {:fd 999 :name "test-map" :key-size 4 :value-size 8}
          ref (refs/->MapEntryRef mock-map :counter
                                  (java.util.concurrent.atomic.AtomicReference. nil)
                                  nil
                                  (java.util.concurrent.atomic.AtomicBoolean. false))]
      (with-redefs [clj-ebpf.maps/map-lookup (fn [_ _] 42)]
        (is (= 42 @ref)))
      (.close ref))))

(deftest test-map-entry-ref-reset
  (testing "MapEntryRef reset! writes value"
    (let [mock-map {:fd 999 :name "test-map" :key-size 4 :value-size 8}
          written-value (atom nil)
          ref (refs/->MapEntryRef mock-map :counter
                                  (java.util.concurrent.atomic.AtomicReference. nil)
                                  nil
                                  (java.util.concurrent.atomic.AtomicBoolean. false))]
      (with-redefs [clj-ebpf.maps/map-update (fn [_ _ v] (reset! written-value v))]
        (reset! ref 100)
        (is (= 100 @written-value)))
      (.close ref))))

(deftest test-map-entry-ref-swap
  (testing "MapEntryRef swap! applies function"
    (let [mock-map {:fd 999 :name "test-map" :key-size 4 :value-size 8}
          current-value (atom 10)
          ref (refs/->MapEntryRef mock-map :counter
                                  (java.util.concurrent.atomic.AtomicReference. nil)
                                  nil
                                  (java.util.concurrent.atomic.AtomicBoolean. false))]
      (with-redefs [clj-ebpf.maps/map-lookup (fn [_ _] @current-value)
                    clj-ebpf.maps/map-update (fn [_ _ v] (reset! current-value v))]
        (let [result (swap! ref inc)]
          (is (= 11 result))
          (is (= 11 @current-value))))
      (.close ref))))

(deftest test-map-entry-ref-swap-with-args
  (testing "MapEntryRef swap! with additional arguments"
    (let [mock-map {:fd 999 :name "test-map" :key-size 4 :value-size 8}
          current-value (atom 10)
          ref (refs/->MapEntryRef mock-map :counter
                                  (java.util.concurrent.atomic.AtomicReference. nil)
                                  nil
                                  (java.util.concurrent.atomic.AtomicBoolean. false))]
      (with-redefs [clj-ebpf.maps/map-lookup (fn [_ _] @current-value)
                    clj-ebpf.maps/map-update (fn [_ _ v] (reset! current-value v))]
        ;; swap! with one arg
        (swap! ref + 5)
        (is (= 15 @current-value))

        ;; swap! with two args
        (swap! ref * 2 3)
        (is (= 90 @current-value)))  ; 15 * 2 * 3 = 90
      (.close ref))))

(deftest test-map-entry-ref-compare-and-set
  (testing "MapEntryRef compare-and-set! conditional update"
    (let [mock-map {:fd 999 :name "test-map" :key-size 4 :value-size 8}
          current-value (atom 10)
          ref (refs/->MapEntryRef mock-map :counter
                                  (java.util.concurrent.atomic.AtomicReference. nil)
                                  nil
                                  (java.util.concurrent.atomic.AtomicBoolean. false))]
      (with-redefs [clj-ebpf.maps/map-lookup (fn [_ _] @current-value)
                    clj-ebpf.maps/map-update (fn [_ _ v] (reset! current-value v))]
        ;; Should succeed when old value matches
        (is (true? (compare-and-set! ref 10 20)))
        (is (= 20 @current-value))

        ;; Should fail when old value doesn't match
        (is (false? (compare-and-set! ref 10 30)))
        (is (= 20 @current-value)))  ; unchanged
      (.close ref))))

(deftest test-map-entry-ref-validator
  (testing "MapEntryRef validator rejects invalid values"
    (let [mock-map {:fd 999 :name "test-map" :key-size 4 :value-size 8}
          ref (refs/->MapEntryRef mock-map :counter
                                  (java.util.concurrent.atomic.AtomicReference. nil)
                                  pos?  ; validator: must be positive
                                  (java.util.concurrent.atomic.AtomicBoolean. false))]
      (with-redefs [clj-ebpf.maps/map-update (fn [_ _ _] nil)]
        ;; Valid value should work
        (is (= 42 (reset! ref 42)))

        ;; Invalid value should throw
        (is (thrown? IllegalStateException
                     (reset! ref -1))))
      (.close ref))))

;; ============================================================================
;; QueueWriter/StackWriter Behavioral Tests
;; ============================================================================

(deftest test-queue-writer-conj
  (testing "QueueWriter conj! pushes values"
    (let [mock-map {:fd 999 :name "test-queue" :value-size 8}
          pushed-values (atom [])
          writer (refs/->QueueWriter mock-map (java.util.concurrent.atomic.AtomicBoolean. false))]
      (with-redefs [clj-ebpf.maps/queue-push (fn [_ v] (swap! pushed-values conj v))]
        (-> writer
            (conj! :a)
            (conj! :b)
            (conj! :c))
        (is (= [:a :b :c] @pushed-values)))
      (.close writer))))

(deftest test-queue-writer-deref-peeks
  (testing "QueueWriter deref peeks without removing"
    (let [mock-map {:fd 999 :name "test-queue" :value-size 8}
          writer (refs/->QueueWriter mock-map (java.util.concurrent.atomic.AtomicBoolean. false))]
      (with-redefs [clj-ebpf.maps/queue-peek (fn [_] :front-item)]
        (is (= :front-item @writer)))
      (.close writer))))

(deftest test-stack-writer-conj
  (testing "StackWriter conj! pushes values"
    (let [mock-map {:fd 999 :name "test-stack" :value-size 8}
          pushed-values (atom [])
          writer (refs/->StackWriter mock-map (java.util.concurrent.atomic.AtomicBoolean. false))]
      (with-redefs [clj-ebpf.maps/stack-push (fn [_ v] (swap! pushed-values conj v))]
        (conj! writer 1)
        (conj! writer 2)
        (conj! writer 3)
        (is (= [1 2 3] @pushed-values)))
      (.close writer))))

;; ============================================================================
;; QueueChannel/StackChannel Behavioral Tests
;; ============================================================================

(deftest test-queue-channel-bidirectional
  (testing "QueueChannel supports both read and write"
    (let [mock-map {:fd 999 :name "test-queue" :value-size 8}
          queue-data (atom [])
          channel (refs/->QueueChannel mock-map 5 (java.util.concurrent.atomic.AtomicBoolean. false))]

      (with-redefs [clj-ebpf.maps/queue-push (fn [_ v] (swap! queue-data conj v))
                    clj-ebpf.maps/queue-pop (fn [_]
                                              (when (seq @queue-data)
                                                (let [v (first @queue-data)]
                                                  (swap! queue-data rest)
                                                  v)))]
        ;; Write some values
        (conj! channel :first)
        (conj! channel :second)

        ;; Read them back (FIFO)
        (is (= :first (deref channel 100 :timeout)))
        (is (= :second (deref channel 100 :timeout)))

        ;; Queue is now empty, should timeout
        (is (= :timeout (deref channel 20 :timeout))))

      (.close channel))))

(deftest test-stack-channel-lifo-order
  (testing "StackChannel pops in LIFO order"
    (let [mock-map {:fd 999 :name "test-stack" :value-size 8}
          stack-data (atom [])
          channel (refs/->StackChannel mock-map 5 (java.util.concurrent.atomic.AtomicBoolean. false))]

      (with-redefs [clj-ebpf.maps/stack-push (fn [_ v] (swap! stack-data conj v))
                    clj-ebpf.maps/stack-pop (fn [_]
                                              (when (seq @stack-data)
                                                (let [v (peek @stack-data)]
                                                  (swap! stack-data pop)
                                                  v)))]
        ;; Push values
        (conj! channel :first)
        (conj! channel :second)
        (conj! channel :third)

        ;; Pop should be LIFO
        (is (= :third (deref channel 100 :timeout)))
        (is (= :second (deref channel 100 :timeout)))
        (is (= :first (deref channel 100 :timeout))))

      (.close channel))))

;; ============================================================================
;; Writable Macro Tests
;; ============================================================================

(deftest test-writable-macros-defined
  (testing "with-map-entry-ref macro is defined"
    (is (some? (ns-resolve 'clj-ebpf.refs 'with-map-entry-ref))))

  (testing "with-queue-writer macro is defined"
    (is (some? (ns-resolve 'clj-ebpf.refs 'with-queue-writer))))

  (testing "with-stack-writer macro is defined"
    (is (some? (ns-resolve 'clj-ebpf.refs 'with-stack-writer))))

  (testing "with-queue-channel macro is defined"
    (is (some? (ns-resolve 'clj-ebpf.refs 'with-queue-channel))))

  (testing "with-stack-channel macro is defined"
    (is (some? (ns-resolve 'clj-ebpf.refs 'with-stack-channel)))))
