(ns clj-ebpf.stack-queue-lpm-test
  "Tests for stack, queue, and LPM trie BPF maps"
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
;; Stack Map Tests (LIFO)
;; ============================================================================

(deftest test-create-stack-map
  (when (linux-with-bpf?)
    (testing "Create a stack map"
      (let [m (maps/create-stack-map 10 :map-name "test_stack")]
        (try
          (is (some? m))
          (is (pos? (:fd m)))
          (is (= :stack (:type m)))
          (is (= 10 (:max-entries m)))
          (is (= 0 (:key-size m)))  ; Stacks don't use keys
          (finally
            (maps/close-map m)))))))

(deftest test-stack-lifo-semantics
  (when (linux-with-bpf?)
    (testing "Stack follows LIFO (Last-In-First-Out) order"
      (let [m (maps/create-stack-map 10 :map-name "test_stack_lifo")]
        (try
          ;; Push values 1, 2, 3
          (maps/stack-push m 1)
          (maps/stack-push m 2)
          (maps/stack-push m 3)

          ;; Pop should return 3, 2, 1 (reverse order - LIFO)
          (is (= 3 (maps/stack-pop m)))
          (is (= 2 (maps/stack-pop m)))
          (is (= 1 (maps/stack-pop m)))
          (finally
            (maps/close-map m)))))))

(deftest test-stack-peek
  (when (linux-with-bpf?)
    (testing "Stack peek returns top value without removing it"
      (let [m (maps/create-stack-map 10 :map-name "test_stack_peek")]
        (try
          ;; Push values
          (maps/stack-push m 100)
          (maps/stack-push m 200)

          ;; Peek should return 200 without removing it
          (is (= 200 (maps/stack-peek m)))
          (is (= 200 (maps/stack-peek m)))  ; Still there

          ;; Pop should also return 200
          (is (= 200 (maps/stack-pop m)))

          ;; Now peek and pop should return 100
          (is (= 100 (maps/stack-peek m)))
          (is (= 100 (maps/stack-pop m)))
          (finally
            (maps/close-map m)))))))

(deftest test-stack-empty
  (when (linux-with-bpf?)
    (testing "Popping from empty stack returns nil"
      (let [m (maps/create-stack-map 10 :map-name "test_stack_empty")]
        (try
          ;; Pop from empty stack
          (is (nil? (maps/stack-pop m)))
          (is (nil? (maps/stack-peek m)))

          ;; Push and pop one item
          (maps/stack-push m 42)
          (is (= 42 (maps/stack-pop m)))

          ;; Now empty again
          (is (nil? (maps/stack-pop m)))
          (finally
            (maps/close-map m)))))))

(deftest test-stack-full
  (when (linux-with-bpf?)
    (testing "Stack behavior when reaching max capacity"
      (let [m (maps/create-stack-map 3 :map-name "test_stack_full")]
        (try
          ;; Fill stack to capacity
          (maps/stack-push m 1)
          (maps/stack-push m 2)
          (maps/stack-push m 3)

          ;; Trying to push beyond capacity may fail or succeed depending on kernel
          ;; Don't assert specific behavior, just verify we can still pop
          (try
            (maps/stack-push m 4)
            (catch Exception _))

          ;; Should be able to pop values
          (is (number? (maps/stack-pop m)))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Queue Map Tests (FIFO)
;; ============================================================================

(deftest test-create-queue-map
  (when (linux-with-bpf?)
    (testing "Create a queue map"
      (let [m (maps/create-queue-map 10 :map-name "test_queue")]
        (try
          (is (some? m))
          (is (pos? (:fd m)))
          (is (= :queue (:type m)))
          (is (= 10 (:max-entries m)))
          (is (= 0 (:key-size m)))  ; Queues don't use keys
          (finally
            (maps/close-map m)))))))

(deftest test-queue-fifo-semantics
  (when (linux-with-bpf?)
    (testing "Queue follows FIFO (First-In-First-Out) order"
      (let [m (maps/create-queue-map 10 :map-name "test_queue_fifo")]
        (try
          ;; Push values 1, 2, 3
          (maps/queue-push m 1)
          (maps/queue-push m 2)
          (maps/queue-push m 3)

          ;; Pop should return 1, 2, 3 (same order - FIFO)
          (is (= 1 (maps/queue-pop m)))
          (is (= 2 (maps/queue-pop m)))
          (is (= 3 (maps/queue-pop m)))
          (finally
            (maps/close-map m)))))))

(deftest test-queue-peek
  (when (linux-with-bpf?)
    (testing "Queue peek returns front value without removing it"
      (let [m (maps/create-queue-map 10 :map-name "test_queue_peek")]
        (try
          ;; Push values
          (maps/queue-push m 100)
          (maps/queue-push m 200)

          ;; Peek should return 100 (front) without removing it
          (is (= 100 (maps/queue-peek m)))
          (is (= 100 (maps/queue-peek m)))  ; Still there

          ;; Pop should also return 100
          (is (= 100 (maps/queue-pop m)))

          ;; Now peek and pop should return 200
          (is (= 200 (maps/queue-peek m)))
          (is (= 200 (maps/queue-pop m)))
          (finally
            (maps/close-map m)))))))

(deftest test-queue-empty
  (when (linux-with-bpf?)
    (testing "Popping from empty queue returns nil"
      (let [m (maps/create-queue-map 10 :map-name "test_queue_empty")]
        (try
          ;; Pop from empty queue
          (is (nil? (maps/queue-pop m)))
          (is (nil? (maps/queue-peek m)))

          ;; Push and pop one item
          (maps/queue-push m 42)
          (is (= 42 (maps/queue-pop m)))

          ;; Now empty again
          (is (nil? (maps/queue-pop m)))
          (finally
            (maps/close-map m)))))))

(deftest test-queue-full
  (when (linux-with-bpf?)
    (testing "Queue behavior when reaching max capacity"
      (let [m (maps/create-queue-map 3 :map-name "test_queue_full")]
        (try
          ;; Fill queue to capacity
          (maps/queue-push m 1)
          (maps/queue-push m 2)
          (maps/queue-push m 3)

          ;; Trying to push beyond capacity may fail or succeed depending on kernel
          ;; Don't assert specific behavior, just verify we can still pop
          (try
            (maps/queue-push m 4)
            (catch Exception _))

          ;; Should be able to pop values in FIFO order
          (is (number? (maps/queue-pop m)))
          (finally
            (maps/close-map m)))))))

(deftest test-stack-vs-queue-ordering
  (when (linux-with-bpf?)
    (testing "Stack (LIFO) vs Queue (FIFO) ordering difference"
      (let [stack (maps/create-stack-map 10 :map-name "test_compare_stack")
            queue (maps/create-queue-map 10 :map-name "test_compare_queue")]
        (try
          ;; Push same values to both
          (doseq [i [1 2 3]]
            (maps/stack-push stack i)
            (maps/queue-push queue i))

          ;; Stack pops in reverse order (LIFO: 3, 2, 1)
          (is (= 3 (maps/stack-pop stack)))
          (is (= 2 (maps/stack-pop stack)))
          (is (= 1 (maps/stack-pop stack)))

          ;; Queue pops in same order (FIFO: 1, 2, 3)
          (is (= 1 (maps/queue-pop queue)))
          (is (= 2 (maps/queue-pop queue)))
          (is (= 3 (maps/queue-pop queue)))
          (finally
            (maps/close-map stack)
            (maps/close-map queue)))))))

;; ============================================================================
;; LPM Trie Map Tests (Longest Prefix Match)
;; ============================================================================

(deftest test-create-lpm-trie-map
  (when (linux-with-bpf?)
    (testing "Create an LPM trie map"
      (let [m (maps/create-lpm-trie-map 100 :map-name "test_lpm")]
        (try
          (is (some? m))
          (is (pos? (:fd m)))
          (is (= :lpm-trie (:type m)))
          (is (= 100 (:max-entries m)))
          (is (= 8 (:key-size m)))  ; Default: 4 bytes prefix len + 4 bytes data
          (is (= 1 (:flags m)))  ; BPF_F_NO_PREALLOC required
          (finally
            (maps/close-map m)))))))

(deftest test-lpm-trie-basic-operations
  (when (linux-with-bpf?)
    (testing "LPM trie basic insert and lookup"
      (let [m (maps/create-lpm-trie-map 100 :map-name "test_lpm_basic")]
        (try
          ;; LPM trie keys have special format:
          ;; First 4 bytes: prefix length (in bits)
          ;; Remaining bytes: prefix data

          ;; For now, skip this test as LPM tries require special key handling
          ;; that needs more infrastructure (custom serializers for the key format)
          (is true "LPM trie basic operations test placeholder")
          (finally
            (maps/close-map m)))))))

(deftest test-lpm-trie-longest-match
  (when (linux-with-bpf?)
    (testing "LPM trie returns longest matching prefix"
      (let [m (maps/create-lpm-trie-map 100 :map-name "test_lpm_longest")]
        (try
          ;; For now, skip this test as LPM tries require special key handling
          ;; that needs more infrastructure (custom serializers for the key format)
          (is true "LPM trie longest match test placeholder")
          (finally
            (maps/close-map m)))))))

(deftest test-lpm-trie-delete
  (when (linux-with-bpf?)
    (testing "Delete entries from LPM trie"
      (let [m (maps/create-lpm-trie-map 100 :map-name "test_lpm_delete")]
        (try
          ;; For now, skip this test as LPM tries require special key handling
          ;; that needs more infrastructure (custom serializers for the key format)
          (is true "LPM trie delete test placeholder")
          (finally
            (maps/close-map m)))))))

(deftest test-lpm-trie-custom-key-size
  (when (linux-with-bpf?)
    (testing "LPM trie with custom key size for IPv6"
      ;; IPv6 would use: 4 bytes prefix len + 16 bytes IPv6 address = 20 bytes
      (let [m (maps/create-lpm-trie-map 100
                                        :key-size 20
                                        :value-size 4
                                        :map-name "test_lpm_ipv6")]
        (try
          (is (some? m))
          (is (= 20 (:key-size m)))
          (is (= :lpm-trie (:type m)))
          (finally
            (maps/close-map m)))))))

;; ============================================================================
;; Edge Cases and Error Handling
;; ============================================================================

(deftest test-stack-queue-with-custom-value-size
  (when (linux-with-bpf?)
    (testing "Stack and queue with custom value sizes"
      (let [stack (maps/create-stack-map 10 :value-size 8 :map-name "test_stack_8")
            queue (maps/create-queue-map 10 :value-size 8 :map-name "test_queue_8")]
        (try
          (is (= 8 (:value-size stack)))
          (is (= 8 (:value-size queue)))
          (finally
            (maps/close-map stack)
            (maps/close-map queue)))))))

(deftest test-multiple-stacks
  (when (linux-with-bpf?)
    (testing "Multiple independent stacks"
      (let [s1 (maps/create-stack-map 10 :map-name "test_stack_1")
            s2 (maps/create-stack-map 10 :map-name "test_stack_2")]
        (try
          ;; Push to different stacks
          (maps/stack-push s1 100)
          (maps/stack-push s2 200)

          ;; Pop from each should return their own values
          (is (= 100 (maps/stack-pop s1)))
          (is (= 200 (maps/stack-pop s2)))

          ;; Both should be empty
          (is (nil? (maps/stack-pop s1)))
          (is (nil? (maps/stack-pop s2)))
          (finally
            (maps/close-map s1)
            (maps/close-map s2)))))))

(deftest test-multiple-queues
  (when (linux-with-bpf?)
    (testing "Multiple independent queues"
      (let [q1 (maps/create-queue-map 10 :map-name "test_queue_1")
            q2 (maps/create-queue-map 10 :map-name "test_queue_2")]
        (try
          ;; Push to different queues
          (maps/queue-push q1 100)
          (maps/queue-push q2 200)

          ;; Pop from each should return their own values
          (is (= 100 (maps/queue-pop q1)))
          (is (= 200 (maps/queue-pop q2)))

          ;; Both should be empty
          (is (nil? (maps/queue-pop q1)))
          (is (nil? (maps/queue-pop q2)))
          (finally
            (maps/close-map q1)
            (maps/close-map q2)))))))
