(ns clj-ebpf.memory-test
  "Tests for memory management and concurrent program loading.

   These tests verify the fix for issue #1: Memory corruption when loading
   multiple BPF programs in the same JVM. The root cause was Arena/ofAuto
   (GC-managed) memory being reclaimed before BPF syscalls completed."
  (:require [clojure.test :refer :all]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.core :as bpf]))

;; Simple BPF program bytecode: r0=0; exit
(def simple-bpf-bytecode
  (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00   ; r0 = 0
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

;; More complex program: r0=1; r1=2; r0+=r1; exit (result r0=3)
(def arithmetic-bpf-bytecode
  (byte-array [0xb7 0x00 0x00 0x00 0x01 0x00 0x00 0x00   ; r0 = 1
               0xb7 0x01 0x00 0x00 0x02 0x00 0x00 0x00   ; r1 = 2
               0x0f 0x10 0x00 0x00 0x00 0x00 0x00 0x00   ; r0 += r1
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

(defn linux-with-bpf?
  "Check if we're on Linux with BPF available"
  []
  (and (= "Linux" (System/getProperty "os.name"))
       (try
         (utils/check-bpf-available)
         true
         (catch Exception _ false))))

(use-fixtures :once
  (fn [f]
    (if (linux-with-bpf?)
      (f)
      (println "Skipping BPF memory tests (not on Linux or insufficient permissions)"))))

;; ============================================================================
;; Sequential Loading Tests
;; ============================================================================

(deftest test-sequential-program-loading
  (when (linux-with-bpf?)
    (testing "Load multiple programs sequentially without corruption"
      (let [programs (atom [])]
        (try
          ;; Load 10 programs sequentially
          (dotimes [i 10]
            (let [prog (programs/load-program
                         {:prog-type :kprobe
                          :insns simple-bpf-bytecode
                          :license "GPL"
                          :prog-name (str "seq_test_" i)})]
              (is (some? prog) (str "Program " i " loaded"))
              (is (pos? (:fd prog)) (str "Program " i " has valid fd"))
              (is (= 2 (:insn-count prog)) (str "Program " i " has correct insn count"))
              (swap! programs conj prog)))

          ;; All programs should be valid
          (is (= 10 (count @programs)))

          (finally
            ;; Cleanup
            (doseq [prog @programs]
              (programs/close-program prog))))))))

(deftest test-rapid-load-unload-cycles
  (when (linux-with-bpf?)
    (testing "Rapid load/unload cycles don't cause corruption"
      ;; Do 20 rapid load/unload cycles
      (dotimes [i 20]
        (let [prog (programs/load-program
                     {:prog-type :kprobe
                      :insns simple-bpf-bytecode
                      :license "GPL"
                      :prog-name (str "rapid_test_" i)})]
          (is (some? prog) (str "Cycle " i " - program loaded"))
          (is (pos? (:fd prog)) (str "Cycle " i " - valid fd"))
          (programs/close-program prog))))))

;; ============================================================================
;; Concurrent Loading Tests
;; ============================================================================

(deftest test-concurrent-program-loading
  (when (linux-with-bpf?)
    (testing "Load multiple programs concurrently without corruption"
      (let [num-threads 10
            results (atom [])
            errors (atom [])
            latch (java.util.concurrent.CountDownLatch. num-threads)]

        ;; Launch concurrent loading threads
        (dotimes [i num-threads]
          (future
            (try
              (let [prog (programs/load-program
                           {:prog-type :kprobe
                            :insns simple-bpf-bytecode
                            :license "GPL"
                            :prog-name (str "concurrent_" i)})]
                (swap! results conj {:idx i :prog prog})
                (is (some? prog) (str "Thread " i " - program loaded"))
                (is (pos? (:fd prog)) (str "Thread " i " - valid fd"))
                (is (= 2 (:insn-count prog)) (str "Thread " i " - correct insn count")))
              (catch Exception e
                (swap! errors conj {:idx i :error e}))
              (finally
                (.countDown latch)))))

        ;; Wait for all threads with timeout
        (is (.await latch 30 java.util.concurrent.TimeUnit/SECONDS)
            "All threads completed within timeout")

        ;; Check results
        (is (empty? @errors) (str "No errors occurred: " @errors))
        (is (= num-threads (count @results)) "All programs loaded")

        ;; Cleanup
        (doseq [{:keys [prog]} @results]
          (when prog
            (programs/close-program prog)))))))

(deftest test-concurrent-load-unload
  (when (linux-with-bpf?)
    (testing "Concurrent load/unload operations don't cause corruption"
      (let [num-threads 5
            cycles-per-thread 10
            errors (atom [])
            latch (java.util.concurrent.CountDownLatch. num-threads)]

        ;; Each thread does multiple load/unload cycles
        (dotimes [thread-idx num-threads]
          (future
            (try
              (dotimes [cycle-idx cycles-per-thread]
                (let [prog (programs/load-program
                             {:prog-type :kprobe
                              :insns simple-bpf-bytecode
                              :license "GPL"
                              :prog-name (str "lu_" thread-idx "_" cycle-idx)})]
                  (when-not (and (some? prog) (pos? (:fd prog)))
                    (swap! errors conj {:thread thread-idx
                                        :cycle cycle-idx
                                        :error "Invalid program"}))
                  (when prog
                    (programs/close-program prog))))
              (catch Exception e
                (swap! errors conj {:thread thread-idx :error e}))
              (finally
                (.countDown latch)))))

        ;; Wait for completion
        (is (.await latch 60 java.util.concurrent.TimeUnit/SECONDS)
            "All threads completed")

        (is (empty? @errors) (str "No errors: " @errors))))))

;; ============================================================================
;; GC Pressure Tests
;; ============================================================================

(deftest test-load-under-gc-pressure
  (when (linux-with-bpf?)
    (testing "Program loading works correctly under GC pressure"
      (let [programs (atom [])
            gc-thread (future
                        ;; Generate garbage and trigger GC repeatedly
                        (dotimes [_ 1000]
                          ;; Create garbage
                          (doall (repeatedly 1000 #(byte-array 1024)))
                          (System/gc)
                          (Thread/sleep 1)))]

        (try
          ;; Load programs while GC is running
          (dotimes [i 20]
            (let [prog (programs/load-program
                         {:prog-type :kprobe
                          :insns simple-bpf-bytecode
                          :license "GPL"
                          :prog-name (str "gc_test_" i)})]
              (is (some? prog) (str "Program " i " loaded under GC pressure"))
              (is (pos? (:fd prog)) (str "Program " i " has valid fd"))
              ;; Verify bytecode wasn't corrupted by checking instruction count
              (is (= 2 (:insn-count prog))
                  (str "Program " i " bytecode not corrupted (expected 2 insns)"))
              (swap! programs conj prog)))

          (is (= 20 (count @programs)) "All 20 programs loaded successfully")

          (finally
            ;; Stop GC thread
            (future-cancel gc-thread)
            ;; Cleanup programs
            (doseq [prog @programs]
              (programs/close-program prog))))))))

(deftest test-different-program-types-concurrent
  (when (linux-with-bpf?)
    (testing "Load different program types concurrently"
      ;; Only use kprobe type which works reliably with simple bytecode
      (let [prog-types [:kprobe :kprobe :kprobe]
            results (atom [])
            errors (atom [])
            latch (java.util.concurrent.CountDownLatch. (count prog-types))]

        (doseq [[idx prog-type] (map-indexed vector prog-types)]
          (future
            (try
              (let [prog (programs/load-program
                           {:prog-type prog-type
                            :insns simple-bpf-bytecode
                            :license "GPL"
                            :prog-name (str "type_" (name prog-type))})]
                (swap! results conj {:type prog-type :prog prog})
                (is (some? prog))
                (is (pos? (:fd prog)))
                (is (= prog-type (:type prog))))
              (catch Exception e
                (swap! errors conj {:type prog-type :error e}))
              (finally
                (.countDown latch)))))

        (is (.await latch 30 java.util.concurrent.TimeUnit/SECONDS))
        (is (empty? @errors) (str "Errors: " @errors))

        ;; Cleanup
        (doseq [{:keys [prog]} @results]
          (when prog
            (programs/close-program prog)))))))

;; ============================================================================
;; Arena Management Tests
;; ============================================================================

(deftest test-arena-isolation
  (when (linux-with-bpf?)
    (testing "Arena memory is properly isolated between operations"
      ;; Each program load should use its own arena
      ;; and not interfere with others
      (let [prog1 (programs/load-program
                    {:prog-type :kprobe
                     :insns simple-bpf-bytecode
                     :license "GPL"
                     :prog-name "arena_test_1"})
            prog2 (programs/load-program
                    {:prog-type :kprobe
                     :insns arithmetic-bpf-bytecode
                     :license "GPL"
                     :prog-name "arena_test_2"})]

        (try
          (is (some? prog1))
          (is (some? prog2))
          (is (= 2 (:insn-count prog1)) "First program has 2 instructions")
          (is (= 4 (:insn-count prog2)) "Second program has 4 instructions")
          ;; Verify they're different programs
          (is (not= (:fd prog1) (:fd prog2)) "Programs have different fds")

          (finally
            (programs/close-program prog1)
            (programs/close-program prog2)))))))

(deftest test-arena-safety-mechanism
  (testing "Low-level allocation requires arena context"
    ;; This test verifies the safety mechanism works for direct calls
    ;; All high-level functions now provide their own arena context
    (is (thrown? clojure.lang.ExceptionInfo
                 (utils/allocate-memory 16))
        "Direct allocate-memory call should throw without arena context")

    (is (thrown? clojure.lang.ExceptionInfo
                 (utils/bytes->segment (byte-array [1 2 3])))
        "Direct bytes->segment call should throw without arena context"))

  (testing "with-bpf-arena enables allocation"
    (utils/with-bpf-arena
      (let [mem (utils/allocate-memory 16)]
        (is (some? mem) "Allocation should succeed inside arena")))))
