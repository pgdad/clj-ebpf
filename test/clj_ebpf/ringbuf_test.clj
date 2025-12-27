(ns clj-ebpf.ringbuf-test
  "Tests for ring buffer helpers - CI-safe"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.ringbuf :as rb]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.asm :as asm]))

(deftest test-constants
  (testing "BPF helper function IDs are correct"
    (is (= 130 rb/BPF-FUNC-ringbuf-output))
    (is (= 131 rb/BPF-FUNC-ringbuf-reserve))
    (is (= 132 rb/BPF-FUNC-ringbuf-submit))
    (is (= 133 rb/BPF-FUNC-ringbuf-discard))
    (is (= 134 rb/BPF-FUNC-ringbuf-query)))

  (testing "Ring buffer flags are correct"
    (is (= 1 rb/BPF-RB-NO-WAKEUP))
    (is (= 2 rb/BPF-RB-FORCE-WAKEUP)))

  (testing "Ring buffer query flags are correct"
    (is (= 0 rb/BPF-RB-AVAIL-DATA))
    (is (= 1 rb/BPF-RB-RING-SIZE))
    (is (= 2 rb/BPF-RB-CONS-POS))
    (is (= 3 rb/BPF-RB-PROD-POS))))

(deftest test-build-ringbuf-reserve
  (testing "build-ringbuf-reserve generates correct instructions"
    (let [instrs (rb/build-ringbuf-reserve 42 64)]
      ;; ld-map-fd takes 2 slots (16 bytes), mov, mov, call
      (is (= 4 (count instrs)))
      ;; First instruction is ld-map-fd (16 bytes)
      (is (= 16 (count (first instrs))))
      ;; Rest are 8 bytes each
      (is (every? #(= 8 (count %)) (rest instrs)))))

  (testing "build-ringbuf-reserve with flags"
    (let [instrs (rb/build-ringbuf-reserve 42 64 rb/BPF-RB-NO-WAKEUP)]
      (is (= 4 (count instrs))))))

(deftest test-build-ringbuf-submit
  (testing "build-ringbuf-submit generates 3 instructions"
    (let [instrs (rb/build-ringbuf-submit :r9)]
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-ringbuf-submit with flags"
    (let [instrs (rb/build-ringbuf-submit :r9 rb/BPF-RB-NO-WAKEUP)]
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-build-ringbuf-discard
  (testing "build-ringbuf-discard generates 3 instructions"
    (let [instrs (rb/build-ringbuf-discard :r9)]
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-ringbuf-discard with flags"
    (let [instrs (rb/build-ringbuf-discard :r9 rb/BPF-RB-NO-WAKEUP)]
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-build-ringbuf-output
  (testing "build-ringbuf-output generates correct instructions"
    (let [instrs (rb/build-ringbuf-output 42 :r6 64 0)]
      ;; ld-map-fd (2 slots), mov-reg, mov, mov, call
      (is (= 5 (count instrs)))
      (is (= 16 (count (first instrs))))
      (is (every? #(= 8 (count %)) (rest instrs))))))

(deftest test-build-ringbuf-query
  (testing "build-ringbuf-query generates correct instructions"
    (let [instrs (rb/build-ringbuf-query 42 rb/BPF-RB-RING-SIZE)]
      ;; ld-map-fd (2 slots), mov, call
      (is (= 3 (count instrs)))
      (is (= 16 (count (first instrs))))))

  (testing "build-ringbuf-query with different query types"
    (doseq [query-type [rb/BPF-RB-AVAIL-DATA
                        rb/BPF-RB-RING-SIZE
                        rb/BPF-RB-CONS-POS
                        rb/BPF-RB-PROD-POS]]
      (let [instrs (rb/build-ringbuf-query 42 query-type)]
        (is (= 3 (count instrs)))))))

(deftest test-write-helpers
  (testing "build-write-u64-to-ringbuf generates 1 instruction"
    (let [instrs (rb/build-write-u64-to-ringbuf :r9 0 :r0)]
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs)))))

  (testing "build-write-u32-to-ringbuf generates 1 instruction"
    (let [instrs (rb/build-write-u32-to-ringbuf :r9 0 :r0)]
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs))))))

(deftest test-complete-event-output
  (testing "Complete reserve/write/submit pattern assembles"
    (let [ringbuf-fd 42
          program (concat
                    ;; Reserve 32 bytes
                    (rb/build-ringbuf-reserve ringbuf-fd 32)
                    ;; Check for NULL
                    [(dsl/jmp-imm :jeq :r0 0 8)]  ; jump to exit if NULL
                    ;; Save pointer
                    [(dsl/mov-reg :r9 :r0)]
                    ;; Write timestamp to ringbuf
                    [(dsl/call 5)]  ; ktime_get_ns
                    (rb/build-write-u64-to-ringbuf :r9 0 :r0)
                    ;; Submit
                    (rb/build-ringbuf-submit :r9)
                    ;; Return 0
                    [(dsl/mov :r0 0)
                     (dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; Count instructions: 4 (reserve) + 1 (jeq) + 1 (mov) + 1 (call) + 1 (stx) + 3 (submit) + 2 (exit)
      ;; But ld-map-fd is 16 bytes, so: 16 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 = 112
      (is (pos? (count bytecode))))))

(deftest test-ringbuf-output-pattern
  (testing "Direct output pattern assembles"
    (let [ringbuf-fd 42
          program (concat
                    ;; Assume data is on stack at r10-32
                    [(dsl/mov-reg :r6 :r10)
                     (dsl/add :r6 -32)]
                    ;; Output directly
                    (rb/build-ringbuf-output ringbuf-fd :r6 32 0)
                    ;; Return 0
                    [(dsl/mov :r0 0)
                     (dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode)))))

(deftest test-query-pattern
  (testing "Ring buffer query pattern assembles"
    (let [ringbuf-fd 42
          program (concat
                    ;; Query available data
                    (rb/build-ringbuf-query ringbuf-fd rb/BPF-RB-AVAIL-DATA)
                    ;; r0 now contains available bytes
                    [(dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode)))))

(deftest test-discard-pattern
  (testing "Reserve/discard pattern assembles"
    (let [ringbuf-fd 42
          program (concat
                    ;; Reserve space
                    (rb/build-ringbuf-reserve ringbuf-fd 64)
                    ;; Check for NULL
                    [(dsl/jmp-imm :jeq :r0 0 4)]
                    ;; Save pointer
                    [(dsl/mov-reg :r9 :r0)]
                    ;; Decide to discard
                    (rb/build-ringbuf-discard :r9)
                    ;; Return
                    [(dsl/mov :r0 0)
                     (dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode)))))
