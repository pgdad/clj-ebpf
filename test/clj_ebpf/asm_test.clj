(ns clj-ebpf.asm-test
  "Tests for label-based assembly utilities."
  (:require [clojure.test :refer [deftest testing is]]
            [clj-ebpf.asm :as asm]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.programs :as programs]))

;; ============================================================================
;; Label Tests
;; ============================================================================

(deftest test-label-creation
  (testing "Label creates correct structure"
    (let [lbl (asm/label :my-label)]
      (is (= {:type :label :name :my-label} lbl))))

  (testing "Label requires keyword name"
    (is (thrown? Exception (asm/label "not-a-keyword")))
    (is (thrown? Exception (asm/label 123)))))

(deftest test-label-predicate
  (testing "label? identifies labels"
    (is (asm/label? (asm/label :test)))
    (is (not (asm/label? (dsl/mov :r0 0))))
    (is (not (asm/label? {:type :jmp :target :foo})))
    (is (not (asm/label? nil)))))

;; ============================================================================
;; Symbolic Jump Tests
;; ============================================================================

(deftest test-symbolic-jumps
  (testing "jmp-imm with keyword creates symbolic jump"
    (let [insn (asm/jmp-imm :jeq :r0 0 :target)]
      (is (map? insn))
      (is (= :jmp-imm (:type insn)))
      (is (= :target (:target insn)))))

  (testing "jmp-imm with number returns bytecode"
    (let [insn (asm/jmp-imm :jeq :r0 0 5)]
      (is (bytes? insn))))

  (testing "jmp-reg with keyword creates symbolic jump"
    (let [insn (asm/jmp-reg :jgt :r0 :r1 :greater)]
      (is (map? insn))
      (is (= :jmp-reg (:type insn)))
      (is (= :greater (:target insn)))))

  (testing "jmp with keyword creates symbolic jump"
    (let [insn (asm/jmp :done)]
      (is (map? insn))
      (is (= :jmp (:type insn)))
      (is (= :done (:target insn)))))

  (testing "jmp with number returns bytecode"
    (let [insn (asm/jmp 5)]
      (is (bytes? insn)))))

(deftest test-symbolic-jump-predicate
  (testing "symbolic-jump? identifies symbolic jumps"
    (is (asm/symbolic-jump? (asm/jmp-imm :jeq :r0 0 :target)))
    (is (asm/symbolic-jump? (asm/jmp-reg :jgt :r0 :r1 :target)))
    (is (asm/symbolic-jump? (asm/jmp :target)))
    (is (not (asm/symbolic-jump? (asm/jmp 5))))
    (is (not (asm/symbolic-jump? (asm/label :foo))))
    (is (not (asm/symbolic-jump? (dsl/mov :r0 0))))))

;; ============================================================================
;; Label Resolution Tests
;; ============================================================================

(deftest test-simple-forward-jump
  (testing "Forward jump resolves correctly"
    ;; Position 0: jmp-imm to :target (offset should be 1)
    ;; Position 1: mov r0, 1
    ;; Position 2 (label :target): exit
    ;; offset = 2 - 0 - 1 = 1
    (let [resolved (asm/resolve-labels
                     [(asm/jmp-imm :jeq :r0 0 :target)
                      (dsl/mov :r0 1)
                      (asm/label :target)
                      (dsl/exit-insn)])]
      (is (= 3 (count resolved)))  ; label removed
      (is (every? bytes? resolved)))))

(deftest test-backward-jump
  (testing "Backward jump resolves correctly"
    ;; Position 0 (label :loop): mov r0, 1
    ;; Position 1: jmp to :loop
    ;; offset = 0 - 1 - 1 = -2
    (let [resolved (asm/resolve-labels
                     [(asm/label :loop)
                      (dsl/mov :r0 1)
                      (asm/jmp :loop)])]
      (is (= 2 (count resolved)))
      (is (every? bytes? resolved)))))

(deftest test-multiple-labels
  (testing "Multiple labels resolve correctly"
    ;; Position 0: jmp-imm to :a
    ;; Position 1: jmp-imm to :b
    ;; Position 2 (label :a): mov r0, 0
    ;; Position 3 (label :b): exit
    (let [resolved (asm/resolve-labels
                     [(asm/jmp-imm :jeq :r0 0 :a)
                      (asm/jmp-imm :jeq :r0 1 :b)
                      (asm/label :a)
                      (dsl/mov :r0 0)
                      (asm/label :b)
                      (dsl/exit-insn)])]
      (is (= 4 (count resolved))))))

(deftest test-adjacent-labels
  (testing "Adjacent labels resolve correctly"
    ;; Position 0: jmp to :second
    ;; Position 1 (labels :first and :second): exit
    (let [resolved (asm/resolve-labels
                     [(asm/jmp :second)
                      (asm/label :first)
                      (asm/label :second)
                      (dsl/exit-insn)])]
      (is (= 2 (count resolved))))))

(deftest test-undefined-label-error
  (testing "Undefined label throws error"
    (is (thrown-with-msg? Exception #"Undefined label"
          (asm/resolve-labels
            [(asm/jmp :nonexistent)
             (dsl/exit-insn)])))))

(deftest test-duplicate-label-error
  (testing "Duplicate label throws error"
    (is (thrown-with-msg? Exception #"Duplicate label"
          (asm/resolve-labels
            [(asm/label :dup)
             (dsl/mov :r0 0)
             (asm/label :dup)
             (dsl/exit-insn)])))))

;; ============================================================================
;; Full Assembly Tests
;; ============================================================================

(deftest test-assemble-with-labels
  (testing "assemble-with-labels produces bytecode"
    (let [bytecode (asm/assemble-with-labels
                     [(dsl/mov :r0 0)
                      (asm/jmp-imm :jeq :r1 0 :done)
                      (dsl/mov :r0 1)
                      (asm/label :done)
                      (dsl/exit-insn)])]
      (is (bytes? bytecode))
      ;; 4 instructions * 8 bytes = 32 bytes
      (is (= 32 (count bytecode)))))

  (testing "Nested instruction sequences flatten correctly"
    (let [bytecode (asm/assemble-with-labels
                     [[(dsl/mov :r0 0)]
                      [(asm/jmp :done)]
                      [(asm/label :done)
                       (dsl/exit-insn)]])]
      (is (bytes? bytecode))
      ;; 3 instructions * 8 bytes = 24 bytes
      (is (= 24 (count bytecode))))))

(deftest test-check-bounds-helper
  (testing "check-bounds generates correct instructions"
    (let [insns (asm/check-bounds :r7 :r8 14 :fail :r9)]
      (is (= 3 (count insns)))
      ;; First two should be bytecode, last should be symbolic jump
      (is (bytes? (first insns)))
      (is (bytes? (second insns)))
      (is (asm/symbolic-jump? (nth insns 2))))))

;; ============================================================================
;; Integration Tests (require root for loading)
;; ============================================================================

(deftest test-xdp-program-with-labels
  (testing "XDP program with labels assembles correctly"
    (let [bytecode (asm/assemble-with-labels
                     [;; Save context
                      (dsl/mov-reg :r6 :r1)
                      ;; Load data pointers
                      (dsl/ldx :w :r7 :r6 0)
                      (dsl/ldx :w :r8 :r6 4)
                      ;; Check bounds - jump to :pass if fail
                      (asm/check-bounds :r7 :r8 14 :pass :r9)
                      ;; Load ethertype
                      (dsl/ldx :h :r9 :r7 12)
                      ;; Check for IPv4
                      (asm/jmp-imm :jne :r9 0x0008 :pass)
                      ;; IPv4 - could drop, but pass for test
                      (asm/jmp :pass)
                      ;; Pass block
                      (asm/label :pass)
                      (dsl/mov :r0 2)  ; XDP_PASS
                      (dsl/exit-insn)])]
      (is (bytes? bytecode))
      ;; Verify instruction count: 1 + 2 + 3 + 1 + 1 + 1 + 2 = 11 instructions
      ;; 11 * 8 = 88 bytes
      (is (= 88 (count bytecode))))))

(deftest test-tc-program-with-labels
  (testing "TC program with labels assembles correctly"
    (let [bytecode (asm/assemble-with-labels
                     [;; Save context
                      (dsl/mov-reg :r6 :r1)
                      ;; Load data pointers (TC offsets)
                      (dsl/ldx :w :r7 :r6 76)
                      (dsl/ldx :w :r8 :r6 80)
                      ;; Check bounds
                      (asm/check-bounds :r7 :r8 14 :ok :r9)
                      ;; Load ethertype
                      (dsl/ldx :h :r9 :r7 12)
                      ;; Check for IPv4
                      (asm/jmp-imm :jne :r9 0x0008 :ok)
                      ;; IPv4 handling
                      (asm/jmp :ok)
                      ;; OK block
                      (asm/label :ok)
                      (dsl/mov :r0 0)  ; TC_ACT_OK
                      (dsl/exit-insn)])]
      (is (bytes? bytecode))
      (is (= 88 (count bytecode))))))

;; Run these tests only when running as root
(deftest ^:integration test-load-program-with-labels
  (testing "Program with labels loads into kernel"
    (when (zero? (-> (Runtime/getRuntime)
                     (.exec "id -u")
                     (.getInputStream)
                     (slurp)
                     (.trim)
                     (Integer/parseInt)))
      (let [bytecode (asm/assemble-with-labels
                       [(dsl/mov :r0 2)  ; XDP_PASS
                        (asm/jmp-imm :jeq :r1 0 :done)
                        (dsl/mov :r0 1)  ; XDP_DROP
                        (asm/label :done)
                        (dsl/exit-insn)])
            prog (programs/load-program
                   {:insns bytecode
                    :prog-type :xdp
                    :prog-name "asm_test"
                    :license "GPL"})]
        (is (some? (:fd prog)))
        (programs/close-program prog)))))
