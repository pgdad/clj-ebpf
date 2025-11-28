(ns clj-ebpf.dsl-test
  "Tests for BPF DSL - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-instruction-classes
  (testing "Instruction class constants"
    (is (= 0x00 (:ld dsl/instruction-class)))
    (is (= 0x01 (:ldx dsl/instruction-class)))
    (is (= 0x02 (:st dsl/instruction-class)))
    (is (= 0x03 (:stx dsl/instruction-class)))
    (is (= 0x04 (:alu dsl/instruction-class)))
    (is (= 0x05 (:jmp dsl/instruction-class)))
    (is (= 0x06 (:jmp32 dsl/instruction-class)))
    (is (= 0x07 (:alu64 dsl/instruction-class)))))

(deftest test-alu-operations
  (testing "ALU operation codes"
    (is (= 0x00 (:add dsl/alu-op)))
    (is (= 0x10 (:sub dsl/alu-op)))
    (is (= 0x20 (:mul dsl/alu-op)))
    (is (= 0xb0 (:mov dsl/alu-op)))
    (is (= 0x40 (:or dsl/alu-op)))
    (is (= 0x50 (:and dsl/alu-op)))
    (is (= 0xa0 (:xor dsl/alu-op)))))

(deftest test-jump-operations
  (testing "Jump operation codes"
    (is (= 0x00 (:ja dsl/jmp-op)))
    (is (= 0x10 (:jeq dsl/jmp-op)))
    (is (= 0x20 (:jgt dsl/jmp-op)))
    (is (= 0x80 (:call dsl/jmp-op)))
    (is (= 0x90 (:exit dsl/jmp-op)))))

(deftest test-registers
  (testing "Register mapping"
    (is (= 0 (:r0 dsl/registers)))
    (is (= 1 (:r1 dsl/registers)))
    (is (= 5 (:r5 dsl/registers)))
    (is (= 10 (:r10 dsl/registers)))))

(deftest test-xdp-actions
  (testing "XDP action codes"
    (is (= 0 (:aborted dsl/xdp-action)))
    (is (= 1 (:drop dsl/xdp-action)))
    (is (= 2 (:pass dsl/xdp-action)))
    (is (= 3 (:tx dsl/xdp-action)))
    (is (= 4 (:redirect dsl/xdp-action)))))

(deftest test-tc-actions
  (testing "TC action codes"
    (is (= -1 (:unspec dsl/tc-action)))
    (is (= 0 (:ok dsl/tc-action)))
    (is (= 2 (:shot dsl/tc-action)))))

(deftest test-bpf-helpers
  (testing "BPF helper function IDs"
    (is (= 1 (:map-lookup-elem dsl/bpf-helpers)))
    (is (= 2 (:map-update-elem dsl/bpf-helpers)))
    (is (= 5 (:ktime-get-ns dsl/bpf-helpers)))
    (is (= 6 (:trace-printk dsl/bpf-helpers)))
    (is (= 14 (:get-current-pid-tgid dsl/bpf-helpers)))))

;; ============================================================================
;; Instruction Building Tests
;; ============================================================================

(deftest test-mov-immediate
  (testing "MOV immediate instruction"
    (let [insn (dsl/mov :r0 42)]
      (is (= 8 (count insn)))
      ;; Check opcode: ALU64 | K | MOV
      (is (= (unchecked-byte 0xb7) (aget insn 0))))))

(deftest test-mov-register
  (testing "MOV register instruction"
    (let [insn (dsl/mov-reg :r0 :r1)]
      (is (= 8 (count insn)))
      ;; Check opcode: ALU64 | X | MOV
      (is (= (unchecked-byte 0xbf) (aget insn 0))))))

(deftest test-add-immediate
  (testing "ADD immediate instruction"
    (let [insn (dsl/add :r0 10)]
      (is (= 8 (count insn)))
      ;; Check opcode: ALU64 | K | ADD
      (is (= (unchecked-byte 0x07) (aget insn 0))))))

(deftest test-add-register
  (testing "ADD register instruction"
    (let [insn (dsl/add-reg :r0 :r1)]
      (is (= 8 (count insn)))
      ;; Check opcode: ALU64 | X | ADD
      (is (= (unchecked-byte 0x0f) (aget insn 0))))))

(deftest test-exit-instruction
  (testing "EXIT instruction"
    (let [insn (dsl/exit-insn)]
      (is (= 8 (count insn)))
      ;; Check opcode: JMP | EXIT
      (is (= (unchecked-byte 0x95) (aget insn 0))))))

(deftest test-call-instruction
  (testing "CALL helper instruction"
    (let [insn (dsl/call 5)]  ; ktime-get-ns
      (is (= 8 (count insn)))
      ;; Check opcode: JMP | CALL
      (is (= (unchecked-byte 0x85) (aget insn 0))))))

;; ============================================================================
;; ALU Operations Tests
;; ============================================================================

(deftest test-alu-operations-encoding
  (testing "Various ALU operations"
    ;; SUB
    (let [insn (dsl/sub :r0 5)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x17) (aget insn 0))))

    ;; MUL
    (let [insn (dsl/mul :r0 2)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x27) (aget insn 0))))

    ;; AND
    (let [insn (dsl/and-op :r0 0xFF)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x57) (aget insn 0))))

    ;; OR
    (let [insn (dsl/or-op :r0 0x10)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x47) (aget insn 0))))

    ;; XOR
    (let [insn (dsl/xor-op :r0 0xFF)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0xa7) (aget insn 0))))

    ;; LSH (left shift)
    (let [insn (dsl/lsh :r0 8)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x67) (aget insn 0))))

    ;; RSH (right shift)
    (let [insn (dsl/rsh :r0 8)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x77) (aget insn 0))))

    ;; NEG (negate)
    (let [insn (dsl/neg-reg :r0)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x87) (aget insn 0))))))

;; ============================================================================
;; Jump Operations Tests
;; ============================================================================

(deftest test-jump-operations-encoding
  (testing "Various jump operations"
    ;; JA (unconditional jump)
    (let [insn (dsl/ja 10)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x05) (aget insn 0))))

    ;; JEQ immediate
    (let [insn (dsl/jmp-imm :jeq :r0 0 5)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x15) (aget insn 0))))

    ;; JEQ register
    (let [insn (dsl/jmp-reg :jeq :r0 :r1 5)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x1d) (aget insn 0))))

    ;; JGT immediate
    (let [insn (dsl/jmp-imm :jgt :r0 100 3)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x25) (aget insn 0))))))

;; ============================================================================
;; Load/Store Operations Tests
;; ============================================================================

(deftest test-load-store-operations
  (testing "Load from memory (LDX)"
    ;; LDX DW (8 bytes)
    (let [insn (dsl/ldx :dw :r0 :r1 4)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x79) (aget insn 0))))

    ;; LDX W (4 bytes)
    (let [insn (dsl/ldx :w :r0 :r1 0)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x61) (aget insn 0))))

    ;; LDX H (2 bytes)
    (let [insn (dsl/ldx :h :r0 :r1 0)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x69) (aget insn 0))))

    ;; LDX B (1 byte)
    (let [insn (dsl/ldx :b :r0 :r1 0)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x71) (aget insn 0)))))

  (testing "Store to memory (STX)"
    ;; STX DW (8 bytes)
    (let [insn (dsl/stx :dw :r1 :r0 4)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x7b) (aget insn 0))))

    ;; STX W (4 bytes)
    (let [insn (dsl/stx :w :r1 :r0 0)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x63) (aget insn 0)))))

  (testing "Store immediate (ST)"
    ;; ST DW (8 bytes)
    (let [insn (dsl/st :dw :r1 4 42)]
      (is (= 8 (count insn)))
      (is (= (unchecked-byte 0x7a) (aget insn 0))))))

;; ============================================================================
;; Wide Instruction Tests
;; ============================================================================

(deftest test-wide-instruction
  (testing "LDDW (64-bit immediate load)"
    (let [insn (dsl/lddw :r0 0x123456789ABCDEF0)
          insn-vec (vec insn)]
      ;; Should be 16 bytes (2 instructions)
      (is (= 16 (count insn)))
      ;; First instruction opcode
      (is (= (unchecked-byte 0x18) (first insn-vec))))))

;; ============================================================================
;; Program Assembly Tests
;; ============================================================================

(deftest test-assemble-simple-program
  (testing "Assemble simple program"
    (let [bytecode (dsl/assemble [(dsl/mov :r0 0)
                                  (dsl/exit-insn)])]
      ;; Should be 16 bytes (2 instructions × 8 bytes)
      (is (= 16 (count bytecode)))
      ;; First instruction: MOV
      (is (= (unchecked-byte 0xb7) (aget bytecode 0)))
      ;; Second instruction: EXIT
      (is (= (unchecked-byte 0x95) (aget bytecode 8))))))

(deftest test-assemble-xdp-pass-program
  (testing "Assemble XDP PASS program"
    (let [bytecode (dsl/assemble [(dsl/mov :r0 (:pass dsl/xdp-action))
                                  (dsl/exit-insn)])]
      ;; Should be 16 bytes
      (is (= 16 (count bytecode)))
      ;; Verify it's valid bytecode
      (is (every? #(instance? Byte %) (seq bytecode))))))

(deftest test-assemble-tc-ok-program
  (testing "Assemble TC OK program"
    (let [bytecode (dsl/assemble [(dsl/mov :r0 (:ok dsl/tc-action))
                                  (dsl/exit-insn)])]
      ;; Should be 16 bytes
      (is (= 16 (count bytecode))))))

;; ============================================================================
;; Compile Program Tests
;; ============================================================================

(deftest test-compile-program
  (testing "Compile program at runtime"
    (let [bytecode (dsl/compile-program
                    (dsl/mov :r0 42)
                    (dsl/exit-insn))]
      (is (= 16 (count bytecode)))
      (is (= (unchecked-byte 0xb7) (aget bytecode 0)))
      (is (= (unchecked-byte 0x95) (aget bytecode 8))))))

;; ============================================================================
;; Complex Program Tests
;; ============================================================================

(deftest test-arithmetic-program
  (testing "Compile program with arithmetic"
    (let [bytecode (dsl/assemble [(dsl/mov :r0 10)
                                  (dsl/mov :r1 5)
                                  (dsl/add-reg :r0 :r1)  ; r0 = 10 + 5 = 15
                                  (dsl/exit-insn)])]
      ;; 4 instructions × 8 bytes = 32 bytes
      (is (= 32 (count bytecode))))))

(deftest test-conditional-program
  (testing "Compile program with conditional jump"
    (let [bytecode (dsl/assemble [(dsl/mov :r0 10)
                                  (dsl/jmp-imm :jeq :r0 10 1)  ; if r0 == 10 skip next
                                  (dsl/mov :r0 0)              ; skipped
                                  (dsl/exit-insn)])]
      ;; 4 instructions × 8 bytes = 32 bytes
      (is (= 32 (count bytecode))))))

(deftest test-load-store-program
  (testing "Compile program with load/store"
    (let [bytecode (dsl/assemble [;; Load from stack
                                  (dsl/ldx :dw :r0 :r10 -8)
                                  ;; Increment
                                  (dsl/add :r0 1)
                                  ;; Store back
                                  (dsl/stx :dw :r10 :r0 -8)
                                  (dsl/exit-insn)])]
      ;; 4 instructions × 8 bytes = 32 bytes
      (is (= 32 (count bytecode))))))

(deftest test-helper-call-program
  (testing "Compile program with helper call"
    (let [bytecode (dsl/assemble [(dsl/call (:ktime-get-ns dsl/bpf-helpers))
                                  (dsl/exit-insn)])]
      ;; 2 instructions × 8 bytes = 16 bytes
      (is (= 16 (count bytecode))))))

;; ============================================================================
;; Edge Cases Tests
;; ============================================================================

(deftest test-negative-immediate
  (testing "Negative immediate values"
    (let [insn (dsl/mov :r0 -1)]
      (is (= 8 (count insn))))))

(deftest test-large-immediate
  (testing "Large immediate values"
    (let [insn (dsl/mov :r0 0x7FFFFFFF)]
      (is (= 8 (count insn))))))

(deftest test-zero-immediate
  (testing "Zero immediate value"
    (let [insn (dsl/mov :r0 0)]
      (is (= 8 (count insn))))))

(deftest test-all-registers
  (testing "All registers can be used"
    (doseq [reg [:r0 :r1 :r2 :r3 :r4 :r5 :r6 :r7 :r8 :r9 :r10]]
      (let [insn (dsl/mov reg 0)]
        (is (= 8 (count insn)))))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-dsl-api-completeness
  (testing "Core DSL functions are available"
    ;; ALU operations
    (is (fn? dsl/mov))
    (is (fn? dsl/mov-reg))
    (is (fn? dsl/add))
    (is (fn? dsl/add-reg))
    (is (fn? dsl/sub))
    (is (fn? dsl/sub-reg))
    (is (fn? dsl/mul))
    (is (fn? dsl/mul-reg))
    (is (fn? dsl/and-op))
    (is (fn? dsl/and-reg))
    (is (fn? dsl/or-op))
    (is (fn? dsl/or-reg))
    (is (fn? dsl/xor-op))
    (is (fn? dsl/xor-reg))
    (is (fn? dsl/lsh))
    (is (fn? dsl/lsh-reg))
    (is (fn? dsl/rsh))
    (is (fn? dsl/rsh-reg))
    (is (fn? dsl/arsh))
    (is (fn? dsl/neg-reg))

    ;; Jump operations
    (is (fn? dsl/ja))
    (is (fn? dsl/jmp-imm))
    (is (fn? dsl/jmp-reg))
    (is (fn? dsl/call))
    (is (fn? dsl/exit-insn))

    ;; Load/store operations
    (is (fn? dsl/ldx))
    (is (fn? dsl/stx))
    (is (fn? dsl/st))
    (is (fn? dsl/lddw))

    ;; Assembly
    (is (fn? dsl/assemble))
    (is (fn? dsl/compile-program))))

;; ============================================================================
;; Documentation Tests
;; ============================================================================

(deftest test-function-metadata
  (testing "Key functions have docstrings"
    (is (string? (:doc (meta #'dsl/mov))))
    (is (string? (:doc (meta #'dsl/add))))
    (is (string? (:doc (meta #'dsl/exit-insn))))
    (is (string? (:doc (meta #'dsl/ldx))))
    (is (string? (:doc (meta #'dsl/stx))))
    (is (string? (:doc (meta #'dsl/assemble)))))

  (testing "Data structures have docstrings"
    (is (string? (:doc (meta #'dsl/registers))))
    (is (string? (:doc (meta #'dsl/xdp-action))))
    (is (string? (:doc (meta #'dsl/tc-action))))
    (is (string? (:doc (meta #'dsl/bpf-helpers))))))

;; ============================================================================
;; Example Programs Tests
;; ============================================================================

(deftest ^:example test-example-programs
  (testing "Example XDP DROP program"
    (let [xdp-drop (dsl/assemble [(dsl/mov :r0 (:drop dsl/xdp-action))
                                  (dsl/exit-insn)])]
      (is (= 16 (count xdp-drop)))))

  (testing "Example XDP PASS program"
    (let [xdp-pass (dsl/assemble [(dsl/mov :r0 (:pass dsl/xdp-action))
                                  (dsl/exit-insn)])]
      (is (= 16 (count xdp-pass)))))

  (testing "Example TC OK program"
    (let [tc-ok (dsl/assemble [(dsl/mov :r0 (:ok dsl/tc-action))
                               (dsl/exit-insn)])]
      (is (= 16 (count tc-ok)))))

  (testing "Example arithmetic program"
    (let [arithmetic (dsl/assemble [(dsl/mov :r0 100)
                                    (dsl/mov :r1 50)
                                    (dsl/add-reg :r0 :r1)
                                    (dsl/exit-insn)])]
      (is (= 32 (count arithmetic)))))

  (testing "Example bitwise operations"
    (let [bitwise (dsl/assemble [(dsl/mov :r0 0xFF)
                                 (dsl/and-op :r0 0x0F)
                                 (dsl/lsh :r0 4)
                                 (dsl/exit-insn)])]
      (is (= 32 (count bitwise))))))
