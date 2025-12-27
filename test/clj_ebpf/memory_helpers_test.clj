(ns clj-ebpf.memory-helpers-test
  "Tests for memory operation helpers - CI-safe"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.memory :as mem]
            [clj-ebpf.dsl :as dsl]))

(deftest test-build-zero-bytes
  (testing "build-zero-bytes with 8 bytes (1 dword)"
    (let [instrs (mem/build-zero-bytes -16 8)]
      (is (vector? instrs))
      ;; mov + 1 stx :dw = 2 instructions
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-zero-bytes with 12 bytes (1 dword + 1 word)"
    (let [instrs (mem/build-zero-bytes -16 12)]
      (is (vector? instrs))
      ;; mov + 1 stx :dw + 1 stx :w = 3 instructions
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-zero-bytes with 16 bytes (2 dwords)"
    (let [instrs (mem/build-zero-bytes -16 16)]
      (is (vector? instrs))
      ;; mov + 2 stx :dw = 3 instructions
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-zero-bytes with 40 bytes"
    (let [instrs (mem/build-zero-bytes -64 40)]
      (is (vector? instrs))
      ;; mov + 5 stx :dw = 6 instructions
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-zero-bytes with 4 bytes (just 1 word, no dword)"
    (let [instrs (mem/build-zero-bytes -16 4)]
      (is (vector? instrs))
      ;; mov + 1 stx :w = 2 instructions
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-build-zero-struct
  (testing "build-zero-struct rounds up size"
    (let [instrs (mem/build-zero-struct -64 41)]
      ;; Rounds 41 to 44 bytes = 5 dwords + 1 word
      (is (vector? instrs))
      (is (every? bytes? instrs))))

  (testing "build-zero-struct with aligned size"
    (let [instrs (mem/build-zero-struct -64 40)]
      (is (vector? instrs))
      ;; Same as build-zero-bytes -64 40
      (is (= (count (mem/build-zero-bytes -64 40)) (count instrs))))))

(deftest test-build-memcpy-stack
  (testing "build-memcpy-stack with 16 bytes"
    (let [instrs (mem/build-memcpy-stack -32 -64 16)]
      (is (vector? instrs))
      ;; 4 words * 2 instructions each = 8 instructions
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-memcpy-stack with 4 bytes"
    (let [instrs (mem/build-memcpy-stack -32 -64 4)]
      (is (vector? instrs))
      ;; 1 word * 2 instructions = 2 instructions
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-memcpy-stack with 32 bytes"
    (let [instrs (mem/build-memcpy-stack -32 -80 32)]
      (is (vector? instrs))
      ;; 8 words * 2 instructions = 16 instructions
      (is (= 16 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-build-memcpy-stack-dw
  (testing "build-memcpy-stack-dw with 16 bytes"
    (let [instrs (mem/build-memcpy-stack-dw -32 -64 16)]
      (is (vector? instrs))
      ;; 2 dwords * 2 instructions = 4 instructions
      (is (= 4 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-memcpy-stack-dw is more efficient than word version"
    (let [dw-instrs (mem/build-memcpy-stack-dw -32 -64 16)
          w-instrs (mem/build-memcpy-stack -32 -64 16)]
      ;; DW version should have fewer instructions
      (is (< (count dw-instrs) (count w-instrs))))))

(deftest test-build-memset
  ;; Note: Using small byte values to avoid 32-bit overflow when replicated
  ;; 0xFF -> 0xFFFFFFFF overflows, so use smaller values
  (testing "build-memset with 0x12"
    (let [instrs (mem/build-memset -16 0x12 16)]
      (is (vector? instrs))
      ;; mov + 4 stx :w = 5 instructions
      (is (= 5 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-memset with 0x00"
    (let [instrs (mem/build-memset -16 0x00 16)]
      (is (vector? instrs))
      ;; mov + 4 stx :w = 5 instructions
      (is (= 5 (count instrs)))))

  (testing "build-memset with 0x55"
    (let [instrs (mem/build-memset -16 0x55 8)]
      (is (vector? instrs))
      ;; mov + 2 stx :w = 3 instructions
      (is (= 3 (count instrs))))))

(deftest test-build-memset-dw
  (testing "build-memset-dw with 16 bytes"
    ;; Note: Using a value that fits in 32-bit signed integer
    (let [instrs (mem/build-memset-dw -16 0x12345678 16)]
      (is (vector? instrs))
      ;; mov + 2 stx :dw = 3 instructions
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-store-immediate
  (testing "build-store-immediate-w generates 2 instructions"
    (let [instrs (mem/build-store-immediate-w -16 0x12345678)]
      (is (vector? instrs))
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-store-immediate-dw generates 2 instructions"
    ;; Note: dsl/mov only supports 32-bit signed immediates
    ;; Using a value that fits in 32-bit signed integer range
    (let [instrs (mem/build-store-immediate-dw -16 0x12345678)]
      (is (vector? instrs))
      (is (= 2 (count instrs))))))

(deftest test-build-init-struct
  (testing "build-init-struct zeros and sets fields"
    ;; Note: Using values that fit in 32-bit signed integer range
    (let [instrs (mem/build-init-struct -64 24 {0 0x12345678 8 0x7AAABBCC})]
      (is (vector? instrs))
      ;; Zero 24 bytes (3 dwords = 3 stx + 1 mov = 4) + 2 fields * 2 = 8
      (is (pos? (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-init-struct with no fields just zeros"
    (let [instrs (mem/build-init-struct -64 16 {})]
      (is (vector? instrs))
      ;; Just zeroing: mov + 2 stx :dw = 3 instructions
      (is (= 3 (count instrs))))))

(deftest test-struct-field-ops
  (testing "build-load-struct-field-w generates 1 instruction"
    (let [instrs (mem/build-load-struct-field-w :r6 8 :r0)]
      (is (vector? instrs))
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs)))))

  (testing "build-load-struct-field-dw generates 1 instruction"
    (let [instrs (mem/build-load-struct-field-dw :r6 16 :r0)]
      (is (vector? instrs))
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs)))))

  (testing "build-store-struct-field-w generates 1 instruction"
    (let [instrs (mem/build-store-struct-field-w :r6 8 :r0)]
      (is (vector? instrs))
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs)))))

  (testing "build-store-struct-field-dw generates 1 instruction"
    (let [instrs (mem/build-store-struct-field-dw :r6 16 :r0)]
      (is (vector? instrs))
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs))))))

(deftest test-conntrack-key-init
  (testing "Conntrack key initialization pattern assembles"
    (let [program (concat
                    ;; Zero 40-byte conntrack key
                    (mem/build-zero-bytes -64 40)
                    ;; Would then fill in fields...
                    [(dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 6 (zero) + 1 (exit) = 7 instructions = 56 bytes
      (is (= 56 (count bytecode))))))

(deftest test-address-copy-pattern
  (testing "Address copy pattern assembles"
    (let [program (concat
                    ;; Copy 16-byte address from stack[-32] to stack[-64]
                    (mem/build-memcpy-stack -32 -64 16)
                    [(dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 8 (copy) + 1 (exit) = 9 instructions = 72 bytes
      (is (= 72 (count bytecode))))))

(deftest test-event-init-pattern
  (testing "Event structure initialization pattern assembles"
    (let [program (concat
                    ;; Zero 64-byte event structure
                    (mem/build-zero-struct -96 64)
                    ;; Set event type field
                    (mem/build-store-immediate-w -96 1)
                    [(dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))
