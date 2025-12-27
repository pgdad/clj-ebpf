(ns clj-ebpf.maps.helpers-test
  "Tests for BPF map operation instruction helpers."
  (:require [clojure.test :refer :all]
            [clj-ebpf.maps.helpers :as mh]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Instruction Generation Tests
;; ============================================================================

(deftest test-build-map-lookup-generates-instructions
  (testing "build-map-lookup returns instruction sequence"
    (let [instrs (mh/build-map-lookup 42 -16)]
      (is (vector? instrs))
      ;; Should have: ld-map-fd (16 bytes), mov-reg (8), add (8), call (8)
      (is (= 4 (count instrs)))
      ;; All DSL functions return byte arrays (8 bytes each, ld-map-fd is 16)
      (is (every? bytes? instrs))
      ;; ld-map-fd is 16 bytes (2 instruction slots)
      (is (= 16 (count (first instrs))))
      ;; Other instructions are 8 bytes each
      (is (every? #(= 8 (count %)) (rest instrs))))))

(deftest test-build-map-update-generates-instructions
  (testing "build-map-update returns instruction sequence"
    (let [instrs (mh/build-map-update 42 -16 -32 mh/BPF-ANY)]
      (is (vector? instrs))
      ;; Should have: ld-map-fd, mov-reg, add, mov-reg, add, mov, call
      (is (= 7 (count instrs)))
      ;; All DSL functions return byte arrays
      (is (every? bytes? instrs))
      ;; ld-map-fd is 16 bytes, others are 8
      (is (= 16 (count (first instrs))))
      (is (every? #(= 8 (count %)) (rest instrs))))))

(deftest test-build-map-delete-generates-instructions
  (testing "build-map-delete returns instruction sequence"
    (let [instrs (mh/build-map-delete 42 -16)]
      (is (vector? instrs))
      ;; Should have: ld-map-fd, mov-reg, add, call
      (is (= 4 (count instrs)))
      ;; All DSL functions return byte arrays
      (is (every? bytes? instrs))
      ;; ld-map-fd is 16 bytes, others are 8
      (is (= 16 (count (first instrs))))
      (is (every? #(= 8 (count %)) (rest instrs))))))

(deftest test-build-map-lookup-ptr-generates-instructions
  (testing "build-map-lookup-ptr with register pointer"
    (let [instrs (mh/build-map-lookup-ptr 42 :r6)]
      (is (vector? instrs))
      ;; Should have: ld-map-fd, mov-reg, call
      (is (= 3 (count instrs)))
      ;; All DSL functions return byte arrays
      (is (every? bytes? instrs))
      ;; ld-map-fd is 16 bytes, others are 8
      (is (= 16 (count (first instrs))))
      (is (every? #(= 8 (count %)) (rest instrs))))))

(deftest test-update-flags
  (testing "BPF update flags are defined correctly"
    (is (= 0 mh/BPF-ANY))
    (is (= 1 mh/BPF-NOEXIST))
    (is (= 2 mh/BPF-EXIST))))

;; ============================================================================
;; Integration Tests (require BPF)
;; ============================================================================

(defn linux-with-bpf?
  "Check if we're on Linux with BPF available"
  []
  (and (= "Linux" (System/getProperty "os.name"))
       (try
         (utils/check-bpf-available)
         true
         (catch Exception _ false))))

(deftest ^:integration test-map-lookup-in-program
  (when (linux-with-bpf?)
    (testing "Map lookup helper assembles correctly in XDP program"
      (maps/with-map [m {:map-type :array
                         :key-size 4
                         :value-size 8
                         :max-entries 10
                         :map-name "test_lookup"
                         :key-serializer utils/int->bytes
                         :key-deserializer utils/bytes->int
                         :value-serializer utils/long->bytes
                         :value-deserializer utils/bytes->long}]
        ;; Pre-populate map
        (maps/map-update m 0 12345)

        ;; Build XDP program that looks up key 0 and returns XDP_PASS
        (let [program-bytecode
              (bpf/assemble
                (concat
                  ;; Store key 0 on stack at -4
                  [(dsl/mov :r0 0)
                   (dsl/stx :w :r10 :r0 -4)]
                  ;; Look up in map
                  (mh/build-map-lookup (:fd m) -4)
                  ;; Return XDP_PASS (2) regardless of result
                  [(dsl/mov :r0 2)  ; XDP_PASS
                   (dsl/exit-insn)]))]

          ;; Verify bytecode is valid (non-empty byte array)
          (is (bytes? program-bytecode))
          (is (> (count program-bytecode) 0))
          ;; Each BPF instruction is 8 bytes
          (is (zero? (mod (count program-bytecode) 8))))))))

(deftest ^:integration test-map-update-in-program
  (when (linux-with-bpf?)
    (testing "Map update helper assembles correctly in XDP program"
      (maps/with-map [m {:map-type :array
                         :key-size 4
                         :value-size 8
                         :max-entries 10
                         :map-name "test_update"
                         :key-serializer utils/int->bytes
                         :key-deserializer utils/bytes->int
                         :value-serializer utils/long->bytes
                         :value-deserializer utils/bytes->long}]
        ;; Build XDP program that updates key 1 with value 999
        (let [program-bytecode
              (bpf/assemble
                (concat
                  ;; Store key 1 on stack at -4
                  [(dsl/mov :r0 1)
                   (dsl/stx :w :r10 :r0 -4)]
                  ;; Store value 999 on stack at -16 (8 bytes)
                  [(dsl/mov :r0 999)
                   (dsl/stx :dw :r10 :r0 -16)]
                  ;; Update map
                  (mh/build-map-update (:fd m) -4 -16 mh/BPF-ANY)
                  ;; Return XDP_PASS
                  [(dsl/mov :r0 2)
                   (dsl/exit-insn)]))]

          ;; Verify bytecode is valid
          (is (bytes? program-bytecode))
          (is (> (count program-bytecode) 0))
          (is (zero? (mod (count program-bytecode) 8))))))))

(deftest test-build-map-lookup-or-init
  (testing "build-map-lookup-or-init generates correct instruction count"
    (let [instrs (mh/build-map-lookup-or-init 42 -16 -32)]
      ;; First lookup: 4 instrs
      ;; Jump if found: 1 instr
      ;; Update: 7 instrs
      ;; Second lookup: 4 instrs
      ;; Total: 16 instructions
      (is (= 16 (count (flatten instrs)))))))

;; ============================================================================
;; Bytecode Verification Tests
;; ============================================================================

(deftest test-helper-function-ids
  (testing "Helper function IDs match kernel definitions"
    (is (= 1 mh/BPF-FUNC-map-lookup-elem))
    (is (= 2 mh/BPF-FUNC-map-update-elem))
    (is (= 3 mh/BPF-FUNC-map-delete-elem))))
