(ns clj-ebpf.properties
  "Property-based tests for BPF operations.

   Tests invariants like:
   - DSL instructions produce valid outputs
   - Memory operations round-trip correctly
   - Generator outputs meet constraints"
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check :as tc]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [clj-ebpf.generators :as bpf-gen]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Test Configuration
;; ============================================================================

(def num-tests
  "Number of test iterations for quick-check"
  100)

;; ============================================================================
;; Helper Functions
;; ============================================================================

(defn valid-instruction?
  "Check if an instruction map has the required fields"
  [insn]
  (and (map? insn)
       (contains? insn :opcode)
       (number? (:opcode insn))))

;; ============================================================================
;; DSL Instruction Properties
;; ============================================================================

(defspec mov-imm-produces-instruction num-tests
  (prop/for-all [reg bpf-gen/gen-writable-register
                 imm bpf-gen/gen-imm32]
    (let [insn (dsl/mov reg imm)]
      (and (map? insn)
           (contains? insn :opcode)))))

(defspec mov-reg-produces-instruction num-tests
  (prop/for-all [dst bpf-gen/gen-writable-register
                 src bpf-gen/gen-register]
    (let [insn (dsl/mov-reg dst src)]
      (and (map? insn)
           (contains? insn :opcode)))))

(defspec alu-reg-produces-instruction num-tests
  (prop/for-all [op (gen/elements [:add :sub :mul :div :or :and :xor :lsh :rsh :arsh])
                 dst bpf-gen/gen-writable-register
                 src bpf-gen/gen-register]
    (let [insn (dsl/alu-reg op dst src)]
      (valid-instruction? insn))))

(defspec alu-imm-produces-instruction num-tests
  (prop/for-all [op (gen/elements [:add :sub :mul :div :or :and :xor :lsh :rsh :arsh :mov])
                 dst bpf-gen/gen-writable-register
                 imm bpf-gen/gen-imm32]
    (let [insn (dsl/alu-imm op dst imm)]
      (valid-instruction? insn))))

(defspec alu32-reg-produces-instruction num-tests
  (prop/for-all [op (gen/elements [:add :sub :mul :div :or :and :xor :lsh :rsh :arsh])
                 dst bpf-gen/gen-writable-register
                 src bpf-gen/gen-register]
    (let [insn (dsl/alu32-reg op dst src)]
      (valid-instruction? insn))))

(defspec alu32-imm-produces-instruction num-tests
  (prop/for-all [op (gen/elements [:add :sub :mul :div :or :and :xor :lsh :rsh :arsh :mov])
                 dst bpf-gen/gen-writable-register
                 imm bpf-gen/gen-imm32]
    (let [insn (dsl/alu32-imm op dst imm)]
      (valid-instruction? insn))))

(defspec load-produces-instruction num-tests
  (prop/for-all [size bpf-gen/gen-size
                 dst bpf-gen/gen-writable-register
                 src bpf-gen/gen-register
                 offset (gen/choose -32768 32767)]
    (let [insn (dsl/ldx size dst src offset)]
      (valid-instruction? insn))))

(defspec store-produces-instruction num-tests
  (prop/for-all [size bpf-gen/gen-size
                 dst bpf-gen/gen-register
                 offset (gen/choose -32768 32767)
                 src bpf-gen/gen-register]
    (let [insn (dsl/stx size dst offset src)]
      (valid-instruction? insn))))

(defspec store-imm-produces-instruction num-tests
  (prop/for-all [size bpf-gen/gen-size
                 dst bpf-gen/gen-register
                 offset (gen/choose -32768 32767)
                 imm bpf-gen/gen-imm32]
    (let [insn (dsl/st size dst offset imm)]
      (valid-instruction? insn))))

(defspec jump-produces-instruction num-tests
  (prop/for-all [op (gen/elements [:jeq :jne :jgt :jge :jlt :jle :jset :jsgt :jsge :jslt :jsle])
                 dst bpf-gen/gen-register
                 src bpf-gen/gen-register
                 offset (gen/choose -32768 32767)]
    (let [insn (dsl/jmp-reg op dst src offset)]
      (valid-instruction? insn))))

(defspec jump-imm-produces-instruction num-tests
  (prop/for-all [op (gen/elements [:jeq :jne :jgt :jge :jlt :jle :jset :jsgt :jsge :jslt :jsle])
                 dst bpf-gen/gen-register
                 imm bpf-gen/gen-imm32
                 offset (gen/choose -32768 32767)]
    (let [insn (dsl/jmp-imm op dst imm offset)]
      (valid-instruction? insn))))

;; ============================================================================
;; Special Instructions
;; ============================================================================

(defspec exit-produces-instruction num-tests
  (prop/for-all [_ (gen/return nil)]
    (let [insn (dsl/exit-insn)]
      (valid-instruction? insn))))

(defspec call-produces-instruction num-tests
  (prop/for-all [helper-id (gen/choose 1 200)]
    (let [insn (dsl/call helper-id)]
      (valid-instruction? insn))))

(defspec lddw-produces-two-instructions num-tests
  (prop/for-all [dst bpf-gen/gen-writable-register
                 imm bpf-gen/gen-u64]
    (let [insns (dsl/lddw dst imm)]
      (and (vector? insns)
           (= 2 (count insns))
           (every? valid-instruction? insns)))))

;; ============================================================================
;; Arithmetic Operations
;; ============================================================================

(defspec add-produces-instruction num-tests
  (prop/for-all [dst bpf-gen/gen-writable-register
                 imm bpf-gen/gen-imm32]
    (valid-instruction? (dsl/add dst imm))))

(defspec sub-produces-instruction num-tests
  (prop/for-all [dst bpf-gen/gen-writable-register
                 imm bpf-gen/gen-imm32]
    (valid-instruction? (dsl/sub dst imm))))

(defspec mul-produces-instruction num-tests
  (prop/for-all [dst bpf-gen/gen-writable-register
                 imm bpf-gen/gen-imm32]
    (valid-instruction? (dsl/mul dst imm))))

;; ============================================================================
;; Memory Utilities Properties
;; ============================================================================

(defspec byte-array-roundtrip num-tests
  (prop/for-all [data (bpf-gen/gen-byte-array-range 1 256)]
    (let [seg (utils/bytes->segment data)
          result (utils/segment->bytes seg (count data))]
      (java.util.Arrays/equals ^bytes data ^bytes result))))

(defspec int-roundtrip num-tests
  (prop/for-all [value bpf-gen/gen-i32]
    (let [seg (utils/int->segment value)
          result (utils/segment->int seg)]
      (= value result))))

(defspec long-roundtrip num-tests
  (prop/for-all [value bpf-gen/gen-i64]
    (let [seg (utils/long->segment value)
          result (utils/segment->long seg)]
      (= value result))))

(defspec int-bytes-roundtrip num-tests
  (prop/for-all [value bpf-gen/gen-i32]
    (let [bytes (utils/int->bytes value)
          result (utils/bytes->int bytes)]
      (= value result))))

(defspec long-bytes-roundtrip num-tests
  (prop/for-all [value bpf-gen/gen-i64]
    (let [bytes (utils/long->bytes value)
          result (utils/bytes->long bytes)]
      (= value result))))

(defspec short-bytes-roundtrip num-tests
  (prop/for-all [value (gen/choose -32768 32767)]
    (let [bytes (utils/short->bytes (short value))
          result (utils/bytes->short bytes)]
      (= (short value) result))))

;; ============================================================================
;; Generator Sanity Properties
;; ============================================================================

(defspec gen-map-config-produces-valid-configs num-tests
  (prop/for-all [config bpf-gen/gen-map-config]
    (and (keyword? (:type config))
         (pos? (:key-size config))
         (pos? (:value-size config))
         (pos? (:max-entries config)))))

(defspec gen-ethernet-header-has-correct-structure num-tests
  (prop/for-all [header bpf-gen/gen-ethernet-header]
    (and (= 6 (count (:dst-mac header)))
         (= 6 (count (:src-mac header)))
         (number? (:eth-type header)))))

(defspec gen-ipv4-header-has-correct-structure num-tests
  (prop/for-all [header bpf-gen/gen-ipv4-header]
    (and (= 4 (:version header))
         (= 4 (count (:src-ip header)))
         (= 4 (count (:dst-ip header)))
         (<= 1 (:ttl header) 255))))

(defspec gen-syscall-event-has-required-fields num-tests
  (prop/for-all [event bpf-gen/gen-syscall-event]
    (and (contains? event :type)
         (contains? event :timestamp)
         (contains? event :pid)
         (contains? event :syscall-nr))))

(defspec gen-unique-keys-are-unique num-tests
  (prop/for-all [n (gen/choose 1 50)
                 key-size (gen/choose 4 32)]
    (let [keys (gen/generate (bpf-gen/gen-unique-keys n key-size))]
      ;; Convert to vectors for comparison
      (let [key-vecs (map vec keys)]
        (= (count key-vecs) (count (distinct key-vecs)))))))

;; ============================================================================
;; Batch Generation Properties
;; ============================================================================

(defspec gen-kv-batch-produces-correct-count num-tests
  (prop/for-all [batch-size (gen/choose 1 50)
                 key-size (gen/choose 4 16)
                 value-size (gen/choose 4 64)]
    (let [batch (gen/generate (bpf-gen/gen-kv-batch key-size value-size batch-size))]
      (and (= batch-size (count batch))
           (every? #(= 2 (count %)) batch)
           (every? #(= key-size (count (first %))) batch)
           (every? #(= value-size (count (second %))) batch)))))

;; ============================================================================
;; Manual Test Runner (for REPL usage)
;; ============================================================================

(defn run-all-properties
  "Run all property-based tests and return results"
  []
  (println "Running property-based tests...")
  (let [tests [["mov-imm"
                #(tc/quick-check num-tests
                   (prop/for-all [reg bpf-gen/gen-writable-register
                                  imm bpf-gen/gen-imm32]
                     (map? (dsl/mov reg imm))))]
               ["mov-reg"
                #(tc/quick-check num-tests
                   (prop/for-all [dst bpf-gen/gen-writable-register
                                  src bpf-gen/gen-register]
                     (map? (dsl/mov-reg dst src))))]
               ["byte-array-roundtrip"
                #(tc/quick-check num-tests
                   (prop/for-all [data (bpf-gen/gen-byte-array-range 1 64)]
                     (let [seg (utils/bytes->segment data)]
                       (java.util.Arrays/equals
                        ^bytes data
                        ^bytes (utils/segment->bytes seg (count data))))))]
               ["int-roundtrip"
                #(tc/quick-check num-tests
                   (prop/for-all [v bpf-gen/gen-i32]
                     (let [bytes (utils/int->bytes v)]
                       (= v (utils/bytes->int bytes)))))]]
        results (for [[name test-fn] tests]
                  (let [result (test-fn)]
                    (println (format "  %s: %s"
                                     name
                                     (if (:pass? result) "PASS" "FAIL")))
                    [name result]))]
    (into {} results)))
