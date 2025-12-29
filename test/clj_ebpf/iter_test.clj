(ns clj-ebpf.iter-test
  "Tests for BPF Iterator (bpf_iter) support.

   These tests verify:
   - Iterator constants are defined correctly
   - DSL helpers generate valid bytecode
   - Context field access works correctly
   - Program building and assembly functions
   - Helper function patterns

   Note: Actual iterator program loading and execution requires
   root privileges and kernel 5.8+. These tests focus on the
   code generation aspects that can run without privileges."
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.constants :as const]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.iter :as iter]))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-tracing-program-type
  (testing "TRACING program type is defined"
    (is (= 26 (const/prog-type->num :tracing)))
    (is (= :tracing (const/int->prog-type 26)))))

(deftest test-trace-iter-attach-type
  (testing "TRACE_ITER attach type is defined"
    (is (= 28 (const/attach-type->num :trace-iter)))
    (is (= :trace-iter (const/int->attach-type 28)))))

(deftest test-iter-create-command
  (testing "ITER_CREATE BPF command is defined"
    (is (= 33 (const/cmd->num :iter-create)))))

;; ============================================================================
;; Iterator Types Tests
;; ============================================================================

(deftest test-iterator-types
  (testing "Iterator types map is defined"
    (is (map? iter/iterator-types))
    (is (= "bpf_iter__task" (:task iter/iterator-types)))
    (is (= "bpf_iter__bpf_map" (:bpf-map iter/iterator-types)))
    (is (= "bpf_iter__tcp" (:tcp iter/iterator-types)))
    (is (= "bpf_iter__udp" (:udp iter/iterator-types)))))

(deftest test-iterator-types-all-strings
  (testing "All iterator type values are strings"
    (doseq [[k v] iter/iterator-types]
      (is (string? v) (str "Type " k " should have string value")))))

;; ============================================================================
;; Context Offset Tests
;; ============================================================================

(deftest test-iter-context-offsets
  (testing "Iterator context offsets are defined"
    (are [field expected] (= expected (iter/iter-context-offset field))
      :meta      0
      :task      8
      :map       8
      :key       8
      :value     16
      :prog      8
      :link      8
      :tcp-sk    8
      :udp-sk    8
      :file      16)))

(deftest test-invalid-context-offset
  (testing "Invalid context field throws"
    (is (thrown? clojure.lang.ExceptionInfo
                 (iter/iter-context-offset :invalid-field)))))

(deftest test-iter-meta-offsets
  (testing "bpf_iter_meta offsets are defined"
    (is (= 0 (:seq iter/iter-meta-offsets)))
    (is (= 8 (:session-id iter/iter-meta-offsets)))
    (is (= 16 (:seq-num iter/iter-meta-offsets)))))

;; ============================================================================
;; Return Value Tests
;; ============================================================================

(deftest test-iter-return-values
  (testing "Iterator return values"
    (is (= 0 (iter/iter-return-value :continue)))
    (is (= 1 (iter/iter-return-value :stop)))))

(deftest test-iter-return-values-map
  (testing "Return values map contents"
    (is (= {:continue 0 :stop 1} iter/iter-return-values))))

(deftest test-invalid-return-value
  (testing "Invalid return value throws"
    (is (thrown? clojure.lang.ExceptionInfo
                 (iter/iter-return-value :invalid)))))

;; ============================================================================
;; Helper IDs Tests
;; ============================================================================

(deftest test-iter-helper-ids
  (testing "Iterator helper IDs are defined"
    (is (= 126 (:seq-printf iter/iter-helper-ids)))
    (is (= 127 (:seq-write iter/iter-helper-ids)))
    (is (= 128 (:seq-printf-btf iter/iter-helper-ids)))
    (is (= 35 (:get-current-task iter/iter-helper-ids)))
    (is (= 113 (:probe-read-kernel iter/iter-helper-ids)))
    (is (= 45 (:probe-read-str iter/iter-helper-ids)))))

;; ============================================================================
;; Prologue Tests
;; ============================================================================

(deftest test-iter-prologue
  (testing "iter-prologue generates bytecode"
    (let [insns (iter/iter-prologue :r6)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

(deftest test-iter-prologue-different-registers
  (testing "iter-prologue with different registers"
    (doseq [reg [:r6 :r7 :r8 :r9]]
      (let [insns (iter/iter-prologue reg)]
        (is (vector? insns))
        (is (bytes? (first insns)))))))

(deftest test-iter-prologue-with-meta
  (testing "iter-prologue-with-meta generates bytecode"
    (let [insns (iter/iter-prologue-with-meta :r6 :r7)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Context Field Access Tests
;; ============================================================================

(deftest test-iter-load-ctx-ptr
  (testing "iter-load-ctx-ptr generates bytecode"
    (doseq [field [:meta :task :map :key :value]]
      (let [insn (iter/iter-load-ctx-ptr :r6 :r0 field)]
        (is (bytes? insn))
        (is (= 8 (count insn)))))))

(deftest test-iter-load-meta-field
  (testing "iter-load-meta-field generates bytecode"
    (doseq [field [:seq :session-id :seq-num]]
      (let [insn (iter/iter-load-meta-field :r7 :r0 field)]
        (is (bytes? insn))
        (is (= 8 (count insn)))))))

(deftest test-iter-load-meta-invalid-field
  (testing "iter-load-meta-field throws on invalid field"
    (is (thrown? clojure.lang.ExceptionInfo
                 (iter/iter-load-meta-field :r7 :r0 :invalid)))))

;; ============================================================================
;; NULL Check Tests
;; ============================================================================

(deftest test-iter-check-null
  (testing "iter-check-null generates bytecode"
    (let [insns (iter/iter-check-null :r7 3)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

(deftest test-iter-check-null-and-exit
  (testing "iter-check-null-and-exit generates bytecode"
    (let [insns (iter/iter-check-null-and-exit :r7)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; seq_write Helper Tests
;; ============================================================================

(deftest test-seq-write-immediate-len
  (testing "seq-write with immediate length generates bytecode"
    (let [insns (iter/seq-write :r7 :r8 64)]
      (is (vector? insns))
      (is (= 4 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-seq-write-register-len
  (testing "seq-write with register length generates bytecode"
    (let [insns (iter/seq-write :r7 :r8 :r9)]
      (is (vector? insns))
      (is (= 4 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; seq_printf Helper Tests
;; ============================================================================

(deftest test-seq-printf-simple
  (testing "seq-printf-simple generates bytecode"
    (let [insns (iter/seq-printf-simple :r7 :r8 16 :r9 0)]
      (is (vector? insns))
      (is (= 6 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Return Pattern Tests
;; ============================================================================

(deftest test-iter-return-continue
  (testing "iter-return-continue generates bytecode"
    (let [insns (iter/iter-return-continue)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-iter-return-stop
  (testing "iter-return-stop generates bytecode"
    (let [insns (iter/iter-return-stop)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-iter-return
  (testing "iter-return with different actions"
    (doseq [action [:continue :stop]]
      (let [insns (iter/iter-return action)]
        (is (vector? insns))
        (is (= 2 (count insns)))
        (is (every? bytes? insns))))))

;; ============================================================================
;; Task Iterator Helper Tests
;; ============================================================================

(deftest test-task-struct-offsets
  (testing "Task struct offsets are defined"
    (is (map? iter/task-struct-offsets))
    (is (number? (:pid iter/task-struct-offsets)))
    (is (number? (:tgid iter/task-struct-offsets)))
    (is (number? (:comm iter/task-struct-offsets)))))

(deftest test-task-load-pid
  (testing "task-load-pid generates bytecode"
    (let [insn (iter/task-load-pid :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-task-load-tgid
  (testing "task-load-tgid generates bytecode"
    (let [insn (iter/task-load-tgid :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

;; ============================================================================
;; probe_read Helper Tests
;; ============================================================================

(deftest test-probe-read-kernel
  (testing "probe-read-kernel generates bytecode"
    (let [insns (iter/probe-read-kernel :r8 64 :r7)]
      (is (vector? insns))
      (is (= 4 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-probe-read-kernel-str
  (testing "probe-read-kernel-str generates bytecode"
    (let [insns (iter/probe-read-kernel-str :r8 16 :r7)]
      (is (vector? insns))
      (is (= 4 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Stack Allocation Tests
;; ============================================================================

(deftest test-alloc-stack-buffer
  (testing "alloc-stack-buffer generates instructions"
    (let [insns (iter/alloc-stack-buffer :r8 -64)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns))
      (is (every? #(= 8 (count %)) insns)))))

;; ============================================================================
;; Program Builder Tests
;; ============================================================================

(deftest test-build-iter-program-minimal
  (testing "build-iter-program with minimal body"
    (let [bytecode (iter/build-iter-program {:body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-build-iter-program-custom-ctx
  (testing "build-iter-program with custom ctx-reg"
    (let [bytecode (iter/build-iter-program
                     {:ctx-reg :r7
                      :body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-build-iter-program-with-meta
  (testing "build-iter-program with meta-reg"
    (let [bytecode (iter/build-iter-program
                     {:ctx-reg :r6
                      :meta-reg :r7
                      :body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-build-iter-program-default-stop
  (testing "build-iter-program with default stop"
    (let [bytecode (iter/build-iter-program
                     {:body []
                      :default-action :stop})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-build-iter-program-with-body
  (testing "build-iter-program with body instructions"
    (let [bytecode (iter/build-iter-program
                     {:ctx-reg :r6
                      :body [(iter/iter-load-ctx-ptr :r6 :r7 :task)
                             (iter/iter-check-null :r7 2)]
                      :default-action :continue})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Section Names Tests
;; ============================================================================

(deftest test-iter-section-name
  (testing "iter-section-name generates correct names"
    (is (= "iter/bpf_iter__task" (iter/iter-section-name :task)))
    (is (= "iter/bpf_iter__bpf_map" (iter/iter-section-name :bpf-map)))
    (is (= "iter/bpf_iter__tcp" (iter/iter-section-name :tcp)))))

(deftest test-make-iter-info
  (testing "make-iter-info creates correct metadata"
    (let [info (iter/make-iter-info "test_iter" :task [])]
      (is (= "test_iter" (:name info)))
      (is (= "iter/bpf_iter__task" (:section info)))
      (is (= :tracing (:type info)))
      (is (= :trace-iter (:attach-type info)))
      (is (= :task (:iter-type info)))
      (is (= "bpf_iter__task" (:btf-type info)))
      (is (= [] (:instructions info))))))

;; ============================================================================
;; Template Tests
;; ============================================================================

(deftest test-minimal-task-iterator
  (testing "minimal-task-iterator generates bytecode"
    (let [insns (iter/minimal-task-iterator)]
      (is (vector? insns))
      (is (= 3 (count insns)))  ; prologue (1) + return (2)
      (is (every? bytes? insns)))))

(deftest test-task-null-check-template
  (testing "task-null-check-template generates bytecode"
    (let [body [(dsl/mov :r0 1)]
          insns (iter/task-null-check-template body)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Byte Order Utility Tests
;; ============================================================================

(deftest test-htons
  (testing "htons converts correctly"
    (is (= 0x0050 (iter/htons 0x5000)))
    (is (= 0x901F (iter/htons 0x1F90)))))

(deftest test-htonl
  (testing "htonl converts correctly"
    (is (= 0x0101A8C0 (iter/htonl 0xC0A80101)))
    (is (= 0x0100007F (iter/htonl 0x7F000001)))))

;; ============================================================================
;; Complete Program Assembly Tests
;; ============================================================================

(deftest test-complete-task-iterator-assembly
  (testing "Complete task iterator assembles correctly"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          ;; Prologue
                          (iter/iter-prologue :r6)
                          ;; Load task pointer
                          [(iter/iter-load-ctx-ptr :r6 :r7 :task)]
                          ;; Check if NULL (end of iteration)
                          (iter/iter-check-null-and-exit :r7)
                          ;; Continue iteration
                          (iter/iter-return-continue))))]
      (is (bytes? bytecode))
      (is (>= (count bytecode) 56)))))  ; At least 7 instructions

(deftest test-task-iterator-with-pid-load
  (testing "Task iterator with PID load assembles"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          (iter/iter-prologue :r6)
                          [(iter/iter-load-ctx-ptr :r6 :r7 :task)]
                          (iter/iter-check-null-and-exit :r7)
                          ;; Load PID
                          [(iter/task-load-pid :r7 :r0)]
                          (iter/iter-return-continue))))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Instruction Size Tests
;; ============================================================================

(deftest test-instruction-sizes
  (testing "All instructions are 8 bytes"
    (let [test-cases [[(iter/iter-prologue :r6) 1]
                      [(iter/iter-return-continue) 2]
                      [(iter/iter-return-stop) 2]
                      [(iter/iter-check-null :r7 1) 1]
                      [(iter/iter-check-null-and-exit :r7) 3]
                      [(iter/seq-write :r7 :r8 64) 4]
                      [(iter/probe-read-kernel :r8 64 :r7) 4]]]
      (doseq [[insns expected-count] test-cases]
        (is (= expected-count (count insns)))
        (doseq [insn insns]
          (is (= 8 (count insn))))))))

;; ============================================================================
;; Edge Case Tests
;; ============================================================================

(deftest test-various-skip-counts
  (testing "Various skip counts in NULL check"
    (doseq [skip [0 1 5 10 127]]
      (let [insns (iter/iter-check-null :r7 skip)]
        (is (vector? insns))
        (is (every? bytes? insns))))))

(deftest test-all-context-fields-accessible
  (testing "All context fields can be accessed"
    (doseq [field (keys iter/iter-context-offsets)]
      (let [insn (iter/iter-load-ctx-ptr :r6 :r0 field)]
        (is (bytes? insn))))))

(deftest test-all-meta-fields-accessible
  (testing "All meta fields can be accessed"
    (doseq [field (keys iter/iter-meta-offsets)]
      (let [insn (iter/iter-load-meta-field :r7 :r0 field)]
        (is (bytes? insn))))))

;; ============================================================================
;; Register Combinations Tests
;; ============================================================================

(deftest test-prologue-register-combinations
  (testing "Prologue works with various registers"
    (doseq [ctx [:r6 :r7 :r8 :r9]]
      (let [insns (iter/iter-prologue ctx)]
        (is (vector? insns))
        (is (every? bytes? insns))))))

(deftest test-prologue-with-meta-register-combinations
  (testing "Prologue with meta works with various register combinations"
    (doseq [ctx [:r6 :r7]
            meta [:r8 :r9]
            :when (not= ctx meta)]
      (let [insns (iter/iter-prologue-with-meta ctx meta)]
        (is (vector? insns))
        (is (every? bytes? insns))))))

;; ============================================================================
;; Complex Program Tests
;; ============================================================================

(deftest test-complete-iterator-with-probe-read
  (testing "Iterator with probe_read assembles"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          ;; Prologue with meta
                          (iter/iter-prologue-with-meta :r6 :r7)
                          ;; Load task pointer
                          [(iter/iter-load-ctx-ptr :r6 :r8 :task)]
                          ;; Check if NULL
                          (iter/iter-check-null-and-exit :r8)
                          ;; Allocate stack buffer (returns 2 instructions)
                          (iter/alloc-stack-buffer :r9 -64)
                          ;; Read task data to stack
                          (iter/probe-read-kernel :r9 64 :r8)
                          ;; Write to output
                          (iter/seq-write :r7 :r9 64)
                          ;; Continue
                          (iter/iter-return-continue))))]
      (is (bytes? bytecode))
      (is (>= (count bytecode) 100)))))

(deftest test-minimal-iterator-via-builder
  (testing "Minimal iterator via builder"
    (let [bytecode (iter/build-iter-program
                     {:ctx-reg :r6
                      :body []
                      :default-action :continue})]
      (is (bytes? bytecode))
      ;; Minimal: prologue (1) + return (2) = 3 insns = 24 bytes
      (is (>= (count bytecode) 24)))))

;; ============================================================================
;; Iterator Type Tests
;; ============================================================================

(deftest test-all-iterator-types-have-section-names
  (testing "All iterator types produce valid section names"
    (doseq [iter-type (keys iter/iterator-types)]
      (let [section (iter/iter-section-name iter-type)]
        (is (string? section))
        (is (.startsWith section "iter/"))))))

(deftest test-make-iter-info-all-types
  (testing "make-iter-info works for all iterator types"
    (doseq [iter-type (keys iter/iterator-types)]
      (let [info (iter/make-iter-info "test" iter-type [])]
        (is (= iter-type (:iter-type info)))
        (is (= :tracing (:type info)))
        (is (= :trace-iter (:attach-type info)))))))
