(ns clj-ebpf.dsl-fentry-test
  "Tests for Fentry/Fexit DSL - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.fentry :as fentry]))

;; ============================================================================
;; Attach Type Tests
;; ============================================================================

(deftest test-attach-types
  (testing "Fentry attach type values"
    (is (= 49 (:fentry fentry/fentry-attach-types)))
    (is (= 50 (:fexit fentry/fentry-attach-types)))
    (is (= 51 (:fmod-ret fentry/fentry-attach-types))))

  (testing "Program types"
    (is (= :tracing (:fentry fentry/fentry-prog-types)))
    (is (= :tracing (:fexit fentry/fentry-prog-types)))
    (is (= :tracing (:fmod-ret fentry/fentry-prog-types)))))

;; ============================================================================
;; Argument Register Tests
;; ============================================================================

(deftest test-arg-registers
  (testing "Argument register mapping"
    (is (= :r1 (get fentry/arg-registers 0)))
    (is (= :r2 (get fentry/arg-registers 1)))
    (is (= :r3 (get fentry/arg-registers 2)))
    (is (= :r4 (get fentry/arg-registers 3)))
    (is (= :r5 (get fentry/arg-registers 4))))

  (testing "arg-reg function"
    (is (= :r1 (fentry/arg-reg 0)))
    (is (= :r2 (fentry/arg-reg 1)))
    (is (= :r3 (fentry/arg-reg 2)))
    (is (= :r4 (fentry/arg-reg 3)))
    (is (= :r5 (fentry/arg-reg 4))))

  (testing "Invalid argument index throws"
    (is (thrown? clojure.lang.ExceptionInfo (fentry/arg-reg 5)))
    (is (thrown? clojure.lang.ExceptionInfo (fentry/arg-reg -1)))
    (is (thrown? clojure.lang.ExceptionInfo (fentry/arg-reg 10)))))

;; ============================================================================
;; Prologue Tests
;; ============================================================================

(deftest test-fentry-prologue
  (testing "Single argument save"
    (let [insns (fentry/fentry-prologue [[0 :r6]])]
      (is (= 1 (count insns)))
      (is (bytes? (first insns)))))

  (testing "Multiple argument saves"
    (let [insns (fentry/fentry-prologue [[0 :r6] [1 :r7] [2 :r8]])]
      (is (= 3 (count insns)))
      (is (every? bytes? insns))))

  (testing "Empty argument saves"
    (let [insns (fentry/fentry-prologue [])]
      (is (= 0 (count insns))))))

(deftest test-fentry-save-args
  (testing "Save 1 argument"
    (let [insns (fentry/fentry-save-args 1)]
      (is (= 1 (count insns)))
      (is (bytes? (first insns)))))

  (testing "Save 3 arguments"
    (let [insns (fentry/fentry-save-args 3)]
      (is (= 3 (count insns)))
      (is (every? bytes? insns))))

  (testing "Save 5 arguments (max)"
    (let [insns (fentry/fentry-save-args 5)]
      (is (= 5 (count insns)))
      (is (every? bytes? insns))))

  (testing "Save more than 5 arguments caps at 5"
    (let [insns (fentry/fentry-save-args 10)]
      (is (= 5 (count insns))))))

;; ============================================================================
;; Fexit Return Value Tests
;; ============================================================================

(deftest test-fexit-return-value
  (testing "Get return value"
    (let [insns (fentry/fexit-get-return-value :r6)]
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

;; ============================================================================
;; Struct Field Access Tests
;; ============================================================================

(deftest test-read-struct-field
  (testing "Read 8-byte field"
    (let [insns (fentry/read-struct-field :r6 16 :r0 8)]
      (is (= 1 (count insns)))
      (is (bytes? (first insns)))))

  (testing "Read 4-byte field"
    (let [insns (fentry/read-struct-field :r6 8 :r0 4)]
      (is (= 1 (count insns)))
      (is (bytes? (first insns)))))

  (testing "Read 2-byte field"
    (let [insns (fentry/read-struct-field :r6 4 :r0 2)]
      (is (= 1 (count insns)))
      (is (bytes? (first insns)))))

  (testing "Read 1-byte field"
    (let [insns (fentry/read-struct-field :r6 0 :r0 1)]
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

;; ============================================================================
;; Program Builder Tests
;; ============================================================================

(deftest test-build-fentry-program
  (testing "Minimal fentry program"
    (let [bytecode (fentry/build-fentry-program {:body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "Fentry program with arg saves"
    (let [bytecode (fentry/build-fentry-program
                    {:arg-saves [[0 :r6] [1 :r7]]
                     :body [(dsl/mov :r0 42)]
                     :return-value 0})]
      (is (bytes? bytecode))
      ;; Should have: 2 arg saves + 1 body + mov r0,0 + exit = 5 insns
      ;; Each instruction is 8 bytes
      (is (>= (count bytecode) (* 5 8))))))

(deftest test-build-fexit-program
  (testing "Minimal fexit program"
    (let [bytecode (fentry/build-fexit-program {:body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "Fexit program with return value capture"
    (let [bytecode (fentry/build-fexit-program
                    {:arg-saves [[0 :r6]]
                     :ret-reg :r7
                     :body []
                     :return-value 0})]
      (is (bytes? bytecode))
      ;; Should have: 1 arg save + 1 ret save + mov r0,0 + exit = 4 insns
      (is (>= (count bytecode) (* 4 8))))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(fentry/deffentry-instructions test-fentry-basic
  {:function "test_func"
   :args [:a :b]
   :arg-saves [[0 :r6] [1 :r7]]}
  [])

(fentry/deffentry-instructions test-fentry-with-body
  {:function "test_func"
   :args [:sk]
   :arg-saves [[0 :r6]]}
  [(dsl/mov :r0 123)])

(fentry/deffexit-instructions test-fexit-basic
  {:function "test_func"
   :args [:a :b]
   :arg-saves [[0 :r6] [1 :r7]]
   :ret-reg :r8}
  [])

(deftest test-deffentry-macro
  (testing "Basic fentry program generation"
    (let [insns (test-fentry-basic)]
      (is (vector? insns))
      (is (pos? (count insns)))
      ;; Should have arg saves + exit
      (is (>= (count insns) 4))))

  (testing "Fentry with body"
    (let [insns (test-fentry-with-body)]
      (is (vector? insns))
      ;; Should have: 1 arg save + 1 body + mov r0 + exit
      (is (>= (count insns) 4))))

  (testing "Instructions are valid bytes"
    (let [insns (test-fentry-basic)]
      (doseq [insn insns]
        (is (bytes? insn) "Each instruction should be a byte array")))))

(deftest test-deffexit-macro
  (testing "Basic fexit program generation"
    (let [insns (test-fexit-basic)]
      (is (vector? insns))
      (is (pos? (count insns)))
      ;; Should have arg saves + ret save + exit
      (is (>= (count insns) 5))))

  (testing "Assembly works"
    (let [bytecode (dsl/assemble (test-fexit-basic))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-section-names
  (testing "Fentry section name"
    (is (= "fentry/tcp_v4_connect"
           (fentry/fentry-section-name "tcp_v4_connect")))
    (is (= "fentry/do_sys_open"
           (fentry/fentry-section-name "do_sys_open"))))

  (testing "Fexit section name"
    (is (= "fexit/tcp_v4_connect"
           (fentry/fexit-section-name "tcp_v4_connect")))
    (is (= "fexit/do_sys_open"
           (fentry/fexit-section-name "do_sys_open"))))

  (testing "Fmod_ret section name"
    (is (= "fmod_ret/security_bprm_check"
           (fentry/fmod-ret-section-name "security_bprm_check")))))

;; ============================================================================
;; Program Metadata Tests
;; ============================================================================

(deftest test-program-metadata
  (testing "Fentry program info"
    (let [info (fentry/make-fentry-program-info
                "trace_tcp" "tcp_v4_connect" (test-fentry-basic))]
      (is (= "trace_tcp" (:name info)))
      (is (= "fentry/tcp_v4_connect" (:section info)))
      (is (= :tracing (:type info)))
      (is (= :fentry (:attach-type info)))
      (is (= "tcp_v4_connect" (:target-func info)))
      (is (vector? (:instructions info)))))

  (testing "Fexit program info"
    (let [info (fentry/make-fexit-program-info
                "trace_tcp_exit" "tcp_v4_connect" (test-fexit-basic))]
      (is (= "trace_tcp_exit" (:name info)))
      (is (= "fexit/tcp_v4_connect" (:section info)))
      (is (= :tracing (:type info)))
      (is (= :fexit (:attach-type info)))))

  (testing "Fmod_ret program info"
    (let [info (fentry/make-fmod-ret-program-info
                "modify_ret" "some_func" [])]
      (is (= "modify_ret" (:name info)))
      (is (= "fmod_ret/some_func" (:section info)))
      (is (= :fmod-ret (:attach-type info))))))

;; ============================================================================
;; Helper Pattern Tests
;; ============================================================================

(deftest test-fentry-log-pid
  (testing "Get PID instructions"
    (let [insns (fentry/fentry-log-pid)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-fentry-log-comm
  (testing "Get comm instructions"
    (let [insns (fentry/fentry-log-comm :r1)]
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-fentry-ktime-get-ns
  (testing "Get kernel time instructions"
    (let [insns (fentry/fentry-ktime-get-ns)]
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

(deftest test-fentry-return
  (testing "Return instructions"
    (let [insns (fentry/fentry-return 0)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "Return non-zero value"
    (let [insns (fentry/fentry-return 42)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Filter Pattern Tests
;; ============================================================================

(deftest test-fentry-filter-by-pid
  (testing "PID filter instructions"
    (let [insns (fentry/fentry-filter-by-pid 1234 2)]
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-fentry-filter-by-comm
  (testing "Comm filter instructions"
    (let [insns (fentry/fentry-filter-by-comm -16 "bash" 2)]
      (is (= 6 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Trampoline Information Tests
;; ============================================================================

(deftest test-describe-trampoline
  (testing "Fentry trampoline description"
    (let [desc (fentry/describe-fentry-trampoline "tcp_v4_connect" :fentry)]
      (is (= "tcp_v4_connect" (:function desc)))
      (is (= :fentry (:attach-type desc)))
      (is (= :tracing (:prog-type desc)))
      (is (vector? (:notes desc)))))

  (testing "Fexit trampoline description"
    (let [desc (fentry/describe-fentry-trampoline "tcp_v4_connect" :fexit)]
      (is (= :fexit (:attach-type desc)))
      (is (some #(and (string? %) (.contains ^String % "Return value"))
               (:notes desc))))))

;; ============================================================================
;; Complete Program Tests
;; ============================================================================

(deftest test-complete-fentry-program
  (testing "Full fentry program assembly"
    (let [insns (vec (concat
                      ;; Save first 2 args
                      (fentry/fentry-prologue [[0 :r6] [1 :r7]])
                      ;; Get PID
                      (fentry/fentry-log-pid)
                      ;; Save PID
                      [(dsl/mov-reg :r8 :r0)]
                      ;; Return 0
                      (fentry/fentry-return 0)))
          bytecode (dsl/assemble insns)]
      (is (vector? insns))
      (is (>= (count insns) 6))
      (is (bytes? bytecode))
      ;; At least 6 instructions * 8 bytes
      (is (>= (count bytecode) 48)))))

(deftest test-complete-fexit-program
  (testing "Full fexit program assembly"
    (let [insns (vec (concat
                      ;; Save first arg and return value
                      (fentry/fentry-prologue [[0 :r6]])
                      (fentry/fexit-get-return-value :r7)
                      ;; Get timestamp
                      (fentry/fentry-ktime-get-ns)
                      [(dsl/mov-reg :r8 :r0)]
                      ;; Return 0
                      (fentry/fentry-return 0)))
          bytecode (dsl/assemble insns)]
      (is (vector? insns))
      (is (>= (count insns) 5))
      (is (bytes? bytecode)))))

;; ============================================================================
;; Edge Case Tests
;; ============================================================================

(deftest test-edge-cases
  (testing "Empty body program"
    (let [bytecode (fentry/build-fentry-program {:body []})]
      (is (bytes? bytecode))
      ;; Should at least have exit
      (is (pos? (count bytecode)))))

  (testing "Max arguments (5)"
    (let [insns (fentry/fentry-prologue [[0 :r6] [1 :r7] [2 :r8] [3 :r9] [4 :r10]])]
      (is (= 5 (count insns)))
      (is (every? bytes? insns))))

  (testing "Non-contiguous argument saves"
    (let [insns (fentry/fentry-prologue [[0 :r6] [2 :r7] [4 :r8]])]
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Assembly Validation Tests
;; ============================================================================

(deftest test-assembly-validation
  (testing "All generated instructions are assemblable"
    (doseq [[name gen-fn] [["prologue" #(fentry/fentry-prologue [[0 :r6]])]
                           ["save-args" #(fentry/fentry-save-args 3)]
                           ["get-ret" #(fentry/fexit-get-return-value :r6)]
                           ["read-field" #(fentry/read-struct-field :r6 0 :r0 8)]
                           ["log-pid" #(fentry/fentry-log-pid)]
                           ["log-comm" #(fentry/fentry-log-comm :r1)]
                           ["ktime" #(fentry/fentry-ktime-get-ns)]
                           ["return" #(fentry/fentry-return 0)]]]
      (testing name
        (let [insns (gen-fn)]
          (is (every? bytes? insns) (str name " produces byte arrays"))
          (is (bytes? (dsl/assemble insns))
              (str name " assembles to bytes")))))))

;; ============================================================================
;; Instruction Count Tests
;; ============================================================================

(deftest test-instruction-counts
  (testing "Prologue instruction count matches arg count"
    (dotimes [n 5]
      (let [arg-saves (vec (for [i (range n)] [i (keyword (str "r" (+ i 6)))]))
            insns (fentry/fentry-prologue arg-saves)]
        (is (= n (count insns))))))

  (testing "Helper instruction counts"
    (is (= 2 (count (fentry/fentry-log-pid))))
    (is (= 3 (count (fentry/fentry-log-comm :r1))))
    (is (= 1 (count (fentry/fentry-ktime-get-ns))))
    (is (= 2 (count (fentry/fentry-return 0))))
    (is (= 3 (count (fentry/fentry-filter-by-pid 1 2))))
    (is (= 6 (count (fentry/fentry-filter-by-comm -16 "test" 2))))))

;; ============================================================================
;; Bytecode Size Tests
;; ============================================================================

(deftest test-bytecode-sizes
  (testing "Each instruction is 8 bytes"
    (let [single-insn (fentry/fentry-prologue [[0 :r6]])
          assembled (dsl/assemble single-insn)]
      (is (= 8 (count assembled)))))

  (testing "Multiple instructions"
    (let [insns (fentry/fentry-save-args 3)
          assembled (dsl/assemble insns)]
      (is (= 24 (count assembled))))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-api-completeness
  (testing "All public functions exist and are callable"
    (is (fn? fentry/arg-reg))
    (is (fn? fentry/fentry-prologue))
    (is (fn? fentry/fentry-save-args))
    (is (fn? fentry/fexit-get-return-value))
    (is (fn? fentry/read-struct-field))
    (is (fn? fentry/build-fentry-program))
    (is (fn? fentry/build-fexit-program))
    (is (fn? fentry/fentry-section-name))
    (is (fn? fentry/fexit-section-name))
    (is (fn? fentry/fmod-ret-section-name))
    (is (fn? fentry/make-fentry-program-info))
    (is (fn? fentry/make-fexit-program-info))
    (is (fn? fentry/make-fmod-ret-program-info))
    (is (fn? fentry/fentry-log-pid))
    (is (fn? fentry/fentry-log-comm))
    (is (fn? fentry/fentry-ktime-get-ns))
    (is (fn? fentry/fentry-return))
    (is (fn? fentry/fentry-filter-by-pid))
    (is (fn? fentry/fentry-filter-by-comm))
    (is (fn? fentry/describe-fentry-trampoline))
    ;; BTF integration
    (is (fn? fentry/resolve-btf-function))
    (is (fn? fentry/get-arg-by-name))
    (is (fn? fentry/get-arg-type))
    (is (fn? fentry/get-return-type))
    (is (fn? fentry/validate-fentry-target))
    (is (fn? fentry/suggest-arg-saves))))

;; ============================================================================
;; Data Structure Tests
;; ============================================================================

(deftest test-data-structures
  (testing "arg-registers has 5 entries"
    (is (= 5 (count fentry/arg-registers))))

  (testing "attach-types are distinct"
    (is (= 3 (count (set (vals fentry/fentry-attach-types))))))

  (testing "prog-types consistency"
    (is (= #{:tracing} (set (vals fentry/fentry-prog-types))))))
