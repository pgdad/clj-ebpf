(ns clj-ebpf.dsl-tracepoint-test
  "Tests for Tracepoint DSL features
   CI-safe (no BPF privileges required) - uses static format definitions"
  {:ci-safe true}
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.dsl.tracepoint :as tp]
            [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Static Format Tests
;; ============================================================================

(deftest test-static-format-availability
  (testing "Common tracepoint formats are pre-defined"
    (is (some? tp/common-tracepoint-formats))
    (is (map? tp/common-tracepoint-formats))
    (is (>= (count tp/common-tracepoint-formats) 5)))

  (testing "sched/sched_switch format is available"
    (let [format (tp/get-static-format "sched" "sched_switch")]
      (is (some? format))
      (is (= "sched" (:category format)))
      (is (= "sched_switch" (:name format)))
      (is (vector? (:fields format)))
      (is (vector? (:common-fields format)))))

  (testing "syscalls/sys_enter_execve format is available"
    (let [format (tp/get-static-format "syscalls" "sys_enter_execve")]
      (is (some? format))
      (is (= "syscalls" (:category format)))
      (is (vector? (:fields format)))))

  (testing "raw_syscalls/sys_enter format is available"
    (let [format (tp/get-static-format "raw_syscalls" "sys_enter")]
      (is (some? format))
      (is (vector? (:fields format))))))

;; ============================================================================
;; Format Field Tests
;; ============================================================================

(deftest test-sched-switch-fields
  (testing "sched_switch has expected fields"
    (let [format (tp/get-static-format "sched" "sched_switch")]
      (is (some? format))

      ;; Check user fields
      (let [field-names (set (map :name (:fields format)))]
        (is (contains? field-names :prev_comm))
        (is (contains? field-names :prev_pid))
        (is (contains? field-names :prev_prio))
        (is (contains? field-names :prev_state))
        (is (contains? field-names :next_comm))
        (is (contains? field-names :next_pid))
        (is (contains? field-names :next_prio)))

      ;; Check common fields
      (let [common-names (set (map :name (:common-fields format)))]
        (is (contains? common-names :common_type))
        (is (contains? common-names :common_pid))))))

(deftest test-field-offsets
  (testing "sched_switch field offsets are correct"
    (let [format (tp/get-static-format "sched" "sched_switch")]
      ;; Common fields
      (is (= 0 (tp/tracepoint-field-offset format :common_type)))
      (is (= 4 (tp/tracepoint-field-offset format :common_pid)))

      ;; User fields
      (is (= 8 (tp/tracepoint-field-offset format :prev_comm)))
      (is (= 24 (tp/tracepoint-field-offset format :prev_pid)))
      (is (= 56 (tp/tracepoint-field-offset format :next_pid)))))

  (testing "sys_enter field offsets are correct"
    (let [format (tp/get-static-format "raw_syscalls" "sys_enter")]
      (is (= 8 (tp/tracepoint-field-offset format :id)))
      (is (= 16 (tp/tracepoint-field-offset format :args))))))

(deftest test-field-sizes
  (testing "sched_switch field sizes are correct"
    (let [format (tp/get-static-format "sched" "sched_switch")]
      (is (= 2 (tp/tracepoint-field-size format :common_type)))
      (is (= 4 (tp/tracepoint-field-size format :common_pid)))
      (is (= 16 (tp/tracepoint-field-size format :prev_comm)))
      (is (= 4 (tp/tracepoint-field-size format :prev_pid)))
      (is (= 8 (tp/tracepoint-field-size format :prev_state)))))

  (testing "sys_enter field sizes are correct"
    (let [format (tp/get-static-format "raw_syscalls" "sys_enter")]
      (is (= 8 (tp/tracepoint-field-size format :id)))
      (is (= 48 (tp/tracepoint-field-size format :args))))))

(deftest test-field-info
  (testing "tracepoint-field-info returns complete field data"
    (let [format (tp/get-static-format "sched" "sched_switch")
          field (tp/tracepoint-field-info format :prev_pid)]
      (is (some? field))
      (is (= :prev_pid (:name field)))
      (is (= 24 (:offset field)))
      (is (= 4 (:size field)))
      (is (:signed field))
      (is (string? (:type field)))))

  (testing "tracepoint-field-info returns nil for unknown field"
    (let [format (tp/get-static-format "sched" "sched_switch")]
      (is (thrown? clojure.lang.ExceptionInfo
            (tp/tracepoint-field-offset format :nonexistent_field))))))

(deftest test-tracepoint-fields-list
  (testing "tracepoint-fields returns user fields by default"
    (let [format (tp/get-static-format "sched" "sched_switch")
          fields (tp/tracepoint-fields format)]
      (is (vector? fields))
      (is (= 7 (count fields)))
      (is (every? keyword? fields))
      (is (not (some #(clojure.string/starts-with? (name %) "common_") fields)))))

  (testing "tracepoint-fields with include-common returns all fields"
    (let [format (tp/get-static-format "sched" "sched_switch")
          all-fields (tp/tracepoint-fields format true)]
      (is (> (count all-fields) 7))
      (is (some #(clojure.string/starts-with? (name %) "common_") all-fields)))))

;; ============================================================================
;; Instruction Generation Tests
;; ============================================================================

(deftest test-read-field-instruction
  (testing "tracepoint-read-field generates correct ldx for 4-byte field"
    (let [format (tp/get-static-format "sched" "sched_switch")
          insn (tp/tracepoint-read-field :r1 format :prev_pid :r6)]
      (is (some? insn))
      (is (bytes? insn))
      (is (= 8 (count insn)))))

  (testing "tracepoint-read-field generates correct ldx for 8-byte field"
    (let [format (tp/get-static-format "sched" "sched_switch")
          insn (tp/tracepoint-read-field :r1 format :prev_state :r6)]
      (is (some? insn))
      (is (bytes? insn))
      (is (= 8 (count insn)))))

  (testing "tracepoint-read-field generates correct ldx for 2-byte field"
    (let [format (tp/get-static-format "sched" "sched_switch")
          insn (tp/tracepoint-read-field :r1 format :common_type :r6)]
      (is (some? insn))
      (is (bytes? insn)))))

(deftest test-read-fields-multiple
  (testing "tracepoint-read-fields generates multiple instructions"
    (let [format (tp/get-static-format "sched" "sched_switch")
          insns (tp/tracepoint-read-fields :r1 format {:prev_pid :r6 :next_pid :r7})]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Prologue Generation Tests
;; ============================================================================

(deftest test-prologue-generation
  (testing "tracepoint-prologue with context save generates mov + field loads"
    (let [format (tp/get-static-format "sched" "sched_switch")
          prologue (tp/tracepoint-prologue :r9 format {:prev_pid :r6})]
      (is (vector? prologue))
      (is (= 2 (count prologue)))  ; mov r9, r1 + ldx r6
      (is (every? bytes? prologue))))

  (testing "tracepoint-prologue without context save"
    (let [format (tp/get-static-format "sched" "sched_switch")
          prologue (tp/tracepoint-prologue format {:prev_pid :r6 :next_pid :r7})]
      (is (vector? prologue))
      (is (= 2 (count prologue)))  ; Just field loads
      (is (every? bytes? prologue))))

  (testing "tracepoint-prologue with empty fields"
    (let [format (tp/get-static-format "sched" "sched_switch")
          prologue (tp/tracepoint-prologue :r9 format {})]
      (is (vector? prologue))
      (is (= 1 (count prologue)))  ; Just context save
      (is (bytes? (first prologue))))))

;; ============================================================================
;; Program Building Tests
;; ============================================================================

(deftest test-build-tracepoint-program
  (testing "build-tracepoint-program creates valid bytecode"
    (let [prog (tp/build-tracepoint-program
                {:category "sched"
                 :name "sched_switch"
                 :fields {:prev_pid :r6}
                 :body []
                 :return-value 0})]
      (is (bytes? prog))
      (is (> (count prog) 0))
      (is (zero? (mod (count prog) 8)))))  ; 8-byte aligned

  (testing "build-tracepoint-program with body instructions"
    (let [prog (tp/build-tracepoint-program
                {:category "sched"
                 :name "sched_switch"
                 :fields {:prev_pid :r6 :next_pid :r7}
                 :ctx-reg :r9
                 :body [(dsl/mov-reg :r8 :r6)
                        (dsl/add :r8 1)]
                 :return-value 0})]
      (is (bytes? prog))
      ;; Prologue (3) + body (2) + epilogue (2) = 7 instructions = 56 bytes
      (is (>= (count prog) 40)))))

(deftest test-build-tracepoint-program-raw-syscalls
  (testing "build-tracepoint-program works with raw_syscalls"
    (let [prog (tp/build-tracepoint-program
                {:category "raw_syscalls"
                 :name "sys_enter"
                 :fields {:id :r6}
                 :body []
                 :return-value 0})]
      (is (bytes? prog))
      (is (> (count prog) 0)))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(tp/deftracepoint-instructions test-sched-switch
  {:category "sched"
   :name "sched_switch"
   :fields {:prev_pid :r6 :next_pid :r7}
   :ctx-reg :r9}
  [(dsl/mov :r0 0)
   (dsl/exit-insn)])

(deftest test-deftracepoint-instructions-macro
  (testing "deftracepoint-instructions creates a function"
    (is (fn? test-sched-switch)))

  (testing "deftracepoint-instructions returns instructions"
    (let [insns (test-sched-switch)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "deftracepoint-instructions includes prologue"
    (let [insns (test-sched-switch)]
      ;; Should have: mov r9,r1 + 2 field loads + 2 body insns = 5
      (is (>= (count insns) 5)))))

(tp/defraw-tracepoint-instructions test-raw-sys-enter
  {:name "sys_enter"
   :ctx-reg :r9}
  [(dsl/ldx :dw :r6 :r1 0)
   (dsl/mov :r0 0)
   (dsl/exit-insn)])

(deftest test-defraw-tracepoint-instructions-macro
  (testing "defraw-tracepoint-instructions creates a function"
    (is (fn? test-raw-sys-enter)))

  (testing "defraw-tracepoint-instructions returns instructions"
    (let [insns (test-raw-sys-enter)]
      (is (vector? insns))
      (is (= 4 (count insns)))  ; mov + 3 body insns
      (is (every? bytes? insns)))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-section-names
  (testing "tracepoint-section-name generates correct format"
    (is (= "tracepoint/sched/sched_switch"
           (tp/tracepoint-section-name "sched" "sched_switch")))
    (is (= "tracepoint/syscalls/sys_enter_execve"
           (tp/tracepoint-section-name "syscalls" "sys_enter_execve"))))

  (testing "raw-tracepoint-section-name generates correct format"
    (is (= "raw_tracepoint/sys_enter"
           (tp/raw-tracepoint-section-name "sys_enter")))
    (is (= "raw_tracepoint/sys_exit"
           (tp/raw-tracepoint-section-name "sys_exit")))))

;; ============================================================================
;; Program Info Tests
;; ============================================================================

(deftest test-program-info
  (testing "make-tracepoint-program-info returns correct structure"
    (let [info (tp/make-tracepoint-program-info "sched" "sched_switch" "my_prog" [])]
      (is (map? info))
      (is (= "my_prog" (:name info)))
      (is (= "tracepoint/sched/sched_switch" (:section info)))
      (is (= :tracepoint (:type info)))
      (is (= "sched" (:category info)))
      (is (= "sched_switch" (:tracepoint info)))
      (is (vector? (:instructions info)))))

  (testing "make-raw-tracepoint-program-info returns correct structure"
    (let [info (tp/make-raw-tracepoint-program-info "sys_enter" "raw_prog" [])]
      (is (map? info))
      (is (= "raw_prog" (:name info)))
      (is (= "raw_tracepoint/sys_enter" (:section info)))
      (is (= :raw-tracepoint (:type info)))
      (is (= "sys_enter" (:tracepoint info))))))

;; ============================================================================
;; Format Path Tests
;; ============================================================================

(deftest test-format-paths
  (testing "tracepoint-format-path generates correct path"
    (let [path (tp/tracepoint-format-path "sched" "sched_switch")]
      (is (string? path))
      (is (clojure.string/includes? path "sched"))
      (is (clojure.string/includes? path "sched_switch"))
      (is (clojure.string/includes? path "format"))))

  (testing "tracepoint-id-path generates correct path"
    (let [path (tp/tracepoint-id-path "sched" "sched_switch")]
      (is (string? path))
      (is (clojure.string/includes? path "sched"))
      (is (clojure.string/includes? path "sched_switch"))
      (is (clojure.string/includes? path "id")))))

;; ============================================================================
;; Format Parsing Tests
;; ============================================================================

(deftest test-parse-field-line
  (testing "parse-field-line parses standard field"
    (let [line "\tfield:pid_t prev_pid;\toffset:24;\tsize:4;\tsigned:1;"
          result (#'tp/parse-field-line line)]
      (is (some? result))
      (is (= :prev_pid (:name result)))
      (is (= 24 (:offset result)))
      (is (= 4 (:size result)))
      (is (:signed result))))

  (testing "parse-field-line parses unsigned field"
    (let [line "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;"
          result (#'tp/parse-field-line line)]
      (is (some? result))
      (is (= :common_type (:name result)))
      (is (= 0 (:offset result)))
      (is (= 2 (:size result)))
      (is (not (:signed result)))))

  (testing "parse-field-line parses array field"
    (let [line "\tfield:char prev_comm[16];\toffset:8;\tsize:16;\tsigned:0;"
          result (#'tp/parse-field-line line)]
      (is (some? result))
      (is (= :prev_comm (:name result)))
      (is (= 8 (:offset result)))
      (is (= 16 (:size result)))))

  (testing "parse-field-line returns nil for non-field lines"
    (is (nil? (#'tp/parse-field-line "name: sched_switch")))
    (is (nil? (#'tp/parse-field-line "")))
    (is (nil? (#'tp/parse-field-line nil)))))

;; ============================================================================
;; Cache Tests
;; ============================================================================

(deftest test-format-cache
  (testing "clear-format-cache! clears the cache and returns empty map"
    (tp/clear-format-cache!)
    ;; Should not throw and returns empty map
    (is (= {} (tp/clear-format-cache!)))))

;; ============================================================================
;; Error Handling Tests
;; ============================================================================

(deftest test-error-handling
  (testing "get-static-format returns nil for unknown tracepoint"
    (is (nil? (tp/get-static-format "nonexistent" "fake_tracepoint"))))

  (testing "tracepoint-field-offset throws for unknown field"
    (let [format (tp/get-static-format "sched" "sched_switch")]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"field not found"
            (tp/tracepoint-field-offset format :nonexistent_field))))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-api-completeness
  (testing "All core functions are defined"
    (is (fn? tp/parse-tracepoint-format))
    (is (fn? tp/get-tracepoint-format))
    (is (fn? tp/get-static-format))
    (is (fn? tp/get-format))
    (is (fn? tp/tracepoint-field-offset))
    (is (fn? tp/tracepoint-field-size))
    (is (fn? tp/tracepoint-field-info))
    (is (fn? tp/tracepoint-fields))
    (is (fn? tp/tracepoint-read-field))
    (is (fn? tp/tracepoint-read-fields))
    (is (fn? tp/tracepoint-prologue))
    (is (fn? tp/build-tracepoint-program))
    (is (fn? tp/tracepoint-section-name))
    (is (fn? tp/raw-tracepoint-section-name))
    (is (fn? tp/make-tracepoint-program-info))
    (is (fn? tp/make-raw-tracepoint-program-info))
    (is (fn? tp/clear-format-cache!)))

  (testing "Discovery functions are defined"
    (is (fn? tp/find-tracefs))
    (is (fn? tp/list-tracepoint-categories))
    (is (fn? tp/list-tracepoints))
    (is (fn? tp/tracepoint-exists?))))

(deftest test-documentation
  (testing "Core functions have docstrings"
    (is (string? (:doc (meta #'tp/parse-tracepoint-format))))
    (is (string? (:doc (meta #'tp/tracepoint-prologue))))
    (is (string? (:doc (meta #'tp/build-tracepoint-program))))
    (is (string? (:doc (meta #'tp/tracepoint-section-name))))))

;; ============================================================================
;; Integration Tests
;; ============================================================================

(deftest test-complete-program-assembly
  (testing "Complete tracepoint program assembles correctly"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          (let [format (tp/get-static-format "sched" "sched_switch")]
                            (tp/tracepoint-prologue :r9 format {:prev_pid :r6 :next_pid :r7}))
                          ;; Body
                          (dsl/helper-get-current-pid-tgid)
                          [(dsl/mov-reg :r8 :r0)]
                          ;; Exit
                          [(dsl/mov :r0 0)
                           (dsl/exit-insn)])))]
      (is (bytes? bytecode))
      (is (> (count bytecode) 0))
      (is (zero? (mod (count bytecode) 8))))))

(deftest test-syscall-tracepoint-program
  (testing "Syscall tracepoint program builds correctly"
    (let [format (tp/get-static-format "syscalls" "sys_enter_execve")
          prog (tp/build-tracepoint-program
                {:category "syscalls"
                 :name "sys_enter_execve"
                 :fields {:__syscall_nr :r6 :filename :r7}
                 :body [(dsl/mov-reg :r8 :r6)]
                 :return-value 0})]
      (is (bytes? prog))
      (is (> (count prog) 32)))))
