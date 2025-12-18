(ns clj-ebpf.dsl-perf-event-test
  "Tests for Perf Event DSL - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.perf-event :as perf]))

;; ============================================================================
;; Type and Config Tests
;; ============================================================================

(deftest test-perf-types
  (testing "Perf type values"
    (is (= 0 (:hardware perf/perf-types)))
    (is (= 1 (:software perf/perf-types)))
    (is (= 2 (:tracepoint perf/perf-types)))
    (is (= 3 (:hw-cache perf/perf-types)))
    (is (= 4 (:raw perf/perf-types)))
    (is (= 5 (:breakpoint perf/perf-types)))))

(deftest test-hardware-events
  (testing "Hardware event values"
    (is (= 0 (:cpu-cycles perf/hardware-events)))
    (is (= 1 (:instructions perf/hardware-events)))
    (is (= 2 (:cache-references perf/hardware-events)))
    (is (= 3 (:cache-misses perf/hardware-events)))
    (is (= 4 (:branch-instructions perf/hardware-events)))
    (is (= 5 (:branch-misses perf/hardware-events)))))

(deftest test-software-events
  (testing "Software event values"
    (is (= 0 (:cpu-clock perf/software-events)))
    (is (= 1 (:task-clock perf/software-events)))
    (is (= 2 (:page-faults perf/software-events)))
    (is (= 3 (:context-switches perf/software-events)))
    (is (= 4 (:cpu-migrations perf/software-events)))))

;; ============================================================================
;; Offset Tests
;; ============================================================================

(deftest test-perf-event-offsets
  (testing "bpf_perf_event_data offsets"
    (is (= 0 (perf/perf-event-offset :regs)))
    (is (= 128 (perf/perf-event-offset :sample-period)))
    (is (= 136 (perf/perf-event-offset :addr))))

  (testing "Invalid offset throws"
    (is (thrown? clojure.lang.ExceptionInfo
                (perf/perf-event-offset :invalid)))))

;; ============================================================================
;; Prologue Tests
;; ============================================================================

(deftest test-perf-event-prologue
  (testing "Empty prologue"
    (let [insns (perf/perf-event-prologue)]
      (is (= 0 (count insns)))))

  (testing "Prologue with context save"
    (let [insns (perf/perf-event-prologue :r6)]
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

;; ============================================================================
;; Data Access Tests
;; ============================================================================

(deftest test-perf-get-sample-period
  (testing "Get sample period"
    (let [insn (perf/perf-get-sample-period :r1 :r0)]
      (is (bytes? insn)))))

(deftest test-perf-get-addr
  (testing "Get event address"
    (let [insn (perf/perf-get-addr :r1 :r0)]
      (is (bytes? insn)))))

(deftest test-perf-get-ip
  (testing "Get instruction pointer"
    (let [insn (perf/perf-get-ip :r1 :r0)]
      (is (bytes? insn)))))

;; ============================================================================
;; Helper Tests
;; ============================================================================

(deftest test-perf-get-current-pid
  (testing "Get PID instructions"
    (let [insns (perf/perf-get-current-pid)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-perf-get-ktime-ns
  (testing "Get kernel time"
    (let [insns (perf/perf-get-ktime-ns)]
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

;; ============================================================================
;; Builder Tests
;; ============================================================================

(deftest test-build-perf-event-program
  (testing "Minimal program"
    (let [bytecode (perf/build-perf-event-program {:body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "Program with context"
    (let [bytecode (perf/build-perf-event-program
                    {:ctx-reg :r6
                     :body [(perf/perf-get-sample-period :r6 :r0)]
                     :return-value 0})]
      (is (bytes? bytecode)))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(perf/defperf-event-instructions test-profiler
  {:type :software
   :config :cpu-clock
   :ctx-reg :r6}
  (perf/perf-get-current-pid))

(perf/defperf-event-instructions test-minimal
  {:type :hardware
   :config :cpu-cycles}
  [])

(deftest test-defperf-event-macro
  (testing "Profiler macro"
    (let [insns (test-profiler)]
      (is (vector? insns))
      (is (>= (count insns) 4))
      (is (every? bytes? insns))))

  (testing "Minimal macro"
    (let [insns (test-minimal)]
      (is (vector? insns))
      (is (>= (count insns) 2))))

  (testing "Assembly works"
    (is (bytes? (dsl/assemble (test-profiler))))
    (is (bytes? (dsl/assemble (test-minimal))))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-section-names
  (testing "Default section"
    (is (= "perf_event" (perf/perf-event-section-name))))

  (testing "Named section"
    (is (= "perf_event/my_profiler"
           (perf/perf-event-section-name "my_profiler")))))

;; ============================================================================
;; Metadata Tests
;; ============================================================================

(deftest test-program-metadata
  (testing "Perf event info"
    (let [info (perf/make-perf-event-info
                "my_profiler" :software :cpu-clock (test-profiler))]
      (is (= "my_profiler" (:name info)))
      (is (= "perf_event/my_profiler" (:section info)))
      (is (= :perf-event (:type info)))
      (is (= :software (:perf-type info)))
      (is (= :cpu-clock (:config info)))
      (is (vector? (:instructions info))))))

;; ============================================================================
;; Flag Tests
;; ============================================================================

(deftest test-stackid-flags
  (testing "Stackid flag values"
    (is (= 256 (:user-stack perf/stackid-flags)))
    (is (= 512 (:fast-stack-cmp perf/stackid-flags)))
    (is (= 1024 (:reuse-stackid perf/stackid-flags))))

  (testing "stackid-flag function"
    (is (= 256 (perf/stackid-flag :user-stack)))
    (is (= 512 (perf/stackid-flag :fast-stack-cmp))))

  (testing "Combined flags"
    (is (= 768 (perf/stackid-flag #{:user-stack :fast-stack-cmp}))))

  (testing "Invalid flag throws"
    (is (thrown? clojure.lang.ExceptionInfo
                (perf/stackid-flag :invalid)))))

;; ============================================================================
;; Return Pattern Tests
;; ============================================================================

(deftest test-perf-return
  (testing "Default return"
    (let [insns (perf/perf-return)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "Return specific value"
    (let [insns (perf/perf-return 42)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Describe Tests
;; ============================================================================

(deftest test-describe-perf-event
  (testing "Hardware event description"
    (let [info (perf/describe-perf-event :hardware)]
      (is (= :hardware (:type info)))
      (is (= 0 (:type-value info)))
      (is (coll? (:available-configs info)))
      (is (vector? (:notes info)))))

  (testing "Software event description"
    (let [info (perf/describe-perf-event :software)]
      (is (= :software (:type info)))
      (is (= 1 (:type-value info))))))

;; ============================================================================
;; Complete Program Tests
;; ============================================================================

(deftest test-complete-programs
  (testing "CPU profiler program"
    (let [insns (vec (concat
                      (perf/perf-event-prologue :r6)
                      (perf/perf-get-current-pid)
                      [(dsl/mov-reg :r7 :r0)]
                      (perf/perf-get-ktime-ns)
                      (perf/perf-return 0)))
          bytecode (dsl/assemble insns)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "Event address program"
    (let [insns (vec (concat
                      (perf/perf-event-prologue :r6)
                      [(perf/perf-get-addr :r6 :r7)]
                      (perf/perf-return 0)))
          bytecode (dsl/assemble insns)]
      (is (bytes? bytecode)))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-api-completeness
  (testing "Core functions exist"
    (is (fn? perf/perf-event-offset))
    (is (fn? perf/perf-event-prologue))
    (is (fn? perf/perf-get-sample-period))
    (is (fn? perf/perf-get-addr))
    (is (fn? perf/perf-get-ip))
    (is (fn? perf/build-perf-event-program))
    (is (fn? perf/perf-event-section-name))
    (is (fn? perf/make-perf-event-info)))

  (testing "Helper functions exist"
    (is (fn? perf/perf-get-current-pid))
    (is (fn? perf/perf-get-ktime-ns))
    (is (fn? perf/perf-get-stackid))
    (is (fn? perf/perf-output))
    (is (fn? perf/perf-read)))

  (testing "Utility functions exist"
    (is (fn? perf/stackid-flag))
    (is (fn? perf/perf-return))
    (is (fn? perf/describe-perf-event))))

;; ============================================================================
;; Data Structure Tests
;; ============================================================================

(deftest test-data-structures
  (testing "Perf types count"
    (is (= 6 (count perf/perf-types))))

  (testing "Hardware events count"
    (is (= 10 (count perf/hardware-events))))

  (testing "Software events count"
    (is (= 11 (count perf/software-events))))

  (testing "Perf event data offsets"
    (is (= 3 (count perf/perf-event-data-offsets)))))
