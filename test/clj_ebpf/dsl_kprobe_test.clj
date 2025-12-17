(ns clj-ebpf.dsl-kprobe-test
  "Tests for the new kprobe DSL features including:
   - call-helper function
   - pt_regs argument reading
   - ring buffer DSL
   - event struct definitions
   - kprobe program builders"
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.core :as dsl-core]
            [clj-ebpf.dsl.jump :as jmp]
            [clj-ebpf.dsl.structs :as structs]
            [clj-ebpf.dsl.kprobe :as kprobe]))

;; ============================================================================
;; call-helper Tests
;; ============================================================================

(deftest test-call-helper
  (testing "call-helper generates correct instruction for known helpers"
    (let [insn (jmp/call-helper :ktime-get-ns)]
      (is (some? insn))
      ;; Returns an Instruction record, not bytes
      (is (instance? clj_ebpf.dsl.instructions.Instruction insn))
      ;; Verify it's a call instruction with correct helper ID
      (is (= 5 (:imm insn)))))  ; ktime-get-ns = 5

  (testing "call-helper throws for unknown helper"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unknown BPF helper"
          (jmp/call-helper :nonexistent-helper)))))

;; ============================================================================
;; pt_regs Offset Tests
;; ============================================================================

(deftest test-pt-regs-offsets
  (testing "get-kprobe-arg-offset returns correct offsets for x86_64"
    ;; On x86_64: arg0=rdi(112), arg1=rsi(104), arg2=rdx(96)
    (when (= arch/current-arch :x86_64)
      (is (= 112 (arch/get-kprobe-arg-offset 0)))  ; rdi
      (is (= 104 (arch/get-kprobe-arg-offset 1)))  ; rsi
      (is (= 96 (arch/get-kprobe-arg-offset 2)))))  ; rdx

  (testing "get-kprobe-arg-offset throws for out-of-range args"
    (is (thrown? clojure.lang.ExceptionInfo
          (arch/get-kprobe-arg-offset 100)))))

(deftest test-read-kprobe-arg
  (testing "read-kprobe-arg generates ldx instruction"
    (let [insn (dsl/read-kprobe-arg :r1 0 :r6)]
      (is (some? insn))
      (is (bytes? insn)))))

;; ============================================================================
;; Ring Buffer DSL Tests
;; ============================================================================

(deftest test-ringbuf-reserve
  (testing "ringbuf-reserve generates correct instruction sequence"
    (let [insns (dsl/ringbuf-reserve :r6 5 48)]
      (is (vector? insns))
      ;; Should have: ld-map-fd (2 words), mov size, mov flags, call, mov result
      (is (>= (count insns) 4)))))

(deftest test-ringbuf-submit
  (testing "ringbuf-submit generates correct instructions"
    (let [insns (dsl/ringbuf-submit :r6)]
      (is (vector? insns))
      (is (= 3 (count insns))))))  ; mov r1, mov r2, call

(deftest test-ringbuf-discard
  (testing "ringbuf-discard generates correct instructions"
    (let [insns (dsl/ringbuf-discard :r6)]
      (is (vector? insns))
      (is (= 3 (count insns))))))

;; ============================================================================
;; Event Struct Tests
;; ============================================================================

(structs/defevent TestConnectionEvent
  [:timestamp :u64]
  [:pid :u32]
  [:saddr :u32]
  [:daddr :u32]
  [:sport :u16]
  [:dport :u16]
  [:protocol :u8]
  [:direction :u8]
  [:padding :u8 2]
  [:comm :char 16])

(deftest test-defevent
  (testing "defevent creates correct structure definition"
    (is (= 44 (structs/event-size TestConnectionEvent)))
    (is (= [:timestamp :pid :saddr :daddr :sport :dport
            :protocol :direction :padding :comm]
           (structs/event-fields TestConnectionEvent)))))

(deftest test-event-field-offset
  (testing "event-field-offset returns correct offsets"
    (is (= 0 (structs/event-field-offset TestConnectionEvent :timestamp)))
    (is (= 8 (structs/event-field-offset TestConnectionEvent :pid)))
    (is (= 12 (structs/event-field-offset TestConnectionEvent :saddr)))
    (is (= 16 (structs/event-field-offset TestConnectionEvent :daddr)))
    (is (= 20 (structs/event-field-offset TestConnectionEvent :sport)))
    (is (= 22 (structs/event-field-offset TestConnectionEvent :dport)))
    (is (= 24 (structs/event-field-offset TestConnectionEvent :protocol)))
    (is (= 25 (structs/event-field-offset TestConnectionEvent :direction)))
    (is (= 28 (structs/event-field-offset TestConnectionEvent :comm)))))

(deftest test-event-field-size
  (testing "event-field-size returns correct sizes"
    (is (= 8 (structs/event-field-size TestConnectionEvent :timestamp)))
    (is (= 4 (structs/event-field-size TestConnectionEvent :pid)))
    (is (= 2 (structs/event-field-size TestConnectionEvent :sport)))
    (is (= 1 (structs/event-field-size TestConnectionEvent :protocol)))
    (is (= 16 (structs/event-field-size TestConnectionEvent :comm)))))

(deftest test-store-event-field
  (testing "store-event-field generates stx instruction"
    (let [insn (structs/store-event-field :r6 TestConnectionEvent :pid :r7)]
      (is (some? insn))
      ;; Returns an Instruction record
      (is (instance? clj_ebpf.dsl.instructions.Instruction insn))
      ;; Verify correct offset (pid is at offset 8)
      (is (= 8 (:offset insn)))))

  (testing "store-event-field throws for unknown field"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unknown field"
          (structs/store-event-field :r6 TestConnectionEvent :nonexistent :r7)))))

(deftest test-store-event-imm
  (testing "store-event-imm generates st instruction"
    (let [insn (structs/store-event-imm :r6 TestConnectionEvent :protocol 6)]
      (is (some? insn))
      ;; Returns an Instruction record
      (is (instance? clj_ebpf.dsl.instructions.Instruction insn))
      ;; Verify correct value
      (is (= 6 (:imm insn))))))

;; ============================================================================
;; Kprobe Builder Tests
;; ============================================================================

(deftest test-kprobe-prologue
  (testing "kprobe-prologue generates correct prologue"
    (let [insns (kprobe/kprobe-prologue [:r6 :r7])]
      (is (vector? insns))
      (is (= 2 (count insns)))))  ; Two ldx instructions for two args

  (testing "kprobe-prologue with context save"
    (let [insns (kprobe/kprobe-prologue :r9 [:r6])]
      (is (vector? insns))
      (is (= 2 (count insns))))))  ; mov + ldx

(deftest test-kprobe-section-name
  (testing "kprobe-section-name generates correct name"
    (is (= "kprobe/tcp_v4_connect"
           (kprobe/kprobe-section-name "tcp_v4_connect"))))

  (testing "kretprobe-section-name generates correct name"
    (is (= "kretprobe/tcp_v4_connect"
           (kprobe/kretprobe-section-name "tcp_v4_connect")))))

(deftest test-make-kprobe-program-info
  (testing "make-kprobe-program-info creates correct metadata"
    (let [info (kprobe/make-kprobe-program-info
                "tcp_v4_connect"
                "tcp-connect-probe"
                [(dsl/mov :r0 0) (dsl/exit-insn)])]
      (is (= "tcp-connect-probe" (:name info)))
      (is (= "kprobe/tcp_v4_connect" (:section info)))
      (is (= :kprobe (:type info)))
      (is (= "tcp_v4_connect" (:function info))))))

;; ============================================================================
;; dsl/core.clj Re-export Tests
;; ============================================================================

(deftest test-dsl-core-reexports
  (testing "dsl/core.clj re-exports call-helper"
    (is (some? dsl-core/call-helper)))

  (testing "dsl/core.clj re-exports event functions"
    (is (some? dsl-core/event-size))
    (is (some? dsl-core/event-field-offset))
    (is (some? dsl-core/store-event-field)))

  (testing "dsl/core.clj re-exports kprobe functions"
    (is (some? dsl-core/kprobe-prologue))
    (is (some? dsl-core/build-kprobe-program))))

;; ============================================================================
;; Integration Test: Complete Kprobe Program
;; ============================================================================

(deftest test-complete-kprobe-program
  (testing "Can build a complete kprobe program"
    (let [program-bytes
          (dsl/assemble
           (vec (concat
                 ;; Prologue: read first argument (sk pointer) into r6
                 (kprobe/kprobe-prologue [:r6])
                 ;; Get current PID/TGID
                 (dsl/helper-get-current-pid-tgid)
                 ;; Move result to r7
                 [(dsl/mov-reg :r7 :r0)]
                 ;; Return 0
                 [(dsl/mov :r0 0)
                  (dsl/exit-insn)])))]
      (is (bytes? program-bytes))
      (is (pos? (alength program-bytes))))))
