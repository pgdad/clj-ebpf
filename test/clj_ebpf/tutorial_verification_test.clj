(ns clj-ebpf.tutorial-verification-test
  "Tests that verify tutorial code examples work correctly.
   CI-safe (no BPF privileges required - assembly only)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.core :as bpf]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.errors :as errors]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.core :as dsl-core]
            [clj-ebpf.dsl.alu :as alu]
            [clj-ebpf.dsl.mem :as mem]
            [clj-ebpf.dsl.jump :as jmp]
            [clj-ebpf.dsl.atomic :as atomic]
            [clj-ebpf.dsl.instructions :as insns]
            [clj-ebpf.helpers :as helpers]
            [clj-ebpf.constants :as const]))

;; ============================================
;; Chapter 1: Introduction to eBPF
;; ============================================

(deftest test-chapter-1-arch-module
  (testing "Chapter 1: Architecture detection"
    (is (keyword? arch/current-arch))
    (is (string? arch/arch-name))
    (is (number? (arch/get-syscall-nr :bpf)))))

(deftest test-chapter-1-hello-program
  (testing "Chapter 1: Hello eBPF program assembly"
    ;; From lab-1-1-hello-ebpf.md
    (let [hello-program (bpf/assemble
                          [(bpf/mov :r0 0)
                           (bpf/exit-insn)])]
      (is (bytes? hello-program))
      (is (= 16 (count hello-program)))  ;; 2 instructions * 8 bytes
      (is (= 2 (/ (count hello-program) 8))))))

(deftest test-chapter-1-variations
  (testing "Chapter 1: Program variations"
    ;; Return 42
    (let [prog1 (bpf/assemble
                  [(bpf/mov :r0 42)
                   (bpf/exit-insn)])]
      (is (= 16 (count prog1))))

    ;; Multiple instructions
    (let [prog2 (bpf/assemble
                  [(bpf/mov :r0 10)
                   (bpf/add :r0 32)
                   (bpf/exit-insn)])]
      (is (= 24 (count prog2))))))

;; ============================================
;; Chapter 2: BPF Maps
;; ============================================

(deftest test-chapter-2-map-types
  (testing "Chapter 2: Map types available"
    (is (= 1 (const/map-type->num :hash)))
    (is (= 2 (const/map-type->num :array)))
    (is (= 27 (const/map-type->num :ringbuf)))))

;; ============================================
;; Chapter 3: DSL Deep Dive
;; ============================================

(deftest test-chapter-3-dsl-imports
  (testing "Chapter 3: DSL module imports"
    ;; Test that all DSL modules are importable
    (is (fn? dsl/mov))
    (is (fn? dsl/add))
    (is (fn? dsl/sub))
    (is (fn? dsl/ldx))
    (is (fn? dsl/stx))
    (is (fn? dsl/ja))
    (is (fn? dsl/exit-insn))))

(deftest test-chapter-3-dsl-submodules
  (testing "Chapter 3: DSL submodule direct usage"
    ;; Using submodules directly (as shown in tutorials)
    (let [prog (dsl-core/assemble
                 [(alu/mov :r0 100)
                  (alu/add :r0 50)
                  (jmp/exit-insn)])]
      (is (= 24 (count prog))))))

(deftest test-chapter-3-atomic-operations
  (testing "Chapter 3: Atomic DSL module"
    ;; From Chapter 3 atomic operations section
    (is (fn? atomic/atomic-add))
    (is (fn? atomic/atomic-fetch-add))
    (is (fn? atomic/atomic-xchg))
    (is (fn? atomic/atomic-cmpxchg))
    (is (fn? atomic/atomic-available?))

    ;; Test atomic instruction generation - returns instruction map
    (let [insn (atomic/atomic-add :dw :r10 :r1 -8)]
      (is (map? insn))
      ;; Atomic instruction uses STX opcode class with ATOMIC flag
      (is (contains? insn :opcode)))

    ;; Test availability check
    (is (true? (atomic/atomic-available? :atomic-add "5.15")))
    (is (true? (atomic/atomic-available? :atomic-xchg "5.15")))))

;; ============================================
;; Chapter 4: Helpers
;; ============================================

(deftest test-chapter-4-helpers-module
  (testing "Chapter 4: Helpers search functionality"
    ;; Search helpers by name
    (let [results (helpers/search-helpers "get_current")]
      (is (sequential? results))
      (is (pos? (count results))))

    ;; Get all helpers
    (let [all-h (helpers/all-helpers)]
      (is (map? all-h))
      (is (pos? (count all-h))))

    ;; Filter by kernel version
    (let [early-helpers (helpers/helpers-until-kernel "4.1")]
      (is (sequential? early-helpers)))))

(deftest test-chapter-4-helper-stats
  (testing "Chapter 4: Helper statistics"
    (let [stats (helpers/helper-stats)]
      (is (map? stats))
      (is (number? (:total stats)))
      (is (pos? (:total stats))))))

;; ============================================
;; Error handling (used throughout tutorials)
;; ============================================

(deftest test-errors-module
  (testing "Errors module functions"
    (is (fn? errors/format-error))
    (is (fn? errors/permission-error?))
    (is (fn? errors/verifier-error?))))

;; ============================================
;; ALU operations (Chapter 3)
;; ============================================

(deftest test-alu-operations
  (testing "ALU operation instructions"
    ;; 64-bit operations with immediate
    (let [mov-insn (alu/mov :r0 0)]
      (is (map? mov-insn))
      (is (contains? mov-insn :opcode)))

    ;; 64-bit register-to-register operations
    (let [add-insn (alu/add-reg :r1 :r2)]
      (is (map? add-insn)))

    ;; 32-bit operations
    (let [add32-insn (alu/add32-reg :r1 :r2)]
      (is (map? add32-insn)))))

;; ============================================
;; Memory operations (Chapter 3)
;; ============================================

(deftest test-memory-operations
  (testing "Memory operation instructions"
    ;; Load operations: (ldx size dst src offset)
    (let [ldx-insn (mem/ldx :dw :r0 :r1 0)]
      (is (map? ldx-insn))
      (is (contains? ldx-insn :opcode)))

    ;; Store operations: (stx size dst src offset) - now matches main API
    (let [stx-insn (mem/stx :dw :r1 :r2 0)]
      (is (map? stx-insn))
      (is (contains? stx-insn :opcode)))))

;; ============================================
;; Jump operations (Chapter 3)
;; ============================================

(deftest test-jump-operations
  (testing "Jump and control flow instructions"
    ;; Unconditional jump
    (let [ja-insn (jmp/ja 5)]
      (is (map? ja-insn)))

    ;; Conditional jumps
    (let [jeq-insn (jmp/jeq :r0 0 5)]
      (is (map? jeq-insn)))

    ;; Exit
    (let [exit-insn (jmp/exit-insn)]
      (is (map? exit-insn)))))

;; ============================================
;; Complete program assembly (Lab examples)
;; ============================================

(deftest test-packet-counter-program
  (testing "Lab 2.1: Packet counter program structure"
    ;; Simplified packet counter (just tests assembly works)
    ;; Note: bpf/mov-reg for register moves, bpf/mov for immediate
    ;; bpf/stx signature: [size dst src offset]
    (let [prog (bpf/assemble
                 [(bpf/mov-reg :r6 :r1)       ; Save context (reg-to-reg)
                  (bpf/mov :r2 0)             ; Map lookup key immediate
                  (bpf/stx :dw :r10 :r2 -8)   ; Store key on stack (size dst src offset)
                  (bpf/mov :r0 0)             ; Return XDP_PASS
                  (bpf/exit-insn)])]
      (is (bytes? prog))
      (is (pos? (count prog))))))

(deftest test-syscall-tracer-structure
  (testing "Syscall tracer program structure"
    (let [prog (bpf/assemble
                 (vec (concat
                        (bpf/helper-get-current-pid-tgid)
                        [(bpf/mov :r0 0)
                         (bpf/exit-insn)])))]
      (is (bytes? prog)))))

;; ============================================
;; Tutorial-Compatible Aliases
;; ============================================

(deftest test-tutorial-compatible-aliases
  (testing "load-mem alias"
    ;; load-mem is alias for ldx with same signature
    (let [insn1 (bpf/load-mem :dw :r0 :r1 8)
          insn2 (bpf/ldx :dw :r0 :r1 8)]
      (is (= (vec insn1) (vec insn2)))))

  (testing "store-mem alias"
    ;; store-mem uses [size dst offset src] order (different from stx)
    ;; store-mem :dw :r10 -8 :r6 should produce same as stx :dw :r10 :r6 -8
    (let [insn1 (bpf/store-mem :dw :r10 -8 :r6)
          insn2 (bpf/stx :dw :r10 :r6 -8)]
      (is (= (vec insn1) (vec insn2)))))

  (testing "ld-map-fd alias"
    ;; ld-map-fd loads a map fd with BPF_PSEUDO_MAP_FD marker
    (let [insn (bpf/ld-map-fd :r1 42)]
      (is (bytes? insn))
      (is (= 16 (count insn)))))  ; lddw is 16 bytes (2 instructions)

  (testing "jmp alias"
    ;; jmp is alias for ja
    (let [insn1 (bpf/jmp 5)
          insn2 (bpf/ja 5)]
      (is (= (vec insn1) (vec insn2))))))

(deftest test-tutorial-program-patterns
  (testing "Tutorial pattern: map lookup with load-mem/store-mem"
    ;; This pattern is used extensively in tutorials
    (let [prog (bpf/assemble
                 [(bpf/mov :r6 42)                    ; key value
                  (bpf/store-mem :w :r10 -4 :r6)     ; store key on stack
                  (bpf/load-mem :w :r2 :r10 -4)      ; load key back
                  (bpf/mov :r0 0)
                  (bpf/exit-insn)])]
      (is (bytes? prog))
      (is (= 40 (count prog)))))  ; 5 instructions * 8 bytes

  (testing "Tutorial pattern: conditional with jmp"
    (let [prog (bpf/assemble
                 [(bpf/mov :r0 1)
                  (bpf/jmp-imm :jeq :r0 0 2)  ; if r0 == 0, skip 2
                  (bpf/mov :r0 42)
                  (bpf/jmp 1)                  ; skip next instruction
                  (bpf/mov :r0 0)
                  (bpf/exit-insn)])]
      (is (bytes? prog)))))

;; ============================================
;; Constants (used throughout)
;; ============================================

(deftest test-bpf-constants
  (testing "BPF constants used in tutorials"
    ;; XDP return codes
    (is (= 1 (:drop const/xdp-action)))
    (is (= 2 (:pass const/xdp-action)))

    ;; Program types
    (is (= 6 (const/prog-type->num :xdp)))
    (is (= 2 (const/prog-type->num :kprobe)))))
