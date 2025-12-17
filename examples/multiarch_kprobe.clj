(ns multiarch-kprobe
  "Multi-Architecture Kprobe Example

   This example demonstrates how clj-ebpf handles architecture differences
   automatically when building kprobe programs. The kprobe DSL abstracts
   away the differences in pt_regs layouts between architectures.

   Supported architectures:
   - x86_64 (AMD64)
   - ARM64 (AArch64)
   - s390x (IBM Z)
   - PPC64LE (PowerPC 64-bit Little Endian)
   - RISC-V 64-bit

   Key concepts demonstrated:
   - Architecture detection
   - pt_regs offset abstraction
   - Portable kprobe programs
   - Architecture-specific considerations"
  (:require [clj-ebpf.arch :as arch]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.kprobe :as kprobe]))

;; ============================================================================
;; Architecture Information
;; ============================================================================

(defn print-arch-info
  "Print information about the current architecture."
  []
  (println "=== Architecture Information ===\n")
  (println "Current architecture:" arch/current-arch)
  (println "Architecture name:" arch/arch-name)
  (println)

  ;; Print pt_regs argument offsets for this architecture
  (println "pt_regs argument offsets (for reading function arguments in kprobes):")
  (doseq [i (range 6)]
    (try
      (let [offset (arch/get-kprobe-arg-offset i)]
        (printf "  arg%d: offset %d (0x%x)\n" i offset offset))
      (catch Exception e
        (printf "  arg%d: not available\n" i))))
  (println))

;; ============================================================================
;; Architecture-Specific pt_regs Layouts
;; ============================================================================

;; Reference: How different architectures pass function arguments
;;
;; x86_64 (System V ABI):
;;   arg0: RDI (offset 112 in pt_regs)
;;   arg1: RSI (offset 104)
;;   arg2: RDX (offset 96)
;;   arg3: RCX (offset 88) - note: R10 for syscalls
;;   arg4: R8  (offset 72)
;;   arg5: R9  (offset 64)
;;   Return: RAX (offset 80)
;;
;; ARM64 (AAPCS64):
;;   arg0-arg7: X0-X7 (offsets 0, 8, 16, 24, 32, 40, 48, 56)
;;   Return: X0 (offset 0)
;;
;; s390x:
;;   arg0-arg5: R2-R7 (offsets vary)
;;   Return: R2
;;
;; PPC64LE:
;;   arg0-arg7: R3-R10
;;   Return: R3
;;
;; RISC-V64:
;;   arg0-arg7: a0-a7
;;   Return: a0

(def arch-info
  "Reference information about each supported architecture."
  {:x86_64
   {:name "x86_64 (AMD64)"
    :arg-registers ["rdi" "rsi" "rdx" "rcx" "r8" "r9"]
    :return-register "rax"
    :stack-pointer "rsp"
    :frame-pointer "rbp"
    :notes "Most common server architecture. Uses System V ABI."}

   :arm64
   {:name "ARM64 (AArch64)"
    :arg-registers ["x0" "x1" "x2" "x3" "x4" "x5" "x6" "x7"]
    :return-register "x0"
    :stack-pointer "sp"
    :frame-pointer "x29"
    :notes "Common in mobile, embedded, and modern servers (AWS Graviton, Apple M1)."}

   :s390x
   {:name "s390x (IBM Z)"
    :arg-registers ["r2" "r3" "r4" "r5" "r6"]
    :return-register "r2"
    :stack-pointer "r15"
    :frame-pointer "r11"
    :notes "IBM mainframe architecture."}

   :ppc64le
   {:name "PPC64LE (PowerPC 64-bit Little Endian)"
    :arg-registers ["r3" "r4" "r5" "r6" "r7" "r8" "r9" "r10"]
    :return-register "r3"
    :stack-pointer "r1"
    :frame-pointer "r31"
    :notes "IBM POWER architecture, little-endian variant."}

   :riscv64
   {:name "RISC-V 64-bit"
    :arg-registers ["a0" "a1" "a2" "a3" "a4" "a5" "a6" "a7"]
    :return-register "a0"
    :stack-pointer "sp"
    :frame-pointer "fp/s0"
    :notes "Open-source ISA, growing adoption."}})

(defn print-all-arch-info
  "Print reference information about all supported architectures."
  []
  (println "=== Supported Architectures Reference ===\n")
  (doseq [[arch-key info] arch-info]
    (println (:name info))
    (println "  Arguments:" (clojure.string/join ", " (:arg-registers info)))
    (println "  Return:" (:return-register info))
    (println "  Notes:" (:notes info))
    (println)))

;; ============================================================================
;; Portable Kprobe Building
;; ============================================================================

(defn build-portable-kprobe
  "Build a kprobe program that works on any supported architecture.

   The kprobe-prologue function automatically uses the correct pt_regs
   offsets for the current architecture.

   This example builds a program that:
   1. Reads the first two function arguments
   2. Gets the current PID
   3. Returns 0"
  []
  (println "Building portable kprobe for" arch/arch-name "...")

  (dsl/assemble
   (vec (concat
         ;; Use kprobe-prologue to read arguments
         ;; This automatically handles architecture differences!
         ;; arg0 -> r6, arg1 -> r7
         (kprobe/kprobe-prologue :r9 [:r6 :r7])

         ;; Get PID (architecture-independent helper)
         (dsl/helper-get-current-pid-tgid)
         [(dsl/mov-reg :r8 :r0)]

         ;; Return success
         [(dsl/mov :r0 0)
          (dsl/exit-insn)]))))

(defn show-prologue-instructions
  "Show the instructions generated by kprobe-prologue on this architecture."
  []
  (println "=== Kprobe Prologue Instructions ===\n")
  (println "For architecture:" arch/arch-name)
  (println)

  ;; Show prologue for reading 3 arguments
  (println "Reading 3 arguments into r6, r7, r8:")
  (let [prologue (kprobe/kprobe-prologue [:r6 :r7 :r8])]
    (doseq [insn prologue]
      (println "  " insn)))
  (println)

  ;; Show prologue with context save
  (println "With context pointer saved to r9:")
  (let [prologue (kprobe/kprobe-prologue :r9 [:r6 :r7])]
    (doseq [insn prologue]
      (println "  " insn)))
  (println)

  ;; Show the actual offsets being used
  (println "pt_regs offsets on" arch/arch-name ":")
  (doseq [i (range 3)]
    (try
      (printf "  Argument %d: offset %d\n" i (arch/get-kprobe-arg-offset i))
      (catch Exception _)))
  (println))

;; ============================================================================
;; Kretprobe Return Value
;; ============================================================================

(defn show-return-value-offset
  "Show how return values are read on different architectures."
  []
  (println "=== Return Value Reading ===\n")
  (println "In kretprobe handlers, the function return value is accessed")
  (println "from a specific offset in pt_regs that varies by architecture.")
  (println)
  (println "Current architecture:" arch/arch-name)

  ;; Generate instruction to read return value
  (let [insn (kprobe/kretprobe-get-return-value :r1 :r6)]
    (println "Instruction to read return value into r6:")
    (println "  " insn)
    (println "  Offset:" (:offset insn)))
  (println))

;; ============================================================================
;; Complete Multi-Arch Example
;; ============================================================================

(defn build-syscall-tracer
  "Build a portable syscall entry tracer.

   For syscalls, arguments are in specific registers:
   - arg0-arg5 contain syscall arguments

   This works on any architecture because kprobe-prologue
   abstracts the pt_regs differences."
  []
  (dsl/assemble
   (vec (concat
         ;; Read first 4 syscall arguments
         (kprobe/kprobe-prologue :r9 [:r6 :r7 :r8 :r4])
         ;; r6=arg0, r7=arg1, r8=arg2, r4=arg3

         ;; Get timestamp
         (dsl/helper-ktime-get-ns)
         ;; r0 = timestamp

         ;; Get PID
         (dsl/helper-get-current-pid-tgid)
         ;; r0 = (tgid << 32) | pid

         ;; Just return 0 for this example
         [(dsl/mov :r0 0)
          (dsl/exit-insn)]))))

;; ============================================================================
;; Cross-Architecture Testing Support
;; ============================================================================

(defn validate-program-portability
  "Validate that a program can be built on the current architecture.

   This doesn't guarantee it will work on other architectures,
   but ensures the DSL generates valid code for this one."
  [program-builder-fn]
  (try
    (let [bytecode (program-builder-fn)]
      (println "Program built successfully")
      (println "  Bytecode size:" (count bytecode) "bytes")
      (println "  Instructions:" (/ (count bytecode) 8))
      true)
    (catch Exception e
      (println "Program build failed:" (.getMessage e))
      false)))

;; ============================================================================
;; Main Demo
;; ============================================================================

(defn run-demo
  "Run the multi-architecture demonstration."
  []
  (println "Multi-Architecture Kprobe Example")
  (println "==================================\n")

  ;; Show current arch info
  (print-arch-info)

  ;; Show all supported architectures
  (print-all-arch-info)

  ;; Show prologue instructions
  (show-prologue-instructions)

  ;; Show return value reading
  (show-return-value-offset)

  ;; Build and validate portable programs
  (println "=== Building Portable Programs ===\n")

  (println "1. Basic kprobe with 2 arguments:")
  (validate-program-portability build-portable-kprobe)
  (println)

  (println "2. Syscall tracer with 4 arguments:")
  (validate-program-portability build-syscall-tracer)
  (println)

  (println "=== Summary ===\n")
  (println "The kprobe DSL automatically handles architecture differences:")
  (println "- pt_regs argument offsets vary by architecture")
  (println "- Return value location varies by architecture")
  (println "- kprobe-prologue and kretprobe-get-return-value abstract these")
  (println)
  (println "Your kprobe programs are portable across:")
  (println "  - x86_64, ARM64, s390x, PPC64LE, RISC-V64")
  (println)
  (println "Done!"))

(defn -main
  [& args]
  (run-demo))

;; ============================================================================
;; REPL Examples
;; ============================================================================

(comment
  ;; Run the demo
  (run-demo)

  ;; Check current architecture
  arch/current-arch
  ;; => :x86_64

  arch/arch-name
  ;; => "x86_64"

  ;; Get offset for specific argument
  (arch/get-kprobe-arg-offset 0)
  ;; => 112 (on x86_64 - RDI offset)

  (arch/get-kprobe-arg-offset 1)
  ;; => 104 (on x86_64 - RSI offset)

  ;; Build prologue for reading 2 args
  (kprobe/kprobe-prologue [:r6 :r7])

  ;; Build prologue with context save
  (kprobe/kprobe-prologue :r9 [:r6 :r7 :r8])

  ;; Get return value instruction
  (kprobe/kretprobe-get-return-value :r1 :r6)
  )
