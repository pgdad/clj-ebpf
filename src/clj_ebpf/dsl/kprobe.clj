(ns clj-ebpf.dsl.kprobe
  "High-level kprobe definition macros for BPF programs.

   Provides the defkprobe macro for defining kprobe handlers with
   automatic argument extraction and common setup patterns.

   Example:
     (defkprobe tcp-connect
       :function \"tcp_v4_connect\"
       :args [sk]  ; First function argument
       (concat
         (helper-get-current-pid-tgid)
         [(mov-reg :r6 :r0)]  ; Save pid_tgid
         ;; ... rest of program
         [(exit-insn)]))"
  (:require [clj-ebpf.arch :as arch]
            [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Kprobe Argument Handling
;; ============================================================================

(defn kprobe-read-args
  "Generate instructions to read kprobe arguments into registers.

   In kprobe handlers, r1 contains a pointer to pt_regs. This function
   generates instructions to load function arguments from pt_regs into
   the specified destination registers.

   Parameters:
   - ctx-reg: Register containing pt_regs pointer (typically :r1)
   - arg-bindings: Vector of [arg-index dest-reg] pairs

   Returns vector of ldx instructions.

   Example:
     (kprobe-read-args :r1 [[0 :r6] [1 :r7]])
     ;; Generates:
     ;; ldxdw r6, [r1 + 112]  ; First arg (x86_64: rdi)
     ;; ldxdw r7, [r1 + 104]  ; Second arg (x86_64: rsi)"
  [ctx-reg arg-bindings]
  (vec (for [[arg-index dest-reg] arg-bindings]
         (dsl/read-kprobe-arg ctx-reg arg-index dest-reg))))

(defn kprobe-prologue
  "Generate standard kprobe prologue instructions.

   Saves the pt_regs pointer and reads specified arguments.

   Parameters:
   - ctx-save-reg: Register to save pt_regs pointer (optional)
   - arg-regs: Vector of registers for arguments, e.g., [:r6 :r7 :r8]
               Arg 0 goes to first register, arg 1 to second, etc.

   Returns vector of instructions.

   Example:
     (kprobe-prologue :r9 [:r6 :r7])
     ;; Generates:
     ;; mov r9, r1          ; Save pt_regs pointer
     ;; ldxdw r6, [r1 + 112] ; Load arg0
     ;; ldxdw r7, [r1 + 104] ; Load arg1"
  ([arg-regs]
   (kprobe-prologue nil arg-regs))
  ([ctx-save-reg arg-regs]
   (vec (concat
         (when ctx-save-reg
           [(dsl/mov-reg ctx-save-reg :r1)])
         (kprobe-read-args :r1
                          (map-indexed (fn [idx reg] [idx reg]) arg-regs))))))

;; ============================================================================
;; Kretprobe Handling
;; ============================================================================

(defn kretprobe-get-return-value
  "Generate instruction to read the return value in kretprobe.

   In kretprobe handlers, the function return value is accessed via
   PT_REGS_RC macro, which reads from a specific pt_regs offset.

   Parameters:
   - ctx-reg: Register containing pt_regs pointer
   - dst-reg: Destination register for return value

   Returns ldx instruction.

   Example:
     (kretprobe-get-return-value :r1 :r6)
     ;; r6 = function return value"
  [ctx-reg dst-reg]
  ;; On x86_64, return value is in rax at offset 80
  ;; On arm64, return value is in x0 at offset 0
  (let [ret-offset (case arch/current-arch
                    :x86_64 80   ; rax offset
                    :arm64  0    ; x0 offset
                    :s390x  16   ; r2 offset
                    :ppc64le 24  ; r3 offset
                    :riscv64 80  ; a0 offset
                    80)]  ; Default to x86_64
    (dsl/ldx :dw dst-reg ctx-reg ret-offset)))

;; ============================================================================
;; Complete Kprobe Builder
;; ============================================================================

(defn build-kprobe-program
  "Build a complete kprobe program with standard structure.

   Combines prologue, body instructions, and epilogue.

   Parameters:
   - opts: Map with:
     :args - Vector of destination registers for function arguments
     :ctx-reg - Register to save pt_regs pointer (optional)
     :body - Vector of body instructions
     :return-value - Value to return (default 0)

   Returns assembled program bytes.

   Example:
     (build-kprobe-program
       {:args [:r6 :r7]
        :body [(mov :r0 42)]
        :return-value 0})"
  [{:keys [args ctx-reg body return-value]
    :or {args [] return-value 0}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue: save context and load arguments
         (kprobe-prologue ctx-reg args)
         ;; Body instructions
         body
         ;; Epilogue: set return value and exit
         [(dsl/mov :r0 return-value)
          (dsl/exit-insn)]))))

(defn build-kretprobe-program
  "Build a complete kretprobe program with standard structure.

   Similar to build-kprobe-program but for return probes.

   Parameters:
   - opts: Map with:
     :ret-reg - Register to store return value
     :ctx-reg - Register to save pt_regs pointer (optional)
     :body - Vector of body instructions
     :return-value - Value to return (default 0)

   Returns assembled program bytes.

   Example:
     (build-kretprobe-program
       {:ret-reg :r6
        :body [(jmp-imm :jne :r6 0 2)  ; Check if return != 0
               (mov :r0 0)
               (exit-insn)]})"
  [{:keys [ret-reg ctx-reg body return-value]
    :or {return-value 0}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue: save context and get return value
         (when ctx-reg
           [(dsl/mov-reg ctx-reg :r1)])
         (when ret-reg
           [(kretprobe-get-return-value :r1 ret-reg)])
         ;; Body instructions
         body
         ;; Epilogue
         [(dsl/mov :r0 return-value)
          (dsl/exit-insn)]))))

;; ============================================================================
;; Kprobe Program Definition Macro
;; ============================================================================

(defmacro defkprobe-instructions
  "Define a kprobe program as a function returning instructions.

   This macro creates a function that returns a vector of BPF instructions
   for a kprobe handler. It sets up automatic argument loading.

   Parameters:
   - name: Name for the defined function
   - options: Map with :function (kernel function name), :args (arg register bindings)
   - body: Body instructions (should return vector of instructions)

   Example:
     (defkprobe-instructions tcp-connect-probe
       {:function \"tcp_v4_connect\"
        :args [:r6]}  ; r6 = first function argument (sk)
       (concat
         (helper-get-current-pid-tgid)
         [(mov-reg :r7 :r0)]  ; Save pid_tgid in r7
         ;; ... your instructions
         [(mov :r0 0)
          (exit-insn)]))"
  [name options & body]
  (let [args (or (:args options) [])
        function-name (:function options)]
    `(defn ~name
       ~(str "Kprobe handler for " (or function-name "kernel function") ".\n"
             "Arguments: " (pr-str args))
       []
       (vec (concat
             (kprobe-prologue ~args)
             ~@body)))))

(defmacro defkretprobe-instructions
  "Define a kretprobe program as a function returning instructions.

   Similar to defkprobe-instructions but for return probes.
   Automatically loads the return value into the specified register.

   Parameters:
   - name: Name for the defined function
   - options: Map with :function, :ret-reg (register for return value)
   - body: Body instructions

   Example:
     (defkretprobe-instructions tcp-connect-ret-probe
       {:function \"tcp_v4_connect\"
        :ret-reg :r6}  ; r6 = function return value
       (concat
         ;; Check return value
         [(jmp-imm :jne :r6 0 skip-offset)]
         ;; ... handle success case
         [(mov :r0 0)
          (exit-insn)]))"
  [name options & body]
  (let [ret-reg (:ret-reg options)
        function-name (:function options)]
    `(defn ~name
       ~(str "Kretprobe handler for " (or function-name "kernel function") ".\n"
             "Return value in: " (pr-str ret-reg))
       []
       (vec (concat
             ~(when ret-reg
                `[(kretprobe-get-return-value :r1 ~ret-reg)])
             ~@body)))))

;; ============================================================================
;; Utility Functions
;; ============================================================================

(defn kprobe-section-name
  "Generate ELF section name for a kprobe program.

   Parameters:
   - function-name: Kernel function to probe

   Returns section name like \"kprobe/tcp_v4_connect\""
  [function-name]
  (str "kprobe/" function-name))

(defn kretprobe-section-name
  "Generate ELF section name for a kretprobe program.

   Parameters:
   - function-name: Kernel function to probe

   Returns section name like \"kretprobe/tcp_v4_connect\""
  [function-name]
  (str "kretprobe/" function-name))

(defn make-kprobe-program-info
  "Create program metadata for a kprobe.

   Parameters:
   - function-name: Kernel function to probe
   - program-name: Name for the BPF program
   - instructions: Program instructions

   Returns map with program metadata for loading."
  [function-name program-name instructions]
  {:name program-name
   :section (kprobe-section-name function-name)
   :type :kprobe
   :function function-name
   :instructions instructions})

(defn make-kretprobe-program-info
  "Create program metadata for a kretprobe.

   Parameters:
   - function-name: Kernel function to probe
   - program-name: Name for the BPF program
   - instructions: Program instructions

   Returns map with program metadata for loading."
  [function-name program-name instructions]
  {:name program-name
   :section (kretprobe-section-name function-name)
   :type :kretprobe
   :function function-name
   :instructions instructions})
