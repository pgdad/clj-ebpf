(ns clj-ebpf.dsl.fentry
  "High-level Fentry/Fexit DSL for BPF programs.

   Fentry (function entry) and Fexit (function exit) programs are
   modern BPF tracing programs that attach to kernel functions using
   BPF trampolines. They provide typed access to function arguments
   via BTF (BPF Type Format).

   Advantages over kprobes:
   - Lower overhead (no software breakpoints)
   - Typed arguments via BTF
   - Fexit can access both arguments and return value
   - Better verifier support

   Fentry/Fexit programs receive arguments directly:
   - r1-r5: Function arguments (up to 5)
   - Fexit: r0 contains return value at exit

   Example:
     (deffentry-instructions trace-tcp-connect
       {:function \"tcp_v4_connect\"
        :args [:sk :addr :addr-len]}
       ;; sk is in r1, addr in r2, addr-len in r3
       [])"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.btf :as btf]))

;; ============================================================================
;; Fentry Program Types
;; ============================================================================

(def fentry-prog-types
  "BPF program types for fentry/fexit."
  {:fentry      :tracing   ; BPF_PROG_TYPE_TRACING with attach fentry
   :fexit       :tracing   ; BPF_PROG_TYPE_TRACING with attach fexit
   :fmod-ret    :tracing}) ; BPF_PROG_TYPE_TRACING with attach fmod_ret

(def fentry-attach-types
  "BPF attach types for fentry/fexit."
  {:fentry   49   ; BPF_TRACE_FENTRY
   :fexit    50   ; BPF_TRACE_FEXIT
   :fmod-ret 51}) ; BPF_MODIFY_RETURN

;; ============================================================================
;; Argument Register Mapping
;; ============================================================================

(def arg-registers
  "Register mapping for function arguments.
   In fentry/fexit, arguments are passed directly in r1-r5."
  {0 :r1  ; First argument
   1 :r2  ; Second argument
   2 :r3  ; Third argument
   3 :r4  ; Fourth argument
   4 :r5}) ; Fifth argument

(defn arg-reg
  "Get the register containing a function argument.

   Parameters:
   - arg-index: 0-based argument index (0-4)

   Returns register keyword (:r1 through :r5).

   Example:
     (arg-reg 0)  ;; => :r1 (first argument)
     (arg-reg 2)  ;; => :r3 (third argument)"
  [arg-index]
  (or (get arg-registers arg-index)
      (throw (ex-info "Invalid argument index (max 5 args supported)"
                     {:arg-index arg-index
                      :max-index 4}))))

;; ============================================================================
;; Fentry Prologue
;; ============================================================================

(defn fentry-prologue
  "Generate standard fentry prologue instructions.

   Saves specified arguments to callee-saved registers for use
   throughout the program.

   Parameters:
   - arg-saves: Vector of [arg-index dest-reg] pairs

   Returns vector of mov instructions.

   Example:
     (fentry-prologue [[0 :r6] [1 :r7]])
     ;; Generates:
     ;; mov r6, r1  ; Save first arg
     ;; mov r7, r2  ; Save second arg"
  [arg-saves]
  (vec (for [[arg-index dest-reg] arg-saves]
         (dsl/mov-reg dest-reg (arg-reg arg-index)))))

(defn fentry-save-args
  "Generate instructions to save all specified arguments.

   Simplified interface - saves args 0..n to registers starting at :r6.

   Parameters:
   - arg-count: Number of arguments to save (1-5)

   Returns vector of mov instructions.

   Example:
     (fentry-save-args 3)
     ;; Generates:
     ;; mov r6, r1  ; arg0
     ;; mov r7, r2  ; arg1
     ;; mov r8, r3  ; arg2"
  [arg-count]
  (let [dest-regs [:r6 :r7 :r8 :r9 :r10]]
    (fentry-prologue
     (for [i (range (min arg-count 5))]
       [i (nth dest-regs i)]))))

;; ============================================================================
;; Fexit Return Value
;; ============================================================================

(defn fexit-get-return-value
  "Generate instruction to save return value in fexit program.

   In fexit programs, after the function returns, the return value
   is available. We need to access it through the context.

   Note: The actual mechanism depends on the kernel version and
   whether the function has a return value.

   Parameters:
   - dst-reg: Destination register for return value

   Returns vector of instructions.

   Example:
     (fexit-get-return-value :r6)
     ;; Saves return value to r6"
  [dst-reg]
  ;; In fexit, the return value is typically passed as an extra parameter
  ;; after all the function arguments. The exact register depends on
  ;; the number of function arguments.
  ;; For simplicity, we provide a helper that assumes r0 context access.
  [(dsl/mov-reg dst-reg :r0)])

;; ============================================================================
;; BTF Integration
;; ============================================================================

(defn resolve-btf-function
  "Resolve function information from BTF.

   Parameters:
   - btf: BTF data (from btf/load-btf-file)
   - func-name: Kernel function name

   Returns map with:
   - :func - Function BTF info
   - :proto - Function prototype info
   - :params - Vector of parameter info with names
   - :return-type - Return type ID

   Returns nil if function not found."
  [btf func-name]
  (when-let [func (btf/find-function btf func-name)]
    (let [sig (btf/get-function-signature btf func)]
      {:func func
       :proto (btf/get-type-by-id btf (:type func))
       :params (:params sig)
       :return-type (:return-type sig)})))

(defn get-arg-by-name
  "Get argument index by parameter name.

   Parameters:
   - btf: BTF data
   - func-name: Kernel function name
   - param-name: Parameter name (string or keyword)

   Returns 0-based argument index or nil if not found.

   Example:
     (get-arg-by-name btf \"tcp_v4_connect\" :sk)
     ;; => 0"
  [btf func-name param-name]
  (when-let [func-info (resolve-btf-function btf func-name)]
    (let [param-str (if (keyword? param-name)
                     (name param-name)
                     param-name)
          params (:params func-info)]
      (first (keep-indexed
              (fn [idx param]
                (when (= (:name param) param-str)
                  idx))
              params)))))

(defn get-arg-type
  "Get the BTF type of a function argument.

   Parameters:
   - btf: BTF data
   - func-name: Kernel function name
   - arg-index: 0-based argument index

   Returns BTF type info or nil.

   Example:
     (get-arg-type btf \"tcp_v4_connect\" 0)
     ;; Returns type info for first argument"
  [btf func-name arg-index]
  (when-let [func-info (resolve-btf-function btf func-name)]
    (when-let [param (nth (:params func-info) arg-index nil)]
      (btf/get-type-by-id btf (:type param)))))

(defn get-return-type
  "Get the BTF return type of a function.

   Parameters:
   - btf: BTF data
   - func-name: Kernel function name

   Returns BTF type info or nil.

   Example:
     (get-return-type btf \"tcp_v4_connect\")
     ;; Returns type info for return type"
  [btf func-name]
  (when-let [func-info (resolve-btf-function btf func-name)]
    (btf/get-type-by-id btf (:return-type func-info))))

;; ============================================================================
;; Field Access (CO-RE style)
;; ============================================================================

(defn read-struct-field
  "Generate instructions to read a field from a struct pointer.

   Parameters:
   - src-reg: Register containing pointer to struct
   - offset: Field offset in bytes
   - dst-reg: Destination register
   - size: Size in bytes (1, 2, 4, or 8)

   Returns vector of ldx instruction.

   Example:
     (read-struct-field :r6 16 :r0 8)
     ;; ldxdw r0, [r6 + 16]"
  [src-reg offset dst-reg size]
  (let [size-kw (case size
                  1 :b
                  2 :h
                  4 :w
                  8 :dw
                  :dw)]
    [(dsl/ldx size-kw dst-reg src-reg offset)]))

(defn read-nested-field
  "Generate instructions to read a nested struct field.

   Uses BTF to determine the correct offset.

   Parameters:
   - btf: BTF data
   - src-reg: Register containing pointer to outer struct
   - type-id: BTF type ID of the struct
   - field-path: Vector of field names (keywords or strings)
   - dst-reg: Destination register
   - tmp-reg: Temporary register for intermediate pointers

   Returns vector of instructions.

   Example:
     (read-nested-field btf :r6 sock-type-id [:sk_common :skc_daddr] :r0 :r1)"
  [btf src-reg type-id field-path dst-reg tmp-reg]
  (if-let [access-info (btf/field-path->access-info btf type-id field-path)]
    (let [byte-offset (:byte-offset access-info)
          final-type-id (:final-type-id access-info)
          size (or (btf/get-type-size btf final-type-id) 8)]
      (read-struct-field src-reg byte-offset dst-reg size))
    (throw (ex-info "Cannot resolve field path"
                   {:type-id type-id
                    :field-path field-path}))))

;; ============================================================================
;; Program Builders
;; ============================================================================

(defn build-fentry-program
  "Build a complete fentry program with standard structure.

   Parameters:
   - opts: Map with:
     :arg-saves - Vector of [arg-index dest-reg] pairs (optional)
     :body - Vector of body instructions
     :return-value - Value to return (default 0)

   Returns assembled program bytes.

   Example:
     (build-fentry-program
       {:arg-saves [[0 :r6] [1 :r7]]
        :body [(dsl/mov :r0 42)]
        :return-value 0})"
  [{:keys [arg-saves body return-value]
    :or {arg-saves [] return-value 0}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue: save arguments
         (fentry-prologue arg-saves)
         ;; Body instructions
         body
         ;; Epilogue: set return value and exit
         [(dsl/mov :r0 return-value)
          (dsl/exit-insn)]))))

(defn build-fexit-program
  "Build a complete fexit program with standard structure.

   Parameters:
   - opts: Map with:
     :arg-saves - Vector of [arg-index dest-reg] pairs (optional)
     :ret-reg - Register to save return value (optional)
     :body - Vector of body instructions
     :return-value - Value to return (default 0)

   Returns assembled program bytes.

   Example:
     (build-fexit-program
       {:arg-saves [[0 :r6]]
        :ret-reg :r7
        :body [(dsl/mov :r0 0)]
        :return-value 0})"
  [{:keys [arg-saves ret-reg body return-value]
    :or {arg-saves [] return-value 0}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue: save arguments
         (fentry-prologue arg-saves)
         ;; Save return value if requested
         (when ret-reg
           (fexit-get-return-value ret-reg))
         ;; Body instructions
         body
         ;; Epilogue: set return value and exit
         [(dsl/mov :r0 return-value)
          (dsl/exit-insn)]))))

;; ============================================================================
;; Macro Definitions
;; ============================================================================

(defmacro deffentry-instructions
  "Define a fentry program as a function returning instructions.

   Parameters:
   - fn-name: Name for the defined function
   - options: Map with:
     :function - Kernel function name to trace
     :args - Vector of argument names (for documentation)
     :arg-saves - Vector of [arg-index dest-reg] pairs (optional)
   - body: Body expressions (should return vectors of instructions)

   Example:
     (deffentry-instructions trace-tcp-connect
       {:function \"tcp_v4_connect\"
        :args [:sk :addr :addr-len]
        :arg-saves [[0 :r6] [1 :r7]]}
       ;; r6 = sk, r7 = addr
       [])"
  [fn-name options & body]
  (let [arg-saves (or (:arg-saves options) [])]
    `(defn ~fn-name
       ~(str "Fentry program for " (or (:function options) "unknown") ".\n"
             "Arguments: " (or (:args options) []))
       []
       (vec (concat
             (fentry-prologue ~arg-saves)
             ~@body
             [(dsl/mov :r0 0)
              (dsl/exit-insn)])))))

(defmacro deffexit-instructions
  "Define a fexit program as a function returning instructions.

   Parameters:
   - fn-name: Name for the defined function
   - options: Map with:
     :function - Kernel function name to trace
     :args - Vector of argument names (for documentation)
     :arg-saves - Vector of [arg-index dest-reg] pairs (optional)
     :ret-reg - Register to save return value (optional)
   - body: Body expressions (should return vectors of instructions)

   Example:
     (deffexit-instructions trace-tcp-connect-exit
       {:function \"tcp_v4_connect\"
        :args [:sk :addr :addr-len]
        :arg-saves [[0 :r6]]
        :ret-reg :r7}
       ;; r6 = sk, r7 = return value
       [])"
  [fn-name options & body]
  (let [arg-saves (or (:arg-saves options) [])
        ret-reg (:ret-reg options)]
    `(defn ~fn-name
       ~(str "Fexit program for " (or (:function options) "unknown") ".\n"
             "Arguments: " (or (:args options) []) "\n"
             "Return register: " (or ret-reg "not saved"))
       []
       (vec (concat
             (fentry-prologue ~arg-saves)
             ~(when ret-reg
                `(fexit-get-return-value ~ret-reg))
             ~@body
             [(dsl/mov :r0 0)
              (dsl/exit-insn)])))))

;; ============================================================================
;; Section Names and Metadata
;; ============================================================================

(defn fentry-section-name
  "Generate ELF section name for fentry program.

   Parameters:
   - func-name: Kernel function name

   Returns section name like \"fentry/tcp_v4_connect\"

   Example:
     (fentry-section-name \"tcp_v4_connect\")
     ;; => \"fentry/tcp_v4_connect\""
  [func-name]
  (str "fentry/" func-name))

(defn fexit-section-name
  "Generate ELF section name for fexit program.

   Parameters:
   - func-name: Kernel function name

   Returns section name like \"fexit/tcp_v4_connect\"

   Example:
     (fexit-section-name \"tcp_v4_connect\")
     ;; => \"fexit/tcp_v4_connect\""
  [func-name]
  (str "fexit/" func-name))

(defn fmod-ret-section-name
  "Generate ELF section name for fmod_ret program.

   Parameters:
   - func-name: Kernel function name

   Returns section name like \"fmod_ret/func_name\"

   Example:
     (fmod-ret-section-name \"security_bprm_check\")
     ;; => \"fmod_ret/security_bprm_check\""
  [func-name]
  (str "fmod_ret/" func-name))

(defn make-fentry-program-info
  "Create program metadata for a fentry program.

   Parameters:
   - program-name: Name for the BPF program
   - func-name: Kernel function to trace
   - instructions: Program instructions

   Returns map with program metadata."
  [program-name func-name instructions]
  {:name program-name
   :section (fentry-section-name func-name)
   :type :tracing
   :attach-type :fentry
   :target-func func-name
   :instructions instructions})

(defn make-fexit-program-info
  "Create program metadata for a fexit program.

   Parameters:
   - program-name: Name for the BPF program
   - func-name: Kernel function to trace
   - instructions: Program instructions

   Returns map with program metadata."
  [program-name func-name instructions]
  {:name program-name
   :section (fexit-section-name func-name)
   :type :tracing
   :attach-type :fexit
   :target-func func-name
   :instructions instructions})

(defn make-fmod-ret-program-info
  "Create program metadata for a fmod_ret program.

   fmod_ret (modify return) programs can modify the return value
   of certain allowlisted kernel functions.

   Parameters:
   - program-name: Name for the BPF program
   - func-name: Kernel function to trace
   - instructions: Program instructions

   Returns map with program metadata."
  [program-name func-name instructions]
  {:name program-name
   :section (fmod-ret-section-name func-name)
   :type :tracing
   :attach-type :fmod-ret
   :target-func func-name
   :instructions instructions})

;; ============================================================================
;; Helper Patterns
;; ============================================================================

(defn fentry-log-pid
  "Generate instructions to get and log current PID.

   Returns vector of instructions that gets PID into r0.

   Example:
     (fentry-log-pid)
     ;; Calls bpf_get_current_pid_tgid"
  []
  [(dsl/call 14)  ; BPF_FUNC_get_current_pid_tgid
   (dsl/alu-imm :rsh :r0 32)])  ; Right shift to get PID

(defn fentry-log-comm
  "Generate instructions to get current task comm (process name).

   Parameters:
   - buf-reg: Register pointing to 16-byte buffer on stack

   Returns vector of instructions.

   Example:
     (fentry-log-comm :r1)
     ;; Calls bpf_get_current_comm(buf, 16)"
  [buf-reg]
  [(dsl/mov-reg :r1 buf-reg)
   (dsl/mov :r2 16)  ; TASK_COMM_LEN
   (dsl/call 16)])   ; BPF_FUNC_get_current_comm

(defn fentry-ktime-get-ns
  "Generate instruction to get current kernel time in nanoseconds.

   Returns call instruction that puts timestamp in r0.

   Example:
     (fentry-ktime-get-ns)
     ;; r0 = ktime_get_ns()"
  []
  [(dsl/call 5)])  ; BPF_FUNC_ktime_get_ns

(defn fentry-return
  "Generate instructions to return a value from fentry/fexit.

   Parameters:
   - value: Return value (typically 0)

   Returns vector of [mov, exit] instructions.

   Example:
     (fentry-return 0)"
  [value]
  [(dsl/mov :r0 value)
   (dsl/exit-insn)])

;; ============================================================================
;; Common Fentry Patterns
;; ============================================================================

(defn fentry-filter-by-pid
  "Generate instructions to filter by PID.

   Parameters:
   - target-pid: PID to filter for
   - skip-offset: Number of instructions to skip if PID doesn't match

   Returns vector of instructions.

   Example:
     (fentry-filter-by-pid 1234 2)
     ;; If current PID != 1234, skip 2 instructions"
  [target-pid skip-offset]
  [(dsl/call 14)  ; bpf_get_current_pid_tgid
   (dsl/alu-imm :rsh :r0 32)  ; Get PID
   (dsl/jmp-imm :jne :r0 target-pid skip-offset)])

(defn fentry-filter-by-comm
  "Generate instructions to filter by process name.

   Requires stack space for 16-byte comm buffer.

   Parameters:
   - comm-buf-offset: Stack offset for 16-byte buffer
   - target-comm: Target process name (first 8 bytes compared)
   - skip-offset: Number of instructions to skip if comm doesn't match

   Returns vector of instructions.

   Example:
     (fentry-filter-by-comm -16 \"myprocess\" 2)"
  [comm-buf-offset target-comm skip-offset]
  (let [comm-bytes (.getBytes (str target-comm) "UTF-8")
        ;; Take first 8 bytes, pad with zeros
        padded (take 8 (concat comm-bytes (repeat 0)))
        ;; Convert to 64-bit value for comparison
        comm-val (reduce (fn [acc [idx b]]
                          (bit-or acc (bit-shift-left (bit-and b 0xFF) (* idx 8))))
                        0
                        (map-indexed vector padded))]
    [(dsl/mov-reg :r1 :r10)
     (dsl/alu-imm :add :r1 comm-buf-offset)
     (dsl/mov :r2 16)
     (dsl/call 16)  ; bpf_get_current_comm
     ;; Load first 8 bytes and compare
     (dsl/ldx :dw :r0 :r10 comm-buf-offset)
     (dsl/jmp-imm :jne :r0 comm-val skip-offset)]))

;; ============================================================================
;; Trampoline Information
;; ============================================================================

(defn describe-fentry-trampoline
  "Return information about fentry/fexit attachment.

   This is informational only - actual attachment is done
   through the BPF syscall with BTF ID.

   Parameters:
   - func-name: Kernel function name
   - attach-type: :fentry, :fexit, or :fmod-ret

   Returns map describing the trampoline setup."
  [func-name attach-type]
  {:function func-name
   :attach-type attach-type
   :prog-type :tracing
   :expected-attach-btf-id "BTF func ID required at attach time"
   :notes ["Requires CONFIG_DEBUG_INFO_BTF=y"
           "Lower overhead than kprobe"
           "Arguments passed directly in r1-r5"
           (when (= attach-type :fexit)
             "Return value available after all args")]})

;; ============================================================================
;; Validation Helpers
;; ============================================================================

(defn validate-fentry-target
  "Validate that a function can be targeted by fentry/fexit.

   Parameters:
   - btf: BTF data (from btf/load-btf-file)
   - func-name: Kernel function name

   Returns map with:
   - :valid? - true if function exists in BTF
   - :func-info - Function BTF info if found
   - :param-count - Number of parameters
   - :error - Error message if invalid"
  [btf func-name]
  (if-let [func-info (resolve-btf-function btf func-name)]
    {:valid? true
     :func-info func-info
     :param-count (count (:params func-info))}
    {:valid? false
     :error (str "Function not found in BTF: " func-name)}))

(defn suggest-arg-saves
  "Suggest arg-saves configuration for a function.

   Parameters:
   - btf: BTF data
   - func-name: Kernel function name

   Returns suggested arg-saves vector.

   Example:
     (suggest-arg-saves btf \"tcp_v4_connect\")
     ;; => [[0 :r6] [1 :r7] [2 :r8]]"
  [btf func-name]
  (when-let [func-info (resolve-btf-function btf func-name)]
    (let [dest-regs [:r6 :r7 :r8 :r9 :r10]
          param-count (min (count (:params func-info)) 5)]
      (vec (for [i (range param-count)]
             [i (nth dest-regs i)])))))
