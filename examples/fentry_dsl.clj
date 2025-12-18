(ns fentry-dsl
  "Examples demonstrating the Fentry/Fexit DSL.

   Fentry (function entry) and Fexit (function exit) programs are
   modern BPF tracing programs that attach to kernel functions using
   BPF trampolines. They provide typed access to function arguments
   via BTF (BPF Type Format).

   Usage: clj -M:dev -m fentry-dsl
   Note: Some examples require root privileges and BTF for actual BPF loading."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.fentry :as fentry]))

;; ============================================================================
;; 1. Attach Types Demo
;; ============================================================================

(defn demo-attach-types
  "Demonstrate fentry/fexit attach types and program types."
  []
  (println "\n=== Fentry Attach Types ===")
  (println "BPF_TRACE_FENTRY:    " (:fentry fentry/fentry-attach-types))
  (println "BPF_TRACE_FEXIT:     " (:fexit fentry/fentry-attach-types))
  (println "BPF_MODIFY_RETURN:   " (:fmod-ret fentry/fentry-attach-types))

  (println "\nProgram types:")
  (println "  All fentry/fexit types use:" (:fentry fentry/fentry-prog-types)))

;; ============================================================================
;; 2. Argument Registers Demo
;; ============================================================================

(defn demo-argument-registers
  "Demonstrate how arguments are passed to fentry programs.

   In fentry/fexit, function arguments are passed directly in
   registers r1-r5 (unlike kprobes which use pt_regs)."
  []
  (println "\n=== Argument Registers ===")
  (println "Fentry programs receive arguments directly:")
  (doseq [i (range 5)]
    (println (format "  Argument %d: %s" i (fentry/arg-reg i))))

  (println "\nThis is more efficient than kprobes:")
  (println "  - Kprobe: Read from pt_regs structure in memory")
  (println "  - Fentry: Arguments already in registers"))

;; ============================================================================
;; 3. Prologue Demo
;; ============================================================================

(defn demo-prologue
  "Demonstrate fentry prologue generation.

   The prologue saves function arguments to callee-saved registers
   so they remain available after helper calls."
  []
  (println "\n=== Fentry Prologue ===")

  (println "\nSave first 2 arguments to r6, r7:")
  (let [insns (fentry/fentry-prologue [[0 :r6] [1 :r7]])]
    (println "  Instruction count:" (count insns))
    (println "  Saves: arg0 (r1) -> r6, arg1 (r2) -> r7"))

  (println "\nUsing fentry-save-args helper for 3 args:")
  (let [insns (fentry/fentry-save-args 3)]
    (println "  Instruction count:" (count insns))
    (println "  Saves: r1->r6, r2->r7, r3->r8")))

;; ============================================================================
;; 4. Fexit Return Value Demo
;; ============================================================================

(defn demo-fexit-return
  "Demonstrate capturing return value in fexit programs.

   Fexit programs can access both the function arguments AND
   the return value, making them ideal for tracking function results."
  []
  (println "\n=== Fexit Return Value ===")
  (println "Fexit programs can capture the function's return value.")

  (let [insns (fentry/fexit-get-return-value :r6)]
    (println "\nSave return value to r6:")
    (println "  Instruction count:" (count insns)))

  (println "\nUse case example:")
  (println "  - Trace tcp_v4_connect")
  (println "  - Capture socket pointer (arg) and return code (ret)")
  (println "  - Log failed connections (ret != 0)"))

;; ============================================================================
;; 5. Helper Patterns Demo
;; ============================================================================

(defn demo-helper-patterns
  "Demonstrate common helper patterns for fentry programs."
  []
  (println "\n=== Helper Patterns ===")

  (println "\nGet current PID:")
  (let [insns (fentry/fentry-log-pid)]
    (println "  Instruction count:" (count insns))
    (println "  Calls: bpf_get_current_pid_tgid, then shifts right"))

  (println "\nGet process name (comm):")
  (let [insns (fentry/fentry-log-comm :r1)]
    (println "  Instruction count:" (count insns))
    (println "  Calls: bpf_get_current_comm(buf, 16)"))

  (println "\nGet kernel timestamp:")
  (let [insns (fentry/fentry-ktime-get-ns)]
    (println "  Instruction count:" (count insns))
    (println "  Calls: bpf_ktime_get_ns()"))

  (println "\nReturn from program:")
  (let [insns (fentry/fentry-return 0)]
    (println "  Instruction count:" (count insns))
    (println "  Sets r0 = 0, then exit")))

;; ============================================================================
;; 6. Section Names Demo
;; ============================================================================

(defn demo-section-names
  "Demonstrate ELF section naming for fentry/fexit programs."
  []
  (println "\n=== Section Names ===")
  (println "Section names determine how libbpf attaches the program:")

  (println "\nFentry sections:")
  (println " " (fentry/fentry-section-name "tcp_v4_connect"))
  (println " " (fentry/fentry-section-name "do_sys_open"))
  (println " " (fentry/fentry-section-name "__x64_sys_read"))

  (println "\nFexit sections:")
  (println " " (fentry/fexit-section-name "tcp_v4_connect"))
  (println " " (fentry/fexit-section-name "vfs_read"))

  (println "\nFmod_ret sections (modify return value):")
  (println " " (fentry/fmod-ret-section-name "security_bprm_check")))

;; ============================================================================
;; 7. Program Metadata Demo
;; ============================================================================

(defn demo-program-metadata
  "Demonstrate program metadata generation."
  []
  (println "\n=== Program Metadata ===")

  (let [insns (fentry/fentry-save-args 2)
        info (fentry/make-fentry-program-info
              "trace_connect" "tcp_v4_connect" insns)]
    (println "\nFentry program info:")
    (println "  Name:        " (:name info))
    (println "  Section:     " (:section info))
    (println "  Type:        " (:type info))
    (println "  Attach type: " (:attach-type info))
    (println "  Target func: " (:target-func info)))

  (let [insns (fentry/fentry-save-args 1)
        info (fentry/make-fexit-program-info
              "trace_read_ret" "vfs_read" insns)]
    (println "\nFexit program info:")
    (println "  Name:        " (:name info))
    (println "  Section:     " (:section info))
    (println "  Attach type: " (:attach-type info))))

;; ============================================================================
;; 8. Macro Demo
;; ============================================================================

;; Define a simple fentry program
(fentry/deffentry-instructions trace-syscall-entry
  {:function "sys_read"
   :args [:fd :buf :count]
   :arg-saves [[0 :r6] [1 :r7] [2 :r8]]}
  ;; Program body - just save PID
  (fentry/fentry-log-pid))

;; Define a fexit program to capture return value
(fentry/deffexit-instructions trace-syscall-exit
  {:function "sys_read"
   :args [:fd :buf :count]
   :arg-saves [[0 :r6]]
   :ret-reg :r7}
  ;; Body - save timestamp
  (fentry/fentry-ktime-get-ns))

(defn demo-macros
  "Demonstrate the deffentry-instructions and deffexit-instructions macros."
  []
  (println "\n=== DSL Macros ===")

  (println "\ndeffentry-instructions example:")
  (let [insns (trace-syscall-entry)]
    (println "  Program: trace-syscall-entry")
    (println "  Function: sys_read")
    (println "  Instruction count:" (count insns)))

  (println "\ndeffexit-instructions example:")
  (let [insns (trace-syscall-exit)]
    (println "  Program: trace-syscall-exit")
    (println "  Function: sys_read")
    (println "  Captures return value in r7")
    (println "  Instruction count:" (count insns))))

;; ============================================================================
;; 9. Program Assembly Demo
;; ============================================================================

(defn demo-program-assembly
  "Demonstrate assembling fentry programs to bytecode."
  []
  (println "\n=== Program Assembly ===")

  (println "\nAssembling fentry program:")
  (let [insns (trace-syscall-entry)
        bytecode (dsl/assemble insns)]
    (println "  Instruction count:" (count insns))
    (println "  Bytecode size:" (count bytecode) "bytes"))

  (println "\nUsing build-fentry-program:")
  (let [bytecode (fentry/build-fentry-program
                  {:arg-saves [[0 :r6] [1 :r7]]
                   :body (fentry/fentry-log-pid)
                   :return-value 0})]
    (println "  Bytecode size:" (count bytecode) "bytes")))

;; ============================================================================
;; 10. Filter Patterns Demo
;; ============================================================================

(defn demo-filter-patterns
  "Demonstrate filtering patterns for fentry programs."
  []
  (println "\n=== Filter Patterns ===")

  (println "\nFilter by PID (skip 2 instructions if no match):")
  (let [insns (fentry/fentry-filter-by-pid 1234 2)]
    (println "  Instruction count:" (count insns))
    (println "  Logic: if (current_pid != 1234) skip 2 insns"))

  (println "\nFilter by process name:")
  (let [insns (fentry/fentry-filter-by-comm -16 "nginx" 2)]
    (println "  Instruction count:" (count insns))
    (println "  Logic: if (comm != 'nginx') skip 2 insns")
    (println "  Note: Requires 16-byte stack buffer at offset -16")))

;; ============================================================================
;; 11. Trampoline Info Demo
;; ============================================================================

(defn demo-trampoline-info
  "Demonstrate trampoline information."
  []
  (println "\n=== Trampoline Information ===")

  (println "\nFentry trampoline for tcp_v4_connect:")
  (let [info (fentry/describe-fentry-trampoline "tcp_v4_connect" :fentry)]
    (println "  Function:" (:function info))
    (println "  Attach type:" (:attach-type info))
    (println "  Program type:" (:prog-type info))
    (println "  Notes:")
    (doseq [note (:notes info)]
      (when note (println "    -" note))))

  (println "\nFexit trampoline for tcp_v4_connect:")
  (let [info (fentry/describe-fentry-trampoline "tcp_v4_connect" :fexit)]
    (println "  Notes:")
    (doseq [note (:notes info)]
      (when note (println "    -" note)))))

;; ============================================================================
;; 12. Comparison with Kprobes Demo
;; ============================================================================

(defn demo-vs-kprobes
  "Compare fentry/fexit with kprobes."
  []
  (println "\n=== Fentry vs Kprobes ===")

  (println "\nFentry advantages:")
  (println "  - Lower overhead (no software breakpoint)")
  (println "  - Arguments passed directly in r1-r5")
  (println "  - Typed arguments via BTF")
  (println "  - Fexit can access both args AND return value")
  (println "  - Better verifier support")

  (println "\nKprobe advantages:")
  (println "  - Works without BTF")
  (println "  - Can probe any instruction (not just function entry)")
  (println "  - Available on older kernels")

  (println "\nWhen to use each:")
  (println "  - Fentry: Modern kernels with BTF, production tracing")
  (println "  - Kprobe: Legacy systems, arbitrary instruction probing"))

;; ============================================================================
;; 13. Complete Example: TCP Connection Tracer
;; ============================================================================

(defn demo-tcp-tracer-pattern
  "Demonstrate a complete TCP connection tracer pattern."
  []
  (println "\n=== TCP Connection Tracer Pattern ===")

  (println "\nPattern for tracing tcp_v4_connect:")
  (println "  1. Fentry captures: socket pointer, address, address length")
  (println "  2. Fexit captures: return code (success/failure)")
  (println "  3. On success (ret == 0), log connection details")

  (let [fentry-prog
        (vec (concat
              ;; Save socket pointer
              (fentry/fentry-prologue [[0 :r6]])
              ;; Get PID
              (fentry/fentry-log-pid)
              ;; Return
              (fentry/fentry-return 0)))

        fexit-prog
        (vec (concat
              ;; Save socket pointer and return value
              (fentry/fentry-prologue [[0 :r6]])
              (fentry/fexit-get-return-value :r7)
              ;; Get timestamp
              (fentry/fentry-ktime-get-ns)
              ;; Return
              (fentry/fentry-return 0)))]

    (println "\nFentry program (entry):")
    (println "  Instruction count:" (count fentry-prog))
    (println "  Bytecode size:" (count (dsl/assemble fentry-prog)) "bytes")

    (println "\nFexit program (exit):")
    (println "  Instruction count:" (count fexit-prog))
    (println "  Bytecode size:" (count (dsl/assemble fexit-prog)) "bytes")))

;; ============================================================================
;; 14. Struct Field Access Demo
;; ============================================================================

(defn demo-struct-field-access
  "Demonstrate reading struct fields from fentry arguments."
  []
  (println "\n=== Struct Field Access ===")
  (println "Fentry programs often need to read fields from struct pointers.")

  (println "\nRead 8-byte field at offset 16:")
  (let [insns (fentry/read-struct-field :r6 16 :r0 8)]
    (println "  Instruction count:" (count insns))
    (println "  Reads: r0 = *(u64*)(r6 + 16)"))

  (println "\nRead 4-byte field at offset 8:")
  (let [insns (fentry/read-struct-field :r6 8 :r0 4)]
    (println "  Instruction count:" (count insns))
    (println "  Reads: r0 = *(u32*)(r6 + 8)"))

  (println "\nWith BTF, use field names instead of offsets:")
  (println "  (read-nested-field btf :r6 sock-type-id [:sk_common :skc_daddr] :r0 :r1)"))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all Fentry/Fexit DSL demonstrations."
  [& args]
  (println "============================================")
  (println "  Fentry/Fexit DSL Examples")
  (println "============================================")

  (demo-attach-types)
  (demo-argument-registers)
  (demo-prologue)
  (demo-fexit-return)
  (demo-helper-patterns)
  (demo-section-names)
  (demo-program-metadata)
  (demo-macros)
  (demo-program-assembly)
  (demo-filter-patterns)
  (demo-trampoline-info)
  (demo-vs-kprobes)
  (demo-tcp-tracer-pattern)
  (demo-struct-field-access)

  (println "\n============================================")
  (println "  All Fentry/Fexit demonstrations complete!")
  (println "============================================"))
