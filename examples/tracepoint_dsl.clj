(ns tracepoint-dsl
  "Tracepoint DSL Example

   This example demonstrates using the high-level Tracepoint DSL to build
   BPF programs that attach to kernel tracepoints.

   Tracepoints provide:
   - Stable ABI (unlike kprobes which depend on function signatures)
   - Lower overhead than kprobes
   - Well-documented event formats
   - Better portability across kernel versions

   Common tracepoint categories:
   - sched: Scheduler events (context switches, process lifecycle)
   - syscalls: System call entry/exit
   - raw_syscalls: Raw syscall tracing
   - block: Block I/O events
   - net: Network events
   - irq: Interrupt handling

   Usage:
     clojure -M:examples -m tracepoint-dsl"
  (:require [clj-ebpf.dsl.tracepoint :as tp]
            [clj-ebpf.dsl.structs :as structs]
            [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Event Structure Definitions
;; ============================================================================

;; Define event structure for scheduler switch tracing
(structs/defevent SchedSwitchEvent
  [:timestamp :u64]     ; 8 bytes, offset 0
  [:prev_pid :u32]      ; 4 bytes, offset 8
  [:next_pid :u32]      ; 4 bytes, offset 12
  [:prev_prio :i32]     ; 4 bytes, offset 16
  [:next_prio :i32]     ; 4 bytes, offset 20
  [:cpu :u32])          ; 4 bytes, offset 24
;; Total: 28 bytes

;; Define event structure for syscall tracing
(structs/defevent SyscallEvent
  [:timestamp :u64]     ; 8 bytes, offset 0
  [:pid :u32]           ; 4 bytes, offset 8
  [:syscall_nr :u32]    ; 4 bytes, offset 12
  [:ret :i64])          ; 8 bytes, offset 16
;; Total: 24 bytes

;; ============================================================================
;; Example 1: Basic Tracepoint Format Inspection
;; ============================================================================

(defn demo-format-inspection
  "Demonstrate inspecting tracepoint format information."
  []
  (println "\n=== Tracepoint Format Inspection ===\n")

  ;; Get static format for sched_switch (works without tracefs)
  (let [format (tp/get-static-format "sched" "sched_switch")]
    (println "Tracepoint: sched/sched_switch")
    (println "Category:" (:category format))
    (println "Name:" (:name format))

    (println "\nUser Fields:")
    (doseq [field (:fields format)]
      (printf "  %-15s offset=%-3d size=%-2d type=%s%s\n"
              (name (:name field))
              (:offset field)
              (:size field)
              (:type field)
              (if (:signed field) " (signed)" "")))

    (println "\nCommon Fields:")
    (doseq [field (:common-fields format)]
      (printf "  %-25s offset=%-3d size=%-2d\n"
              (name (:name field))
              (:offset field)
              (:size field))))

  ;; Show field query functions
  (println "\n--- Field Query Functions ---")
  (let [format (tp/get-static-format "sched" "sched_switch")]
    (println "prev_pid offset:" (tp/tracepoint-field-offset format :prev_pid))
    (println "prev_pid size:" (tp/tracepoint-field-size format :prev_pid))
    (println "All field names:" (tp/tracepoint-fields format))))

;; ============================================================================
;; Example 2: Building Tracepoint Programs with DSL
;; ============================================================================

(defn demo-tracepoint-prologue
  "Demonstrate generating tracepoint prologue instructions."
  []
  (println "\n=== Tracepoint Prologue Generation ===\n")

  (let [format (tp/get-static-format "sched" "sched_switch")]
    ;; Generate prologue that reads prev_pid and next_pid
    (let [prologue (tp/tracepoint-prologue :r9 format {:prev_pid :r6 :next_pid :r7})]
      (println "Prologue instructions for sched_switch:")
      (println "  Context saved to: r9")
      (println "  prev_pid loaded to: r6")
      (println "  next_pid loaded to: r7")
      (println "  Total instructions:" (count prologue))
      (println "  Total bytes:" (* 8 (count prologue)))))

  ;; Show field reading
  (println "\n--- Individual Field Reading ---")
  (let [format (tp/get-static-format "sched" "sched_switch")
        insn (tp/tracepoint-read-field :r1 format :prev_pid :r6)]
    (println "Read prev_pid (4 bytes at offset 24) into r6")
    (println "Instruction bytes:" (count insn))))

;; ============================================================================
;; Example 3: Complete Tracepoint Program
;; ============================================================================

(defn demo-complete-program
  "Demonstrate building a complete tracepoint program."
  []
  (println "\n=== Complete Tracepoint Program ===\n")

  ;; Build a program that traces sched_switch events
  (let [prog (tp/build-tracepoint-program
              {:category "sched"
               :name "sched_switch"
               :ctx-reg :r9
               :fields {:prev_pid :r6 :next_pid :r7}
               :body [;; Get current timestamp
                      ;; (would use helper-ktime-get-ns in real program)
                      (dsl/mov :r8 0)
                      ;; Compare prev_pid and next_pid
                      (dsl/mov-reg :r0 :r6)]
               :return-value 0})]
    (println "Program for sched/sched_switch:")
    (println "  Bytecode size:" (count prog) "bytes")
    (println "  Instructions:" (/ (count prog) 8))
    (println "  8-byte aligned:" (zero? (mod (count prog) 8)))))

;; ============================================================================
;; Example 4: Using deftracepoint-instructions Macro
;; ============================================================================

;; Define a scheduler switch handler using the macro
(tp/deftracepoint-instructions sched-switch-handler
  {:category "sched"
   :name "sched_switch"
   :fields {:prev_pid :r6 :next_pid :r7 :prev_prio :r8}
   :ctx-reg :r9}
  ;; Body: just return 0 for this example
  [(dsl/mov :r0 0)
   (dsl/exit-insn)])

;; Define a raw tracepoint handler for sys_enter
(tp/defraw-tracepoint-instructions raw-sys-enter-handler
  {:name "sys_enter"
   :ctx-reg :r9}
  ;; Load syscall number from context
  [(dsl/ldx :dw :r6 :r1 8)  ; syscall number at offset 8
   (dsl/mov :r0 0)
   (dsl/exit-insn)])

(defn demo-macro-usage
  "Demonstrate using deftracepoint-instructions macro."
  []
  (println "\n=== deftracepoint-instructions Macro ===\n")

  ;; Use the macro-defined handler
  (let [insns (sched-switch-handler)]
    (println "sched-switch-handler:")
    (println "  Function defined: yes")
    (println "  Returns instructions: yes")
    (println "  Instruction count:" (count insns))
    (println "  All bytes:" (every? bytes? insns)))

  (println)

  (let [insns (raw-sys-enter-handler)]
    (println "raw-sys-enter-handler:")
    (println "  Instruction count:" (count insns))
    (println "  Includes context save + syscall load + exit")))

;; ============================================================================
;; Example 5: Assembling Complete Programs
;; ============================================================================

(defn demo-program-assembly
  "Demonstrate assembling complete tracepoint programs."
  []
  (println "\n=== Program Assembly ===\n")

  ;; Assemble the macro-defined handler
  (let [bytecode (dsl/assemble (sched-switch-handler))]
    (println "Assembled sched-switch-handler:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8)))

  ;; Build and assemble a syscall tracer
  (let [format (tp/get-static-format "raw_syscalls" "sys_enter")
        bytecode (dsl/assemble
                  (vec (concat
                        ;; Prologue: save context, load syscall ID
                        (tp/tracepoint-prologue :r9 format {:id :r6})
                        ;; Get PID
                        (dsl/helper-get-current-pid-tgid)
                        [(dsl/mov-reg :r7 :r0)
                         ;; Mask to get just PID
                         (dsl/and :r7 0xffffffff)]
                        ;; Exit
                        [(dsl/mov :r0 0)
                         (dsl/exit-insn)])))]
    (println "\nAssembled sys_enter tracer:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))))

;; ============================================================================
;; Example 6: Program Metadata
;; ============================================================================

(defn demo-program-metadata
  "Demonstrate creating program metadata for loading."
  []
  (println "\n=== Program Metadata ===\n")

  ;; Create tracepoint program info
  (let [insns (sched-switch-handler)
        info (tp/make-tracepoint-program-info
              "sched" "sched_switch" "my_sched_tracer" insns)]
    (println "Tracepoint Program Info:")
    (println "  Name:" (:name info))
    (println "  Section:" (:section info))
    (println "  Type:" (:type info))
    (println "  Category:" (:category info))
    (println "  Tracepoint:" (:tracepoint info)))

  (println)

  ;; Create raw tracepoint program info
  (let [insns (raw-sys-enter-handler)
        info (tp/make-raw-tracepoint-program-info
              "sys_enter" "raw_syscall_tracer" insns)]
    (println "Raw Tracepoint Program Info:")
    (println "  Name:" (:name info))
    (println "  Section:" (:section info))
    (println "  Type:" (:type info))))

;; ============================================================================
;; Example 7: Available Static Formats
;; ============================================================================

(defn demo-static-formats
  "Show all pre-defined static tracepoint formats."
  []
  (println "\n=== Available Static Formats ===\n")
  (println "These formats work without tracefs access (e.g., in CI):\n")

  (doseq [[key format] tp/common-tracepoint-formats]
    (printf "  %-35s %d fields\n"
            (name key)
            (count (:fields format)))))

;; ============================================================================
;; Example 8: Tracepoint Discovery (requires tracefs)
;; ============================================================================

(defn demo-tracepoint-discovery
  "Demonstrate tracepoint discovery (requires tracefs access)."
  []
  (println "\n=== Tracepoint Discovery ===\n")

  (if-let [tracefs (tp/find-tracefs)]
    (do
      (println "Tracefs found at:" tracefs)

      ;; List categories
      (when-let [categories (tp/list-tracepoint-categories)]
        (println "\nTracepoint categories:" (count categories))
        (println "Sample categories:" (take 10 categories)))

      ;; List tracepoints in sched category
      (when-let [tracepoints (tp/list-tracepoints "sched")]
        (println "\nTracepoints in 'sched':" (count tracepoints))
        (println "Sample tracepoints:" (take 5 tracepoints)))

      ;; Check if specific tracepoint exists
      (println "\nsched/sched_switch exists:" (tp/tracepoint-exists? "sched" "sched_switch"))
      (println "fake/nonexistent exists:" (tp/tracepoint-exists? "fake" "nonexistent")))

    (println "Tracefs not found - discovery features require root access")))

;; ============================================================================
;; Example 9: Complete Sched Switch Tracer with Ring Buffer
;; ============================================================================

(defn build-sched-switch-tracer
  "Build a complete scheduler switch tracer program.

   This example shows how to:
   1. Read tracepoint fields
   2. Get additional context (timestamp, CPU)
   3. Fill an event structure
   4. Submit to ring buffer

   Note: This returns bytecode, actual loading requires BPF privileges."
  [ringbuf-fd]
  (let [format (tp/get-static-format "sched" "sched_switch")
        event-size (structs/event-size SchedSwitchEvent)]
    (dsl/assemble
     (vec (concat
           ;; Prologue: save context, read prev_pid and next_pid
           (tp/tracepoint-prologue :r9 format {:prev_pid :r6 :next_pid :r7})

           ;; Read priorities
           [(tp/tracepoint-read-field :r9 format :prev_prio :r3)
            (tp/tracepoint-read-field :r9 format :next_prio :r4)]

           ;; Get timestamp
           (dsl/helper-ktime-get-ns)
           [(dsl/mov-reg :r8 :r0)]  ; r8 = timestamp

           ;; Get CPU ID
           (dsl/helper-get-smp-processor-id)
           [(dsl/stx :w :r10 :r0 -4)]  ; Store CPU on stack temporarily

           ;; Reserve ring buffer space
           (dsl/ringbuf-reserve :r5 ringbuf-fd event-size)

           ;; Check for NULL (reservation failed)
           [(dsl/jmp-imm :jeq :r5 0 12)]  ; Jump to exit if r5 == 0

           ;; Fill event structure
           [(structs/store-event-field :r5 SchedSwitchEvent :timestamp :r8)
            (structs/store-event-field :r5 SchedSwitchEvent :prev_pid :r6)
            (structs/store-event-field :r5 SchedSwitchEvent :next_pid :r7)
            (structs/store-event-field :r5 SchedSwitchEvent :prev_prio :r3)
            (structs/store-event-field :r5 SchedSwitchEvent :next_prio :r4)]

           ;; Load CPU from stack and store
           [(dsl/ldx :w :r0 :r10 -4)
            (structs/store-event-field :r5 SchedSwitchEvent :cpu :r0)]

           ;; Submit to ring buffer
           (dsl/ringbuf-submit :r5)

           ;; Exit successfully
           [(dsl/mov :r0 0)
            (dsl/exit-insn)])))))

(defn demo-complete-tracer
  "Demonstrate building a complete tracer program."
  []
  (println "\n=== Complete Sched Switch Tracer ===\n")

  (let [bytecode (build-sched-switch-tracer 5)]  ; dummy fd
    (println "Built complete sched_switch tracer:")
    (println "  Event structure size:" (structs/event-size SchedSwitchEvent) "bytes")
    (println "  Program bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))
    (println)
    (println "Event fields:")
    (doseq [field (structs/event-fields SchedSwitchEvent)]
      (printf "  %-12s offset=%-2d size=%-2d\n"
              (name field)
              (structs/event-field-offset SchedSwitchEvent field)
              (structs/event-field-size SchedSwitchEvent field)))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all tracepoint DSL demonstrations."
  [& args]
  (println "==============================================")
  (println "  Tracepoint DSL Examples")
  (println "==============================================")

  (demo-format-inspection)
  (demo-tracepoint-prologue)
  (demo-complete-program)
  (demo-macro-usage)
  (demo-program-assembly)
  (demo-program-metadata)
  (demo-static-formats)
  (demo-tracepoint-discovery)
  (demo-complete-tracer)

  (println "\n==============================================")
  (println "  All demonstrations complete!")
  (println "=============================================="))

;; ============================================================================
;; REPL Usage
;; ============================================================================

(comment
  ;; Run all demos
  (-main)

  ;; Inspect a format
  (tp/get-static-format "sched" "sched_switch")

  ;; Get field offset
  (let [format (tp/get-static-format "sched" "sched_switch")]
    (tp/tracepoint-field-offset format :prev_pid))

  ;; Build a simple program
  (tp/build-tracepoint-program
   {:category "sched"
    :name "sched_switch"
    :fields {:prev_pid :r6}
    :body []})

  ;; Use macro-defined handler
  (sched-switch-handler)

  ;; List available tracepoints (requires tracefs)
  (tp/list-tracepoint-categories)
  (tp/list-tracepoints "sched")
  )
