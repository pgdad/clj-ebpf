(ns clj-ebpf.dsl.perf-event
  "High-level Perf Event DSL for BPF programs.

   Perf event programs are attached to hardware or software performance
   events and can sample CPU state, collect stack traces, and more.

   Context: bpf_perf_event_data contains pt_regs and sample info.

   Example:
     (defperf-event-instructions sample-cpu
       {:type :software
        :config :cpu-clock}
       [])"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.arch :as arch]))

;; ============================================================================
;; Perf Event Types
;; ============================================================================

(def perf-types
  "Perf event types."
  {:hardware  0    ; PERF_TYPE_HARDWARE
   :software  1    ; PERF_TYPE_SOFTWARE
   :tracepoint 2   ; PERF_TYPE_TRACEPOINT
   :hw-cache  3    ; PERF_TYPE_HW_CACHE
   :raw       4    ; PERF_TYPE_RAW
   :breakpoint 5}) ; PERF_TYPE_BREAKPOINT

(def hardware-events
  "Hardware performance events."
  {:cpu-cycles          0
   :instructions        1
   :cache-references    2
   :cache-misses        3
   :branch-instructions 4
   :branch-misses       5
   :bus-cycles          6
   :stalled-cycles-frontend 7
   :stalled-cycles-backend  8
   :ref-cpu-cycles      9})

(def software-events
  "Software performance events."
  {:cpu-clock        0
   :task-clock       1
   :page-faults      2
   :context-switches 3
   :cpu-migrations   4
   :page-faults-min  5
   :page-faults-maj  6
   :alignment-faults 7
   :emulation-faults 8
   :dummy            9
   :bpf-output       10})

;; ============================================================================
;; bpf_perf_event_data Structure
;; ============================================================================

;; struct bpf_perf_event_data {
;;   bpf_user_pt_regs_t regs;  // pt_regs at offset 0
;;   __u64 sample_period;       // offset 128 (after pt_regs)
;;   __u64 addr;                // offset 136
;; };

(def perf-event-data-offsets
  "bpf_perf_event_data field offsets (x86_64)."
  {:regs          0    ; pt_regs structure
   :sample-period 128  ; Sample period
   :addr          136}) ; Event address

(defn perf-event-offset
  "Get offset for bpf_perf_event_data field.

   Parameters:
   - field: Field keyword

   Returns offset in bytes."
  [field]
  (or (get perf-event-data-offsets field)
      (throw (ex-info "Unknown perf_event_data field" {:field field}))))

;; ============================================================================
;; Perf Event Prologue
;; ============================================================================

(defn perf-event-prologue
  "Generate standard perf event program prologue.

   Saves context pointer to callee-saved register.

   Parameters:
   - ctx-save-reg: Register to save context (optional)

   Returns vector of instructions."
  ([]
   [])
  ([ctx-save-reg]
   (when ctx-save-reg
     [(dsl/mov-reg ctx-save-reg :r1)])))

(defn perf-event-get-regs
  "Get pointer to pt_regs from perf event context.

   The pt_regs starts at offset 0, so ctx pointer is also regs pointer.

   Parameters:
   - ctx-reg: Register containing context pointer

   Returns the same register (pt_regs is at offset 0)."
  [ctx-reg]
  ctx-reg)

;; ============================================================================
;; Perf Event Data Access
;; ============================================================================

(defn perf-get-sample-period
  "Get sample period from perf event context.

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (dsl/ldx :dw dst-reg ctx-reg (perf-event-offset :sample-period)))

(defn perf-get-addr
  "Get event address from perf event context.

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (dsl/ldx :dw dst-reg ctx-reg (perf-event-offset :addr)))

(defn perf-get-ip
  "Get instruction pointer from pt_regs in perf event context.

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  ;; IP offset in pt_regs (x86_64: 128)
  (let [ip-offset (case arch/current-arch
                   :x86_64 128   ; rip
                   :arm64  256   ; pc
                   128)]
    (dsl/ldx :dw dst-reg ctx-reg ip-offset)))

;; ============================================================================
;; Perf Event Helpers
;; ============================================================================

(defn perf-get-stackid
  "Generate call to bpf_get_stackid helper.

   Parameters:
   - ctx-reg: Register containing context pointer
   - map-fd: Stack map file descriptor
   - flags: Flags (e.g., BPF_F_USER_STACK, BPF_F_FAST_STACK_CMP)

   Returns vector of instructions."
  [ctx-reg map-fd flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/ld-map-fd :r2 map-fd)
   (dsl/mov :r3 flags)
   (dsl/call 27)])  ; BPF_FUNC_get_stackid

(defn perf-output
  "Generate call to bpf_perf_event_output helper.

   Outputs data to a perf buffer.

   Parameters:
   - ctx-reg: Register containing context pointer
   - map-fd: Perf event array map FD
   - flags: Flags
   - data-reg: Register pointing to data
   - size: Data size

   Returns vector of instructions."
  [ctx-reg map-fd flags data-reg size]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/ld-map-fd :r2 map-fd)
   (dsl/mov :r3 flags)
   (dsl/mov-reg :r4 data-reg)
   (dsl/mov :r5 size)
   (dsl/call 25)])  ; BPF_FUNC_perf_event_output

(defn perf-read
  "Generate call to bpf_perf_event_read helper.

   Reads counter value from perf event.

   Parameters:
   - map-fd: Perf event array map FD
   - flags: Index and flags

   Returns vector of instructions."
  [map-fd flags]
  [(dsl/ld-map-fd :r1 map-fd)
   (dsl/mov :r2 flags)
   (dsl/call 22)])  ; BPF_FUNC_perf_event_read

;; ============================================================================
;; Common Helpers (reused)
;; ============================================================================

(defn perf-get-current-pid
  "Generate instructions to get current PID.

   Returns vector of instructions with PID in r0."
  []
  [(dsl/call 14)  ; BPF_FUNC_get_current_pid_tgid
   (dsl/alu-imm :rsh :r0 32)])

(defn perf-get-ktime-ns
  "Generate instruction to get kernel time.

   Returns call instruction with time in r0."
  []
  [(dsl/call 5)])  ; BPF_FUNC_ktime_get_ns

;; ============================================================================
;; Program Builders
;; ============================================================================

(defn build-perf-event-program
  "Build a complete perf event program.

   Parameters:
   - opts: Map with:
     :ctx-reg - Register to save context (optional)
     :body - Vector of body instructions
     :return-value - Return value (default 0)

   Returns assembled program bytes."
  [{:keys [ctx-reg body return-value]
    :or {return-value 0}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue
         (perf-event-prologue ctx-reg)
         ;; Body
         body
         ;; Return
         [(dsl/mov :r0 return-value)
          (dsl/exit-insn)]))))

(defmacro defperf-event-instructions
  "Define a perf event program as a function returning instructions.

   Parameters:
   - fn-name: Name for the defined function
   - options: Map with:
     :type - Perf type (:hardware, :software, etc.)
     :config - Event config
     :ctx-reg - Register to save context (optional)
   - body: Body expressions

   Example:
     (defperf-event-instructions cpu-profiler
       {:type :software
        :config :cpu-clock
        :ctx-reg :r6}
       (perf-get-current-pid))"
  [fn-name options & body]
  (let [ctx-reg (:ctx-reg options)]
    `(defn ~fn-name
       ~(str "Perf event program.\n"
             "Type: " (or (:type options) "unspecified") "\n"
             "Config: " (or (:config options) "unspecified"))
       []
       (vec (concat
             (perf-event-prologue ~ctx-reg)
             ~@body
             [(dsl/mov :r0 0)
              (dsl/exit-insn)])))))

;; ============================================================================
;; Section Names and Metadata
;; ============================================================================

(defn perf-event-section-name
  "Generate ELF section name for perf event program.

   Parameters:
   - name: Optional program name

   Returns section name like \"perf_event\" or \"perf_event/name\"."
  ([]
   "perf_event")
  ([name]
   (str "perf_event/" name)))

(defn make-perf-event-info
  "Create program metadata for a perf event program.

   Parameters:
   - program-name: Name for the BPF program
   - perf-type: Perf type (:hardware, :software, etc.)
   - config: Event config
   - instructions: Program instructions

   Returns map with program metadata."
  [program-name perf-type config instructions]
  {:name program-name
   :section (perf-event-section-name program-name)
   :type :perf-event
   :perf-type perf-type
   :config config
   :instructions instructions})

;; ============================================================================
;; Perf Event Flags
;; ============================================================================

(def stackid-flags
  "Flags for bpf_get_stackid."
  {:user-stack     (bit-shift-left 1 8)   ; BPF_F_USER_STACK
   :fast-stack-cmp (bit-shift-left 1 9)   ; BPF_F_FAST_STACK_CMP
   :reuse-stackid  (bit-shift-left 1 10)}) ; BPF_F_REUSE_STACKID

(defn stackid-flag
  "Get stackid flag value.

   Parameters:
   - flag: Flag keyword or set of keywords

   Returns integer flag value."
  [flag]
  (if (keyword? flag)
    (or (get stackid-flags flag)
        (throw (ex-info "Unknown stackid flag" {:flag flag})))
    (reduce bit-or 0 (map stackid-flag flag))))

;; ============================================================================
;; Return Patterns
;; ============================================================================

(defn perf-return
  "Generate instructions to return from perf event program.

   Parameters:
   - value: Return value (default 0)

   Returns vector of instructions."
  ([]
   (perf-return 0))
  ([value]
   [(dsl/mov :r0 value)
    (dsl/exit-insn)]))

;; ============================================================================
;; Describe Perf Event
;; ============================================================================

(defn describe-perf-event
  "Return information about a perf event type.

   Parameters:
   - perf-type: Type keyword (:hardware, :software, etc.)

   Returns map with event information."
  [perf-type]
  {:type perf-type
   :type-value (get perf-types perf-type)
   :available-configs (case perf-type
                       :hardware (keys hardware-events)
                       :software (keys software-events)
                       [])
   :notes ["Requires CAP_PERFMON or CAP_SYS_ADMIN"
           "Sample-based profiling"
           "Can collect stack traces"]})
