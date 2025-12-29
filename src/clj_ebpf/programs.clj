(ns clj-ebpf.programs
  "BPF program loading and attachment"
  (:require [clj-ebpf.syscall :as syscall]
            [clj-ebpf.constants :as const]
            [clj-ebpf.utils :as utils]
            [clojure.tools.logging :as log]
            [clojure.string :as str]
            [clojure.java.io :as io])
  (:import [java.lang.foreign MemorySegment]))

;; BPF Program representation

(defrecord BpfProgram
  [fd              ; File descriptor
   type            ; Program type keyword
   name            ; Program name
   insn-count      ; Number of instructions
   license         ; License string
   verifier-log    ; Verifier log (if any)
   attachments])   ; Vector of attachments

(defrecord ProgramAttachment
  [type            ; Attachment type (:kprobe, :uprobe, :tracepoint, etc.)
   target          ; Target (function name, file path, etc.)
   event-fd        ; File descriptor for the perf event
   detach-fn])     ; Function to detach

;; Program loading

(defn load-program
  "Load a BPF program into the kernel

  Options:
  - :prog-type - Program type (:kprobe, :tracepoint, :xdp, :tracing, etc.)
  - :insns - BPF instructions as byte array or pointer
  - :insn-count - Number of instructions (auto-calculated if insns is byte array)
  - :license - License string (e.g., 'GPL')
  - :prog-name - Optional program name
  - :log-level - Verifier log level (0=off, 1=basic, 2=verbose)
  - :kern-version - Kernel version (default: current kernel)
  - :expected-attach-type - Expected attach type for certain prog types
  - :attach-btf-id - BTF type ID for fentry/fexit programs"
  [{:keys [prog-type insns insn-count license prog-name log-level kern-version
           prog-flags expected-attach-type prog-btf-fd attach-btf-id]
    :or {log-level 1
         license "GPL"
         kern-version (utils/get-kernel-version)
         prog-flags 0}}]
  (utils/with-bpf-arena
    (let [;; Convert insns to memory segment if needed
          insns-seg (if (instance? MemorySegment insns)
                     insns
                     (utils/bytes->segment insns))
          ;; Calculate instruction count (each BPF insn is 8 bytes)
          insn-cnt (or insn-count
                      (if (instance? MemorySegment insns)
                        (throw (ex-info "Must provide :insn-count when :insns is a MemorySegment"
                                       {:insns insns}))
                        (/ (count insns) 8)))
          ;; Allocate log buffer
          log-buf (utils/allocate-memory const/BPF_LOG_BUF_SIZE)
          _ (utils/zero-memory log-buf const/BPF_LOG_BUF_SIZE)

          ;; Load the program
          fd (try
               (syscall/prog-load
                 {:prog-type prog-type
                  :insn-cnt insn-cnt
                  :insns insns-seg
                  :license license
                  :log-level log-level
                  :log-size const/BPF_LOG_BUF_SIZE
                  :log-buf log-buf
                  :kern-version kern-version
                  :prog-flags prog-flags
                  :prog-name prog-name
                  :expected-attach-type (when expected-attach-type
                                         (const/attach-type->num expected-attach-type))
                  :prog-btf-fd prog-btf-fd
                  :attach-btf-id attach-btf-id})
               (catch clojure.lang.ExceptionInfo e
                 ;; Extract verifier log
                 (let [log-str (utils/segment->string log-buf const/BPF_LOG_BUF_SIZE)]
                   (log/error "BPF program load failed. Verifier log:\n" log-str)
                   (throw (ex-info "BPF program load failed"
                                  (assoc (ex-data e) :verifier-log log-str))))))

          ;; Get verifier log even on success
          log-str (utils/segment->string log-buf const/BPF_LOG_BUF_SIZE)
          log-str (when (and log-str (not (str/blank? log-str)))
                    (str/trim log-str))]

      (when (and log-str (> log-level 0))
        (log/debug "Verifier log for" prog-name ":\n" log-str))

      (log/info "Loaded BPF program:" prog-name "type:" prog-type "fd:" fd)
      (->BpfProgram fd prog-type prog-name insn-cnt license log-str []))))

(defn close-program
  "Close a BPF program and detach all attachments"
  [^BpfProgram prog]
  ;; Detach all attachments first
  (doseq [attachment (:attachments prog)]
    (when-let [detach-fn (:detach-fn attachment)]
      (try
        (detach-fn)
        (catch Exception e
          (log/warn "Failed to detach" (:type attachment) "from" (:target attachment) ":" e)))))
  ;; Close the program FD
  (when-let [fd (:fd prog)]
    (syscall/close-fd fd)
    (log/info "Closed BPF program:" (:name prog) "fd:" fd)))

;; Kprobe/Kretprobe attachment

(defn- remove-kprobe-event
  "Remove kprobe event from tracefs"
  [event-name]
  (let [kprobe-events-path "/sys/kernel/debug/tracing/kprobe_events"
        event-def (str "-:" event-name "\n")]
    (try
      (spit kprobe-events-path event-def :append true)
      (log/debug "Removed kprobe event:" event-name)
      (catch Exception e
        (log/warn "Failed to remove kprobe event" event-name ":" e)))))

(defn- write-kprobe-event
  "Write kprobe event to tracefs"
  [event-name function-name is-retprobe?]
  (let [tracefs-path "/sys/kernel/debug/tracing"
        kprobe-events-path (str tracefs-path "/kprobe_events")
        event-def (str (if is-retprobe? "r:" "p:")
                      event-name " " function-name "\n")]
    ;; First try to remove the event if it exists (ignore errors)
    (try
      (remove-kprobe-event event-name)
      (catch Exception _ nil))
    ;; Now create the event
    (try
      (spit kprobe-events-path event-def :append true)
      (log/debug "Created kprobe event:" event-def)
      (catch Exception e
        (throw (ex-info "Failed to create kprobe event"
                       {:event-name event-name
                        :function-name function-name
                        :is-retprobe is-retprobe?
                        :cause e}))))))

(defn- get-tracepoint-id
  "Get tracepoint ID from tracefs"
  [category name]
  (let [id-path (str "/sys/kernel/debug/tracing/events/" category "/" name "/id")]
    (try
      (Integer/parseInt (str/trim (slurp id-path)))
      (catch Exception e
        (throw (ex-info "Failed to get tracepoint ID"
                       {:category category
                        :name name
                        :id-path id-path
                        :cause e}))))))

(defn attach-kprobe
  "Attach BPF program to a kprobe using perf events

  This uses the tracefs-based approach which is widely compatible:
  1. Creates a kprobe event in /sys/kernel/debug/tracing/kprobe_events
  2. Opens a perf event for that tracepoint
  3. Attaches the BPF program via PERF_EVENT_IOC_SET_BPF

  Options:
  - :function - Kernel function name to probe
  - :retprobe? - If true, attach to function return (default: false)
  - :pid - PID to attach to (default: -1 for all processes)
  - :cpu - CPU to attach to (default: 0)"
  [^BpfProgram prog {:keys [function retprobe? pid cpu]
                     :or {retprobe? false pid -1 cpu 0}}]
  (let [;; Generate unique event name
        event-name (str (if retprobe? "kretp_" "kprobe_")
                       (str/replace function #"[^a-zA-Z0-9_]" "_")
                       "_" (System/currentTimeMillis))

        ;; Create kprobe event in tracefs
        _ (write-kprobe-event event-name function retprobe?)

        ;; Get the event ID from tracefs
        tracepoint-id (get-tracepoint-id "kprobes" event-name)
        _ (log/debug "Kprobe event" event-name "has tracepoint ID:" tracepoint-id)

        ;; Open perf event
        event-fd (syscall/perf-event-open
                   (const/perf-type :tracepoint)
                   tracepoint-id
                   pid
                   cpu
                   -1   ; group_fd
                   0)   ; flags

        ;; Attach BPF program
        _ (syscall/ioctl event-fd (const/perf-event-ioc :set-bpf) (:fd prog))

        ;; Enable the event
        _ (syscall/ioctl event-fd (const/perf-event-ioc :enable))

        ;; Create detach function
        detach-fn (fn []
                   (try
                     (syscall/ioctl event-fd (const/perf-event-ioc :disable))
                     (catch Exception e
                       (log/warn "Failed to disable perf event:" e)))
                   (syscall/close-fd event-fd)
                   (remove-kprobe-event event-name))

        attachment (->ProgramAttachment
                     (if retprobe? :kretprobe :kprobe)
                     function
                     event-fd
                     detach-fn)]

    (log/info "Attached" (if retprobe? "kretprobe" "kprobe")
              "to" function "event-fd:" event-fd)

    ;; Add attachment to program
    (update prog :attachments conj attachment)))

(defn attach-kretprobe
  "Attach BPF program to a kretprobe (function return probe)"
  [^BpfProgram prog options]
  (attach-kprobe prog (assoc options :retprobe? true)))

;; Uprobe/Uretprobe attachment

(defn- remove-uprobe-event
  "Remove uprobe event from tracefs"
  [event-name]
  (let [uprobe-events-path "/sys/kernel/debug/tracing/uprobe_events"
        event-def (str "-:" event-name "\n")]
    (try
      (spit uprobe-events-path event-def :append true)
      (log/debug "Removed uprobe event:" event-name)
      (catch Exception e
        (log/warn "Failed to remove uprobe event" event-name ":" e)))))

(defn- write-uprobe-event
  "Write uprobe event to tracefs

  For uprobes, the event definition is:
    p:event_name /path/to/binary:offset   (for entry probe)
    r:event_name /path/to/binary:offset   (for return probe)

  The offset can be:
    - A hex offset like 0x1234
    - A symbol name (if the binary has symbols)"
  [event-name binary-path offset is-retprobe?]
  (let [tracefs-path "/sys/kernel/debug/tracing"
        uprobe-events-path (str tracefs-path "/uprobe_events")
        ;; Format offset - if it's a number, convert to hex
        offset-str (cond
                    (number? offset) (format "0x%x" offset)
                    (string? offset) offset
                    :else (str offset))
        event-def (str (if is-retprobe? "r:" "p:")
                      event-name " " binary-path ":" offset-str "\n")]
    ;; First try to remove the event if it exists (ignore errors)
    (try
      (remove-uprobe-event event-name)
      (catch Exception _ nil))
    ;; Now create the event
    (try
      (spit uprobe-events-path event-def :append true)
      (log/debug "Created uprobe event:" event-def)
      (catch Exception e
        (throw (ex-info "Failed to create uprobe event"
                       {:event-name event-name
                        :binary-path binary-path
                        :offset offset
                        :is-retprobe is-retprobe?
                        :cause e}))))))

(defn attach-uprobe
  "Attach BPF program to a uprobe using perf events

  This uses the tracefs-based approach which is widely compatible:
  1. Creates a uprobe event in /sys/kernel/debug/tracing/uprobe_events
  2. Opens a perf event for that tracepoint
  3. Attaches the BPF program via PERF_EVENT_IOC_SET_BPF

  Options:
  - :binary - Path to the binary or library to probe (e.g., \"/lib/x86_64-linux-gnu/libc.so.6\")
  - :offset - Offset or symbol name within the binary (e.g., 0x9d850 or \"malloc\")
  - :retprobe? - If true, attach to function return (default: false)
  - :pid - PID to attach to (default: -1 for all processes)
  - :cpu - CPU to attach to (default: 0)

  Example:
    ;; Attach to malloc in libc
    (attach-uprobe prog {:binary \"/lib/x86_64-linux-gnu/libc.so.6\"
                         :offset \"malloc\"})

    ;; Attach to specific offset
    (attach-uprobe prog {:binary \"/usr/bin/myapp\"
                         :offset 0x1234})"
  [^BpfProgram prog {:keys [binary offset retprobe? pid cpu]
                     :or {retprobe? false pid -1 cpu 0}}]
  (let [;; Generate unique event name - sanitize binary name for event name
        binary-basename (last (str/split binary #"/"))
        offset-str (if (number? offset) (format "%x" offset) (str offset))
        event-name (str (if retprobe? "uretp_" "uprobe_")
                       (str/replace binary-basename #"[^a-zA-Z0-9_]" "_")
                       "_" (str/replace offset-str #"[^a-zA-Z0-9_]" "_")
                       "_" (System/currentTimeMillis))

        ;; Create uprobe event in tracefs
        _ (write-uprobe-event event-name binary offset retprobe?)

        ;; Get the event ID from tracefs
        tracepoint-id (get-tracepoint-id "uprobes" event-name)
        _ (log/debug "Uprobe event" event-name "has tracepoint ID:" tracepoint-id)

        ;; Open perf event
        event-fd (syscall/perf-event-open
                   (const/perf-type :tracepoint)
                   tracepoint-id
                   pid
                   cpu
                   -1   ; group_fd
                   0)   ; flags

        ;; Attach BPF program
        _ (syscall/ioctl event-fd (const/perf-event-ioc :set-bpf) (:fd prog))

        ;; Enable the event
        _ (syscall/ioctl event-fd (const/perf-event-ioc :enable))

        ;; Create detach function
        detach-fn (fn []
                   (try
                     (syscall/ioctl event-fd (const/perf-event-ioc :disable))
                     (catch Exception e
                       (log/warn "Failed to disable perf event:" e)))
                   (syscall/close-fd event-fd)
                   (remove-uprobe-event event-name))

        attachment (->ProgramAttachment
                     (if retprobe? :uretprobe :uprobe)
                     (str binary ":" offset)
                     event-fd
                     detach-fn)]

    (log/info "Attached" (if retprobe? "uretprobe" "uprobe")
              "to" binary "at" offset "event-fd:" event-fd)

    ;; Add attachment to program
    (update prog :attachments conj attachment)))

(defn attach-uretprobe
  "Attach BPF program to a uretprobe (function return probe)"
  [^BpfProgram prog options]
  (attach-uprobe prog (assoc options :retprobe? true)))

;; Fentry/Fexit attachment

(defn load-fentry-program
  "Load a BPF program for fentry/fexit attachment.

  Fentry/fexit programs require special loading with:
  - prog-type: :tracing
  - expected-attach-type: :trace-fentry or :trace-fexit
  - attach-btf-id: BTF type ID of the target function

  Options:
  - :insns - BPF bytecode
  - :function - Kernel function name to attach to
  - :fexit? - If true, load as fexit (default: false for fentry)
  - :prog-name - Optional program name
  - :license - License string (default: 'GPL')
  - :log-level - Verifier log level (default: 1)

  Returns a BpfProgram record with :btf-id in metadata."
  [{:keys [insns function fexit? prog-name license log-level]
    :or {fexit? false license "GPL" log-level 1}}]
  (let [;; Find BTF ID for the target function
        btf-id (syscall/parse-btf-vmlinux function)
        _ (when-not btf-id
            (throw (ex-info "Function not found in kernel BTF"
                           {:function function})))

        ;; Load the program with tracing type and BTF ID
        prog (load-program {:insns insns
                           :prog-type :tracing
                           :expected-attach-type (if fexit? :trace-fexit :trace-fentry)
                           :prog-name (or prog-name (str (if fexit? "fexit_" "fentry_") function))
                           :license license
                           :log-level log-level
                           :attach-btf-id btf-id})]
    ;; Store BTF ID for later use in attachment
    (assoc prog :btf-id btf-id :target-function function)))

(defn attach-fentry
  "Attach BPF program to a kernel function entry point using fentry.

  Fentry is a modern, efficient alternative to kprobes that uses BTF
  (BPF Type Format) for type-safe function argument access.

  There are two ways to use this:

  1. Load program separately, then attach:
     (let [prog (load-fentry-program {:insns bytecode
                                      :function \"tcp_v4_connect\"})]
       (attach-fentry prog {}))

  2. Or provide the function name if not already set:
     (attach-fentry prog {:function \"tcp_v4_connect\"})

  Options:
  - :function - Kernel function name (optional if program was loaded with load-fentry-program)

  Requirements:
  - Kernel 5.5+ with BTF support
  - Program must be loaded with :prog-type :tracing"
  [^BpfProgram prog {:keys [function] :as opts}]
  (let [;; Get BTF ID either from stored metadata or by looking up function
        btf-id (or (:btf-id prog)
                  (when function
                    (syscall/parse-btf-vmlinux function))
                  (throw (ex-info "No BTF ID or function specified"
                                 {:prog prog :opts opts})))
        target-fn (or (:target-function prog) function)

        ;; Create the BPF link
        link-fd (syscall/bpf-link-create-fentry (:fd prog) btf-id :trace-fentry)

        ;; Create detach function
        detach-fn (fn []
                   (try
                     (syscall/close-fd link-fd)
                     (catch Exception e
                       (log/warn "Failed to close BPF link:" e))))

        attachment (->ProgramAttachment
                     :fentry
                     target-fn
                     link-fd
                     detach-fn)]

    (log/info "Attached fentry to" target-fn "link-fd:" link-fd)

    ;; Add attachment to program
    (update prog :attachments conj attachment)))

(defn attach-fexit
  "Attach BPF program to a kernel function exit point using fexit.

  Fexit is similar to fentry but triggers when the function returns,
  allowing access to the return value.

  See attach-fentry for usage details."
  [^BpfProgram prog {:keys [function] :as opts}]
  (let [;; Get BTF ID either from stored metadata or by looking up function
        btf-id (or (:btf-id prog)
                  (when function
                    (syscall/parse-btf-vmlinux function))
                  (throw (ex-info "No BTF ID or function specified"
                                 {:prog prog :opts opts})))
        target-fn (or (:target-function prog) function)

        ;; Create the BPF link
        link-fd (syscall/bpf-link-create-fentry (:fd prog) btf-id :trace-fexit)

        ;; Create detach function
        detach-fn (fn []
                   (try
                     (syscall/close-fd link-fd)
                     (catch Exception e
                       (log/warn "Failed to close BPF link:" e))))

        attachment (->ProgramAttachment
                     :fexit
                     target-fn
                     link-fd
                     detach-fn)]

    (log/info "Attached fexit to" target-fn "link-fd:" link-fd)

    ;; Add attachment to program
    (update prog :attachments conj attachment)))

;; Tracepoint attachment

(defn attach-tracepoint
  "Attach BPF program to a tracepoint

  Options:
  - :category - Tracepoint category (e.g., 'sched')
  - :name - Tracepoint name (e.g., 'sched_switch')
  - :pid - PID to attach to (default: -1 for all processes)
  - :cpu - CPU to attach to (default: 0)

  Note: For perf-based tracepoints, at least one of pid or cpu must be non-negative.
  If pid=-1, you must specify a cpu. If cpu=-1, you must specify a pid.
  Use :cpu 0 to attach to all processes on CPU 0."
  [^BpfProgram prog {:keys [category name pid cpu]
                     :or {pid -1 cpu 0}}]
  (let [tracepoint-id (get-tracepoint-id category name)

        ;; Open perf event
        event-fd (syscall/perf-event-open
                   (const/perf-type :tracepoint)
                   tracepoint-id
                   pid
                   cpu
                   -1  ; group_fd
                   0)  ; flags

        ;; Attach BPF program
        _ (syscall/ioctl event-fd (const/perf-event-ioc :set-bpf) (:fd prog))

        ;; Enable the event
        _ (syscall/ioctl event-fd (const/perf-event-ioc :enable))

        ;; Create detach function
        detach-fn (fn []
                   (try
                     (syscall/ioctl event-fd (const/perf-event-ioc :disable))
                     (catch Exception e
                       (log/warn "Failed to disable perf event:" e)))
                   (syscall/close-fd event-fd))

        attachment (->ProgramAttachment
                     :tracepoint
                     (str category "/" name)
                     event-fd
                     detach-fn)]

    (log/info "Attached tracepoint" category "/" name "event-fd:" event-fd)

    ;; Add attachment to program
    (update prog :attachments conj attachment)))

;; Raw tracepoint attachment

(defn attach-raw-tracepoint
  "Attach BPF program to a raw tracepoint

  Options:
  - :name - Tracepoint name (e.g., 'sched_process_exec')"
  [^BpfProgram prog {:keys [name]}]
  (let [link-fd (syscall/raw-tracepoint-open name (:fd prog))

        ;; Create detach function
        detach-fn (fn []
                   (syscall/close-fd link-fd))

        attachment (->ProgramAttachment
                     :raw-tracepoint
                     name
                     link-fd
                     detach-fn)]

    (log/info "Attached raw tracepoint" name "link-fd:" link-fd)

    ;; Add attachment to program
    (update prog :attachments conj attachment)))

;; Program pinning

(defn pin-program
  "Pin program to BPF filesystem"
  [^BpfProgram prog path]
  (syscall/obj-pin path (:fd prog))
  (log/info "Pinned program" (:name prog) "to" path))

(defn get-pinned-program
  "Get a pinned program from BPF filesystem"
  [path {:keys [prog-type prog-name]}]
  (let [fd (syscall/obj-get path)]
    (log/info "Retrieved pinned program from" path "fd:" fd)
    (->BpfProgram fd prog-type prog-name nil nil nil [])))

;; Loading from ELF files

(defn- parse-elf-section
  "Parse a section from ELF file (simplified)"
  [elf-bytes section-name]
  ;; This is a simplified implementation
  ;; A full implementation would parse the ELF header and section headers
  ;; For now, we'll just return nil and require pre-extracted bytecode
  nil)

(defn load-from-elf
  "Load BPF program from ELF object file
  Note: This is a simplified version. Full ELF parsing not yet implemented."
  [file-path & {:keys [section-name prog-type license prog-name]
                :or {section-name ".text"
                     license "GPL"}}]
  (let [elf-bytes (utils/read-file-bytes file-path)]
    (throw (ex-info "ELF loading not yet implemented. Please extract bytecode manually."
                   {:file file-path
                    :section section-name}))))

;; Macro for resource management

(defmacro with-program
  "Load a program and ensure it's closed after use"
  [[binding prog-spec] & body]
  `(let [~binding (load-program ~prog-spec)]
     (try
       ~@body
       (finally
         (close-program ~binding)))))

;; Helper for creating simple programs

(defn create-simple-program
  "Create a simple BPF program from bytecode

  Example:
  (create-simple-program
    :type :kprobe
    :bytecode [0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00] ; BPF_EXIT
    :name \"my_prog\")"
  [& {:keys [type bytecode name license]
      :or {license "GPL"}}]
  (load-program {:prog-type type
                 :insns bytecode
                 :prog-name name
                 :license license}))

;; ============================================================================
;; Existence Predicates
;; ============================================================================

(defn program-exists?
  "Check if a BPF program is still valid and loaded in the kernel.

  Returns true if the program FD is valid and the program exists.
  Returns false if the program has been closed or unloaded.

  Note: This is a simple check that verifies the FD is positive.
  The kernel will return EBADF on operations if the FD is invalid."
  [^BpfProgram prog]
  (when-let [fd (:fd prog)]
    (and (integer? fd) (pos? fd))))

(defn program-attached?
  "Check if a BPF program has any active attachments.

  Returns true if the program has one or more attachments."
  [^BpfProgram prog]
  (boolean (seq (:attachments prog))))

;; ============================================================================
;; Tail Call Support
;; ============================================================================
;;
;; Tail calls allow BPF programs to chain together, enabling:
;; - Breaking up large programs to fit within instruction limits
;; - Dynamic dispatch based on packet type or other criteria
;; - Modular program design with shared components
;;
;; Usage pattern:
;; 1. Create a prog_array map
;; 2. Load individual BPF programs
;; 3. Register programs in the prog_array at specific indices
;; 4. Use bpf_tail_call helper in BPF code to jump between programs

(defrecord TailCallChain
  [prog-array         ; The prog_array map
   programs           ; Map of index -> BpfProgram
   entry-program])    ; The entry point program (index 0)

(defn create-prog-array
  "Create a program array map for tail calls.

  Parameters:
  - max-entries: Maximum number of programs (indices 0 to max-entries-1)
  - name: Optional name for the map

  Returns a BPF map suitable for use with bpf_tail_call."
  [max-entries & {:keys [name] :or {name "prog_array"}}]
  (syscall/map-create
    {:map-type :prog-array
     :key-size 4
     :value-size 4
     :max-entries max-entries
     :map-name name}))

(defn register-tail-call
  "Register a BPF program in a prog_array at the specified index.

  Parameters:
  - prog-array-fd: File descriptor of the prog_array map
  - index: Index at which to register the program (0 to max-entries-1)
  - program: BpfProgram to register

  Example:
    (register-tail-call prog-array 0 entry-program)
    (register-tail-call prog-array 1 handler-program)
    (register-tail-call prog-array 2 exit-program)"
  [prog-array-fd index ^BpfProgram program]
  (let [key-seg (utils/bytes->segment (utils/int->bytes index))
        value-seg (utils/bytes->segment (utils/int->bytes (:fd program)))]
    (syscall/map-update-elem prog-array-fd key-seg value-seg 0)
    (log/info "Registered program" (:name program) "at tail call index" index)))

(defn unregister-tail-call
  "Remove a program from a prog_array at the specified index.

  Parameters:
  - prog-array-fd: File descriptor of the prog_array map
  - index: Index to clear"
  [prog-array-fd index]
  (let [key-seg (utils/bytes->segment (utils/int->bytes index))]
    (try
      (syscall/map-delete-elem prog-array-fd key-seg)
      (log/info "Unregistered tail call at index" index)
      true
      (catch Exception _
        false))))

(defn create-tail-call-chain
  "Create a tail call chain with multiple BPF programs.

  A tail call chain allows BPF programs to call each other in sequence,
  useful for breaking up large programs or implementing state machines.

  Parameters:
  - programs: Vector of {:program BpfProgram :index int} maps
  - :max-entries: Maximum programs in chain (default: 32)
  - :name: Name for the prog_array map

  Returns a TailCallChain record.

  Example:
    (create-tail-call-chain
      [{:program entry-prog :index 0}
       {:program parse-prog :index 1}
       {:program action-prog :index 2}]
      :name \"my_chain\")"
  [programs & {:keys [max-entries name]
               :or {max-entries 32
                    name "tail_call_chain"}}]
  (let [prog-array-fd (create-prog-array max-entries :name name)
        ;; Register all programs
        _ (doseq [{:keys [program index]} programs]
            (register-tail-call prog-array-fd index program))
        ;; Build index map
        prog-map (into {} (map (fn [{:keys [program index]}]
                                 [index program])
                               programs))
        ;; Find entry program (index 0)
        entry-prog (get prog-map 0)]
    (->TailCallChain prog-array-fd prog-map entry-prog)))

(defn close-tail-call-chain
  "Close a tail call chain and all its programs.

  Parameters:
  - chain: TailCallChain to close
  - :close-programs? - Whether to close the individual programs (default: true)"
  [^TailCallChain chain & {:keys [close-programs?] :or {close-programs? true}}]
  ;; Close all registered programs
  (when close-programs?
    (doseq [[_index prog] (:programs chain)]
      (close-program prog)))
  ;; Close the prog_array map
  (syscall/close-fd (:prog-array chain))
  (log/info "Closed tail call chain"))

(defn get-tail-call-program
  "Get the program at a specific index in a tail call chain.

  Returns the BpfProgram or nil if not found."
  [^TailCallChain chain index]
  (get (:programs chain) index))

(defn tail-call-chain-size
  "Get the number of programs registered in a tail call chain."
  [^TailCallChain chain]
  (count (:programs chain)))

(defmacro with-tail-call-chain
  "Create and manage a tail call chain with automatic cleanup.

  Example:
    (with-tail-call-chain [chain [{:program p1 :index 0}
                                   {:program p2 :index 1}]]
      ;; Use the chain
      (attach-xdp (:entry-program chain) \"eth0\")
      (Thread/sleep 10000))"
  [[binding programs & opts] & body]
  `(let [~binding (create-tail-call-chain ~programs ~@opts)]
     (try
       ~@body
       (finally
         (close-tail-call-chain ~binding)))))

;; ============================================================================
;; BPF_PROG_TEST_RUN Support
;; ============================================================================
;;
;; BPF_PROG_TEST_RUN allows testing BPF programs without attaching them
;; to real hooks. This is useful for:
;; - Unit testing BPF programs
;; - Validating packet processing logic
;; - CI/CD integration

(defn test-run-program
  "Run a BPF program in test mode with synthetic input.

  This uses the BPF_PROG_TEST_RUN command to execute a BPF program
  without attaching it to a real hook. Useful for testing XDP, TC,
  and other packet-processing programs.

  Parameters:
  - prog: BpfProgram to test (or program fd as integer)
  - opts: Map with:
    - :data-in - Input data (byte array, e.g., packet data)
    - :data-size-out - Size of output buffer (default: size of data-in or 256)
    - :ctx-in - Optional context data (program-type specific)
    - :ctx-size-out - Size of context output buffer (default: 0)
    - :repeat - Number of times to run (default: 1, for benchmarking)
    - :flags - Test run flags (default: 0)
    - :cpu - CPU to run on (default: 0)

  Returns a map with:
  - :retval - Return value from BPF program (e.g., XDP_PASS=2, XDP_DROP=1)
  - :data-out - Output data (modified packet)
  - :ctx-out - Output context (if ctx-size-out > 0)
  - :duration-ns - Execution time in nanoseconds (average if repeat > 1)
  - :data-size-out - Actual size of output data

  Example:
    ;; Test an XDP program with a synthetic packet
    (test-run-program xdp-prog
      {:data-in (build-test-packet :tcp {})
       :repeat 1000})
    ;; => {:retval 2 :data-out [...] :duration-ns 150}

  Supported program types:
  - XDP (xdp_md context)
  - Sched CLS/ACT (sk_buff context)
  - Socket filter
  - Raw tracepoint
  - Flow dissector

  Note: Requires kernel 4.12+ for basic support, 5.10+ for full features."
  [prog {:keys [data-in data-size-out ctx-in ctx-size-out repeat flags cpu]
         :or {data-size-out nil
              ctx-in nil
              ctx-size-out 0
              repeat 1
              flags 0
              cpu 0}
         :as opts}]
  (let [prog-fd (if (integer? prog)
                  prog
                  (:fd prog))]
    (when-not prog-fd
      (throw (ex-info "Invalid program: no file descriptor"
                      {:prog prog})))
    (syscall/prog-test-run prog-fd opts)))

(defn build-test-packet
  "Build a test packet for BPF program testing.

  Creates a minimal Ethernet/IP/TCP or UDP packet for testing
  XDP and TC programs.

  Parameters:
  - protocol: :tcp or :udp
  - opts: Map with:
    - :src-mac - Source MAC (default: \"00:00:00:00:00:01\")
    - :dst-mac - Destination MAC (default: \"00:00:00:00:00:02\")
    - :src-ip - Source IP (default: \"10.0.0.1\")
    - :dst-ip - Destination IP (default: \"10.0.0.2\")
    - :src-port - Source port (default: 12345)
    - :dst-port - Destination port (default: 80)
    - :payload - Optional payload bytes

  Returns a byte array containing the packet."
  [protocol {:keys [src-mac dst-mac src-ip dst-ip src-port dst-port payload]
             :or {src-mac "00:00:00:00:00:01"
                  dst-mac "00:00:00:00:00:02"
                  src-ip "10.0.0.1"
                  dst-ip "10.0.0.2"
                  src-port 12345
                  dst-port 80
                  payload nil}}]
  (let [;; Parse MAC addresses
        parse-mac (fn [mac-str]
                    (byte-array (map #(unchecked-byte (Integer/parseInt % 16))
                                     (str/split mac-str #":"))))
        ;; Parse IP address
        parse-ip (fn [ip-str]
                   (byte-array (map #(unchecked-byte (Integer/parseInt %))
                                    (str/split ip-str #"\."))))

        src-mac-bytes (parse-mac src-mac)
        dst-mac-bytes (parse-mac dst-mac)
        src-ip-bytes (parse-ip src-ip)
        dst-ip-bytes (parse-ip dst-ip)

        ;; Ethernet header (14 bytes)
        eth-header (byte-array 14)
        _ (System/arraycopy dst-mac-bytes 0 eth-header 0 6)
        _ (System/arraycopy src-mac-bytes 0 eth-header 6 6)
        _ (aset eth-header 12 (unchecked-byte 0x08))  ; EtherType: IPv4
        _ (aset eth-header 13 (unchecked-byte 0x00))

        ;; IP header (20 bytes, no options)
        ip-proto (case protocol :tcp 6 :udp 17 6)
        payload-len (if payload (count payload) 0)
        l4-len (case protocol :tcp 20 :udp 8)
        total-len (+ 20 l4-len payload-len)

        ip-header (byte-array 20)
        _ (aset ip-header 0 (unchecked-byte 0x45))   ; Version + IHL
        _ (aset ip-header 1 (unchecked-byte 0x00))   ; DSCP/ECN
        _ (aset ip-header 2 (unchecked-byte (bit-shift-right total-len 8)))  ; Total length
        _ (aset ip-header 3 (unchecked-byte (bit-and total-len 0xFF)))
        _ (aset ip-header 4 (unchecked-byte 0x00))   ; Identification
        _ (aset ip-header 5 (unchecked-byte 0x00))
        _ (aset ip-header 6 (unchecked-byte 0x40))   ; Flags (DF)
        _ (aset ip-header 7 (unchecked-byte 0x00))   ; Fragment offset
        _ (aset ip-header 8 (unchecked-byte 64))     ; TTL
        _ (aset ip-header 9 (unchecked-byte ip-proto)) ; Protocol
        ;; Skip checksum for now (bytes 10-11)
        _ (System/arraycopy src-ip-bytes 0 ip-header 12 4)
        _ (System/arraycopy dst-ip-bytes 0 ip-header 16 4)

        ;; L4 header
        l4-header (case protocol
                    :tcp (let [h (byte-array 20)]
                           (aset h 0 (unchecked-byte (bit-shift-right src-port 8)))
                           (aset h 1 (unchecked-byte (bit-and src-port 0xFF)))
                           (aset h 2 (unchecked-byte (bit-shift-right dst-port 8)))
                           (aset h 3 (unchecked-byte (bit-and dst-port 0xFF)))
                           (aset h 12 (unchecked-byte 0x50))  ; Data offset (5 words)
                           (aset h 13 (unchecked-byte 0x02))  ; SYN flag
                           h)
                    :udp (let [h (byte-array 8)]
                           (aset h 0 (unchecked-byte (bit-shift-right src-port 8)))
                           (aset h 1 (unchecked-byte (bit-and src-port 0xFF)))
                           (aset h 2 (unchecked-byte (bit-shift-right dst-port 8)))
                           (aset h 3 (unchecked-byte (bit-and dst-port 0xFF)))
                           (aset h 4 (unchecked-byte (bit-shift-right (+ 8 payload-len) 8)))
                           (aset h 5 (unchecked-byte (bit-and (+ 8 payload-len) 0xFF)))
                           h))

        ;; Combine all parts
        total-size (+ 14 20 (count l4-header) payload-len)
        packet (byte-array total-size)]

    (System/arraycopy eth-header 0 packet 0 14)
    (System/arraycopy ip-header 0 packet 14 20)
    (System/arraycopy l4-header 0 packet 34 (count l4-header))
    (when payload
      (System/arraycopy payload 0 packet (+ 34 (count l4-header)) payload-len))

    packet))

;; ============================================================================
;; SK_SKB and SK_MSG Program Attachment (for SOCKMAP/SOCKHASH)
;; ============================================================================

(defn- prog-attach-attr->segment
  "Create memory segment for bpf_attr union for BPF_PROG_ATTACH.

  Structure (from linux/bpf.h):
  struct {
    __u32 target_fd;      // map fd for SOCKMAP
    __u32 attach_bpf_fd;  // program fd
    __u32 attach_type;
    __u32 attach_flags;
    __u32 replace_bpf_fd; // for BPF_F_REPLACE
  }"
  [target-fd prog-fd attach-type-int attach-flags replace-fd]
  (let [attr (utils/pack-struct [[:u32 target-fd]
                                 [:u32 prog-fd]
                                 [:u32 attach-type-int]
                                 [:u32 attach-flags]
                                 [:u32 (or replace-fd 0)]])]
    (utils/bytes->segment attr)))

(defn- prog-detach-attr->segment
  "Create memory segment for bpf_attr union for BPF_PROG_DETACH.

  Structure:
  struct {
    __u32 target_fd;      // map fd
    __u32 attach_bpf_fd;  // program fd (0 to detach all)
    __u32 attach_type;
  }"
  [target-fd prog-fd attach-type-int]
  (let [attr (utils/pack-struct [[:u32 target-fd]
                                 [:u32 (or prog-fd 0)]
                                 [:u32 attach-type-int]])]
    (utils/bytes->segment attr)))

(defn attach-sk-skb
  "Attach SK_SKB program to a SOCKMAP or SOCKHASH.

   SK_SKB programs are used for socket stream redirection. Two types:
   - :stream-parser - Parses message boundaries (returns message length)
   - :stream-verdict - Decides what to do with the message (pass/drop/redirect)

   Parameters:
   - prog: BpfProgram to attach
   - map-fd: SOCKMAP or SOCKHASH file descriptor (or map record with :fd)
   - attach-type: :stream-parser or :stream-verdict

   Optional:
   - :flags - Attach flags (default 0)
   - :replace-fd - Program FD to replace

   Example:
     ;; Attach a stream parser
     (attach-sk-skb parser-prog (:fd sock-map) :stream-parser)

     ;; Attach a stream verdict program
     (attach-sk-skb verdict-prog (:fd sock-map) :stream-verdict)

   Returns the program with attachment info added."
  [prog map-fd attach-type & {:keys [flags replace-fd]
                              :or {flags 0 replace-fd nil}}]
  (let [prog-fd (:fd prog)
        map-fd-int (if (map? map-fd) (:fd map-fd) map-fd)
        attach-type-kw (case attach-type
                         :stream-parser :sk-skb-stream-parser
                         :stream-verdict :sk-skb-stream-verdict
                         :parser :sk-skb-stream-parser
                         :verdict :sk-skb-stream-verdict
                         attach-type)
        attach-type-int (const/attach-type->num attach-type-kw)
        attr-seg (prog-attach-attr->segment map-fd-int prog-fd attach-type-int flags replace-fd)
        result (syscall/bpf-syscall :prog-attach attr-seg)]
    (when (neg? result)
      (throw (ex-info "Failed to attach SK_SKB program to map"
                     {:prog-fd prog-fd
                      :map-fd map-fd-int
                      :attach-type attach-type
                      :errno (- result)
                      :error (syscall/errno->keyword (- result))})))
    ;; Add attachment to program
    (update prog :attachments conj
            (->ProgramAttachment
             :sk-skb
             {:map-fd map-fd-int :attach-type attach-type}
             (fn []
               (let [detach-attr (prog-detach-attr->segment map-fd-int prog-fd attach-type-int)
                     detach-result (syscall/bpf-syscall :prog-detach detach-attr)]
                 (when (neg? detach-result)
                   (throw (ex-info "Failed to detach SK_SKB program"
                                  {:prog-fd prog-fd
                                   :map-fd map-fd-int
                                   :errno (- detach-result)})))))))))

(defn attach-sk-msg
  "Attach SK_MSG program to a SOCKMAP or SOCKHASH.

   SK_MSG programs run on sendmsg()/sendfile() operations and can
   redirect messages between sockets.

   Parameters:
   - prog: BpfProgram to attach
   - map-fd: SOCKMAP or SOCKHASH file descriptor (or map record with :fd)

   Optional:
   - :flags - Attach flags (default 0)
   - :replace-fd - Program FD to replace

   Example:
     (attach-sk-msg msg-verdict-prog (:fd sock-map))

   Returns the program with attachment info added."
  [prog map-fd & {:keys [flags replace-fd]
                  :or {flags 0 replace-fd nil}}]
  (let [prog-fd (:fd prog)
        map-fd-int (if (map? map-fd) (:fd map-fd) map-fd)
        attach-type-int (const/attach-type->num :sk-msg-verdict)
        attr-seg (prog-attach-attr->segment map-fd-int prog-fd attach-type-int flags replace-fd)
        result (syscall/bpf-syscall :prog-attach attr-seg)]
    (when (neg? result)
      (throw (ex-info "Failed to attach SK_MSG program to map"
                     {:prog-fd prog-fd
                      :map-fd map-fd-int
                      :errno (- result)
                      :error (syscall/errno->keyword (- result))})))
    ;; Add attachment to program
    (update prog :attachments conj
            (->ProgramAttachment
             :sk-msg
             {:map-fd map-fd-int}
             (fn []
               (let [detach-attr (prog-detach-attr->segment map-fd-int prog-fd attach-type-int)
                     detach-result (syscall/bpf-syscall :prog-detach detach-attr)]
                 (when (neg? detach-result)
                   (throw (ex-info "Failed to detach SK_MSG program"
                                  {:prog-fd prog-fd
                                   :map-fd map-fd-int
                                   :errno (- detach-result)})))))))))

(defn detach-sk-skb
  "Detach SK_SKB program from a SOCKMAP or SOCKHASH.

   Parameters:
   - map-fd: SOCKMAP or SOCKHASH file descriptor
   - attach-type: :stream-parser or :stream-verdict
   - prog-fd: Optional program FD (nil to detach all)

   Returns 0 on success."
  [map-fd attach-type & {:keys [prog-fd]}]
  (let [map-fd-int (if (map? map-fd) (:fd map-fd) map-fd)
        attach-type-kw (case attach-type
                         :stream-parser :sk-skb-stream-parser
                         :stream-verdict :sk-skb-stream-verdict
                         :parser :sk-skb-stream-parser
                         :verdict :sk-skb-stream-verdict
                         attach-type)
        attach-type-int (const/attach-type->num attach-type-kw)
        attr-seg (prog-detach-attr->segment map-fd-int prog-fd attach-type-int)
        result (syscall/bpf-syscall :prog-detach attr-seg)]
    (when (neg? result)
      (throw (ex-info "Failed to detach SK_SKB program"
                     {:map-fd map-fd-int
                      :attach-type attach-type
                      :prog-fd prog-fd
                      :errno (- result)})))
    result))

(defn detach-sk-msg
  "Detach SK_MSG program from a SOCKMAP or SOCKHASH.

   Parameters:
   - map-fd: SOCKMAP or SOCKHASH file descriptor
   - prog-fd: Optional program FD (nil to detach all)

   Returns 0 on success."
  [map-fd & {:keys [prog-fd]}]
  (let [map-fd-int (if (map? map-fd) (:fd map-fd) map-fd)
        attach-type-int (const/attach-type->num :sk-msg-verdict)
        attr-seg (prog-detach-attr->segment map-fd-int prog-fd attach-type-int)
        result (syscall/bpf-syscall :prog-detach attr-seg)]
    (when (neg? result)
      (throw (ex-info "Failed to detach SK_MSG program"
                     {:map-fd map-fd-int
                      :prog-fd prog-fd
                      :errno (- result)})))
    result))
