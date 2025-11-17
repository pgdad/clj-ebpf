(ns clj-ebpf.programs
  "BPF program loading and attachment"
  (:require [clj-ebpf.syscall :as syscall]
            [clj-ebpf.constants :as const]
            [clj-ebpf.utils :as utils]
            [clojure.tools.logging :as log]
            [clojure.string :as str]
            [clojure.java.io :as io])
  (:import [com.sun.jna Pointer Memory]))

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
  - :prog-type - Program type (:kprobe, :tracepoint, :xdp, etc.)
  - :insns - BPF instructions as byte array or pointer
  - :insn-count - Number of instructions (auto-calculated if insns is byte array)
  - :license - License string (e.g., 'GPL')
  - :prog-name - Optional program name
  - :log-level - Verifier log level (0=off, 1=basic, 2=verbose)
  - :kern-version - Kernel version (default: current kernel)
  - :expected-attach-type - Expected attach type for certain prog types"
  [{:keys [prog-type insns insn-count license prog-name log-level kern-version
           prog-flags expected-attach-type prog-btf-fd]
    :or {log-level 1
         license "GPL"
         kern-version (utils/get-kernel-version)
         prog-flags 0}}]
  (let [;; Convert insns to pointer if needed
        insns-ptr (if (instance? Pointer insns)
                   insns
                   (utils/bytes->pointer insns))
        ;; Calculate instruction count (each BPF insn is 8 bytes)
        insn-cnt (or insn-count
                    (if (instance? Pointer insns)
                      (throw (ex-info "Must provide :insn-count when :insns is a Pointer"
                                     {:insns insns}))
                      (/ (count insns) 8)))
        ;; Allocate log buffer
        log-buf (Memory. const/BPF_LOG_BUF_SIZE)
        _ (.clear log-buf)

        ;; Load the program
        fd (try
             (syscall/prog-load
               {:prog-type prog-type
                :insn-cnt insn-cnt
                :insns insns-ptr
                :license license
                :log-level log-level
                :log-size const/BPF_LOG_BUF_SIZE
                :log-buf log-buf
                :kern-version kern-version
                :prog-flags prog-flags
                :prog-name prog-name
                :expected-attach-type (when expected-attach-type
                                       (const/attach-type->num expected-attach-type))
                :prog-btf-fd prog-btf-fd})
             (catch clojure.lang.ExceptionInfo e
               ;; Extract verifier log
               (let [log-str (.getString log-buf 0 "UTF-8")]
                 (log/error "BPF program load failed. Verifier log:\n" log-str)
                 (throw (ex-info "BPF program load failed"
                                (assoc (ex-data e) :verifier-log log-str))))))

        ;; Get verifier log even on success
        log-str (.getString log-buf 0 "UTF-8")
        log-str (when (and log-str (not (str/blank? log-str)))
                  (str/trim log-str))]

    (when (and log-str (> log-level 0))
      (log/debug "Verifier log for" prog-name ":\n" log-str))

    (log/info "Loaded BPF program:" prog-name "type:" prog-type "fd:" fd)
    (->BpfProgram fd prog-type prog-name insn-cnt license log-str [])))

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

(defn- write-kprobe-event
  "Write kprobe event to tracefs"
  [event-name function-name is-retprobe?]
  (let [tracefs-path "/sys/kernel/debug/tracing"
        kprobe-events-path (str tracefs-path "/kprobe_events")
        event-def (str (if is-retprobe? "r:" "p:")
                      event-name " " function-name "\n")]
    (try
      (spit kprobe-events-path event-def :append true)
      (log/debug "Created kprobe event:" event-def)
      (catch Exception e
        (throw (ex-info "Failed to create kprobe event"
                       {:event-name event-name
                        :function-name function-name
                        :is-retprobe is-retprobe?
                        :cause e}))))))

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
  "Attach BPF program to a kprobe

  Options:
  - :function - Kernel function name to probe
  - :retprobe? - If true, attach to function return (default: false)
  - :pid - PID to attach to (default: -1 for all processes)
  - :cpu - CPU to attach to (default: -1 for all CPUs)"
  [^BpfProgram prog {:keys [function retprobe? pid cpu]
                     :or {retprobe? false pid -1 cpu -1}}]
  (let [event-name (str "clj_ebpf_" (name (gensym "kprobe_")))
        _ (write-kprobe-event event-name function retprobe?)
        tracepoint-id (get-tracepoint-id "kprobes" event-name)

        ;; Open perf event
        event-fd (syscall/perf-event-open
                   (const/perf-type :tracepoint)
                   tracepoint-id
                   pid
                   cpu
                   -1  ; group_fd
                   0)  ; flags

        ;; Attach BPF program to perf event
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

;; Tracepoint attachment

(defn attach-tracepoint
  "Attach BPF program to a tracepoint

  Options:
  - :category - Tracepoint category (e.g., 'syscalls')
  - :name - Tracepoint name (e.g., 'sys_enter_execve')
  - :pid - PID to attach to (default: -1 for all processes)
  - :cpu - CPU to attach to (default: -1 for all CPUs)"
  [^BpfProgram prog {:keys [category name pid cpu]
                     :or {pid -1 cpu -1}}]
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
