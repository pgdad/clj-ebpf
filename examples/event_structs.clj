(ns event-structs
  "Event Structure DSL Examples

   This example demonstrates the clj-ebpf.dsl.structs namespace for defining
   event structures used in BPF programs. The defevent macro provides a
   convenient way to define C-like structures with automatic offset calculation.

   Key features demonstrated:
   - Basic event structure definition
   - Various field types (u8, u16, u32, u64, char arrays)
   - Querying structure metadata (size, offsets, types)
   - Generating BPF store instructions
   - Common event patterns for different use cases"
  (:require [clj-ebpf.dsl.structs :as structs]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.mem :as mem]))

;; ============================================================================
;; Basic Event Structure
;; ============================================================================

;; A simple event for process tracking
(structs/defevent BasicProcessEvent
  [:timestamp :u64]    ; 8 bytes at offset 0
  [:pid :u32]          ; 4 bytes at offset 8
  [:uid :u32]          ; 4 bytes at offset 12
  [:event_type :u8]    ; 1 byte at offset 16
  [:padding :u8 3])    ; 3 bytes padding for alignment (offset 17-19)
;; Total size: 20 bytes

;; ============================================================================
;; Network Event Structure
;; ============================================================================

;; Event for network connection tracking (TCP/UDP)
(structs/defevent NetworkConnectionEvent
  [:timestamp :u64]        ; When the event occurred
  [:pid :u32]              ; Process ID
  [:tgid :u32]             ; Thread group ID
  [:saddr :u32]            ; Source IPv4 address (network byte order)
  [:daddr :u32]            ; Destination IPv4 address
  [:sport :u16]            ; Source port
  [:dport :u16]            ; Destination port
  [:protocol :u8]          ; Protocol (6=TCP, 17=UDP)
  [:direction :u8]         ; 0=incoming, 1=outgoing
  [:family :u8]            ; Address family (AF_INET=2, AF_INET6=10)
  [:state :u8]             ; Connection state
  [:bytes_sent :u64]       ; Bytes sent (cumulative)
  [:bytes_recv :u64]       ; Bytes received (cumulative)
  [:comm :char 16])        ; Process command name
;; Total size: 64 bytes

;; ============================================================================
;; File System Event Structure
;; ============================================================================

;; Event for file system operations (open, read, write, close)
(structs/defevent FileSystemEvent
  [:timestamp :u64]
  [:pid :u32]
  [:uid :u32]
  [:operation :u32]       ; 0=open, 1=read, 2=write, 3=close, 4=unlink
  [:flags :u32]           ; Open flags or operation-specific flags
  [:mode :u32]            ; File mode
  [:ret_code :i32]        ; Return code (negative = error)
  [:inode :u64]           ; Inode number
  [:dev :u64]             ; Device ID
  [:size :u64]            ; File size or bytes transferred
  [:filename :char 64])   ; Filename (truncated if longer)
;; Total size: 120 bytes

;; ============================================================================
;; Security Audit Event Structure
;; ============================================================================

;; Event for security-sensitive operations
(structs/defevent SecurityAuditEvent
  [:timestamp :u64]
  [:pid :u32]
  [:tgid :u32]
  [:uid :u32]
  [:gid :u32]
  [:euid :u32]            ; Effective UID
  [:egid :u32]            ; Effective GID
  [:syscall_nr :u32]      ; System call number
  [:ret_code :i32]        ; Return code
  [:audit_type :u16]      ; Audit event type
  [:severity :u8]         ; 0=info, 1=warning, 2=alert, 3=critical
  [:padding :u8]
  [:arg0 :u64]            ; Syscall argument 0
  [:arg1 :u64]            ; Syscall argument 1
  [:arg2 :u64]            ; Syscall argument 2
  [:comm :char 16]        ; Command name
  [:parent_comm :char 16]); Parent process command name
;; Total size: 112 bytes

;; ============================================================================
;; Syscall Latency Event Structure
;; ============================================================================

;; Event for measuring syscall latency
(structs/defevent SyscallLatencyEvent
  [:start_ns :u64]        ; Start timestamp (nanoseconds)
  [:end_ns :u64]          ; End timestamp (nanoseconds)
  [:latency_ns :u64]      ; Calculated latency
  [:pid :u32]
  [:tgid :u32]
  [:syscall_nr :u32]      ; System call number
  [:ret_code :i32]        ; Return code
  [:cpu :u32]             ; CPU ID where syscall executed
  [:padding :u32])
;; Total size: 48 bytes

;; ============================================================================
;; Querying Structure Information
;; ============================================================================

(defn print-structure-info
  "Print detailed information about an event structure."
  [event-def]
  (println "Structure:" (:name event-def))
  (println "Total size:" (structs/event-size event-def) "bytes")
  (println "Fields:")
  (doseq [field (:fields event-def)]
    (printf "  %-20s type=%-5s size=%2d offset=%3d\n"
            (name (:name field))
            (name (:type field))
            (:size field)
            (:offset field)))
  (println))

(defn demo-structure-queries
  "Demonstrate structure query functions."
  []
  (println "=== Structure Query Examples ===\n")

  ;; Basic queries
  (println "NetworkConnectionEvent:")
  (println "  Total size:" (structs/event-size NetworkConnectionEvent) "bytes")
  (println "  Field count:" (count (structs/event-fields NetworkConnectionEvent)))
  (println)

  ;; Field-specific queries
  (println "Field offsets:")
  (println "  timestamp:" (structs/event-field-offset NetworkConnectionEvent :timestamp))
  (println "  saddr:" (structs/event-field-offset NetworkConnectionEvent :saddr))
  (println "  daddr:" (structs/event-field-offset NetworkConnectionEvent :daddr))
  (println "  sport:" (structs/event-field-offset NetworkConnectionEvent :sport))
  (println "  dport:" (structs/event-field-offset NetworkConnectionEvent :dport))
  (println "  comm:" (structs/event-field-offset NetworkConnectionEvent :comm))
  (println)

  ;; Field sizes
  (println "Field sizes:")
  (println "  timestamp:" (structs/event-field-size NetworkConnectionEvent :timestamp) "bytes")
  (println "  sport:" (structs/event-field-size NetworkConnectionEvent :sport) "bytes")
  (println "  comm:" (structs/event-field-size NetworkConnectionEvent :comm) "bytes")
  (println)

  ;; Field types
  (println "Field types:")
  (println "  timestamp:" (structs/event-field-type NetworkConnectionEvent :timestamp))
  (println "  sport:" (structs/event-field-type NetworkConnectionEvent :sport))
  (println "  comm:" (structs/event-field-type NetworkConnectionEvent :comm))
  (println))

;; ============================================================================
;; Generating BPF Instructions
;; ============================================================================

(defn demo-store-instructions
  "Demonstrate generating store instructions for event fields."
  []
  (println "=== BPF Store Instruction Examples ===\n")

  ;; Single field store from register
  (println "Store PID from r7 to event at r6:")
  (let [insn (structs/store-event-field :r6 NetworkConnectionEvent :pid :r7)]
    (println "  Instruction:" insn)
    (println "  Offset:" (:offset insn))
    (println))

  ;; Store immediate value
  (println "Store protocol=6 (TCP) as immediate:")
  (let [insn (structs/store-event-imm :r6 NetworkConnectionEvent :protocol 6)]
    (println "  Instruction:" insn)
    (println "  Immediate value:" (:imm insn))
    (println))

  ;; Zero a field
  (println "Zero the padding field:")
  (let [insn (structs/zero-event-field :r6 NetworkConnectionEvent :state)]
    (println "  Instruction:" insn)
    (println))

  ;; Batch store multiple fields
  (println "Store multiple fields at once:")
  (let [insns (structs/store-event-fields :r6 NetworkConnectionEvent
                {:timestamp {:reg :r8}
                 :pid {:reg :r7}
                 :protocol {:imm 6}
                 :direction {:imm 1}})]
    (println "  Generated" (count insns) "instructions:")
    (doseq [insn insns]
      (println "   " insn)))
  (println))

;; ============================================================================
;; Complete BPF Program Pattern
;; ============================================================================

(defn build-network-event-program
  "Build a BPF program that populates a NetworkConnectionEvent.

   This demonstrates the typical pattern for filling an event structure
   in a BPF program and submitting it to a ring buffer.

   Parameters:
   - ringbuf-fd: File descriptor of the ring buffer map"
  [ringbuf-fd]
  (let [event-size (structs/event-size NetworkConnectionEvent)]
    (dsl/assemble
     (vec (concat
           ;; Reserve ring buffer space
           ;; After this, r6 contains pointer to event or NULL
           (dsl/ringbuf-reserve :r6 ringbuf-fd event-size)

           ;; Check if reservation succeeded
           [(dsl/jmp-imm :jeq :r6 0 20)]  ; Skip to exit if NULL

           ;; Get and store timestamp
           (dsl/helper-ktime-get-ns)
           [(structs/store-event-field :r6 NetworkConnectionEvent :timestamp :r0)]

           ;; Get and store PID/TGID
           (dsl/helper-get-current-pid-tgid)
           [(dsl/mov-reg :r7 :r0)         ; Save full value
            (dsl/and-imm :r7 0xffffffff)  ; Extract PID
            (structs/store-event-field :r6 NetworkConnectionEvent :pid :r7)
            (dsl/rsh :r0 32)              ; Extract TGID
            (structs/store-event-field :r6 NetworkConnectionEvent :tgid :r0)]

           ;; Store constant fields
           [(structs/store-event-imm :r6 NetworkConnectionEvent :protocol 6)   ; TCP
            (structs/store-event-imm :r6 NetworkConnectionEvent :direction 1)  ; Outgoing
            (structs/store-event-imm :r6 NetworkConnectionEvent :family 2)]    ; AF_INET

           ;; Initialize counters to zero
           [(structs/store-event-imm :r6 NetworkConnectionEvent :bytes_sent 0)
            (structs/store-event-imm :r6 NetworkConnectionEvent :bytes_recv 0)]

           ;; Submit event to ring buffer
           (dsl/ringbuf-submit :r6)

           ;; Exit with success
           [(dsl/mov :r0 0)
            (dsl/exit-insn)])))))

;; ============================================================================
;; Alignment and Padding Helpers
;; ============================================================================

(defn calculate-padding
  "Calculate padding needed to align a field to a specific boundary.

   Parameters:
   - current-offset: Current byte offset
   - alignment: Required alignment (typically 1, 2, 4, or 8)"
  [current-offset alignment]
  (let [remainder (mod current-offset alignment)]
    (if (zero? remainder)
      0
      (- alignment remainder))))

(defn suggest-padding
  "Analyze an event structure and suggest padding for natural alignment."
  [event-def]
  (println "Alignment analysis for" (:name event-def) ":")
  (doseq [field (:fields event-def)]
    (let [offset (:offset field)
          size (:size field)
          natural-align (min size 8)  ; Natural alignment is min of size and 8
          misalign (mod offset natural-align)]
      (when (pos? misalign)
        (printf "  WARNING: %s at offset %d is misaligned (needs %d-byte alignment)\n"
                (name (:name field)) offset natural-align))))
  (println))

;; ============================================================================
;; Main Demo
;; ============================================================================

(defn run-demo
  "Run all demonstrations."
  []
  (println "Event Structure DSL Examples")
  (println "============================\n")

  ;; Print all structure definitions
  (println "=== Structure Definitions ===\n")
  (print-structure-info BasicProcessEvent)
  (print-structure-info NetworkConnectionEvent)
  (print-structure-info FileSystemEvent)
  (print-structure-info SecurityAuditEvent)
  (print-structure-info SyscallLatencyEvent)

  ;; Demo queries
  (demo-structure-queries)

  ;; Demo store instructions
  (demo-store-instructions)

  ;; Check alignment
  (println "=== Alignment Analysis ===\n")
  (suggest-padding NetworkConnectionEvent)
  (suggest-padding FileSystemEvent)

  (println "Done!"))

(defn -main
  [& args]
  (run-demo))

;; ============================================================================
;; REPL Examples
;; ============================================================================

(comment
  ;; Run the full demo
  (run-demo)

  ;; Define a custom event
  (structs/defevent MyCustomEvent
    [:ts :u64]
    [:id :u32]
    [:value :u32])

  ;; Query it
  (structs/event-size MyCustomEvent)
  ;; => 16

  (structs/event-field-offset MyCustomEvent :value)
  ;; => 12

  ;; Generate a store instruction
  (structs/store-event-field :r6 MyCustomEvent :value :r7)

  ;; Build a complete program
  (build-network-event-program 5)
  )
