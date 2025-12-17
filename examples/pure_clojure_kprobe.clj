(ns pure-clojure-kprobe
  "Pure Clojure Kprobe Example - Building BPF Programs Without External Compilers

   This example demonstrates the new kprobe DSL features that allow building
   complete BPF kprobe programs entirely in Clojure, without needing LLVM,
   clang, or any external compilation tools.

   Key features demonstrated:
   - Using defevent to define event structures
   - Using kprobe-prologue for automatic argument extraction
   - Using ring buffer DSL for efficient event output
   - Building complete kprobe and kretprobe programs

   Requirements:
   - Linux with BPF support
   - Root privileges or CAP_BPF capability"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.kprobe :as kprobe]
            [clj-ebpf.dsl.structs :as structs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.events :as events]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Event Structure Definition
;; ============================================================================

;; Define the event structure that will be sent to userspace.
;; The defevent macro automatically calculates field offsets and sizes.

(structs/defevent ProcessExecEvent
  [:timestamp :u64]      ; Kernel timestamp (nanoseconds)
  [:pid :u32]            ; Process ID
  [:tgid :u32]           ; Thread Group ID (parent process)
  [:uid :u32]            ; User ID
  [:gid :u32]            ; Group ID
  [:comm :char 16]       ; Process command name (16 bytes, null-terminated)
  [:filename_len :u32]   ; Length of filename
  [:ret_code :i32])      ; Return code (for kretprobe)

;; Query the structure - useful for debugging
(def event-size-bytes (structs/event-size ProcessExecEvent))
(def event-fields-list (structs/event-fields ProcessExecEvent))

;; ============================================================================
;; Kprobe Program: Trace execve Entry
;; ============================================================================

(defn build-execve-entry-probe
  "Build a kprobe program that traces execve system call entry.

   This program:
   1. Reads the filename argument from pt_regs
   2. Gets the current PID/TGID and UID/GID
   3. Reserves space in the ring buffer
   4. Fills in the event structure
   5. Submits the event to userspace

   Parameters:
   - ringbuf-fd: File descriptor of the ring buffer map"
  [ringbuf-fd]
  (dsl/assemble
   (vec (concat
         ;; === Prologue: Save context and read arguments ===
         ;; kprobe-prologue reads pt_regs and extracts function arguments
         ;; For execve: arg0 = filename pointer (char*)
         ;;             arg1 = argv
         ;;             arg2 = envp
         ;; We only need filename (arg0), save it in r7
         (kprobe/kprobe-prologue :r9 [:r7])

         ;; === Get timestamp ===
         (dsl/helper-ktime-get-ns)
         [(dsl/mov-reg :r8 :r0)]  ; Save timestamp in r8

         ;; === Get PID/TGID ===
         (dsl/helper-get-current-pid-tgid)
         ;; r0 = (tgid << 32) | pid
         ;; Save full value, we'll extract parts later
         [(dsl/stx :dw :r10 :r0 -8)]  ; Store on stack temporarily

         ;; === Get UID/GID ===
         (dsl/helper-get-current-uid-gid)
         ;; r0 = (gid << 32) | uid
         [(dsl/stx :dw :r10 :r0 -16)]  ; Store on stack

         ;; === Reserve ring buffer space ===
         (dsl/ringbuf-reserve :r6 ringbuf-fd event-size-bytes)

         ;; Check if reservation succeeded (r6 != 0)
         [(dsl/jmp-imm :jeq :r6 0 18)]  ; Jump to exit if NULL

         ;; === Fill event structure ===

         ;; Store timestamp (r8)
         [(structs/store-event-field :r6 ProcessExecEvent :timestamp :r8)]

         ;; Load and store PID (lower 32 bits of pid_tgid)
         [(dsl/ldx :dw :r1 :r10 -8)     ; Load pid_tgid from stack
          (dsl/mov-reg :r2 :r1)          ; Copy to r2
          (dsl/and-imm :r2 0xffffffff)   ; Mask lower 32 bits (PID)
          (structs/store-event-field :r6 ProcessExecEvent :pid :r2)]

         ;; Store TGID (upper 32 bits)
         [(dsl/rsh :r1 32)               ; Shift right to get TGID
          (structs/store-event-field :r6 ProcessExecEvent :tgid :r1)]

         ;; Load and store UID (lower 32 bits of uid_gid)
         [(dsl/ldx :dw :r1 :r10 -16)    ; Load uid_gid from stack
          (dsl/mov-reg :r2 :r1)          ; Copy to r2
          (dsl/and-imm :r2 0xffffffff)   ; Mask lower 32 bits (UID)
          (structs/store-event-field :r6 ProcessExecEvent :uid :r2)]

         ;; Store GID (upper 32 bits)
         [(dsl/rsh :r1 32)               ; Shift right to get GID
          (structs/store-event-field :r6 ProcessExecEvent :gid :r1)]

         ;; Store return code as 0 (entry probe)
         [(structs/store-event-imm :r6 ProcessExecEvent :ret_code 0)]

         ;; === Submit event to ring buffer ===
         (dsl/ringbuf-submit :r6)

         ;; === Exit ===
         [(dsl/mov :r0 0)
          (dsl/exit-insn)]))))

;; ============================================================================
;; Kretprobe Program: Trace execve Return
;; ============================================================================

(defn build-execve-return-probe
  "Build a kretprobe program that traces execve return.

   This captures the return value of execve, which indicates
   success (0) or failure (negative errno).

   Parameters:
   - ringbuf-fd: File descriptor of the ring buffer map"
  [ringbuf-fd]
  (dsl/assemble
   (vec (concat
         ;; === Get return value ===
         ;; In kretprobe, we use kretprobe-get-return-value
         [(kprobe/kretprobe-get-return-value :r1 :r7)]  ; Return value in r7

         ;; === Get timestamp ===
         (dsl/helper-ktime-get-ns)
         [(dsl/mov-reg :r8 :r0)]

         ;; === Get PID/TGID ===
         (dsl/helper-get-current-pid-tgid)
         [(dsl/stx :dw :r10 :r0 -8)]

         ;; === Get UID/GID ===
         (dsl/helper-get-current-uid-gid)
         [(dsl/stx :dw :r10 :r0 -16)]

         ;; === Reserve ring buffer space ===
         (dsl/ringbuf-reserve :r6 ringbuf-fd event-size-bytes)
         [(dsl/jmp-imm :jeq :r6 0 15)]  ; Jump to exit if NULL

         ;; === Fill event structure ===
         [(structs/store-event-field :r6 ProcessExecEvent :timestamp :r8)]

         ;; Store PID/TGID
         [(dsl/ldx :dw :r1 :r10 -8)
          (dsl/mov-reg :r2 :r1)
          (dsl/and-imm :r2 0xffffffff)
          (structs/store-event-field :r6 ProcessExecEvent :pid :r2)
          (dsl/rsh :r1 32)
          (structs/store-event-field :r6 ProcessExecEvent :tgid :r1)]

         ;; Store UID/GID
         [(dsl/ldx :dw :r1 :r10 -16)
          (dsl/mov-reg :r2 :r1)
          (dsl/and-imm :r2 0xffffffff)
          (structs/store-event-field :r6 ProcessExecEvent :uid :r2)
          (dsl/rsh :r1 32)
          (structs/store-event-field :r6 ProcessExecEvent :gid :r1)]

         ;; Store return code (r7 contains return value)
         [(structs/store-event-field :r6 ProcessExecEvent :ret_code :r7)]

         ;; === Submit event ===
         (dsl/ringbuf-submit :r6)

         ;; === Exit ===
         [(dsl/mov :r0 0)
          (dsl/exit-insn)]))))

;; ============================================================================
;; Using defkprobe-instructions Macro
;; ============================================================================

;; Alternative: Use the defkprobe-instructions macro for cleaner code
(kprobe/defkprobe-instructions simple-exec-trace
  {:function "do_execveat_common"
   :args [:r7]}  ; First arg (filename) in r7
  ;; Body: just get PID and return 0
  (concat
   (dsl/helper-get-current-pid-tgid)
   [(dsl/mov :r0 0)
    (dsl/exit-insn)]))

;; ============================================================================
;; Event Processing
;; ============================================================================

(defn parse-event
  "Parse a raw event from the ring buffer into a Clojure map.

   Parameters:
   - data: Byte array containing event data"
  [data]
  (when (>= (count data) event-size-bytes)
    {:timestamp (utils/bytes->long (byte-array (take 8 data)))
     :pid (utils/bytes->int (byte-array (take 4 (drop 8 data))))
     :tgid (utils/bytes->int (byte-array (take 4 (drop 12 data))))
     :uid (utils/bytes->int (byte-array (take 4 (drop 16 data))))
     :gid (utils/bytes->int (byte-array (take 4 (drop 20 data))))
     :comm (String. (byte-array (take 16 (drop 24 data))) "UTF-8")
     :filename-len (utils/bytes->int (byte-array (take 4 (drop 40 data))))
     :ret-code (utils/bytes->int (byte-array (take 4 (drop 44 data))))}))

(defn format-event
  "Format an event for display."
  [event]
  (format "[%d] pid=%d tgid=%d uid=%d gid=%d ret=%d comm=%s"
          (:timestamp event)
          (:pid event)
          (:tgid event)
          (:uid event)
          (:gid event)
          (:ret-code event)
          (clojure.string/trim (:comm event ""))))

;; ============================================================================
;; Main Runner
;; ============================================================================

(defn run-execve-tracer
  "Run the execve tracer.

   This demonstrates the complete workflow:
   1. Create ring buffer map
   2. Build kprobe program using DSL
   3. Load and attach program
   4. Read events from ring buffer
   5. Clean up on exit"
  []
  (println "Pure Clojure Kprobe Example")
  (println "===========================")
  (println)
  (println "This example traces execve calls using BPF programs")
  (println "built entirely in Clojure using the kprobe DSL.")
  (println)
  (println "Event structure size:" event-size-bytes "bytes")
  (println "Event fields:" event-fields-list)
  (println "Architecture:" arch/arch-name)
  (println)

  (try
    ;; Check BPF availability
    (println "Checking BPF availability...")
    (bpf/check-bpf-available)
    (println "BPF is available!")
    (println)

    ;; Create ring buffer map
    (println "Creating ring buffer map...")
    (let [ringbuf (maps/create-ringbuf-map (* 256 1024)  ; 256KB
                                           :map-name "exec_events")]
      (println "Ring buffer created, fd:" (:fd ringbuf))

      ;; Build the kprobe program
      (println "Building kprobe program with DSL...")
      (let [prog-bytes (build-execve-entry-probe (:fd ringbuf))]
        (println "Program bytecode size:" (count prog-bytes) "bytes")
        (println "Instruction count:" (/ (count prog-bytes) 8))

        ;; Load the program
        (println "Loading BPF program...")
        (bpf/with-program [prog {:prog-type :kprobe
                                 :insns prog-bytes
                                 :license "GPL"
                                 :prog-name "exec_entry"}]
          (println "Program loaded! FD:" (:fd prog))

          ;; Attach to do_execveat_common or sys_execve
          (println "Attaching kprobe...")
          (let [attached (programs/attach-kprobe prog
                           {:function "do_execveat_common"})]
            (println "Kprobe attached successfully!")
            (println)
            (println "Tracing execve calls. Press Ctrl+C to exit...")
            (println "Try running some commands in another terminal.")
            (println)

            ;; Poll for events
            (loop [count 0]
              (when (< count 100)  ; Limit events for demo
                (when-let [event-data (events/poll-ringbuf ringbuf 1000)]
                  (when-let [event (parse-event event-data)]
                    (println (format-event event))))
                (recur (inc count))))

            (println)
            (println "Detaching and cleaning up...")))))

      ;; Clean up map
      (maps/close-map ringbuf))

    (println "Done!")

    (catch Exception e
      (println "Error:" (.getMessage e))
      (when-let [data (ex-data e)]
        (println "Details:" data)
        (when-let [log (:verifier-log data)]
          (println)
          (println "Verifier log:")
          (println log))))))

(defn -main
  [& args]
  (run-execve-tracer))

;; ============================================================================
;; REPL Usage Examples
;; ============================================================================

(comment
  ;; Check event structure
  (structs/event-size ProcessExecEvent)
  ;; => 48

  (structs/event-field-offset ProcessExecEvent :pid)
  ;; => 8

  (structs/event-fields ProcessExecEvent)
  ;; => [:timestamp :pid :tgid :uid :gid :comm :filename_len :ret_code]

  ;; Generate a store instruction
  (structs/store-event-field :r6 ProcessExecEvent :pid :r7)
  ;; => #Instruction{:opcode ... :dst 6 :src 7 :offset 8 ...}

  ;; Build kprobe prologue
  (kprobe/kprobe-prologue [:r6 :r7])
  ;; => vector of instructions to read args 0 and 1

  ;; Assemble a simple program
  (dsl/assemble
   [(dsl/mov :r0 42)
    (dsl/exit-insn)])
  ;; => byte-array of BPF bytecode

  ;; Run the tracer (requires root)
  (run-execve-tracer)
  )
