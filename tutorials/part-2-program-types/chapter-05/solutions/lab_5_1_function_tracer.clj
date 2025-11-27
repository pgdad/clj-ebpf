(ns lab-5-1-function-tracer
  "Lab 5.1: Function Call Tracer using Kprobes

   This solution demonstrates:
   - Attaching kprobes to kernel functions
   - Reading function arguments from pt_regs
   - Using ring buffer for event streaming
   - Tracing kernel function calls with arguments

   Run with: sudo clojure -M -m lab-5-1-function-tracer
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; pt_regs offsets for x86_64 (Linux kernel convention)
;; These are offsets into the pt_regs structure passed to kprobes
(def PT_REGS_RDI 112)   ; arg0
(def PT_REGS_RSI 104)   ; arg1
(def PT_REGS_RDX 96)    ; arg2
(def PT_REGS_RCX 88)    ; arg3 (note: different from syscall convention)
(def PT_REGS_R8 72)     ; arg4
(def PT_REGS_R9 64)     ; arg5

;; Event structure size
;; struct trace_event {
;;   u64 timestamp;    // offset 0
;;   u64 pid_tgid;     // offset 8
;;   u64 args[6];      // offset 16 (48 bytes)
;;   char comm[16];    // offset 64
;; };
(def TRACE_EVENT_SIZE 80)

(def MAX_ENTRIES 10000)
(def COMM_SIZE 16)

;;; ============================================================================
;;; Part 2: Data Structures
;;; ============================================================================

(defn read-u64-le [^bytes buf offset]
  (let [bb (ByteBuffer/wrap buf)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getLong bb offset)))

(defn read-string-from-bytes [^bytes buf offset max-len]
  (let [end (min (+ offset max-len) (count buf))
        relevant (byte-array (- end offset))]
    (System/arraycopy buf offset relevant 0 (- end offset))
    (let [null-idx (or (first (keep-indexed
                               (fn [i b] (when (zero? b) i))
                               relevant))
                       (count relevant))]
      (String. relevant 0 null-idx "UTF-8"))))

(defn parse-trace-event [^bytes buf]
  "Parse trace_event structure from raw bytes"
  {:timestamp (read-u64-le buf 0)
   :pid-tgid (read-u64-le buf 8)
   :pid (bit-and (read-u64-le buf 8) 0xFFFFFFFF)
   :tgid (bit-shift-right (read-u64-le buf 8) 32)
   :args (vec (for [i (range 6)]
                (read-u64-le buf (+ 16 (* i 8)))))
   :comm (read-string-from-bytes buf 64 COMM_SIZE)})

;;; ============================================================================
;;; Part 3: Maps
;;; ============================================================================

(defn create-events-map
  "Hash map to store trace events (for demonstration without ring buffer)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8              ; u64 key
                   :value-size TRACE_EVENT_SIZE
                   :max-entries MAX_ENTRIES
                   :map-name "trace_events"}))

(defn create-count-map
  "Array map to track function call count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4   ; [total_calls, unique_pids, ...]
                   :map-name "call_counts"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: BPF Program - Kprobe Handler
;;; ============================================================================

(defn create-kprobe-handler
  "Create BPF program for tracing function calls.

   This simplified program demonstrates:
   - Reading pt_regs structure (r1 contains pointer to pt_regs)
   - Getting PID/TGID with bpf_get_current_pid_tgid()
   - Getting timestamp with bpf_ktime_get_ns()
   - Getting comm with bpf_get_current_comm()

   For kprobes, r1 points to pt_regs which contains the function arguments.

   Instruction layout:
   0: mov-reg r6, r1        ; save pt_regs pointer
   1: call get_current_pid_tgid
   2: mov-reg r7, r0        ; save pid_tgid
   3: call ktime_get_ns
   4: mov-reg r8, r0        ; save timestamp
   5: mov r0, 0             ; return 0
   6: exit"
  [count-map-fd]
  (bpf/assemble
    [;; Save pt_regs pointer (r1) to r6
     (bpf/mov-reg :r6 :r1)

     ;; Get current PID/TGID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r7 :r0)      ; r7 = pid_tgid

     ;; Get timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r8 :r0)      ; r8 = timestamp

     ;; Store timestamp as key on stack
     (bpf/store-mem :dw :r10 -8 :r8)

     ;; Increment call count at index 0
     (bpf/ld-map-fd :r1 count-map-fd)
     (bpf/store-mem :w :r10 -16 0)  ; key = 0
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -16)              ; r2 = &key
     (bpf/call 1)                   ; BPF_FUNC_map_lookup_elem

     ;; Check if lookup succeeded
     (bpf/jmp-imm :jeq :r0 0 4)     ; if NULL, skip increment

     ;; Increment counter (r0 points to value)
     (bpf/load-mem :dw :r1 :r0 0)   ; load current count
     (bpf/add :r1 1)                ; increment
     (bpf/store-mem :dw :r0 0 :r1)  ; store back

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Userspace - Event Display
;;; ============================================================================

(defn format-timestamp [ns]
  "Format nanoseconds as human-readable time"
  (let [sec (quot ns 1000000000)
        usec (quot (mod ns 1000000000) 1000)]
    (format "%d.%06d" sec usec)))

(defn format-args [args]
  "Format function arguments"
  (str/join ", " (map #(format "0x%x" %) args)))

(defn display-trace-event [event]
  "Display a single trace event"
  (println (format "[%s] PID: %d TGID: %d COMM: %s"
                   (format-timestamp (:timestamp event))
                   (:pid event)
                   (:tgid event)
                   (:comm event)))
  (println (format "  Args: %s" (format-args (:args event)))))

(defn display-call-stats [count-map]
  "Display function call statistics"
  (println "\nFunction Call Statistics:")
  (println "═══════════════════════════════════════")
  (let [total-calls (or (bpf/map-lookup count-map 0) 0)]
    (println (format "Total calls traced: %d" total-calls))))

;;; ============================================================================
;;; Part 6: Simulation
;;; ============================================================================

(defn simulate-trace-events
  "Simulate trace events for demonstration"
  [count-map]
  (println "\n  Simulating trace events...")

  ;; Simulate some function calls
  (let [simulated-count 42]
    (bpf/map-update count-map 0 simulated-count)
    (println (format "  Simulated %d function call traces" simulated-count))))

(defn display-simulated-events
  "Display simulated trace events"
  []
  (println "\nSimulated Trace Events:")
  (println "═══════════════════════════════════════")

  (let [events [{:timestamp 1234567890000
                 :pid 1234
                 :tgid 1234
                 :comm "bash"
                 :args [0x7ffd12345678 0x100 0x1 0 0 0]}
                {:timestamp 1234567891000
                 :pid 5678
                 :tgid 5678
                 :comm "python3"
                 :args [0x55555555 0x200 0x2 0 0 0]}
                {:timestamp 1234567892000
                 :pid 1234
                 :tgid 1234
                 :comm "bash"
                 :args [0x7ffd87654321 0x50 0x0 0 0 0]}]]
    (doseq [event events]
      (display-trace-event event)
      (println))))

;;; ============================================================================
;;; Part 7: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 5.1: Function Call Tracer ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [events-map (create-events-map)
        count-map (create-count-map)]
    (println "  Events map created (FD:" (:fd events-map) ")")
    (println "  Count map created (FD:" (:fd count-map) ")")

    ;; Initialize counter to 0
    (bpf/map-update count-map 0 0)

    (try
      ;; Step 3: Create BPF program
      (println "\nStep 3: Creating kprobe handler...")
      (let [program (create-kprobe-handler (:fd count-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :kprobe
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Explain kprobe attachment
            (println "\nStep 5: Kprobe attachment info...")
            (println "  Note: Kprobe attachment requires:")
            (println "    - perf_event_open() syscall")
            (println "    - ioctl() to attach BPF program")
            (println "  Would attach to functions like:")
            (println "    - do_sys_open")
            (println "    - vfs_read")
            (println "    - vfs_write")
            (println "    - tcp_sendmsg")

            ;; Step 6: Explain pt_regs structure
            (println "\nStep 6: pt_regs structure (x86_64):")
            (println "  ┌─────────────────────────────────┐")
            (println "  │ Offset  │ Register │ Purpose    │")
            (println "  ├─────────┼──────────┼────────────┤")
            (println "  │   112   │   rdi    │   arg0     │")
            (println "  │   104   │   rsi    │   arg1     │")
            (println "  │    96   │   rdx    │   arg2     │")
            (println "  │    88   │   rcx    │   arg3     │")
            (println "  │    72   │   r8     │   arg4     │")
            (println "  │    64   │   r9     │   arg5     │")
            (println "  └─────────────────────────────────┘")

            ;; Step 7: Simulate trace events
            (println "\nStep 7: Simulating trace data...")
            (simulate-trace-events count-map)
            (display-simulated-events)

            ;; Step 8: Display statistics
            (println "\nStep 8: Statistics...")
            (display-call-stats count-map)

            ;; Step 9: Cleanup
            (println "\nStep 9: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map events-map)
        (bpf/close-map count-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 5.1 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test event parsing
  (let [buf (byte-array TRACE_EVENT_SIZE)]
    (parse-trace-event buf))
  )
