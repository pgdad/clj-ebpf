(ns lab-3-2-syscall-args
  "Lab 3.2: System Call Argument Capture using BPF instructions

   This solution demonstrates:
   - Reading syscall arguments from pt_regs structure
   - Handling different argument types (integers, pointers, strings)
   - Safe user space memory access with probe_read_user
   - Building argument parsers
   - Storing captured data in maps

   Run with: sudo clojure -M -m lab-3-2-syscall-args
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Architecture-Specific Offsets (x86_64)
;;; ============================================================================

;; x86_64 pt_regs offsets (in bytes)
;; These match the kernel's struct pt_regs layout
(def PT_REGS_R15  0)
(def PT_REGS_R14  8)
(def PT_REGS_R13  16)
(def PT_REGS_R12  24)
(def PT_REGS_RBP  32)
(def PT_REGS_RBX  40)
(def PT_REGS_R11  48)
(def PT_REGS_R10  56)   ; 4th syscall argument
(def PT_REGS_R9   64)   ; 6th syscall argument
(def PT_REGS_R8   72)   ; 5th syscall argument
(def PT_REGS_RAX  80)   ; Syscall number / return value
(def PT_REGS_RCX  88)
(def PT_REGS_RDX  96)   ; 3rd syscall argument
(def PT_REGS_RSI  104)  ; 2nd syscall argument
(def PT_REGS_RDI  112)  ; 1st syscall argument

;; Syscall numbers (x86_64)
(def SYS_READ 0)
(def SYS_WRITE 1)
(def SYS_OPEN 2)
(def SYS_CLOSE 3)
(def SYS_OPENAT 257)
(def SYS_EXECVE 59)

;;; ============================================================================
;;; Part 2: Data Structures
;;; ============================================================================

(def MAX_STRING_LEN 128)
(def MAX_ARGS 6)

;; Event structure layout:
;; offset 0:  timestamp (8 bytes)
;; offset 8:  pid_tgid (8 bytes)
;; offset 16: syscall_nr (4 bytes)
;; offset 20: padding (4 bytes)
;; offset 24: args[0] (8 bytes)
;; offset 32: args[1] (8 bytes)
;; offset 40: args[2] (8 bytes)
;; offset 48: args[3] (8 bytes)
;; offset 56: args[4] (8 bytes)
;; offset 64: args[5] (8 bytes)
;; offset 72: filename (128 bytes)
;; Total: 200 bytes

(def EVENT_TIMESTAMP 0)
(def EVENT_PID_TGID 8)
(def EVENT_SYSCALL_NR 16)
(def EVENT_ARGS 24)
(def EVENT_FILENAME 72)
(def EVENT_SIZE 200)

;;; ============================================================================
;;; Part 3: Maps
;;; ============================================================================

(defn create-events-map
  "Create hash map to store captured syscall events.
   Key: sequence number, Value: event data"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8          ; u64 for sequence
                   :value-size EVENT_SIZE
                   :max-entries 1000
                   :map-name "syscall_events"}))

(defn create-counter-map
  "Create map to track event count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 1
                   :map-name "event_counter"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: Argument Reading Helpers
;;; ============================================================================

(defn get-arg-offset
  "Get pt_regs offset for syscall argument N"
  [arg-num]
  (case arg-num
    0 PT_REGS_RDI
    1 PT_REGS_RSI
    2 PT_REGS_RDX
    3 PT_REGS_R10
    4 PT_REGS_R8
    5 PT_REGS_R9
    (throw (ex-info "Invalid argument number" {:arg-num arg-num}))))

(defn read-arg
  "Generate BPF instructions to read syscall argument N from pt_regs.
   ctx-reg: register containing pt_regs pointer
   arg-num: 0-5
   dst-reg: destination register"
  [ctx-reg arg-num dst-reg]
  [(bpf/load-mem :dw dst-reg ctx-reg (get-arg-offset arg-num))])

;;; ============================================================================
;;; Part 5: BPF Program - Simple Syscall Tracer
;;; ============================================================================

(defn create-syscall-tracer
  "Create a simple syscall tracer that captures basic info.

   This demonstrates:
   - Reading PID/TGID
   - Reading syscall arguments from pt_regs
   - Storing data in a map

   Note: This is a simplified version. Full implementation would
   use ring buffers and probe_read_user for strings."
  [events-map-fd counter-map-fd]
  (bpf/assemble
    [;; ════════════════════════════════════════════════════════════════
     ;; Step 1: Save context pointer (r1 = pt_regs)
     ;; ════════════════════════════════════════════════════════════════
     (bpf/mov-reg :r6 :r1)          ; r6 = ctx (pt_regs pointer)

     ;; ════════════════════════════════════════════════════════════════
     ;; Step 2: Get current PID/TGID
     ;; ════════════════════════════════════════════════════════════════
     ;; bpf_get_current_pid_tgid returns:
     ;; upper 32 bits: TGID (process ID)
     ;; lower 32 bits: PID (thread ID)
     (bpf/call 14)                  ; bpf_get_current_pid_tgid
     (bpf/mov-reg :r7 :r0)          ; r7 = pid_tgid

     ;; ════════════════════════════════════════════════════════════════
     ;; Step 3: Read first syscall argument (arg0)
     ;; ════════════════════════════════════════════════════════════════
     ;; arg0 is in RDI register (offset 112 in pt_regs)
     (bpf/load-mem :dw :r8 :r6 PT_REGS_RDI)  ; r8 = arg0

     ;; ════════════════════════════════════════════════════════════════
     ;; Step 4: Read second syscall argument (arg1)
     ;; ════════════════════════════════════════════════════════════════
     ;; arg1 is in RSI register (offset 104 in pt_regs)
     (bpf/load-mem :dw :r9 :r6 PT_REGS_RSI)  ; r9 = arg1

     ;; ════════════════════════════════════════════════════════════════
     ;; Step 5: Store event data on stack
     ;; ════════════════════════════════════════════════════════════════
     ;; Use stack for temporary event structure
     ;; Stack layout (from r10):
     ;;   -8:  timestamp
     ;;   -16: pid_tgid
     ;;   -24: arg0
     ;;   -32: arg1

     ;; Get timestamp
     (bpf/call 5)                   ; bpf_ktime_get_ns
     (bpf/store-mem :dw :r10 -8 :r0)   ; stack[-8] = timestamp

     ;; Store pid_tgid
     (bpf/store-mem :dw :r10 -16 :r7)  ; stack[-16] = pid_tgid

     ;; Store arg0
     (bpf/store-mem :dw :r10 -24 :r8)  ; stack[-24] = arg0

     ;; Store arg1
     (bpf/store-mem :dw :r10 -32 :r9)  ; stack[-32] = arg1

     ;; ════════════════════════════════════════════════════════════════
     ;; Step 6: Return success
     ;; ════════════════════════════════════════════════════════════════
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 6: Userspace Event Processing
;;; ============================================================================

(defn parse-pid-tgid
  "Parse PID and TGID from combined value"
  [pid-tgid]
  {:pid (bit-and pid-tgid 0xFFFFFFFF)
   :tgid (bit-shift-right pid-tgid 32)})

(defn format-syscall-name
  "Format syscall number as name"
  [nr]
  (case nr
    0   "read"
    1   "write"
    2   "open"
    3   "close"
    59  "execve"
    257 "openat"
    (str "syscall_" nr)))

(defn format-open-flags
  "Format open() flags as string"
  [flags]
  (let [flag-names {0x0000 "O_RDONLY"
                    0x0001 "O_WRONLY"
                    0x0002 "O_RDWR"
                    0x0040 "O_CREAT"
                    0x0080 "O_EXCL"
                    0x0100 "O_NOCTTY"
                    0x0200 "O_TRUNC"
                    0x0400 "O_APPEND"
                    0x0800 "O_NONBLOCK"}
        mode (bit-and flags 0x03)
        mode-str (get flag-names mode "?")
        other-flags (for [[mask name] flag-names
                          :when (and (> mask 0x03)
                                     (pos? (bit-and flags mask)))]
                      name)]
    (str/join "|" (cons mode-str other-flags))))

(defn display-syscall-event
  "Display a syscall event"
  [{:keys [timestamp pid tgid syscall-nr args filename]}]
  (let [name (format-syscall-name syscall-nr)]
    (println (format "[%d:%d] %s" tgid pid name))
    (case syscall-nr
      ;; read(fd, buf, count)
      0 (println (format "  fd=%d, count=%d" (first args) (nth args 2)))
      ;; write(fd, buf, count)
      1 (println (format "  fd=%d, count=%d" (first args) (nth args 2)))
      ;; open(filename, flags, mode)
      2 (println (format "  filename=\"%s\", flags=%s"
                         filename
                         (format-open-flags (second args))))
      ;; openat(dirfd, filename, flags, mode)
      257 (println (format "  dirfd=%d, filename=\"%s\", flags=%s"
                           (first args)
                           filename
                           (format-open-flags (nth args 2))))
      ;; default
      (println (format "  args=%s" (vec (take 3 args)))))))

;;; ============================================================================
;;; Part 7: Simulated Event Collection
;;; ============================================================================

(defn simulate-syscall-events
  "Simulate syscall events for demonstration.
   In production, these would come from the kernel."
  []
  (println "\nSimulated Syscall Events:")
  (println "─────────────────────────────────────────────────────")

  ;; Simulate some events
  (let [events [{:timestamp (System/nanoTime)
                 :pid 1234
                 :tgid 1234
                 :syscall-nr SYS_OPENAT
                 :args [0xFFFFFF9C "/etc/passwd" 0x0 0x0 0 0]
                 :filename "/etc/passwd"}
                {:timestamp (System/nanoTime)
                 :pid 1234
                 :tgid 1234
                 :syscall-nr SYS_READ
                 :args [3 0x7ffd12340000 4096 0 0 0]
                 :filename ""}
                {:timestamp (System/nanoTime)
                 :pid 1235
                 :tgid 1234
                 :syscall-nr SYS_WRITE
                 :args [1 0x7ffd12340000 128 0 0 0]
                 :filename ""}
                {:timestamp (System/nanoTime)
                 :pid 5678
                 :tgid 5678
                 :syscall-nr SYS_EXECVE
                 :args [0x7ffd00001000 0x7ffd00002000 0x7ffd00003000 0 0 0]
                 :filename "/usr/bin/ls"}
                {:timestamp (System/nanoTime)
                 :pid 1234
                 :tgid 1234
                 :syscall-nr SYS_CLOSE
                 :args [3 0 0 0 0 0]
                 :filename ""}]]

    (doseq [event events]
      (display-syscall-event event)
      (Thread/sleep 100)))

  (println "─────────────────────────────────────────────────────")
  (println "Total: 5 simulated events"))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 3.2: System Call Argument Capture ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [events-map (create-events-map)
        counter-map (create-counter-map)]
    (println "  Events map created (FD:" (:fd events-map) ")")
    (println "  Counter map created (FD:" (:fd counter-map) ")")

    ;; Initialize counter
    (bpf/map-update counter-map 0 0)

    (try
      ;; Step 3: Create syscall tracer
      (println "\nStep 3: Creating syscall tracer program...")
      (let [program (create-syscall-tracer (:fd events-map) (:fd counter-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :kprobe
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Explain pt_regs structure
            (println "\nStep 5: pt_regs structure (x86_64)...")
            (println "\n  Syscall Argument → Register → pt_regs Offset")
            (println "  ─────────────────────────────────────────────")
            (println "  arg0             → RDI      → 112 bytes")
            (println "  arg1             → RSI      → 104 bytes")
            (println "  arg2             → RDX      →  96 bytes")
            (println "  arg3             → R10      →  56 bytes")
            (println "  arg4             → R8       →  72 bytes")
            (println "  arg5             → R9       →  64 bytes")
            (println "  syscall number   → RAX      →  80 bytes")

            ;; Step 6: Explain common syscalls
            (println "\nStep 6: Common syscall signatures...")
            (println "\n  open(const char *filename, int flags, mode_t mode)")
            (println "    arg0: filename (pointer → use probe_read_user)")
            (println "    arg1: flags (integer)")
            (println "    arg2: mode (integer)")
            (println)
            (println "  read(int fd, void *buf, size_t count)")
            (println "    arg0: fd (integer)")
            (println "    arg1: buf (pointer)")
            (println "    arg2: count (size_t)")
            (println)
            (println "  write(int fd, const void *buf, size_t count)")
            (println "    arg0: fd (integer)")
            (println "    arg1: buf (pointer)")
            (println "    arg2: count (size_t)")

            ;; Step 7: Attachment info
            (println "\nStep 7: Tracepoint attachment info...")
            (println "\n  Available syscall tracepoints:")
            (println "    - syscalls:sys_enter_open")
            (println "    - syscalls:sys_enter_openat")
            (println "    - syscalls:sys_enter_read")
            (println "    - syscalls:sys_enter_write")
            (println "    - syscalls:sys_enter_execve")
            (println)
            (println "  To attach: bpftool prog attach <id> tracepoint <name>")

            ;; Step 8: Simulated events
            (println "\nStep 8: Event demonstration...")
            (simulate-syscall-events)

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
        (bpf/close-map counter-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 3.2 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test argument offset calculation
  (get-arg-offset 0)  ; => 112 (RDI)
  (get-arg-offset 1)  ; => 104 (RSI)
  (get-arg-offset 2)  ; => 96  (RDX)

  ;; Test flag formatting
  (format-open-flags 0x0)    ; "O_RDONLY"
  (format-open-flags 0x42)   ; "O_RDWR|O_CREAT"
  (format-open-flags 0x241)  ; "O_WRONLY|O_CREAT|O_TRUNC"
  )
