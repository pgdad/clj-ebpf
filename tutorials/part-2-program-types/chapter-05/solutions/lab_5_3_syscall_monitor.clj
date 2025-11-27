(ns lab-5-3-syscall-monitor
  "Lab 5.3: System Call Monitor using Kprobes

   This solution demonstrates:
   - Monitoring system calls with kprobes
   - Detecting security-sensitive operations
   - Tracking syscall success/failure rates
   - Building a comprehensive syscall monitor
   - Security alerting for privilege escalation

   Run with: sudo clojure -M -m lab-5-3-syscall-monitor
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Constants and Syscall Numbers
;;; ============================================================================

;; Common x86_64 syscall numbers
(def SYSCALL_READ 0)
(def SYSCALL_WRITE 1)
(def SYSCALL_OPEN 2)
(def SYSCALL_CLOSE 3)
(def SYSCALL_STAT 4)
(def SYSCALL_FSTAT 5)
(def SYSCALL_POLL 7)
(def SYSCALL_MMAP 9)
(def SYSCALL_MPROTECT 10)
(def SYSCALL_MUNMAP 11)
(def SYSCALL_SOCKET 41)
(def SYSCALL_CONNECT 42)
(def SYSCALL_ACCEPT 43)
(def SYSCALL_SENDTO 44)
(def SYSCALL_RECVFROM 45)
(def SYSCALL_FORK 57)
(def SYSCALL_EXECVE 59)
(def SYSCALL_EXIT 60)
(def SYSCALL_KILL 62)
(def SYSCALL_SETUID 105)
(def SYSCALL_SETGID 106)
(def SYSCALL_PTRACE 101)
(def SYSCALL_CLONE 56)
(def SYSCALL_CLONE3 435)

;; Syscall name lookup
(def SYSCALL_NAMES
  {0 "read" 1 "write" 2 "open" 3 "close" 4 "stat" 5 "fstat"
   7 "poll" 9 "mmap" 10 "mprotect" 11 "munmap"
   41 "socket" 42 "connect" 43 "accept" 44 "sendto" 45 "recvfrom"
   56 "clone" 57 "fork" 59 "execve" 60 "exit" 62 "kill"
   101 "ptrace" 105 "setuid" 106 "setgid" 435 "clone3"})

;; Security-sensitive syscalls
(def SECURITY_SENSITIVE
  #{SYSCALL_EXECVE SYSCALL_SETUID SYSCALL_SETGID SYSCALL_PTRACE
    SYSCALL_FORK SYSCALL_CLONE SYSCALL_CLONE3})

(def MAX_ENTRIES 10000)
(def NUM_SYSCALLS 512)  ; Track up to 512 syscall numbers

;;; ============================================================================
;;; Part 2: Data Structures
;;; ============================================================================

;; Syscall event structure
;; struct syscall_event {
;;   u64 timestamp;     // offset 0
;;   u64 pid_tgid;      // offset 8
;;   u64 syscall_nr;    // offset 16
;;   u64 args[6];       // offset 24 (48 bytes)
;;   s64 ret_value;     // offset 72
;;   char comm[16];     // offset 80
;; };
(def SYSCALL_EVENT_SIZE 96)

(defn read-u64-le [^bytes buf offset]
  (let [bb (ByteBuffer/wrap buf)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getLong bb offset)))

(defn read-s64-le [^bytes buf offset]
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

(defn parse-syscall-event [^bytes buf]
  "Parse syscall_event structure from raw bytes"
  {:timestamp (read-u64-le buf 0)
   :pid-tgid (read-u64-le buf 8)
   :pid (bit-and (read-u64-le buf 8) 0xFFFFFFFF)
   :tgid (bit-shift-right (read-u64-le buf 8) 32)
   :syscall-nr (read-u64-le buf 16)
   :args (vec (for [i (range 6)]
                (read-u64-le buf (+ 24 (* i 8)))))
   :ret-value (read-s64-le buf 72)
   :comm (read-string-from-bytes buf 80 16)})

;;; ============================================================================
;;; Part 3: Maps
;;; ============================================================================

(defn create-syscall-count-map
  "Array map: syscall_nr -> count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries NUM_SYSCALLS
                   :map-name "syscall_counts"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-error-count-map
  "Array map: syscall_nr -> error_count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries NUM_SYSCALLS
                   :map-name "error_counts"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-alerts-map
  "Array map: alert_type -> count
   [0] = total_alerts
   [1] = setuid_to_root
   [2] = execve_count
   [3] = ptrace_count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 8
                   :map-name "security_alerts"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: BPF Program - Syscall Entry Handler
;;; ============================================================================

(defn create-syscall-entry-handler
  "Create BPF program for monitoring syscall entries.

   This simplified version demonstrates:
   - Getting PID/TGID
   - Getting timestamp
   - Incrementing syscall counter

   Instruction layout:
   0: call get_current_pid_tgid
   1: mov-reg r6, r0
   2: call ktime_get_ns
   3: mov-reg r7, r0
   4: mov r0, 0
   5: exit"
  [syscall-count-fd]
  (bpf/assemble
    [;; Get current PID/TGID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r6 :r0)      ; r6 = pid_tgid

     ;; Get timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r7 :r0)      ; r7 = timestamp

     ;; Note: Full implementation would:
     ;; 1. Read syscall number from pt_regs
     ;; 2. Increment syscall_counts[syscall_nr]
     ;; 3. Check if security-sensitive syscall
     ;; 4. Generate alert if needed

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: BPF Program - Syscall Exit Handler
;;; ============================================================================

(defn create-syscall-exit-handler
  "Create BPF program for monitoring syscall returns.

   This simplified version demonstrates:
   - Getting PID/TGID
   - Getting return value from pt_regs

   Instruction layout:
   0: mov-reg r6, r1           ; save pt_regs pointer
   1: call get_current_pid_tgid
   2: mov-reg r7, r0
   3: mov r0, 0
   4: exit"
  [error-count-fd]
  (bpf/assemble
    [;; Save pt_regs pointer
     (bpf/mov-reg :r6 :r1)

     ;; Get current PID/TGID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r7 :r0)      ; r7 = pid_tgid

     ;; Note: Full implementation would:
     ;; 1. Read return value from pt_regs->rax
     ;; 2. If negative, increment error_counts[syscall_nr]
     ;; 3. For setuid, check if arg0 == 0 (root)

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 6: Userspace - Statistics and Alerts
;;; ============================================================================

(defn display-syscall-stats [syscall-map error-map]
  "Display syscall statistics"
  (println "\nSyscall Statistics:")
  (println "═══════════════════════════════════════════════════════")
  (println (format "%-15s │ %10s │ %10s │ %8s"
                   "Syscall" "Count" "Errors" "Error%"))
  (println "────────────────┼────────────┼────────────┼──────────")

  (let [syscalls-with-counts
        (for [nr (range NUM_SYSCALLS)
              :let [count (or (bpf/map-lookup syscall-map nr) 0)
                    errors (or (bpf/map-lookup error-map nr) 0)]
              :when (pos? count)]
          {:nr nr
           :name (get SYSCALL_NAMES nr (str "syscall_" nr))
           :count count
           :errors errors
           :error-pct (if (pos? count)
                        (* 100.0 (/ errors count))
                        0.0)})]

    (doseq [{:keys [name count errors error-pct]}
            (take 20 (sort-by :count > syscalls-with-counts))]
      (println (format "%-15s │ %,10d │ %,10d │ %7.1f%%"
                       name count errors error-pct)))

    (println "═══════════════════════════════════════════════════════")

    ;; Summary
    (let [total-calls (reduce + (map :count syscalls-with-counts))
          total-errors (reduce + (map :errors syscalls-with-counts))]
      (println (format "\nTotal syscalls: %,d" total-calls))
      (println (format "Total errors:   %,d (%.1f%%)"
                       total-errors
                       (if (pos? total-calls)
                         (* 100.0 (/ total-errors total-calls))
                         0.0))))))

(defn display-security-alerts [alerts-map]
  "Display security alerts"
  (println "\nSecurity Alerts:")
  (println "═══════════════════════════════════════")

  (let [total-alerts (or (bpf/map-lookup alerts-map 0) 0)
        setuid-root (or (bpf/map-lookup alerts-map 1) 0)
        execve-count (or (bpf/map-lookup alerts-map 2) 0)
        ptrace-count (or (bpf/map-lookup alerts-map 3) 0)]

    (println (format "Total alerts:       %d" total-alerts))
    (println)
    (println "Alert breakdown:")
    (println (format "  setuid(0) calls:  %d %s"
                     setuid-root
                     (if (pos? setuid-root) "⚠️  PRIVILEGE ESCALATION" "")))
    (println (format "  execve() calls:   %d" execve-count))
    (println (format "  ptrace() calls:   %d %s"
                     ptrace-count
                     (if (pos? ptrace-count) "⚠️  PROCESS INJECTION RISK" "")))

    (when (pos? total-alerts)
      (println)
      (println "⚠️  SECURITY EVENTS DETECTED!")
      (println "    Review the events above for potential security issues."))))

;;; ============================================================================
;;; Part 7: Simulation
;;; ============================================================================

(defn simulate-syscall-data
  "Simulate syscall monitoring data"
  [syscall-map error-map alerts-map]
  (println "\n  Simulating syscall data...")

  ;; Simulate syscall counts (realistic distribution)
  (let [syscall-data
        {SYSCALL_READ 15000
         SYSCALL_WRITE 12000
         SYSCALL_CLOSE 8000
         SYSCALL_OPEN 5000
         SYSCALL_FSTAT 4000
         SYSCALL_STAT 3000
         SYSCALL_MMAP 2500
         SYSCALL_POLL 2000
         SYSCALL_SOCKET 500
         SYSCALL_CONNECT 300
         SYSCALL_EXECVE 25
         SYSCALL_FORK 15
         SYSCALL_CLONE 50
         SYSCALL_SETUID 3
         SYSCALL_PTRACE 2}

        ;; Simulate error rates
        error-data
        {SYSCALL_OPEN 150      ; file not found, permission denied
         SYSCALL_CONNECT 80    ; connection refused
         SYSCALL_READ 20       ; interrupted syscall
         SYSCALL_WRITE 15
         SYSCALL_STAT 200}]    ; no such file

    ;; Update syscall counts
    (doseq [[nr cnt] syscall-data]
      (bpf/map-update syscall-map nr cnt))

    ;; Update error counts
    (doseq [[nr cnt] error-data]
      (bpf/map-update error-map nr cnt))

    ;; Simulate security alerts
    (bpf/map-update alerts-map 0 5)  ; total alerts
    (bpf/map-update alerts-map 1 1)  ; setuid(0) - privilege escalation!
    (bpf/map-update alerts-map 2 25) ; execve count
    (bpf/map-update alerts-map 3 2)  ; ptrace count

    (println (format "  Simulated %d syscalls across %d types"
                     (reduce + (vals syscall-data))
                     (count syscall-data)))))

(defn display-simulated-events
  "Display simulated syscall events"
  []
  (println "\nRecent Syscall Events:")
  (println "═══════════════════════════════════════════════════════")

  (let [events
        [{:timestamp 1234567890000000
          :pid 1234
          :comm "bash"
          :syscall-nr SYSCALL_EXECVE
          :args [0x7ffd12345678 0x7ffd12345690 0x7ffd123456a0 0 0 0]
          :ret-value 0}
         {:timestamp 1234567891000000
          :pid 5678
          :comm "python3"
          :syscall-nr SYSCALL_OPEN
          :args [0x7f1234567890 2 0644 0 0 0]
          :ret-value 3}
         {:timestamp 1234567892000000
          :pid 1234
          :comm "bash"
          :syscall-nr SYSCALL_READ
          :args [3 0x7ffd12345000 4096 0 0 0]
          :ret-value 1024}
         {:timestamp 1234567893000000
          :pid 9999
          :comm "exploit"
          :syscall-nr SYSCALL_SETUID
          :args [0 0 0 0 0 0]  ; setuid(0) - privilege escalation!
          :ret-value 0}
         {:timestamp 1234567894000000
          :pid 8888
          :comm "debugger"
          :syscall-nr SYSCALL_PTRACE
          :args [16 1234 0 0 0 0]
          :ret-value 0}]]

    (doseq [{:keys [timestamp pid comm syscall-nr args ret-value]} events]
      (let [name (get SYSCALL_NAMES syscall-nr (str "syscall_" syscall-nr))
            alert (cond
                    (and (= syscall-nr SYSCALL_SETUID) (zero? (first args)))
                    " ⚠️  PRIVILEGE ESCALATION"

                    (= syscall-nr SYSCALL_PTRACE)
                    " ⚠️  PROCESS DEBUG/INJECTION"

                    :else "")]
        (println (format "[%d.%06d] PID %5d %-12s %-12s ret=%d%s"
                         (quot timestamp 1000000)
                         (mod timestamp 1000000)
                         pid
                         comm
                         name
                         ret-value
                         alert))))

    (println "═══════════════════════════════════════════════════════")))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 5.3: System Call Monitor ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [syscall-map (create-syscall-count-map)
        error-map (create-error-count-map)
        alerts-map (create-alerts-map)]
    (println "  Syscall count map created (FD:" (:fd syscall-map) ")")
    (println "  Error count map created (FD:" (:fd error-map) ")")
    (println "  Alerts map created (FD:" (:fd alerts-map) ")")

    ;; Initialize maps
    (doseq [i (range 8)]
      (bpf/map-update alerts-map i 0))

    (try
      ;; Step 3: Create BPF programs
      (println "\nStep 3: Creating BPF programs...")
      (let [entry-prog (create-syscall-entry-handler (:fd syscall-map))
            exit-prog (create-syscall-exit-handler (:fd error-map))]
        (println "  Entry handler assembled (" (/ (count entry-prog) 8) "instructions)")
        (println "  Exit handler assembled (" (/ (count exit-prog) 8) "instructions)")

        ;; Step 4: Load programs
        (println "\nStep 4: Loading programs into kernel...")
        (let [entry-loaded (bpf/load-program {:prog-type :kprobe
                                              :insns entry-prog})
              exit-loaded (bpf/load-program {:prog-type :kprobe
                                             :insns exit-prog})]
          (println "  Entry handler loaded (FD:" (:fd entry-loaded) ")")
          (println "  Exit handler loaded (FD:" (:fd exit-loaded) ")")

          (try
            ;; Step 5: Show security monitoring info
            (println "\nStep 5: Security monitoring targets:")
            (println "  ┌──────────────────────────────────────────┐")
            (println "  │ Security-Sensitive Syscalls Monitored    │")
            (println "  ├──────────────────────────────────────────┤")
            (println "  │ setuid(0)  - Privilege escalation        │")
            (println "  │ setgid(0)  - Group privilege escalation  │")
            (println "  │ execve()   - Process execution           │")
            (println "  │ ptrace()   - Process debugging/injection │")
            (println "  │ fork()     - Process creation            │")
            (println "  │ clone()    - Thread/process creation     │")
            (println "  └──────────────────────────────────────────┘")

            ;; Step 6: Show attachment info
            (println "\nStep 6: Attachment info...")
            (println "  Would attach kprobes to:")
            (println "    - __x64_sys_* (syscall entry points)")
            (println "  And kretprobes for return value monitoring")

            ;; Step 7: Simulate syscall data
            (println "\nStep 7: Simulating syscall data...")
            (simulate-syscall-data syscall-map error-map alerts-map)

            ;; Step 8: Display recent events
            (println "\nStep 8: Recent events...")
            (display-simulated-events)

            ;; Step 9: Display statistics
            (println "\nStep 9: Statistics...")
            (display-syscall-stats syscall-map error-map)

            ;; Step 10: Display security alerts
            (println "\nStep 10: Security alerts...")
            (display-security-alerts alerts-map)

            ;; Step 11: Cleanup
            (println "\nStep 11: Cleanup...")
            (bpf/close-program entry-loaded)
            (bpf/close-program exit-loaded)
            (println "  Programs closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map syscall-map)
        (bpf/close-map error-map)
        (bpf/close-map alerts-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 5.3 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test syscall name lookup
  (get SYSCALL_NAMES 59)  ; => "execve"

  ;; Check security-sensitive
  (contains? SECURITY_SENSITIVE SYSCALL_EXECVE)  ; => true
  )
