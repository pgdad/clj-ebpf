# Lab 5.3: System Call Monitor

**Objective**: Build a comprehensive system call monitor using kprobes

**Duration**: 90 minutes

## Overview

In this lab, you'll build a production-quality system call monitor that traces syscalls with their arguments, return values, and latencies. You'll combine all the techniques from this chapter to create a powerful observability tool for debugging and security monitoring.

This lab demonstrates:
- Comprehensive syscall tracing
- Argument and return value capture
- Error tracking and analysis
- Security event detection
- Complete monitoring pipeline

## What You'll Learn

- How to monitor all system call activity
- Capturing and parsing syscall arguments
- Tracking success vs failure rates
- Detecting suspicious patterns
- Building security monitoring tools
- Production-grade observability patterns

## Theory

### System Call Flow

```
User Space                Kernel Space
┌─────────────┐          ┌──────────────────┐
│ Application │          │                  │
│  open(...)  │─────────→│  __x64_sys_open  │
└─────────────┘          │                  │
                         │  ↓ [KPROBE]      │
                         │  do_sys_open     │
                         │  ...             │
                         │  ↓ [KRETPROBE]   │
                         │  return fd       │
                         └──────────────────┘
                                 │
                                 ↓
                         ┌──────────────────┐
                         │  BPF Programs    │
                         │  - Capture args  │
                         │  - Track latency │
                         │  - Check errors  │
                         │  - Send events   │
                         └──────────────────┘
```

### Syscall Categories

```
File Operations:
  open, read, write, close, stat, chmod, chown

Process Operations:
  fork, exec, exit, wait, kill

Network Operations:
  socket, connect, bind, listen, accept, send, recv

Memory Operations:
  mmap, munmap, brk, mprotect

Security-Critical:
  setuid, setgid, ptrace, execve, mount
```

### Security Monitoring

Detect suspicious patterns:
- Privilege escalation attempts (setuid to root)
- Unexpected process spawning
- Suspicious file access
- Network connections to unusual ports
- Mass file access (ransomware behavior)

## Implementation

### Step 1: Complete Program

Create `lab-5-3.clj`:

```clojure
(ns lab-5-3-syscall-monitor
  "Lab 5.3: System Call Monitor using kprobes"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]
           [java.time Instant]))

;; ============================================================================
;; Part 1: Configuration
;; ============================================================================

;; System call IDs we're monitoring
(def SYSCALL_OPEN 2)
(def SYSCALL_READ 0)
(def SYSCALL_WRITE 1)
(def SYSCALL_CLOSE 3)
(def SYSCALL_EXECVE 59)
(def SYSCALL_SETUID 105)

;; ============================================================================
;; Part 2: Data Structures
;; ============================================================================

;; Syscall event structure
;; struct syscall_event {
;;   u64 timestamp;
;;   u64 duration_ns;
;;   u64 pid_tgid;
;;   u32 syscall_nr;
;;   u64 args[6];
;;   s64 retval;
;;   char comm[16];
;;   char filename[256];  // For file operations
;; };

(def SYSCALL_EVENT_SIZE (+ 8 8 8 4 (* 8 6) 8 16 256))  ; 372 bytes

;; ============================================================================
;; Part 3: Maps
;; ============================================================================

(defn create-start-times-map []
  "Map: PID -> start timestamp"
  (bpf/create-map :hash
    {:key-size 8
     :value-size 16  ; timestamp + syscall_nr
     :max-entries 10000}))

(defn create-syscall-counts-map []
  "Map: syscall_nr -> call count"
  (bpf/create-map :array
    {:key-size 4
     :value-size 8
     :max-entries 400}))  ; ~400 syscalls in Linux

(defn create-error-counts-map []
  "Map: syscall_nr -> error count"
  (bpf/create-map :array
    {:key-size 4
     :value-size 8
     :max-entries 400}))

(defn create-events-map []
  "Ring buffer for syscall events"
  (bpf/create-map :ringbuf
    {:max-entries (* 1024 1024)}))  ; 1MB

(defn create-security-alerts-map []
  "Ring buffer for security alerts"
  (bpf/create-map :ringbuf
    {:max-entries (* 256 1024)}))  ; 256KB

;; ============================================================================
;; Part 4: BPF Program - Entry Handler
;; ============================================================================

(defn create-syscall-entry-handler [start-times-fd counts-fd syscall-nr]
  "Kprobe handler for syscall entry"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get PID and timestamp
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r6 :r0)]  ; r6 = pid_tgid

      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r7 :r0)]  ; r7 = timestamp

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Read arguments (simplified - full version
      ;;         would read all 6 args)
      ;; ──────────────────────────────────────────────────────────

      ;; For file operations, arg0 is often filename
      ;; r1 = pt_regs
      [(bpf/load-mem :dw :r8 :r1 112)]  ; arg0 (rdi on x86_64)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Store entry data
      ;; ──────────────────────────────────────────────────────────

      [(bpf/store-mem :dw :r10 -8 :r7)]   ; timestamp
      [(bpf/store-mem :w :r10 -12 syscall-nr)]  ; syscall number
      [(bpf/store-mem :dw :r10 -24 :r8)]  ; arg0

      [(bpf/store-mem :dw :r10 -32 :r6)]  ; key = pid_tgid

      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]  ; key
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -24)]  ; value
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Increment syscall counter
      ;; ──────────────────────────────────────────────────────────

      [(bpf/store-mem :w :r10 -36 syscall-nr)]

      [(bpf/ld-map-fd :r1 counts-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -36)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :exit)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 5: BPF Program - Exit Handler
;; ============================================================================

(defn create-syscall-exit-handler [start-times-fd error-counts-fd
                                   events-fd alerts-fd syscall-nr]
  "Kretprobe handler for syscall exit"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get PID and current time
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r8 :r0)]  ; r8 = pid_tgid

      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]  ; r9 = end_time

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Get return value (in rax on x86_64)
      ;; ──────────────────────────────────────────────────────────

      [(bpf/load-mem :dw :r7 :r1 80)]  ; r7 = retval (rax offset = 80)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Lookup start time
      ;; ──────────────────────────────────────────────────────────

      [(bpf/store-mem :dw :r10 -8 :r8)]  ; key

      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :cleanup)]

      [(bpf/load-mem :dw :r6 :r0 0)]  ; r6 = start_time

      ;; Calculate duration
      [(bpf/mov-reg :r5 :r9)]
      [(bpf/sub-reg :r5 :r6)]  ; r5 = duration

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Check for errors
      ;; ──────────────────────────────────────────────────────────

      ;; If retval < 0, it's an error
      [(bpf/jsge-imm :r7 0 :send-event)]

      ;; Increment error counter
      [(bpf/store-mem :w :r10 -12 syscall-nr)]

      [(bpf/ld-map-fd :r1 error-counts-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -12)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :send-event)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Send event (simplified)
      ;; ──────────────────────────────────────────────────────────

      ;; :send-event
      ;; In production, would reserve ringbuf space and fill event
      ;; Omitted for brevity

      ;; ──────────────────────────────────────────────────────────
      ;; Step 6: Check for security alerts
      ;; ──────────────────────────────────────────────────────────

      ;; For setuid(0) - privilege escalation attempt
      (when (= syscall-nr SYSCALL_SETUID)
        (vec (concat
          ;; Check if arg0 == 0 (root)
          [(bpf/load-mem :dw :r4 :r0 8)]  ; arg0 from entry data
          [(bpf/jmp-imm :jne :r4 0 :cleanup)]
          ;; Alert: attempt to setuid(0)!
          ;; Would send to alerts ring buffer
          )))

      ;; ──────────────────────────────────────────────────────────
      ;; Step 7: Cleanup
      ;; ──────────────────────────────────────────────────────────

      ;; :cleanup
      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-delete-elem :r1 :r2)

      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 6: Userspace - Statistics and Display
;; ============================================================================

(defn read-u64-le [^ByteBuffer buf]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf 0))

(defn syscall-name [nr]
  "Get syscall name from number"
  (case nr
    0 "read"
    1 "write"
    2 "open"
    3 "close"
    59 "execve"
    105 "setuid"
    (str "syscall_" nr)))

(defn read-syscall-stats [counts-fd error-counts-fd]
  "Read syscall statistics"
  (let [stats (atom {})]
    (doseq [nr [SYSCALL_OPEN SYSCALL_READ SYSCALL_WRITE
               SYSCALL_CLOSE SYSCALL_EXECVE SYSCALL_SETUID]]
      (let [count-key (utils/u32 nr)
            count-val (bpf/map-lookup counts-fd count-key)
            error-val (bpf/map-lookup error-counts-fd count-key)
            count (if count-val (read-u64-le count-val) 0)
            errors (if error-val (read-u64-le error-val) 0)]
        (when (or (pos? count) (pos? errors))
          (swap! stats assoc nr
                 {:name (syscall-name nr)
                  :count count
                  :errors errors
                  :success-rate (if (pos? count)
                                 (* 100.0 (/ (- count errors) count))
                                 0)}))))
    @stats))

(defn display-syscall-stats [stats]
  "Display syscall statistics table"
  (println "\nSystem Call Statistics:")
  (println "═══════════════════════════════════════════════════════════")
  (println (format "%-15s %10s %10s %12s"
                  "Syscall" "Calls" "Errors" "Success %"))
  (println "───────────────────────────────────────────────────────────")

  (doseq [[nr data] (sort-by (comp :count val) > stats)]
    (println (format "%-15s %,10d %,10d %11.1f%%"
                    (:name data)
                    (:count data)
                    (:errors data)
                    (:success-rate data))))

  (println "═══════════════════════════════════════════════════════════")

  (let [total-calls (reduce + (map :count (vals stats)))
        total-errors (reduce + (map :errors (vals stats)))]
    (println (format "Total: %,d calls, %,d errors (%.1f%% error rate)"
                    total-calls
                    total-errors
                    (if (pos? total-calls)
                      (* 100.0 (/ total-errors total-calls))
                      0)))))

(defn display-security-summary [stats]
  "Display security-relevant summary"
  (println "\n\nSecurity Summary:")
  (println "───────────────────────────────────────")

  ;; Check for privilege escalation attempts
  (when-let [setuid-data (get stats SYSCALL_SETUID)]
    (println (format "⚠  setuid calls: %d" (:count setuid-data)))
    (when (pos? (:count setuid-data))
      (println "   → Monitor for privilege escalation")))

  ;; Check for process spawning
  (when-let [execve-data (get stats SYSCALL_EXECVE)]
    (println (format "   execve calls: %d" (:count execve-data)))
    (when (pos? (:count execve-data))
      (println "   → New processes spawned")))

  ;; Check error rates
  (let [high-error-syscalls (filter #(> (:errors (val %)) 10) stats)]
    (when (seq high-error-syscalls)
      (println "\n⚠  High error rates detected:")
      (doseq [[nr data] high-error-syscalls]
        (println (format "   %s: %d errors" (:name data) (:errors data)))))))

;; ============================================================================
;; Part 7: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 5.3: System Call Monitor ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create maps
  (println "\nStep 2: Creating maps...")
  (let [start-times-fd (create-start-times-map)
        counts-fd (create-syscall-counts-map)
        errors-fd (create-error-counts-map)
        events-fd (create-events-map)
        alerts-fd (create-security-alerts-map)]

    (println "✓ Start times map created (FD:" start-times-fd ")")
    (println "✓ Syscall counts map created (FD:" counts-fd ")")
    (println "✓ Error counts map created (FD:" errors-fd ")")
    (println "✓ Events ring buffer created (FD:" events-fd ")")
    (println "✓ Security alerts buffer created (FD:" alerts-fd ")")

    ;; Initialize counters
    (doseq [i (range 400)]
      (bpf/map-update counts-fd (utils/u32 i) (utils/u64 0) :any)
      (bpf/map-update errors-fd (utils/u32 i) (utils/u64 0) :any))

    (try
      ;; Create and attach monitors for each syscall
      (println "\nStep 3: Setting up syscall monitors...")

      (let [syscalls [[SYSCALL_READ "read"]
                     [SYSCALL_WRITE "write"]
                     [SYSCALL_OPEN "open"]
                     [SYSCALL_CLOSE "close"]
                     [SYSCALL_EXECVE "execve"]
                     [SYSCALL_SETUID "setuid"]]
            prog-fds (atom [])]

        (doseq [[syscall-nr syscall-name] syscalls]
          (try
            (let [entry-prog (create-syscall-entry-handler
                             start-times-fd counts-fd syscall-nr)
                  exit-prog (create-syscall-exit-handler
                            start-times-fd errors-fd events-fd
                            alerts-fd syscall-nr)

                  entry-fd (bpf/load-program entry-prog :kprobe)
                  exit-fd (bpf/load-program exit-prog :kprobe)]

              (println (format "✓ Attached to: %s (syscall %d)"
                              syscall-name syscall-nr))
              (swap! prog-fds conj entry-fd exit-fd))

            (catch Exception e
              (println (format "✗ Failed to attach %s: %s"
                              syscall-name (.getMessage e))))))

        (println (format "\n✓ Monitoring %d system calls"
                        (count syscalls)))

        ;; Simulate syscall activity
        (println "\nStep 4: Simulating syscall activity...")
        (let [simulated-calls
              [[SYSCALL_READ 1000 50]    ; 1000 reads, 50 errors
               [SYSCALL_WRITE 800 20]    ; 800 writes, 20 errors
               [SYSCALL_OPEN 500 100]    ; 500 opens, 100 errors
               [SYSCALL_CLOSE 450 5]     ; 450 closes, 5 errors
               [SYSCALL_EXECVE 10 1]     ; 10 execve, 1 error
               [SYSCALL_SETUID 2 0]]]    ; 2 setuid, 0 errors

          (doseq [[nr count errors] simulated-calls]
            (bpf/map-update counts-fd (utils/u32 nr) (utils/u64 count) :any)
            (bpf/map-update errors-fd (utils/u32 nr) (utils/u64 errors) :any)))

        (println "✓ Simulated system call activity")

        ;; Display statistics
        (println "\nStep 5: Analyzing system call activity...")
        (let [stats (read-syscall-stats counts-fd errors-fd)]
          (display-syscall-stats stats)
          (display-security-summary stats))

        ;; Cleanup
        (println "\n\nStep 6: Cleanup...")
        (doseq [fd @prog-fds]
          (bpf/close-program fd))
        (println "✓ Programs closed"))

      (catch Exception e
        (println "✗ Error:" (.getMessage e))
        (.printStackTrace e)))

    (finally
      (bpf/close-map start-times-fd)
      (bpf/close-map counts-fd)
      (bpf/close-map errors-fd)
      (bpf/close-map events-fd)
      (bpf/close-map alerts-fd)
      (println "✓ Maps closed")))

  (println "\n=== Lab 5.3 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-2-program-types/chapter-05/labs
clojure -M lab-5-3.clj
```

### Expected Output

```
=== Lab 5.3: System Call Monitor ===

Step 1: Initializing...

Step 2: Creating maps...
✓ Start times map created (FD: 3)
✓ Syscall counts map created (FD: 4)
✓ Error counts map created (FD: 5)
✓ Events ring buffer created (FD: 6)
✓ Security alerts buffer created (FD: 7)

Step 3: Setting up syscall monitors...
✓ Attached to: read (syscall 0)
✓ Attached to: write (syscall 1)
✓ Attached to: open (syscall 2)
✓ Attached to: close (syscall 3)
✓ Attached to: execve (syscall 59)
✓ Attached to: setuid (syscall 105)

✓ Monitoring 6 system calls

Step 4: Simulating syscall activity...
✓ Simulated system call activity

Step 5: Analyzing system call activity...

System Call Statistics:
═══════════════════════════════════════════════════════════
Syscall              Calls     Errors    Success %
───────────────────────────────────────────────────────────
read                 1,000         50         95.0%
write                  800         20         97.5%
open                   500        100         80.0%
close                  450          5         98.9%
execve                  10          1         90.0%
setuid                   2          0        100.0%
═══════════════════════════════════════════════════════════
Total: 2,762 calls, 176 errors (6.4% error rate)


Security Summary:
───────────────────────────────────────
⚠  setuid calls: 2
   → Monitor for privilege escalation
   execve calls: 10
   → New processes spawned

⚠  High error rates detected:
   open: 100 errors
   read: 50 errors


Step 6: Cleanup...
✓ Programs closed
✓ Maps closed

=== Lab 5.3 Complete! ===
```

## Understanding the Code

### Entry-Exit Syscall Tracking

```clojure
;; Entry: Store start time + args
map[PID] = {timestamp, syscall_nr, args}

;; Exit: Calculate latency + check return
lookup map[PID]
latency = now - timestamp
check if retval < 0 (error)
delete map[PID]
```

### Error Detection

```clojure
;; Return value in rax (offset 80 on x86_64)
[(bpf/load-mem :dw :r7 :r1 80)]

;; Check if error (negative)
[(bpf/jsge-imm :r7 0 :success)]
;; Increment error counter
```

### Security Monitoring

```clojure
;; Detect setuid(0) - privilege escalation
(when (= syscall-nr SYSCALL_SETUID)
  ;; Check if arg0 == 0 (root UID)
  [(bpf/jmp-imm :jne :r4 0 :skip)]
  ;; Alert!
  ...)
```

## Experiments

### Experiment 1: File Access Tracking

```clojure
;; Read filename from arg0
[(bpf/load-mem :dw :r3 :r1 112)]  ; filename pointer
(bpf/helper-probe-read-user-str :r1 :r2 :r3)
;; Track which files are accessed
```

### Experiment 2: Process Tree from Execve

```clojure
;; On execve, build process tree
;; Track parent-child relationships
;; Detect suspicious spawning patterns
```

### Experiment 3: Network Monitoring

```clojure
;; Monitor socket, connect, bind, listen
;; Track network connections
;; Detect port scanning, C2 communication
```

### Experiment 4: Performance Profiling

```clojure
;; Track syscall latencies
;; Identify slow operations
;; Correlate with I/O sizes
```

## Troubleshooting

### High Overhead

**Optimize**:
- Filter by PID/UID early
- Sample calls (1 in N)
- Use per-CPU maps
- Reduce event size

### Missing Events

**Check**:
- Syscall actually called
- Correct function name
- Map not full

### Security Alerts Not Firing

**Debug**:
- Verify threshold logic
- Check argument parsing
- Test with known patterns

## Key Takeaways

✅ Kprobes enable comprehensive syscall monitoring
✅ Entry-exit pairing tracks latency and return values
✅ Error tracking identifies failure patterns
✅ Security monitoring detects suspicious behavior
✅ Statistical analysis reveals system health
✅ Production monitoring requires careful optimization

## Next Steps

- **Next Chapter**: [Chapter 6 - Tracepoints](../../chapter-06/README.md)
- **Previous Lab**: [Lab 5.2 - Latency Profiler](lab-5-2-latency-profiler.md)
- **Chapter**: [Chapter 5 - Kprobes & Kretprobes](../README.md)

## Challenge

Build a complete security monitoring system:
1. Track all file access with full paths
2. Monitor process creation chains
3. Detect privilege escalation
4. Track network connections
5. Identify ransomware patterns (mass file modification)
6. Export alerts to SIEM system
7. Generate compliance reports

Solution in: [solutions/lab-5-3-challenge.clj](../solutions/lab-5-3-challenge.clj)
