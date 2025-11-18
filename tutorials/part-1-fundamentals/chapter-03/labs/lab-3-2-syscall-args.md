# Lab 3.2: System Call Argument Capture

**Objective**: Capture and parse system call arguments using BPF instructions

**Duration**: 60 minutes

## Overview

In this lab, you'll build a system call tracer that captures arguments from common syscalls like `open()`, `read()`, `write()`, and `execve()`. You'll learn how to read argument values from CPU registers, handle different data types, and safely read string arguments from user space.

This lab demonstrates:
- Reading syscall arguments from pt_regs structure
- Handling different argument types (integers, pointers, strings)
- Safe user space memory access
- Building argument parsers
- Storing captured data in maps

## What You'll Learn

- How syscall arguments are passed in registers
- How to access pt_regs structure in BPF
- Safe techniques for reading user space strings
- Handling variable-length data
- Building type-aware argument parsers
- Efficient data capture patterns

## Theory

### System Call Argument Passing

On x86_64, syscall arguments are passed in registers:

```
┌──────────┬──────────────────────────┐
│ Register │ Purpose                  │
├──────────┼──────────────────────────┤
│   rax    │ Syscall number           │
│   rdi    │ 1st argument (arg0)      │
│   rsi    │ 2nd argument (arg1)      │
│   rdx    │ 3rd argument (arg2)      │
│   r10    │ 4th argument (arg3)      │
│   r8     │ 5th argument (arg4)      │
│   r9     │ 6th argument (arg5)      │
│   rax    │ Return value (after call)│
└──────────┴──────────────────────────┘
```

### pt_regs Structure

The kernel provides syscall arguments via `struct pt_regs`:

```c
struct pt_regs {
    unsigned long r15;      // offset 0
    unsigned long r14;      // offset 8
    unsigned long r13;      // offset 16
    unsigned long r12;      // offset 24
    unsigned long rbp;      // offset 32
    unsigned long rbx;      // offset 40
    unsigned long r11;      // offset 48
    unsigned long r10;      // offset 56
    unsigned long r9;       // offset 64
    unsigned long r8;       // offset 72
    unsigned long rax;      // offset 80
    unsigned long rcx;      // offset 88
    unsigned long rdx;      // offset 96
    unsigned long rsi;      // offset 104
    unsigned long rdi;      // offset 112
    // ... more fields ...
};
```

### Common Syscalls and Their Arguments

```
open(const char *filename, int flags, mode_t mode)
    arg0: filename (pointer to string)
    arg1: flags (integer)
    arg2: mode (integer)

read(int fd, void *buf, size_t count)
    arg0: fd (integer)
    arg1: buf (pointer)
    arg2: count (size_t)

write(int fd, const void *buf, size_t count)
    arg0: fd (integer)
    arg1: buf (pointer)
    arg2: count (size_t)

execve(const char *filename, char *const argv[], char *const envp[])
    arg0: filename (pointer to string)
    arg1: argv (pointer to array of strings)
    arg2: envp (pointer to array of strings)
```

### Safe String Reading

Reading strings from user space requires:
1. **Bounds checking**: Limit maximum read length
2. **Safe probe**: Use `bpf_probe_read_user()` helper
3. **NULL termination**: Ensure strings are terminated
4. **Error handling**: Handle inaccessible memory

## Implementation

### Step 1: Complete Program

Create `lab-3-2.clj`:

```clojure
(ns lab-3-2-syscall-args
  "Lab 3.2: System Call Argument Capture using BPF instructions"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Part 1: Architecture-Specific Offsets
;; ============================================================================

;; x86_64 pt_regs offsets (in bytes)
(def PT_REGS_RDI 112)   ; 1st syscall argument
(def PT_REGS_RSI 104)   ; 2nd syscall argument
(def PT_REGS_RDX 96)    ; 3rd syscall argument
(def PT_REGS_R10 56)    ; 4th syscall argument
(def PT_REGS_R8  72)    ; 5th syscall argument
(def PT_REGS_R9  64)    ; 6th syscall argument

;; ARM64 would use different offsets
;; (def PT_REGS_X0 0)    ; 1st argument on ARM64
;; (def PT_REGS_X1 8)    ; 2nd argument on ARM64
;; etc.

;; ============================================================================
;; Part 2: Data Structures
;; ============================================================================

(def MAX_STRING_LEN 256)
(def MAX_ARGS 6)

;; Event structure for captured syscalls
;; struct syscall_event {
;;   u64 timestamp;
;;   u64 pid_tgid;
;;   u32 syscall_nr;
;;   u64 args[6];
;;   char filename[256];
;; }

(def EVENT_SIZE (+ 8 8 4 4 (* 8 MAX_ARGS) MAX_STRING_LEN))  ; Total: 336 bytes

;; ============================================================================
;; Part 3: Maps
;; ============================================================================

(defn create-events-map []
  "Create ring buffer for syscall events"
  (bpf/create-map :ringbuf
    {:max-entries (* 256 1024)}))  ; 256KB ring buffer

(defn create-args-map []
  "Create map to store syscall arguments temporarily"
  (bpf/create-map :hash
    {:key-size 8          ; u64 for PID
     :value-size EVENT_SIZE
     :max-entries 10000}))

;; ============================================================================
;; Part 4: Argument Reading Helpers
;; ============================================================================

(defn read-arg
  "Read syscall argument N from pt_regs"
  [ctx-reg arg-num dst-reg]
  (let [offset (case arg-num
                 0 PT_REGS_RDI
                 1 PT_REGS_RSI
                 2 PT_REGS_RDX
                 3 PT_REGS_R10
                 4 PT_REGS_R8
                 5 PT_REGS_R9)]
    [(bpf/load-mem :dw dst-reg ctx-reg offset)]))

(defn read-all-args
  "Read all 6 syscall arguments and store on stack"
  [ctx-reg]
  (vec (concat
    ;; Read arg0 (rdi) → stack[-8]
    (read-arg ctx-reg 0 :r7)
    [(bpf/store-mem :dw :r10 -8 :r7)]

    ;; Read arg1 (rsi) → stack[-16]
    (read-arg ctx-reg 1 :r7)
    [(bpf/store-mem :dw :r10 -16 :r7)]

    ;; Read arg2 (rdx) → stack[-24]
    (read-arg ctx-reg 2 :r7)
    [(bpf/store-mem :dw :r10 -24 :r7)]

    ;; Read arg3 (r10) → stack[-32]
    (read-arg ctx-reg 3 :r7)
    [(bpf/store-mem :dw :r10 -32 :r7)]

    ;; Read arg4 (r8) → stack[-40]
    (read-arg ctx-reg 4 :r7)
    [(bpf/store-mem :dw :r10 -40 :r7)]

    ;; Read arg5 (r9) → stack[-48]
    (read-arg ctx-reg 5 :r7)
    [(bpf/store-mem :dw :r10 -48 :r7)])))

;; ============================================================================
;; Part 5: BPF Program - Open Syscall Tracer
;; ============================================================================

(defn create-open-tracer [events-map-fd]
  "Trace open() syscall - capture filename and flags"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get current PID/TGID
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r6 :r0)]  ; r6 = pid_tgid

      ;; Filter: only trace specific PID (optional)
      ;; [(bpf/rsh :r7 :r6 32)]  ; Extract TGID
      ;; [(bpf/jmp-imm :jne :r7 TARGET_PID :exit)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Read syscall arguments
      ;; ──────────────────────────────────────────────────────────

      ;; r1 points to struct pt_regs
      ;; Read arg0 (filename pointer)
      (read-arg :r1 0 :r7)  ; r7 = filename pointer

      ;; Read arg1 (flags)
      (read-arg :r1 1 :r8)  ; r8 = flags

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Reserve space in ring buffer
      ;; ──────────────────────────────────────────────────────────

      [(bpf/ld-map-fd :r1 events-map-fd)]  ; r1 = ringbuf map
      [(bpf/mov :r2 EVENT_SIZE)]            ; r2 = size
      [(bpf/mov :r3 0)]                     ; r3 = flags
      (bpf/helper-ringbuf-reserve :r1 :r2)  ; Reserve space

      ;; Check if reservation succeeded
      [(bpf/mov-reg :r9 :r0)]  ; r9 = event pointer
      [(bpf/jmp-imm :jeq :r9 0 :exit)]  ; NULL check

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Fill event structure
      ;; ──────────────────────────────────────────────────────────

      ;; event->timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/store-mem :dw :r9 0 :r0)]

      ;; event->pid_tgid
      [(bpf/store-mem :dw :r9 8 :r6)]

      ;; event->syscall_nr (2 = open on x86_64)
      [(bpf/store-mem :w :r9 16 2)]

      ;; event->args[0] = filename pointer (for reference)
      [(bpf/store-mem :dw :r9 24 :r7)]

      ;; event->args[1] = flags
      [(bpf/store-mem :dw :r9 32 :r8)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Read filename string from user space
      ;; ──────────────────────────────────────────────────────────

      ;; Calculate offset to filename field
      [(bpf/mov-reg :r1 :r9)]
      [(bpf/add :r1 72)]     ; r1 = &event->filename (offset 72)

      [(bpf/mov :r2 MAX_STRING_LEN)]  ; r2 = max length
      [(bpf/mov-reg :r3 :r7)]          ; r3 = user pointer (filename)
      (bpf/helper-probe-read-user-str :r1 :r2 :r3)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 6: Submit event to ring buffer
      ;; ──────────────────────────────────────────────────────────

      [(bpf/mov-reg :r1 :r9)]  ; r1 = event pointer
      [(bpf/mov :r2 0)]         ; r2 = flags (0 = BPF_RB_NO_WAKEUP)
      (bpf/helper-ringbuf-submit :r1)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 6: BPF Program - Read/Write Syscall Tracer
;; ============================================================================

(defn create-rw-tracer [events-map-fd syscall-nr]
  "Trace read()/write() syscalls - capture fd and count"
  (bpf/assemble
    (vec (concat
      ;; Get PID
      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r6 :r0)]

      ;; Read arguments
      ;; arg0 = fd (r1 = pt_regs)
      (read-arg :r1 0 :r7)  ; r7 = fd

      ;; arg2 = count
      (read-arg :r1 2 :r8)  ; r8 = count

      ;; Reserve ring buffer space
      [(bpf/ld-map-fd :r1 events-map-fd)]
      [(bpf/mov :r2 EVENT_SIZE)]
      [(bpf/mov :r3 0)]
      (bpf/helper-ringbuf-reserve :r1 :r2)

      [(bpf/mov-reg :r9 :r0)]
      [(bpf/jmp-imm :jeq :r9 0 :exit)]

      ;; Fill event
      (bpf/helper-ktime-get-ns)
      [(bpf/store-mem :dw :r9 0 :r0)]      ; timestamp
      [(bpf/store-mem :dw :r9 8 :r6)]      ; pid_tgid
      [(bpf/store-mem :w :r9 16 syscall-nr)] ; syscall number
      [(bpf/store-mem :dw :r9 24 :r7)]     ; args[0] = fd
      [(bpf/store-mem :dw :r9 32 :r8)]     ; args[1] = count

      ;; Submit
      [(bpf/mov-reg :r1 :r9)]
      [(bpf/mov :r2 0)]
      (bpf/helper-ringbuf-submit :r1)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 7: Userspace Event Processing
;; ============================================================================

(defn read-u64-le [^ByteBuffer buf offset]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf offset))

(defn read-u32-le [^ByteBuffer buf offset]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getInt buf offset))

(defn read-string [^ByteBuffer buf offset max-len]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.position buf offset)
  (let [bytes (byte-array max-len)
        _ (.get buf bytes)
        null-idx (loop [i 0]
                   (if (or (>= i max-len) (zero? (aget bytes i)))
                     i
                     (recur (inc i))))]
    (String. bytes 0 null-idx "UTF-8")))

(defn parse-syscall-event [^ByteBuffer event]
  "Parse syscall event from ring buffer"
  {:timestamp (read-u64-le event 0)
   :pid-tgid (read-u64-le event 8)
   :pid (bit-and (read-u64-le event 8) 0xFFFFFFFF)
   :tid (bit-shift-right (read-u64-le event 8) 32)
   :syscall-nr (read-u32-le event 16)
   :args [(read-u64-le event 24)
          (read-u64-le event 32)
          (read-u64-le event 40)
          (read-u64-le event 48)
          (read-u64-le event 56)
          (read-u64-le event 64)]
   :filename (read-string event 72 MAX_STRING_LEN)})

(defn format-syscall-event [event]
  "Format syscall event as human-readable string"
  (let [syscall-name (case (:syscall-nr event)
                      2 "open"
                      0 "read"
                      1 "write"
                      (str "syscall_" (:syscall-nr event)))]
    (case (:syscall-nr event)
      2 (format "[%d] open(\"%s\", 0x%x)"
               (:pid event)
               (:filename event)
               ((:args event) 1))
      0 (format "[%d] read(fd=%d, count=%d)"
               (:pid event)
               ((:args event) 0)
               ((:args event) 2))
      1 (format "[%d] write(fd=%d, count=%d)"
               (:pid event)
               ((:args event) 0)
               ((:args event) 2))
      (str "[" (:pid event) "] " syscall-name))))

;; ============================================================================
;; Part 8: Ring Buffer Consumer
;; ============================================================================

(defn consume-events [ringbuf-map-fd duration-ms]
  "Consume events from ring buffer for specified duration"
  (println "\nConsuming events for" duration-ms "ms...")
  (println "─────────────────────────────────────────────────────")

  (let [start-time (System/currentTimeMillis)
        event-count (atom 0)]

    ;; Note: Actual ring buffer consumption requires
    ;; bpf_ringbuf__consume() or bpf_ringbuf__poll()
    ;; This is a simplified simulation

    (println "ℹ Ring buffer consumption requires libbpf integration")
    (println "ℹ Events would appear here as they're captured:")
    (println)

    ;; Simulated events for demonstration
    (doseq [i (range 5)]
      (Thread/sleep 200)
      (let [event {:timestamp (System/nanoTime)
                   :pid (+ 1000 (rand-int 100))
                   :syscall-nr (rand-nth [0 1 2])
                   :args [3 0 1024 0 0 0]
                   :filename "/etc/passwd"}]
        (println (format-syscall-event event))
        (swap! event-count inc)))

    (println)
    (println "─────────────────────────────────────────────────────")
    (println "Captured" @event-count "events")))

;; ============================================================================
;; Part 9: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 3.2: System Call Argument Capture ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create ring buffer map
  (println "\nStep 2: Creating ring buffer...")
  (let [ringbuf-fd (create-events-map)]
    (println "✓ Ring buffer created (FD:" ringbuf-fd ")")
    (println "  Size: 256 KB")

    (try
      ;; Create open() tracer
      (println "\nStep 3: Creating open() syscall tracer...")
      (let [open-prog (create-open-tracer ringbuf-fd)]
        (println "✓ Program assembled (" (/ (count open-prog) 8) "instructions)")

        (println "\nStep 4: Loading open() tracer...")
        (let [open-fd (bpf/load-program open-prog :tracepoint)]
          (println "✓ Program loaded (FD:" open-fd ")")

          (try
            ;; Create read() tracer
            (println "\nStep 5: Creating read() syscall tracer...")
            (let [read-prog (create-rw-tracer ringbuf-fd 0)]
              (println "✓ Program assembled (" (/ (count read-prog) 8) "instructions)")

              (println "\nStep 6: Loading read() tracer...")
              (let [read-fd (bpf/load-program read-prog :tracepoint)]
                (println "✓ Program loaded (FD:" read-fd ")")

                (try
                  ;; Note: Actual tracepoint attachment requires Chapter 5
                  (println "\nStep 7: Attaching to tracepoints...")
                  (println "ℹ Tracepoint attachment requires Chapter 5")
                  (println "ℹ Would attach to:")
                  (println "  - syscalls:sys_enter_openat")
                  (println "  - syscalls:sys_enter_read")
                  (println "  - syscalls:sys_enter_write")

                  ;; Demonstrate argument parsing
                  (println "\nStep 8: Argument parsing demonstration...")
                  (println "\nSyscall signatures captured:")
                  (println "  open(filename, flags, mode)")
                  (println "    ├─ arg0: string (via probe_read_user)")
                  (println "    ├─ arg1: int (flags)")
                  (println "    └─ arg2: int (mode)")
                  (println)
                  (println "  read(fd, buf, count)")
                  (println "    ├─ arg0: int (fd)")
                  (println "    ├─ arg1: pointer (buf)")
                  (println "    └─ arg2: size_t (count)")

                  ;; Simulate event collection
                  (println "\nStep 9: Collecting syscall events...")
                  (consume-events ringbuf-fd 1000)

                  ;; Cleanup
                  (println "\nStep 10: Cleanup...")
                  (bpf/close-program read-fd)
                  (bpf/close-program open-fd)
                  (println "✓ Programs closed")

                  (catch Exception e
                    (println "✗ Error:" (.getMessage e))
                    (.printStackTrace e)))

                (catch Exception e
                  (println "✗ Error:" (.getMessage e))))))

            (catch Exception e
              (println "✗ Error:" (.getMessage e))))))

        (catch Exception e
          (println "✗ Error:" (.getMessage e)))))

      (finally
        (bpf/close-map ringbuf-fd)
        (println "✓ Ring buffer closed"))))

  (println "\n=== Lab 3.2 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-03/labs
clojure -M lab-3-2.clj
```

### Expected Output

```
=== Lab 3.2: System Call Argument Capture ===

Step 1: Initializing...

Step 2: Creating ring buffer...
✓ Ring buffer created (FD: 3)
  Size: 256 KB

Step 3: Creating open() syscall tracer...
✓ Program assembled (25 instructions)

Step 4: Loading open() tracer...
✓ Program loaded (FD: 4)

Step 5: Creating read() syscall tracer...
✓ Program assembled (20 instructions)

Step 6: Loading read() tracer...
✓ Program loaded (FD: 5)

Step 7: Attaching to tracepoints...
ℹ Tracepoint attachment requires Chapter 5
ℹ Would attach to:
  - syscalls:sys_enter_openat
  - syscalls:sys_enter_read
  - syscalls:sys_enter_write

Step 8: Argument parsing demonstration...

Syscall signatures captured:
  open(filename, flags, mode)
    ├─ arg0: string (via probe_read_user)
    ├─ arg1: int (flags)
    └─ arg2: int (mode)

  read(fd, buf, count)
    ├─ arg0: int (fd)
    ├─ arg1: pointer (buf)
    └─ arg2: size_t (count)

Step 9: Collecting syscall events...

Consuming events for 1000 ms...
─────────────────────────────────────────────────────
ℹ Ring buffer consumption requires libbpf integration
ℹ Events would appear here as they're captured:

[1042] open("/etc/passwd", 0x0)
[1015] read(fd=3, count=1024)
[1087] open("/etc/passwd", 0x0)
[1023] write(fd=3, count=1024)
[1056] read(fd=3, count=1024)

─────────────────────────────────────────────────────
Captured 5 events

Step 10: Cleanup...
✓ Programs closed
✓ Ring buffer closed

=== Lab 3.2 Complete! ===
```

## Understanding the Code

### Reading pt_regs Arguments

```clojure
(defn read-arg [ctx-reg arg-num dst-reg]
  (let [offset (case arg-num
                 0 PT_REGS_RDI  ; 112 bytes
                 1 PT_REGS_RSI  ; 104 bytes
                 ...)]
    [(bpf/load-mem :dw dst-reg ctx-reg offset)]))
```

Direct memory access to pt_regs structure at known offsets.

### Safe User String Reading

```clojure
;; Setup for bpf_probe_read_user_str()
[(bpf/mov-reg :r1 :r9)]          ; r1 = dst (kernel buffer)
[(bpf/add :r1 72)]                ; Offset to filename field
[(bpf/mov :r2 MAX_STRING_LEN)]   ; r2 = max size
[(bpf/mov-reg :r3 :r7)]          ; r3 = src (user pointer)
(bpf/helper-probe-read-user-str :r1 :r2 :r3)
```

The helper safely reads user memory and handles page faults.

### Ring Buffer Pattern

```clojure
;; Reserve space
(bpf/helper-ringbuf-reserve :r1 :r2)  ; Returns pointer or NULL

;; Fill data at returned pointer
[(bpf/store-mem :dw :r9 0 :r0)]  ; Write fields

;; Submit (makes data visible to userspace)
(bpf/helper-ringbuf-submit :r1)
```

Ring buffers provide efficient event streaming.

## Experiments

### Experiment 1: Capture execve() Arguments

```clojure
(defn create-execve-tracer [events-map-fd]
  ;; Read arg0 = filename
  (read-arg :r1 0 :r7)

  ;; Read arg1 = argv (array of string pointers)
  (read-arg :r1 1 :r8)

  ;; Read first argv element
  (bpf/helper-probe-read-user :r1 :r2 :r8)
  ;; Parse as array...
  ...)
```

### Experiment 2: Track Syscall Latency

```clojure
;; On sys_enter: store timestamp
(def enter-times-map (create-map :hash {...}))

;; In sys_enter handler:
(bpf/helper-ktime-get-ns)
[(bpf/store-mem :dw :r10 -8 :r0)]  ; Save timestamp

;; On sys_exit: calculate delta
;; delta = current_time - enter_time
```

### Experiment 3: Filter by Process Name

```clojure
;; Get current task's comm (process name)
[(bpf/mov-reg :r1 :r10)]
[(bpf/add :r1 -16)]  ; Stack buffer
[(bpf/mov :r2 16)]   ; Size
(bpf/helper-get-current-comm :r1 :r2)

;; Compare with target name
;; Use bpf_strncmp or manual byte comparison
```

### Experiment 4: Capture Return Values

```clojure
;; Attach to sys_exit tracepoint
;; Return value is in RAX register

(defn create-exit-tracer []
  ;; Read return value from pt_regs.rax
  [(bpf/load-mem :dw :r7 :r1 80)]  ; RAX offset = 80
  ;; Store in event...
  ...)
```

## Troubleshooting

### Error: "invalid mem access 'scalar'"

```
R1 invalid mem access 'scalar'
```

**Cause**: Using scalar value as pointer

**Solution**: Ensure register contains valid pointer:
```clojure
;; WRONG
[(bpf/mov :r1 0)]
(bpf/helper-probe-read-user :r1 :r2 :r3)

;; RIGHT
[(bpf/mov-reg :r1 :r10)]  ; Use stack pointer
[(bpf/add :r1 -16)]
(bpf/helper-probe-read-user :r1 :r2 :r3)
```

### Error: "helper access to variable size"

**Cause**: Size parameter must be constant or bounded

**Solution**: Use constant or verify bounds:
```clojure
;; Ensure size is bounded
[(bpf/mov :r2 MAX_STRING_LEN)]  ; Constant
;; Or:
[(bpf/jmp-imm :jgt :r2 MAX_STRING_LEN :error)]  ; Bound check
```

### Events Not Appearing

**Causes**:
1. Program not attached
2. No syscalls matching filter
3. Ring buffer full

**Debug**:
```bash
# Check if programs loaded
sudo bpftool prog list

# Check ring buffer stats
sudo bpftool map dump name events

# Kernel logs
sudo dmesg | tail
```

### Incorrect Offsets on Different Architecture

**Solution**: Detect architecture and use correct offsets:
```clojure
(defn get-pt-regs-offsets [arch]
  (case arch
    :x86-64 {:arg0 112 :arg1 104 :arg2 96 ...}
    :aarch64 {:arg0 0 :arg1 8 :arg2 16 ...}))
```

## Key Takeaways

✅ Syscall arguments are in CPU registers, accessed via pt_regs
✅ Use `bpf_probe_read_user()` for safe user memory access
✅ Ring buffers efficiently stream events to userspace
✅ Always bound string reads (MAX_STRING_LEN)
✅ pt_regs offsets are architecture-specific
✅ Event structures must be carefully aligned

## Next Steps

- **Next Lab**: [Lab 3.3 - Custom Protocol Parser](lab-3-3-protocol-parser.md)
- **Previous Lab**: [Lab 3.1 - Packet Filter](lab-3-1-packet-filter.md)
- **Chapter**: [Chapter 3 - BPF Instruction Set](../README.md)

## Challenge

Build a complete syscall tracer that:
1. Traces all syscalls (not just open/read/write)
2. Captures both enter and exit (with return values)
3. Calculates syscall latency
4. Filters by process name or PID
5. Exports data to JSON for analysis
6. Handles nested syscalls (from signal handlers)

Solution in: [solutions/lab-3-2-challenge.clj](../solutions/lab-3-2-challenge.clj)
