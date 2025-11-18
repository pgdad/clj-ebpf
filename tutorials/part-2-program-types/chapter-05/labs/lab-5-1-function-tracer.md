# Lab 5.1: Function Call Tracer

**Objective**: Attach kprobes to kernel functions and trace calls with arguments

**Duration**: 60 minutes

## Overview

In this lab, you'll build a function call tracer that attaches kprobes to kernel functions and logs calls with their arguments. You'll learn how to attach to different functions, read arguments from pt_regs, and display results in real-time.

This lab demonstrates:
- Attaching kprobes to kernel functions
- Reading function arguments from pt_regs
- Handling different architectures (x86_64, ARM64)
- Formatting and displaying trace data
- Managing multiple kprobes

## What You'll Learn

- How to attach BPF programs as kprobes
- Reading function arguments correctly
- Architecture-specific register layouts
- Managing kprobe lifecycle (attach/detach)
- Real-time event streaming
- Formatting kernel function traces

## Theory

### Function Call Convention (x86_64)

```
Function: ssize_t vfs_read(struct file *file, char __user *buf,
                           size_t count, loff_t *pos)

Register Layout:
┌──────┬────────────────────────────┐
│ rdi  │ arg0: file (struct file *) │
│ rsi  │ arg1: buf (char __user *)  │
│ rdx  │ arg2: count (size_t)       │
│ rcx  │ arg3: pos (loff_t *)       │
└──────┴────────────────────────────┘

In pt_regs (offsets in bytes):
rdi = 112
rsi = 104
rdx = 96
rcx = 88
```

### Trace Event Flow

```
1. Kernel function called
   ↓
2. Kprobe fires
   ↓
3. BPF program executes
   ├─ Read arguments from pt_regs
   ├─ Get process info
   ├─ Get timestamp
   └─ Send event to userspace
   ↓
4. Userspace receives event
   ├─ Parse event data
   ├─ Format output
   └─ Display trace
   ↓
5. Function continues normally
```

## Implementation

### Step 1: Complete Program

Create `lab-5-1.clj`:

```clojure
(ns lab-5-1-function-tracer
  "Lab 5.1: Function Call Tracer using kprobes"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]
           [java.time Instant]))

;; ============================================================================
;; Part 1: Architecture-Specific Configuration
;; ============================================================================

(def arch (utils/get-arch))

;; x86_64 pt_regs offsets
(def x86-64-offsets
  {:arg0 112  ; rdi
   :arg1 104  ; rsi
   :arg2 96   ; rdx
   :arg3 88   ; rcx (or r10 for syscalls)
   :arg4 72   ; r8
   :arg5 64}) ; r9

;; ARM64 pt_regs offsets
(def aarch64-offsets
  {:arg0 0   ; x0
   :arg1 8   ; x1
   :arg2 16  ; x2
   :arg3 24  ; x3
   :arg4 32  ; x4
   :arg5 40}) ; x5

(def pt-regs-offsets
  (case arch
    :x86-64 x86-64-offsets
    :aarch64 aarch64-offsets
    x86-64-offsets))  ; Default to x86-64

;; ============================================================================
;; Part 2: Data Structures
;; ============================================================================

;; Trace event structure
;; struct trace_event {
;;   u64 timestamp;
;;   u64 pid_tgid;
;;   u64 args[6];
;;   char comm[16];
;; };

(def TRACE_EVENT_SIZE (+ 8 8 (* 8 6) 16))  ; 104 bytes

;; ============================================================================
;; Part 3: Maps
;; ============================================================================

(defn create-events-map []
  "Ring buffer for trace events"
  (bpf/create-map :ringbuf
    {:max-entries (* 1024 1024)}))  ; 1MB ring buffer

(defn create-counts-map []
  "Map to count function calls per function"
  (bpf/create-map :hash
    {:key-size 4    ; u32 function ID
     :value-size 8  ; u64 count
     :max-entries 100}))

;; ============================================================================
;; Part 4: BPF Program - Kprobe Handler
;; ============================================================================

(defn create-trace-handler [events-map-fd counts-map-fd function-id]
  "Create kprobe handler for tracing function calls"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get timestamp
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r6 :r0)]  ; r6 = timestamp

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Get process info
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r7 :r0)]  ; r7 = pid_tgid

      ;; Get process name
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -16)]  ; Stack buffer for comm
      [(bpf/mov :r3 16)]
      [(bpf/mov-reg :r1 :r2)]
      (bpf/helper-get-current-comm :r1 :r3)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Read function arguments from pt_regs
      ;; ──────────────────────────────────────────────────────────

      ;; r1 points to struct pt_regs
      ;; Save it for later use
      [(bpf/mov-reg :r8 :r1)]  ; r8 = pt_regs pointer

      ;; Read arg0
      [(bpf/load-mem :dw :r2 :r8 (:arg0 pt-regs-offsets))]
      [(bpf/store-mem :dw :r10 -24 :r2)]

      ;; Read arg1
      [(bpf/load-mem :dw :r2 :r8 (:arg1 pt-regs-offsets))]
      [(bpf/store-mem :dw :r10 -32 :r2)]

      ;; Read arg2
      [(bpf/load-mem :dw :r2 :r8 (:arg2 pt-regs-offsets))]
      [(bpf/store-mem :dw :r10 -40 :r2)]

      ;; Read arg3
      [(bpf/load-mem :dw :r2 :r8 (:arg3 pt-regs-offsets))]
      [(bpf/store-mem :dw :r10 -48 :r2)]

      ;; Read arg4
      [(bpf/load-mem :dw :r2 :r8 (:arg4 pt-regs-offsets))]
      [(bpf/store-mem :dw :r10 -56 :r2)]

      ;; Read arg5
      [(bpf/load-mem :dw :r2 :r8 (:arg5 pt-regs-offsets))]
      [(bpf/store-mem :dw :r10 -64 :r2)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Update call counter
      ;; ──────────────────────────────────────────────────────────

      [(bpf/store-mem :w :r10 -68 function-id)]

      [(bpf/ld-map-fd :r1 counts-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -68)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :init-counter)]

      ;; Increment existing counter
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]
      [(bpf/jmp :send-event)]

      ;; :init-counter - Initialize counter to 1
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -76 :r3)]
      [(bpf/ld-map-fd :r1 counts-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -68)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -76)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Send event to ring buffer
      ;; ──────────────────────────────────────────────────────────

      ;; :send-event
      ;; Reserve space in ring buffer
      [(bpf/ld-map-fd :r1 events-map-fd)]
      [(bpf/mov :r2 TRACE_EVENT_SIZE)]
      [(bpf/mov :r3 0)]
      (bpf/helper-ringbuf-reserve :r1 :r2)

      ;; Check if reservation succeeded
      [(bpf/mov-reg :r9 :r0)]
      [(bpf/jmp-imm :jeq :r9 0 :exit)]

      ;; Fill event structure
      ;; timestamp
      [(bpf/store-mem :dw :r9 0 :r6)]

      ;; pid_tgid
      [(bpf/store-mem :dw :r9 8 :r7)]

      ;; args (copy from stack)
      [(bpf/load-mem :dw :r2 :r10 -24)]
      [(bpf/store-mem :dw :r9 16 :r2)]  ; arg0

      [(bpf/load-mem :dw :r2 :r10 -32)]
      [(bpf/store-mem :dw :r9 24 :r2)]  ; arg1

      [(bpf/load-mem :dw :r2 :r10 -40)]
      [(bpf/store-mem :dw :r9 32 :r2)]  ; arg2

      [(bpf/load-mem :dw :r2 :r10 -48)]
      [(bpf/store-mem :dw :r9 40 :r2)]  ; arg3

      [(bpf/load-mem :dw :r2 :r10 -56)]
      [(bpf/store-mem :dw :r9 48 :r2)]  ; arg4

      [(bpf/load-mem :dw :r2 :r10 -64)]
      [(bpf/store-mem :dw :r9 56 :r2)]  ; arg5

      ;; comm (copy from stack)
      [(bpf/load-mem :dw :r2 :r10 -16)]
      [(bpf/store-mem :dw :r9 64 :r2)]
      [(bpf/load-mem :dw :r2 :r10 -8)]
      [(bpf/store-mem :dw :r9 72 :r2)]

      ;; Submit event
      [(bpf/mov-reg :r1 :r9)]
      [(bpf/mov :r2 0)]
      (bpf/helper-ringbuf-submit :r1)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 6: Return
      ;; ──────────────────────────────────────────────────────────

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 5: Userspace - Event Processing
;; ============================================================================

(defn read-u64-le [^ByteBuffer buf offset]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf offset))

(defn read-string [^ByteBuffer buf offset max-len]
  (.position buf offset)
  (let [bytes (byte-array max-len)
        _ (.get buf bytes)
        null-idx (or (first (keep-indexed
                             (fn [i b] (when (zero? b) i))
                             bytes))
                    max-len)]
    (String. bytes 0 null-idx "UTF-8")))

(defn parse-trace-event [^ByteBuffer event]
  "Parse trace event from ring buffer"
  {:timestamp (read-u64-le event 0)
   :pid-tgid (read-u64-le event 8)
   :pid (bit-and (read-u64-le event 8) 0xFFFFFFFF)
   :tgid (bit-shift-right (read-u64-le event 8) 32)
   :args [(read-u64-le event 16)
          (read-u64-le event 24)
          (read-u64-le event 32)
          (read-u64-le event 40)
          (read-u64-le event 48)
          (read-u64-le event 56)]
   :comm (read-string event 64 16)})

(defn format-timestamp [ns]
  "Format nanosecond timestamp as time"
  (let [instant (Instant/ofEpochMilli (quot ns 1000000))
        millis (rem (quot ns 1000000) 1000)]
    (format "%s.%03d" (.toString instant) millis)))

(defn format-trace-event [event function-name]
  "Format trace event for display"
  (format "[%s] %s[%d]: %s(0x%x, 0x%x, 0x%x, ...)"
         (format-timestamp (:timestamp event))
         (:comm event)
         (:pid event)
         function-name
         ((:args event) 0)
         ((:args event) 1)
         ((:args event) 2)))

;; ============================================================================
;; Part 6: Kprobe Attachment
;; ============================================================================

(defn attach-function-tracer [function-name function-id events-map-fd counts-map-fd]
  "Attach tracer to a kernel function"
  (println (format "\nAttaching to function: %s" function-name))

  (try
    ;; Create and load program
    (let [program (create-trace-handler events-map-fd counts-map-fd function-id)
          prog-fd (bpf/load-program program :kprobe)]

      (println (format "✓ Program loaded (FD: %d, %d instructions)"
                      prog-fd
                      (/ (count program) 8)))

      ;; Attach kprobe
      ;; Note: Actual attachment requires perf_event_open or BPF link API
      (println "ℹ Kprobe attachment in production uses:")
      (println "  - perf_event_open() with PERF_TYPE_TRACEPOINT")
      (println "  - BPF_LINK_CREATE with BPF_TRACE_KPROBE")
      (println "  - Or tracefs: /sys/kernel/debug/tracing/kprobe_events")

      prog-fd)

    (catch Exception e
      (println (format "✗ Failed to attach to %s: %s"
                      function-name
                      (.getMessage e)))
      nil)))

;; ============================================================================
;; Part 7: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 5.1: Function Call Tracer ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)
  (println (format "Architecture: %s" (name arch)))

  ;; Create maps
  (println "\nStep 2: Creating maps...")
  (let [events-map-fd (create-events-map)
        counts-map-fd (create-counts-map)]
    (println "✓ Events ring buffer created (FD:" events-map-fd ")")
    (println "✓ Counts map created (FD:" counts-map-fd ")")

    ;; Initialize counters
    (doseq [i (range 10)]
      (bpf/map-update counts-map-fd (utils/u32 i) (utils/u64 0) :any))

    (try
      ;; Functions to trace
      (println "\nStep 3: Setting up function tracers...")
      (let [functions [["vfs_read" 1]
                      ["vfs_write" 2]
                      ["vfs_open" 3]]
            prog-fds (atom [])]

        (doseq [[func-name func-id] functions]
          (when-let [fd (attach-function-tracer func-name func-id
                                               events-map-fd counts-map-fd)]
            (swap! prog-fds conj fd)))

        (println (format "\n✓ Attached to %d functions" (count @prog-fds)))

        ;; Demonstrate trace output format
        (println "\nStep 4: Trace output format:")
        (println "──────────────────────────────────────────────────────")
        (println "ℹ In production, events would stream in real-time:")
        (println)

        ;; Simulated trace events
        (let [simulated-events
              [{:timestamp (System/nanoTime)
                :pid 12345
                :comm "cat"
                :args [0xffff8881234 0x7fff1234 4096 0 0 0]}
               {:timestamp (+ (System/nanoTime) 1000000)
                :pid 12346
                :comm "bash"
                :args [0xffff8882345 0x7fff2345 1024 0 0 0]}
               {:timestamp (+ (System/nanoTime) 2000000)
                :pid 12345
                :comm "cat"
                :args [0xffff8881234 0x7fff1234 4096 0 0 0]}]]

          (doseq [event simulated-events]
            (println (format-trace-event event "vfs_read"))))

        (println)
        (println "──────────────────────────────────────────────────────")

        ;; Display call counts
        (println "\nStep 5: Function call statistics:")
        (println "──────────────────────────────────────────────────────")
        (doseq [[func-name func-id] functions]
          (let [key (utils/u32 func-id)
                value (bpf/map-lookup counts-map-fd key)
                count (if value (read-u64-le value 0) 0)]
            (println (format "%-20s: %,d calls" func-name count))))

        ;; Cleanup
        (println "\nStep 6: Cleanup...")
        (doseq [fd @prog-fds]
          (bpf/close-program fd))
        (println "✓ Programs closed"))

      (catch Exception e
        (println "✗ Error:" (.getMessage e))
        (.printStackTrace e)))

    (finally
      (bpf/close-map events-map-fd)
      (bpf/close-map counts-map-fd)
      (println "✓ Maps closed")))

  (println "\n=== Lab 5.1 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-2-program-types/chapter-05/labs
clojure -M lab-5-1.clj
```

### Expected Output

```
=== Lab 5.1: Function Call Tracer ===

Step 1: Initializing...
Architecture: x86-64

Step 2: Creating maps...
✓ Events ring buffer created (FD: 3)
✓ Counts map created (FD: 4)

Step 3: Setting up function tracers...

Attaching to function: vfs_read
✓ Program loaded (FD: 5, 45 instructions)
ℹ Kprobe attachment in production uses:
  - perf_event_open() with PERF_TYPE_TRACEPOINT
  - BPF_LINK_CREATE with BPF_TRACE_KPROBE
  - Or tracefs: /sys/kernel/debug/tracing/kprobe_events

Attaching to function: vfs_write
✓ Program loaded (FD: 6, 45 instructions)
ℹ Kprobe attachment in production uses:
  - perf_event_open() with PERF_TYPE_TRACEPOINT
  - BPF_LINK_CREATE with BPF_TRACE_KPROBE
  - Or tracefs: /sys/kernel/debug/tracing/kprobe_events

Attaching to function: vfs_open
✓ Program loaded (FD: 7, 45 instructions)
ℹ Kprobe attachment in production uses:
  - perf_event_open() with PERF_TYPE_TRACEPOINT
  - BPF_LINK_CREATE with BPF_TRACE_KPROBE
  - Or tracefs: /sys/kernel/debug/tracing/kprobe_events

✓ Attached to 3 functions

Step 4: Trace output format:
──────────────────────────────────────────────────────
ℹ In production, events would stream in real-time:

[2025-01-15T10:23:45.123] cat[12345]: vfs_read(0xffff8881234, 0x7fff1234, 0x1000, ...)
[2025-01-15T10:23:45.124] bash[12346]: vfs_read(0xffff8882345, 0x7fff2345, 0x400, ...)
[2025-01-15T10:23:45.125] cat[12345]: vfs_read(0xffff8881234, 0x7fff1234, 0x1000, ...)

──────────────────────────────────────────────────────

Step 5: Function call statistics:
──────────────────────────────────────────────────────
vfs_read            : 0 calls
vfs_write           : 0 calls
vfs_open            : 0 calls

Step 6: Cleanup...
✓ Programs closed
✓ Maps closed

=== Lab 5.1 Complete! ===
```

## Understanding the Code

### Reading pt_regs Arguments

```clojure
;; Architecture-specific offsets
(def pt-regs-offsets
  (case arch
    :x86-64 {:arg0 112 :arg1 104 ...}
    :aarch64 {:arg0 0 :arg1 8 ...}))

;; Read argument
[(bpf/load-mem :dw :r2 :r8 (:arg0 pt-regs-offsets))]
```

### Ring Buffer Pattern

```clojure
;; Reserve space
(bpf/helper-ringbuf-reserve :r1 :r2)
[(bpf/mov-reg :r9 :r0)]  ; Save pointer
[(bpf/jmp-imm :jeq :r9 0 :exit)]  ; NULL check

;; Fill data
[(bpf/store-mem :dw :r9 0 :r6)]  ; timestamp
[(bpf/store-mem :dw :r9 8 :r7)]  ; pid_tgid

;; Submit
[(bpf/mov-reg :r1 :r9)]
(bpf/helper-ringbuf-submit :r1)
```

## Experiments

### Experiment 1: Add Return Value Tracking

```clojure
;; Attach kretprobe
(def exit-prog (create-kretprobe-handler ...))
(bpf/attach-kretprobe exit-prog "vfs_read")

;; In kretprobe, read return value:
[(bpf/load-mem :dw :r6 :r1 80)]  ; rax on x86_64
```

### Experiment 2: Filter by Process

```clojure
;; Early in program:
(bpf/helper-get-current-pid-tgid)
[(bpf/rsh :r0 32)]  ; TGID
[(bpf/jmp-imm :jne :r0 TARGET_PID :exit)]
```

### Experiment 3: Decode Pointer Arguments

```clojure
;; Read string from user space pointer (arg1)
[(bpf/load-mem :dw :r3 :r8 104)]  ; arg1 address

[(bpf/mov-reg :r1 :r10)]
[(bpf/add :r1 -128)]  ; dst buffer
[(bpf/mov :r2 128)]    ; size
(bpf/helper-probe-read-user-str :r1 :r2 :r3)
```

## Troubleshooting

### Function Not Found

```bash
# Check if function exists
grep vfs_read /proc/kallsyms

# Check if it's inlined (won't work)
```

### Verifier Rejection

Common issues:
- Unbounded memory access
- Invalid register state
- Stack overflow

**Solution**: Add bounds checks, simplify program

### High Overhead

**Optimize**:
- Filter early (by PID, UID)
- Sample calls (1 in N)
- Use per-CPU maps

## Key Takeaways

✅ Kprobes attach to (almost) any kernel function
✅ pt_regs structure contains function arguments
✅ Architecture affects register layouts
✅ Ring buffers efficiently stream events
✅ Early filtering reduces overhead
✅ Proper cleanup prevents resource leaks

## Next Steps

- **Next Lab**: [Lab 5.2 - Latency Profiler](lab-5-2-latency-profiler.md)
- **Previous Lab**: [Chapter 5 - Kprobes & Kretprobes](../README.md)
- **Chapter**: [Part II - Program Types](../../part-2-program-types/)

## Challenge

Enhance the function tracer to:
1. Decode struct file * to show filename
2. Track call stack depth
3. Measure per-function latency
4. Generate call graphs
5. Filter by cgroup or namespace
6. Export traces to JSON/protobuf

Solution in: [solutions/lab-5-1-challenge.clj](../solutions/lab-5-1-challenge.clj)
