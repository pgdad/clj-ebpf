# Lab 5.4: Pure Clojure Kprobe

**Duration**: 45 minutes | **Difficulty**: Intermediate

## Objectives

In this lab, you will:
1. Use the `defevent` macro to define BPF event structures
2. Build a kprobe program using the high-level DSL
3. Use `kprobe-prologue` for portable argument extraction
4. Send events to userspace via ring buffer DSL
5. Create a complete tracer without external compilers

## Prerequisites

- Completed Labs 5.1-5.3
- Understanding of BPF program structure
- Familiarity with ring buffers (Chapter 13)

## Background

Traditional BPF development requires:
1. Writing C code
2. Compiling with clang/LLVM
3. Parsing the resulting ELF file
4. Loading and attaching

The clj-ebpf kprobe DSL eliminates these steps by:
- Generating BPF bytecode directly from Clojure
- Abstracting architecture-specific details
- Providing high-level macros for common patterns

## Part 1: Event Structure Definition

### Task 1.1: Define a Process Event Structure

Create an event structure for tracking process execution:

```clojure
(ns lab-5-4-pure-clojure-kprobe
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.kprobe :as kprobe]
            [clj-ebpf.dsl.structs :as structs]
            [clj-ebpf.arch :as arch]))

;; TODO: Define ProcessExecEvent with:
;; - timestamp (u64) - when the event occurred
;; - pid (u32) - process ID
;; - tgid (u32) - thread group ID (parent)
;; - uid (u32) - user ID
;; - ppid (u32) - parent process ID
;; - comm (char, 16 bytes) - command name
```

**Hint**: Use `structs/defevent` with field specifications like `[:fieldname :type]` or `[:fieldname :type count]` for arrays.

### Task 1.2: Query the Structure

Verify your structure definition:

```clojure
;; Check total size
(structs/event-size ProcessExecEvent)
;; Expected: 40 bytes

;; Check field offsets
(structs/event-field-offset ProcessExecEvent :timestamp)  ;; => 0
(structs/event-field-offset ProcessExecEvent :pid)        ;; => 8
(structs/event-field-offset ProcessExecEvent :comm)       ;; => 24

;; List all fields
(structs/event-fields ProcessExecEvent)
```

## Part 2: Building the Kprobe Program

### Task 2.1: Create the Prologue

Use `kprobe-prologue` to read function arguments:

```clojure
(defn build-exec-tracer-prologue []
  ;; For do_execveat_common:
  ;; arg0 = fd (int)
  ;; arg1 = filename (struct filename *)
  ;; arg2 = argv (struct user_arg_ptr)
  ;; arg3 = envp (struct user_arg_ptr)
  ;; arg4 = flags (int)

  ;; TODO: Create prologue that:
  ;; 1. Saves pt_regs pointer to r9
  ;; 2. Reads filename (arg1) into r7
  (kprobe/kprobe-prologue ??? ???))
```

### Task 2.2: Build the Complete Program

Create a program that:
1. Reads function arguments
2. Gets timestamp, PID, and UID
3. Reserves ring buffer space
4. Fills the event structure
5. Submits to ring buffer

```clojure
(defn build-exec-tracer [ringbuf-fd]
  (let [event-size (structs/event-size ProcessExecEvent)]
    (dsl/assemble
      (vec (concat
        ;; === Prologue ===
        ;; TODO: Read filename arg into r7, save context to r9

        ;; === Get Timestamp ===
        (dsl/helper-ktime-get-ns)
        [(dsl/mov-reg :r8 :r0)]  ; Save timestamp in r8

        ;; === Get PID/TGID ===
        ;; TODO: Call helper and extract PID (lower 32 bits) and TGID (upper 32 bits)

        ;; === Get UID/GID ===
        ;; TODO: Call helper

        ;; === Reserve Ring Buffer Space ===
        ;; TODO: Use dsl/ringbuf-reserve with event-size
        ;; Check for NULL (reservation failed)

        ;; === Fill Event Structure ===
        ;; TODO: Use structs/store-event-field for each field

        ;; === Submit Event ===
        ;; TODO: Use dsl/ringbuf-submit

        ;; === Exit ===
        [(dsl/mov :r0 0)
         (dsl/exit-insn)])))))
```

## Part 3: Using the defkprobe-instructions Macro

### Task 3.1: Refactor Using the Macro

The `defkprobe-instructions` macro provides a cleaner syntax:

```clojure
(kprobe/defkprobe-instructions exec-entry-handler
  {:function "do_execveat_common"
   :args [:r7]}  ; filename in r7
  ;; Body - return vector of instructions
  (concat
    ;; TODO: Your program logic here
    ;; The prologue is automatically generated!

    [(dsl/mov :r0 0)
     (dsl/exit-insn)]))

;; Use it:
(def my-program (dsl/assemble (exec-entry-handler)))
```

### Task 3.2: Create a Kretprobe Handler

Create a return probe to capture the execve result:

```clojure
(kprobe/defkretprobe-instructions exec-return-handler
  {:function "do_execveat_common"
   :ret-reg :r6}  ; Return value in r6
  (concat
    ;; Check if return value indicates error (< 0)
    ;; TODO: Jump if r6 >= 0 (success)

    ;; Handle error case - maybe increment error counter

    [(dsl/mov :r0 0)
     (dsl/exit-insn)]))
```

## Part 4: Integration

### Task 4.1: Complete Tracer Implementation

Put it all together:

```clojure
(defn create-exec-tracer []
  ;; Create ring buffer
  (let [ringbuf (maps/create-ringbuf-map (* 256 1024)
                                         :map-name "exec_events")]
    ;; Build program
    (let [prog-bytes (build-exec-tracer (:fd ringbuf))]

      ;; Load program
      (bpf/with-program [prog {:prog-type :kprobe
                               :insns prog-bytes
                               :license "GPL"
                               :prog-name "exec_trace"}]
        ;; Attach to function
        (let [attached (programs/attach-kprobe prog
                         {:function "do_execveat_common"})]

          ;; Return resources for cleanup
          {:program prog
           :ringbuf ringbuf
           :attachment attached})))))
```

### Task 4.2: Event Processing

Parse events from the ring buffer:

```clojure
(defn parse-exec-event [data]
  ;; TODO: Extract fields from byte array using event structure offsets
  {:timestamp (extract-u64 data 0)
   :pid (extract-u32 data 8)
   :tgid (extract-u32 data 12)
   :uid (extract-u32 data 16)
   :ppid (extract-u32 data 20)
   :comm (extract-string data 24 16)})

(defn run-tracer [duration-ms]
  (let [{:keys [program ringbuf]} (create-exec-tracer)]
    (try
      (loop [end-time (+ (System/currentTimeMillis) duration-ms)]
        (when (< (System/currentTimeMillis) end-time)
          (when-let [data (events/poll-ringbuf ringbuf 100)]
            (println (parse-exec-event data)))
          (recur end-time)))
      (finally
        ;; Cleanup
        (maps/close-map ringbuf)))))
```

## Verification

Test your implementation:

```clojure
;; 1. Check structure size
(assert (= 40 (structs/event-size ProcessExecEvent)))

;; 2. Check prologue generation
(let [prologue (kprobe/kprobe-prologue :r9 [:r7])]
  (assert (= 2 (count prologue))))  ; mov + ldx

;; 3. Build program and check size
(let [prog (build-exec-tracer 5)]
  (assert (bytes? prog))
  (assert (> (count prog) 100)))  ; Should have many instructions

;; 4. Test architecture detection
(println "Architecture:" arch/current-arch)
(println "Arg0 offset:" (arch/get-kprobe-arg-offset 0))
```

## Challenge: Add More Features

1. **Filter by UID**: Only trace executions by specific user
2. **Capture Filename**: Read the actual filename string
3. **Track Parent Process**: Get parent PID and command
4. **Latency Tracking**: Use entry + exit probes to measure exec time

## Solution

See `solutions/lab_5_4_pure_clojure_kprobe.clj` for the complete implementation.

## Key Takeaways

1. **defevent** provides type-safe structure definitions with automatic offset calculation
2. **kprobe-prologue** abstracts architecture-specific pt_regs layouts
3. **Ring buffer DSL** (ringbuf-reserve, ringbuf-submit) simplifies event output
4. **defkprobe-instructions** macro provides clean syntax for defining handlers
5. Programs built with the DSL are **portable across architectures**

## Navigation

- **Previous**: [Lab 5.3 - System Call Monitor](lab-5-3-syscall-monitor.md)
- **Next**: [Chapter 6 - Tracepoints](../../chapter-06/README.md)
- **Up**: [Chapter 5 - Kprobes](../README.md)
