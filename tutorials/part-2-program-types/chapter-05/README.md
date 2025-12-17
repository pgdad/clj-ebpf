# Chapter 5: Kprobes & Kretprobes

**Duration**: 3-4 hours | **Difficulty**: Intermediate

## Learning Objectives

By the end of this chapter, you will:
- Understand kprobes and how they work
- Attach BPF programs to kernel functions
- Read function arguments from pt_regs
- Use kretprobes to capture return values
- Build practical tracing and monitoring tools
- Handle kernel version differences

## Prerequisites

- Completed [Part I: Fundamentals](../../part-1-fundamentals/)
- Understanding of Linux kernel concepts
- Familiarity with C function calling conventions
- Basic knowledge of kernel debugging

## 5.1 What are Kprobes?

### Overview

**Kprobes** (Kernel Probes) allow dynamic instrumentation of kernel functions:
- Insert breakpoints at (almost) any kernel instruction
- Execute handler code when breakpoint is hit
- Minimal overhead when not active
- No kernel recompilation needed

### How Kprobes Work

```
Original Function Flow:
┌─────────────────────────────────┐
│ vfs_read(file, buf, count)      │
│   ├─ check permissions          │
│   ├─ prepare buffer             │
│   ├─ call file_operations->read │
│   └─ return bytes_read          │
└─────────────────────────────────┘

With Kprobe:
┌─────────────────────────────────┐
│ vfs_read(file, buf, count)      │
│   ↓ [KPROBE FIRES]              │
│   ├─ Save registers             │
│   ├─ Execute BPF program        │ ← Your code runs here!
│   ├─ Restore registers          │
│   ↓                              │
│   ├─ check permissions          │
│   ├─ prepare buffer             │
│   └─ ...                         │
└─────────────────────────────────┘
```

### Kprobe Types

1. **Kprobe (entry)**: Fires at function entry
   - Access function arguments
   - Modify arguments (with caution)
   - Track function calls

2. **Kretprobe (return)**: Fires at function return
   - Access return value
   - Calculate function latency
   - Track success/failure

3. **Offset kprobe**: Fires at specific offset in function
   - Access local variables
   - Hook specific code paths
   - Advanced use case

## 5.2 Kprobe Architecture

### Attachment Flow

```
1. User Space                    2. Kernel Space
┌─────────────────┐              ┌─────────────────┐
│ Load BPF        │─────────────→│ BPF Verifier    │
│ Program         │              │                 │
└─────────────────┘              └────────┬────────┘
                                          │ ✓ Verified
                                          ▼
┌─────────────────┐              ┌─────────────────┐
│ Attach Kprobe   │─────────────→│ Insert Probe    │
│ to Function     │              │ at Function     │
└─────────────────┘              └────────┬────────┘
                                          │
                                          ▼
┌─────────────────┐              ┌─────────────────┐
│ Function        │              │ BPF Program     │
│ Executes        │─────────────→│ Runs on Event   │
└─────────────────┘              └─────────────────┘
```

### pt_regs Structure

When a kprobe fires, it receives a `struct pt_regs *` containing CPU register state:

```c
// x86_64
struct pt_regs {
    unsigned long r15, r14, r13, r12, rbp, rbx;
    unsigned long r11, r10, r9, r8;
    unsigned long rax, rcx, rdx, rsi, rdi;
    unsigned long orig_rax;
    unsigned long rip, cs, eflags;
    unsigned long rsp, ss;
};

// Function arguments on x86_64:
// arg0 = rdi (offset 112)
// arg1 = rsi (offset 104)
// arg2 = rdx (offset 96)
// arg3 = rcx (offset 88) or r10 (offset 56) for syscalls
// arg4 = r8  (offset 72)
// arg5 = r9  (offset 64)
```

### ARM64 Architecture

On ARM64, arguments are in different registers:

```c
struct pt_regs {
    u64 regs[31];  // x0-x30
    u64 sp;
    u64 pc;
    u64 pstate;
};

// Function arguments on ARM64:
// arg0 = x0 (offset 0)
// arg1 = x1 (offset 8)
// arg2 = x2 (offset 16)
// arg3 = x3 (offset 24)
// arg4 = x4 (offset 32)
// arg5 = x5 (offset 40)
```

## 5.3 Kretprobes

### Return Value Capture

Kretprobes intercept function returns:

```
Function Execution Timeline:
┌────────┬──────────────────┬──────────┐
│ Entry  │   Function Body  │  Return  │
│        │                  │          │
│ Kprobe │                  │ Kretprobe│
│ fires  │                  │ fires    │
│        │                  │          │
│ Get    │                  │ Get      │
│ args   │                  │ retval   │
└────────┴──────────────────┴──────────┘
```

### Return Value Location

Return values are in the same register (`rax` on x86_64, `x0` on ARM64):

```clojure
;; In kretprobe handler (x86_64):
;; r1 = pt_regs
[(bpf/load-mem :dw :r0 :r1 80)]  ; rax offset = 80
;; r0 now contains return value
```

### Entry-Exit Pairing

Track latency by pairing entry and exit:

```clojure
;; Kprobe (entry):
(bpf/helper-ktime-get-ns)
;; Store timestamp in map[PID] = timestamp

;; Kretprobe (exit):
(bpf/helper-ktime-get-ns)
;; current_time = r0
;; Lookup start_time from map[PID]
;; latency = current_time - start_time
```

## 5.4 Choosing Functions to Probe

### Finding Probeable Functions

```bash
# List all available kernel functions
sudo cat /proc/kallsyms | grep ' T ' | awk '{print $3}'

# Common functions to probe:
# VFS layer
vfs_read, vfs_write, vfs_open, vfs_close

# Network
tcp_sendmsg, tcp_recvmsg, ip_rcv, ip_output

# Process
do_fork, wake_up_new_task, do_exit

# File systems
ext4_file_read_iter, xfs_file_write_iter

# Memory
__alloc_pages_nodemask, __free_pages, kmem_cache_alloc
```

### Stability Considerations

Functions fall into different stability categories:

| Category | Examples | Stability |
|----------|----------|-----------|
| **Syscall handlers** | `__x64_sys_*` | Very stable |
| **VFS layer** | `vfs_read`, `vfs_write` | Stable |
| **Subsystem exports** | `tcp_sendmsg` | Mostly stable |
| **Internal helpers** | `__tcp_transmit_skb` | Unstable |
| **Static inlines** | Many macros | Cannot probe |

### BTF and CO-RE

Modern approach using BTF (BPF Type Format):
- Access to kernel structure definitions
- Portable across kernel versions
- Automatic field offset resolution

## 5.5 clj-ebpf Kprobe API

### Attaching Kprobes

```clojure
;; Create and load program
(def prog-fd (bpf/load-program program :kprobe))

;; Attach to function
(def link-fd (bpf/attach-kprobe prog-fd "vfs_read"))

;; Detach
(bpf/detach-kprobe link-fd)

;; Close
(bpf/close-program prog-fd)
```

### Attaching Kretprobes

```clojure
;; Load program
(def prog-fd (bpf/load-program program :kprobe))

;; Attach as kretprobe
(def link-fd (bpf/attach-kretprobe prog-fd "vfs_read"))
```

### Pattern: Entry-Exit Tracking

```clojure
(defn create-latency-tracker [function-name start-map-fd]
  ;; Entry program
  (def entry-prog
    (bpf/assemble
      (vec (concat
        (bpf/helper-get-current-pid-tgid)
        [(bpf/mov-reg :r6 :r0)]  ; Save PID
        (bpf/helper-ktime-get-ns)
        ;; Store timestamp in map[PID]
        ...))))

  ;; Exit program
  (def exit-prog
    (bpf/assemble
      (vec (concat
        (bpf/helper-get-current-pid-tgid)
        [(bpf/mov-reg :r6 :r0)]  ; PID
        (bpf/helper-ktime-get-ns)
        [(bpf/mov-reg :r7 :r0)]  ; end_time
        ;; Lookup start_time from map[PID]
        ;; Calculate: latency = end_time - start_time
        ...))))

  ;; Attach both
  (def entry-fd (bpf/load-program entry-prog :kprobe))
  (def exit-fd (bpf/load-program exit-prog :kprobe))
  (def entry-link (bpf/attach-kprobe entry-fd function-name))
  (def exit-link (bpf/attach-kretprobe exit-fd function-name)))
```

## 5.6 Common Patterns

### Pattern 1: Function Call Counting

```clojure
(defn create-call-counter [map-fd]
  (bpf/assemble
    (vec (concat
      ;; Get function pointer or identifier
      [(bpf/mov :r6 1)]  ; Function ID
      [(bpf/store-mem :w :r10 -4 :r6)]

      ;; Increment counter in map
      [(bpf/ld-map-fd :r1 map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :init)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]
      [(bpf/jmp :exit)]

      ;; :init
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -16 :r3)]
      [(bpf/ld-map-fd :r1 map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))
```

### Pattern 2: Argument Filtering

```clojure
(defn filter-by-argument [arg-num expected-value]
  (vec (concat
    ;; Read argument N
    [(bpf/load-mem :dw :r6 :r1 (arg-offset arg-num))]

    ;; Compare with expected
    [(bpf/jmp-imm :jne :r6 expected-value :skip)]

    ;; Process matching calls
    ...

    ;; :skip
    [(bpf/mov :r0 0)]
    [(bpf/exit-insn)])))
```

### Pattern 3: Return Value Checking

```clojure
(defn track-errors [map-fd]
  "Track functions that return errors (< 0)"
  (bpf/assemble
    (vec (concat
      ;; Get return value (in rax on x86_64)
      [(bpf/load-mem :dw :r6 :r1 80)]

      ;; Check if error (< 0)
      [(bpf/jsge-imm :r6 0 :exit)]  ; Skip if >= 0

      ;; Increment error counter
      ...

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))
```

## 5.7 Performance Considerations

### Overhead

Kprobes add overhead:
- **Entry overhead**: ~100-500ns per call
- **BPF program execution**: Depends on program complexity
- **Map operations**: ~50-200ns per operation

### Optimization Strategies

1. **Filter Early**: Reduce unnecessary work
   ```clojure
   ;; Filter by PID first
   (bpf/helper-get-current-pid-tgid)
   [(bpf/jmp-imm :jne :r0 TARGET_PID :exit)]
   ```

2. **Use Per-CPU Maps**: Avoid lock contention
   ```clojure
   (bpf/create-map :percpu-hash {...})
   ```

3. **Sampling**: Probe 1 in N calls
   ```clojure
   (bpf/helper-get-prandom-u32)
   [(bpf/mod :r0 100)]  ; 1 in 100
   [(bpf/jmp-imm :jne :r0 0 :exit)]
   ```

4. **Batch Updates**: Use ring buffers instead of perf buffers

## 5.8 Debugging Kprobes

### Common Issues

**1. Function Not Found**
```bash
# Check if function exists
sudo grep function_name /proc/kallsyms

# Check if it's inlined
sudo grep -A 10 function_name /proc/kallsyms
```

**2. Verifier Rejection**
```bash
# Check kernel logs
sudo dmesg | tail -50

# Look for verifier messages
# Common: invalid memory access, unbounded loop
```

**3. Attachment Fails**
```bash
# Check if function is traceable
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep function_name

# Some functions cannot be traced (blacklisted)
```

### Debugging Tools

```bash
# List attached kprobes
sudo cat /sys/kernel/debug/tracing/kprobe_events

# List active BPF programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id <ID>

# Dump program instructions
sudo bpftool prog dump xlated id <ID>
```

## 5.9 High-Level Kprobe DSL

clj-ebpf provides a high-level DSL for building kprobe programs that abstracts
away architecture-specific details like pt_regs offsets.

### The Kprobe DSL Module

```clojure
(require '[clj-ebpf.dsl.kprobe :as kprobe])
```

### Automatic Argument Extraction

Instead of manually calculating pt_regs offsets, use `kprobe-prologue`:

```clojure
;; Read first two function arguments into r6 and r7
(kprobe/kprobe-prologue [:r6 :r7])
;; Generates architecture-appropriate ldx instructions

;; With context pointer saved for later use
(kprobe/kprobe-prologue :r9 [:r6 :r7])
;; r9 = pt_regs pointer, r6 = arg0, r7 = arg1
```

This works on all supported architectures (x86_64, ARM64, s390x, PPC64LE, RISC-V).

### Building Complete Kprobe Programs

Use `build-kprobe-program` for a complete program structure:

```clojure
(kprobe/build-kprobe-program
  {:args [:r6 :r7]        ;; Function arguments to read
   :ctx-reg :r9           ;; Optional: save pt_regs pointer
   :body [...]            ;; Your program logic
   :return-value 0})      ;; Return value (default 0)
```

### Defining Kprobe Handlers with Macros

The `defkprobe-instructions` macro provides a clean way to define handlers:

```clojure
(kprobe/defkprobe-instructions tcp-connect-probe
  {:function "tcp_v4_connect"
   :args [:r6]}  ;; sk pointer in r6
  (concat
    (dsl/helper-get-current-pid-tgid)
    [(dsl/mov-reg :r7 :r0)]  ;; Save pid_tgid
    ;; ... your logic ...
    [(dsl/mov :r0 0)
     (dsl/exit-insn)]))

;; Use it:
(def program-bytes (dsl/assemble (tcp-connect-probe)))
```

### Kretprobe Return Values

For kretprobes, use `kretprobe-get-return-value`:

```clojure
;; Read function return value into r6
(kprobe/kretprobe-get-return-value :r1 :r6)
;; r1 = pt_regs, r6 = return value

;; Or use the macro:
(kprobe/defkretprobe-instructions tcp-connect-ret
  {:function "tcp_v4_connect"
   :ret-reg :r6}  ;; Return value in r6
  (concat
    ;; Check if error (return value < 0)
    [(dsl/jsge-imm :r6 0 :success)]
    ;; Handle error case...
    [(dsl/mov :r0 0)
     (dsl/exit-insn)]))
```

### Multi-Architecture Support

The DSL automatically handles architecture differences:

```clojure
(require '[clj-ebpf.arch :as arch])

;; Check current architecture
arch/current-arch  ;; => :x86_64

;; Get offset for argument N (handled automatically by prologue)
(arch/get-kprobe-arg-offset 0)  ;; => 112 on x86_64, 0 on ARM64
```

### Complete Example: Pure Clojure Kprobe

```clojure
(ns my-tracer
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.kprobe :as kprobe]
            [clj-ebpf.dsl.structs :as structs]))

;; Define event structure
(structs/defevent ExecEvent
  [:timestamp :u64]
  [:pid :u32]
  [:uid :u32])

;; Build kprobe program
(defn build-execve-tracer [ringbuf-fd]
  (dsl/assemble
    (vec (concat
      ;; Read filename arg into r7
      (kprobe/kprobe-prologue [:r7])

      ;; Get timestamp
      (dsl/helper-ktime-get-ns)
      [(dsl/mov-reg :r8 :r0)]

      ;; Reserve ring buffer space
      (dsl/ringbuf-reserve :r6 ringbuf-fd (structs/event-size ExecEvent))
      [(dsl/jmp-imm :jeq :r6 0 :exit)]

      ;; Store event data
      [(structs/store-event-field :r6 ExecEvent :timestamp :r8)]

      ;; Get and store PID
      (dsl/helper-get-current-pid-tgid)
      [(dsl/and-imm :r0 0xffffffff)
       (structs/store-event-field :r6 ExecEvent :pid :r0)]

      ;; Submit event
      (dsl/ringbuf-submit :r6)

      ;; Exit
      [[:label :exit]
       (dsl/mov :r0 0)
       (dsl/exit-insn)]))))
```

## Labs

This chapter includes four hands-on labs:

### Lab 5.1: Function Call Tracer
Basic kprobe attachment and argument reading

### Lab 5.2: Latency Profiler
Use kprobe + kretprobe for function latency measurement

### Lab 5.3: System Call Monitor
Comprehensive syscall monitoring with arguments and return values

### Lab 5.4: Pure Clojure Kprobe
Build a complete kprobe using the high-level DSL without external compilers

## Navigation

- **Next**: [Lab 5.1 - Function Call Tracer](labs/lab-5-1-function-tracer.md)
- **Previous**: [Chapter 4 - Helper Functions](../../part-1-fundamentals/chapter-04/README.md)
- **Up**: [Part II - Program Types](../../part-2-program-types/)
- **Home**: [Tutorial Home](../../README.md)

## Additional Resources

- [Linux Kprobes Documentation](https://www.kernel.org/doc/html/latest/trace/kprobes.html)
- [BPF Kprobe Attachment](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [Brendan Gregg's Kprobe Guide](http://www.brendangregg.com/blog/2015-06-28/linux-ftrace-kprobe.html)
- [Kernel Function Graph](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
