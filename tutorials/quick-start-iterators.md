# Quick Start: BPF Iterators for Kernel Data Dumping

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Learning Objectives

By the end of this tutorial, you will:
- Understand BPF Iterator (bpf_iter) architecture and workflow
- Know how to build programs that iterate over kernel data structures
- Use DSL helpers for context access and output writing
- Understand the different iterator types (task, map, tcp, etc.)
- Build custom data dumping programs

## Prerequisites

- Basic clj-ebpf knowledge (maps, programs, DSL)
- Understanding of kernel data structures (task_struct, sock, etc.)
- Familiarity with `/proc` filesystem concepts
- Linux kernel 5.8+ with BTF support
- Root privileges for running examples

## Introduction

### What are BPF Iterators?

BPF Iterators (bpf_iter) allow BPF programs to **iterate over kernel data structures** and dump their contents. They're designed as a replacement for `/proc` files like `/proc/net/tcp`, providing more flexible, efficient, and customizable data dumping.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                      BPF Iterator Workflow                          │
└─────────────────────────────────────────────────────────────────────┘

  1. Load iterator program (type: TRACING, attach: TRACE_ITER)
        │
        v
┌─────────────────────────────────────────────────────────────────────┐
│   2. Create BPF link with iterator type info                        │
│      bpf_link_create(prog_fd, 0, BPF_TRACE_ITER, ...)              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               v
┌─────────────────────────────────────────────────────────────────────┐
│   3. Create iterator FD from link                                   │
│      bpf_iter_create(link_fd, ...)                                 │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               v
┌─────────────────────────────────────────────────────────────────────┐
│   4. Read from iterator FD                                          │
│      ┌──────────────────────────────────────────────────────────┐  │
│      │  For each element in kernel data structure:              │  │
│      │    - BPF program is invoked with element context         │  │
│      │    - Program uses bpf_seq_write/bpf_seq_printf          │  │
│      │    - Returns 0 to continue, 1 to stop early             │  │
│      └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               v
┌─────────────────────────────────────────────────────────────────────┐
│   5. Close iterator FD, link, and program                           │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Differences from Other BPF Program Types

| Aspect | Regular BPF (kprobe, XDP) | BPF Iterators |
|--------|--------------------------|---------------|
| Trigger | Events (syscall, packet) | Reading from FD |
| Output | Maps, perf/ring buffers | Direct file read |
| Invocation | Once per event | Once per element |
| Control flow | Always continues | Can stop early |
| Use case | Tracing, filtering | Data dumping |

### Iterator Types

| Type | Description | Context Field |
|------|-------------|---------------|
| `task` | All processes/threads | `task_struct *task` |
| `task_file` | Files per task | `file *file` |
| `bpf_map` | All BPF maps | `bpf_map *map` |
| `bpf_map_elem` | Elements in a map | `key, value` |
| `bpf_prog` | All BPF programs | `bpf_prog *prog` |
| `bpf_link` | All BPF links | `bpf_link *link` |
| `tcp` | TCP sockets | `sock *tcp_sk` |
| `udp` | UDP sockets | `sock *udp_sk` |
| `unix` | Unix sockets | `sock *unix_sk` |
| `netlink` | Netlink sockets | `sock *netlink_sk` |

---

## Part 1: Understanding Iterator Contexts

### Context Structure

All iterator contexts share a common structure:

```clojure
(require '[clj-ebpf.dsl.iter :as iter])

;; Common context offsets
iter/iter-context-offsets
;; => {:meta       0    ; bpf_iter_meta pointer (always first)
;;     :task       8    ; struct task_struct * (for task iterator)
;;     :map        8    ; struct bpf_map * (for bpf_map iterator)
;;     :key        8    ; void * (for bpf_map_elem)
;;     :value      16   ; void * (for bpf_map_elem)
;;     :prog       8    ; struct bpf_prog * (for bpf_prog iterator)
;;     :tcp-sk     8    ; struct sock * (for tcp iterator)
;;     ...}

;; Meta structure offsets
iter/iter-meta-offsets
;; => {:seq        0    ; seq_file * (for output)
;;     :session-id 8    ; u64
;;     :seq-num    16}  ; u64
```

### NULL Pointer at End of Iteration

When iteration completes, the element pointer is NULL:

```clojure
;; Task iterator: task is NULL at end
;; BPF map iterator: map is NULL at end
;; etc.

;; Your program must check for NULL!
```

---

## Part 2: Building Iterator Programs

### Basic Program Structure

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.iter :as iter])

;; Minimal iterator program - just continues
(def minimal-iter-insns
  (vec (concat
        ;; Save context pointer in r6
        (iter/iter-prologue :r6)
        ;; Return 0 to continue iteration
        (iter/iter-return-continue))))

;; Assemble to bytecode
(def bytecode (dsl/assemble minimal-iter-insns))
```

### Prologue Variations

```clojure
;; Basic prologue - just save context
(iter/iter-prologue :r6)
;; => [(mov-reg r6 r1)]

;; Prologue with meta pointer
(iter/iter-prologue-with-meta :r6 :r8)
;; => [(mov-reg r6 r1)
;;     (ldx dw r8 r6 0)]  ; r8 = ctx->meta
```

### Loading Context Fields

```clojure
;; Load pointer from context
(iter/iter-load-ctx-ptr :r6 :r7 :task)
;; => (ldx dw r7 r6 8)  ; offset 8 for task

(iter/iter-load-ctx-ptr :r6 :r7 :map)
;; => (ldx dw r7 r6 8)  ; offset 8 for map

(iter/iter-load-ctx-ptr :r6 :r7 :key)
;; => (ldx dw r7 r6 8)  ; offset 8 for key

(iter/iter-load-ctx-ptr :r6 :r7 :value)
;; => (ldx dw r7 r6 16)  ; offset 16 for value
```

---

## Part 3: NULL Check Patterns

### Basic NULL Check

```clojure
;; Check if pointer is NULL and skip N instructions
(iter/iter-check-null :r7 5)
;; => [(jmp-imm jeq r7 0 5)]

;; Check NULL and exit if true
(iter/iter-check-null-and-exit :r7)
;; => [(jmp-imm jne r7 0 2)   ; Skip exit if NOT null
;;     (mov r0 0)              ; Return 0 (continue)
;;     (exit)]
```

### Complete NULL Check Pattern

```clojure
(def task-iter-with-null-check
  (vec (concat
        ;; Prologue
        (iter/iter-prologue :r6)

        ;; Load task pointer
        [(iter/iter-load-ctx-ptr :r6 :r7 :task)]

        ;; Check for NULL (end of iteration)
        (iter/iter-check-null-and-exit :r7)

        ;; Task is valid - do something with it
        ;; ... your code here ...

        ;; Continue to next task
        (iter/iter-return-continue))))
```

---

## Part 4: Output with seq_write and seq_printf

### Using bpf_seq_write

```clojure
;; bpf_seq_write writes raw bytes to output
;; Signature: long bpf_seq_write(seq_file *m, void *data, u32 len)

;; Generate seq_write call
(iter/seq-write :r8 :r9 4)
;; r8 = meta pointer (seq_file at offset 0)
;; r9 = data pointer
;; 4 = length in bytes

;; Generates:
;; => [(ldx dw r1 r8 0)     ; r1 = meta->seq
;;     (mov-reg r2 r9)       ; r2 = data
;;     (mov r3 4)            ; r3 = len
;;     (call 127)]           ; bpf_seq_write
```

### Using bpf_seq_printf (Simplified)

```clojure
;; bpf_seq_printf for formatted output
;; Note: Requires format string in program memory

(iter/seq-printf-simple :r8 :r2 16 :r4 8)
;; r8 = meta pointer
;; r2 = format string pointer, 16 = fmt length
;; r4 = data array pointer, 8 = data length
```

---

## Part 5: Reading Kernel Memory Safely

### Using probe_read_kernel

```clojure
;; bpf_probe_read_kernel for safe kernel memory access
;; Required when reading fields from task_struct, etc.

(iter/probe-read-kernel :r9 4 :r7)
;; r9 = destination buffer (on stack)
;; 4 = size to read
;; r7 = source pointer (kernel memory)

;; Generates:
;; => [(mov-reg r1 r9)           ; dst
;;     (mov r2 4)                 ; size
;;     (mov-reg r3 r7)           ; src
;;     (call 113)]               ; bpf_probe_read_kernel
```

### Using probe_read_kernel_str

```clojure
;; For null-terminated strings
(iter/probe-read-kernel-str :r9 16 :r7)
;; Reads up to 16 bytes including null terminator
```

### Stack Buffer Allocation

```clojure
;; Allocate buffer on stack (negative offset from r10)
(iter/alloc-stack-buffer :r9 -32)
;; r9 = r10 - 32 (32 bytes of stack space)

;; BPF stack is 512 bytes max
;; Use negative offsets from r10 (frame pointer)
```

---

## Part 6: Return Values

### Continue vs Stop

```clojure
;; Return values for iterators
iter/iter-return-values
;; => {:continue 0   ; Continue to next element
;;     :stop     1}  ; Stop iteration early

;; Generate return instructions
(iter/iter-return-continue)
;; => [(mov r0 0)
;;     (exit)]

(iter/iter-return-stop)
;; => [(mov r0 1)
;;     (exit)]

;; Using keyword
(iter/iter-return :continue)
(iter/iter-return :stop)
```

### Early Stop Pattern

```clojure
(def stop-at-pid-1
  "Stop iteration when we find PID 1 (init)."
  (vec (concat
        (iter/iter-prologue :r6)

        ;; Load task
        [(iter/iter-load-ctx-ptr :r6 :r7 :task)]

        ;; NULL check
        (iter/iter-check-null-and-exit :r7)

        ;; Read PID (offset varies by kernel!)
        [(iter/task-load-pid :r7 :r8)]

        ;; Check if PID == 1
        [(dsl/jmp-imm :jne :r8 1 2)]

        ;; Found PID 1 - stop
        (iter/iter-return-stop)

        ;; Not PID 1 - continue
        (iter/iter-return-continue))))
```

---

## Part 7: Using Program Builder

### build-iter-program

```clojure
(def task-program
  (iter/build-iter-program
   {:ctx-reg :r6
    :meta-reg :r8
    :body [;; Load task pointer
           (iter/iter-load-ctx-ptr :r6 :r7 :task)
           ;; NULL check - skip to return
           (dsl/jmp-imm :jeq :r7 0 2)
           ;; Do something with task
           (dsl/mov :r0 0)
           (dsl/exit-insn)]
    :default-action :continue}))

;; task-program is assembled bytecode (byte array)
```

### Template Functions

```clojure
;; Minimal task iterator
(iter/minimal-task-iterator)

;; Task iterator with NULL check
(iter/task-null-check-template
 [;; Body instructions here
  (iter/task-load-pid :r7 :r8)])
```

---

## Part 8: Using defprogram Macro

```clojure
(require '[clj-ebpf.macros :refer [defprogram]])

(defprogram task-dumper
  "Iterate over all tasks and dump basic info."
  :type :tracing
  :attach-type :trace-iter
  :license "GPL"
  :body (vec (concat
              ;; Prologue with meta
              (iter/iter-prologue-with-meta :r6 :r8)

              ;; Load task
              [(iter/iter-load-ctx-ptr :r6 :r7 :task)]

              ;; NULL check
              (iter/iter-check-null-and-exit :r7)

              ;; Allocate stack buffer
              [(iter/alloc-stack-buffer :r9 -32)]

              ;; Read PID (4 bytes)
              (iter/probe-read-kernel :r9 4 :r7)

              ;; Write to output
              (iter/seq-write :r8 :r9 4)

              ;; Continue
              (iter/iter-return-continue))))
```

---

## Part 9: Section Names and BTF

### Iterator Section Names

```clojure
;; Generate ELF section name
(iter/iter-section-name :task)
;; => "iter/bpf_iter__task"

(iter/iter-section-name :bpf-map)
;; => "iter/bpf_iter__bpf_map"

(iter/iter-section-name :tcp)
;; => "iter/bpf_iter__tcp"
```

### BTF Type Names

```clojure
iter/iterator-types
;; => {:task          "bpf_iter__task"
;;     :task-file     "bpf_iter__task_file"
;;     :bpf-map       "bpf_iter__bpf_map"
;;     :bpf-map-elem  "bpf_iter__bpf_map_elem"
;;     :bpf-prog      "bpf_iter__bpf_prog"
;;     :bpf-link      "bpf_iter__bpf_link"
;;     :tcp           "bpf_iter__tcp"
;;     :udp           "bpf_iter__udp"
;;     ...}
```

---

## Part 10: Creating and Using Iterators

### High-Level API

```clojure
(require '[clj-ebpf.programs :as progs])

;; Load iterator program
(def prog
  (progs/load-iterator-program
   bytecode
   :task
   {:license "GPL"
    :prog-name "task_dump"}))

;; Create iterator
(progs/with-iterator [iter prog {:iter-type :task}]
  ;; Read from iterator
  ;; iter contains :iter-fd, :link-fd, :prog
  (let [output (slurp (str "/proc/self/fd/" (:iter-fd iter)))]
    (println output)))

;; Cleanup is automatic with with-iterator
```

### Manual Lifecycle

```clojure
;; Create iterator manually
(def iter (progs/create-iterator prog {:iter-type :task}))

;; Use the iterator FD
(let [fd (:iter-fd iter)]
  ;; Read from fd...
  )

;; Close when done
(progs/close-iterator iter)
```

---

## Part 11: Complete Examples

### Task Counter

```clojure
(ns my-task-counter
  (:require [clj-ebpf.programs :as progs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.iter :as iter]))

;; Create a map to store the count
(def count-map
  (maps/create-array-map 4 8 1 :map-name "count"))

;; Build iterator that increments counter
(def counter-insns
  (vec (concat
        ;; Prologue
        (iter/iter-prologue :r6)

        ;; Load task pointer
        [(iter/iter-load-ctx-ptr :r6 :r7 :task)]

        ;; NULL check
        (iter/iter-check-null-and-exit :r7)

        ;; Task is valid - would increment map counter here
        ;; (Simplified - actual implementation needs map lookup/update)

        ;; Continue
        (iter/iter-return-continue))))
```

### BPF Map Dumper

```clojure
(def map-dumper-insns
  "Iterate over all BPF maps in the system."
  (vec (concat
        ;; Prologue with meta for output
        (iter/iter-prologue-with-meta :r6 :r8)

        ;; Load map pointer
        [(iter/iter-load-ctx-ptr :r6 :r7 :map)]

        ;; NULL check
        (iter/iter-check-null-and-exit :r7)

        ;; Allocate stack buffer
        [(iter/alloc-stack-buffer :r9 -64)]

        ;; Read map info and write to output
        ;; (Actual implementation would read map fields)

        ;; Continue
        (iter/iter-return-continue))))
```

---

## DSL Reference

### Context Access

| Function | Description |
|----------|-------------|
| `iter-prologue` | Save context pointer |
| `iter-prologue-with-meta` | Save context and load meta |
| `iter-load-ctx-ptr` | Load pointer from context |
| `iter-load-meta-field` | Load field from meta structure |
| `iter-context-offset` | Get offset for context field |

### NULL Handling

| Function | Description |
|----------|-------------|
| `iter-check-null` | Jump if pointer is NULL |
| `iter-check-null-and-exit` | Exit with 0 if NULL |

### Output Functions

| Function | Description |
|----------|-------------|
| `seq-write` | Write raw bytes to output |
| `seq-printf-simple` | Write formatted output |

### Memory Access

| Function | Description |
|----------|-------------|
| `probe-read-kernel` | Safely read kernel memory |
| `probe-read-kernel-str` | Read null-terminated string |
| `alloc-stack-buffer` | Get pointer to stack buffer |

### Task Helpers

| Function | Description |
|----------|-------------|
| `task-load-pid` | Load PID from task_struct |
| `task-load-tgid` | Load TGID from task_struct |

### Return Patterns

| Function | Description |
|----------|-------------|
| `iter-return-continue` | Return 0 (continue) |
| `iter-return-stop` | Return 1 (stop) |
| `iter-return` | Return by keyword |

### Program Building

| Function | Description |
|----------|-------------|
| `build-iter-program` | Build complete iterator program |
| `minimal-task-iterator` | Minimal task iterator template |
| `task-null-check-template` | Task iterator with NULL check |
| `make-iter-info` | Create program metadata |
| `iter-section-name` | Generate ELF section name |

---

## Troubleshooting

### Common Issues

1. **"Permission denied"**
   - Need root or CAP_BPF + CAP_PERFMON

2. **"Invalid argument" on link create**
   - Kernel 5.8+ required for BPF iterators
   - BTF must be enabled in kernel
   - Check `/sys/kernel/btf/vmlinux` exists

3. **"Invalid BTF" error**
   - Iterator type name must match kernel BTF
   - Use `iter/iterator-types` for correct names

4. **Program verifier rejects**
   - Check all code paths return a value
   - NULL checks are required for safety
   - Stack usage must be under 512 bytes

5. **Empty output from iterator**
   - Check NULL handling at end of iteration
   - Verify seq_write is called correctly
   - Check meta pointer is loaded

### Debugging

```bash
# Check kernel version
uname -r

# Check BTF availability
ls -la /sys/kernel/btf/vmlinux

# List iterator programs
sudo bpftool prog list | grep tracing

# Check BPF links
sudo bpftool link list | grep iter

# View iterator output (for task iterator)
sudo cat /proc/<iter-pid>/fdinfo/<iter-fd>
```

---

## Summary

You learned:
- BPF iterator architecture and workflow
- Iterator context structures for different types
- NULL handling at end of iteration
- Output with seq_write and seq_printf
- Safe kernel memory access with probe_read
- Return values for continue/stop control
- Using program builder and macros

---

## Next Steps

- **[SK_LOOKUP Tutorial](quick-start-sk-lookup.md)** - Socket dispatch
- **[FLOW_DISSECTOR Tutorial](quick-start-flow-dissector.md)** - Packet parsing

---

## Reference

### Kernel Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| BPF Iterators | 5.8 |
| Task iterator | 5.8 |
| BPF map iterator | 5.8 |
| TCP/UDP iterators | 5.9 |
| BTF-based iterators | 5.8 |

### Helper Function IDs

| Helper | ID | Description |
|--------|-----|-------------|
| `bpf_seq_write` | 127 | Write raw bytes to output |
| `bpf_seq_printf` | 126 | Write formatted output |
| `bpf_seq_printf_btf` | 128 | BTF-based formatted output |
| `bpf_probe_read_kernel` | 113 | Safe kernel memory read |
| `bpf_probe_read_kernel_str` | 45 | Safe kernel string read |
| `bpf_get_current_task` | 35 | Get current task pointer |

### Context Field Offsets

| Field | Offset | Iterator Types |
|-------|--------|---------------|
| meta | 0 | All types |
| task | 8 | task |
| map | 8 | bpf_map |
| key | 8 | bpf_map_elem |
| value | 16 | bpf_map_elem |
| prog | 8 | bpf_prog |
| link | 8 | bpf_link |
| tcp_sk | 8 | tcp |
| udp_sk | 8 | udp |
| file | 16 | task_file |

### Return Values

| Value | Meaning |
|-------|---------|
| 0 | Continue iteration |
| 1 | Stop iteration early |
