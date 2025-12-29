# BPF Iterators Guide: Kernel Data Dumping

This guide covers BPF Iterators (bpf_iter) for iterating over kernel data structures.

## Overview

BPF Iterators enable:

- **Kernel data dumping** - Iterate over tasks, maps, sockets, etc.
- **Custom /proc replacements** - Flexible alternatives to /proc files
- **Efficient data export** - seq_file output with BPF filtering
- **Introspection** - List BPF programs, maps, and links

## Creating Iterator Programs

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.iter :as iter])

;; Build iterator bytecode
(def bytecode
  (dsl/assemble
    (vec (concat
          (iter/iter-prologue-with-meta :r6 :r8)
          [(iter/iter-load-ctx-ptr :r6 :r7 :task)]
          (iter/iter-check-null-and-exit :r7)
          ;; ... iteration logic ...
          (iter/iter-return-continue)))))
```

## Using Iterators

```clojure
(require '[clj-ebpf.programs :as progs])

;; Load iterator program
(def prog
  (progs/load-iterator-program
    bytecode
    :task
    {:license "GPL"}))

;; Create and use iterator
(progs/with-iterator [iter prog {:iter-type :task}]
  (let [output (slurp (str "/proc/self/fd/" (:iter-fd iter)))]
    (println output)))
```

## DSL Reference

### Prologue Functions

| Function | Description |
|----------|-------------|
| `iter-prologue` | Save context pointer |
| `iter-prologue-with-meta` | Save context and load meta pointer |

### Context Access

| Function | Description |
|----------|-------------|
| `iter-load-ctx-ptr` | Load pointer from context (task, map, etc.) |
| `iter-load-meta-field` | Load field from bpf_iter_meta |
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

| Function | Returns | Description |
|----------|---------|-------------|
| `iter-return-continue` | 0 | Continue iteration |
| `iter-return-stop` | 1 | Stop iteration early |
| `iter-return` | 0 or 1 | Return by keyword |

### Program Building

| Function | Description |
|----------|-------------|
| `build-iter-program` | Build complete iterator program |
| `minimal-task-iterator` | Minimal task iterator template |
| `task-null-check-template` | Task iterator with NULL check |
| `make-iter-info` | Create program metadata |
| `iter-section-name` | Generate ELF section name |

## Iterator Types

| Type | BTF Name | Context Fields |
|------|----------|----------------|
| `:task` | `bpf_iter__task` | meta, task |
| `:task-file` | `bpf_iter__task_file` | meta, task, file |
| `:bpf-map` | `bpf_iter__bpf_map` | meta, map |
| `:bpf-map-elem` | `bpf_iter__bpf_map_elem` | meta, key, value |
| `:bpf-prog` | `bpf_iter__bpf_prog` | meta, prog |
| `:bpf-link` | `bpf_iter__bpf_link` | meta, link |
| `:tcp` | `bpf_iter__tcp` | meta, tcp_sk |
| `:udp` | `bpf_iter__udp` | meta, udp_sk |
| `:unix` | `bpf_iter__unix` | meta, unix_sk |
| `:netlink` | `bpf_iter__netlink` | meta, netlink_sk |

## Context Structures

### Common Context Layout

All iterator contexts start with:
```
offset 0:  bpf_iter_meta *meta
offset 8:  type-specific pointer
```

### bpf_iter_meta Structure

```
struct bpf_iter_meta {
    struct seq_file *seq;   // offset 0: Output file
    u64 session_id;         // offset 8: Iteration session
    u64 seq_num;            // offset 16: Sequence number
};
```

### Context Offsets

| Field | Offset | Description |
|-------|--------|-------------|
| `meta` | 0 | bpf_iter_meta pointer |
| `task` | 8 | task_struct pointer (task iterator) |
| `map` | 8 | bpf_map pointer (bpf_map iterator) |
| `key` | 8 | Key pointer (bpf_map_elem iterator) |
| `value` | 16 | Value pointer (bpf_map_elem iterator) |
| `prog` | 8 | bpf_prog pointer (bpf_prog iterator) |
| `link` | 8 | bpf_link pointer (bpf_link iterator) |
| `tcp-sk` | 8 | sock pointer (tcp iterator) |
| `udp-sk` | 8 | sock pointer (udp iterator) |
| `file` | 16 | file pointer (task_file iterator) |

## BPF Helper Functions

| Helper | ID | Description |
|--------|-----|-------------|
| `bpf_seq_write` | 127 | Write raw bytes to output |
| `bpf_seq_printf` | 126 | Write formatted output |
| `bpf_seq_printf_btf` | 128 | BTF-based formatted output |
| `bpf_probe_read_kernel` | 113 | Safe kernel memory read |
| `bpf_probe_read_kernel_str` | 45 | Safe kernel string read |
| `bpf_get_current_task` | 35 | Get current task pointer |

## Complete Examples

### Task Iterator

```clojure
(def task-dumper
  (dsl/assemble
    (vec (concat
          ;; Prologue with meta for output
          (iter/iter-prologue-with-meta :r6 :r8)

          ;; Load task pointer
          [(iter/iter-load-ctx-ptr :r6 :r7 :task)]

          ;; Check for NULL (end of iteration)
          (iter/iter-check-null-and-exit :r7)

          ;; Allocate stack buffer
          [(iter/alloc-stack-buffer :r9 -32)]

          ;; Read PID into buffer
          (iter/probe-read-kernel :r9 4 :r7)

          ;; Write to output
          (iter/seq-write :r8 :r9 4)

          ;; Continue
          (iter/iter-return-continue)))))
```

### BPF Map Iterator

```clojure
(def map-lister
  (dsl/assemble
    (vec (concat
          (iter/iter-prologue :r6)
          [(iter/iter-load-ctx-ptr :r6 :r7 :map)]
          (iter/iter-check-null-and-exit :r7)
          ;; Map pointer in r7 - read map info
          (iter/iter-return-continue)))))
```

### BPF Map Element Iterator

```clojure
(def map-elem-dumper
  (dsl/assemble
    (vec (concat
          (iter/iter-prologue-with-meta :r6 :r8)

          ;; Load key pointer
          [(iter/iter-load-ctx-ptr :r6 :r7 :key)]

          ;; NULL check
          (iter/iter-check-null-and-exit :r7)

          ;; Load value pointer
          [(iter/iter-load-ctx-ptr :r6 :r9 :value)]

          ;; Write key to output
          (iter/seq-write :r8 :r7 4)

          ;; Write value to output
          (iter/seq-write :r8 :r9 8)

          (iter/iter-return-continue)))))
```

### Early Stop Pattern

```clojure
(def stop-at-pid-1
  (dsl/assemble
    (vec (concat
          (iter/iter-prologue :r6)
          [(iter/iter-load-ctx-ptr :r6 :r7 :task)]
          (iter/iter-check-null-and-exit :r7)

          ;; Read PID
          [(iter/task-load-pid :r7 :r8)]

          ;; Check if PID == 1
          [(dsl/jmp-imm :jne :r8 1 2)]

          ;; Found PID 1 - stop
          (iter/iter-return-stop)

          ;; Not PID 1 - continue
          (iter/iter-return-continue)))))
```

## Using build-iter-program

```clojure
(def built-bytecode
  (iter/build-iter-program
    {:ctx-reg :r6
     :meta-reg :r8
     :body [(iter/iter-load-ctx-ptr :r6 :r7 :task)
            (dsl/jmp-imm :jeq :r7 0 2)
            (dsl/mov :r0 0)
            (dsl/exit-insn)]
     :default-action :continue}))
```

## Section Names

```clojure
(iter/iter-section-name :task)
;; => "iter/bpf_iter__task"

(iter/iter-section-name :bpf-map)
;; => "iter/bpf_iter__bpf_map"

(iter/iter-section-name :tcp)
;; => "iter/bpf_iter__tcp"
```

## High-Level API

### Loading Programs

```clojure
(def prog
  (progs/load-iterator-program
    bytecode
    :task
    {:license "GPL"
     :prog-name "my_iterator"
     :log-level 1}))
```

### Creating Iterators

```clojure
;; With automatic cleanup
(progs/with-iterator [iter prog {:iter-type :task}]
  (let [fd (:iter-fd iter)]
    ;; Read from fd...
    ))

;; Manual lifecycle
(def iter (progs/create-iterator prog {:iter-type :task}))
;; ... use iter ...
(progs/close-iterator iter)
```

### BpfIterator Record

```clojure
;; Fields in BpfIterator:
;; - :prog      - The BPF program
;; - :link-fd   - BPF link file descriptor
;; - :iter-fd   - Iterator file descriptor (read from this)
;; - :iter-type - Iterator type keyword
```

## Kernel Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| BPF Iterators | 5.8 |
| Task iterator | 5.8 |
| BPF map iterator | 5.8 |
| BPF map element iterator | 5.8 |
| TCP/UDP iterators | 5.9 |
| bpf_seq_printf | 5.8 |
| bpf_seq_write | 5.8 |
| BTF support | 5.2 |

## Troubleshooting

### Common Issues

1. **"Invalid argument" on link create**
   - Kernel 5.8+ required
   - BTF must be available (`/sys/kernel/btf/vmlinux`)
   - Iterator type must match BTF name

2. **Empty output from iterator**
   - Check NULL handling at end of iteration
   - Verify seq_write is called correctly
   - Ensure meta pointer is loaded

3. **Verifier rejects program**
   - All code paths must return a value
   - NULL checks are required for element pointers
   - Stack usage must be under 512 bytes

4. **"Operation not permitted"**
   - Need CAP_BPF + CAP_PERFMON
   - Or run as root

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

# View verifier log (on error)
# Error message includes detailed verifier output
```

## See Also

- [BPF Iterators Tutorial](../tutorials/quick-start-iterators.md)
- [Example: Task Dump](../examples/iter_task_dump.clj)
