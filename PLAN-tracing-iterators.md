# Plan: Tracing Iterators (bpf_iter) Implementation

## 1. Feature Description
**BPF Iterators (TRACING)** allow BPF programs to dump kernel data structures to userspace by "iterating" over them. Unlike standard tracing (triggered by events), iterators are triggered by reading a file (usually in `/sys/fs/bpf`). This replaces the need for custom `/proc` files and allows flexible, high-performance system introspection (e.g., listing all open sockets, all processes, all maps).

## 2. Implementation Details

### 2.1 Constants
Update `src/clj_ebpf/constants.clj`:
- Program Type: `BPF_PROG_TYPE_TRACING`.
- Attach Type: `BPF_TRACE_ITER`.

### 2.2 Link Creation (`src/clj_ebpf/syscall.clj`)
- Implement `bpf_link_create` for iterators.
- Unlike other links, creating an iterator link usually results in a file descriptor that must be pinned to the BPF filesystem to be read, OR `bpf_iter_create` is used to get a file descriptor that can be `read()` directly.
- **New Syscall**: `bpf_iter_create` (creates a file descriptor from a link).

### 2.3 High-Level API
- `create-iterator`:
  1. Load program (tracing type).
  2. Create link (`bpf_link_create`).
  3. Create iterator FD (`bpf_iter_create`).
  4. Return a "Reader" object that wraps the FD. Reading from it executes the BPF program loop in the kernel.

## 3. Testing Strategy

### 3.1 Unit Tests
- Create `test/clj_ebpf/programs/iterator_test.clj`.

### 3.2 Integration Tests
- **Test Case 1**: Implement a simple iterator (e.g., `iter/task` to list processes).
- **Test Case 2**: Create iterator, read from the resulting FD.
- **Test Case 3**: Verify output matches expected format (e.g., list of PIDs).

## 4. Examples
Create `examples/iter_task_dump.clj`:
```clojure
(ns examples.iter-task-dump
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.iter :as iter]))

(def dump-tasks-prog
  (dsl/assemble
    [;; Context is struct bpf_iter__task
     ;; Print task->comm, task->pid via bpf_seq_printf helper
     ...]
    :prog-type :tracing
    :expected-attach-type :trace-iter))

(def session (iter/create-iterator dump-tasks-prog "task"))
(println (iter/read-all session))
```

## 5. Tutorial Content
Add **Chapter 18: BPF Iterators** to `tutorials/part-3-advanced/README.md`.
- Explain how this replaces `/proc` parsing.
- Show how to dump BPF map contents (iter/bpf_map_elem) which is useful for debugging.
