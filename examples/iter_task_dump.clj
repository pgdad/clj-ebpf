(ns examples.iter-task-dump
  "Example: BPF Iterators for Dumping Kernel Data

   This example demonstrates BPF Iterators (bpf_iter), which allow BPF programs
   to iterate over kernel data structures and dump their contents. Reading from
   an iterator file descriptor triggers the BPF program for each element.

   Common iterator types:
   - task: Iterate over all tasks/processes
   - bpf_map: Iterate over BPF maps
   - bpf_map_elem: Iterate over elements in a specific map
   - tcp/udp: Iterate over TCP/UDP sockets
   - bpf_prog: Iterate over BPF programs
   - bpf_link: Iterate over BPF links

   NOTE: Actual iterator programs require:
   - Root privileges (CAP_BPF + CAP_PERFMON)
   - Kernel 5.8+ with BTF support
   - BTF type information for the iterator type

   This example focuses on program construction patterns.

   Run with: clj -M:examples -e \"(load-file \\\"examples/iter_task_dump.clj\\\")\"
             or: clj -M -m examples.iter-task-dump"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.iter :as iter]
            [clj-ebpf.macros :refer [defprogram defmap-spec]]))

;; ============================================================================
;; BPF Iterator Architecture
;; ============================================================================
;;
;; BPF Iterators work by:
;;
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │                      BPF Iterator Workflow                          │
;;   └─────────────────────────────────────────────────────────────────────┘
;;
;;   1. Load iterator program (type: TRACING, attach: TRACE_ITER)
;;         │
;;         v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │   2. Create BPF link with iterator type info                        │
;;   │      bpf_link_create(prog_fd, 0, BPF_TRACE_ITER, ...)              │
;;   └──────────────────────────────┬──────────────────────────────────────┘
;;                                  │
;;                                  v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │   3. Create iterator FD from link                                   │
;;   │      bpf_iter_create(link_fd, ...)                                 │
;;   └──────────────────────────────┬──────────────────────────────────────┘
;;                                  │
;;                                  v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │   4. Read from iterator FD                                          │
;;   │      ┌──────────────────────────────────────────────────────────┐  │
;;   │      │  For each element in kernel data structure:              │  │
;;   │      │    - BPF program is invoked with context                 │  │
;;   │      │    - Program can use bpf_seq_write/bpf_seq_printf       │  │
;;   │      │    - Returns 0 to continue, 1 to stop                    │  │
;;   │      └──────────────────────────────────────────────────────────┘  │
;;   └──────────────────────────────┬──────────────────────────────────────┘
;;                                  │
;;                                  v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │   5. Close iterator FD, link, and program                           │
;;   └─────────────────────────────────────────────────────────────────────┘

;; ============================================================================
;; Iterator Types and Their Contexts
;; ============================================================================

(println "\n=== Iterator Types and Contexts ===")

(println "\nSupported iterator types:")
(doseq [[k v] (sort-by (comp str key) iter/iterator-types)]
  (println (format "  %-14s -> %s" (name k) v)))

(println "\nIterator context offsets:")
(doseq [[k v] (sort-by (comp str key) iter/iter-context-offsets)]
  (println (format "  %-10s at offset %2d" (name k) v)))

;; ============================================================================
;; Example 1: Minimal Task Iterator
;; ============================================================================

(println "\n=== Example 1: Minimal Task Iterator ===")

(def minimal-task-insns
  "Simplest possible task iterator - just continues for each task."
  (iter/minimal-task-iterator))

(println "Minimal task iterator instructions:" (count minimal-task-insns))
(println "Assembled bytecode size:" (count (dsl/assemble minimal-task-insns)) "bytes")

;; ============================================================================
;; Example 2: Task Iterator with NULL Check
;; ============================================================================

(println "\n=== Example 2: Task Iterator with NULL Check ===")

(def task-null-check-insns
  "Task iterator that properly handles NULL pointer at end of iteration.

   At the end of iteration, the task pointer is NULL, indicating
   no more tasks to process."
  (vec (concat
        ;; Save context
        (iter/iter-prologue :r6)

        ;; Load task pointer from context
        [(iter/iter-load-ctx-ptr :r6 :r7 :task)]

        ;; Check if task is NULL (end of iteration)
        (iter/iter-check-null-and-exit :r7)

        ;; Task is valid - continue iteration
        (iter/iter-return-continue))))

(println "Task NULL check instructions:" (count task-null-check-insns))
(println "Assembled bytecode size:" (count (dsl/assemble task-null-check-insns)) "bytes")

;; ============================================================================
;; Example 3: Task Iterator with seq_write
;; ============================================================================

(println "\n=== Example 3: Using bpf_seq_write ===")

(def task-seq-write-insns
  "Task iterator that writes data using bpf_seq_write.

   bpf_seq_write writes raw bytes to the output buffer."
  (vec (concat
        ;; Prologue - save context and load meta
        (iter/iter-prologue-with-meta :r6 :r8)

        ;; Load task pointer
        [(iter/iter-load-ctx-ptr :r6 :r7 :task)]

        ;; Check for NULL
        (iter/iter-check-null-and-exit :r7)

        ;; Allocate stack buffer at r10-32
        (iter/alloc-stack-buffer :r9 -32)

        ;; Read PID into stack buffer (4 bytes)
        (iter/probe-read-kernel :r9 4 :r7)

        ;; Write PID to output (4 bytes from stack buffer)
        (iter/seq-write :r8 :r9 4)

        ;; Continue iteration
        (iter/iter-return-continue))))

(println "seq_write instructions:" (count task-seq-write-insns))
(println "Assembled bytecode size:" (count (dsl/assemble task-seq-write-insns)) "bytes")

;; ============================================================================
;; Example 4: BPF Map Iterator
;; ============================================================================

(println "\n=== Example 4: BPF Map Iterator ===")

(def map-iterator-insns
  "Iterator over all BPF maps in the system.

   Context structure (bpf_iter__bpf_map):
   - meta: bpf_iter_meta pointer at offset 0
   - map: bpf_map pointer at offset 8"
  (vec (concat
        ;; Save context
        (iter/iter-prologue :r6)

        ;; Load map pointer from context
        [(iter/iter-load-ctx-ptr :r6 :r7 :map)]

        ;; Check if map is NULL
        (iter/iter-check-null-and-exit :r7)

        ;; Map is valid - in real program would read map info
        ;; and write to seq_file

        ;; Continue to next map
        (iter/iter-return-continue))))

(println "Map iterator instructions:" (count map-iterator-insns))
(println "Section name:" (iter/iter-section-name :bpf-map))

;; ============================================================================
;; Example 5: BPF Map Element Iterator
;; ============================================================================

(println "\n=== Example 5: BPF Map Element Iterator ===")

(def map-elem-iterator-insns
  "Iterator over elements in a specific BPF map.

   Context structure (bpf_iter__bpf_map_elem):
   - meta: bpf_iter_meta pointer at offset 0
   - key: key pointer at offset 8
   - value: value pointer at offset 16"
  (vec (concat
        ;; Save context and load meta
        (iter/iter-prologue-with-meta :r6 :r8)

        ;; Load key pointer
        [(iter/iter-load-ctx-ptr :r6 :r7 :key)]

        ;; Check if key is NULL (end of iteration)
        (iter/iter-check-null-and-exit :r7)

        ;; Load value pointer
        [(iter/iter-load-ctx-ptr :r6 :r9 :value)]

        ;; In real program: read key/value and write to output
        ;; Example: write key bytes
        (iter/seq-write :r8 :r7 4)  ; Write 4-byte key

        ;; Continue iteration
        (iter/iter-return-continue))))

(println "Map element iterator instructions:" (count map-elem-iterator-insns))
(println "Section name:" (iter/iter-section-name :bpf-map-elem))

;; ============================================================================
;; Example 6: TCP Socket Iterator
;; ============================================================================

(println "\n=== Example 6: TCP Socket Iterator ===")

(def tcp-iterator-insns
  "Iterator over TCP sockets (for /proc/net/tcp replacement).

   Context structure (bpf_iter__tcp):
   - meta: bpf_iter_meta pointer at offset 0
   - tcp_sk: sock pointer at offset 8"
  (vec (concat
        ;; Save context
        (iter/iter-prologue :r6)

        ;; Load TCP socket pointer
        [(iter/iter-load-ctx-ptr :r6 :r7 :tcp-sk)]

        ;; Check for NULL
        (iter/iter-check-null-and-exit :r7)

        ;; Socket is valid - would read socket info and output
        ;; Fields like sk_family, sk_state, sk_num, etc.

        ;; Continue
        (iter/iter-return-continue))))

(println "TCP iterator instructions:" (count tcp-iterator-insns))
(println "Section name:" (iter/iter-section-name :tcp))

;; ============================================================================
;; Example 7: Using build-iter-program
;; ============================================================================

(println "\n=== Example 7: Using Program Builder ===")

(def built-program
  (iter/build-iter-program
   {:ctx-reg :r6
    :meta-reg :r8
    :body [;; Load and check task pointer
           (iter/iter-load-ctx-ptr :r6 :r7 :task)
           (dsl/jmp-imm :jeq :r7 0 2)  ; Skip to return if NULL
           (dsl/mov :r0 0)              ; Return continue
           (dsl/exit-insn)]
    :default-action :continue}))

(println "Built program bytecode size:" (count built-program) "bytes")

;; ============================================================================
;; Example 8: Using defprogram Macro
;; ============================================================================

(println "\n=== Example 8: Using defprogram Macro ===")

(defprogram task-counter
  "Task iterator that counts tasks.

   This is a conceptual example - actual implementation would
   need a map to store the count between invocations."
  :type :tracing
  :attach-type :trace-iter
  :license "GPL"
  :body (vec (concat
              ;; Save context
              (iter/iter-prologue :r6)
              ;; Load task pointer
              [(iter/iter-load-ctx-ptr :r6 :r7 :task)]
              ;; Check NULL
              (iter/iter-check-null-and-exit :r7)
              ;; Task is valid - would increment counter in map
              ;; Continue iteration
              (iter/iter-return-continue))))

(println "defprogram spec created:" (:name task-counter))
(println "Program type:" (:type task-counter))
(println "Attach type:" (:attach-type task-counter))

;; ============================================================================
;; Example 9: Return Value Patterns
;; ============================================================================

(println "\n=== Example 9: Return Value Patterns ===")

(println "\nIterator return values:")
(doseq [[k v] iter/iter-return-values]
  (println (format "  %-10s -> %d" (name k) v)))

(def early-stop-insns
  "Iterator that stops early when it finds PID 1 (init process)."
  (vec (concat
        (iter/iter-prologue :r6)

        ;; Load task pointer
        [(iter/iter-load-ctx-ptr :r6 :r7 :task)]

        ;; Check NULL
        (iter/iter-check-null-and-exit :r7)

        ;; Read PID into r8 (unsafe - just for demo)
        [(iter/task-load-pid :r7 :r8)]

        ;; Check if PID == 1
        [(dsl/jmp-imm :jne :r8 1 2)]

        ;; Found PID 1 - stop iteration
        (iter/iter-return-stop)

        ;; Not PID 1 - continue
        (iter/iter-return-continue))))

(println "\nEarly stop example:" (count early-stop-insns) "instructions")

;; ============================================================================
;; Example 10: BPF Helper Functions
;; ============================================================================

(println "\n=== Example 10: BPF Helper Functions ===")

(println "\nRelevant BPF helpers for iterators:")
(doseq [[k v] (sort-by val iter/iter-helper-ids)]
  (println (format "  %-18s ID: %3d" (name k) v)))

(println "
Helper function usage:

  bpf_seq_write (ID 127):
    - Write raw bytes to output
    - Signature: long bpf_seq_write(seq_file *m, void *data, u32 len)

  bpf_seq_printf (ID 126):
    - Write formatted output (like printf)
    - Signature: long bpf_seq_printf(seq_file *m, char *fmt, u32 fmt_size,
                                      void *data, u32 data_len)

  bpf_probe_read_kernel (ID 113):
    - Safely read kernel memory
    - Required for reading fields from task_struct, etc.

  bpf_get_current_task (ID 35):
    - Get current task_struct pointer
    - Useful for comparison with iterator task")

;; ============================================================================
;; Example 11: Task Template Usage
;; ============================================================================

(println "\n=== Example 11: Task Template ===")

(def task-with-body-insns
  "Using task-null-check-template with custom body."
  (iter/task-null-check-template
   ;; Body: Just load PID into r8
   [(iter/task-load-pid :r7 :r8)]))

(println "Template-based program:" (count task-with-body-insns) "instructions")
(println "Assembled size:" (count (dsl/assemble task-with-body-insns)) "bytes")

;; ============================================================================
;; Example 12: Meta Field Access
;; ============================================================================

(println "\n=== Example 12: Meta Field Access ===")

(println "\nbpf_iter_meta field offsets:")
(doseq [[k v] (sort-by val iter/iter-meta-offsets)]
  (println (format "  %-12s at offset %2d" (name k) v)))

(def meta-access-insns
  "Demonstrate accessing meta fields."
  (vec (concat
        ;; Prologue with meta
        (iter/iter-prologue-with-meta :r6 :r8)

        ;; Load seq_file pointer from meta
        [(iter/iter-load-meta-field :r8 :r9 :seq)]

        ;; Load session_id from meta
        [(iter/iter-load-meta-field :r8 :r7 :session-id)]

        ;; Continue
        (iter/iter-return-continue))))

(println "\nMeta access instructions:" (count meta-access-insns))

;; ============================================================================
;; Example 13: Section Names
;; ============================================================================

(println "\n=== Example 13: Section Names ===")

(println "\nIterator section names for ELF output:")
(doseq [iter-type [:task :bpf-map :bpf-map-elem :tcp :udp :bpf-prog :bpf-link]]
  (println (format "  %-14s -> %s" (name iter-type) (iter/iter-section-name iter-type))))

;; ============================================================================
;; Example 14: Program Info Metadata
;; ============================================================================

(println "\n=== Example 14: Program Info Metadata ===")

(def task-iter-info
  (iter/make-iter-info "task_dump" :task
                       (iter/minimal-task-iterator)))

(println "Iterator program info:")
(println "  Name:" (:name task-iter-info))
(println "  Section:" (:section task-iter-info))
(println "  Type:" (:type task-iter-info))
(println "  Attach type:" (:attach-type task-iter-info))
(println "  BTF type:" (:btf-type task-iter-info))

;; ============================================================================
;; Conceptual Usage Example
;; ============================================================================

(println "\n=== Conceptual Usage (Requires Root + Kernel 5.8+) ===")

(println "
;; Real-world usage would look like:

(require '[clj-ebpf.programs :as progs])

;; 1. Build iterator program
(def task-iter-bytecode
  (iter/build-iter-program
    {:ctx-reg :r6
     :meta-reg :r8
     :body [...]  ; Your iteration logic
     :default-action :continue}))

;; 2. Load the program
(def prog
  (progs/load-iterator-program
    task-iter-bytecode
    :task
    {:license \"GPL\"
     :prog-name \"task_dump\"}))

;; 3. Create iterator and read output
(progs/with-iterator [iter prog {:iter-type :task}]
  ;; Read from iterator FD
  (let [output (slurp (str \"/proc/self/fd/\" (:iter-fd iter)))]
    (println output)))

;; Cleanup is automatic with with-iterator
")

;; ============================================================================
;; Summary
;; ============================================================================

(println "\n=== Summary ===")
(println "
BPF Iterators provide a way to dump kernel data structures:

Key concepts:
- Program type: TRACING (26)
- Attach type: TRACE_ITER (28)
- Reading from iterator FD triggers BPF program per element
- bpf_seq_write/bpf_seq_printf for output
- Return 0 to continue, 1 to stop

Common iterator types:
- task: All processes/threads
- bpf_map: All BPF maps
- bpf_map_elem: Elements in a specific map
- tcp/udp: Network sockets
- bpf_prog/bpf_link: BPF objects

Kernel requirements:
- Linux 5.8+ for BPF iterators
- BTF support required
- CAP_BPF + CAP_PERFMON capabilities

This example demonstrated:
- Iterator context structures
- NULL handling patterns
- bpf_seq_write usage
- Return value patterns
- Using program builder and macros
- Section names for ELF output
")

(defn -main [& _args]
  (println "\n=== BPF Iterator Example Complete ==="))
