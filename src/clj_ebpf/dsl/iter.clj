(ns clj-ebpf.dsl.iter
  "High-level BPF Iterator DSL for tracing programs.

   BPF Iterators (bpf_iter) allow BPF programs to dump kernel data
   structures by iterating over them. Reading from an iterator FD
   triggers the BPF program for each element.

   Common iterator types:
   - task: Iterate over all tasks/processes
   - bpf_map: Iterate over BPF maps
   - bpf_map_elem: Iterate over elements in a specific map
   - tcp: Iterate over TCP sockets
   - udp: Iterate over UDP sockets
   - netlink: Iterate over netlink sockets
   - bpf_prog: Iterate over BPF programs
   - bpf_link: Iterate over BPF links

   Iterator programs use:
   - bpf_seq_write: Write raw bytes to output
   - bpf_seq_printf: Write formatted output (like printf)

   Context varies by iterator type:
   - bpf_iter__task: struct task_struct *task
   - bpf_iter__bpf_map: struct bpf_map *map
   - etc."
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Iterator Types and Context Offsets
;; ============================================================================

(def iterator-types
  "Common BPF iterator types and their BTF names."
  {:task          "bpf_iter__task"
   :task-file     "bpf_iter__task_file"
   :bpf-map       "bpf_iter__bpf_map"
   :bpf-map-elem  "bpf_iter__bpf_map_elem"
   :bpf-prog      "bpf_iter__bpf_prog"
   :bpf-link      "bpf_iter__bpf_link"
   :tcp           "bpf_iter__tcp"
   :udp           "bpf_iter__udp"
   :unix          "bpf_iter__unix"
   :netlink       "bpf_iter__netlink"
   :ipv6-route    "bpf_iter__ipv6_route"
   :sockmap       "bpf_iter__sockmap"
   :ksym          "bpf_iter__ksym"})

(def iter-context-offsets
  "Context structure offsets for different iterator types.
   All iterator contexts start with:
   - meta (struct bpf_iter_meta *) at offset 0
   - type-specific pointer at offset 8

   bpf_iter_meta contains:
   - seq (struct seq_file *) at offset 0
   - session_id at offset 8
   - seq_num at offset 16"
  {:meta       0
   :task       8
   :map        8
   :key        8
   :value      16
   :prog       8
   :link       8
   :tcp-sk     8
   :udp-sk     8
   :file       16})

(def iter-meta-offsets
  "Offsets within bpf_iter_meta structure."
  {:seq        0
   :session-id 8
   :seq-num    16})

(defn iter-context-offset
  "Get the offset for an iterator context field.

   Parameters:
   - field: Field keyword (e.g., :meta, :task, :map)

   Returns offset or throws on invalid field."
  [field]
  (or (get iter-context-offsets field)
      (throw (ex-info "Unknown iterator context field"
                      {:field field
                       :valid-fields (keys iter-context-offsets)}))))

;; ============================================================================
;; Return Values
;; ============================================================================

(def iter-return-values
  "BPF iterator return values."
  {:continue 0
   :stop     1})

(defn iter-return-value
  "Get numeric value for iterator return code.

   Parameters:
   - action: :continue or :stop

   Returns numeric value."
  [action]
  (or (get iter-return-values action)
      (throw (ex-info "Unknown iterator return value"
                      {:action action
                       :valid-actions (keys iter-return-values)}))))

;; ============================================================================
;; BPF Helper IDs for Iterators
;; ============================================================================

(def iter-helper-ids
  "BPF helper function IDs used by iterators."
  {:seq-printf         126
   :seq-write          127
   :seq-printf-btf     128
   :get-current-task   35
   :probe-read-kernel  113
   :probe-read-str     45})

;; ============================================================================
;; Iterator Prologue
;; ============================================================================

(defn iter-prologue
  "Generate standard iterator program prologue.

   Iterator programs receive context in r1:
   - r1 points to iterator-specific context structure

   Parameters:
   - ctx-reg: Register to save context pointer (e.g., :r6)

   Returns vector of instructions."
  [ctx-reg]
  [(dsl/mov-reg ctx-reg :r1)])

(defn iter-prologue-with-meta
  "Generate iterator prologue that also loads meta pointer.

   Parameters:
   - ctx-reg: Register to save context pointer
   - meta-reg: Register to load meta pointer into

   Returns vector of instructions."
  [ctx-reg meta-reg]
  [(dsl/mov-reg ctx-reg :r1)
   (dsl/ldx :dw meta-reg ctx-reg (iter-context-offset :meta))])

;; ============================================================================
;; Context Field Access
;; ============================================================================

(defn iter-load-ctx-ptr
  "Load a pointer field from iterator context.

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register for loaded pointer
   - field: Field keyword (e.g., :task, :map, :meta)

   Returns ldx instruction."
  [ctx-reg dst-reg field]
  (dsl/ldx :dw dst-reg ctx-reg (iter-context-offset field)))

(defn iter-load-meta-field
  "Load a field from bpf_iter_meta structure.

   Parameters:
   - meta-reg: Register containing meta pointer
   - dst-reg: Destination register
   - field: Field keyword (:seq, :session-id, :seq-num)

   Returns ldx instruction."
  [meta-reg dst-reg field]
  (let [offset (or (get iter-meta-offsets field)
                   (throw (ex-info "Unknown meta field"
                                   {:field field
                                    :valid-fields (keys iter-meta-offsets)})))]
    (dsl/ldx :dw dst-reg meta-reg offset)))

;; ============================================================================
;; NULL Checks (for end of iteration)
;; ============================================================================

(defn iter-check-null
  "Generate NULL check for iterator element.

   At the end of iteration, the element pointer is NULL.
   This generates instructions to check and skip if NULL.

   Parameters:
   - ptr-reg: Register containing pointer to check
   - skip-count: Number of instructions to skip if NULL

   Returns vector of instructions."
  [ptr-reg skip-count]
  [(dsl/jmp-imm :jeq ptr-reg 0 skip-count)])

(defn iter-check-null-and-exit
  "Check if pointer is NULL and exit with 0 if so.

   Common pattern for handling end of iteration.

   Parameters:
   - ptr-reg: Register containing pointer to check

   Returns vector of instructions that exits if NULL."
  [ptr-reg]
  [(dsl/jmp-imm :jne ptr-reg 0 2)
   (dsl/mov :r0 0)
   (dsl/exit-insn)])

;; ============================================================================
;; seq_write Helper
;; ============================================================================

(defn seq-write
  "Generate bpf_seq_write helper call.

   Writes raw bytes to the seq_file output.

   Signature:
     long bpf_seq_write(struct seq_file *m, const void *data, u32 len)

   Parameters:
   - meta-reg: Register with bpf_iter_meta pointer (seq is at offset 0)
   - data-reg: Register with pointer to data buffer
   - len: Length to write (immediate or register)

   Returns vector of instructions."
  ([meta-reg data-reg len]
   (if (number? len)
     [(dsl/ldx :dw :r1 meta-reg 0)
      (dsl/mov-reg :r2 data-reg)
      (dsl/mov :r3 len)
      (dsl/call (:seq-write iter-helper-ids))]
     [(dsl/ldx :dw :r1 meta-reg 0)
      (dsl/mov-reg :r2 data-reg)
      (dsl/mov-reg :r3 len)
      (dsl/call (:seq-write iter-helper-ids))])))

;; ============================================================================
;; seq_printf Helper
;; ============================================================================

(defn seq-printf-simple
  "Generate bpf_seq_printf helper call with simple format.

   Writes formatted output. Limited to 3 format arguments.

   Signature:
     long bpf_seq_printf(struct seq_file *m, const char *fmt,
                         u32 fmt_size, const void *data, u32 data_len)

   Note: This is a simplified version. For full seq_printf with
   format arguments, you need to set up a data array on the stack.

   Parameters:
   - meta-reg: Register with bpf_iter_meta pointer
   - fmt-ptr-reg: Register with pointer to format string
   - fmt-len: Format string length
   - data-ptr-reg: Register with pointer to data array (or 0 for no args)
   - data-len: Data array length (or 0)

   Returns vector of instructions."
  [meta-reg fmt-ptr-reg fmt-len data-ptr-reg data-len]
  [(dsl/ldx :dw :r1 meta-reg 0)
   (dsl/mov-reg :r2 fmt-ptr-reg)
   (dsl/mov :r3 fmt-len)
   (dsl/mov-reg :r4 data-ptr-reg)
   (dsl/mov :r5 data-len)
   (dsl/call (:seq-printf iter-helper-ids))])

;; ============================================================================
;; Return Patterns
;; ============================================================================

(defn iter-return-continue
  "Generate instructions to continue iteration.

   Returns 0 to continue to next element."
  []
  [(dsl/mov :r0 0)
   (dsl/exit-insn)])

(defn iter-return-stop
  "Generate instructions to stop iteration early.

   Returns 1 to stop iteration."
  []
  [(dsl/mov :r0 1)
   (dsl/exit-insn)])

(defn iter-return
  "Generate instructions to return from iterator.

   Parameters:
   - action: :continue or :stop

   Returns vector of instructions."
  [action]
  [(dsl/mov :r0 (iter-return-value action))
   (dsl/exit-insn)])

;; ============================================================================
;; Task Iterator Helpers
;; ============================================================================

(def task-struct-offsets
  "Common offsets in struct task_struct.
   Note: These may vary by kernel version. Use BTF for portability."
  {:pid      2376
   :tgid     2380
   :comm     2424
   :state    0
   :flags    44})

(defn task-load-pid
  "Load task PID from task_struct.

   Parameters:
   - task-reg: Register containing task_struct pointer
   - dst-reg: Destination register for PID

   Note: Offset is kernel-dependent. Use BTF for production."
  [task-reg dst-reg]
  (dsl/ldx :w dst-reg task-reg (:pid task-struct-offsets)))

(defn task-load-tgid
  "Load task TGID (thread group ID / process ID).

   Parameters:
   - task-reg: Register containing task_struct pointer
   - dst-reg: Destination register for TGID"
  [task-reg dst-reg]
  (dsl/ldx :w dst-reg task-reg (:tgid task-struct-offsets)))

;; ============================================================================
;; probe_read Helpers (for safe kernel memory access)
;; ============================================================================

(defn probe-read-kernel
  "Generate bpf_probe_read_kernel helper call.

   Safely reads kernel memory.

   Signature:
     long bpf_probe_read_kernel(void *dst, u32 size, const void *src)

   Parameters:
   - dst-reg: Register with destination buffer pointer
   - size: Number of bytes to read
   - src-reg: Register with source pointer

   Returns vector of instructions."
  [dst-reg size src-reg]
  [(dsl/mov-reg :r1 dst-reg)
   (dsl/mov :r2 size)
   (dsl/mov-reg :r3 src-reg)
   (dsl/call (:probe-read-kernel iter-helper-ids))])

(defn probe-read-kernel-str
  "Generate bpf_probe_read_kernel_str helper call.

   Safely reads null-terminated string from kernel memory.

   Signature:
     long bpf_probe_read_kernel_str(void *dst, u32 size, const void *src)

   Parameters:
   - dst-reg: Register with destination buffer pointer
   - size: Max bytes to read (including null terminator)
   - src-reg: Register with source string pointer

   Returns vector of instructions."
  [dst-reg size src-reg]
  [(dsl/mov-reg :r1 dst-reg)
   (dsl/mov :r2 size)
   (dsl/mov-reg :r3 src-reg)
   (dsl/call (:probe-read-str iter-helper-ids))])

;; ============================================================================
;; Stack Allocation Helpers
;; ============================================================================

(defn alloc-stack-buffer
  "Generate instructions to get pointer to stack buffer.

   BPF stack is accessed via r10 (frame pointer) with negative offsets.

   Parameters:
   - dst-reg: Register to store buffer pointer
   - offset: Negative offset from r10 (e.g., -64 for 64 bytes)

   Returns vector of instructions to compute buffer address."
  [dst-reg offset]
  [(dsl/mov-reg dst-reg :r10)
   (dsl/add dst-reg offset)])

;; ============================================================================
;; Program Builder
;; ============================================================================

(defn- byte-array? [x]
  (instance? (Class/forName "[B") x))

(defn build-iter-program
  "Build a complete iterator program from components.

   Parameters:
   - opts: Map with:
     - :ctx-reg - Register to save context (default :r6)
     - :meta-reg - Register for meta pointer (optional)
     - :body - Vector of instructions or instruction vectors
     - :default-action - :continue or :stop (default :continue)

   Returns assembled bytecode."
  [{:keys [ctx-reg meta-reg body default-action]
    :or {ctx-reg :r6
         default-action :continue}}]
  (let [prologue (if meta-reg
                   (iter-prologue-with-meta ctx-reg meta-reg)
                   (iter-prologue ctx-reg))
        return-insns (iter-return default-action)
        ;; Flatten body: single instructions stay as-is, vectors get flattened
        flat-body (mapcat (fn [item]
                            (cond
                              ;; Single instruction (byte array)
                              (byte-array? item) [item]
                              ;; Vector of instructions
                              (and (sequential? item)
                                   (not (empty? item))
                                   (byte-array? (first item)))
                              item
                              ;; Other sequential (probably nested)
                              (sequential? item)
                              (mapcat (fn [x]
                                        (if (byte-array? x) [x] x))
                                      item)
                              :else [item]))
                          body)]
    (dsl/assemble (vec (concat prologue flat-body return-insns)))))

;; ============================================================================
;; Section Names
;; ============================================================================

(defn iter-section-name
  "Generate ELF section name for iterator program.

   Parameters:
   - iter-type: Iterator type keyword (e.g., :task, :bpf-map)

   Returns section name string."
  [iter-type]
  (let [btf-name (get iterator-types iter-type
                      (name iter-type))]
    (str "iter/" btf-name)))

(defn make-iter-info
  "Create iterator program metadata.

   Parameters:
   - name: Program name
   - iter-type: Iterator type keyword
   - instructions: Vector of instructions

   Returns map with program metadata."
  [prog-name iter-type instructions]
  {:name prog-name
   :section (iter-section-name iter-type)
   :type :tracing
   :attach-type :trace-iter
   :iter-type iter-type
   :btf-type (get iterator-types iter-type)
   :instructions instructions})

;; ============================================================================
;; Common Iterator Program Templates
;; ============================================================================

(defn minimal-task-iterator
  "Generate minimal task iterator that just returns continue.

   Useful as a starting point or for testing."
  []
  (vec (concat
        (iter-prologue :r6)
        (iter-return-continue))))

(defn task-null-check-template
  "Generate task iterator template with NULL check.

   Parameters:
   - body-insns: Instructions to execute for each non-NULL task

   Returns complete instruction vector."
  [body-insns]
  (let [body-count (count body-insns)
        skip-count (+ body-count 2)]
    (vec (concat
          (iter-prologue :r6)
          [(iter-load-ctx-ptr :r6 :r7 :task)]
          (iter-check-null :r7 skip-count)
          body-insns
          (iter-return-continue)
          (iter-return-continue)))))

;; ============================================================================
;; Byte Order Utilities
;; ============================================================================

(defn htons
  "Convert 16-bit value from host to network byte order."
  [x]
  (bit-or (bit-and (bit-shift-right x 8) 0xFF)
          (bit-shift-left (bit-and x 0xFF) 8)))

(defn htonl
  "Convert 32-bit value from host to network byte order."
  [x]
  (bit-or
   (bit-shift-left (bit-and x 0xFF) 24)
   (bit-shift-left (bit-and (bit-shift-right x 8) 0xFF) 16)
   (bit-shift-left (bit-and (bit-shift-right x 16) 0xFF) 8)
   (bit-and (bit-shift-right x 24) 0xFF)))
