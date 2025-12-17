(ns clj-ebpf.dsl.jump
  "Jump and control flow operations for BPF programs.

   Provides:
   - Conditional jumps (jeq, jne, jgt, jge, etc.)
   - Unconditional jumps (ja)
   - Function calls (call, call-helper)
   - Program exit (exit)"
  (:require [clj-ebpf.dsl.instructions :as insn]
            [clj-ebpf.helpers :as helpers]))

;; ============================================================================
;; Jump Operation Mapping
;; ============================================================================

(def jmp-ops
  "Map of jump operation keywords to BPF opcodes"
  {:ja   insn/BPF_JA    ; Unconditional jump
   :jeq  insn/BPF_JEQ   ; Jump if equal
   :jne  insn/BPF_JNE   ; Jump if not equal
   :jgt  insn/BPF_JGT   ; Jump if greater (unsigned)
   :jge  insn/BPF_JGE   ; Jump if greater or equal (unsigned)
   :jlt  insn/BPF_JLT   ; Jump if less than (unsigned)
   :jle  insn/BPF_JLE   ; Jump if less or equal (unsigned)
   :jset insn/BPF_JSET  ; Jump if bitwise AND is non-zero
   :jsgt insn/BPF_JSGT  ; Jump if greater (signed)
   :jsge insn/BPF_JSGE  ; Jump if greater or equal (signed)
   :jslt insn/BPF_JSLT  ; Jump if less than (signed)
   :jsle insn/BPF_JSLE})  ; Jump if less or equal (signed)

;; ============================================================================
;; Conditional Jumps (64-bit comparison)
;; ============================================================================

(defn jmp-imm
  "Conditional jump with immediate comparison.

   if (dst OP imm) goto +offset

   Arguments:
   - op: Jump operation (:jeq, :jne, :jgt, etc.)
   - dst: Register to compare
   - imm: Immediate value to compare against
   - offset: Jump offset (in instructions, not bytes)"
  [op dst imm offset]
  (let [opcode (insn/make-opcode insn/BPF_JMP insn/BPF_K (get jmp-ops op))]
    (insn/make-instruction opcode dst 0 offset imm)))

(defn jmp-reg
  "Conditional jump with register comparison.

   if (dst OP src) goto +offset

   Arguments:
   - op: Jump operation (:jeq, :jne, :jgt, etc.)
   - dst: Register to compare
   - src: Register to compare against
   - offset: Jump offset (in instructions)"
  [op dst src offset]
  (let [opcode (insn/make-opcode insn/BPF_JMP insn/BPF_X (get jmp-ops op))]
    (insn/make-instruction opcode dst src offset 0)))

;; ============================================================================
;; Conditional Jumps (32-bit comparison)
;; ============================================================================

(defn jmp32-imm
  "32-bit conditional jump with immediate comparison.

   if ((u32)dst OP imm) goto +offset"
  [op dst imm offset]
  (let [opcode (insn/make-opcode insn/BPF_JMP32 insn/BPF_K (get jmp-ops op))]
    (insn/make-instruction opcode dst 0 offset imm)))

(defn jmp32-reg
  "32-bit conditional jump with register comparison.

   if ((u32)dst OP (u32)src) goto +offset"
  [op dst src offset]
  (let [opcode (insn/make-opcode insn/BPF_JMP32 insn/BPF_X (get jmp-ops op))]
    (insn/make-instruction opcode dst src offset 0)))

;; ============================================================================
;; Unconditional Jump
;; ============================================================================

(defn ja
  "Unconditional jump.

   goto +offset

   Arguments:
   - offset: Jump offset (in instructions)"
  [offset]
  (let [opcode (insn/make-opcode insn/BPF_JMP insn/BPF_K insn/BPF_JA)]
    (insn/make-instruction opcode 0 0 offset 0)))

;; ============================================================================
;; Jump Convenience Functions (64-bit)
;; ============================================================================

(defn jeq
  "Jump if equal.

   if (dst == src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jeq dst src-or-imm offset)
     (jmp-imm :jeq dst src-or-imm offset))))

(defn jne
  "Jump if not equal.

   if (dst != src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jne dst src-or-imm offset)
     (jmp-imm :jne dst src-or-imm offset))))

(defn jgt
  "Jump if greater than (unsigned).

   if (dst > src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jgt dst src-or-imm offset)
     (jmp-imm :jgt dst src-or-imm offset))))

(defn jge
  "Jump if greater than or equal (unsigned).

   if (dst >= src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jge dst src-or-imm offset)
     (jmp-imm :jge dst src-or-imm offset))))

(defn jlt
  "Jump if less than (unsigned).

   if (dst < src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jlt dst src-or-imm offset)
     (jmp-imm :jlt dst src-or-imm offset))))

(defn jle
  "Jump if less than or equal (unsigned).

   if (dst <= src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jle dst src-or-imm offset)
     (jmp-imm :jle dst src-or-imm offset))))

(defn jset
  "Jump if bitwise AND is non-zero.

   if (dst & src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jset dst src-or-imm offset)
     (jmp-imm :jset dst src-or-imm offset))))

(defn jsgt
  "Jump if greater than (signed).

   if ((s64)dst > (s64)src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jsgt dst src-or-imm offset)
     (jmp-imm :jsgt dst src-or-imm offset))))

(defn jsge
  "Jump if greater than or equal (signed).

   if ((s64)dst >= (s64)src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jsge dst src-or-imm offset)
     (jmp-imm :jsge dst src-or-imm offset))))

(defn jslt
  "Jump if less than (signed).

   if ((s64)dst < (s64)src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jslt dst src-or-imm offset)
     (jmp-imm :jslt dst src-or-imm offset))))

(defn jsle
  "Jump if less than or equal (signed).

   if ((s64)dst <= (s64)src/imm) goto +offset"
  ([dst src-or-imm offset]
   (if (keyword? src-or-imm)
     (jmp-reg :jsle dst src-or-imm offset)
     (jmp-imm :jsle dst src-or-imm offset))))

;; ============================================================================
;; Function Call
;; ============================================================================

(defn call
  "Call a BPF helper function.

   r0 = bpf_helper(r1, r2, r3, r4, r5)

   Arguments:
   - helper-id: BPF helper function ID (e.g., 1 for map_lookup_elem)"
  [helper-id]
  (let [opcode (insn/make-opcode insn/BPF_JMP insn/BPF_K insn/BPF_CALL)]
    (insn/make-instruction opcode 0 0 0 helper-id)))

(defn call-helper
  "Call a BPF helper function by keyword name.

   r0 = bpf_helper(r1, r2, r3, r4, r5)

   Arguments:
   - helper-key: Keyword name of the helper (e.g., :map-lookup-elem, :ringbuf-reserve)

   Example:
     (call-helper :get-current-pid-tgid)  ; Returns current PID/TGID in r0
     (call-helper :ringbuf-reserve)       ; Reserve ring buffer space
     (call-helper :ktime-get-ns)          ; Get kernel timestamp

   See clj-ebpf.helpers/helper-functions for all available helpers."
  [helper-key]
  (if-let [id (helpers/get-helper-id helper-key)]
    (call id)
    (throw (ex-info (str "Unknown BPF helper: " helper-key)
                    {:helper helper-key
                     :available-helpers (helpers/list-helpers)}))))

(defn tail-call
  "Generate a tail call to another BPF program.

   This is essentially: bpf_tail_call(ctx, prog_array, index)
   Helper ID 12 = bpf_tail_call"
  []
  (call 12))

;; ============================================================================
;; Program Exit
;; ============================================================================

(defn exit-insn
  "Exit the BPF program.

   return r0

   The value in r0 is returned to the caller."
  []
  (let [opcode (insn/make-opcode insn/BPF_JMP insn/BPF_K insn/BPF_EXIT)]
    (insn/make-instruction opcode 0 0 0 0)))

;; ============================================================================
;; Label Support (for assembler)
;; ============================================================================

(defrecord Label [name])

(defn label
  "Create a label marker for the assembler.

   Labels are resolved during assembly to compute jump offsets."
  [name]
  (->Label name))

(defn label?
  "Check if an instruction is a label."
  [insn]
  (instance? Label insn))

(defrecord LabelRef [name])

(defn label-ref
  "Create a reference to a label.

   Used as the offset argument in jump instructions."
  [name]
  (->LabelRef name))

(defn label-ref?
  "Check if a value is a label reference."
  [v]
  (instance? LabelRef v))

;; ============================================================================
;; Jump with Label Support
;; ============================================================================

(defn jeq-label
  "Jump if equal to label.

   if (dst == src/imm) goto label"
  [dst src-or-imm label-name]
  (if (keyword? src-or-imm)
    (jmp-reg :jeq dst src-or-imm (label-ref label-name))
    (jmp-imm :jeq dst src-or-imm (label-ref label-name))))

(defn jne-label
  "Jump if not equal to label."
  [dst src-or-imm label-name]
  (if (keyword? src-or-imm)
    (jmp-reg :jne dst src-or-imm (label-ref label-name))
    (jmp-imm :jne dst src-or-imm (label-ref label-name))))

(defn ja-label
  "Unconditional jump to label."
  [label-name]
  (ja (label-ref label-name)))
