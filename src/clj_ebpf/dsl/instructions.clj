(ns clj-ebpf.dsl.instructions
  "Low-level BPF instruction encoding.

   This namespace provides the fundamental BPF instruction encoding primitives.
   It defines:
   - Instruction format constants
   - Opcode construction
   - Single instruction encoding
   - Register definitions

   BPF instructions are 64-bit:
   |immediate:32|offset:16|src_reg:4|dst_reg:4|opcode:8|")

;; ============================================================================
;; Instruction Classes (3 LSB bits of opcode)
;; ============================================================================

(def ^:const BPF_LD    0x00)  ; Non-standard load
(def ^:const BPF_LDX   0x01)  ; Load into register
(def ^:const BPF_ST    0x02)  ; Store from immediate
(def ^:const BPF_STX   0x03)  ; Store from register
(def ^:const BPF_ALU   0x04)  ; 32-bit arithmetic
(def ^:const BPF_JMP   0x05)  ; 64-bit jump
(def ^:const BPF_JMP32 0x06)  ; 32-bit jump
(def ^:const BPF_ALU64 0x07)  ; 64-bit arithmetic

;; ============================================================================
;; Source Operand (bit 3 of opcode)
;; ============================================================================

(def ^:const BPF_K   0x00)  ; Immediate
(def ^:const BPF_X   0x08)  ; Register

;; ============================================================================
;; ALU/ALU64 Operations (bits 4-7 of opcode)
;; ============================================================================

(def ^:const BPF_ADD  0x00)
(def ^:const BPF_SUB  0x10)
(def ^:const BPF_MUL  0x20)
(def ^:const BPF_DIV  0x30)
(def ^:const BPF_OR   0x40)
(def ^:const BPF_AND  0x50)
(def ^:const BPF_LSH  0x60)
(def ^:const BPF_RSH  0x70)
(def ^:const BPF_NEG  0x80)
(def ^:const BPF_MOD  0x90)
(def ^:const BPF_XOR  0xa0)
(def ^:const BPF_MOV  0xb0)
(def ^:const BPF_ARSH 0xc0)
(def ^:const BPF_END  0xd0)

;; ============================================================================
;; Jump Operations (bits 4-7 of opcode)
;; ============================================================================

(def ^:const BPF_JA   0x00)  ; Unconditional jump
(def ^:const BPF_JEQ  0x10)  ; Jump if equal
(def ^:const BPF_JGT  0x20)  ; Jump if greater (unsigned)
(def ^:const BPF_JGE  0x30)  ; Jump if greater or equal (unsigned)
(def ^:const BPF_JSET 0x40)  ; Jump if bitwise AND is non-zero
(def ^:const BPF_JNE  0x50)  ; Jump if not equal
(def ^:const BPF_JSGT 0x60)  ; Jump if greater (signed)
(def ^:const BPF_JSGE 0x70)  ; Jump if greater or equal (signed)
(def ^:const BPF_CALL 0x80)  ; Function/helper call
(def ^:const BPF_EXIT 0x90)  ; Exit program
(def ^:const BPF_JLT  0xa0)  ; Jump if less than (unsigned)
(def ^:const BPF_JLE  0xb0)  ; Jump if less or equal (unsigned)
(def ^:const BPF_JSLT 0xc0)  ; Jump if less than (signed)
(def ^:const BPF_JSLE 0xd0)  ; Jump if less or equal (signed)

;; ============================================================================
;; Load/Store Size (bits 3-4 of opcode)
;; ============================================================================

(def ^:const BPF_W  0x00)  ; 4 bytes (word)
(def ^:const BPF_H  0x08)  ; 2 bytes (half-word)
(def ^:const BPF_B  0x10)  ; 1 byte
(def ^:const BPF_DW 0x18)  ; 8 bytes (double-word)

;; ============================================================================
;; Load/Store Mode (bits 5-7 of opcode)
;; ============================================================================

(def ^:const BPF_IMM    0x00)  ; 64-bit immediate
(def ^:const BPF_ABS    0x20)  ; Packet access (absolute)
(def ^:const BPF_IND    0x40)  ; Packet access (indirect)
(def ^:const BPF_MEM    0x60)  ; Regular memory
(def ^:const BPF_ATOMIC 0xc0)  ; Atomic operations

;; ============================================================================
;; Atomic Operations (immediate field)
;; ============================================================================

(def ^:const BPF_ATOMIC_ADD    0x00)
(def ^:const BPF_ATOMIC_OR     0x40)
(def ^:const BPF_ATOMIC_AND    0x50)
(def ^:const BPF_ATOMIC_XOR    0xa0)
(def ^:const BPF_ATOMIC_XCHG   0xe0)
(def ^:const BPF_ATOMIC_CMPXCHG 0xf0)
(def ^:const BPF_ATOMIC_FETCH  0x01)  ; OR with above for fetch variant

;; ============================================================================
;; Registers
;; ============================================================================

(def registers
  "BPF register mapping"
  {:r0  0   ; Return value
   :r1  1   ; Argument 1 / context pointer
   :r2  2   ; Argument 2
   :r3  3   ; Argument 3
   :r4  4   ; Argument 4
   :r5  5   ; Argument 5
   :r6  6   ; Callee-saved
   :r7  7   ; Callee-saved
   :r8  8   ; Callee-saved
   :r9  9   ; Callee-saved
   :r10 10  ; Frame pointer (read-only)
   :fp  10})  ; Alias for r10

(defn reg->num
  "Convert register keyword to number"
  [reg]
  (if (keyword? reg)
    (get registers reg)
    reg))

;; ============================================================================
;; Opcode Construction
;; ============================================================================

(defn make-opcode
  "Construct an opcode from class, source, and operation.

   Arguments:
   - class: BPF_ALU, BPF_ALU64, BPF_JMP, etc.
   - src: BPF_K (immediate) or BPF_X (register)
   - op: Operation code (BPF_ADD, BPF_JEQ, etc.)"
  [class src op]
  (bit-or class src op))

(defn make-ld-opcode
  "Construct a load opcode.

   Arguments:
   - size: BPF_B, BPF_H, BPF_W, or BPF_DW
   - mode: BPF_IMM, BPF_MEM, BPF_ABS, BPF_IND"
  [size mode]
  (bit-or BPF_LDX size mode))

(defn make-st-opcode
  "Construct a store opcode.

   Arguments:
   - size: BPF_B, BPF_H, BPF_W, or BPF_DW
   - src: BPF_K (from immediate) or BPF_X (from register)"
  [size src]
  (if (= src BPF_K)
    (bit-or BPF_ST size BPF_MEM)
    (bit-or BPF_STX size BPF_MEM)))

;; ============================================================================
;; Instruction Encoding
;; ============================================================================

(defrecord Instruction
  [^byte opcode
   ^byte dst
   ^byte src
   ^short offset
   ^int imm])

(defn make-instruction
  "Create a BPF instruction.

   Arguments:
   - opcode: Instruction opcode
   - dst: Destination register (0-10)
   - src: Source register (0-10)
   - offset: 16-bit signed offset
   - imm: 32-bit immediate value

   Returns an Instruction record."
  [opcode dst src offset imm]
  (->Instruction
   (unchecked-byte opcode)
   (unchecked-byte (reg->num dst))
   (unchecked-byte (reg->num src))
   (unchecked-short offset)
   (unchecked-int imm)))

(defn instruction->bytes
  "Encode an instruction to 8 bytes (little-endian).

   BPF instruction format:
   Byte 0: opcode
   Byte 1: dst:4 | src:4
   Bytes 2-3: offset (little-endian)
   Bytes 4-7: immediate (little-endian)"
  [{:keys [opcode dst src offset imm]}]
  (let [bytes (byte-array 8)]
    (aset bytes 0 (unchecked-byte opcode))
    (aset bytes 1 (unchecked-byte (bit-or (bit-shift-left (bit-and src 0xf) 4)
                                          (bit-and dst 0xf))))
    (aset bytes 2 (unchecked-byte (bit-and offset 0xff)))
    (aset bytes 3 (unchecked-byte (bit-and (bit-shift-right offset 8) 0xff)))
    (aset bytes 4 (unchecked-byte (bit-and imm 0xff)))
    (aset bytes 5 (unchecked-byte (bit-and (bit-shift-right imm 8) 0xff)))
    (aset bytes 6 (unchecked-byte (bit-and (bit-shift-right imm 16) 0xff)))
    (aset bytes 7 (unchecked-byte (bit-and (bit-shift-right imm 24) 0xff)))
    bytes))

(defn instructions->bytes
  "Encode a sequence of instructions to bytes."
  [insns]
  (let [total-size (* 8 (count insns))
        result (byte-array total-size)]
    (loop [insns insns
           offset 0]
      (if (seq insns)
        (let [insn-bytes (instruction->bytes (first insns))]
          (System/arraycopy insn-bytes 0 result offset 8)
          (recur (rest insns) (+ offset 8)))
        result))))

;; ============================================================================
;; Instruction Validation
;; ============================================================================

(defn valid-register?
  "Check if a value is a valid register."
  [r]
  (let [n (reg->num r)]
    (and (integer? n) (<= 0 n 10))))

(defn valid-offset?
  "Check if a value is a valid 16-bit signed offset."
  [o]
  (and (integer? o)
       (<= -32768 o 32767)))

(defn valid-imm32?
  "Check if a value is a valid 32-bit immediate."
  [i]
  (and (integer? i)
       (<= Integer/MIN_VALUE i Integer/MAX_VALUE)))

(defn valid-instruction?
  "Check if an instruction record is valid."
  [insn]
  (and (instance? Instruction insn)
       (integer? (:opcode insn))
       (valid-register? (:dst insn))
       (valid-register? (:src insn))
       (valid-offset? (:offset insn))
       (valid-imm32? (:imm insn))))
