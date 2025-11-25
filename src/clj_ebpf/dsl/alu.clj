(ns clj-ebpf.dsl.alu
  "ALU (Arithmetic Logic Unit) operations for BPF programs.

   Provides 32-bit and 64-bit arithmetic operations:
   - Arithmetic: add, sub, mul, div, mod, neg
   - Bitwise: and, or, xor, lsh, rsh, arsh
   - Data movement: mov
   - Endianness conversion: end-to-be, end-to-le"
  (:require [clj-ebpf.dsl.instructions :as insn]))

;; ============================================================================
;; ALU Operation Mapping
;; ============================================================================

(def alu-ops
  "Map of ALU operation keywords to BPF opcodes"
  {:add  insn/BPF_ADD
   :sub  insn/BPF_SUB
   :mul  insn/BPF_MUL
   :div  insn/BPF_DIV
   :or   insn/BPF_OR
   :and  insn/BPF_AND
   :lsh  insn/BPF_LSH
   :rsh  insn/BPF_RSH
   :neg  insn/BPF_NEG
   :mod  insn/BPF_MOD
   :xor  insn/BPF_XOR
   :mov  insn/BPF_MOV
   :arsh insn/BPF_ARSH
   :end  insn/BPF_END})

;; ============================================================================
;; 64-bit ALU Operations
;; ============================================================================

(defn alu64-reg
  "64-bit ALU operation with register source.

   dst = dst OP src

   Arguments:
   - op: Operation keyword (:add, :sub, :mul, etc.)
   - dst: Destination register
   - src: Source register"
  [op dst src]
  (let [opcode (insn/make-opcode insn/BPF_ALU64 insn/BPF_X (get alu-ops op))]
    (insn/make-instruction opcode dst src 0 0)))

(defn alu64-imm
  "64-bit ALU operation with immediate source.

   dst = dst OP imm

   Arguments:
   - op: Operation keyword (:add, :sub, :mul, etc.)
   - dst: Destination register
   - imm: Immediate value (32-bit)"
  [op dst imm]
  (let [opcode (insn/make-opcode insn/BPF_ALU64 insn/BPF_K (get alu-ops op))]
    (insn/make-instruction opcode dst 0 0 imm)))

;; ============================================================================
;; 32-bit ALU Operations
;; ============================================================================

(defn alu32-reg
  "32-bit ALU operation with register source.

   (u32)dst = (u32)dst OP (u32)src

   Arguments:
   - op: Operation keyword (:add, :sub, :mul, etc.)
   - dst: Destination register
   - src: Source register"
  [op dst src]
  (let [opcode (insn/make-opcode insn/BPF_ALU insn/BPF_X (get alu-ops op))]
    (insn/make-instruction opcode dst src 0 0)))

(defn alu32-imm
  "32-bit ALU operation with immediate source.

   (u32)dst = (u32)dst OP imm

   Arguments:
   - op: Operation keyword (:add, :sub, :mul, etc.)
   - dst: Destination register
   - imm: Immediate value (32-bit)"
  [op dst imm]
  (let [opcode (insn/make-opcode insn/BPF_ALU insn/BPF_K (get alu-ops op))]
    (insn/make-instruction opcode dst 0 0 imm)))

;; ============================================================================
;; Move Operations
;; ============================================================================

(defn mov
  "Move immediate to register (64-bit).

   dst = imm

   Arguments:
   - dst: Destination register
   - imm: Immediate value (32-bit, sign-extended to 64-bit)"
  [dst imm]
  (alu64-imm :mov dst imm))

(defn mov-reg
  "Move register to register (64-bit).

   dst = src

   Arguments:
   - dst: Destination register
   - src: Source register"
  [dst src]
  (alu64-reg :mov dst src))

(defn mov32
  "Move immediate to register (32-bit).

   (u32)dst = imm

   Arguments:
   - dst: Destination register
   - imm: Immediate value (32-bit)"
  [dst imm]
  (alu32-imm :mov dst imm))

(defn mov32-reg
  "Move register to register (32-bit).

   (u32)dst = (u32)src

   Arguments:
   - dst: Destination register
   - src: Source register"
  [dst src]
  (alu32-reg :mov dst src))

;; ============================================================================
;; Arithmetic Convenience Functions (64-bit)
;; ============================================================================

(defn add
  "Add immediate to register.

   dst += imm"
  [dst imm]
  (alu64-imm :add dst imm))

(defn add-reg
  "Add register to register.

   dst += src"
  [dst src]
  (alu64-reg :add dst src))

(defn sub
  "Subtract immediate from register.

   dst -= imm"
  [dst imm]
  (alu64-imm :sub dst imm))

(defn sub-reg
  "Subtract register from register.

   dst -= src"
  [dst src]
  (alu64-reg :sub dst src))

(defn mul
  "Multiply register by immediate.

   dst *= imm"
  [dst imm]
  (alu64-imm :mul dst imm))

(defn mul-reg
  "Multiply register by register.

   dst *= src"
  [dst src]
  (alu64-reg :mul dst src))

(defn div
  "Divide register by immediate.

   dst /= imm"
  [dst imm]
  (alu64-imm :div dst imm))

(defn div-reg
  "Divide register by register.

   dst /= src"
  [dst src]
  (alu64-reg :div dst src))

(defn mod-op
  "Modulo register by immediate.

   dst %= imm"
  [dst imm]
  (alu64-imm :mod dst imm))

(defn mod-reg
  "Modulo register by register.

   dst %= src"
  [dst src]
  (alu64-reg :mod dst src))

(defn neg-reg
  "Negate register.

   dst = -dst"
  [dst]
  (alu64-imm :neg dst 0))

;; ============================================================================
;; Bitwise Convenience Functions (64-bit)
;; ============================================================================

(defn and-op
  "Bitwise AND register with immediate.

   dst &= imm"
  [dst imm]
  (alu64-imm :and dst imm))

(defn and-reg
  "Bitwise AND register with register.

   dst &= src"
  [dst src]
  (alu64-reg :and dst src))

(defn or-op
  "Bitwise OR register with immediate.

   dst |= imm"
  [dst imm]
  (alu64-imm :or dst imm))

(defn or-reg
  "Bitwise OR register with register.

   dst |= src"
  [dst src]
  (alu64-reg :or dst src))

(defn xor-op
  "Bitwise XOR register with immediate.

   dst ^= imm"
  [dst imm]
  (alu64-imm :xor dst imm))

(defn xor-reg
  "Bitwise XOR register with register.

   dst ^= src"
  [dst src]
  (alu64-reg :xor dst src))

(defn lsh
  "Left shift register by immediate.

   dst <<= imm"
  [dst imm]
  (alu64-imm :lsh dst imm))

(defn lsh-reg
  "Left shift register by register.

   dst <<= src"
  [dst src]
  (alu64-reg :lsh dst src))

(defn rsh
  "Right shift register by immediate (logical).

   dst >>= imm"
  [dst imm]
  (alu64-imm :rsh dst imm))

(defn rsh-reg
  "Right shift register by register (logical).

   dst >>= src"
  [dst src]
  (alu64-reg :rsh dst src))

(defn arsh
  "Arithmetic right shift by immediate.

   dst >>>= imm (preserving sign)"
  [dst imm]
  (alu64-imm :arsh dst imm))

(defn arsh-reg
  "Arithmetic right shift by register.

   dst >>>= src (preserving sign)"
  [dst src]
  (alu64-reg :arsh dst src))

;; ============================================================================
;; Endianness Conversion
;; ============================================================================

(defn end-to-be
  "Convert register to big-endian.

   Arguments:
   - dst: Register to convert
   - size: Size in bits (16, 32, or 64)"
  [dst size]
  (let [opcode (insn/make-opcode insn/BPF_ALU insn/BPF_X insn/BPF_END)]
    (insn/make-instruction opcode dst 0 0 size)))

(defn end-to-le
  "Convert register to little-endian.

   Arguments:
   - dst: Register to convert
   - size: Size in bits (16, 32, or 64)"
  [dst size]
  (let [opcode (insn/make-opcode insn/BPF_ALU insn/BPF_K insn/BPF_END)]
    (insn/make-instruction opcode dst 0 0 size)))

(defn bswap16
  "Byte swap 16-bit value (big-endian to little-endian or vice versa)."
  [dst]
  (end-to-be dst 16))

(defn bswap32
  "Byte swap 32-bit value."
  [dst]
  (end-to-be dst 32))

(defn bswap64
  "Byte swap 64-bit value."
  [dst]
  (end-to-be dst 64))

;; ============================================================================
;; 32-bit Arithmetic Convenience Functions
;; ============================================================================

(defn add32
  "Add immediate to register (32-bit).

   (u32)dst += imm"
  [dst imm]
  (alu32-imm :add dst imm))

(defn add32-reg
  "Add register to register (32-bit).

   (u32)dst += (u32)src"
  [dst src]
  (alu32-reg :add dst src))

(defn sub32
  "Subtract immediate from register (32-bit).

   (u32)dst -= imm"
  [dst imm]
  (alu32-imm :sub dst imm))

(defn sub32-reg
  "Subtract register from register (32-bit).

   (u32)dst -= (u32)src"
  [dst src]
  (alu32-reg :sub dst src))
