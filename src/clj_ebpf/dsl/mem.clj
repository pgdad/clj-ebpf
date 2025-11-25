(ns clj-ebpf.dsl.mem
  "Memory operations for BPF programs.

   Provides:
   - Load operations (ldx, ld)
   - Store operations (stx, st)
   - Atomic operations (atomic-add, atomic-xchg, etc.)
   - 64-bit immediate loads (lddw)"
  (:require [clj-ebpf.dsl.instructions :as insn]))

;; ============================================================================
;; Size Mapping
;; ============================================================================

(def size-map
  "Map of size keywords to BPF size constants"
  {:b  insn/BPF_B   ; 1 byte
   :h  insn/BPF_H   ; 2 bytes (half-word)
   :w  insn/BPF_W   ; 4 bytes (word)
   :dw insn/BPF_DW})  ; 8 bytes (double-word)

(defn size->bytes
  "Convert size keyword to byte count"
  [size]
  (case size
    :b 1
    :h 2
    :w 4
    :dw 8))

;; ============================================================================
;; Load Operations
;; ============================================================================

(defn ldx
  "Load from memory to register.

   dst = *(size*)(src + offset)

   Arguments:
   - size: :b (byte), :h (half-word), :w (word), :dw (double-word)
   - dst: Destination register
   - src: Source register (base address)
   - offset: Memory offset"
  [size dst src offset]
  (let [opcode (bit-or insn/BPF_LDX (get size-map size) insn/BPF_MEM)]
    (insn/make-instruction opcode dst src offset 0)))

(defn ldxb
  "Load byte from memory.

   dst = *(u8*)(src + offset)"
  [dst src offset]
  (ldx :b dst src offset))

(defn ldxh
  "Load half-word (2 bytes) from memory.

   dst = *(u16*)(src + offset)"
  [dst src offset]
  (ldx :h dst src offset))

(defn ldxw
  "Load word (4 bytes) from memory.

   dst = *(u32*)(src + offset)"
  [dst src offset]
  (ldx :w dst src offset))

(defn ldxdw
  "Load double-word (8 bytes) from memory.

   dst = *(u64*)(src + offset)"
  [dst src offset]
  (ldx :dw dst src offset))

;; ============================================================================
;; Store Operations (from register)
;; ============================================================================

(defn stx
  "Store register to memory.

   *(size*)(dst + offset) = src

   Arguments:
   - size: :b, :h, :w, :dw
   - dst: Destination register (base address)
   - offset: Memory offset
   - src: Source register"
  [size dst offset src]
  (let [opcode (bit-or insn/BPF_STX (get size-map size) insn/BPF_MEM)]
    (insn/make-instruction opcode dst src offset 0)))

(defn stxb
  "Store byte to memory from register.

   *(u8*)(dst + offset) = src"
  [dst offset src]
  (stx :b dst offset src))

(defn stxh
  "Store half-word to memory from register.

   *(u16*)(dst + offset) = src"
  [dst offset src]
  (stx :h dst offset src))

(defn stxw
  "Store word to memory from register.

   *(u32*)(dst + offset) = src"
  [dst offset src]
  (stx :w dst offset src))

(defn stxdw
  "Store double-word to memory from register.

   *(u64*)(dst + offset) = src"
  [dst offset src]
  (stx :dw dst offset src))

;; ============================================================================
;; Store Operations (from immediate)
;; ============================================================================

(defn st
  "Store immediate to memory.

   *(size*)(dst + offset) = imm

   Arguments:
   - size: :b, :h, :w, :dw
   - dst: Destination register (base address)
   - offset: Memory offset
   - imm: Immediate value"
  [size dst offset imm]
  (let [opcode (bit-or insn/BPF_ST (get size-map size) insn/BPF_MEM)]
    (insn/make-instruction opcode dst 0 offset imm)))

(defn stb
  "Store byte to memory from immediate.

   *(u8*)(dst + offset) = imm"
  [dst offset imm]
  (st :b dst offset imm))

(defn sth
  "Store half-word to memory from immediate.

   *(u16*)(dst + offset) = imm"
  [dst offset imm]
  (st :h dst offset imm))

(defn stw
  "Store word to memory from immediate.

   *(u32*)(dst + offset) = imm"
  [dst offset imm]
  (st :w dst offset imm))

(defn stdw
  "Store double-word to memory from immediate.

   *(u64*)(dst + offset) = imm"
  [dst offset imm]
  (st :dw dst offset imm))

;; ============================================================================
;; 64-bit Immediate Load
;; ============================================================================

(defn lddw
  "Load 64-bit immediate to register.

   dst = imm64

   This requires two instructions due to the 64-bit immediate.
   Returns a vector of two instructions."
  [dst imm]
  (let [lo (unchecked-int (bit-and imm 0xFFFFFFFF))
        hi (unchecked-int (bit-and (unsigned-bit-shift-right imm 32) 0xFFFFFFFF))
        opcode (bit-or insn/BPF_LD insn/BPF_DW insn/BPF_IMM)]
    [(insn/make-instruction opcode dst 0 0 lo)
     (insn/make-instruction 0 0 0 0 hi)]))

(defn ld-map-fd
  "Load map file descriptor as a pseudo 64-bit immediate.

   dst = map_fd (with BPF_PSEUDO_MAP_FD marker)

   Arguments:
   - dst: Destination register
   - map-fd: Map file descriptor"
  [dst map-fd]
  (let [opcode (bit-or insn/BPF_LD insn/BPF_DW insn/BPF_IMM)]
    ;; src=1 indicates BPF_PSEUDO_MAP_FD
    [(insn/make-instruction opcode dst 1 0 map-fd)
     (insn/make-instruction 0 0 0 0 0)]))

(defn ld-map-value
  "Load map value pointer as 64-bit immediate.

   dst = &map[0] (for direct value access)

   Arguments:
   - dst: Destination register
   - map-fd: Map file descriptor"
  [dst map-fd]
  (let [opcode (bit-or insn/BPF_LD insn/BPF_DW insn/BPF_IMM)]
    ;; src=2 indicates BPF_PSEUDO_MAP_VALUE
    [(insn/make-instruction opcode dst 2 0 map-fd)
     (insn/make-instruction 0 0 0 0 0)]))

;; ============================================================================
;; Atomic Operations
;; ============================================================================

(defn- atomic-insn
  "Create an atomic operation instruction.

   Arguments:
   - size: :w or :dw
   - dst: Destination register (memory address)
   - src: Source register
   - offset: Memory offset
   - op: Atomic operation code"
  [size dst src offset op]
  (let [opcode (bit-or insn/BPF_STX (get size-map size) insn/BPF_ATOMIC)]
    (insn/make-instruction opcode dst src offset op)))

(defn atomic-add
  "Atomic add to memory.

   *(size*)(dst + offset) += src

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Destination register (memory address)
   - src: Source register
   - offset: Memory offset"
  [size dst src offset]
  (atomic-insn size dst src offset insn/BPF_ATOMIC_ADD))

(defn atomic-or
  "Atomic OR to memory.

   *(size*)(dst + offset) |= src"
  [size dst src offset]
  (atomic-insn size dst src offset insn/BPF_ATOMIC_OR))

(defn atomic-and
  "Atomic AND to memory.

   *(size*)(dst + offset) &= src"
  [size dst src offset]
  (atomic-insn size dst src offset insn/BPF_ATOMIC_AND))

(defn atomic-xor
  "Atomic XOR to memory.

   *(size*)(dst + offset) ^= src"
  [size dst src offset]
  (atomic-insn size dst src offset insn/BPF_ATOMIC_XOR))

(defn atomic-xchg
  "Atomic exchange.

   src = xchg(*(size*)(dst + offset), src)"
  [size dst src offset]
  (atomic-insn size dst src offset insn/BPF_ATOMIC_XCHG))

(defn atomic-cmpxchg
  "Atomic compare and exchange.

   r0 = cmpxchg(*(size*)(dst + offset), r0, src)
   If *addr == r0, then *addr = src"
  [size dst src offset]
  (atomic-insn size dst src offset insn/BPF_ATOMIC_CMPXCHG))

(defn atomic-fetch-add
  "Atomic fetch and add.

   src = fetch_add(*(size*)(dst + offset), src)
   Returns old value in src."
  [size dst src offset]
  (atomic-insn size dst src offset (bit-or insn/BPF_ATOMIC_ADD insn/BPF_ATOMIC_FETCH)))

(defn atomic-fetch-or
  "Atomic fetch and OR."
  [size dst src offset]
  (atomic-insn size dst src offset (bit-or insn/BPF_ATOMIC_OR insn/BPF_ATOMIC_FETCH)))

(defn atomic-fetch-and
  "Atomic fetch and AND."
  [size dst src offset]
  (atomic-insn size dst src offset (bit-or insn/BPF_ATOMIC_AND insn/BPF_ATOMIC_FETCH)))

(defn atomic-fetch-xor
  "Atomic fetch and XOR."
  [size dst src offset]
  (atomic-insn size dst src offset (bit-or insn/BPF_ATOMIC_XOR insn/BPF_ATOMIC_FETCH)))

;; ============================================================================
;; Stack Operations
;; ============================================================================

(defn stack-alloc
  "Generate instructions to allocate space on stack.

   Arguments:
   - size: Number of bytes to allocate (should be 8-byte aligned)

   Returns mov instruction to set up stack pointer offset."
  [size]
  ;; Stack grows down from r10 (fp)
  ;; Typical usage: load address relative to fp
  nil)  ; No-op, stack is implicit via fp-relative addressing

(defn stack-load
  "Load from stack.

   dst = *(size*)(fp - offset)

   Arguments:
   - size: :b, :h, :w, :dw
   - dst: Destination register
   - offset: Positive offset from frame pointer"
  [size dst offset]
  (ldx size dst :r10 (- offset)))

(defn stack-store
  "Store to stack from register.

   *(size*)(fp - offset) = src

   Arguments:
   - size: :b, :h, :w, :dw
   - offset: Positive offset from frame pointer
   - src: Source register"
  [size offset src]
  (stx size :r10 (- offset) src))

(defn stack-store-imm
  "Store to stack from immediate.

   *(size*)(fp - offset) = imm"
  [size offset imm]
  (st size :r10 (- offset) imm))
