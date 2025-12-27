(ns clj-ebpf.memory
  "Memory operation helpers for BPF programs.

   Provides helper functions for common memory operations on the BPF stack:
   - Zeroing memory regions
   - Copying data between stack locations
   - Setting memory to specific values

   These operations require multiple BPF instructions and are error-prone
   when done manually. These helpers generate correct, efficient sequences.

   Usage:
     (require '[clj-ebpf.memory :as mem])

     ;; Zero 40 bytes at stack[-64]
     (mem/build-zero-bytes -64 40)

     ;; Copy 16 bytes from stack[-32] to stack[-64]
     (mem/build-memcpy-stack -32 -64 16)

     ;; Set 16 bytes to 0xFF
     (mem/build-memset -16 0xFF 16)"
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Memory Zeroing
;; ============================================================================

(defn build-zero-bytes
  "Generate instructions to zero a contiguous range of bytes on the stack.

   Uses 8-byte stores (stx :dw) where possible for efficiency,
   falling back to 4-byte stores for remaining bytes.

   Args:
     stack-offset: Starting stack offset (negative, e.g., -84)
     num-bytes: Number of bytes to zero (must be multiple of 4)

   Uses: :r0 as scratch

   Returns: Vector of instructions

   Example:
     (build-zero-bytes -84 12)
     ;; Zeros bytes at stack[-84] to stack[-73]
     ;; Generates:
     ;;   mov r0, 0
     ;;   stx dw [r10-84], r0   ; zero bytes 0-7
     ;;   stx w [r10-76], r0    ; zero bytes 8-11"
  [stack-offset num-bytes]
  {:pre [(neg? stack-offset)
         (pos? num-bytes)
         (zero? (mod num-bytes 4))]}
  (let [num-dwords (quot num-bytes 8)
        remaining-words (quot (mod num-bytes 8) 4)]
    (vec
      (concat
        [(dsl/mov :r0 0)]
        (for [i (range num-dwords)]
          (dsl/stx :dw :r10 :r0 (+ stack-offset (* i 8))))
        (when (pos? remaining-words)
          [(dsl/stx :w :r10 :r0 (+ stack-offset (* num-dwords 8)))])))))

(defn build-zero-struct
  "Zero a structure on the stack.

   Convenience wrapper around build-zero-bytes with automatic alignment.
   Rounds size up to multiple of 4.

   Args:
     stack-offset: Stack offset of structure start
     size: Structure size (will be rounded up to multiple of 4)

   Uses: :r0 as scratch

   Returns: Vector of instructions

   Example:
     ;; Zero a 40-byte conntrack key
     (build-zero-struct -64 40)"
  [stack-offset size]
  (let [aligned-size (* 4 (quot (+ size 3) 4))]
    (build-zero-bytes stack-offset aligned-size)))

;; ============================================================================
;; Memory Copying
;; ============================================================================

(defn build-memcpy-stack
  "Copy bytes from one stack location to another.

   Uses 4-byte load/store pairs for simplicity and reliability.

   Args:
     src-offset: Source stack offset
     dst-offset: Destination stack offset
     num-bytes: Bytes to copy (must be multiple of 4)

   Uses: :r0 as scratch

   Returns: Vector of instructions

   Example:
     ;; Copy 16 bytes from stack[-32] to stack[-64]
     (build-memcpy-stack -32 -64 16)"
  [src-offset dst-offset num-bytes]
  {:pre [(zero? (mod num-bytes 4))]}
  (let [num-words (quot num-bytes 4)]
    (vec
      (apply concat
        (for [i (range num-words)
              :let [off (* i 4)]]
          [(dsl/ldx :w :r0 :r10 (+ src-offset off))
           (dsl/stx :w :r10 :r0 (+ dst-offset off))])))))

(defn build-memcpy-stack-dw
  "Copy bytes from one stack location to another using 8-byte operations.

   More efficient than build-memcpy-stack for large aligned copies.

   Args:
     src-offset: Source stack offset
     dst-offset: Destination stack offset
     num-bytes: Bytes to copy (must be multiple of 8)

   Uses: :r0 as scratch

   Returns: Vector of instructions"
  [src-offset dst-offset num-bytes]
  {:pre [(zero? (mod num-bytes 8))]}
  (let [num-dwords (quot num-bytes 8)]
    (vec
      (apply concat
        (for [i (range num-dwords)
              :let [off (* i 8)]]
          [(dsl/ldx :dw :r0 :r10 (+ src-offset off))
           (dsl/stx :dw :r10 :r0 (+ dst-offset off))])))))

;; ============================================================================
;; Memory Setting
;; ============================================================================

(defn build-memset
  "Set memory region to a specific byte value.

   Replicates the byte value across 4 bytes and uses word stores.

   Args:
     stack-offset: Stack offset
     value: Byte value to set (0-255)
     num-bytes: Bytes to set (must be multiple of 4)

   Uses: :r0 as scratch

   Note: For zeroing, use build-zero-bytes which is more efficient.

   Returns: Vector of instructions

   Example:
     ;; Fill with 0xFF (useful for masks)
     (build-memset -16 0xFF 16)"
  [stack-offset value num-bytes]
  {:pre [(zero? (mod num-bytes 4))
         (<= 0 value 255)]}
  (let [word-value (bit-or value
                           (bit-shift-left value 8)
                           (bit-shift-left value 16)
                           (bit-shift-left value 24))
        num-words (quot num-bytes 4)]
    (vec
      (concat
        [(dsl/mov :r0 word-value)]
        (for [i (range num-words)]
          (dsl/stx :w :r10 :r0 (+ stack-offset (* i 4))))))))

(defn build-memset-dw
  "Set memory region using 8-byte values.

   More efficient for large fills.

   Args:
     stack-offset: Stack offset
     value: 64-bit value to fill with
     num-bytes: Bytes to set (must be multiple of 8)

   Uses: :r0 as scratch

   Returns: Vector of instructions"
  [stack-offset value num-bytes]
  {:pre [(zero? (mod num-bytes 8))]}
  (let [num-dwords (quot num-bytes 8)]
    (vec
      (concat
        [(dsl/mov :r0 value)]
        (for [i (range num-dwords)]
          (dsl/stx :dw :r10 :r0 (+ stack-offset (* i 8))))))))

;; ============================================================================
;; Specialized Operations
;; ============================================================================

(defn build-store-immediate-w
  "Store a 32-bit immediate value to stack.

   Args:
     stack-offset: Stack offset
     value: 32-bit value to store

   Uses: :r0 as scratch

   Returns: Vector of 2 instructions"
  [stack-offset value]
  [(dsl/mov :r0 value)
   (dsl/stx :w :r10 :r0 stack-offset)])

(defn build-store-immediate-dw
  "Store a 64-bit immediate value to stack.

   Args:
     stack-offset: Stack offset
     value: 64-bit value to store

   Uses: :r0 as scratch

   Returns: Vector of 2 instructions (mov is 16 bytes for 64-bit)"
  [stack-offset value]
  [(dsl/mov :r0 value)
   (dsl/stx :dw :r10 :r0 stack-offset)])

(defn build-init-struct
  "Initialize a structure on stack with zeros and then set specific fields.

   Args:
     stack-offset: Stack offset of structure start
     size: Total structure size (rounded up to multiple of 4)
     fields: Map of {field-offset value} pairs

   Uses: :r0 as scratch

   Returns: Vector of instructions

   Example:
     ;; Init 24-byte struct with specific fields
     (build-init-struct -64 24
       {0 0x12345678      ; u32 at offset 0
        8 0xDEADBEEF})    ; u32 at offset 8"
  [stack-offset size fields]
  (vec
    (concat
      ;; First zero the entire struct
      (build-zero-struct stack-offset size)
      ;; Then set specific fields
      (mapcat (fn [[offset value]]
                [(dsl/mov :r0 value)
                 (dsl/stx :w :r10 :r0 (+ stack-offset offset))])
              fields))))

;; ============================================================================
;; Copy Between Registers and Stack
;; ============================================================================

(defn build-load-struct-field-w
  "Load a 32-bit field from a structure pointer.

   Args:
     ptr-reg: Register containing structure pointer
     field-offset: Offset of field within structure
     dst-reg: Destination register

   Returns: Vector of 1 instruction"
  [ptr-reg field-offset dst-reg]
  [(dsl/ldx :w dst-reg ptr-reg field-offset)])

(defn build-load-struct-field-dw
  "Load a 64-bit field from a structure pointer.

   Args:
     ptr-reg: Register containing structure pointer
     field-offset: Offset of field within structure
     dst-reg: Destination register

   Returns: Vector of 1 instruction"
  [ptr-reg field-offset dst-reg]
  [(dsl/ldx :dw dst-reg ptr-reg field-offset)])

(defn build-store-struct-field-w
  "Store a 32-bit value to a structure field.

   Args:
     ptr-reg: Register containing structure pointer
     field-offset: Offset of field within structure
     src-reg: Source register containing value

   Returns: Vector of 1 instruction"
  [ptr-reg field-offset src-reg]
  [(dsl/stx :w ptr-reg src-reg field-offset)])

(defn build-store-struct-field-dw
  "Store a 64-bit value to a structure field.

   Args:
     ptr-reg: Register containing structure pointer
     field-offset: Offset of field within structure
     src-reg: Source register containing value

   Returns: Vector of 1 instruction"
  [ptr-reg field-offset src-reg]
  [(dsl/stx :dw ptr-reg src-reg field-offset)])
