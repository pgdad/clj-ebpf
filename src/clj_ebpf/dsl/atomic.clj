(ns clj-ebpf.dsl.atomic
  "Atomic memory operations for BPF programs.

   Provides thread-safe operations for concurrent access to shared memory,
   essential for implementing lock-free counters, statistics, and data structures.

   Available operations:
   - atomic-add    : *dst += src
   - atomic-or     : *dst |= src
   - atomic-and    : *dst &= src
   - atomic-xor    : *dst ^= src
   - atomic-xchg   : src = xchg(*dst, src)
   - atomic-cmpxchg: r0 = cmpxchg(*dst, r0, src)

   Fetch variants return the original value:
   - atomic-fetch-add, atomic-fetch-or, atomic-fetch-and, atomic-fetch-xor

   All operations support 32-bit (:w) and 64-bit (:dw) sizes.

   Example:
   ```clojure
   ;; Increment counter atomically
   (atomic-add :dw :r1 :r2 0)  ; *r1 += r2

   ;; Fetch and add (returns old value in src register)
   (atomic-fetch-add :dw :r1 :r2 0)  ; r2 = fetch_add(*r1, r2)
   ```"
  (:require [clj-ebpf.dsl.instructions :as insns]))

;; ============================================================================
;; Size Constants
;; ============================================================================

(def ^:private size->code
  "Map size keywords to BPF size codes"
  {:w  insns/BPF_W    ; 32-bit
   :dw insns/BPF_DW}) ; 64-bit

(defn- validate-size!
  "Validate that size is :w or :dw"
  [size]
  (when-not (contains? size->code size)
    (throw (ex-info "Atomic operations only support :w (32-bit) or :dw (64-bit)"
                    {:size size :valid #{:w :dw}}))))

;; ============================================================================
;; Atomic Instruction Generation
;; ============================================================================

(defn- make-atomic-insn
  "Create an atomic instruction.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Destination register (memory pointer)
   - src: Source register
   - offset: Memory offset
   - atomic-op: Atomic operation code"
  [size dst src offset atomic-op]
  (validate-size! size)
  (let [opcode (bit-or insns/BPF_STX (get size->code size) insns/BPF_ATOMIC)]
    (insns/make-instruction opcode dst src offset atomic-op)))

;; ============================================================================
;; Basic Atomic Operations
;; ============================================================================

(defn atomic-add
  "Atomic add: *dst += src

   Atomically adds src to the memory location pointed to by dst+offset.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register containing value to add
   - offset: Memory offset (default 0)

   Example:
   ```clojure
   ;; counter += 1 where counter is at address in r1
   (mov :r2 1)
   (atomic-add :dw :r1 :r2 0)
   ```"
  ([size dst src]
   (atomic-add size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset insns/BPF_ATOMIC_ADD)))

(defn atomic-or
  "Atomic OR: *dst |= src

   Atomically ORs src with the memory location pointed to by dst+offset.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register containing value to OR
   - offset: Memory offset (default 0)"
  ([size dst src]
   (atomic-or size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset insns/BPF_ATOMIC_OR)))

(defn atomic-and
  "Atomic AND: *dst &= src

   Atomically ANDs src with the memory location pointed to by dst+offset.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register containing value to AND
   - offset: Memory offset (default 0)"
  ([size dst src]
   (atomic-and size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset insns/BPF_ATOMIC_AND)))

(defn atomic-xor
  "Atomic XOR: *dst ^= src

   Atomically XORs src with the memory location pointed to by dst+offset.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register containing value to XOR
   - offset: Memory offset (default 0)"
  ([size dst src]
   (atomic-xor size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset insns/BPF_ATOMIC_XOR)))

;; ============================================================================
;; Atomic Exchange Operations
;; ============================================================================

(defn atomic-xchg
  "Atomic exchange: src = xchg(*dst, src)

   Atomically swaps the value at memory location dst+offset with src.
   The original memory value is placed in src.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register containing new value, receives old value
   - offset: Memory offset (default 0)

   Example:
   ```clojure
   ;; Swap values: r2 = *r1, *r1 = r2
   (atomic-xchg :dw :r1 :r2 0)
   ```"
  ([size dst src]
   (atomic-xchg size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset insns/BPF_ATOMIC_XCHG)))

(defn atomic-cmpxchg
  "Atomic compare and exchange: r0 = cmpxchg(*dst, r0, src)

   If *dst equals r0, atomically replace *dst with src.
   Always returns the original value of *dst in r0.

   This is the fundamental building block for lock-free algorithms.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register containing new value (if compare succeeds)
   - offset: Memory offset (default 0)

   Note: r0 contains the expected value and receives the original value.

   Example:
   ```clojure
   ;; Try to set *r1 to 1 if it's currently 0
   (mov :r0 0)           ; Expected value
   (mov :r2 1)           ; New value
   (atomic-cmpxchg :dw :r1 :r2 0)
   ;; r0 now contains original *r1, *r1 is 1 if it was 0
   ```"
  ([size dst src]
   (atomic-cmpxchg size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset insns/BPF_ATOMIC_CMPXCHG)))

;; ============================================================================
;; Fetch Variants (return original value in src)
;; ============================================================================

(defn atomic-fetch-add
  "Atomic fetch and add: src = fetch_add(*dst, src)

   Atomically adds src to *dst and returns the original value in src.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register with value to add, receives original value
   - offset: Memory offset (default 0)

   Example:
   ```clojure
   ;; Increment counter and get previous value
   (mov :r2 1)
   (atomic-fetch-add :dw :r1 :r2 0)
   ;; r2 now contains the value before increment
   ```"
  ([size dst src]
   (atomic-fetch-add size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset
                     (bit-or insns/BPF_ATOMIC_ADD insns/BPF_ATOMIC_FETCH))))

(defn atomic-fetch-or
  "Atomic fetch and OR: src = fetch_or(*dst, src)

   Atomically ORs src with *dst and returns the original value in src.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register with value to OR, receives original value
   - offset: Memory offset (default 0)"
  ([size dst src]
   (atomic-fetch-or size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset
                     (bit-or insns/BPF_ATOMIC_OR insns/BPF_ATOMIC_FETCH))))

(defn atomic-fetch-and
  "Atomic fetch and AND: src = fetch_and(*dst, src)

   Atomically ANDs src with *dst and returns the original value in src.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register with value to AND, receives original value
   - offset: Memory offset (default 0)"
  ([size dst src]
   (atomic-fetch-and size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset
                     (bit-or insns/BPF_ATOMIC_AND insns/BPF_ATOMIC_FETCH))))

(defn atomic-fetch-xor
  "Atomic fetch and XOR: src = fetch_xor(*dst, src)

   Atomically XORs src with *dst and returns the original value in src.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - dst: Register containing memory address
   - src: Register with value to XOR, receives original value
   - offset: Memory offset (default 0)"
  ([size dst src]
   (atomic-fetch-xor size dst src 0))
  ([size dst src offset]
   (make-atomic-insn size dst src offset
                     (bit-or insns/BPF_ATOMIC_XOR insns/BPF_ATOMIC_FETCH))))

;; ============================================================================
;; Higher-Level Patterns
;; ============================================================================

(defn atomic-inc
  "Generate instructions to atomically increment a counter by 1.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - ptr-reg: Register containing pointer to counter
   - tmp-reg: Temporary register (will be set to 1)
   - offset: Memory offset (default 0)

   Returns a vector of instructions."
  ([size ptr-reg tmp-reg]
   (atomic-inc size ptr-reg tmp-reg 0))
  ([size ptr-reg tmp-reg offset]
   [(insns/make-instruction
     (bit-or insns/BPF_ALU64 insns/BPF_K insns/BPF_MOV)
     tmp-reg 0 0 1)
    (atomic-add size ptr-reg tmp-reg offset)]))

(defn atomic-dec
  "Generate instructions to atomically decrement a counter by 1.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - ptr-reg: Register containing pointer to counter
   - tmp-reg: Temporary register (will be set to -1)
   - offset: Memory offset (default 0)

   Returns a vector of instructions."
  ([size ptr-reg tmp-reg]
   (atomic-dec size ptr-reg tmp-reg 0))
  ([size ptr-reg tmp-reg offset]
   [(insns/make-instruction
     (bit-or insns/BPF_ALU64 insns/BPF_K insns/BPF_MOV)
     tmp-reg 0 0 -1)
    (atomic-add size ptr-reg tmp-reg offset)]))

(defn atomic-set-bit
  "Generate instructions to atomically set a bit.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - ptr-reg: Register containing pointer to value
   - tmp-reg: Temporary register (will hold bit mask)
   - bit-num: Bit number to set (0-31 for :w, 0-63 for :dw)
   - offset: Memory offset (default 0)

   Returns a vector of instructions."
  ([size ptr-reg tmp-reg bit-num]
   (atomic-set-bit size ptr-reg tmp-reg bit-num 0))
  ([size ptr-reg tmp-reg bit-num offset]
   (let [mask (bit-shift-left 1 bit-num)]
     [(insns/make-instruction
       (bit-or insns/BPF_ALU64 insns/BPF_K insns/BPF_MOV)
       tmp-reg 0 0 (unchecked-int mask))
      (atomic-or size ptr-reg tmp-reg offset)])))

(defn atomic-clear-bit
  "Generate instructions to atomically clear a bit.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - ptr-reg: Register containing pointer to value
   - tmp-reg: Temporary register (will hold inverted bit mask)
   - bit-num: Bit number to clear (0-31 for :w, 0-63 for :dw)
   - offset: Memory offset (default 0)

   Returns a vector of instructions."
  ([size ptr-reg tmp-reg bit-num]
   (atomic-clear-bit size ptr-reg tmp-reg bit-num 0))
  ([size ptr-reg tmp-reg bit-num offset]
   (let [mask (bit-not (bit-shift-left 1 bit-num))]
     [(insns/make-instruction
       (bit-or insns/BPF_ALU64 insns/BPF_K insns/BPF_MOV)
       tmp-reg 0 0 (unchecked-int mask))
      (atomic-and size ptr-reg tmp-reg offset)])))

(defn atomic-toggle-bit
  "Generate instructions to atomically toggle a bit.

   Arguments:
   - size: :w (32-bit) or :dw (64-bit)
   - ptr-reg: Register containing pointer to value
   - tmp-reg: Temporary register (will hold bit mask)
   - bit-num: Bit number to toggle (0-31 for :w, 0-63 for :dw)
   - offset: Memory offset (default 0)

   Returns a vector of instructions."
  ([size ptr-reg tmp-reg bit-num]
   (atomic-toggle-bit size ptr-reg tmp-reg bit-num 0))
  ([size ptr-reg tmp-reg bit-num offset]
   (let [mask (bit-shift-left 1 bit-num)]
     [(insns/make-instruction
       (bit-or insns/BPF_ALU64 insns/BPF_K insns/BPF_MOV)
       tmp-reg 0 0 (unchecked-int mask))
      (atomic-xor size ptr-reg tmp-reg offset)])))

;; ============================================================================
;; Kernel Version Information
;; ============================================================================

(def atomic-support
  "Kernel version requirements for atomic operations.

   All basic atomics (add, or, and, xor) require kernel 4.20+.
   Exchange and compare-exchange require kernel 5.12+.
   Fetch variants require kernel 5.12+."
  {:atomic-add     {:min-kernel "4.20" :description "Atomic add"}
   :atomic-or      {:min-kernel "4.20" :description "Atomic OR"}
   :atomic-and     {:min-kernel "4.20" :description "Atomic AND"}
   :atomic-xor     {:min-kernel "4.20" :description "Atomic XOR"}
   :atomic-xchg    {:min-kernel "5.12" :description "Atomic exchange"}
   :atomic-cmpxchg {:min-kernel "5.12" :description "Atomic compare-exchange"}
   :atomic-fetch   {:min-kernel "5.12" :description "Fetch variants (fetch-add, etc.)"}})

(defn atomic-available?
  "Check if an atomic operation is available for a kernel version.

   Arguments:
   - op: Operation keyword (:atomic-add, :atomic-xchg, etc.)
   - kernel-version: Kernel version string (e.g. \"5.15\")

   Returns true if the operation is supported."
  [op kernel-version]
  (when-let [info (get atomic-support op)]
    (let [min-parts (mapv #(Integer/parseInt %) (clojure.string/split (:min-kernel info) #"\."))
          cur-parts (mapv #(Integer/parseInt %) (clojure.string/split kernel-version #"\."))
          compare-versions (fn [a b]
                             (let [a-major (first a)
                                   a-minor (second a)
                                   b-major (first b)
                                   b-minor (second b)]
                               (or (> b-major a-major)
                                   (and (= b-major a-major)
                                        (>= b-minor a-minor)))))]
      (compare-versions min-parts cur-parts))))
