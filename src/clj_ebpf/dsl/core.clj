(ns clj-ebpf.dsl.core
  "Core DSL module that re-exports all DSL functionality.

   This namespace provides a unified API for BPF program construction:

   ```clojure
   (require '[clj-ebpf.dsl.core :as dsl])

   ;; Build a simple XDP program that drops all packets
   (def drop-all
     (dsl/assemble
       [(dsl/mov :r0 1)    ; XDP_DROP = 1
        (dsl/exit-insn)]))
   ```

   For more focused imports, use the submodules directly:
   - clj-ebpf.dsl.instructions - Low-level instruction encoding
   - clj-ebpf.dsl.alu - Arithmetic operations
   - clj-ebpf.dsl.mem - Memory operations
   - clj-ebpf.dsl.jump - Control flow"
  (:require [clj-ebpf.dsl.instructions :as insn]
            [clj-ebpf.dsl.alu :as alu]
            [clj-ebpf.dsl.mem :as mem]
            [clj-ebpf.dsl.jump :as jmp]))

;; ============================================================================
;; Re-export Instructions
;; ============================================================================

(def registers insn/registers)
(def reg->num insn/reg->num)
(def make-instruction insn/make-instruction)
(def instruction->bytes insn/instruction->bytes)
(def instructions->bytes insn/instructions->bytes)
(def valid-instruction? insn/valid-instruction?)

;; ============================================================================
;; Re-export ALU Operations
;; ============================================================================

(def alu64-reg alu/alu64-reg)
(def alu64-imm alu/alu64-imm)
(def alu32-reg alu/alu32-reg)
(def alu32-imm alu/alu32-imm)

(def mov alu/mov)
(def mov-reg alu/mov-reg)
(def mov32 alu/mov32)
(def mov32-reg alu/mov32-reg)

(def add alu/add)
(def add-reg alu/add-reg)
(def sub alu/sub)
(def sub-reg alu/sub-reg)
(def mul alu/mul)
(def mul-reg alu/mul-reg)
(def div alu/div)
(def div-reg alu/div-reg)
(def mod-op alu/mod-op)
(def mod-reg alu/mod-reg)
(def neg-reg alu/neg-reg)

(def and-op alu/and-op)
(def and-reg alu/and-reg)
(def or-op alu/or-op)
(def or-reg alu/or-reg)
(def xor-op alu/xor-op)
(def xor-reg alu/xor-reg)
(def lsh alu/lsh)
(def lsh-reg alu/lsh-reg)
(def rsh alu/rsh)
(def rsh-reg alu/rsh-reg)
(def arsh alu/arsh)
(def arsh-reg alu/arsh-reg)

(def end-to-be alu/end-to-be)
(def end-to-le alu/end-to-le)
(def bswap16 alu/bswap16)
(def bswap32 alu/bswap32)
(def bswap64 alu/bswap64)

;; ============================================================================
;; Re-export Memory Operations
;; ============================================================================

(def ldx mem/ldx)
(def ldxb mem/ldxb)
(def ldxh mem/ldxh)
(def ldxw mem/ldxw)
(def ldxdw mem/ldxdw)

(def stx mem/stx)
(def stxb mem/stxb)
(def stxh mem/stxh)
(def stxw mem/stxw)
(def stxdw mem/stxdw)

(def st mem/st)
(def stb mem/stb)
(def sth mem/sth)
(def stw mem/stw)
(def stdw mem/stdw)

(def lddw mem/lddw)
(def ld-map-fd mem/ld-map-fd)
(def ld-map-value mem/ld-map-value)

(def atomic-add mem/atomic-add)
(def atomic-or mem/atomic-or)
(def atomic-and mem/atomic-and)
(def atomic-xor mem/atomic-xor)
(def atomic-xchg mem/atomic-xchg)
(def atomic-cmpxchg mem/atomic-cmpxchg)
(def atomic-fetch-add mem/atomic-fetch-add)
(def atomic-fetch-or mem/atomic-fetch-or)
(def atomic-fetch-and mem/atomic-fetch-and)
(def atomic-fetch-xor mem/atomic-fetch-xor)

(def stack-load mem/stack-load)
(def stack-store mem/stack-store)
(def stack-store-imm mem/stack-store-imm)

;; ============================================================================
;; Re-export Jump Operations
;; ============================================================================

(def jmp-imm jmp/jmp-imm)
(def jmp-reg jmp/jmp-reg)
(def jmp32-imm jmp/jmp32-imm)
(def jmp32-reg jmp/jmp32-reg)

(def ja jmp/ja)
(def jeq jmp/jeq)
(def jne jmp/jne)
(def jgt jmp/jgt)
(def jge jmp/jge)
(def jlt jmp/jlt)
(def jle jmp/jle)
(def jset jmp/jset)
(def jsgt jmp/jsgt)
(def jsge jmp/jsge)
(def jslt jmp/jslt)
(def jsle jmp/jsle)

(def call jmp/call)
(def tail-call jmp/tail-call)
(def exit-insn jmp/exit-insn)

(def label jmp/label)
(def label? jmp/label?)
(def label-ref jmp/label-ref)
(def label-ref? jmp/label-ref?)

;; ============================================================================
;; Assembler
;; ============================================================================

(defn resolve-labels
  "Resolve label references to actual offsets.

   Arguments:
   - insns: Sequence of instructions (may include labels and label refs)

   Returns a sequence of instructions with label references replaced
   by actual offsets."
  [insns]
  ;; First pass: find label positions
  (let [label-positions
        (loop [insns insns
               pos 0
               positions {}]
          (if (empty? insns)
            positions
            (let [insn (first insns)]
              (if (jmp/label? insn)
                (recur (rest insns) pos (assoc positions (:name insn) pos))
                (recur (rest insns) (inc pos) positions)))))]
    ;; Second pass: resolve references
    (loop [insns insns
           pos 0
           result []]
      (if (empty? insns)
        result
        (let [insn (first insns)]
          (if (jmp/label? insn)
            ;; Skip labels
            (recur (rest insns) pos result)
            ;; Resolve label references in offset
            (let [resolved
                  (if (jmp/label-ref? (:offset insn))
                    (let [target-pos (get label-positions (:name (:offset insn)))]
                      (if target-pos
                        (assoc insn :offset (- target-pos pos 1))
                        (throw (ex-info (str "Unknown label: " (:name (:offset insn)))
                                        {:label (:name (:offset insn))}))))
                    insn)]
              (recur (rest insns) (inc pos) (conj result resolved)))))))))

(defn flatten-insns
  "Flatten nested instruction sequences (e.g., from lddw).

   Handles:
   - Vectors of instructions
   - Single instructions
   - Labels"
  [insns]
  (reduce (fn [acc insn]
            (cond
              (vector? insn) (into acc (flatten-insns insn))
              (sequential? insn) (into acc (flatten-insns insn))
              :else (conj acc insn)))
          []
          insns))

(defn assemble
  "Assemble a sequence of DSL instructions into bytes.

   Arguments:
   - insns: Sequence of instruction maps (from DSL functions)

   Returns a byte array ready for BPF loading."
  [insns]
  (-> insns
      flatten-insns
      resolve-labels
      insn/instructions->bytes))

;; ============================================================================
;; Program Construction Helpers
;; ============================================================================

(defn xdp-action
  "Get XDP action constant.

   Actions:
   - :aborted (0)
   - :drop (1)
   - :pass (2)
   - :tx (3)
   - :redirect (4)"
  [action]
  (case action
    :aborted 0
    :drop 1
    :pass 2
    :tx 3
    :redirect 4
    action))

(defn tc-action
  "Get TC action constant.

   Actions:
   - :ok (0)
   - :reclassify (1)
   - :shot (2)
   - :pipe (3)
   - :stolen (4)
   - :queued (5)
   - :repeat (6)
   - :redirect (7)"
  [action]
  (case action
    :ok 0
    :reclassify 1
    :shot 2
    :pipe 3
    :stolen 4
    :queued 5
    :repeat 6
    :redirect 7
    action))

(defn sk-action
  "Get socket filter action.

   - :reject (0)
   - :accept (positive value, usually packet length)"
  [action]
  (case action
    :reject 0
    :accept 65535
    action))

(defmacro program
  "Define a BPF program.

   Example:
   ```clojure
   (program :xdp
     (mov :r0 (xdp-action :pass))
     (exit-insn))
   ```"
  [prog-type & body]
  `(assemble [~@body]))
