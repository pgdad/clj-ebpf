(ns clj-ebpf.asm
  "BPF assembly utilities including label resolution.

   Provides symbolic label support for BPF programs, eliminating
   the need for manual jump offset calculations.

   Example:
     (require '[clj-ebpf.asm :as asm]
              '[clj-ebpf.dsl :as dsl])

     (asm/assemble-with-labels
       [(dsl/mov :r0 0)
        (asm/jmp-imm :jeq :r1 0 :success)
        (dsl/mov :r0 -1)
        (asm/jmp :done)
        (asm/label :success)
        (dsl/mov :r0 1)
        (asm/label :done)
        (dsl/exit-insn)])"
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Label Pseudo-Instructions
;; ============================================================================

(defn label
  "Create a label pseudo-instruction.
   Labels mark positions in the instruction stream for jump targets.
   They don't generate bytecode - they're resolved during assembly.

   Parameters:
   - name: Keyword naming the label (e.g., :loop, :error, :done)

   Example:
     (label :my-target)"
  [name]
  (when-not (keyword? name)
    (throw (ex-info "Label name must be a keyword" {:name name})))
  {:type :label :name name})

(defn label?
  "Check if instruction is a label pseudo-instruction."
  [insn]
  (and (map? insn)
       (= (:type insn) :label)))

;; ============================================================================
;; Symbolic Jump Instructions
;; ============================================================================

(defn jmp-imm
  "Conditional jump with immediate operand and symbolic target.

   Parameters:
   - op: Jump operation (:jeq, :jne, :jgt, :jge, :jlt, :jle, :jset, :jsgt, :jsge, :jslt, :jsle)
   - dst: Destination register
   - imm: Immediate value to compare
   - target: Jump target - keyword label or numeric offset

   If target is a keyword, it will be resolved during assembly.
   If target is a number, works like dsl/jmp-imm.

   Example:
     (jmp-imm :jeq :r0 0 :is-zero)   ; symbolic
     (jmp-imm :jeq :r0 0 5)          ; numeric (backwards compat)"
  [op dst imm target]
  (if (keyword? target)
    {:type :jmp-imm :op op :dst dst :imm imm :target target}
    (dsl/jmp-imm op dst imm target)))

(defn jmp-reg
  "Conditional jump with register operand and symbolic target.

   Parameters:
   - op: Jump operation
   - dst: First register to compare
   - src: Second register to compare
   - target: Jump target - keyword label or numeric offset

   Example:
     (jmp-reg :jgt :r0 :r1 :greater)  ; symbolic
     (jmp-reg :jgt :r0 :r1 3)         ; numeric"
  [op dst src target]
  (if (keyword? target)
    {:type :jmp-reg :op op :dst dst :src src :target target}
    (dsl/jmp-reg op dst src target)))

(defn jmp
  "Unconditional jump to symbolic target.

   Parameters:
   - target: Jump target - keyword label or numeric offset

   Example:
     (jmp :done)   ; symbolic
     (jmp 5)       ; numeric"
  [target]
  (if (keyword? target)
    {:type :jmp :target target}
    (dsl/jmp target)))

;; Alias for ja
(def ja jmp)

;; ============================================================================
;; Instruction Type Detection
;; ============================================================================

(defn symbolic-jump?
  "Check if instruction is a symbolic jump (with keyword target)."
  [insn]
  (and (map? insn)
       (#{:jmp-imm :jmp-reg :jmp} (:type insn))
       (keyword? (:target insn))))

(defn real-instruction?
  "Check if this counts as a real instruction (not a label).
   Used for position counting."
  [insn]
  (not (label? insn)))

(defn instruction-size
  "Return the size of an instruction in 8-byte units.
   Most instructions are 1, but lddw (64-bit immediate load) is 2."
  [insn]
  (cond
    (label? insn) 0
    (symbolic-jump? insn) 1
    ;; lddw instructions are 16 bytes (2 instructions)
    (and (bytes? insn) (= 16 (count insn))) 2
    :else 1))

;; ============================================================================
;; Label Resolution
;; ============================================================================

(defn- collect-labels
  "First pass: collect label positions.
   Returns map of label-name -> instruction-index."
  [instructions]
  (loop [insns instructions
         pos 0
         labels {}]
    (if (empty? insns)
      labels
      (let [insn (first insns)]
        (cond
          (label? insn)
          (let [name (:name insn)]
            (when (contains? labels name)
              (throw (ex-info (str "Duplicate label: " name)
                             {:label name
                              :first-position (get labels name)
                              :second-position pos})))
            (recur (rest insns) pos (assoc labels name pos)))

          :else
          (recur (rest insns) (+ pos (instruction-size insn)) labels))))))

(defn- resolve-jump
  "Resolve a symbolic jump instruction to bytecode.

   Parameters:
   - insn: Symbolic jump instruction map
   - current-pos: Position of this instruction
   - labels: Map of label-name -> position"
  [insn current-pos labels]
  (let [target-label (:target insn)
        target-pos (get labels target-label)]
    (when-not target-pos
      (throw (ex-info (str "Undefined label: " target-label)
                     {:label target-label
                      :instruction-position current-pos
                      :available-labels (keys labels)})))
    (let [offset (- target-pos current-pos 1)]
      ;; Check offset range (16-bit signed: -32768 to 32767)
      (when (or (< offset -32768) (> offset 32767))
        (throw (ex-info (str "Jump offset " offset " out of range")
                       {:label target-label
                        :offset offset
                        :from current-pos
                        :to target-pos})))
      (case (:type insn)
        :jmp-imm (dsl/jmp-imm (:op insn) (:dst insn) (:imm insn) offset)
        :jmp-reg (dsl/jmp-reg (:op insn) (:dst insn) (:src insn) offset)
        :jmp (dsl/jmp offset)))))

(defn resolve-labels
  "Resolve symbolic labels to numeric offsets.

   Two-pass algorithm:
   1. Collect all label positions
   2. Resolve jump targets and filter out labels

   Parameters:
   - instructions: Sequence of instructions (may include labels and symbolic jumps)

   Returns: Sequence of resolved instructions (byte arrays only, no labels)"
  [instructions]
  (let [;; Pass 1: Collect label positions
        labels (collect-labels instructions)

        ;; Pass 2: Resolve jumps and filter labels
        resolved
        (loop [insns instructions
               pos 0
               result []]
          (if (empty? insns)
            result
            (let [insn (first insns)]
              (cond
                ;; Skip labels
                (label? insn)
                (recur (rest insns) pos result)

                ;; Resolve symbolic jumps
                (symbolic-jump? insn)
                (let [resolved-insn (resolve-jump insn pos labels)]
                  (recur (rest insns) (inc pos) (conj result resolved-insn)))

                ;; Keep other instructions as-is
                :else
                (recur (rest insns)
                       (+ pos (instruction-size insn))
                       (conj result insn))))))]
    resolved))

;; ============================================================================
;; Assembly with Labels
;; ============================================================================

(defn assemble-with-labels
  "Assemble instructions with automatic label resolution.

   This is the main entry point for programs using symbolic labels.
   Handles mixed sequences of:
   - Label pseudo-instructions (created with `label`)
   - Symbolic jump instructions (created with `jmp-imm`, `jmp-reg`, `jmp`)
   - Regular DSL instructions (byte arrays)

   Parameters:
   - instructions: Sequence of instructions

   Returns: Assembled bytecode (byte array)

   Example:
     (assemble-with-labels
       [(dsl/mov :r0 0)
        (jmp-imm :jeq :r1 0 :success)
        (dsl/mov :r0 -1)
        (jmp :done)
        (label :success)
        (dsl/mov :r0 1)
        (label :done)
        (dsl/exit-insn)])"
  [instructions]
  (let [flattened (flatten instructions)
        resolved (resolve-labels flattened)]
    (dsl/assemble resolved)))

;; ============================================================================
;; Helper Wrappers for Common Patterns
;; ============================================================================

(defn check-bounds
  "Generate bounds check with symbolic label for failure.

   Like net/check-bounds but accepts keyword labels.

   Parameters:
   - data-reg: Register containing data pointer
   - data-end-reg: Register containing data_end pointer
   - offset: Number of bytes needed
   - fail-label: Label (keyword) or offset (number) to jump on failure
   - scratch-reg: Scratch register for calculation

   Example:
     (check-bounds :r7 :r8 14 :pass :r9)"
  [data-reg data-end-reg offset fail-label scratch-reg]
  [(dsl/mov-reg scratch-reg data-reg)
   (dsl/add scratch-reg offset)
   (jmp-reg :jgt scratch-reg data-end-reg fail-label)])

(defn check-bounds-dynamic
  "Generate bounds check with dynamic offset.

   Parameters:
   - data-reg: Register containing data pointer
   - data-end-reg: Register containing data_end pointer
   - offset-reg: Register containing offset value
   - fail-label: Label (keyword) or offset (number) to jump on failure
   - scratch-reg: Scratch register for calculation"
  [data-reg data-end-reg offset-reg fail-label scratch-reg]
  [(dsl/mov-reg scratch-reg data-reg)
   (dsl/add-reg scratch-reg offset-reg)
   (jmp-reg :jgt scratch-reg data-end-reg fail-label)])
