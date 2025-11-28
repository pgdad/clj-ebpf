(ns lab-14-3-verifier-errors
  "Lab 14.3: Verifier Error Analysis and Auto-Fixing

   This solution demonstrates:
   - BPF verifier error pattern recognition
   - Plain-language error explanations
   - Automated fix suggestions
   - Error classification and categorization
   - Fix verification testing

   Note: Real verifier errors come from kernel BPF verifier.
   This solution simulates error analysis and fix patterns.

   Run with: clojure -M -m lab-14-3-verifier-errors test"
  (:require [clj-ebpf.core :as ebpf]
            [clojure.string :as str]
            [clojure.test :as t :refer [deftest testing is]])
  (:import [java.util.regex Pattern]))

;;; ============================================================================
;;; Part 1: Error Pattern Database
;;; ============================================================================

(def error-patterns
  "Database of verifier error patterns with explanations and fixes"
  [{:id :invalid-mem-access
    :pattern #"invalid mem access '(scalar|inv|fp)'"
    :name "Invalid Memory Access"
    :explanation "You're accessing memory without proper bounds checking. The verifier cannot prove that the memory access is safe."
    :common-causes ["Missing packet bounds check (data + offset > data_end)"
                    "Accessing map value without null check"
                    "Reading from unverified pointer"]
    :fix-hint "Add bounds check: if (ptr + offset > end) goto error;"
    :severity :high
    :example-bad "(bpf/load-mem :w :r1 :r2 12)  ; No bounds check!"
    :example-good "[(bpf/jmp-reg :jgt :r4 :r3 :drop)]  ; bounds check first
(bpf/load-mem :w :r1 :r2 12)  ; Now safe"}

   {:id :unbounded-loop
    :pattern #"back-edge from insn (\d+) to (\d+)"
    :name "Unbounded Loop"
    :explanation "The verifier detected a loop but cannot prove it will terminate. All loops must have a provable upper bound."
    :common-causes ["Loop counter not checked against maximum"
                    "Complex loop condition verifier can't analyze"
                    "Missing iteration limit"]
    :fix-hint "Add iteration limit: if (i >= MAX_ITER) break;"
    :severity :high
    :example-bad "[:loop]
  ;; No upper bound check
  [(bpf/add :r6 1)]
  [(bpf/jmp :loop)]"
    :example-good "[:loop]
  [(bpf/jmp-imm :jge :r6 16 :exit)]  ; Max 16 iterations
  ;; ... loop body ...
  [(bpf/add :r6 1)]
  [(bpf/jmp :loop)]"}

   {:id :uninitialized-register
    :pattern #"R(\d+) !read_ok"
    :name "Uninitialized Register"
    :explanation "A register is being read before it was written to. All registers must be initialized on all code paths before use."
    :common-causes ["Register not initialized on one branch path"
                    "Conditional initialization without coverage"
                    "Typo in register name"]
    :fix-hint "Initialize register on ALL code paths before use."
    :severity :high
    :example-bad "[(bpf/jmp-imm :jeq :r1 0 :path-a)]
  [(bpf/mov :r6 100)]
  [(bpf/jmp :merge)]
[:path-a]
  ;; r6 NOT initialized here!
[:merge]
  [(bpf/mov-reg :r0 :r6)]  ; Error!"
    :example-good "[(bpf/jmp-imm :jeq :r1 0 :path-a)]
  [(bpf/mov :r6 100)]
  [(bpf/jmp :merge)]
[:path-a]
  [(bpf/mov :r6 0)]  ; Initialize here too!
[:merge]
  [(bpf/mov-reg :r0 :r6)]  ; Now safe"}

   {:id :stack-out-of-bounds
    :pattern #"invalid stack off=(-?\d+)"
    :name "Stack Out of Bounds"
    :explanation "Stack access exceeds the 512-byte limit. BPF programs have a maximum stack size of 512 bytes."
    :common-causes ["Large local buffer allocation"
                    "Deep function call nesting"
                    "Incorrect stack offset calculation"]
    :fix-hint "Use a BPF map instead of large stack allocations."
    :severity :high
    :example-bad "[(bpf/store-mem :dw :r10 -600 :r1)]  ; -600 exceeds -512 limit!"
    :example-good ";; Use map for large buffers
(def buffer-map {:type :array :max-entries 1})
;; Then access via map_lookup_elem"}

   {:id :invalid-return
    :pattern #"R0 !read_ok.*at program exit|at program exit R0 is not a known value"
    :name "Uninitialized Return Value"
    :explanation "The program exits without setting r0 (return value) on all paths. Every exit must have r0 set."
    :common-causes ["Missing return value on error path"
                    "Early exit without setting r0"
                    "Conditional return without full coverage"]
    :fix-hint "Set r0 before every exit instruction."
    :severity :medium
    :example-bad "[(bpf/jmp-imm :jeq :r1 0 :exit)]
  [(bpf/mov :r0 1)]
  [(bpf/exit)]
[:exit]
  [(bpf/exit)]  ; r0 not set!"
    :example-good "[(bpf/jmp-imm :jeq :r1 0 :exit)]
  [(bpf/mov :r0 1)]
  [(bpf/exit)]
[:exit]
  [(bpf/mov :r0 0)]  ; Set return value!
  [(bpf/exit)]"}

   {:id :unreachable-insn
    :pattern #"unreachable insn (\d+)"
    :name "Unreachable Instruction"
    :explanation "Code exists that can never be executed. This often indicates a logic error."
    :common-causes ["Dead code after unconditional jump"
                    "Code after exit instruction"
                    "Logic error in control flow"]
    :fix-hint "Remove unreachable code or fix control flow logic."
    :severity :low
    :example-bad "[(bpf/exit)]
  [(bpf/mov :r0 42)]  ; Never reached!"
    :example-good "[(bpf/mov :r0 42)]
  [(bpf/exit)]  ; Correct order"}

   {:id :invalid-helper-arg
    :pattern #"invalid (arg|type) (.*) for helper"
    :name "Invalid Helper Argument"
    :explanation "A BPF helper function was called with wrong argument type or value."
    :common-causes ["Wrong register for argument"
                    "Incorrect argument order"
                    "Type mismatch (e.g., passing scalar instead of pointer)"]
    :fix-hint "Check helper function signature and ensure correct argument types."
    :severity :high}

   {:id :path-limit
    :pattern #"(path|complexity) limit|BPF_COMPLEXITY_LIMIT"
    :name "Program Too Complex"
    :explanation "The verifier hit its complexity limit while analyzing your program. The program has too many paths or instructions."
    :common-causes ["Too many conditional branches"
                    "Large unrolled loops"
                    "Excessive nesting"]
    :fix-hint "Simplify program logic, reduce branches, or split into multiple programs."
    :severity :medium}

   {:id :map-value-null
    :pattern #"map_value_or_null|invalid mem access 'map_value_or_null'"
    :name "Unchecked Map Lookup"
    :explanation "Map lookup result used without null check. map_lookup_elem can return NULL if key doesn't exist."
    :common-causes ["Missing null check after map_lookup_elem"
                    "Dereferencing map value directly"]
    :fix-hint "Always check map lookup result: if (!value) return 0;"
    :severity :high
    :example-bad "[(bpf/call :map_lookup_elem)]
  [(bpf/load-mem :dw :r1 :r0 0)]  ; r0 might be NULL!"
    :example-good "[(bpf/call :map_lookup_elem)]
  [(bpf/jmp-imm :jeq :r0 0 :not-found)]  ; Check for NULL
  [(bpf/load-mem :dw :r1 :r0 0)]  ; Now safe"}])

;;; ============================================================================
;;; Part 2: Error Analysis Functions
;;; ============================================================================

(defn match-error-pattern
  "Match error message against known patterns"
  [error-msg]
  (first (filter #(re-find (:pattern %) error-msg) error-patterns)))

(defn analyze-verifier-error
  "Analyze a verifier error message and provide explanation"
  [error-msg]
  (if-let [pattern (match-error-pattern error-msg)]
    (let [matches (re-find (:pattern pattern) error-msg)]
      {:matched true
       :error-id (:id pattern)
       :error-type (:name pattern)
       :explanation (:explanation pattern)
       :common-causes (:common-causes pattern)
       :fix-hint (:fix-hint pattern)
       :severity (:severity pattern)
       :example-bad (:example-bad pattern)
       :example-good (:example-good pattern)
       :raw-matches (if (vector? matches) (rest matches) nil)})
    {:matched false
     :error-type "Unknown Verifier Error"
     :explanation "This error is not in our pattern database. Check kernel documentation."
     :fix-hint "Review the full verifier log for more context."
     :severity :unknown}))

(defn extract-error-location
  "Extract instruction number and context from error"
  [error-msg]
  (cond
    ;; "from insn X to Y" pattern (check before single "insn X")
    (re-find #"from insn (\d+) to (\d+)" error-msg)
    (let [[_ from to] (re-find #"from insn (\d+) to (\d+)" error-msg)]
      {:from (Integer/parseInt from)
       :to (Integer/parseInt to)
       :context :loop})

    ;; "insn X" pattern
    (re-find #"insn (\d+)" error-msg)
    (let [[_ insn] (re-find #"insn (\d+)" error-msg)]
      {:instruction (Integer/parseInt insn)
       :context :instruction})

    ;; "R[0-9]" register pattern
    (re-find #"R(\d+)" error-msg)
    (let [[_ reg] (re-find #"R(\d+)" error-msg)]
      {:register (Integer/parseInt reg)
       :context :register})

    :else nil))

;;; ============================================================================
;;; Part 3: Error Display Functions
;;; ============================================================================

(defn severity-symbol
  "Get symbol for severity level"
  [severity]
  (case severity
    :high "🔴"
    :medium "🟡"
    :low "🟢"
    "⚪"))

(defn explain-error-interactive
  "Display interactive error explanation"
  [error-msg]
  (let [analysis (analyze-verifier-error error-msg)
        location (extract-error-location error-msg)]

    (println)
    (println "╔════════════════════════════════════════════════════════════════╗")
    (println "║              BPF Verifier Error Analysis                       ║")
    (println "╚════════════════════════════════════════════════════════════════╝")
    (println)

    (println (format "Error Type: %s %s"
                     (severity-symbol (:severity analysis))
                     (:error-type analysis)))
    (println)

    (println "What This Means:")
    (println (str "  " (:explanation analysis)))
    (println)

    (when (:common-causes analysis)
      (println "Common Causes:")
      (doseq [cause (:common-causes analysis)]
        (println (str "  • " cause)))
      (println))

    (when location
      (println "Error Location:")
      (case (:context location)
        :instruction (println (format "  Instruction #%d" (:instruction location)))
        :loop (println (format "  Loop from instruction %d to %d" (:from location) (:to location)))
        :register (println (format "  Register R%d" (:register location)))
        nil)
      (println))

    (println "How to Fix:")
    (println (str "  " (:fix-hint analysis)))
    (println)

    (when (:example-bad analysis)
      (println "❌ Broken Code:")
      (doseq [line (str/split-lines (:example-bad analysis))]
        (println (str "    " line)))
      (println))

    (when (:example-good analysis)
      (println "✅ Fixed Code:")
      (doseq [line (str/split-lines (:example-good analysis))]
        (println (str "    " line)))
      (println))

    analysis))

(defn format-error-summary
  "Format one-line error summary"
  [error-msg]
  (let [analysis (analyze-verifier-error error-msg)]
    (format "[%s] %s: %s"
            (name (:severity analysis :unknown))
            (:error-type analysis)
            (:fix-hint analysis))))

;;; ============================================================================
;;; Part 4: Auto-Fix Suggestions
;;; ============================================================================

(defn suggest-bounds-check-fix
  "Suggest fix for missing bounds check"
  [context]
  {:fix-type :bounds-check
   :description "Add packet/memory bounds check"
   :code-before (str ";; Calculate required offset\n"
                     "[(bpf/mov-reg :r4 :r2)]           ; r4 = data\n"
                     "[(bpf/add :r4 " (or (:offset context) 14) ")]      ; r4 = data + offset\n"
                     ";; Check bounds\n"
                     "[(bpf/jmp-reg :jgt :r4 :r3 :drop)] ; if (data + offset > data_end) drop")})

(defn suggest-loop-bound-fix
  "Suggest fix for unbounded loop"
  [context]
  {:fix-type :loop-bound
   :description "Add loop iteration limit"
   :code-before (str ";; Add at start of loop:\n"
                     "[(bpf/jmp-imm :jge :r6 " (or (:max-iter context) 16) " :exit)] ; Max iterations")})

(defn suggest-register-init-fix
  "Suggest fix for uninitialized register"
  [context]
  (let [reg (or (:register context) 6)]
    {:fix-type :register-init
     :description (format "Initialize R%d on all paths" reg)
     :code-before (format ";; Add at the start or on missing path:\n[(bpf/mov :r%d 0)]" reg)}))

(defn suggest-null-check-fix
  "Suggest fix for unchecked map lookup"
  [context]
  {:fix-type :null-check
   :description "Add null check after map lookup"
   :code-before (str ";; After map_lookup_elem call:\n"
                     "[(bpf/jmp-imm :jeq :r0 0 :not-found)] ; Check for NULL\n"
                     ";; ... use :r0 safely ...\n"
                     "[:not-found]\n"
                     "[(bpf/mov :r0 0)]\n"
                     "[(bpf/exit)]")})

(defn suggest-return-fix
  "Suggest fix for missing return value"
  [context]
  {:fix-type :return-value
   :description "Set r0 before exit"
   :code-before ";; Add before every exit:\n[(bpf/mov :r0 0)]  ; or appropriate value\n[(bpf/exit)]"})

(defn get-fix-suggestion
  "Get appropriate fix suggestion for error"
  [error-msg]
  (let [analysis (analyze-verifier-error error-msg)
        location (extract-error-location error-msg)]
    (case (:error-id analysis)
      :invalid-mem-access (suggest-bounds-check-fix location)
      :unbounded-loop (suggest-loop-bound-fix location)
      :uninitialized-register (suggest-register-init-fix location)
      :map-value-null (suggest-null-check-fix location)
      :invalid-return (suggest-return-fix location)
      {:fix-type :manual
       :description "Manual fix required"
       :hint (:fix-hint analysis)})))

;;; ============================================================================
;;; Part 5: Error Cheat Sheet
;;; ============================================================================

(defn print-cheat-sheet
  "Print verifier error cheat sheet"
  []
  (println)
  (println "╔════════════════════════════════════════════════════════════════════════════╗")
  (println "║                    BPF Verifier Error Cheat Sheet                           ║")
  (println "╚════════════════════════════════════════════════════════════════════════════╝")
  (println)
  (println "ERROR MESSAGE                  │ CAUSE                    │ FIX")
  (println "───────────────────────────────┼──────────────────────────┼─────────────────────────")
  (println "invalid mem access             │ No bounds check          │ Add ptr + offset < end")
  (println "back-edge from insn            │ Unbounded loop           │ Add i >= MAX check")
  (println "R6 !read_ok                    │ Uninitialized register   │ Init on all paths")
  (println "invalid stack off              │ Stack > 512 bytes        │ Use map instead")
  (println "R0 !read_ok at exit            │ Return not set           │ Set r0 before exit")
  (println "map_value_or_null              │ Unchecked map lookup     │ Add NULL check")
  (println "unreachable insn               │ Dead code                │ Remove or fix flow")
  (println "path/complexity limit          │ Program too complex      │ Simplify logic")
  (println "invalid arg for helper         │ Wrong helper argument    │ Check helper signature")
  (println))

;;; ============================================================================
;;; Part 6: Simulated Error Examples
;;; ============================================================================

(def example-errors
  "Example verifier error messages for testing"
  ["invalid mem access 'scalar'"
   "R1 invalid mem access 'scalar'"
   "back-edge from insn 45 to 20"
   "R6 !read_ok"
   "invalid stack off=-520 size=4"
   "R0 !read_ok at program exit"
   "map_value_or_null access in R0"
   "unreachable insn 42"
   "BPF_COMPLEXITY_LIMIT exceeded"
   "invalid arg type PTR for helper bpf_probe_read"])

(defn analyze-all-examples
  "Analyze all example errors"
  []
  (println "\n=== Analyzing Example Verifier Errors ===\n")
  (doseq [error example-errors]
    (println (format "Error: \"%s\"" error))
    (println (format "  → %s" (format-error-summary error)))
    (println)))

;;; ============================================================================
;;; Part 7: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 14.3 Tests ===\n")

  ;; Test 1: Pattern matching
  (println "Test 1: Error Pattern Matching")
  (let [result (match-error-pattern "invalid mem access 'scalar'")]
    (assert result "Should match invalid mem access pattern")
    (assert (= :invalid-mem-access (:id result)) "Should identify correct error type")
    (println "  Matched: invalid-mem-access")
    (println "  PASSED"))

  ;; Test 2: Loop error detection
  (println "\nTest 2: Loop Error Detection")
  (let [result (analyze-verifier-error "back-edge from insn 45 to 20")]
    (assert (:matched result) "Should match")
    (assert (= :unbounded-loop (:error-id result)) "Should identify unbounded loop")
    (assert (= :high (:severity result)) "Should be high severity")
    (println "  Identified unbounded loop error")
    (println "  PASSED"))

  ;; Test 3: Register error detection
  (println "\nTest 3: Register Error Detection")
  (let [result (analyze-verifier-error "R6 !read_ok")
        location (extract-error-location "R6 !read_ok")]
    (assert (:matched result) "Should match")
    (assert (= :uninitialized-register (:error-id result)) "Should identify register error")
    (assert (= 6 (:register location)) "Should extract register number")
    (println "  Identified R6 initialization error")
    (println "  PASSED"))

  ;; Test 4: Stack error detection
  (println "\nTest 4: Stack Error Detection")
  (let [result (analyze-verifier-error "invalid stack off=-520 size=4")]
    (assert (:matched result) "Should match")
    (assert (= :stack-out-of-bounds (:error-id result)) "Should identify stack error")
    (println "  Identified stack out of bounds error")
    (println "  PASSED"))

  ;; Test 5: Fix suggestions
  (println "\nTest 5: Fix Suggestions")
  (let [fix (get-fix-suggestion "invalid mem access 'scalar'")]
    (assert (= :bounds-check (:fix-type fix)) "Should suggest bounds check")
    (assert (:code-before fix) "Should have code suggestion")
    (println "  Suggested fix: bounds-check")
    (println "  PASSED"))

  ;; Test 6: Unknown error handling
  (println "\nTest 6: Unknown Error Handling")
  (let [result (analyze-verifier-error "some completely unknown error xyz123")]
    (assert (not (:matched result)) "Should not match")
    (assert (= "Unknown Verifier Error" (:error-type result)) "Should report unknown")
    (println "  Handled unknown error gracefully")
    (println "  PASSED"))

  ;; Test 7: Error location extraction
  (println "\nTest 7: Error Location Extraction")
  (let [loc1 (extract-error-location "unreachable insn 42")
        loc2 (extract-error-location "back-edge from insn 45 to 20")
        loc3 (extract-error-location "R3 !read_ok")]
    (assert (= 42 (:instruction loc1)) "Should extract instruction number")
    (assert (= 45 (:from loc2)) "Should extract loop start")
    (assert (= 20 (:to loc2)) "Should extract loop end")
    (assert (= 3 (:register loc3)) "Should extract register number")
    (println "  Extracted instruction: 42")
    (println "  Extracted loop: 45 -> 20")
    (println "  Extracted register: R3")
    (println "  PASSED"))

  ;; Test 8: All patterns have required fields
  (println "\nTest 8: Pattern Database Completeness")
  (doseq [pattern error-patterns]
    (assert (:id pattern) "Pattern must have :id")
    (assert (:pattern pattern) "Pattern must have :pattern")
    (assert (:name pattern) "Pattern must have :name")
    (assert (:explanation pattern) "Pattern must have :explanation")
    (assert (:fix-hint pattern) "Pattern must have :fix-hint"))
  (println (format "  All %d patterns have required fields" (count error-patterns)))
  (println "  PASSED")

  (println "\n=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 8: Demo
;;; ============================================================================

(defn run-demo
  "Run interactive demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 14.3: Verifier Error Analysis")
  (println (str/join "" (repeat 60 "=")) "\n")

  ;; Print cheat sheet
  (print-cheat-sheet)

  ;; Analyze all example errors
  (analyze-all-examples)

  ;; Interactive analysis of one error
  (println "\n=== Detailed Analysis Example ===")
  (explain-error-interactive "invalid mem access 'scalar'")

  ;; Show fix suggestion
  (println "\n=== Fix Suggestion ===")
  (let [fix (get-fix-suggestion "invalid mem access 'scalar'")]
    (println (format "Fix Type: %s" (name (:fix-type fix))))
    (println (format "Description: %s" (:description fix)))
    (println "Suggested Code:")
    (doseq [line (str/split-lines (:code-before fix))]
      (println (str "  " line)))))

;;; ============================================================================
;;; Part 9: Main
;;; ============================================================================

(defn -main
  "Main entry point"
  [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      "cheat" (print-cheat-sheet)
      "analyze" (if (second args)
                  (explain-error-interactive (str/join " " (rest args)))
                  (println "Usage: analyze <error-message>"))
      "examples" (analyze-all-examples)
      ;; Default: run demo
      (run-demo))))
