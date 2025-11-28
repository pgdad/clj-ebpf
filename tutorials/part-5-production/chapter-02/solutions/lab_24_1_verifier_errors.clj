(ns lab-24-1-verifier-errors
  "Lab 24.1: Verifier Error Handling

   Learn to diagnose and fix common BPF verifier rejections."
  (:require [clojure.string :as str]))

;;; ============================================================================
;;; Part 1: Error Categories
;;; ============================================================================

(def error-categories
  "Categories of verifier errors"
  {:loop-errors #{:unbounded-loop :back-edge :infinite-loop}
   :memory-errors #{:invalid-mem-access :out-of-bounds :null-pointer}
   :register-errors #{:uninitialized-register :type-mismatch :invalid-argument}
   :stack-errors #{:stack-overflow :stack-underflow}
   :return-errors #{:invalid-return :missing-exit}
   :helper-errors #{:unknown-helper :invalid-helper-args}})

(defn categorize-error
  "Categorize a verifier error message"
  [error-msg]
  (let [msg (str/lower-case error-msg)]
    (cond
      (or (str/includes? msg "back-edge")
          (str/includes? msg "loop"))
      :loop-error

      (or (str/includes? msg "invalid mem")
          (str/includes? msg "invalid access")
          (str/includes? msg "out of bound")
          (str/includes? msg "null"))
      :memory-error

      (or (str/includes? msg "!read_ok")
          (str/includes? msg "uninit")
          (str/includes? msg "type=inv"))
      :register-error

      (str/includes? msg "stack")
      :stack-error

      (str/includes? msg "return")
      :return-error

      (or (str/includes? msg "unknown func")
          (str/includes? msg "helper"))
      :helper-error

      :else :unknown-error)))

;;; ============================================================================
;;; Part 2: Error Patterns
;;; ============================================================================

(defrecord ErrorPattern
  [pattern
   category
   description
   fix-suggestion
   example-bad
   example-good])

(def common-error-patterns
  "Common verifier error patterns and their fixes"
  [(->ErrorPattern
    #"back-edge from insn (\d+) to (\d+)"
    :loop-error
    "Unbounded loop detected"
    "Use bounded loops with explicit iteration counts or loop unrolling"
    "(loop [] (recur)) ; Infinite loop"
    "(dotimes [i 10] ...) ; Bounded to 10 iterations")

   (->ErrorPattern
    #"R(\d+) invalid mem access 'inv'"
    :memory-error
    "Accessing memory through invalid pointer"
    "Ensure map lookups are checked for NULL before dereferencing"
    "(load-mem :dw :r0 :r1 0) ; r1 might be NULL"
    "(when-not (null? r1) (load-mem :dw :r0 :r1 0))")

   (->ErrorPattern
    #"invalid access to packet.*off=(\d+) size=(\d+)"
    :memory-error
    "Packet access without bounds check"
    "Add bounds check: if (data + offset + size > data_end) return"
    "(load-mem :w :r0 :r2 14) ; No bounds check"
    "(if (> (+ data 14) data_end) drop (load-mem :w :r0 :r2 14))")

   (->ErrorPattern
    #"tried to allocate (\d+) bytes.*max is 512"
    :stack-error
    "Stack allocation exceeds 512 byte limit"
    "Use maps for large data storage instead of stack"
    "(store-mem :dw :r10 -600 :r1) ; 600 > 512"
    "(map-update scratch-map key value) ; Use map instead")

   (->ErrorPattern
    #"R(\d+) !read_ok"
    :register-error
    "Reading from uninitialized register"
    "Initialize all registers before use"
    "(add :r1 :r2) ; r2 never initialized"
    "(mov :r2 0) (add :r1 :r2)")

   (->ErrorPattern
    #"At program exit R0 has invalid value"
    :return-error
    "Invalid return value for program type"
    "Return appropriate value (e.g., XDP_PASS, 0 for tracepoints)"
    "(mov :r1 123) (exit) ; r0 not set"
    "(mov :r0 XDP_PASS) (exit)")

   (->ErrorPattern
    #"unknown func bpf_(\w+)"
    :helper-error
    "Helper function not available"
    "Check kernel version requirements for the helper"
    "(call :ringbuf_reserve) ; Requires kernel 5.8+"
    "(call :perf_event_output) ; Available in older kernels")])

(defn match-error-pattern
  "Find matching error pattern"
  [error-msg]
  (first (filter #(re-find (:pattern %) error-msg) common-error-patterns)))

;;; ============================================================================
;;; Part 3: Error Analysis
;;; ============================================================================

(defrecord ErrorAnalysis
  [original-error
   category
   description
   suggestion
   line-number
   register
   instruction])

(defn extract-line-number
  "Extract line/instruction number from error"
  [error-msg]
  (when-let [match (re-find #"insn (\d+)" error-msg)]
    (parse-long (second match))))

(defn extract-register
  "Extract register from error"
  [error-msg]
  (when-let [match (re-find #"R(\d+)" error-msg)]
    (keyword (str "r" (second match)))))

(defn analyze-error
  "Analyze a verifier error message"
  [error-msg]
  (let [pattern (match-error-pattern error-msg)
        category (categorize-error error-msg)]
    (->ErrorAnalysis
     error-msg
     category
     (or (:description pattern) "Unknown error")
     (or (:fix-suggestion pattern) "Review the BPF verifier documentation")
     (extract-line-number error-msg)
     (extract-register error-msg)
     nil)))

;;; ============================================================================
;;; Part 4: Fix Suggestions
;;; ============================================================================

(defn suggest-fix
  "Suggest a fix for the error"
  [analysis]
  (case (:category analysis)
    :loop-error
    {:fix "Convert to bounded loop"
     :steps ["1. Identify loop location"
             "2. Add explicit iteration counter"
             "3. Use (jmp-reg :jlt counter max-iter :loop)"
             "4. Or use macro to unroll small loops"]}

    :memory-error
    {:fix "Add bounds/NULL check"
     :steps ["1. After map_lookup_elem, check if result is NULL"
             "2. For packet access, verify data + offset <= data_end"
             "3. Store result in register before dereferencing"]}

    :register-error
    {:fix "Initialize register before use"
     :steps ["1. Find all register usages"
             "2. Ensure each is set before read"
             "3. Use (mov :rN 0) to initialize"]}

    :stack-error
    {:fix "Reduce stack usage"
     :steps ["1. Use maps for large data (>512 bytes)"
             "2. Reuse stack slots"
             "3. Pass data by reference via maps"]}

    :return-error
    {:fix "Set correct return value"
     :steps ["1. XDP programs: XDP_PASS, XDP_DROP, etc."
             "2. TC programs: TC_ACT_OK, TC_ACT_SHOT, etc."
             "3. Tracepoints/kprobes: 0"
             "4. LSM: 0 (allow) or -EPERM (deny)"]}

    :helper-error
    {:fix "Use available helper"
     :steps ["1. Check kernel version"
             "2. Find alternative helper for older kernels"
             "3. Use feature detection"]}

    {:fix "Review error message"
     :steps ["1. Check BPF verifier documentation"
             "2. Enable verbose verifier output"
             "3. Simplify program to isolate issue"]}))

;;; ============================================================================
;;; Part 5: Diagnostic Tools
;;; ============================================================================

(defn generate-diagnostic-report
  "Generate diagnostic report for an error"
  [error-msg]
  (let [analysis (analyze-error error-msg)
        fix (suggest-fix analysis)]
    {:error error-msg
     :analysis {:category (name (:category analysis))
                :description (:description analysis)
                :line (or (:line-number analysis) "unknown")
                :register (or (:register analysis) "none")}
     :fix fix}))

(defn print-diagnostic-report
  "Print formatted diagnostic report"
  [report]
  (println "\n=== BPF Verifier Error Diagnostic ===\n")
  (println "Error:" (:error report))
  (println "\nAnalysis:")
  (println "  Category:" (get-in report [:analysis :category]))
  (println "  Description:" (get-in report [:analysis :description]))
  (println "  Line/Instruction:" (get-in report [:analysis :line]))
  (println "  Register:" (get-in report [:analysis :register]))
  (println "\nSuggested Fix:" (get-in report [:fix :fix]))
  (println "\nSteps:")
  (doseq [step (get-in report [:fix :steps])]
    (println "  " step)))

;;; ============================================================================
;;; Part 6: Error History
;;; ============================================================================

(def error-history
  "History of encountered errors"
  (atom []))

(defn record-error!
  "Record an error in history"
  [error-msg]
  (let [analysis (analyze-error error-msg)]
    (swap! error-history conj
           {:timestamp (System/currentTimeMillis)
            :error error-msg
            :category (:category analysis)})
    analysis))

(defn get-error-stats
  "Get statistics on encountered errors"
  []
  (let [by-category (group-by :category @error-history)]
    {:total (count @error-history)
     :by-category (into {} (map (fn [[k v]] [k (count v)]) by-category))}))

(defn clear-error-history!
  []
  (reset! error-history []))

;;; ============================================================================
;;; Part 7: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 24.1 Tests ===\n")

  ;; Test 1: Error categorization
  (println "Test 1: Error Categorization")
  (assert (= :loop-error (categorize-error "back-edge from insn 45 to 23")) "back-edge")
  (assert (= :memory-error (categorize-error "R1 invalid mem access 'inv'")) "mem access")
  (assert (= :register-error (categorize-error "R2 !read_ok")) "uninitialized")
  (assert (= :stack-error (categorize-error "tried to allocate 600 bytes from stack")) "stack")
  (println "  Error categorization works correctly")
  (println "  PASSED\n")

  ;; Test 2: Pattern matching
  (println "Test 2: Pattern Matching")
  (let [pattern (match-error-pattern "back-edge from insn 45 to 23")]
    (assert (some? pattern) "pattern found")
    (assert (= :loop-error (:category pattern)) "correct category"))
  (println "  Pattern matching works correctly")
  (println "  PASSED\n")

  ;; Test 3: Line number extraction
  (println "Test 3: Line Number Extraction")
  (assert (= 45 (extract-line-number "back-edge from insn 45 to 23")) "extracts line")
  (assert (nil? (extract-line-number "some other error")) "nil when missing")
  (println "  Line number extraction works correctly")
  (println "  PASSED\n")

  ;; Test 4: Register extraction
  (println "Test 4: Register Extraction")
  (assert (= :r1 (extract-register "R1 invalid mem access")) "extracts register")
  (assert (nil? (extract-register "some error")) "nil when missing")
  (println "  Register extraction works correctly")
  (println "  PASSED\n")

  ;; Test 5: Error analysis
  (println "Test 5: Error Analysis")
  (let [analysis (analyze-error "R2 !read_ok")]
    (assert (= :register-error (:category analysis)) "correct category")
    (assert (some? (:description analysis)) "has description")
    (assert (some? (:suggestion analysis)) "has suggestion"))
  (println "  Error analysis works correctly")
  (println "  PASSED\n")

  ;; Test 6: Fix suggestions
  (println "Test 6: Fix Suggestions")
  (let [analysis (analyze-error "back-edge from insn 45 to 23")
        fix (suggest-fix analysis)]
    (assert (some? (:fix fix)) "has fix")
    (assert (seq (:steps fix)) "has steps"))
  (println "  Fix suggestions work correctly")
  (println "  PASSED\n")

  ;; Test 7: Diagnostic report
  (println "Test 7: Diagnostic Report")
  (let [report (generate-diagnostic-report "tried to allocate 600 bytes from stack, max is 512")]
    (assert (= "stack-error" (get-in report [:analysis :category])) "correct category")
    (assert (some? (get-in report [:fix :fix])) "has fix"))
  (println "  Diagnostic report works correctly")
  (println "  PASSED\n")

  ;; Test 8: Error history
  (println "Test 8: Error History")
  (clear-error-history!)
  (record-error! "R1 invalid mem access 'inv'")
  (record-error! "R2 !read_ok")
  (record-error! "R3 invalid mem access 'inv'")
  (let [stats (get-error-stats)]
    (assert (= 3 (:total stats)) "three errors")
    (assert (= 2 (get-in stats [:by-category :memory-error])) "two memory errors"))
  (println "  Error history works correctly")
  (println "  PASSED\n")

  ;; Test 9: Memory error pattern
  (println "Test 9: Memory Error Pattern")
  (let [analysis (analyze-error "invalid access to packet, off=0 size=14, R0(id=0,off=0,r=0)")]
    (assert (= :memory-error (:category analysis)) "memory error detected"))
  (println "  Memory error pattern works correctly")
  (println "  PASSED\n")

  ;; Test 10: Helper error pattern
  (println "Test 10: Helper Error Pattern")
  (let [analysis (analyze-error "unknown func bpf_ringbuf_reserve")]
    (assert (= :helper-error (:category analysis)) "helper error detected"))
  (println "  Helper error pattern works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 8: Demo
;;; ============================================================================

(defn demo
  "Demonstrate verifier error handling"
  []
  (println "\n=== Verifier Error Handling Demo ===\n")

  (let [errors ["back-edge from insn 45 to 23"
                "R1 invalid mem access 'inv'"
                "tried to allocate 600 bytes from stack, max is 512"
                "R2 !read_ok"
                "At program exit R0 has invalid value"]]

    (doseq [error errors]
      (println (str "\n" (apply str (repeat 60 "-"))))
      (print-diagnostic-report (generate-diagnostic-report error)))))

;;; ============================================================================
;;; Part 9: Main
;;; ============================================================================

(defn -main
  [& args]
  (case (first args)
    "test" (run-tests)
    "demo" (demo)
    (do
      (println "Usage: clojure -M -m lab-24-1-verifier-errors [test|demo]")
      (System/exit 1))))
