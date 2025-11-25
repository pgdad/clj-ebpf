# Lab 14.3: Verifier Error Analysis and Auto-Fixing

## Objective

Build a system that analyzes BPF verifier errors, explains them in plain language, and suggests or automatically applies fixes. Learn to understand and resolve all common verifier errors.

## Learning Goals

- Understand verifier error messages
- Recognize error patterns
- Apply systematic fixes
- Build automated error detection
- Create error fix suggestions
- Test fixes automatically

## Common Verifier Errors

### Error 1: Invalid Memory Access

**Verifier Message**:
```
invalid mem access 'scalar'
R1 invalid mem access 'scalar'
```

**Cause**: Accessing memory without bounds check.

**Example (Broken)**:
```clojure
(def broken-packet-parser
  {:type :xdp
   :program
   [;; Load packet pointer
    [(bpf/load-ctx :dw :r2 0)]     ; r2 = data

    ;; BROKEN: No bounds check!
    [(bpf/load-mem :w :r1 :r2 12)]  ; Read EtherType

    [(bpf/mov :r0 (bpf/xdp-action :pass))]
    [(bpf/exit)]]}))
```

**Fix**:
```clojure
(def fixed-packet-parser
  {:type :xdp
   :program
   [;; Load packet pointers
    [(bpf/load-ctx :dw :r2 0)]     ; r2 = data
    [(bpf/load-ctx :dw :r3 8)]     ; r3 = data_end

    ;; Bounds check BEFORE access
    [(bpf/mov-reg :r4 :r2)]
    [(bpf/add :r4 14)]              ; r4 = data + 14
    [(bpf/jmp-reg :jgt :r4 :r3 :drop)]  ; if (data + 14 > data_end) drop

    ;; Now safe to access
    [(bpf/load-mem :w :r1 :r2 12)]  ; Read EtherType

    [(bpf/mov :r0 (bpf/xdp-action :pass))]
    [(bpf/exit)]

    [:drop]
    [(bpf/mov :r0 (bpf/xdp-action :drop))]
    [(bpf/exit)]]}))
```

**Pattern**: Always `data + offset < data_end` before access.

### Error 2: Unbounded Loop

**Verifier Message**:
```
back-edge from insn 45 to 20
```

**Cause**: Loop without provable termination.

**Example (Broken)**:
```clojure
(def broken-array-scan
  {:type :kprobe
   :name "scan_array"
   :program
   [;; Initialize index
    [(bpf/mov :r6 0)]

    [:loop]
    ;; BROKEN: No upper bound check!
    [(bpf/jmp-imm :jeq :r6 0 :exit)]  ; Would loop forever if r6 != 0

    ;; Process element
    [(bpf/add :r6 1)]

    ;; Loop back
    [(bpf/jmp :loop)]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))
```

**Fix**:
```clojure
(def fixed-array-scan
  {:type :kprobe
   :name "scan_array"
   :program
   [;; Initialize index
    [(bpf/mov :r6 0)]

    [:loop]
    ;; Upper bound check (verifier can prove termination)
    [(bpf/jmp-imm :jge :r6 16 :exit)]  ; Max 16 iterations

    ;; Process element
    ;; ... code ...

    ;; Increment and loop
    [(bpf/add :r6 1)]
    [(bpf/jmp :loop)]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))
```

**Pattern**: Always `index >= MAX` before loop.

### Error 3: Uninitialized Register

**Verifier Message**:
```
R6 !read_ok
invalid read from stack off -8+0 size 8
```

**Cause**: Reading register before writing.

**Example (Broken)**:
```clojure
(def broken-conditional
  {:type :kprobe
   :name "conditional_logic"
   :program
   [;; Branch on r1
    [(bpf/jmp-imm :jeq :r1 0 :path-a)]

    ;; Path B: r6 initialized
    [(bpf/mov :r6 100)]
    [(bpf/jmp :merge)]

    ;; Path A: r6 NOT initialized
    [:path-a]
    ;; Missing: [(bpf/mov :r6 0)]

    [:merge]
    ;; BROKEN: r6 might be uninitialized (from path A)
    [(bpf/mov-reg :r0 :r6)]  ; Read uninitialized r6!

    [(bpf/exit)]]}))
```

**Fix**:
```clojure
(def fixed-conditional
  {:type :kprobe
   :name "conditional_logic"
   :program
   [;; Branch on r1
    [(bpf/jmp-imm :jeq :r1 0 :path-a)]

    ;; Path B: r6 initialized
    [(bpf/mov :r6 100)]
    [(bpf/jmp :merge)]

    ;; Path A: r6 initialized
    [:path-a]
    [(bpf/mov :r6 0)]  ; Initialize on this path too!

    [:merge]
    ;; Now safe: r6 initialized on all paths
    [(bpf/mov-reg :r0 :r6)]

    [(bpf/exit)]]}))
```

**Pattern**: Initialize variables on ALL paths before use.

### Error 4: Stack Out of Bounds

**Verifier Message**:
```
invalid stack off=-520 size=4
```

**Cause**: Stack access beyond 512-byte limit.

**Example (Broken)**:
```clojure
(def broken-large-buffer
  {:type :kprobe
   :name "use_large_buffer"
   :program
   [;; Allocate large buffer on stack
    ;; BROKEN: -600 exceeds -512 limit!
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :dw :r10 -600 :r1)]  ; Out of bounds!

    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))
```

**Fix (Use Map)**:
```clojure
(def temp-buffer-map
  {:type :array
   :key-type :u32
   :value-type [512 :u8]  ; Large buffer
   :max-entries 1})

(def fixed-large-buffer
  {:type :kprobe
   :name "use_large_buffer"
   :program
   [;; Use map instead of stack
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -4 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref temp-buffer-map))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    ;; Use buffer via pointer in r0
    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    ;; ... use buffer ...

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))
```

**Pattern**: Use maps for data > 512 bytes.

### Error 5: Invalid Return Value

**Verifier Message**:
```
R0 !read_ok
at program exit R0 is not a known value
```

**Cause**: Not setting return value on all paths.

**Example (Broken)**:
```clojure
(def broken-return
  {:type :xdp
   :program
   [;; Conditional logic
    [(bpf/jmp-imm :jeq :r1 0 :path-a)]

    ;; Path B: return set
    [(bpf/mov :r0 (bpf/xdp-action :pass))]
    [(bpf/exit)]

    ;; Path A: return NOT set
    [:path-a]
    ;; Missing: [(bpf/mov :r0 (bpf/xdp-action :drop))]
    [(bpf/exit)]  ; BROKEN: r0 not initialized!
    ]}))
```

**Fix**:
```clojure
(def fixed-return
  {:type :xdp
   :program
   [;; Conditional logic
    [(bpf/jmp-imm :jeq :r1 0 :path-a)]

    ;; Path B: return set
    [(bpf/mov :r0 (bpf/xdp-action :pass))]
    [(bpf/exit)]

    ;; Path A: return set
    [:path-a]
    [(bpf/mov :r0 (bpf/xdp-action :drop))]  ; Set return value!
    [(bpf/exit)]]}))
```

**Pattern**: Set r0 before every exit.

## Automated Error Analysis

```clojure
(ns testing.verifier-analyzer
  "Verifier error analysis using clj-ebpf's structured error handling"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.errors :as errors]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.dsl.core :as dsl]
            [clojure.string :as str]
            [clojure.test :refer [deftest testing is]]))

;; ============================================================================
;; Integration with clj-ebpf.errors
;; ============================================================================

;; The errors.clj module provides structured error handling for verifier errors:
;;
;; - errors/verifier-error? - Check if an exception is a verifier rejection
;; - errors/format-error    - Format error for display
;; - errors/error-summary   - One-line error summary
;; - :verifier-log in ex-data - Contains the full verifier log

(defn analyze-with-errors-module
  "Analyze a verifier error using clj-ebpf.errors"
  [e]
  (when (errors/verifier-error? e)
    (let [data (ex-data e)]
      {:error-type :verifier-error
       :message (.getMessage e)
       :verifier-log (:verifier-log data)
       :formatted (errors/format-error e)})))

;; ============================================================================
;; Error Pattern Matching
;; ============================================================================

(def error-patterns
  [{:pattern #"invalid mem access '.*'"
    :name "Invalid Memory Access"
    :explanation "You're accessing memory without bounds checking first."
    :fix-hint "Add bounds check: if (ptr + offset > end) goto error;"
    :example-fix add-bounds-check}

   {:pattern #"back-edge from insn (\d+) to (\d+)"
    :name "Unbounded Loop"
    :explanation "Loop doesn't have a provable upper bound."
    :fix-hint "Add iteration limit: if (i >= MAX_ITER) break;"
    :example-fix add-loop-bound}

   {:pattern #"R(\d+) !read_ok"
    :name "Uninitialized Register"
    :explanation "Register used before initialization on some path."
    :fix-hint "Initialize register on all code paths."
    :example-fix initialize-register}

   {:pattern #"invalid stack off=(-?\d+)"
    :name "Stack Out of Bounds"
    :explanation "Stack access exceeds 512-byte limit."
    :fix-hint "Use map instead of large stack allocation."
    :example-fix use-map-instead}

   {:pattern #"R0 !read_ok.*at program exit"
    :name "Uninitialized Return Value"
    :explanation "Return value (r0) not set on all paths."
    :fix-hint "Set r0 before every exit instruction."
    :example-fix set-return-value}])

(defn analyze-verifier-error
  "Analyze verifier error and provide explanation"
  [error-message]
  (let [matching-pattern (first
                          (filter #(re-find (:pattern %) error-message)
                                 error-patterns))]
    (if matching-pattern
      {:error-type (:name matching-pattern)
       :explanation (:explanation matching-pattern)
       :fix-hint (:fix-hint matching-pattern)
       :can-auto-fix (some? (:example-fix matching-pattern))
       :auto-fix-fn (:example-fix matching-pattern)}
      {:error-type "Unknown"
       :explanation "Unknown verifier error. Check kernel documentation."
       :fix-hint "Simplify program or check verifier log for details."
       :can-auto-fix false})))

;; ============================================================================
;; Automated Fixes
;; ============================================================================

(defn add-bounds-check
  "Automatically add bounds check before memory access"
  [program insn-idx]
  (let [insns (:program program)
        problematic-insn (nth insns insn-idx)]

    ;; Detect if this is a load from packet
    (if (and (= :load-mem (:op problematic-insn))
             (= :r2 (:src problematic-insn)))  ; r2 typically = data

      ;; Insert bounds check before this instruction
      (let [offset (:offset problematic-insn)
            check-insns [[(bpf/mov-reg :r4 :r2)]
                        [(bpf/add :r4 offset)]
                        [(bpf/load-ctx :dw :r3 8)]  ; data_end
                        [(bpf/jmp-reg :jgt :r4 :r3 :error)]]]

        (assoc program :program
               (concat (take insn-idx insns)
                      check-insns
                      (drop insn-idx insns))))

      ;; Can't auto-fix, return original
      program)))

(defn add-loop-bound
  "Add upper bound check to loop"
  [program loop-start loop-end]
  ;; Find loop counter register
  ;; Add check: if (counter >= MAX) goto exit

  ;; Simplified: assume r6 is counter
  (let [insns (:program program)
        bound-check [[(bpf/jmp-imm :jge :r6 100 :exit)]]]

    (assoc program :program
           (concat (take loop-start insns)
                  bound-check
                  (drop loop-start insns)))))

(defn initialize-register
  "Initialize register on all paths"
  [program reg-num]
  ;; Find all paths
  ;; Add initialization at merge points

  ;; Simplified: add at program start
  (let [insns (:program program)
        init-insn [[(bpf/mov (keyword (str "r" reg-num)) 0)]]]

    (assoc program :program
           (concat init-insn insns))))

(defn use-map-instead
  "Replace large stack allocation with map"
  [program]
  (println "Auto-fix: Creating map for large buffer...")

  (let [buffer-map {:type :array
                   :key-type :u32
                   :value-type [512 :u8]
                   :max-entries 1}]

    (-> program
        (assoc-in [:maps :temp-buffer] buffer-map)
        (update :program replace-stack-with-map-access))))

(defn set-return-value
  "Ensure r0 set before all exits"
  [program]
  (let [insns (:program program)]
    ;; Find all exit instructions without preceding r0 set
    ;; Add: [(bpf/mov :r0 0)] before them

    ;; Simplified implementation
    (assoc program :program
           (mapcat (fn [insn]
                    (if (= :exit (:op insn))
                      [[(bpf/mov :r0 0)] insn]
                      [insn]))
                  insns))))

;; ============================================================================
;; Error Fixer Pipeline
;; ============================================================================

(defn try-load-with-error-capture
  "Attempt to load program, capturing verifier errors.
   Uses clj-ebpf.errors for structured error information."
  [program]
  (try
    {:success true
     :program (bpf/load-program program)}
    (catch Exception e
      (let [analysis (analyze-with-errors-module e)]
        {:success false
         :error (.getMessage e)
         :verifier-log (or (:verifier-log analysis)
                          (extract-verifier-log e))
         :is-verifier-error (errors/verifier-error? e)
         :formatted-error (errors/format-error e)}))))

(defn extract-verifier-log [exception]
  "Extract verifier log from exception data"
  (or (:verifier-log (ex-data exception))
      (.getMessage exception)))

(defn fix-program-iteratively
  "Attempt to fix program by applying fixes iteratively"
  [program max-iterations]
  (println (format "Attempting to fix program (max %d iterations)..." max-iterations))

  (loop [current-prog program
         iteration 1]

    (println (format "\nIteration %d: Loading program..." iteration))

    (let [result (try-load-with-error-capture current-prog)]

      (if (:success result)
        ;; Success!
        (do
          (println "✓ Program loaded successfully after fixes!")
          {:success true
           :program (:program result)
           :iterations iteration})

        ;; Failed, try to fix
        (if (>= iteration max-iterations)
          ;; Give up
          (do
            (println "✗ Could not fix program after" iteration "iterations")
            {:success false
             :final-error (:error result)
             :iterations iteration})

          ;; Try to apply fix
          (let [analysis (analyze-verifier-error (:error result))]
            (println "  Error detected:" (:error-type analysis))
            (println "  Explanation:" (:explanation analysis))
            (println "  Hint:" (:fix-hint analysis))

            (if (:can-auto-fix analysis)
              (do
                (println "  Attempting automatic fix...")
                (let [fixed-prog ((:auto-fix-fn analysis) current-prog)]
                  (recur fixed-prog (inc iteration))))

              ;; Can't auto-fix
              (do
                (println "  Cannot auto-fix this error")
                {:success false
                 :error (:error result)
                 :analysis analysis
                 :iterations iteration}))))))))

;; ============================================================================
;; Interactive Error Explanation
;; ============================================================================

(defn explain-error-interactive
  "Explain verifier error with examples"
  [error-message]
  (let [analysis (analyze-verifier-error error-message)]

    (println "\n╔════════════════════════════════════════════╗")
    (println "║     Verifier Error Explanation           ║")
    (println "╚════════════════════════════════════════════╝\n")

    (println "Error Type:")
    (println "  " (:error-type analysis) "\n")

    (println "What This Means:")
    (println "  " (:explanation analysis) "\n")

    (println "How to Fix:")
    (println "  " (:fix-hint analysis) "\n")

    (when (:can-auto-fix analysis)
      (println "Auto-fix Available: Yes")
      (println "  Run with --auto-fix to attempt automatic correction\n"))

    analysis))

;; ============================================================================
;; Testing
;; ============================================================================

(deftest test-bounds-check-detection
  (testing "Detects missing bounds check"
    (let [result (try-load-with-error-capture broken-packet-parser)]
      (is (not (:success result)))
      (is (str/includes? (:error result) "invalid mem access")))))

(deftest test-bounds-check-fix
  (testing "Automatically adds bounds check"
    (let [fixed (add-bounds-check broken-packet-parser 3)
          result (try-load-with-error-capture fixed)]
      (is (:success result) "Fixed program should load"))))

(deftest test-loop-bound-detection
  (testing "Detects unbounded loop"
    (let [result (try-load-with-error-capture broken-array-scan)]
      (is (not (:success result)))
      (is (str/includes? (:error result) "back-edge")))))

;; ============================================================================
;; CLI Tool
;; ============================================================================

(defn -main [& args]
  (let [[command & rest-args] args]

    (case command
      "explain"
      (let [[error-file] rest-args
            error-msg (slurp error-file)]
        (explain-error-interactive error-msg))

      "fix"
      (let [[program-file] rest-args
            program (load-program-from-file program-file)]
        (fix-program-iteratively program 5))

      "test"
      (run-tests 'testing.verifier-analyzer)

      (println "Usage: verifier-analyzer <explain|fix|test> [args]"))))

;; Example usage:
;;
;; $ lein run -m testing.verifier-analyzer explain error.txt
;;
;; ╔════════════════════════════════════════════╗
;; ║     Verifier Error Explanation           ║
;; ╚════════════════════════════════════════════╝
;;
;; Error Type:
;;   Invalid Memory Access
;;
;; What This Means:
;;   You're accessing memory without bounds checking first.
;;
;; How to Fix:
;;   Add bounds check: if (ptr + offset > end) goto error;
;;
;; Auto-fix Available: Yes
;;   Run with --auto-fix to attempt automatic correction
```

## Verifier Error Cheat Sheet

| Error Message | Cause | Fix |
|---------------|-------|-----|
| `invalid mem access` | No bounds check | Add `ptr + offset < end` check |
| `back-edge from insn` | Unbounded loop | Add `i >= MAX` check |
| `R6 !read_ok` | Uninitialized register | Initialize on all paths |
| `invalid stack off` | Stack > 512 bytes | Use map instead |
| `R0 !read_ok at exit` | Return not set | Set r0 before exit |
| `path not explored` | Too complex | Simplify or add assertions |
| `unreachable insn` | Dead code | Remove unreachable code |
| `invalid arg` | Wrong helper arg type | Check helper signature |

## Using clj-ebpf.errors for Verifier Errors

The `clj-ebpf.errors` module provides first-class support for verifier errors:

```clojure
(require '[clj-ebpf.errors :as errors])

;; Load and handle verifier errors
(try
  (bpf/load-program my-program)
  (catch Exception e
    (when (errors/verifier-error? e)
      (println "Verifier rejected program:")
      (println (errors/format-error e))

      ;; Access the raw verifier log
      (when-let [log (:verifier-log (ex-data e))]
        (println "\nFull verifier log:")
        (println log)))))

;; Error classification
(errors/verifier-error? e)    ; Is this a verifier rejection?
(errors/permission-error? e)  ; Permission issue (not verifier)
(errors/resource-error? e)    ; Resource exhaustion (not verifier)

;; Formatted output
(errors/format-error e)       ; Multi-line formatted error
(errors/error-summary e)      ; One-line summary
```

## Key Takeaways

- Verifier errors are cryptic but follow patterns
- Use `clj-ebpf.errors` for structured error handling
- `errors/verifier-error?` identifies verifier rejections
- Access `:verifier-log` in ex-data for full details
- Most errors have systematic fixes
- Bounds checks are most common requirement
- Loop bounds must be provable at verification time
- All paths must initialize variables
- Stack is limited to 512 bytes
- Auto-fixing is possible for common errors
- Understanding verifier helps write better code

## clj-ebpf Modules Used

| Module | Purpose |
|--------|---------|
| `clj-ebpf.errors` | Error classification, formatting, verifier-error? predicate |
| `clj-ebpf.dsl.core` | DSL for writing BPF programs |
| `clj-ebpf.arch` | Architecture-specific constants |

## References

- [clj-ebpf.errors Documentation](../../api/errors.md)
- [BPF Verifier Documentation](https://www.kernel.org/doc/html/latest/bpf/verifier.html)
- [Verifier Error Examples](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#verifier)
- [libbpf Error Handling](https://github.com/libbpf/libbpf)
