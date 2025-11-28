(ns lab-18-1-cpu-profiling
  "Lab 18.1: CPU Profiling and Flamegraphs

   This solution demonstrates:
   - CPU sampling at configurable frequency
   - Stack trace collection and aggregation
   - Flamegraph data generation
   - Hotspot identification

   Run with: clojure -M -m lab-18-1-cpu-profiling test"
  (:require [clojure.string :as str]))

;;; ============================================================================
;;; Part 1: Stack Trace Representation
;;; ============================================================================

(defrecord StackFrame
  [function file line])

(defrecord StackTrace
  [frames pid tid comm timestamp-ns])

(defn create-frame
  "Create a stack frame"
  [function & {:keys [file line] :or {file "" line 0}}]
  (->StackFrame function file line))

(defn create-stack-trace
  "Create a stack trace"
  [frames pid tid comm]
  (->StackTrace frames pid tid comm (System/nanoTime)))

(defn stack-key
  "Create unique key for stack trace (for aggregation)"
  [trace]
  (mapv :function (:frames trace)))

;;; ============================================================================
;;; Part 2: Sample Collection
;;; ============================================================================

(def samples
  "Collected CPU samples"
  (atom []))

(def aggregated-samples
  "Aggregated samples by stack"
  (atom {}))

(defn record-sample!
  "Record a CPU sample"
  [trace]
  (swap! samples conj trace)
  (swap! aggregated-samples update (stack-key trace) (fnil inc 0)))

(defn get-samples
  "Get all samples"
  []
  @samples)

(defn get-aggregated
  "Get aggregated sample counts"
  []
  @aggregated-samples)

(defn clear-samples!
  "Clear all samples"
  []
  (reset! samples [])
  (reset! aggregated-samples {}))

(defn sample-count
  "Get total sample count"
  []
  (count @samples))

;;; ============================================================================
;;; Part 3: Flamegraph Generation
;;; ============================================================================

(defn stack->folded
  "Convert stack to folded format: func1;func2;func3"
  [stack-frames]
  (str/join ";" (reverse (map :function stack-frames))))

(defn generate-folded-stacks
  "Generate folded stack format for flamegraph"
  []
  (for [[stack count] (get-aggregated)]
    (format "%s %d" (str/join ";" stack) count)))

(defn print-folded-stacks
  "Print folded stacks to stdout"
  []
  (doseq [line (sort (generate-folded-stacks))]
    (println line)))

(defn save-folded-stacks
  "Save folded stacks to file"
  [filename]
  (spit filename (str/join "\n" (sort (generate-folded-stacks)))))

;;; ============================================================================
;;; Part 4: Hotspot Analysis
;;; ============================================================================

(defn top-stacks
  "Get top N stacks by sample count"
  [n]
  (->> (get-aggregated)
       (sort-by second >)
       (take n)
       (map (fn [[stack count]]
              {:stack stack
               :count count
               :percentage (* 100.0 (/ count (sample-count)))}))))

(defn top-functions
  "Get top N functions by sample count"
  [n]
  (let [func-counts (atom {})]
    (doseq [[stack count] (get-aggregated)]
      (doseq [func stack]
        (swap! func-counts update func (fnil + 0) count)))
    (->> @func-counts
         (sort-by second >)
         (take n)
         (map (fn [[func count]]
                {:function func
                 :count count
                 :percentage (* 100.0 (/ count (sample-count)))})))))

(defn self-time
  "Calculate self-time for each function (time at top of stack)"
  []
  (let [self-counts (atom {})]
    (doseq [[stack count] (get-aggregated)]
      (when (seq stack)
        (swap! self-counts update (first stack) (fnil + 0) count)))
    (->> @self-counts
         (sort-by second >)
         (map (fn [[func count]]
                {:function func
                 :self-count count
                 :self-percentage (* 100.0 (/ count (sample-count)))})))))

;;; ============================================================================
;;; Part 5: Profile Statistics
;;; ============================================================================

(defn profile-summary
  "Generate profile summary"
  []
  (let [total (sample-count)
        unique-stacks (count (get-aggregated))
        by-pid (group-by #(:pid %) (get-samples))]
    {:total-samples total
     :unique-stacks unique-stacks
     :processes (count by-pid)
     :by-process (into {} (map (fn [[pid samples]]
                                 [pid {:count (count samples)
                                       :comm (:comm (first samples))}])
                               by-pid))}))

;;; ============================================================================
;;; Part 6: Simulated Sampling
;;; ============================================================================

(def sample-stacks
  "Sample stack traces for testing"
  [[{:function "main"} {:function "run_server"} {:function "handle_request"} {:function "parse_json"}]
   [{:function "main"} {:function "run_server"} {:function "handle_request"} {:function "query_db"}]
   [{:function "main"} {:function "run_server"} {:function "handle_request"} {:function "query_db"} {:function "execute_sql"}]
   [{:function "main"} {:function "run_server"} {:function "handle_request"}]
   [{:function "main"} {:function "run_server"} {:function "accept_connection"}]
   [{:function "main"} {:function "gc_collect"}]
   [{:function "main"} {:function "run_server"} {:function "handle_request"} {:function "render_template"}]])

(defn simulate-sampling
  "Simulate CPU sampling with weighted distribution"
  [n-samples & {:keys [weights]
                :or {weights [10 30 25 15 5 5 10]}}]
  (clear-samples!)
  (let [weighted-stacks (mapcat (fn [stack weight]
                                  (repeat weight stack))
                                sample-stacks weights)
        total-weight (reduce + weights)]
    (dotimes [i n-samples]
      (let [stack (nth weighted-stacks (mod i total-weight))
            frames (mapv #(create-frame (:function %)) stack)]
        (record-sample! (create-stack-trace frames 1234 1234 "server"))))))

;;; ============================================================================
;;; Part 7: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 18.1 Tests ===\n")

  ;; Test 1: Stack frame creation
  (println "Test 1: Stack Frame Creation")
  (let [frame (create-frame "my_function" :file "test.c" :line 42)]
    (assert (= "my_function" (:function frame)) "function name")
    (assert (= "test.c" (:file frame)) "file name")
    (assert (= 42 (:line frame)) "line number"))
  (println "  Stack frames created correctly")
  (println "  PASSED\n")

  ;; Test 2: Stack trace creation
  (println "Test 2: Stack Trace Creation")
  (let [frames [(create-frame "main") (create-frame "foo") (create-frame "bar")]
        trace (create-stack-trace frames 1234 5678 "test")]
    (assert (= 3 (count (:frames trace))) "frame count")
    (assert (= 1234 (:pid trace)) "pid")
    (assert (pos? (:timestamp-ns trace)) "timestamp"))
  (println "  Stack traces created correctly")
  (println "  PASSED\n")

  ;; Test 3: Sample recording
  (println "Test 3: Sample Recording")
  (clear-samples!)
  (let [trace1 (create-stack-trace [(create-frame "a") (create-frame "b")] 1 1 "t")
        trace2 (create-stack-trace [(create-frame "a") (create-frame "b")] 1 1 "t")
        trace3 (create-stack-trace [(create-frame "a") (create-frame "c")] 1 1 "t")]
    (record-sample! trace1)
    (record-sample! trace2)
    (record-sample! trace3)
    (assert (= 3 (sample-count)) "total samples")
    (assert (= 2 (get (get-aggregated) ["a" "b"])) "aggregated a->b")
    (assert (= 1 (get (get-aggregated) ["a" "c"])) "aggregated a->c"))
  (println "  Sample recording works correctly")
  (println "  PASSED\n")

  ;; Test 4: Folded stack generation
  (println "Test 4: Folded Stack Generation")
  (clear-samples!)
  (dotimes [_ 5]
    (record-sample! (create-stack-trace
                      [(create-frame "main") (create-frame "foo")] 1 1 "t")))
  (let [folded (generate-folded-stacks)]
    (assert (= 1 (count folded)) "one unique stack")
    (assert (str/includes? (first folded) "main;foo 5") "correct format"))
  (println "  Folded stack generation works correctly")
  (println "  PASSED\n")

  ;; Test 5: Top stacks
  (println "Test 5: Top Stacks Analysis")
  (simulate-sampling 100)
  (let [top (top-stacks 3)]
    (assert (= 3 (count top)) "top 3 returned")
    (assert (> (:count (first top)) (:count (second top))) "sorted desc")
    (assert (pos? (:percentage (first top))) "percentage calculated"))
  (println "  Top stacks analysis works correctly")
  (println "  PASSED\n")

  ;; Test 6: Top functions
  (println "Test 6: Top Functions Analysis")
  (let [top (top-functions 5)]
    (assert (<= (count top) 5) "at most 5 returned")
    (assert (some #(= "main" (:function %)) top) "main in top functions"))
  (println "  Top functions analysis works correctly")
  (println "  PASSED\n")

  ;; Test 7: Self time
  (println "Test 7: Self Time Calculation")
  (let [self (self-time)]
    (assert (seq self) "self time calculated")
    (assert (every? #(:self-count %) self) "counts present")
    (assert (every? #(:self-percentage %) self) "percentages present"))
  (println "  Self time calculation works correctly")
  (println "  PASSED\n")

  ;; Test 8: Profile summary
  (println "Test 8: Profile Summary")
  (let [summary (profile-summary)]
    (assert (= 100 (:total-samples summary)) "total samples")
    (assert (pos? (:unique-stacks summary)) "unique stacks counted")
    (assert (= 1 (:processes summary)) "one process"))
  (println "  Profile summary works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 8: Demo
;;; ============================================================================

(defn run-demo
  "Run demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 18.1: CPU Profiling and Flamegraphs")
  (println (str/join "" (repeat 60 "=")) "\n")

  ;; Simulate sampling
  (println "=== Simulating CPU Sampling (1000 samples @ 99Hz) ===\n")
  (simulate-sampling 1000)

  (let [summary (profile-summary)]
    (println (format "Total samples: %d" (:total-samples summary)))
    (println (format "Unique stacks: %d" (:unique-stacks summary)))
    (println (format "Processes: %d" (:processes summary)))
    (println))

  ;; Top stacks
  (println "=== Top 5 Hot Paths ===\n")
  (println (format "%-5s %-6s %s" "SAMP" "%" "STACK"))
  (println (str/join "" (repeat 60 "-")))
  (doseq [{:keys [stack count percentage]} (top-stacks 5)]
    (println (format "%-5d %5.1f%% %s"
                     count percentage
                     (str/join " -> " (reverse stack)))))
  (println)

  ;; Top functions
  (println "=== Top 5 Functions (inclusive time) ===\n")
  (println (format "%-20s %-8s %s" "FUNCTION" "SAMPLES" "%"))
  (println (str/join "" (repeat 40 "-")))
  (doseq [{:keys [function count percentage]} (top-functions 5)]
    (println (format "%-20s %-8d %5.1f%%" function count percentage)))
  (println)

  ;; Self time
  (println "=== Top 5 Functions (self time) ===\n")
  (println (format "%-20s %-8s %s" "FUNCTION" "SELF" "%"))
  (println (str/join "" (repeat 40 "-")))
  (doseq [{:keys [function self-count self-percentage]} (take 5 (self-time))]
    (println (format "%-20s %-8d %5.1f%%" function self-count self-percentage)))
  (println)

  ;; Folded stacks preview
  (println "=== Folded Stacks (for flamegraph.pl) ===\n")
  (doseq [line (take 5 (sort-by #(- (Integer/parseInt (last (str/split % #" "))))
                                 (generate-folded-stacks)))]
    (println line))
  (println "..."))

;;; ============================================================================
;;; Part 9: Main
;;; ============================================================================

(defn -main [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      (do
        (println "Usage: clojure -M -m lab-18-1-cpu-profiling <command>")
        (println "Commands:")
        (println "  test  - Run tests")
        (println "  demo  - Run demonstration")))))
