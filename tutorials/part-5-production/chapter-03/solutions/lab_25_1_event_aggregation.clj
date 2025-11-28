(ns lab-25-1-event-aggregation
  "Lab 25.1: Event Aggregation Pattern

   Implements efficient event aggregation in the kernel."
  (:require [clojure.string :as str]))

;;; ============================================================================
;;; Part 1: Aggregation Key
;;; ============================================================================

(defrecord AggregationKey
  [category     ; Event category (e.g., syscall name, IP address)
   subcategory  ; Optional subcategory
   bucket])     ; Time bucket for time-windowed aggregation

(defn create-agg-key
  "Create an aggregation key"
  [category & {:keys [subcategory bucket]
               :or {subcategory nil bucket 0}}]
  (->AggregationKey category subcategory bucket))

(defn key-hash
  "Generate hash for aggregation key"
  [agg-key]
  (hash [(:category agg-key) (:subcategory agg-key) (:bucket agg-key)]))

;;; ============================================================================
;;; Part 2: Aggregation Value
;;; ============================================================================

(defrecord AggregationValue
  [count
   sum
   min-val
   max-val
   last-seen])

(defn create-agg-value
  "Create initial aggregation value"
  [initial-value]
  (->AggregationValue
   1
   initial-value
   initial-value
   initial-value
   (System/currentTimeMillis)))

(defn update-agg-value
  "Update aggregation value with new data point"
  [agg-val new-value]
  (->AggregationValue
   (inc (:count agg-val))
   (+ (:sum agg-val) new-value)
   (min (:min-val agg-val) new-value)
   (max (:max-val agg-val) new-value)
   (System/currentTimeMillis)))

(defn agg-average
  "Calculate average from aggregation"
  [agg-val]
  (when (pos? (:count agg-val))
    (/ (:sum agg-val) (:count agg-val))))

;;; ============================================================================
;;; Part 3: Per-CPU Aggregation Map (Simulated)
;;; ============================================================================

(def num-cpus
  "Number of CPUs (simulated)"
  4)

(def per-cpu-maps
  "Per-CPU aggregation maps"
  (atom (vec (repeat num-cpus {}))))

(defn get-cpu-map
  "Get map for specific CPU"
  [cpu-id]
  (nth @per-cpu-maps cpu-id))

(defn update-cpu-map!
  "Update aggregation on specific CPU"
  [cpu-id agg-key value]
  (swap! per-cpu-maps
         update cpu-id
         (fn [cpu-map]
           (if-let [existing (get cpu-map agg-key)]
             (assoc cpu-map agg-key (update-agg-value existing value))
             (assoc cpu-map agg-key (create-agg-value value))))))

(defn aggregate-event!
  "Aggregate an event (simulates per-CPU update)"
  [agg-key value]
  (let [cpu-id (rand-int num-cpus)]
    (update-cpu-map! cpu-id agg-key value)))

(defn clear-cpu-maps!
  "Clear all per-CPU maps"
  []
  (reset! per-cpu-maps (vec (repeat num-cpus {}))))

;;; ============================================================================
;;; Part 4: Cross-CPU Aggregation
;;; ============================================================================

(defn merge-agg-values
  "Merge aggregation values from multiple CPUs"
  [values]
  (when (seq values)
    (->AggregationValue
     (reduce + (map :count values))
     (reduce + (map :sum values))
     (apply min (map :min-val values))
     (apply max (map :max-val values))
     (apply max (map :last-seen values)))))

(defn collect-all-aggregations
  "Collect and merge aggregations from all CPUs"
  []
  (let [all-keys (distinct (mapcat keys @per-cpu-maps))]
    (into {}
          (for [k all-keys
                :let [values (keep #(get % k) @per-cpu-maps)]
                :when (seq values)]
            [k (merge-agg-values values)]))))

(defn get-aggregation
  "Get aggregation for a specific key"
  [agg-key]
  (let [values (keep #(get % agg-key) @per-cpu-maps)]
    (when (seq values)
      (merge-agg-values values))))

;;; ============================================================================
;;; Part 5: Time-Windowed Aggregation
;;; ============================================================================

(def window-size-ms
  "Size of aggregation window in milliseconds"
  (atom 10000))

(defn current-bucket
  "Get current time bucket"
  []
  (quot (System/currentTimeMillis) @window-size-ms))

(defn create-windowed-key
  "Create key with current time bucket"
  [category subcategory]
  (create-agg-key category :subcategory subcategory :bucket (current-bucket)))

(def window-history
  "History of window aggregations"
  (atom []))

(defn flush-window!
  "Flush current window aggregations to history"
  []
  (let [aggregations (collect-all-aggregations)
        bucket (current-bucket)]
    (when (seq aggregations)
      (swap! window-history conj {:bucket bucket
                                  :timestamp (System/currentTimeMillis)
                                  :aggregations aggregations}))
    (clear-cpu-maps!)
    aggregations))

(defn get-window-history
  "Get aggregation history"
  [num-windows]
  (take-last num-windows @window-history))

(defn clear-window-history!
  []
  (reset! window-history []))

;;; ============================================================================
;;; Part 6: Aggregation Statistics
;;; ============================================================================

(defn aggregation-stats
  "Calculate statistics across all aggregations"
  []
  (let [aggs (collect-all-aggregations)]
    {:num-keys (count aggs)
     :total-events (reduce + (map #(:count (val %)) aggs))
     :keys-per-cpu (mapv count @per-cpu-maps)}))

(defn top-aggregations
  "Get top N aggregations by count"
  [n]
  (->> (collect-all-aggregations)
       (sort-by #(:count (val %)) >)
       (take n)))

(defn aggregation-distribution
  "Get distribution of event counts across keys"
  []
  (let [counts (map #(:count (val %)) (collect-all-aggregations))]
    (when (seq counts)
      {:min (apply min counts)
       :max (apply max counts)
       :avg (/ (reduce + counts) (count counts))
       :total-keys (count counts)})))

;;; ============================================================================
;;; Part 7: Flush Controller
;;; ============================================================================

(def flush-interval-ms
  "Interval between flushes"
  (atom 10000))

(def flush-running
  "Flag to control flush loop"
  (atom false))

(defn start-flush-controller!
  "Start background flush controller"
  [callback]
  (reset! flush-running true)
  (future
    (while @flush-running
      (Thread/sleep @flush-interval-ms)
      (let [aggregations (flush-window!)]
        (when (seq aggregations)
          (callback aggregations))))))

(defn stop-flush-controller!
  "Stop flush controller"
  []
  (reset! flush-running false))

;;; ============================================================================
;;; Part 8: Event Reduction
;;; ============================================================================

(defn calculate-reduction
  "Calculate event reduction factor"
  [raw-event-count aggregated-key-count]
  (if (pos? aggregated-key-count)
    (/ raw-event-count aggregated-key-count)
    0))

(def event-counters
  "Track raw vs aggregated events"
  (atom {:raw 0 :aggregated 0}))

(defn record-raw-event!
  "Record a raw event for statistics"
  []
  (swap! event-counters update :raw inc))

(defn record-aggregated-output!
  "Record aggregated output for statistics"
  [num-keys]
  (swap! event-counters update :aggregated + num-keys))

(defn get-reduction-stats
  "Get event reduction statistics"
  []
  (let [{:keys [raw aggregated]} @event-counters]
    {:raw-events raw
     :aggregated-keys aggregated
     :reduction-factor (if (pos? aggregated) (/ raw aggregated) 0)}))

(defn reset-counters!
  []
  (reset! event-counters {:raw 0 :aggregated 0}))

;;; ============================================================================
;;; Part 9: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 25.1 Tests ===\n")

  ;; Test 1: Aggregation key creation
  (println "Test 1: Aggregation Key Creation")
  (let [k1 (create-agg-key "syscall" :subcategory "open")
        k2 (create-agg-key "syscall" :subcategory "read")]
    (assert (= "syscall" (:category k1)) "category set")
    (assert (= "open" (:subcategory k1)) "subcategory set")
    (assert (not= (key-hash k1) (key-hash k2)) "different hashes"))
  (println "  Aggregation key creation works correctly")
  (println "  PASSED\n")

  ;; Test 2: Aggregation value update
  (println "Test 2: Aggregation Value Update")
  (let [v1 (create-agg-value 10)
        v2 (update-agg-value v1 20)
        v3 (update-agg-value v2 5)]
    (assert (= 1 (:count v1)) "initial count")
    (assert (= 2 (:count v2)) "updated count")
    (assert (= 3 (:count v3)) "final count")
    (assert (= 35 (:sum v3)) "sum")
    (assert (= 5 (:min-val v3)) "min")
    (assert (= 20 (:max-val v3)) "max"))
  (println "  Aggregation value update works correctly")
  (println "  PASSED\n")

  ;; Test 3: Per-CPU aggregation
  (println "Test 3: Per-CPU Aggregation")
  (clear-cpu-maps!)
  (let [key (create-agg-key "test")]
    (update-cpu-map! 0 key 10)
    (update-cpu-map! 0 key 20)
    (update-cpu-map! 1 key 30)
    (let [agg (get-aggregation key)]
      (assert (= 3 (:count agg)) "count across CPUs")
      (assert (= 60 (:sum agg)) "sum across CPUs")))
  (println "  Per-CPU aggregation works correctly")
  (println "  PASSED\n")

  ;; Test 4: Cross-CPU merge
  (println "Test 4: Cross-CPU Merge")
  (clear-cpu-maps!)
  (dotimes [cpu num-cpus]
    (update-cpu-map! cpu (create-agg-key "test") (* cpu 10)))
  (let [agg (get-aggregation (create-agg-key "test"))]
    (assert (= num-cpus (:count agg)) "all CPUs contributed")
    (assert (= 0 (:min-val agg)) "min from CPU 0")
    (assert (= 30 (:max-val agg)) "max from CPU 3"))
  (println "  Cross-CPU merge works correctly")
  (println "  PASSED\n")

  ;; Test 5: Collect all aggregations
  (println "Test 5: Collect All Aggregations")
  (clear-cpu-maps!)
  (aggregate-event! (create-agg-key "key1") 10)
  (aggregate-event! (create-agg-key "key2") 20)
  (aggregate-event! (create-agg-key "key1") 30)
  (let [all (collect-all-aggregations)]
    (assert (= 2 (count all)) "two unique keys")
    (assert (>= (:count (get all (create-agg-key "key1"))) 1) "key1 counted"))
  (println "  Collect all aggregations works correctly")
  (println "  PASSED\n")

  ;; Test 6: Window flush
  (println "Test 6: Window Flush")
  (clear-cpu-maps!)
  (clear-window-history!)
  (aggregate-event! (create-agg-key "test") 100)
  (let [flushed (flush-window!)]
    (assert (seq flushed) "flushed data")
    (assert (empty? (collect-all-aggregations)) "maps cleared")
    (assert (= 1 (count (get-window-history 10))) "history recorded"))
  (println "  Window flush works correctly")
  (println "  PASSED\n")

  ;; Test 7: Top aggregations
  (println "Test 7: Top Aggregations")
  (clear-cpu-maps!)
  (dotimes [_ 10] (aggregate-event! (create-agg-key "frequent") 1))
  (dotimes [_ 5] (aggregate-event! (create-agg-key "medium") 1))
  (aggregate-event! (create-agg-key "rare") 1)
  (let [top (top-aggregations 2)]
    (assert (= 2 (count top)) "two returned")
    (assert (>= (:count (val (first top))) (:count (val (second top)))) "sorted desc"))
  (println "  Top aggregations works correctly")
  (println "  PASSED\n")

  ;; Test 8: Aggregation statistics
  (println "Test 8: Aggregation Statistics")
  (clear-cpu-maps!)
  (dotimes [i 100]
    (aggregate-event! (create-agg-key (str "key" (mod i 10))) i))
  (let [stats (aggregation-stats)]
    (assert (= 10 (:num-keys stats)) "10 unique keys")
    (assert (= 100 (:total-events stats)) "100 total events"))
  (println "  Aggregation statistics work correctly")
  (println "  PASSED\n")

  ;; Test 9: Event reduction calculation
  (println "Test 9: Event Reduction")
  (reset-counters!)
  (dotimes [_ 1000] (record-raw-event!))
  (record-aggregated-output! 10)
  (let [stats (get-reduction-stats)]
    (assert (= 1000 (:raw-events stats)) "raw events counted")
    (assert (= 100 (:reduction-factor stats)) "100x reduction"))
  (println "  Event reduction calculation works correctly")
  (println "  PASSED\n")

  ;; Test 10: Distribution analysis
  (println "Test 10: Distribution Analysis")
  (clear-cpu-maps!)
  (dotimes [_ 100] (aggregate-event! (create-agg-key "hot") 1))
  (dotimes [_ 10] (aggregate-event! (create-agg-key "warm") 1))
  (aggregate-event! (create-agg-key "cold") 1)
  (let [dist (aggregation-distribution)]
    (assert (= 1 (:min dist)) "min is 1")
    (assert (>= (:max dist) 100) "max is >= 100")
    (assert (= 3 (:total-keys dist)) "3 keys"))
  (println "  Distribution analysis works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 10: Demo
;;; ============================================================================

(defn demo
  "Demonstrate event aggregation"
  []
  (println "\n=== Event Aggregation Demo ===\n")
  (clear-cpu-maps!)
  (reset-counters!)

  ;; Simulate high-rate events
  (println "Simulating 10,000 events across 100 unique keys...")
  (dotimes [_ 10000]
    (record-raw-event!)
    (aggregate-event!
     (create-agg-key (str "syscall-" (rand-int 100)))
     (rand-int 1000)))

  (println "\nAggregation Statistics:")
  (let [stats (aggregation-stats)]
    (println (format "  Unique keys: %d" (:num-keys stats)))
    (println (format "  Total events: %d" (:total-events stats)))
    (println (format "  Events per CPU: %s" (:keys-per-cpu stats))))

  (println "\nTop 5 Aggregations:")
  (doseq [[k v] (top-aggregations 5)]
    (println (format "  %s: count=%d avg=%.1f min=%d max=%d"
                     (:category k)
                     (:count v)
                     (double (agg-average v))
                     (:min-val v)
                     (:max-val v))))

  (println "\nEvent Reduction:")
  (record-aggregated-output! (count (collect-all-aggregations)))
  (let [reduction (get-reduction-stats)]
    (println (format "  Raw events: %d" (:raw-events reduction)))
    (println (format "  Aggregated keys: %d" (:aggregated-keys reduction)))
    (println (format "  Reduction factor: %.1fx" (double (:reduction-factor reduction))))))

;;; ============================================================================
;;; Part 11: Main
;;; ============================================================================

(defn -main
  [& args]
  (case (first args)
    "test" (run-tests)
    "demo" (demo)
    (do
      (println "Usage: clojure -M -m lab-25-1-event-aggregation [test|demo]")
      (System/exit 1))))
