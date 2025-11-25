(ns clj-ebpf.bench-core
  "Core benchmarking infrastructure for clj-ebpf.

   Provides utilities for:
   - Running benchmarks with Criterium
   - Reporting results in consistent format
   - Comparing performance across operations"
  (:require [criterium.core :as crit]))

;; ============================================================================
;; Benchmark Configuration
;; ============================================================================

(def ^:dynamic *quick-bench*
  "Use quick-bench instead of full bench for faster iteration"
  true)

(def ^:dynamic *warmup-time*
  "Warmup time in seconds"
  1.0)

(def ^:dynamic *measurement-time*
  "Measurement time in seconds"
  2.0)

;; ============================================================================
;; Result Formatting
;; ============================================================================

(defn format-time
  "Format a time value (in seconds) to human-readable string"
  [seconds]
  (cond
    (< seconds 1e-6) (format "%.2f ns" (* seconds 1e9))
    (< seconds 1e-3) (format "%.2f µs" (* seconds 1e6))
    (< seconds 1.0)  (format "%.2f ms" (* seconds 1e3))
    :else            (format "%.2f s" seconds)))

(defn format-throughput
  "Format throughput (ops/sec) to human-readable string"
  [ops-per-sec]
  (cond
    (> ops-per-sec 1e9) (format "%.2f B ops/s" (/ ops-per-sec 1e9))
    (> ops-per-sec 1e6) (format "%.2f M ops/s" (/ ops-per-sec 1e6))
    (> ops-per-sec 1e3) (format "%.2f K ops/s" (/ ops-per-sec 1e3))
    :else               (format "%.0f ops/s" ops-per-sec)))

(defn extract-stats
  "Extract key statistics from Criterium results"
  [results]
  (let [mean-time (first (:mean results))
        std-dev (first (:variance results))
        lower-q (first (:lower-q results))
        upper-q (first (:upper-q results))]
    {:mean-time mean-time
     :std-dev (when std-dev (Math/sqrt std-dev))
     :lower-quantile lower-q
     :upper-quantile upper-q
     :throughput (when (pos? mean-time) (/ 1.0 mean-time))
     :sample-count (:sample-count results)}))

(defn print-result
  "Print a single benchmark result"
  [name stats]
  (println (format "%-40s %12s  (%s)"
                   name
                   (format-time (:mean-time stats))
                   (format-throughput (:throughput stats)))))

;; ============================================================================
;; Benchmark Execution
;; ============================================================================

(defmacro bench
  "Run a benchmark and return statistics.

   Arguments:
   - name: String name for the benchmark
   - expr: Expression to benchmark

   Returns a map with :name, :stats, and :raw-results"
  [name expr]
  `(let [results# (if *quick-bench*
                    (crit/quick-benchmark ~expr {})
                    (crit/benchmark ~expr {:warmup-jit-period (* *warmup-time* 1e9)
                                           :target-execution-time (* *measurement-time* 1e9)}))]
     {:name ~name
      :stats (extract-stats results#)
      :raw-results results#}))

(defmacro bench-with-setup
  "Run a benchmark with setup code that runs before each iteration.

   Arguments:
   - name: String name for the benchmark
   - setup: Setup expression (evaluated fresh each time)
   - expr: Expression to benchmark (can use bindings from setup)"
  [name setup expr]
  `(let [results# (if *quick-bench*
                    (crit/quick-benchmark
                     (let [setup-val# ~setup]
                       ~expr)
                     {})
                    (crit/benchmark
                     (let [setup-val# ~setup]
                       ~expr)
                     {:warmup-jit-period (* *warmup-time* 1e9)
                      :target-execution-time (* *measurement-time* 1e9)}))]
     {:name ~name
      :stats (extract-stats results#)
      :raw-results results#}))

(defn run-benchmark-suite
  "Run a suite of benchmarks and print results.

   Arguments:
   - suite-name: Name of the benchmark suite
   - benchmarks: Sequence of benchmark results (from bench macro)

   Returns the benchmark results."
  [suite-name benchmarks]
  (println)
  (println (str "=== " suite-name " ==="))
  (println (format "%-40s %12s  %s" "Benchmark" "Mean Time" "Throughput"))
  (println (apply str (repeat 75 "-")))
  (doseq [{:keys [name stats]} benchmarks]
    (print-result name stats))
  (println)
  benchmarks)

;; ============================================================================
;; Comparison Utilities
;; ============================================================================

(defn compare-benchmarks
  "Compare two benchmark results and print the difference.

   Arguments:
   - baseline: Baseline benchmark result
   - comparison: Comparison benchmark result

   Returns a map with comparison statistics."
  [baseline comparison]
  (let [baseline-time (get-in baseline [:stats :mean-time])
        comparison-time (get-in comparison [:stats :mean-time])
        speedup (/ baseline-time comparison-time)
        percent-change (* 100 (- 1 (/ comparison-time baseline-time)))]
    {:baseline (:name baseline)
     :comparison (:name comparison)
     :baseline-time baseline-time
     :comparison-time comparison-time
     :speedup speedup
     :percent-change percent-change
     :faster? (> speedup 1.0)}))

(defn print-comparison
  "Print a comparison between two benchmarks"
  [comparison]
  (println (format "%s vs %s:"
                   (:baseline comparison)
                   (:comparison comparison)))
  (println (format "  Baseline:   %s" (format-time (:baseline-time comparison))))
  (println (format "  Comparison: %s" (format-time (:comparison-time comparison))))
  (println (format "  Speedup:    %.2fx (%+.1f%%)"
                   (:speedup comparison)
                   (:percent-change comparison))))

;; ============================================================================
;; Batch Benchmark Utilities
;; ============================================================================

(defn batch-sizes
  "Generate a sequence of batch sizes for testing"
  ([] (batch-sizes 1 10000))
  ([min-size max-size]
   (->> [1 10 100 500 1000 2000 5000 10000]
        (filter #(<= min-size % max-size)))))

(defn run-scaling-benchmark
  "Run a benchmark across different sizes to measure scaling.

   Arguments:
   - name: Base name for the benchmark
   - sizes: Sequence of sizes to test
   - setup-fn: (fn [size] -> setup-value) - creates setup data for size
   - bench-fn: (fn [setup-value] -> result) - the operation to benchmark

   Returns a sequence of {:size, :stats, :raw-results}"
  [name sizes setup-fn bench-fn]
  (println)
  (println (str "=== Scaling: " name " ==="))
  (println (format "%-10s %12s  %12s  %s"
                   "Size" "Mean Time" "Per Item" "Throughput"))
  (println (apply str (repeat 65 "-")))
  (doall
   (for [size sizes]
     (let [setup-val (setup-fn size)
           results (if *quick-bench*
                     (crit/quick-benchmark (bench-fn setup-val) {})
                     (crit/benchmark (bench-fn setup-val) {}))
           stats (extract-stats results)
           per-item (/ (:mean-time stats) size)]
       (println (format "%-10d %12s  %12s  %s"
                        size
                        (format-time (:mean-time stats))
                        (format-time per-item)
                        (format-throughput (* size (:throughput stats)))))
       {:size size
        :stats stats
        :per-item-time per-item
        :raw-results results}))))

;; ============================================================================
;; Memory Benchmark Utilities
;; ============================================================================

(defn estimate-memory-usage
  "Estimate memory usage of an object by forcing GC and measuring heap.

   Note: This is an approximation and may not be accurate for all cases."
  [create-fn]
  (System/gc)
  (Thread/sleep 100)
  (let [runtime (Runtime/getRuntime)
        before (- (.totalMemory runtime) (.freeMemory runtime))
        obj (create-fn)]
    (System/gc)
    (Thread/sleep 100)
    (let [after (- (.totalMemory runtime) (.freeMemory runtime))
          diff (- after before)]
      {:object obj
       :estimated-bytes (max 0 diff)
       :before-bytes before
       :after-bytes after})))

(defn format-bytes
  "Format byte count to human-readable string"
  [bytes]
  (cond
    (> bytes (* 1024 1024 1024)) (format "%.2f GB" (/ bytes (* 1024.0 1024 1024)))
    (> bytes (* 1024 1024))      (format "%.2f MB" (/ bytes (* 1024.0 1024)))
    (> bytes 1024)               (format "%.2f KB" (/ bytes 1024.0))
    :else                        (format "%d B" bytes)))
