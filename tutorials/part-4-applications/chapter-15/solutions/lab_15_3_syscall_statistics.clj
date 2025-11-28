(ns lab-15-3-syscall-statistics
  "Lab 15.3: Syscall Statistics and Aggregation

   This solution demonstrates:
   - Per-syscall counting and timing
   - Latency histogram generation
   - Error rate tracking
   - Top-N analysis
   - Per-process statistics

   Run with: clojure -M -m lab-15-3-syscall-statistics test"
  (:require [clojure.string :as str]))

;;; ============================================================================
;;; Part 1: Statistics Data Structures
;;; ============================================================================

(defrecord SyscallStats
  [count total-duration-ns min-duration-ns max-duration-ns error-count])

(defn create-stats
  "Create empty statistics record"
  []
  (->SyscallStats 0 0 Long/MAX_VALUE 0 0))

(defn update-stats
  "Update statistics with new event"
  [stats duration-ns error?]
  (->SyscallStats
    (inc (:count stats))
    (+ (:total-duration-ns stats) duration-ns)
    (min (:min-duration-ns stats) duration-ns)
    (max (:max-duration-ns stats) duration-ns)
    (if error? (inc (:error-count stats)) (:error-count stats))))

(defn avg-duration
  "Calculate average duration"
  [stats]
  (if (pos? (:count stats))
    (/ (:total-duration-ns stats) (:count stats))
    0))

(defn error-rate
  "Calculate error rate as percentage"
  [stats]
  (if (pos? (:count stats))
    (* 100.0 (/ (:error-count stats) (:count stats)))
    0.0))

;;; ============================================================================
;;; Part 2: Per-Syscall Statistics
;;; ============================================================================

(def syscall-statistics
  "Per-syscall statistics, keyed by syscall number"
  (atom {}))

(defn record-syscall!
  "Record a syscall event"
  [syscall-nr duration-ns error?]
  (swap! syscall-statistics
         update syscall-nr
         (fn [stats]
           (update-stats (or stats (create-stats)) duration-ns error?))))

(defn get-syscall-stats
  "Get statistics for a specific syscall"
  [syscall-nr]
  (get @syscall-statistics syscall-nr (create-stats)))

(defn get-all-syscall-stats
  "Get all syscall statistics"
  []
  @syscall-statistics)

(defn reset-syscall-stats!
  "Reset all syscall statistics"
  []
  (reset! syscall-statistics {}))

;;; ============================================================================
;;; Part 3: Per-Process Statistics
;;; ============================================================================

(def process-statistics
  "Per-process statistics, keyed by PID"
  (atom {}))

(defrecord ProcessStats
  [syscall-counts total-duration-ns error-count comm])

(defn create-process-stats
  "Create empty process statistics"
  [comm]
  (->ProcessStats {} 0 0 comm))

(defn record-process-syscall!
  "Record a syscall event for a process"
  [pid comm syscall-nr duration-ns error?]
  (swap! process-statistics
         update pid
         (fn [stats]
           (let [stats (or stats (create-process-stats comm))]
             (->ProcessStats
               (update (:syscall-counts stats) syscall-nr (fnil inc 0))
               (+ (:total-duration-ns stats) duration-ns)
               (if error? (inc (:error-count stats)) (:error-count stats))
               comm)))))

(defn get-process-stats
  "Get statistics for a specific process"
  [pid]
  (get @process-statistics pid))

(defn get-all-process-stats
  "Get all process statistics"
  []
  @process-statistics)

(defn reset-process-stats!
  "Reset all process statistics"
  []
  (reset! process-statistics {}))

;;; ============================================================================
;;; Part 4: Latency Histograms
;;; ============================================================================

(defn duration-to-bucket
  "Convert duration to log2 bucket"
  [duration-ns]
  (if (<= duration-ns 0)
    0
    (min 63 (int (Math/floor (/ (Math/log duration-ns) (Math/log 2)))))))

(defn bucket-to-range
  "Convert bucket number to human-readable range"
  [bucket]
  (let [low (bit-shift-left 1 bucket)
        high (bit-shift-left 1 (inc bucket))]
    (cond
      (< high 1000) (format "%d-%d ns" low high)
      (< high 1000000) (format "%d-%d μs" (quot low 1000) (quot high 1000))
      (< high 1000000000) (format "%d-%d ms" (quot low 1000000) (quot high 1000000))
      :else (format "%d-%d s" (quot low 1000000000) (quot high 1000000000)))))

(def latency-histograms
  "Latency histograms per syscall"
  (atom {}))

(defn record-latency!
  "Record latency in histogram"
  [syscall-nr duration-ns]
  (let [bucket (duration-to-bucket duration-ns)]
    (swap! latency-histograms
           update syscall-nr
           (fn [hist]
             (update (or hist {}) bucket (fnil inc 0))))))

(defn get-latency-histogram
  "Get latency histogram for a syscall"
  [syscall-nr]
  (get @latency-histograms syscall-nr {}))

(defn get-all-latency-histograms
  "Get all latency histograms"
  []
  @latency-histograms)

(defn reset-latency-histograms!
  "Reset all latency histograms"
  []
  (reset! latency-histograms {}))

(defn percentile
  "Calculate percentile from histogram"
  [histogram pct]
  (let [sorted-buckets (sort-by first histogram)
        total (reduce + (map second sorted-buckets))
        target (* total (/ pct 100.0))]
    (loop [buckets sorted-buckets
           cumulative 0]
      (if-let [[bucket count] (first buckets)]
        (let [new-cumulative (+ cumulative count)]
          (if (>= new-cumulative target)
            (bit-shift-left 1 bucket)
            (recur (rest buckets) new-cumulative)))
        (bit-shift-left 1 (or (first (last sorted-buckets)) 0))))))

;;; ============================================================================
;;; Part 5: Combined Event Recording
;;; ============================================================================

(defn record-event!
  "Record a complete syscall event"
  [event]
  (let [{:keys [pid comm syscall-nr duration-ns error?]} event]
    (record-syscall! syscall-nr duration-ns error?)
    (record-process-syscall! pid comm syscall-nr duration-ns error?)
    (record-latency! syscall-nr duration-ns)))

(defn reset-all-stats!
  "Reset all statistics"
  []
  (reset-syscall-stats!)
  (reset-process-stats!)
  (reset-latency-histograms!))

;;; ============================================================================
;;; Part 6: Analysis Functions
;;; ============================================================================

(def syscall-names
  "Common syscall names"
  {0 "read" 1 "write" 2 "open" 3 "close" 41 "socket" 42 "connect"
   44 "sendto" 45 "recvfrom" 59 "execve" 257 "openat"})

(defn syscall-name
  "Get syscall name"
  [nr]
  (get syscall-names nr (format "syscall_%d" nr)))

(defn top-syscalls-by-count
  "Get top N syscalls by count"
  [n]
  (->> (get-all-syscall-stats)
       (sort-by (comp :count second) >)
       (take n)
       (map (fn [[nr stats]]
              {:syscall-nr nr
               :syscall-name (syscall-name nr)
               :count (:count stats)
               :avg-duration-ns (avg-duration stats)
               :error-rate (error-rate stats)}))))

(defn top-syscalls-by-latency
  "Get top N syscalls by average latency"
  [n]
  (->> (get-all-syscall-stats)
       (filter (fn [[_ stats]] (pos? (:count stats))))
       (sort-by (comp avg-duration second) >)
       (take n)
       (map (fn [[nr stats]]
              {:syscall-nr nr
               :syscall-name (syscall-name nr)
               :avg-duration-ns (avg-duration stats)
               :count (:count stats)
               :max-duration-ns (:max-duration-ns stats)}))))

(defn top-syscalls-by-total-time
  "Get top N syscalls by total time spent"
  [n]
  (->> (get-all-syscall-stats)
       (sort-by (comp :total-duration-ns second) >)
       (take n)
       (map (fn [[nr stats]]
              {:syscall-nr nr
               :syscall-name (syscall-name nr)
               :total-duration-ns (:total-duration-ns stats)
               :count (:count stats)
               :pct-time (* 100.0 (/ (:total-duration-ns stats)
                                     (reduce + (map :total-duration-ns (vals (get-all-syscall-stats))))))}))))

(defn top-syscalls-by-errors
  "Get top N syscalls by error count"
  [n]
  (->> (get-all-syscall-stats)
       (filter (fn [[_ stats]] (pos? (:error-count stats))))
       (sort-by (comp :error-count second) >)
       (take n)
       (map (fn [[nr stats]]
              {:syscall-nr nr
               :syscall-name (syscall-name nr)
               :error-count (:error-count stats)
               :error-rate (error-rate stats)
               :count (:count stats)}))))

(defn top-processes-by-syscalls
  "Get top N processes by syscall count"
  [n]
  (->> (get-all-process-stats)
       (map (fn [[pid stats]]
              {:pid pid
               :comm (:comm stats)
               :total-syscalls (reduce + (vals (:syscall-counts stats)))
               :unique-syscalls (count (:syscall-counts stats))
               :total-duration-ns (:total-duration-ns stats)
               :error-count (:error-count stats)}))
       (sort-by :total-syscalls >)
       (take n)))

;;; ============================================================================
;;; Part 7: Reporting
;;; ============================================================================

(defn format-duration
  "Format duration for display"
  [ns]
  (cond
    (< ns 1000) (format "%d ns" ns)
    (< ns 1000000) (format "%.1f μs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.2f ms" (/ ns 1000000.0))
    :else (format "%.2f s" (/ ns 1000000000.0))))

(defn print-syscall-summary
  "Print syscall statistics summary"
  []
  (println "\n=== Syscall Statistics Summary ===\n")

  (let [all-stats (get-all-syscall-stats)
        total-count (reduce + (map :count (vals all-stats)))
        total-errors (reduce + (map :error-count (vals all-stats)))
        total-duration (reduce + (map :total-duration-ns (vals all-stats)))]

    (println (format "Total syscalls: %,d" total-count))
    (println (format "Total errors: %,d (%.2f%%)" total-errors
                     (if (pos? total-count) (* 100.0 (/ total-errors total-count)) 0.0)))
    (println (format "Total time: %s" (format-duration total-duration)))
    (println (format "Unique syscalls: %d" (count all-stats)))
    (println)))

(defn print-top-by-count
  "Print top syscalls by count"
  [n]
  (println (format "=== Top %d Syscalls by Count ===" n))
  (println)
  (println (format "%-15s %10s %12s %10s" "SYSCALL" "COUNT" "AVG LATENCY" "ERR%"))
  (println (str/join "" (repeat 50 "─")))

  (doseq [s (top-syscalls-by-count n)]
    (println (format "%-15s %,10d %12s %9.2f%%"
                     (:syscall-name s)
                     (:count s)
                     (format-duration (long (:avg-duration-ns s)))
                     (:error-rate s))))
  (println))

(defn print-top-by-latency
  "Print top syscalls by latency"
  [n]
  (println (format "=== Top %d Syscalls by Latency ===" n))
  (println)
  (println (format "%-15s %12s %12s %10s" "SYSCALL" "AVG LATENCY" "MAX LATENCY" "COUNT"))
  (println (str/join "" (repeat 55 "─")))

  (doseq [s (top-syscalls-by-latency n)]
    (println (format "%-15s %12s %12s %,10d"
                     (:syscall-name s)
                     (format-duration (long (:avg-duration-ns s)))
                     (format-duration (:max-duration-ns s))
                     (:count s))))
  (println))

(defn print-latency-histogram
  "Print latency histogram for a syscall"
  [syscall-nr]
  (let [hist (get-latency-histogram syscall-nr)
        total (reduce + (vals hist))
        max-count (apply max (cons 0 (vals hist)))]

    (println (format "=== Latency Histogram: %s ===" (syscall-name syscall-nr)))
    (println)
    (println (format "%-20s %10s %6s  %s" "RANGE" "COUNT" "%" "DISTRIBUTION"))
    (println (str/join "" (repeat 70 "─")))

    (doseq [bucket (sort (keys hist))]
      (let [count (get hist bucket)
            pct (* 100.0 (/ count total))
            bar-len (int (* 30 (/ count max-count)))]
        (println (format "%-20s %,10d %5.1f%%  %s"
                         (bucket-to-range bucket)
                         count
                         pct
                         (str/join "" (repeat bar-len "█"))))))

    (println)
    (println (format "P50: %s  P90: %s  P99: %s"
                     (format-duration (percentile hist 50))
                     (format-duration (percentile hist 90))
                     (format-duration (percentile hist 99))))
    (println)))

(defn print-process-summary
  "Print per-process summary"
  [n]
  (println (format "=== Top %d Processes by Syscalls ===" n))
  (println)
  (println (format "%-8s %-16s %10s %8s %12s %8s" "PID" "COMM" "SYSCALLS" "UNIQUE" "TOTAL TIME" "ERRORS"))
  (println (str/join "" (repeat 70 "─")))

  (doseq [p (top-processes-by-syscalls n)]
    (println (format "%-8d %-16s %,10d %8d %12s %8d"
                     (:pid p)
                     (:comm p)
                     (:total-syscalls p)
                     (:unique-syscalls p)
                     (format-duration (:total-duration-ns p))
                     (:error-count p))))
  (println))

;;; ============================================================================
;;; Part 8: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 15.3 Tests ===\n")

  ;; Test 1: Basic stats creation and update
  (println "Test 1: Stats Creation and Update")
  (let [stats (create-stats)
        updated (-> stats
                    (update-stats 1000 false)
                    (update-stats 2000 false)
                    (update-stats 3000 true))]
    (assert (= 3 (:count updated)) "count")
    (assert (= 6000 (:total-duration-ns updated)) "total duration")
    (assert (= 1000 (:min-duration-ns updated)) "min duration")
    (assert (= 3000 (:max-duration-ns updated)) "max duration")
    (assert (= 1 (:error-count updated)) "error count")
    (assert (= 2000 (avg-duration updated)) "avg duration"))
  (println "  Statistics updated correctly")
  (println "  PASSED\n")

  ;; Test 2: Per-syscall statistics
  (println "Test 2: Per-Syscall Statistics")
  (reset-syscall-stats!)
  (record-syscall! 0 1000 false)
  (record-syscall! 0 2000 false)
  (record-syscall! 1 5000 true)
  (let [read-stats (get-syscall-stats 0)
        write-stats (get-syscall-stats 1)]
    (assert (= 2 (:count read-stats)) "read count")
    (assert (= 1 (:count write-stats)) "write count")
    (assert (= 1 (:error-count write-stats)) "write errors"))
  (println "  Per-syscall stats recorded correctly")
  (println "  PASSED\n")

  ;; Test 3: Per-process statistics
  (println "Test 3: Per-Process Statistics")
  (reset-process-stats!)
  (record-process-syscall! 1234 "bash" 0 1000 false)
  (record-process-syscall! 1234 "bash" 1 2000 false)
  (record-process-syscall! 5678 "curl" 42 5000 false)
  (let [bash-stats (get-process-stats 1234)
        curl-stats (get-process-stats 5678)]
    (assert (= 2 (count (:syscall-counts bash-stats))) "bash unique syscalls")
    (assert (= 1 (get (:syscall-counts bash-stats) 0)) "bash read count")
    (assert (= 1 (count (:syscall-counts curl-stats))) "curl unique syscalls"))
  (println "  Per-process stats recorded correctly")
  (println "  PASSED\n")

  ;; Test 4: Latency histograms
  (println "Test 4: Latency Histograms")
  (reset-latency-histograms!)
  (record-latency! 0 100)      ; bucket ~6
  (record-latency! 0 1000)     ; bucket ~9
  (record-latency! 0 10000)    ; bucket ~13
  (record-latency! 0 100000)   ; bucket ~16
  (let [hist (get-latency-histogram 0)]
    (assert (= 4 (count hist)) "4 buckets")
    (assert (= 4 (reduce + (vals hist))) "4 samples"))
  (println "  Latency histograms recorded correctly")
  (println "  PASSED\n")

  ;; Test 5: Bucket conversion
  (println "Test 5: Bucket Conversion")
  (assert (= 0 (duration-to-bucket 1)) "bucket 0")
  (assert (= 10 (duration-to-bucket 1024)) "bucket 10")
  (assert (= 20 (duration-to-bucket 1048576)) "bucket 20")
  (assert (str/includes? (bucket-to-range 10) "μs") "μs range")
  (assert (str/includes? (bucket-to-range 20) "ms") "ms range")
  (println "  Bucket conversion works correctly")
  (println "  PASSED\n")

  ;; Test 6: Percentile calculation
  (println "Test 6: Percentile Calculation")
  (let [hist {10 10, 12 5, 14 3, 16 2}]  ; 20 samples
    (let [p50 (percentile hist 50)]
      (assert (<= (bit-shift-left 1 10) p50 (bit-shift-left 1 12)) "p50 in range"))
    (let [p90 (percentile hist 90)]
      (assert (<= (bit-shift-left 1 14) p90 (bit-shift-left 1 16)) "p90 in range")))
  (println "  Percentiles calculated correctly")
  (println "  PASSED\n")

  ;; Test 7: Top-N analysis
  (println "Test 7: Top-N Analysis")
  (reset-all-stats!)
  (dotimes [_ 100] (record-event! {:pid 1 :comm "a" :syscall-nr 0 :duration-ns 1000 :error? false}))
  (dotimes [_ 50] (record-event! {:pid 1 :comm "a" :syscall-nr 1 :duration-ns 2000 :error? false}))
  (dotimes [_ 10] (record-event! {:pid 1 :comm "a" :syscall-nr 2 :duration-ns 10000 :error? true}))
  (let [by-count (top-syscalls-by-count 3)]
    (assert (= 0 (:syscall-nr (first by-count))) "read is top by count")
    (assert (= 100 (:count (first by-count))) "read has 100 count"))
  (let [by-latency (top-syscalls-by-latency 3)]
    (assert (= 2 (:syscall-nr (first by-latency))) "open is top by latency"))
  (let [by-errors (top-syscalls-by-errors 3)]
    (assert (= 2 (:syscall-nr (first by-errors))) "open has most errors")
    (assert (= 10 (:error-count (first by-errors))) "10 errors"))
  (println "  Top-N analysis works correctly")
  (println "  PASSED\n")

  ;; Test 8: Combined event recording
  (println "Test 8: Combined Event Recording")
  (reset-all-stats!)
  (record-event! {:pid 1234 :comm "test" :syscall-nr 0 :duration-ns 5000 :error? false})
  (assert (= 1 (:count (get-syscall-stats 0))) "syscall recorded")
  (assert (some? (get-process-stats 1234)) "process recorded")
  (assert (seq (get-latency-histogram 0)) "histogram recorded")
  (println "  Combined recording works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 9: Demo
;;; ============================================================================

(defn run-demo
  "Run demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 15.3: Syscall Statistics and Aggregation")
  (println (str/join "" (repeat 60 "=")) "\n")

  (reset-all-stats!)

  ;; Generate sample data
  (println "=== Generating Sample Data ===\n")

  ;; Simulate various syscalls
  (let [events
        (concat
          ;; bash doing file I/O
          (for [_ (range 500)]
            {:pid 1234 :comm "bash" :syscall-nr 0
             :duration-ns (+ 1000 (rand-int 10000)) :error? false})
          (for [_ (range 300)]
            {:pid 1234 :comm "bash" :syscall-nr 1
             :duration-ns (+ 500 (rand-int 5000)) :error? (< (rand) 0.02)})
          (for [_ (range 50)]
            {:pid 1234 :comm "bash" :syscall-nr 257
             :duration-ns (+ 10000 (rand-int 50000)) :error? (< (rand) 0.1)})

          ;; curl doing network I/O
          (for [_ (range 200)]
            {:pid 5678 :comm "curl" :syscall-nr 42
             :duration-ns (+ 100000 (rand-int 2000000)) :error? (< (rand) 0.05)})
          (for [_ (range 400)]
            {:pid 5678 :comm "curl" :syscall-nr 44
             :duration-ns (+ 10000 (rand-int 100000)) :error? false})
          (for [_ (range 350)]
            {:pid 5678 :comm "curl" :syscall-nr 45
             :duration-ns (+ 20000 (rand-int 200000)) :error? false})

          ;; mysql doing mixed I/O
          (for [_ (range 1000)]
            {:pid 9999 :comm "mysql" :syscall-nr 0
             :duration-ns (+ 5000 (rand-int 50000)) :error? false})
          (for [_ (range 800)]
            {:pid 9999 :comm "mysql" :syscall-nr 1
             :duration-ns (+ 2000 (rand-int 20000)) :error? false}))]

    (println (format "Recorded %d syscall events\n" (count events)))
    (doseq [e events]
      (record-event! e)))

  ;; Print reports
  (print-syscall-summary)
  (print-top-by-count 5)
  (print-top-by-latency 5)
  (print-process-summary 5)

  ;; Print histogram for connect syscall
  (print-latency-histogram 42))

;;; ============================================================================
;;; Part 10: Main
;;; ============================================================================

(defn -main [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      (do
        (println "Usage: clojure -M -m lab-15-3-syscall-statistics <command>")
        (println "Commands:")
        (println "  test  - Run tests")
        (println "  demo  - Run demonstration")))))
