;; Lab 16.2 Solution: Per-CPU Counter System
;; Build a high-performance counter system using per-CPU data structures
;;
;; Learning Goals:
;; - Understand per-CPU data structures
;; - Eliminate lock contention
;; - Aggregate per-CPU values efficiently

(ns lab-16-2-percpu-counters
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps])
  (:import [java.util.concurrent.atomic AtomicLong AtomicLongArray]
           [java.util.concurrent CountDownLatch]
           [java.time Instant]))

;; ============================================================================
;; Per-CPU Counter Implementation
;; ============================================================================

(defrecord PerCPUCounter [^"[Ljava.util.concurrent.atomic.AtomicLong;" cpu-counters
                          num-cpus]
  clojure.lang.IDeref
  (deref [_]
    (reduce + (map #(.get ^AtomicLong %) cpu-counters))))

(defn create-percpu-counter
  "Create a per-CPU counter"
  [num-cpus]
  (let [counters (into-array AtomicLong
                   (repeatedly num-cpus #(AtomicLong. 0)))]
    (->PerCPUCounter counters num-cpus)))

(defn increment-percpu!
  "Increment the counter for a specific CPU"
  [^PerCPUCounter counter cpu-id]
  (.incrementAndGet ^AtomicLong (aget ^"[Ljava.util.concurrent.atomic.AtomicLong;"
                                       (:cpu-counters counter) cpu-id)))

(defn add-percpu!
  "Add value to the counter for a specific CPU"
  [^PerCPUCounter counter cpu-id value]
  (.addAndGet ^AtomicLong (aget ^"[Ljava.util.concurrent.atomic.AtomicLong;"
                                 (:cpu-counters counter) cpu-id) value))

(defn get-percpu-value
  "Get counter value for a specific CPU"
  [^PerCPUCounter counter cpu-id]
  (.get ^AtomicLong (aget ^"[Ljava.util.concurrent.atomic.AtomicLong;"
                          (:cpu-counters counter) cpu-id)))

(defn get-all-percpu-values
  "Get all per-CPU values as a vector"
  [^PerCPUCounter counter]
  (vec (map #(.get ^AtomicLong %) (:cpu-counters counter))))

(defn reset-percpu!
  "Reset all per-CPU values to zero"
  [^PerCPUCounter counter]
  (doseq [^AtomicLong c (:cpu-counters counter)]
    (.set c 0)))

;; ============================================================================
;; Per-CPU Statistics Struct
;; ============================================================================

(defrecord CPUStats [packets bytes errors dropped])

(defn create-cpu-stats []
  (atom (->CPUStats 0 0 0 0)))

(defrecord PerCPUStats [stats-array num-cpus]
  clojure.lang.IDeref
  (deref [_]
    (reduce
      (fn [acc stats-atom]
        (let [stats @stats-atom]
          {:packets (+ (:packets acc) (:packets stats))
           :bytes (+ (:bytes acc) (:bytes stats))
           :errors (+ (:errors acc) (:errors stats))
           :dropped (+ (:dropped acc) (:dropped stats))}))
      {:packets 0 :bytes 0 :errors 0 :dropped 0}
      stats-array)))

(defn create-percpu-stats
  "Create per-CPU statistics structure"
  [num-cpus]
  (let [stats-array (vec (repeatedly num-cpus create-cpu-stats))]
    (->PerCPUStats stats-array num-cpus)))

(defn update-stats!
  "Update statistics for a specific CPU"
  [^PerCPUStats percpu-stats cpu-id update-fn]
  (swap! (nth (:stats-array percpu-stats) cpu-id) update-fn))

(defn record-packet!
  "Record a packet on the specified CPU"
  [^PerCPUStats percpu-stats cpu-id packet-size]
  (update-stats! percpu-stats cpu-id
    (fn [stats]
      (-> stats
          (update :packets inc)
          (update :bytes + packet-size)))))

(defn record-error!
  "Record an error on the specified CPU"
  [^PerCPUStats percpu-stats cpu-id]
  (update-stats! percpu-stats cpu-id
    (fn [stats]
      (update stats :errors inc))))

(defn record-drop!
  "Record a dropped packet on the specified CPU"
  [^PerCPUStats percpu-stats cpu-id]
  (update-stats! percpu-stats cpu-id
    (fn [stats]
      (update stats :dropped inc))))

(defn get-cpu-stats
  "Get statistics for a specific CPU"
  [^PerCPUStats percpu-stats cpu-id]
  @(nth (:stats-array percpu-stats) cpu-id))

(defn reset-all-stats!
  "Reset all per-CPU statistics"
  [^PerCPUStats percpu-stats]
  (doseq [stats-atom (:stats-array percpu-stats)]
    (reset! stats-atom (->CPUStats 0 0 0 0))))

;; ============================================================================
;; Multi-Counter Dashboard
;; ============================================================================

(def EVENT-TYPES [:tcp :udp :icmp :other])

(defn create-event-counters
  "Create per-CPU counters for each event type"
  [num-cpus]
  (into {}
    (for [event-type EVENT-TYPES]
      [event-type (create-percpu-counter num-cpus)])))

(defn increment-event!
  "Increment event counter for given type on specified CPU"
  [counters event-type cpu-id]
  (when-let [counter (get counters event-type)]
    (increment-percpu! counter cpu-id)))

(defn get-event-totals
  "Get total counts for all event types"
  [counters]
  (into {}
    (for [[event-type counter] counters]
      [event-type @counter])))

(defn get-event-breakdown
  "Get per-CPU breakdown for all event types"
  [counters]
  (into {}
    (for [[event-type counter] counters]
      [event-type (get-all-percpu-values counter)])))

(defn reset-all-event-counters!
  "Reset all event counters"
  [counters]
  (doseq [[_ counter] counters]
    (reset-percpu! counter)))

;; ============================================================================
;; Display Functions
;; ============================================================================

(defn display-event-dashboard
  "Display event counter dashboard"
  [counters]
  (println "\n=== Event Counter Dashboard ===")
  (println (format "%-12s %15s" "Event Type" "Count"))
  (println (apply str (repeat 30 "-")))
  (let [totals (get-event-totals counters)]
    (doseq [event-type EVENT-TYPES]
      (println (format "%-12s %,15d"
                       (name event-type)
                       (get totals event-type 0)))))
  (println (apply str (repeat 30 "-")))
  (println (format "%-12s %,15d"
                   "TOTAL"
                   (reduce + (vals (get-event-totals counters))))))

(defn display-percpu-breakdown
  "Display per-CPU breakdown"
  [counters]
  (println "\n=== Per-CPU Breakdown ===")
  (let [breakdown (get-event-breakdown counters)
        num-cpus (count (first (vals breakdown)))]
    (print (format "%-10s" ""))
    (dotimes [cpu num-cpus]
      (print (format "%10s" (str "CPU" cpu))))
    (println)
    (println (apply str (repeat (+ 10 (* 10 num-cpus)) "-")))
    (doseq [event-type EVENT-TYPES]
      (print (format "%-10s" (name event-type)))
      (doseq [v (get breakdown event-type)]
        (print (format "%10d" v)))
      (println))))

(defn display-stats-dashboard
  "Display statistics dashboard"
  [^PerCPUStats percpu-stats]
  (let [totals @percpu-stats]
    (println "\n=== Statistics Dashboard ===")
    (println (format "Packets:  %,15d" (:packets totals)))
    (println (format "Bytes:    %,15d" (:bytes totals)))
    (println (format "Errors:   %,15d" (:errors totals)))
    (println (format "Dropped:  %,15d" (:dropped totals)))
    (when (pos? (:packets totals))
      (println (format "Avg Size: %15.1f bytes"
                       (double (/ (:bytes totals) (:packets totals))))))))

;; ============================================================================
;; Rate Calculator
;; ============================================================================

(defn calculate-rate
  "Calculate events per second over a sample period"
  [counter sample-ms]
  (let [start-count @counter
        _ (Thread/sleep sample-ms)
        end-count @counter
        delta (- end-count start-count)]
    {:delta delta
     :duration-ms sample-ms
     :rate-per-sec (/ (* delta 1000.0) sample-ms)}))

(defn calculate-all-rates
  "Calculate rates for all event types"
  [counters sample-ms]
  (let [start-totals (get-event-totals counters)
        _ (Thread/sleep sample-ms)
        end-totals (get-event-totals counters)]
    (into {}
      (for [event-type EVENT-TYPES]
        (let [delta (- (get end-totals event-type 0)
                       (get start-totals event-type 0))]
          [event-type (/ (* delta 1000.0) sample-ms)])))))

(defn display-rate-dashboard
  "Display event rates"
  [counters sample-ms]
  (println (format "\n=== Event Rates (sampled over %dms) ===" sample-ms))
  (println (format "%-12s %15s" "Event Type" "Rate/sec"))
  (println (apply str (repeat 30 "-")))
  (let [rates (calculate-all-rates counters sample-ms)]
    (doseq [event-type EVENT-TYPES]
      (println (format "%-12s %,15.1f"
                       (name event-type)
                       (get rates event-type 0.0))))))

;; ============================================================================
;; Benchmarking
;; ============================================================================

(defn benchmark-shared-counter
  "Benchmark shared counter with contention"
  [num-threads iterations-per-thread]
  (let [counter (AtomicLong. 0)
        latch (CountDownLatch. num-threads)
        start-time (atom nil)
        threads (doall
                  (for [_ (range num-threads)]
                    (Thread.
                      (fn []
                        (.await latch)
                        (dotimes [_ iterations-per-thread]
                          (.incrementAndGet counter))))))]

    (doseq [^Thread t threads] (.start t))
    (reset! start-time (System/nanoTime))
    (dotimes [_ num-threads] (.countDown latch))
    (doseq [^Thread t threads] (.join t))

    (let [elapsed-ns (- (System/nanoTime) @start-time)
          total-ops (* num-threads iterations-per-thread)
          ops-per-sec (/ (* total-ops 1e9) elapsed-ns)]
      {:threads num-threads
       :total-ops total-ops
       :elapsed-ms (/ elapsed-ns 1e6)
       :ops-per-sec ops-per-sec
       :final-count (.get counter)})))

(defn benchmark-percpu-counter
  "Benchmark per-CPU counter (no contention)"
  [num-cpus iterations-per-cpu]
  (let [counter (create-percpu-counter num-cpus)
        latch (CountDownLatch. num-cpus)
        start-time (atom nil)
        threads (doall
                  (for [cpu-id (range num-cpus)]
                    (Thread.
                      (fn []
                        (.await latch)
                        (dotimes [_ iterations-per-cpu]
                          (increment-percpu! counter cpu-id))))))]

    (doseq [^Thread t threads] (.start t))
    (reset! start-time (System/nanoTime))
    (dotimes [_ num-cpus] (.countDown latch))
    (doseq [^Thread t threads] (.join t))

    (let [elapsed-ns (- (System/nanoTime) @start-time)
          total-ops (* num-cpus iterations-per-cpu)
          ops-per-sec (/ (* total-ops 1e9) elapsed-ns)]
      {:cpus num-cpus
       :total-ops total-ops
       :elapsed-ms (/ elapsed-ns 1e6)
       :ops-per-sec ops-per-sec
       :final-count @counter})))

(defn compare-implementations
  "Compare shared vs per-CPU counter performance"
  []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "     Shared vs Per-CPU Counter Comparison")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (let [iterations 1000000]
    (println (format "%-20s %10s %15s %10s"
                     "Implementation" "Threads" "Ops/sec" "Scaling"))
    (println (apply str (repeat 60 "-")))

    ;; Baseline
    (let [shared-1 (benchmark-shared-counter 1 iterations)
          percpu-1 (benchmark-percpu-counter 1 iterations)]

      (doseq [threads [1 2 4 8]]
        (let [shared (benchmark-shared-counter threads (/ iterations threads))
              percpu (benchmark-percpu-counter threads (/ iterations threads))]

          (println (format "%-20s %10d %,15.0f %10.2fx"
                           "Shared"
                           threads
                           (:ops-per-sec shared)
                           (/ (:ops-per-sec shared) (:ops-per-sec shared-1))))

          (println (format "%-20s %10d %,15.0f %10.2fx"
                           "Per-CPU"
                           threads
                           (:ops-per-sec percpu)
                           (/ (:ops-per-sec percpu) (:ops-per-sec percpu-1))))
          (println))))))

;; ============================================================================
;; Event Simulation
;; ============================================================================

(defn simulate-events
  "Simulate events across multiple CPUs"
  [counters num-cpus events-per-cpu]
  (let [latch (CountDownLatch. num-cpus)
        threads (doall
                  (for [cpu-id (range num-cpus)]
                    (Thread.
                      (fn []
                        (dotimes [_ events-per-cpu]
                          (let [event-type (rand-nth EVENT-TYPES)]
                            (increment-event! counters event-type cpu-id)))
                        (.countDown latch)))))]
    (doseq [^Thread t threads] (.start t))
    (.await latch)))

(defn run-simulation
  "Run event simulation and display results"
  [num-cpus duration-ms target-rate]
  (let [counters (create-event-counters num-cpus)
        events-per-cpu (/ (* target-rate duration-ms) num-cpus 1000)]

    (println (format "\nSimulating %d events/sec across %d CPUs for %dms..."
                     target-rate num-cpus duration-ms))

    (let [start-time (System/nanoTime)]
      (simulate-events counters num-cpus (int events-per-cpu))
      (let [elapsed-ns (- (System/nanoTime) start-time)
            actual-rate (/ (* (reduce + (vals (get-event-totals counters))) 1e9)
                           elapsed-ns)]
        (display-event-dashboard counters)
        (display-percpu-breakdown counters)
        (println (format "\nActual throughput: %,.0f events/sec" actual-rate))))

    counters))

;; ============================================================================
;; Throughput Test
;; ============================================================================

(defn throughput-test
  "Test maximum throughput"
  []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "     Per-CPU Counter Throughput Test")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (let [num-cpus 8
        iterations 10000000
        counters (create-event-counters num-cpus)
        start-time (System/nanoTime)]

    (simulate-events counters num-cpus (/ iterations num-cpus))

    (let [elapsed-ns (- (System/nanoTime) start-time)
          elapsed-ms (/ elapsed-ns 1e6)
          ops-per-sec (/ (* iterations 1e9) elapsed-ns)]

      (println (format "Total events: %,d" iterations))
      (println (format "Elapsed time: %.2f ms" elapsed-ms))
      (println (format "Throughput: %,.0f events/sec" ops-per-sec))

      (display-event-dashboard counters))))

;; ============================================================================
;; Tests
;; ============================================================================

(defn test-percpu-counter []
  (println "Testing per-CPU counter...")
  (let [counter (create-percpu-counter 4)]
    ;; Test increments
    (doseq [cpu-id (range 4)]
      (dotimes [_ 100]
        (increment-percpu! counter cpu-id)))

    (assert (= 400 @counter) "Total should be 400")

    ;; Test per-CPU values
    (doseq [cpu-id (range 4)]
      (assert (= 100 (get-percpu-value counter cpu-id))
              (format "CPU %d should have 100" cpu-id)))

    ;; Test add
    (add-percpu! counter 0 50)
    (assert (= 450 @counter) "Total should be 450 after add")

    ;; Test reset
    (reset-percpu! counter)
    (assert (= 0 @counter) "Total should be 0 after reset")

    (println "Per-CPU counter tests passed!")))

(defn test-percpu-stats []
  (println "Testing per-CPU stats...")
  (let [stats (create-percpu-stats 4)]
    ;; Record packets on different CPUs
    (doseq [cpu-id (range 4)]
      (dotimes [_ 10]
        (record-packet! stats cpu-id 1500)))

    (let [totals @stats]
      (assert (= 40 (:packets totals)) "Should have 40 packets")
      (assert (= 60000 (:bytes totals)) "Should have 60000 bytes"))

    ;; Record errors and drops
    (record-error! stats 0)
    (record-drop! stats 1)

    (let [totals @stats]
      (assert (= 1 (:errors totals)) "Should have 1 error")
      (assert (= 1 (:dropped totals)) "Should have 1 drop"))

    (println "Per-CPU stats tests passed!")))

(defn test-event-counters []
  (println "Testing event counters...")
  (let [counters (create-event-counters 4)]
    ;; Increment events
    (doseq [cpu-id (range 4)]
      (dotimes [_ 25]
        (increment-event! counters :tcp cpu-id))
      (dotimes [_ 15]
        (increment-event! counters :udp cpu-id)))

    (let [totals (get-event-totals counters)]
      (assert (= 100 (:tcp totals)) "Should have 100 TCP events")
      (assert (= 60 (:udp totals)) "Should have 60 UDP events"))

    (println "Event counter tests passed!")))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the per-CPU counter lab"
  [& args]
  (println "Lab 16.2: Per-CPU Counter System")
  (println "=================================\n")

  (let [command (first args)]
    (case command
      "test"
      (do
        (test-percpu-counter)
        (test-percpu-stats)
        (test-event-counters))

      "compare"
      (compare-implementations)

      "throughput"
      (throughput-test)

      "simulate"
      (run-simulation 8 2000 100000)

      ;; Default: full demo
      (do
        (test-percpu-counter)
        (test-percpu-stats)
        (test-event-counters)

        (compare-implementations)
        (throughput-test)
        (run-simulation 8 2000 100000)

        (println "\n=== Key Takeaways ===")
        (println "1. Shared counters suffer from cache line bouncing")
        (println "2. Per-CPU counters scale linearly with CPU count")
        (println "3. Aggregation adds minimal overhead")
        (println "4. Use per-CPU for any high-frequency counter")))))

;; Run with: clj -M -m lab-16-2-percpu-counters
