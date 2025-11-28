;; Lab 12.3 Solution: Adaptive Sampling System
;; Dynamically adjusts sampling rate based on system load to maintain target overhead
;;
;; Learning Goals:
;; - Implement feedback control for sampling rate
;; - Monitor and estimate BPF program overhead
;; - Balance data quality vs performance
;; - Handle varying load conditions

(ns lab-12-3-adaptive-sampling
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils])
  (:import [java.time LocalTime]
           [java.util Random]))

;; ============================================================================
;; Configuration Constants
;; ============================================================================

(def TARGET_OVERHEAD_PERCENT 2.0)  ; Target 2% CPU overhead
(def ADAPTATION_INTERVAL_MS 1000)  ; Adjust every second
(def MIN_SAMPLE_RATE 1)            ; Sample at least 1%
(def MAX_SAMPLE_RATE 100)          ; Sample at most 100%
(def COST_PER_EVENT_NS 200.0)      ; Estimated 200ns per sampled event

;; PI Controller gains
(def Kp 5.0)   ; Proportional gain
(def Ki 0.5)  ; Integral gain

;; ============================================================================
;; Sampling Configuration
;; ============================================================================

(defrecord SamplingConfig [sample-rate threshold])

(defn create-sampling-config-map
  "Create sampling configuration map"
  []
  {:map-type :array
   :key-type :u32
   :value-type [:struct {:sample-rate :u32
                         :threshold :u32}]
   :max-entries 1
   :description "Sampling configuration (updated by userspace)"})

(defn create-event-stats-map
  "Create per-CPU event statistics map"
  []
  {:map-type :percpu-array
   :key-type :u32
   :value-type [:struct {:processed :u64
                         :sampled :u64}]
   :max-entries 1
   :description "Per-CPU event statistics"})

;; ============================================================================
;; System Metrics
;; ============================================================================

(defrecord SystemMetrics
  [cpu-usage        ; Current CPU usage (%)
   event-rate       ; Events/second
   sample-rate      ; Current sampling rate (1-100)
   overhead         ; Estimated overhead (%)
   target-overhead]) ; Target overhead (%)

(defn measure-cpu-usage
  "Measure CPU usage (simplified simulation)"
  []
  ;; In real implementation, would read /proc/stat
  ;; Here we simulate varying CPU usage
  (+ 10 (rand-int 80)))

;; ============================================================================
;; Event Generation (Simulation)
;; ============================================================================

(def ^:private random (Random.))

(defn generate-event-burst
  "Generate a burst of events (simulating varying load)"
  [base-rate variance]
  (let [actual-rate (+ base-rate
                       (- (rand-int (* 2 variance)) variance))]
    (max 100 actual-rate)))

(defn generate-load-pattern
  "Generate realistic load pattern over time"
  []
  ;; Simulates daily pattern: low -> spike -> high -> low
  (let [hour (mod (.getHour (LocalTime/now)) 24)]
    (cond
      (< hour 6)  {:base-rate 10000 :variance 2000 :description "Low (night)"}
      (< hour 9)  {:base-rate 50000 :variance 10000 :description "Morning spike"}
      (< hour 17) {:base-rate 100000 :variance 20000 :description "High (day)"}
      (< hour 21) {:base-rate 80000 :variance 15000 :description "Evening"}
      :else       {:base-rate 20000 :variance 5000 :description "Low (night)"})))

;; ============================================================================
;; Probabilistic Sampling
;; ============================================================================

(defn should-sample?
  "Determine if event should be sampled based on rate"
  [sample-rate]
  (< (.nextInt random 100) sample-rate))

(defn sample-events
  "Sample events based on current rate"
  [events sample-rate]
  (let [processed (count events)
        sampled (filter (fn [_] (should-sample? sample-rate)) events)]
    {:processed processed
     :sampled (count sampled)
     :events sampled}))

;; ============================================================================
;; Overhead Estimation
;; ============================================================================

(defn estimate-overhead
  "Estimate BPF program overhead based on event rate and sample rate"
  [event-rate sample-rate]
  (let [sampled-events (* event-rate (/ sample-rate 100.0))
        overhead-ns (* sampled-events COST_PER_EVENT_NS)
        overhead-percent (/ overhead-ns 10000000.0)] ; Convert to %
    overhead-percent))

(defn estimate-overhead-detailed
  "Detailed overhead estimation with breakdown"
  [event-rate sample-rate]
  (let [sampled-events (* event-rate (/ sample-rate 100.0))
        sampling-ns (* sampled-events 50)       ; Sampling decision cost
        collection-ns (* sampled-events 100)    ; Event collection cost
        ringbuf-ns (* sampled-events 50)        ; Ring buffer submission
        total-ns (+ sampling-ns collection-ns ringbuf-ns)
        overhead-percent (/ total-ns 10000000.0)]
    {:sampled-events sampled-events
     :sampling-ns sampling-ns
     :collection-ns collection-ns
     :ringbuf-ns ringbuf-ns
     :total-ns total-ns
     :overhead-percent overhead-percent}))

;; ============================================================================
;; PI Controller
;; ============================================================================

(defrecord ControllerState
  [current-rate
   integral-error
   last-error])

(defn create-controller
  "Create PI controller state"
  [initial-rate]
  (->ControllerState initial-rate 0.0 0.0))

(defn calculate-new-sample-rate
  "PI controller for sample rate adjustment"
  [controller current-overhead target-overhead]
  (let [error (- current-overhead target-overhead)
        {:keys [current-rate integral-error]} controller

        ;; Proportional term
        p-term (* Kp error)

        ;; Integral term (with anti-windup)
        new-integral (if (and (> current-rate MIN_SAMPLE_RATE)
                              (< current-rate MAX_SAMPLE_RATE))
                       (+ integral-error (* Ki error))
                       integral-error)  ; Don't accumulate if saturated
        i-term new-integral

        ;; Calculate adjustment
        adjustment (+ p-term i-term)

        ;; Calculate new rate
        new-rate (- current-rate adjustment)

        ;; Clamp to valid range
        clamped-rate (max MIN_SAMPLE_RATE
                         (min MAX_SAMPLE_RATE new-rate))]

    {:new-rate (int clamped-rate)
     :controller (->ControllerState (int clamped-rate) new-integral error)
     :p-term p-term
     :i-term i-term
     :adjustment adjustment}))

;; ============================================================================
;; Adaptive Control Loop
;; ============================================================================

(defn adaptive-control-step
  "Execute one step of adaptive control"
  [state event-rate]
  (let [{:keys [controller last-processed last-sampled history]} state

        ;; Estimate current overhead
        current-rate (:current-rate controller)
        overhead (estimate-overhead event-rate current-rate)

        ;; Calculate new sample rate
        control-result (calculate-new-sample-rate
                        controller
                        overhead
                        TARGET_OVERHEAD_PERCENT)

        new-rate (:new-rate control-result)

        ;; Create metrics entry
        metrics {:time (LocalTime/now)
                 :event-rate (int event-rate)
                 :sample-rate new-rate
                 :overhead overhead
                 :target TARGET_OVERHEAD_PERCENT}]

    ;; Return updated state
    (assoc state
           :controller (:controller control-result)
           :current-metrics metrics
           :history (conj (take 59 history) metrics))))

(defn run-adaptive-loop
  "Run the adaptive control loop"
  [duration-sec]
  (println "Starting Adaptive Sampling System")
  (println (format "Target Overhead: %.1f%%" TARGET_OVERHEAD_PERCENT))
  (println (format "Running for %d seconds" duration-sec))
  (println)

  (let [iterations (quot (* duration-sec 1000) ADAPTATION_INTERVAL_MS)
        initial-state {:controller (create-controller 50)
                       :last-processed 0
                       :last-sampled 0
                       :history []}]

    ;; Run control loop
    (loop [state initial-state
           iteration 0]
      (if (>= iteration iterations)
        ;; Return final state
        state

        ;; Execute one control step
        (let [;; Generate varying load
              load-pattern (generate-load-pattern)
              event-rate (generate-event-burst
                          (:base-rate load-pattern)
                          (:variance load-pattern))

              ;; Execute control step
              new-state (adaptive-control-step state event-rate)
              metrics (:current-metrics new-state)]

          ;; Display status
          (println (format "[%s] Events: %6d/sec, Sample: %3d%%, Overhead: %5.2f%%, Target: %.1f%% [%s]"
                           (:time metrics)
                           (:event-rate metrics)
                           (:sample-rate metrics)
                           (:overhead metrics)
                           (:target metrics)
                           (if (< (Math/abs (- (:overhead metrics) (:target metrics))) 0.5)
                             "STABLE"
                             (if (> (:overhead metrics) (:target metrics))
                               "REDUCING"
                               "INCREASING"))))

          ;; Wait for next interval
          (Thread/sleep ADAPTATION_INTERVAL_MS)

          ;; Continue loop
          (recur new-state (inc iteration)))))))

;; ============================================================================
;; Visualization
;; ============================================================================

(defn plot-adaptation-history
  "Display adaptation history"
  [history]
  (println "\n=== Sampling Rate Adaptation History ===")
  (println "TIME        RATE   OVERHEAD   EVENTS/SEC   STATUS")
  (println "=====================================================")

  (doseq [entry history]
    (let [status (cond
                   (< (Math/abs (- (:overhead entry) (:target entry))) 0.3) "STABLE"
                   (> (:overhead entry) (:target entry)) "HIGH"
                   :else "LOW")]
      (println (format "%s  %3d%%   %5.2f%%     %6d      %s"
                       (:time entry)
                       (:sample-rate entry)
                       (:overhead entry)
                       (:event-rate entry)
                       status)))))

(defn plot-ascii-graph
  "Plot ASCII graph of sample rate over time"
  [history]
  (println "\n=== Sample Rate Over Time ===")
  (println "100% |")

  ;; Plot each row
  (doseq [threshold (range 100 0 -10)]
    (print (format "%3d%% |" threshold))
    (doseq [entry history]
      (print (if (>= (:sample-rate entry) threshold) "*" " ")))
    (println))

  (println "     +" (apply str (repeat (count history) "-")))
  (println "      Time ->"))

;; ============================================================================
;; Load Scenario Simulation
;; ============================================================================

(defn simulate-load-scenario
  "Simulate specific load scenario"
  [scenario]
  (println (format "\n=== Simulating Load Scenario: %s ===" (:name scenario)))

  (let [controller (atom (create-controller 50))
        history (atom [])]

    (doseq [phase (:phases scenario)]
      (println (format "\nPhase: %s (duration: %ds)" (:name phase) (:duration phase)))

      (dotimes [_ (:duration phase)]
        (let [event-rate (generate-event-burst (:rate phase) (:variance phase))
              current-overhead (estimate-overhead event-rate (:current-rate @controller))
              result (calculate-new-sample-rate @controller current-overhead TARGET_OVERHEAD_PERCENT)]

          (reset! controller (:controller result))

          (swap! history conj {:rate (:current-rate @controller)
                               :overhead current-overhead
                               :events event-rate})

          (println (format "  Events: %6d, Rate: %3d%%, Overhead: %.2f%%"
                           event-rate
                           (:current-rate @controller)
                           current-overhead))

          (Thread/sleep 100))))

    @history))

(def spike-scenario
  "Traffic spike scenario"
  {:name "Traffic Spike"
   :phases [{:name "Baseline" :rate 10000 :variance 1000 :duration 5}
            {:name "Spike" :rate 200000 :variance 30000 :duration 5}
            {:name "Recovery" :rate 10000 :variance 1000 :duration 5}]})

(def gradual-increase-scenario
  "Gradual traffic increase"
  {:name "Gradual Increase"
   :phases [{:name "Low" :rate 5000 :variance 500 :duration 3}
            {:name "Medium" :rate 50000 :variance 5000 :duration 3}
            {:name "High" :rate 150000 :variance 15000 :duration 3}
            {:name "Very High" :rate 300000 :variance 30000 :duration 3}]})

;; ============================================================================
;; Stratified Sampling
;; ============================================================================

(defn stratified-sample-rate
  "Calculate sample rate based on event importance"
  [event base-rate]
  (let [importance (cond
                     ;; High importance events (always sample)
                     (= (:type event) :error) 100

                     ;; Medium importance (higher sample rate)
                     (= (:type event) :warning) (min 100 (* base-rate 2))

                     ;; Security events (always sample)
                     (:security event) 100

                     ;; Normal events (base rate)
                     :else base-rate)]
    importance))

(defn stratified-sample
  "Sample with stratification"
  [events base-rate]
  (let [results (atom {:high 0 :medium 0 :low 0 :sampled []})]
    (doseq [event events]
      (let [event-rate (stratified-sample-rate event base-rate)
            sampled? (should-sample? event-rate)]
        (when sampled?
          (swap! results update :sampled conj event))
        (cond
          (>= event-rate 90) (swap! results update :high inc)
          (>= event-rate 50) (swap! results update :medium inc)
          :else (swap! results update :low inc))))
    @results))

;; ============================================================================
;; Multi-Target Adaptation
;; ============================================================================

(defrecord ProgramTarget
  [program-name
   target-overhead
   current-rate
   priority])  ; Higher priority programs get more overhead budget

(defn multi-program-adaptation
  "Adapt multiple programs with shared overhead budget"
  [programs total-budget]
  (let [total-priority (reduce + (map :priority programs))
        allocations (for [prog programs]
                      (let [budget-share (* total-budget (/ (:priority prog) total-priority))]
                        (assoc prog :budget-share budget-share)))]
    (println "\n=== Multi-Program Overhead Allocation ===")
    (println "PROGRAM          PRIORITY   BUDGET   CURRENT")
    (println "================================================")
    (doseq [prog allocations]
      (println (format "%-16s %8d   %5.2f%%   %5.2f%%"
                       (:program-name prog)
                       (:priority prog)
                       (:budget-share prog)
                       (:current-rate prog))))
    allocations))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the adaptive sampling lab"
  [& args]
  (let [command (first args)]
    (case command
      "run"
      (let [duration (or (some-> (second args) Integer/parseInt) 30)]
        (let [final-state (run-adaptive-loop duration)]
          (plot-adaptation-history (:history final-state))
          (plot-ascii-graph (:history final-state))))

      "spike"
      (simulate-load-scenario spike-scenario)

      "gradual"
      (simulate-load-scenario gradual-increase-scenario)

      "multi"
      (multi-program-adaptation
       [{:program-name "network-monitor" :priority 3 :current-rate 2.5}
        {:program-name "syscall-tracer" :priority 2 :current-rate 1.5}
        {:program-name "security-audit" :priority 5 :current-rate 3.0}
        {:program-name "performance-profiler" :priority 1 :current-rate 0.5}]
       5.0) ; Total 5% overhead budget

      ;; Default: quick demo
      (do
        (println "Lab 12.3: Adaptive Sampling System")
        (println "===================================")
        (println "\nUsage:")
        (println "  run [duration-sec]   - Run adaptive control loop")
        (println "  spike               - Simulate traffic spike scenario")
        (println "  gradual             - Simulate gradual increase scenario")
        (println "  multi               - Demo multi-program adaptation")
        (println)

        ;; Quick demonstration
        (println "=== Quick Demonstration ===")
        (println "\nAdaptive sampling adjusts rate to maintain target overhead:")
        (println "- Low load: High sample rate (more data, still under budget)")
        (println "- High load: Low sample rate (less data, stay under budget)")
        (println)

        ;; Show one scenario
        (simulate-load-scenario spike-scenario)

        (println "\n=== Key Takeaways ===")
        (println "1. Feedback control maintains target overhead")
        (println "2. PI controller provides stable adaptation")
        (println "3. Probabilistic sampling preserves data distribution")
        (println "4. Essential for production observability systems")))))

;; Run with: clj -M -m lab-12-3-adaptive-sampling
;; Or:       clj -M -m lab-12-3-adaptive-sampling run 60
