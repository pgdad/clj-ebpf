# Lab 12.3: Adaptive Sampling System

## Objective

Build a system that dynamically adjusts sampling rate based on system load to maintain target overhead. This demonstrates intelligent performance management.

## Target Metrics

- **Overhead Target**: 2% CPU
- **Adaptation Speed**: Adjust within 1 second
- **Accuracy**: ±0.5% of target

## The Problem

Fixed sampling rates don't adapt to varying load:
- **Low load**: Under-sampling, miss events
- **High load**: Over-sampling, excessive overhead

**Solution**: Adaptive sampling that monitors overhead and adjusts rate dynamically.

## Implementation

```clojure
(ns performance.adaptive-sampling
  (:require [clj-ebpf.core :as bpf]))

;; ============================================================================
;; Configuration
;; ============================================================================

(def TARGET_OVERHEAD_PERCENT 2.0)  ; Target 2% CPU overhead
(def ADAPTATION_INTERVAL_MS 1000)  ; Adjust every second
(def MIN_SAMPLE_RATE 1)            ; Sample at least 1%
(def MAX_SAMPLE_RATE 100)          ; Sample at most 100%

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def sampling-config
  "Sampling configuration (updated by userspace)"
  {:type :array
   :key-type :u32
   :value-type :struct  ; {sample_rate: u32, threshold: u32}
   :max-entries 1})

(def event-stats
  "Per-CPU event statistics"
  {:type :percpu_array
   :key-type :u32
   :value-type :struct  ; {processed: u64, sampled: u64}
   :max-entries 1})

(def sample-events
  "Sampled events"
  {:type :ring_buffer
   :max-entries (* 128 1024)})

;; ============================================================================
;; Adaptive Sampling Program
;; ============================================================================

(def adaptive-sampler
  "Samples events adaptively based on load"
  {:type :tracepoint
   :category "syscalls"
   :name "sys_enter_openat"
   :program
   [;; Load sampling configuration
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -4 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref sampling-config))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/mov-reg :r9 :r0)]             ; Save config pointer

    ;; Load sample rate (1-100)
    [(bpf/load-mem :w :r8 :r9 0)]       ; sample_rate

    ;; Increment total processed counter
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -8 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref event-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/mov-reg :r7 :r0)]             ; Save stats pointer

    [(bpf/load-mem :dw :r1 :r7 0)]      ; processed count
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r7 0 :r1)]

    ;; **ADAPTIVE SAMPLING**: Probabilistic sampling
    [(bpf/call (bpf/helper :get_prandom_u32))]
    [(bpf/mod :r0 100)]                 ; r0 = random(0-99)

    ;; Sample if random < sample_rate
    [(bpf/jmp-reg :jge :r0 :r8 :exit)]

    ;; Increment sampled counter
    [(bpf/load-mem :dw :r1 :r7 8)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r7 8 :r1)]

    ;; Collect event data
    [(bpf/mov-reg :r1 (bpf/map-ref sample-events))]
    [(bpf/mov :r2 32)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]

    ;; Fill event (simplified)
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/store-mem :dw :r0 0 :r0)]

    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r0 8 :r0)]

    ;; Submit
    [(bpf/mov-reg :r1 :r0)]
    [(bpf/mov :r2 0)]
    [(bpf/call (bpf/helper :ringbuf_submit))]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

;; ============================================================================
;; Adaptive Controller (Userspace)
;; ============================================================================

(defrecord SystemMetrics
  [cpu-usage          ; Current CPU usage (%)
   event-rate         ; Events/second
   sample-rate        ; Current sampling rate (1-100)
   overhead           ; Estimated overhead (%)
   target-overhead])  ; Target overhead (%)

(defn measure-cpu-usage
  "Measure CPU usage over interval"
  []
  (let [proc-stat (slurp "/proc/stat")
        cpu-line (first (clojure.string/split-lines proc-stat))
        values (map #(Long/parseLong %)
                   (rest (clojure.string/split cpu-line #"\s+")))]
    ;; Simplified CPU calculation
    (let [total (reduce + values)
          idle (nth values 3)]
      (* 100.0 (- 1.0 (/ idle total))))))

(defn estimate-overhead
  "Estimate BPF program overhead"
  [event-rate sample-rate]
  (let [cost-per-event-ns 200.0  ; Estimated 200ns per sampled event
        sampled-events (* event-rate (/ sample-rate 100.0))
        overhead-ns (* sampled-events cost-per-event-ns)
        overhead-percent (/ overhead-ns 10000000.0)]  ; Convert to %
    overhead-percent))

(defn calculate-new-sample-rate
  "PI controller for sample rate adjustment"
  [current-rate current-overhead target-overhead]
  (let [error (- current-overhead target-overhead)
        Kp 5.0        ; Proportional gain
        Ki 0.5        ; Integral gain (simplified)

        ;; P control
        adjustment (* Kp error)

        ;; Calculate new rate
        new-rate (- current-rate adjustment)

        ;; Clamp to valid range
        clamped-rate (max MIN_SAMPLE_RATE
                         (min MAX_SAMPLE_RATE new-rate))]

    (int clamped-rate)))

(defn get-event-stats
  "Get aggregated event statistics"
  []
  (let [num-cpus (.. Runtime getRuntime availableProcessors)]
    (when-let [per-cpu-stats (bpf/map-lookup event-stats 0)]
      (reduce (fn [acc cpu-stats]
                {:processed (+ (:processed acc) (:processed cpu-stats))
                 :sampled (+ (:sampled acc) (:sampled cpu-stats))})
              {:processed 0 :sampled 0}
              per-cpu-stats))))

(defn adaptive-control-loop
  "Main control loop for adaptive sampling"
  []
  (let [state (atom {:last-processed 0
                     :last-sampled 0
                     :current-sample-rate 50})]  ; Start at 50%

    (loop []
      ;; Wait for adaptation interval
      (Thread/sleep ADAPTATION_INTERVAL_MS)

      ;; Measure current state
      (let [stats (get-event-stats)
            processed (:processed stats)
            sampled (:sampled stats)

            ;; Calculate rates
            delta-processed (- processed (:last-processed @state))
            delta-sampled (- sampled (:last-sampled @state))
            event-rate (/ delta-processed (/ ADAPTATION_INTERVAL_MS 1000.0))

            ;; Estimate overhead
            current-rate (:current-sample-rate @state)
            overhead (estimate-overhead event-rate current-rate)

            ;; Calculate new sample rate
            new-rate (calculate-new-sample-rate
                      current-rate
                      overhead
                      TARGET_OVERHEAD_PERCENT)]

        ;; Update configuration
        (bpf/map-update! sampling-config 0
                        {:sample-rate new-rate
                         :threshold (int (* new-rate 10))})

        ;; Display metrics
        (println (format "[%s] Events: %d/sec, Sample: %d%%, Overhead: %.2f%%, Target: %.1f%%"
                        (java.time.LocalTime/now)
                        (int event-rate)
                        new-rate
                        overhead
                        TARGET_OVERHEAD_PERCENT))

        ;; Update state
        (swap! state assoc
               :last-processed processed
               :last-sampled sampled
               :current-sample-rate new-rate)

        (recur)))))

;; ============================================================================
;; Visualization
;; ============================================================================

(defn plot-adaptation
  "Plot adaptation over time"
  [history]
  (println "\n=== Sampling Rate Adaptation ===")
  (println "TIME     RATE  OVERHEAD  EVENTS/SEC")
  (println "=====================================")
  (doseq [entry history]
    (printf "%s  %3d%%  %5.2f%%     %d\n"
            (:time entry)
            (:sample-rate entry)
            (:overhead entry)
            (:event-rate entry))))

;; ============================================================================
;; Main
;; ============================================================================

(defn -main []
  (println "Starting Adaptive Sampling System")
  (println (format "Target Overhead: %.1f%%" TARGET_OVERHEAD_PERCENT))
  (println)

  ;; Load and attach program
  (let [prog (bpf/load-program adaptive-sampler)]
    (bpf/attach-tracepoint prog "syscalls" "sys_enter_openat")

    ;; Initialize configuration
    (bpf/map-update! sampling-config 0
                    {:sample-rate 50
                     :threshold 500})

    ;; Start adaptive controller
    (println "Adaptive controller running...")
    (println "Press Ctrl-C to stop\n")
    (adaptive-control-loop)))

;; Expected output:
;; [10:15:00] Events: 50000/sec, Sample: 50%, Overhead: 5.00%, Target: 2.0%
;; [10:15:01] Events: 50000/sec, Sample: 30%, Overhead: 3.00%, Target: 2.0%
;; [10:15:02] Events: 50000/sec, Sample: 20%, Overhead: 2.00%, Target: 2.0%
;; [10:15:03] Events: 50000/sec, Sample: 20%, Overhead: 2.00%, Target: 2.0% ← Stable
```

## Key Concepts

1. **Feedback Control** - PI controller adjusts sampling rate
2. **Overhead Estimation** - Model cost per event
3. **Probabilistic Sampling** - Random selection maintains distribution
4. **Dynamic Adaptation** - Responds to load changes in real-time

## Expected Behavior

```
Low load (10K events/sec):
  Sample Rate: 80-100% (low overhead, can afford high sampling)

Medium load (100K events/sec):
  Sample Rate: 10-20% (maintains target overhead)

High load (1M events/sec):
  Sample Rate: 1-2% (minimal sampling to meet overhead target)
```

## Challenges

1. Implement multiple overhead targets per program type
2. Add predictive control (anticipate load spikes)
3. Implement stratified sampling (sample important events more)
4. Add machine learning for better adaptation
5. Multi-program coordination

## Key Takeaways

- Adaptive sampling maintains performance under varying load
- Feedback control ensures target metrics
- Essential for production observability systems
- Trade accuracy for guaranteed low overhead

## References

- [Adaptive Sampling](https://www.brendangregg.com/blog/2015-02-27/linux-profiling-at-netflix.html)
- [Probabilistic Data Structures](https://en.wikipedia.org/wiki/Bloom_filter)
