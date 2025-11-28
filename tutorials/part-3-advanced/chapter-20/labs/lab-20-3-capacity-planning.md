# Lab 20.3: Capacity Planning

**Duration**: 45 minutes | **Difficulty**: Advanced

## Objective

Learn to size and plan BPF deployments for production workloads.

## Part 1: Resource Estimation

```clojure
(ns lab-20-3.capacity-planning)

(defn estimate-map-size [entries entry-size]
  "Estimate memory for BPF map"
  (let [overhead-per-entry 64  ; Hash bucket overhead
        total-per-entry (+ entry-size overhead-per-entry)]
    {:entries entries
     :memory-bytes (* entries total-per-entry)
     :memory-mb (/ (* entries total-per-entry) 1024 1024)}))

(defn estimate-ringbuf-size [events-per-sec event-size buffer-seconds]
  "Estimate ring buffer size"
  (let [total-events (* events-per-sec buffer-seconds)
        total-bytes (* total-events event-size)
        with-overhead (* total-bytes 1.2)]  ; 20% overhead
    {:events-per-sec events-per-sec
     :buffer-seconds buffer-seconds
     :recommended-size (next-power-of-2 with-overhead)}))
```

## Part 2: Load Testing

```clojure
(defn run-load-test [target-rate duration-sec]
  "Run load test to determine capacity"
  (let [results (atom {:processed 0 :dropped 0 :errors 0})
        start-time (System/currentTimeMillis)]

    ;; Generate load
    (dotimes [_ (* target-rate duration-sec)]
      (let [result (process-test-event)]
        (swap! results update (if (:success result) :processed :errors) inc)))

    (let [elapsed (- (System/currentTimeMillis) start-time)]
      {:target-rate target-rate
       :actual-rate (/ (:processed @results) (/ elapsed 1000))
       :drop-rate (/ (:dropped @results) (:processed @results))
       :error-rate (/ (:errors @results) (:processed @results))})))

(defn find-max-capacity []
  "Binary search for maximum sustainable rate"
  (loop [low 1000 high 10000000]
    (if (< (- high low) 1000)
      low
      (let [mid (/ (+ low high) 2)
            result (run-load-test mid 10)]
        (if (< (:drop-rate result) 0.001)
          (recur mid high)
          (recur low mid))))))
```

## Part 3: Capacity Report

```clojure
(defn generate-capacity-report [workload]
  {:workload workload
   :recommendations
   {:map-sizes (estimate-all-maps workload)
    :ring-buffer (estimate-ringbuf-size (:events-per-sec workload)
                                        (:avg-event-size workload)
                                        5)
    :cpu-cores (estimate-cpu-needs workload)
    :memory-mb (estimate-total-memory workload)}
   :scaling-factors
   {:events-growth 1.5
    :connections-growth 2.0}})
```

## Summary

This lab covers capacity planning:
- Resource estimation formulas
- Load testing methodology
- Capacity reporting
- Growth planning
