# Lab 16.2: Per-CPU Counter System

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Build a high-performance counter system using per-CPU data structures that eliminates lock contention and scales linearly with CPU count.

## Prerequisites

- Completed Lab 16.1
- Understanding of per-CPU data structures
- Familiarity with concurrent programming

## Scenario

You're building a high-throughput packet processing system that needs to count events at rates exceeding 10 million events per second. Regular counters with locks become a bottleneck. This lab shows how per-CPU structures solve this problem.

---

## Part 1: Understanding the Problem

### Step 1.1: Contention with Shared Counters

```clojure
(ns lab-16-2.percpu-counters
  (:require [clojure.core.async :as async])
  (:import [java.util.concurrent.atomic AtomicLong AtomicLongArray]
           [java.util.concurrent CountDownLatch]))

;; Simulate shared counter with contention
(defn benchmark-shared-counter [num-threads iterations-per-thread]
  (let [counter (AtomicLong. 0)
        latch (CountDownLatch. num-threads)
        start-time (atom nil)]

    ;; Launch threads
    (dotimes [_ num-threads]
      (async/thread
        (.await latch)
        (dotimes [_ iterations-per-thread]
          (.incrementAndGet counter))))

    ;; Start all threads simultaneously
    (reset! start-time (System/nanoTime))
    (.countDown latch)

    ;; Wait for completion (simplified)
    (Thread/sleep 2000)

    (let [elapsed-ns (- (System/nanoTime) @start-time)
          total-ops (* num-threads iterations-per-thread)
          ops-per-sec (/ (* total-ops 1e9) elapsed-ns)]

      {:threads num-threads
       :total-ops total-ops
       :elapsed-ms (/ elapsed-ns 1e6)
       :ops-per-sec ops-per-sec
       :final-count (.get counter)})))

(defn demonstrate-contention []
  (println "\n=== Shared Counter Contention ===\n")
  (println (format "%-10s %15s %15s" "Threads" "Ops/sec" "Scaling"))
  (println (apply str (repeat 45 "-")))

  (let [baseline (benchmark-shared-counter 1 1000000)]
    (doseq [threads [1 2 4 8]]
      (let [result (benchmark-shared-counter threads 1000000)
            scaling (/ (:ops-per-sec result)
                       (:ops-per-sec baseline))]
        (println (format "%-10d %15.0f %15.2fx"
                         threads
                         (:ops-per-sec result)
                         scaling))))))
```

### Step 1.2: The Per-CPU Solution

```clojure
;; Per-CPU counter eliminates contention
(defrecord PerCPUCounter [^AtomicLongArray cpu-counters num-cpus]
  clojure.lang.IDeref
  (deref [_]
    (reduce + (for [i (range num-cpus)]
                (.get cpu-counters i)))))

(defn create-percpu-counter [num-cpus]
  (->PerCPUCounter (AtomicLongArray. num-cpus) num-cpus))

(defn increment-percpu!
  "Increment the counter for a specific CPU"
  [^PerCPUCounter counter cpu-id]
  (.incrementAndGet ^AtomicLongArray (:cpu-counters counter) cpu-id))

(defn get-percpu-value
  "Get counter value for a specific CPU"
  [^PerCPUCounter counter cpu-id]
  (.get ^AtomicLongArray (:cpu-counters counter) cpu-id))

(defn get-total
  "Sum all per-CPU values"
  [^PerCPUCounter counter]
  @counter)
```

---

## Part 2: Implementing Per-CPU Counters

### Step 2.1: Basic Per-CPU Counter

```clojure
(defn benchmark-percpu-counter [num-cpus iterations-per-cpu]
  (let [counter (create-percpu-counter num-cpus)
        latch (CountDownLatch. num-cpus)
        start-time (atom nil)]

    ;; Each "CPU" updates its own counter
    (dotimes [cpu-id num-cpus]
      (async/thread
        (.await latch)
        (dotimes [_ iterations-per-cpu]
          (increment-percpu! counter cpu-id))))

    (reset! start-time (System/nanoTime))
    (dotimes [_ num-cpus] (.countDown latch))

    (Thread/sleep 2000)

    (let [elapsed-ns (- (System/nanoTime) @start-time)
          total-ops (* num-cpus iterations-per-cpu)
          ops-per-sec (/ (* total-ops 1e9) elapsed-ns)]

      {:cpus num-cpus
       :total-ops total-ops
       :elapsed-ms (/ elapsed-ns 1e6)
       :ops-per-sec ops-per-sec
       :final-count (get-total counter)})))

(defn demonstrate-percpu []
  (println "\n=== Per-CPU Counter (No Contention) ===\n")
  (println (format "%-10s %15s %15s" "CPUs" "Ops/sec" "Scaling"))
  (println (apply str (repeat 45 "-")))

  (let [baseline (benchmark-percpu-counter 1 1000000)]
    (doseq [cpus [1 2 4 8]]
      (let [result (benchmark-percpu-counter cpus 1000000)
            scaling (/ (:ops-per-sec result)
                       (:ops-per-sec baseline))]
        (println (format "%-10d %15.0f %15.2fx"
                         cpus
                         (:ops-per-sec result)
                         scaling))))))
```

### Step 2.2: Per-CPU Statistics Struct

```clojure
(defrecord CPUStats [packets bytes errors dropped])

(defrecord PerCPUStats [stats-array num-cpus]
  clojure.lang.IDeref
  (deref [_]
    (reduce
      (fn [acc cpu-id]
        (let [stats (aget stats-array cpu-id)]
          {:packets (+ (:packets acc) (:packets @stats))
           :bytes (+ (:bytes acc) (:bytes @stats))
           :errors (+ (:errors acc) (:errors @stats))
           :dropped (+ (:dropped acc) (:dropped @stats))}))
      {:packets 0 :bytes 0 :errors 0 :dropped 0}
      (range num-cpus))))

(defn create-percpu-stats [num-cpus]
  (let [stats-array (object-array num-cpus)]
    (dotimes [i num-cpus]
      (aset stats-array i (atom (->CPUStats 0 0 0 0))))
    (->PerCPUStats stats-array num-cpus)))

(defn update-stats!
  "Update statistics for a specific CPU"
  [percpu-stats cpu-id update-fn]
  (swap! (aget (:stats-array percpu-stats) cpu-id) update-fn))

(defn record-packet!
  "Record a packet on the specified CPU"
  [percpu-stats cpu-id packet-size]
  (update-stats! percpu-stats cpu-id
    (fn [stats]
      (-> stats
          (update :packets inc)
          (update :bytes + packet-size)))))

(defn record-error!
  "Record an error on the specified CPU"
  [percpu-stats cpu-id]
  (update-stats! percpu-stats cpu-id
    (fn [stats]
      (update stats :errors inc))))
```

---

## Part 3: Multi-Counter Dashboard

### Step 3.1: Event Type Counters

```clojure
(def EVENT-TYPES [:tcp :udp :icmp :other])

(defn create-event-counters [num-cpus]
  (into {}
    (for [event-type EVENT-TYPES]
      [event-type (create-percpu-counter num-cpus)])))

(defn increment-event! [counters event-type cpu-id]
  (when-let [counter (get counters event-type)]
    (increment-percpu! counter cpu-id)))

(defn get-event-totals [counters]
  (into {}
    (for [[event-type counter] counters]
      [event-type (get-total counter)])))

(defn display-event-dashboard [counters]
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
```

### Step 3.2: Rate Calculator

```clojure
(defn calculate-rate
  "Calculate events per second over a sample period"
  [counter sample-ms]
  (let [start-count (get-total counter)
        _ (Thread/sleep sample-ms)
        end-count (get-total counter)
        delta (- end-count start-count)]
    (/ (* delta 1000.0) sample-ms)))

(defn calculate-all-rates [counters sample-ms]
  (let [start-totals (get-event-totals counters)
        _ (Thread/sleep sample-ms)
        end-totals (get-event-totals counters)]
    (into {}
      (for [event-type EVENT-TYPES]
        (let [delta (- (get end-totals event-type 0)
                       (get start-totals event-type 0))]
          [event-type (/ (* delta 1000.0) sample-ms)])))))

(defn display-rate-dashboard [counters sample-ms]
  (println (format "\n=== Event Rates (sampled over %dms) ===" sample-ms))
  (println (format "%-12s %15s" "Event Type" "Rate/sec"))
  (println (apply str (repeat 30 "-")))
  (let [rates (calculate-all-rates counters sample-ms)]
    (doseq [event-type EVENT-TYPES]
      (println (format "%-12s %,15.1f"
                       (name event-type)
                       (get rates event-type 0.0))))))
```

---

## Part 4: Simulating High-Throughput Events

### Step 4.1: Event Generator

```clojure
(defn generate-events
  "Simulate events across multiple CPUs"
  [counters num-cpus events-per-cpu]
  (let [latch (CountDownLatch. num-cpus)]
    (dotimes [cpu-id num-cpus]
      (async/thread
        (dotimes [_ events-per-cpu]
          (let [event-type (rand-nth EVENT-TYPES)]
            (increment-event! counters event-type cpu-id)))
        (.countDown latch)))
    latch))

(defn run-simulation [num-cpus duration-ms target-rate]
  (let [counters (create-event-counters num-cpus)
        events-per-cpu (/ (* target-rate duration-ms) num-cpus 1000)
        running (atom true)]

    (println (format "\nSimulating %d events/sec across %d CPUs for %dms..."
                     target-rate num-cpus duration-ms))

    ;; Start generator
    (let [latch (generate-events counters num-cpus (int events-per-cpu))]

      ;; Monitor while running
      (dotimes [_ 3]
        (Thread/sleep 500)
        (display-event-dashboard counters))

      ;; Wait for completion
      (.await latch)

      (println "\n=== Final Results ===")
      (display-event-dashboard counters)

      counters)))
```

### Step 4.2: Throughput Test

```clojure
(defn throughput-test []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "     Per-CPU Counter Throughput Test")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (let [num-cpus 8
        iterations 10000000
        counters (create-event-counters num-cpus)
        start-time (System/nanoTime)]

    ;; Generate events
    (let [latch (generate-events counters num-cpus (/ iterations num-cpus))]
      (.await latch))

    (let [elapsed-ns (- (System/nanoTime) start-time)
          elapsed-ms (/ elapsed-ns 1e6)
          ops-per-sec (/ (* iterations 1e9) elapsed-ns)]

      (println (format "Total events: %,d" iterations))
      (println (format "Elapsed time: %.2f ms" elapsed-ms))
      (println (format "Throughput: %,.0f events/sec" ops-per-sec))

      (display-event-dashboard counters))))
```

---

## Part 5: Comparison with Shared Counter

### Step 5.1: Side-by-Side Benchmark

```clojure
(defn compare-implementations []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "     Shared vs Per-CPU Counter Comparison")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (let [iterations 1000000]
    (println (format "%-20s %10s %15s %10s"
                     "Implementation" "Threads" "Ops/sec" "Scaling"))
    (println (apply str (repeat 60 "-")))

    ;; Shared counter baseline
    (let [shared-1 (benchmark-shared-counter 1 iterations)]
      (doseq [threads [1 2 4 8]]
        (let [shared (benchmark-shared-counter threads (/ iterations threads))
              percpu (benchmark-percpu-counter threads (/ iterations threads))]

          (println (format "%-20s %10d %15,.0f %10.2fx"
                           "Shared"
                           threads
                           (:ops-per-sec shared)
                           (/ (:ops-per-sec shared) (:ops-per-sec shared-1))))

          (println (format "%-20s %10d %15,.0f %10.2fx"
                           "Per-CPU"
                           threads
                           (:ops-per-sec percpu)
                           (double threads)))
          (println))))))
```

---

## Part 6: Exercises

### Exercise 1: Per-CPU Hash Map

Implement a per-CPU hash map for flow tracking:

```clojure
(defn exercise-percpu-hash []
  ;; TODO: Implement per-CPU hash map
  ;; 1. Create per-CPU hash maps (one per CPU)
  ;; 2. Route updates to appropriate CPU's map
  ;; 3. Implement aggregation across CPUs
  ;; 4. Benchmark vs shared hash map
  )
```

### Exercise 2: Atomic Operations

Implement various atomic operations on per-CPU values:

```clojure
(defn exercise-atomic-ops []
  ;; TODO: Implement atomic operations
  ;; 1. Atomic add
  ;; 2. Atomic max (track maximum value seen)
  ;; 3. Atomic exchange
  ;; 4. Compare-and-swap
  )
```

### Exercise 3: Per-CPU Ring Buffer

Implement per-CPU ring buffers for event collection:

```clojure
(defn exercise-percpu-ringbuf []
  ;; TODO: Implement per-CPU ring buffer
  ;; 1. Create ring buffer per CPU
  ;; 2. Route events to local CPU's buffer
  ;; 3. Implement consumer that drains all buffers
  ;; 4. Compare throughput vs shared ring buffer
  )
```

---

## Part 7: Testing Your Implementation

### Test Script

```clojure
(defn test-percpu-counter []
  (println "Testing per-CPU counter...")
  (let [counter (create-percpu-counter 4)]
    ;; Test increments
    (doseq [cpu-id (range 4)]
      (dotimes [_ 100]
        (increment-percpu! counter cpu-id)))

    (assert (= 400 (get-total counter))
            "Total should be 400")

    ;; Test per-CPU values
    (doseq [cpu-id (range 4)]
      (assert (= 100 (get-percpu-value counter cpu-id))
              (format "CPU %d should have 100" cpu-id)))

    (println "All per-CPU counter tests passed!")))

(defn test-percpu-stats []
  (println "Testing per-CPU stats...")
  (let [stats (create-percpu-stats 4)]
    ;; Record packets on different CPUs
    (doseq [cpu-id (range 4)]
      (dotimes [_ 10]
        (record-packet! stats cpu-id 1500)))

    (let [totals @stats]
      (assert (= 40 (:packets totals))
              "Should have 40 packets total")
      (assert (= 60000 (:bytes totals))
              "Should have 60000 bytes total"))

    (println "All per-CPU stats tests passed!")))

(defn run-all-tests []
  (println "\nLab 16.2: Per-CPU Counter System")
  (println "=================================\n")

  (test-percpu-counter)
  (test-percpu-stats)

  (demonstrate-contention)
  (demonstrate-percpu)
  (compare-implementations)

  (println "\n=== Key Insights ===\n")
  (println "1. Shared counters suffer from cache line bouncing")
  (println "2. Per-CPU counters scale linearly with CPU count")
  (println "3. Aggregation has minimal overhead")
  (println "4. Use per-CPU for any high-frequency counter"))
```

---

## Summary

In this lab you learned:
- Why shared counters don't scale with CPU count
- How per-CPU data structures eliminate contention
- Implementation of per-CPU counters and statistics
- Building a real-time monitoring dashboard
- Performance comparison between shared and per-CPU approaches

## Next Steps

- Try Lab 16.3 to learn about batch operations
- Implement per-CPU structures in your BPF programs
- Profile existing counters for contention issues
