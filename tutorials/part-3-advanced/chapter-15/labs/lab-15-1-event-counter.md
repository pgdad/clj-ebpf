# Lab 15.1: Event Counter Dashboard

**Duration**: 45-60 minutes | **Difficulty**: Intermediate

## Objective

Build a real-time event counter dashboard that demonstrates:
- Using `map-entry-ref` for atom-like counter access
- Using `map-watch-changes` to detect value changes
- Combining multiple reference types for a complete solution

## Prerequisites

- Completed Chapter 15 reading
- Understanding of BPF maps
- Familiarity with Clojure atoms

## Scenario

You're building a system monitoring tool that tracks various kernel events (syscalls, network packets, file operations) and displays real-time statistics. The BPF program updates counters, and your userspace code needs to display them efficiently.

---

## Part 1: Setting Up the Infrastructure

### Step 1.1: Create the Statistics Map

```clojure
(ns lab-15-1.event-counter
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.refs :as refs]))

;; Statistics map with pre-defined keys
;; Key: 4-byte integer (event type)
;; Value: 8-byte integer (counter)
(def stats-map
  (bpf/create-hash-map
    {:key-size 4
     :value-size 8
     :max-entries 16
     :key-serializer bpf/int->bytes
     :key-deserializer bpf/bytes->int
     :value-serializer bpf/long->bytes
     :value-deserializer bpf/bytes->long}))

;; Event type constants
(def EVENT-SYSCALL 1)
(def EVENT-PACKET 2)
(def EVENT-FILE-OPEN 3)
(def EVENT-FILE-CLOSE 4)
```

### Step 1.2: Initialize Counters

```clojure
(defn init-counters! []
  "Initialize all counters to zero"
  (doseq [event-type [EVENT-SYSCALL EVENT-PACKET EVENT-FILE-OPEN EVENT-FILE-CLOSE]]
    (bpf/map-update stats-map event-type 0)))
```

---

## Part 2: Using map-entry-ref for Counter Access

### Step 2.1: Create Counter References

```clojure
(defn create-counter-refs []
  "Create atom-like references to each counter"
  {:syscalls (bpf/map-entry-ref stats-map EVENT-SYSCALL)
   :packets (bpf/map-entry-ref stats-map EVENT-PACKET)
   :file-opens (bpf/map-entry-ref stats-map EVENT-FILE-OPEN)
   :file-closes (bpf/map-entry-ref stats-map EVENT-FILE-CLOSE)})

(defn close-counter-refs [refs]
  "Clean up all counter references"
  (doseq [[_ ref] refs]
    (.close ref)))
```

### Step 2.2: Read and Modify Counters

```clojure
(defn display-counters [refs]
  "Display current counter values"
  (println "\n=== Event Statistics ===")
  (println "Syscalls:    " @(:syscalls refs))
  (println "Packets:     " @(:packets refs))
  (println "File Opens:  " @(:file-opens refs))
  (println "File Closes: " @(:file-closes refs))
  (println "========================\n"))

(defn reset-all-counters! [refs]
  "Reset all counters to zero"
  (doseq [[name ref] refs]
    (reset! ref 0)
    (println "Reset" name "counter")))

(defn increment-counter! [refs counter-key]
  "Increment a specific counter"
  (swap! (get refs counter-key) inc))
```

---

## Part 3: Watching for Counter Changes

### Step 3.1: Single Counter Watcher

```clojure
(defn watch-counter-changes [counter-key duration-ms]
  "Watch a counter for changes and report each change"
  (let [event-type (case counter-key
                     :syscalls EVENT-SYSCALL
                     :packets EVENT-PACKET
                     :file-opens EVENT-FILE-OPEN
                     :file-closes EVENT-FILE-CLOSE)
        watcher (bpf/map-watch-changes stats-map event-type)]
    (try
      (let [start-time (System/currentTimeMillis)]
        (loop [change-count 0]
          (let [elapsed (- (System/currentTimeMillis) start-time)]
            (when (< elapsed duration-ms)
              (let [remaining (- duration-ms elapsed)
                    new-value (deref watcher remaining :timeout)]
                (when-not (= new-value :timeout)
                  (println (format "[%s] Counter changed to: %d"
                                   (name counter-key) new-value))
                  (recur (inc change-count))))))))
      (finally
        (.close watcher)))))
```

### Step 3.2: Multi-Counter Dashboard

```clojure
(defn start-dashboard [refs update-interval-ms]
  "Start a dashboard that polls all counters periodically"
  (let [running (atom true)]
    (future
      (while @running
        (display-counters refs)
        (Thread/sleep update-interval-ms)))
    ;; Return control function
    (fn [] (reset! running false))))

(defn start-change-watcher [refs counter-key]
  "Start a background watcher for a specific counter"
  (let [running (atom true)
        event-type (case counter-key
                     :syscalls EVENT-SYSCALL
                     :packets EVENT-PACKET
                     :file-opens EVENT-FILE-OPEN
                     :file-closes EVENT-FILE-CLOSE)
        watcher (bpf/map-watch-changes stats-map event-type)]
    (future
      (try
        (while @running
          (let [new-value (deref watcher 1000 :timeout)]
            (when-not (= new-value :timeout)
              (println (format ">>> %s changed: %d"
                               (name counter-key) new-value)))))
        (finally
          (.close watcher))))
    ;; Return control function
    (fn [] (reset! running false))))
```

---

## Part 4: Complete Dashboard Application

### Step 4.1: Main Application

```clojure
(defn run-dashboard []
  "Run the complete event counter dashboard"
  (println "Initializing Event Counter Dashboard...")

  ;; Initialize
  (init-counters!)
  (let [refs (create-counter-refs)]
    (try
      ;; Start dashboard display
      (let [stop-dashboard (start-dashboard refs 2000)

            ;; Start change watchers for each counter
            stop-syscall-watcher (start-change-watcher refs :syscalls)
            stop-packet-watcher (start-change-watcher refs :packets)]

        (println "\nDashboard running. Commands:")
        (println "  (increment! :syscalls)  - Increment syscall counter")
        (println "  (increment! :packets)   - Increment packet counter")
        (println "  (reset-all!)            - Reset all counters")
        (println "  (stop!)                 - Stop dashboard")

        ;; Simulate some events (in real use, BPF program would do this)
        (Thread/sleep 1000)
        (dotimes [_ 5]
          (swap! (:syscalls refs) inc)
          (Thread/sleep 200))

        (dotimes [_ 3]
          (swap! (:packets refs) + 10)
          (Thread/sleep 300))

        ;; Let dashboard run
        (Thread/sleep 5000)

        ;; Cleanup
        (stop-dashboard)
        (stop-syscall-watcher)
        (stop-packet-watcher))

      (finally
        (close-counter-refs refs)))))
```

---

## Part 5: Exercises

### Exercise 1: Rate Calculator

Add a rate calculator that shows events per second:

```clojure
(defn calculate-rate [refs counter-key sample-duration-ms]
  "Calculate events per second for a counter"
  ;; TODO: Implement
  ;; 1. Read initial value
  ;; 2. Wait for sample-duration-ms
  ;; 3. Read final value
  ;; 4. Calculate rate
  )
```

### Exercise 2: Threshold Alerts

Implement alerts when counters exceed thresholds:

```clojure
(defn watch-with-threshold [refs counter-key threshold alert-fn]
  "Watch a counter and call alert-fn when it exceeds threshold"
  ;; TODO: Implement using map-watch-changes
  ;; Alert when value > threshold
  )
```

### Exercise 3: Rolling Average

Track a rolling average of counter changes:

```clojure
(defn track-rolling-average [refs counter-key window-size]
  "Track rolling average of counter increments"
  ;; TODO: Implement
  ;; Keep last N deltas and compute average
  )
```

---

## Part 6: Testing Your Implementation

### Test Script

```clojure
(defn test-counter-refs []
  (println "Testing map-entry-ref functionality...")

  (init-counters!)
  (let [refs (create-counter-refs)]
    (try
      ;; Test read
      (assert (= 0 @(:syscalls refs)) "Initial value should be 0")

      ;; Test reset!
      (reset! (:syscalls refs) 100)
      (assert (= 100 @(:syscalls refs)) "Value should be 100 after reset!")

      ;; Test swap!
      (swap! (:syscalls refs) inc)
      (assert (= 101 @(:syscalls refs)) "Value should be 101 after inc")

      (swap! (:syscalls refs) + 10)
      (assert (= 111 @(:syscalls refs)) "Value should be 111 after +10")

      ;; Test compare-and-set!
      (assert (compare-and-set! (:syscalls refs) 111 200)
              "CAS should succeed")
      (assert (not (compare-and-set! (:syscalls refs) 111 300))
              "CAS should fail with wrong expected value")

      (println "All tests passed!")

      (finally
        (close-counter-refs refs)))))

(test-counter-refs)
```

---

## Summary

In this lab you learned:
- How to create `map-entry-ref` for atom-like access to BPF map entries
- Using `@`, `reset!`, `swap!`, and `compare-and-set!` with BPF maps
- Watching for value changes with `map-watch-changes`
- Building a real-time dashboard with multiple reference types
- Proper resource management with reference cleanup

## Next Steps

- Try Lab 15.2 to learn about producer-consumer patterns with queue channels
- Explore combining reference types with actual BPF programs
