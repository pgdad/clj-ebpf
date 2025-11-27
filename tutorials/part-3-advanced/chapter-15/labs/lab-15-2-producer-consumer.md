# Lab 15.2: Producer-Consumer Pipeline

**Duration**: 60-90 minutes | **Difficulty**: Intermediate

## Objective

Build a multi-stage event processing pipeline using queue channels and reference types:
- BPF program produces events to a ring buffer
- Stage 1: Filter and categorize events
- Stage 2: Enrich events with additional data
- Stage 3: Aggregate and store results

## Prerequisites

- Completed Lab 15.1
- Understanding of producer-consumer patterns
- Familiarity with Clojure futures and concurrency

## Architecture

```
[BPF Program] --> [Ring Buffer] --> [Stage 1: Filter] --> [Queue 1]
                                                              |
                                                              v
[Stats Map] <-- [Stage 3: Aggregate] <-- [Queue 2] <-- [Stage 2: Enrich]
```

---

## Part 1: Infrastructure Setup

### Step 1.1: Create Data Structures

```clojure
(ns lab-15-2.pipeline
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.refs :as refs]))

;; Ring buffer for raw events from BPF
(def raw-events-rb
  (bpf/create-ringbuf-map {:max-entries (* 256 1024)}))

;; Queue between Stage 1 and Stage 2
(def filtered-queue
  (bpf/create-queue-map {:value-size 128 :max-entries 10000}))

;; Queue between Stage 2 and Stage 3
(def enriched-queue
  (bpf/create-queue-map {:value-size 256 :max-entries 10000}))

;; Statistics map for aggregated results
(def stats-map
  (bpf/create-hash-map {:key-size 32 :value-size 16 :max-entries 1000}))
```

### Step 1.2: Event Structures

```clojure
;; Raw event from BPF (simulated structure)
(defn parse-raw-event [bytes]
  {:timestamp (bpf/bytes->long bytes 0)
   :event-type (bpf/bytes->int bytes 8)
   :pid (bpf/bytes->int bytes 12)
   :data (bpf/bytes->string bytes 16 64)})

;; Serialization helpers
(defn serialize-filtered [event]
  (let [buf (byte-array 128)]
    (bpf/long->bytes! buf 0 (:timestamp event))
    (bpf/int->bytes! buf 8 (:event-type event))
    (bpf/int->bytes! buf 12 (:pid event))
    (bpf/int->bytes! buf 16 (:priority event))
    (bpf/string->bytes! buf 20 (:category event) 32)
    buf))

(defn deserialize-filtered [bytes]
  {:timestamp (bpf/bytes->long bytes 0)
   :event-type (bpf/bytes->int bytes 8)
   :pid (bpf/bytes->int bytes 12)
   :priority (bpf/bytes->int bytes 16)
   :category (bpf/bytes->string bytes 20 32)})

(defn serialize-enriched [event]
  (let [buf (byte-array 256)]
    (bpf/long->bytes! buf 0 (:timestamp event))
    (bpf/int->bytes! buf 8 (:event-type event))
    (bpf/int->bytes! buf 12 (:pid event))
    (bpf/int->bytes! buf 16 (:priority event))
    (bpf/string->bytes! buf 20 (:category event) 32)
    (bpf/string->bytes! buf 52 (:process-name event) 64)
    (bpf/string->bytes! buf 116 (:enriched-data event) 128)
    buf))

(defn deserialize-enriched [bytes]
  {:timestamp (bpf/bytes->long bytes 0)
   :event-type (bpf/bytes->int bytes 8)
   :pid (bpf/bytes->int bytes 12)
   :priority (bpf/bytes->int bytes 16)
   :category (bpf/bytes->string bytes 20 32)
   :process-name (bpf/bytes->string bytes 52 64)
   :enriched-data (bpf/bytes->string bytes 116 128)})
```

---

## Part 2: Pipeline Stages

### Step 2.1: Stage 1 - Filter and Categorize

```clojure
(def event-categories
  {1 "syscall"
   2 "network"
   3 "filesystem"
   4 "process"})

(defn categorize-event [event]
  (assoc event
         :category (get event-categories (:event-type event) "unknown")
         :priority (cond
                     (= (:event-type event) 4) 1  ; Process events high priority
                     (= (:event-type event) 2) 2  ; Network medium
                     :else 3)))                    ; Others low

(defn should-filter? [event]
  "Return true if event should be discarded"
  ;; Filter out low-priority events from certain PIDs
  (and (= (:priority event) 3)
       (< (:pid event) 100)))  ; System processes

(defn start-filter-stage [input-ref output-channel stats-ref]
  "Stage 1: Read from ring buffer, filter, categorize, output to queue"
  (let [running (atom true)
        processed (atom 0)
        filtered (atom 0)]
    (future
      (try
        (while @running
          (when-let [raw-event (deref input-ref 100 nil)]
            (swap! processed inc)
            (let [categorized (categorize-event raw-event)]
              (if (should-filter? categorized)
                (swap! filtered inc)
                (conj! output-channel (serialize-filtered categorized))))))
        (catch Exception e
          (println "Filter stage error:" (.getMessage e)))
        (finally
          (println (format "Filter stage stopped. Processed: %d, Filtered: %d"
                           @processed @filtered)))))
    ;; Return control and stats functions
    {:stop (fn [] (reset! running false))
     :stats (fn [] {:processed @processed :filtered @filtered})}))
```

### Step 2.2: Stage 2 - Enrich

```clojure
(defn lookup-process-name [pid]
  "Look up process name (simulated)"
  (get {1 "init" 2 "kthreadd" 1000 "myapp" 1001 "worker"}
       pid
       (str "process-" pid)))

(defn enrich-event [event]
  "Add process name and additional metadata"
  (assoc event
         :process-name (lookup-process-name (:pid event))
         :enriched-data (str "Enriched at " (System/currentTimeMillis))))

(defn start-enrich-stage [input-channel output-channel]
  "Stage 2: Read from queue, enrich, output to next queue"
  (let [running (atom true)
        processed (atom 0)]
    (future
      (try
        (while @running
          (when-let [filtered-bytes (deref input-channel 100 nil)]
            (swap! processed inc)
            (let [event (deserialize-filtered filtered-bytes)
                  enriched (enrich-event event)]
              (conj! output-channel (serialize-enriched enriched)))))
        (catch Exception e
          (println "Enrich stage error:" (.getMessage e)))
        (finally
          (println (format "Enrich stage stopped. Processed: %d" @processed)))))
    {:stop (fn [] (reset! running false))
     :stats (fn [] {:processed @processed})}))
```

### Step 2.3: Stage 3 - Aggregate

```clojure
(defn start-aggregate-stage [input-channel stats-refs]
  "Stage 3: Read enriched events, update statistics"
  (let [running (atom true)
        processed (atom 0)]
    (future
      (try
        (while @running
          (when-let [enriched-bytes (deref input-channel 100 nil)]
            (swap! processed inc)
            (let [event (deserialize-enriched enriched-bytes)
                  category (:category event)]
              ;; Update category counter
              (when-let [counter (get stats-refs (keyword category))]
                (swap! counter inc))
              ;; Update total counter
              (swap! (:total stats-refs) inc))))
        (catch Exception e
          (println "Aggregate stage error:" (.getMessage e)))
        (finally
          (println (format "Aggregate stage stopped. Processed: %d" @processed)))))
    {:stop (fn [] (reset! running false))
     :stats (fn [] {:processed @processed})}))
```

---

## Part 3: Pipeline Orchestration

### Step 3.1: Create Pipeline

```clojure
(defn create-stats-refs []
  "Create map-entry-refs for statistics"
  (let [init-counter (fn [key]
                       (bpf/map-update stats-map key 0)
                       (bpf/map-entry-ref stats-map key))]
    {:syscall (init-counter "syscall")
     :network (init-counter "network")
     :filesystem (init-counter "filesystem")
     :process (init-counter "process")
     :total (init-counter "total")}))

(defn close-stats-refs [refs]
  (doseq [[_ ref] refs]
    (.close ref)))

(defn start-pipeline []
  "Start the complete processing pipeline"
  (println "Starting event processing pipeline...")

  ;; Create references
  (let [raw-events (bpf/ringbuf-ref raw-events-rb :deserializer parse-raw-event)
        filter-output (bpf/queue-channel filtered-queue)
        enrich-output (bpf/queue-channel enriched-queue)
        stats-refs (create-stats-refs)]

    ;; Start stages
    (let [filter-stage (start-filter-stage raw-events filter-output stats-refs)
          enrich-stage (start-enrich-stage filter-output enrich-output)
          aggregate-stage (start-aggregate-stage enrich-output stats-refs)]

      (println "Pipeline started!")
      (println "Stages: Filter -> Enrich -> Aggregate")

      ;; Return control object
      {:stop (fn []
               (println "Stopping pipeline...")
               ((:stop filter-stage))
               ((:stop enrich-stage))
               ((:stop aggregate-stage))
               (Thread/sleep 500)
               (.close raw-events)
               (.close filter-output)
               (.close enrich-output)
               (close-stats-refs stats-refs)
               (println "Pipeline stopped."))

       :stats (fn []
                {:filter ((:stats filter-stage))
                 :enrich ((:stats enrich-stage))
                 :aggregate ((:stats aggregate-stage))
                 :counters {:syscall @(:syscall stats-refs)
                            :network @(:network stats-refs)
                            :filesystem @(:filesystem stats-refs)
                            :process @(:process stats-refs)
                            :total @(:total stats-refs)}})

       :refs {:raw-events raw-events
              :filter-output filter-output
              :enrich-output enrich-output
              :stats stats-refs}})))
```

### Step 3.2: Event Simulator

```clojure
(defn simulate-events [pipeline n-events delay-ms]
  "Simulate BPF events being written to ring buffer"
  (let [filter-ch (get-in pipeline [:refs :filter-output])]
    (dotimes [i n-events]
      ;; In real use, BPF program would write to ring buffer
      ;; Here we simulate by writing directly to filter queue
      (let [event {:timestamp (System/currentTimeMillis)
                   :event-type (inc (rand-int 4))
                   :pid (+ 100 (rand-int 1000))
                   :priority (inc (rand-int 3))
                   :category (rand-nth ["syscall" "network" "filesystem" "process"])}]
        (conj! filter-ch (serialize-filtered event)))
      (Thread/sleep delay-ms))
    (println (format "Simulated %d events" n-events))))
```

---

## Part 4: Running the Pipeline

### Step 4.1: Main Function

```clojure
(defn run-demo []
  (let [pipeline (start-pipeline)]
    (try
      ;; Let pipeline initialize
      (Thread/sleep 1000)

      ;; Simulate events
      (println "\nSimulating 100 events...")
      (simulate-events pipeline 100 10)

      ;; Wait for processing
      (Thread/sleep 2000)

      ;; Display stats
      (println "\n=== Pipeline Statistics ===")
      (let [stats ((:stats pipeline))]
        (println "Filter stage:" (:filter stats))
        (println "Enrich stage:" (:enrich stats))
        (println "Aggregate stage:" (:aggregate stats))
        (println "Counters:" (:counters stats)))

      (finally
        ((:stop pipeline))))))

;; Run the demo
(run-demo)
```

---

## Part 5: Exercises

### Exercise 1: Add Backpressure

Modify the pipeline to handle backpressure when queues fill up:

```clojure
(defn start-filter-stage-with-backpressure [...]
  ;; TODO: Check if output queue is full before writing
  ;; If full, either drop events or block
  )
```

### Exercise 2: Add Metrics Stage

Add a stage that calculates rolling averages:

```clojure
(defn start-metrics-stage [input-channel window-size]
  ;; TODO: Calculate rolling average of events per second
  ;; Track latency percentiles
  )
```

### Exercise 3: Fan-Out Pattern

Modify Stage 2 to fan out to multiple worker queues:

```clojure
(defn start-fanout-stage [input-channel output-channels]
  ;; TODO: Distribute events across multiple output queues
  ;; Use round-robin or hash-based distribution
  )
```

### Exercise 4: Dead Letter Queue

Add error handling with a dead letter queue:

```clojure
(def dead-letter-queue
  (bpf/create-queue-map {:value-size 256 :max-entries 1000}))

(defn start-stage-with-dlq [input output dlq process-fn]
  ;; TODO: On processing error, send to dead letter queue
  )
```

---

## Part 6: Testing

### Test Helper Functions

```clojure
(defn test-pipeline-throughput []
  (let [pipeline (start-pipeline)
        start-time (System/currentTimeMillis)]
    (try
      ;; Burst of events
      (simulate-events pipeline 1000 0)

      ;; Wait for completion
      (Thread/sleep 5000)

      (let [end-time (System/currentTimeMillis)
            duration-ms (- end-time start-time)
            stats ((:stats pipeline))
            total-processed (get-in stats [:counters :total])]
        (println (format "Processed %d events in %d ms"
                         total-processed duration-ms))
        (println (format "Throughput: %.2f events/sec"
                         (/ (* total-processed 1000.0) duration-ms))))

      (finally
        ((:stop pipeline))))))
```

---

## Summary

In this lab you learned:
- Building multi-stage processing pipelines with queue channels
- Using `conj!` for producer-side writes
- Using blocking `deref` for consumer-side reads
- Combining ring buffer refs with queue channels
- Using `map-entry-ref` for accumulating statistics
- Proper cleanup of pipeline resources

## Key Patterns

1. **Stage isolation**: Each stage has its own input and output references
2. **Graceful shutdown**: Stop flag plus cleanup of all references
3. **Statistics tracking**: Use map-entry-ref for atomic counter updates
4. **Error handling**: Wrap stages in try/catch with proper cleanup

## Next Steps

- Try Lab 15.3 to build an undo/redo system with stack channels
- Explore adding persistence to the pipeline
- Consider adding monitoring and alerting
