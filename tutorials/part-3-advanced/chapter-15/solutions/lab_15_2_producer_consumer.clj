;; Lab 15.2 Solution: Producer-Consumer Pipeline
;; Multi-stage event processing pipeline using queue channels and reference types
;;
;; Learning Goals:
;; - Build multi-stage processing pipelines with queue channels
;; - Use conj! for producer-side writes
;; - Use blocking deref for consumer-side reads
;; - Combine ring buffer refs with queue channels

(ns lab-15-2-producer-consumer
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils])
  (:import [java.util.concurrent LinkedBlockingQueue TimeUnit]
           [java.time LocalTime]))

;; ============================================================================
;; Event Categories
;; ============================================================================

(def event-categories
  {1 "syscall"
   2 "network"
   3 "filesystem"
   4 "process"})

;; ============================================================================
;; Simulated Queue Channel
;; ============================================================================

(defrecord MockQueueChannel [queue max-entries serializer deserializer]
  clojure.lang.IBlockingDeref
  (deref [_ timeout-ms timeout-val]
    (if-let [bytes (.poll queue timeout-ms TimeUnit/MILLISECONDS)]
      (if deserializer
        (deserializer bytes)
        bytes)
      timeout-val))

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  clojure.lang.ITransientCollection
  (conj [this val]
    (let [bytes (if serializer (serializer val) val)]
      (.offer queue bytes))
    this)

  java.io.Closeable
  (close [_]
    (.clear queue)))

(defn queue-channel
  "Create a mock queue channel"
  [max-entries & {:keys [serializer deserializer]}]
  (->MockQueueChannel
   (LinkedBlockingQueue. max-entries)
   max-entries
   serializer
   deserializer))

(defn queue-size
  "Get current queue size"
  [channel]
  (.size (:queue channel)))

;; ============================================================================
;; Simulated Ring Buffer Reference
;; ============================================================================

(defrecord MockRingbufRef [queue deserializer]
  clojure.lang.IBlockingDeref
  (deref [_ timeout-ms timeout-val]
    (if-let [bytes (.poll queue timeout-ms TimeUnit/MILLISECONDS)]
      (if deserializer
        (deserializer bytes)
        bytes)
      timeout-val))

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  java.io.Closeable
  (close [_]
    (.clear queue)))

(defn ringbuf-ref
  "Create a mock ring buffer reference"
  [queue & {:keys [deserializer]}]
  (->MockRingbufRef queue deserializer))

;; ============================================================================
;; Simulated Map Entry Reference
;; ============================================================================

(defrecord MockMapEntryRef [store key]
  clojure.lang.IDeref
  (deref [_]
    (get @store key 0))

  clojure.lang.IAtom
  (swap [_ f]
    (swap! store update key (fn [v] (f (or v 0)))))
  (swap [_ f x]
    (swap! store update key (fn [v] (f (or v 0) x))))
  (swap [_ f x y]
    (swap! store update key (fn [v] (f (or v 0) x y))))
  (swap [_ f x y more]
    (swap! store update key (fn [v] (apply f (or v 0) x y more))))
  (compareAndSet [_ oldval newval]
    (let [current (get @store key)]
      (if (= current oldval)
        (do (swap! store assoc key newval) true)
        false)))
  (reset [_ newval]
    (swap! store assoc key newval)
    newval)

  java.io.Closeable
  (close [_] nil))

(defn map-entry-ref
  "Create a mock map-entry-ref"
  [store key]
  (->MockMapEntryRef store key))

;; ============================================================================
;; Event Structures
;; ============================================================================

(defn make-raw-event
  "Create a raw event (as if from BPF)"
  [event-type pid]
  {:timestamp (System/currentTimeMillis)
   :event-type event-type
   :pid pid
   :data (str "Event data from PID " pid)})

(defn categorize-event
  "Add category and priority to event"
  [event]
  (assoc event
         :category (get event-categories (:event-type event) "unknown")
         :priority (cond
                     (= (:event-type event) 4) 1  ; Process events high priority
                     (= (:event-type event) 2) 2  ; Network medium
                     :else 3)))                    ; Others low

(defn should-filter?
  "Return true if event should be discarded"
  [event]
  ;; Filter out low-priority events from system processes
  (and (= (:priority event) 3)
       (< (:pid event) 100)))

(defn lookup-process-name
  "Look up process name (simulated)"
  [pid]
  (get {1 "init" 2 "kthreadd" 1000 "myapp" 1001 "worker"
        500 "systemd" 1234 "nginx" 5678 "postgres"}
       pid
       (str "process-" pid)))

(defn enrich-event
  "Add process name and additional metadata"
  [event]
  (assoc event
         :process-name (lookup-process-name (:pid event))
         :enriched-at (System/currentTimeMillis)
         :enriched-data (format "Enriched: %s @ %s"
                                (:category event)
                                (LocalTime/now))))

;; ============================================================================
;; Pipeline Stages
;; ============================================================================

(defn start-filter-stage
  "Stage 1: Read from ring buffer, filter, categorize, output to queue"
  [input-ref output-channel stats-ref]
  (let [running (atom true)
        processed (atom 0)
        filtered (atom 0)]
    (future
      (try
        (while @running
          (when-let [raw-event (.deref input-ref 100 nil)]
            (swap! processed inc)
            (let [categorized (categorize-event raw-event)]
              (if (should-filter? categorized)
                (swap! filtered inc)
                (conj! output-channel categorized)))))
        (catch Exception e
          (println "Filter stage error:" (.getMessage e)))
        (finally
          (println (format "Filter stage stopped. Processed: %d, Filtered: %d"
                           @processed @filtered)))))
    {:stop (fn [] (reset! running false))
     :stats (fn [] {:processed @processed :filtered @filtered})}))

(defn start-enrich-stage
  "Stage 2: Read from queue, enrich, output to next queue"
  [input-channel output-channel]
  (let [running (atom true)
        processed (atom 0)]
    (future
      (try
        (while @running
          (when-let [event (.deref input-channel 100 nil)]
            (swap! processed inc)
            (let [enriched (enrich-event event)]
              (conj! output-channel enriched))))
        (catch Exception e
          (println "Enrich stage error:" (.getMessage e)))
        (finally
          (println (format "Enrich stage stopped. Processed: %d" @processed)))))
    {:stop (fn [] (reset! running false))
     :stats (fn [] {:processed @processed})}))

(defn start-aggregate-stage
  "Stage 3: Read enriched events, update statistics"
  [input-channel stats-refs]
  (let [running (atom true)
        processed (atom 0)]
    (future
      (try
        (while @running
          (when-let [event (.deref input-channel 100 nil)]
            (swap! processed inc)
            (let [category (:category event)]
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

;; ============================================================================
;; Statistics References
;; ============================================================================

(def stats-store (atom {}))

(defn create-stats-refs
  "Create map-entry-refs for statistics"
  []
  (let [init-counter (fn [key]
                       (swap! stats-store assoc key 0)
                       (map-entry-ref stats-store key))]
    {:syscall (init-counter :syscall)
     :network (init-counter :network)
     :filesystem (init-counter :filesystem)
     :process (init-counter :process)
     :total (init-counter :total)}))

(defn close-stats-refs
  "Close all stats references"
  [refs]
  (doseq [[_ ref] refs]
    (.close ref)))

;; ============================================================================
;; Pipeline Orchestration
;; ============================================================================

(defn start-pipeline
  "Start the complete processing pipeline"
  []
  (println "Starting event processing pipeline...")

  ;; Reset stats
  (reset! stats-store {})

  ;; Create queues
  (let [raw-events-queue (LinkedBlockingQueue. 10000)
        filtered-queue (queue-channel 10000)
        enriched-queue (queue-channel 10000)

        ;; Create references
        raw-events (ringbuf-ref raw-events-queue)
        stats-refs (create-stats-refs)

        ;; Start stages
        filter-stage (start-filter-stage raw-events filtered-queue stats-refs)
        enrich-stage (start-enrich-stage filtered-queue enriched-queue)
        aggregate-stage (start-aggregate-stage enriched-queue stats-refs)]

    (println "Pipeline started!")
    (println "Stages: [Raw Events] -> Filter -> Enrich -> Aggregate -> [Stats]")

    ;; Return control object
    {:stop (fn []
             (println "\nStopping pipeline...")
             ((:stop filter-stage))
             ((:stop enrich-stage))
             ((:stop aggregate-stage))
             (Thread/sleep 500)
             (.close raw-events)
             (.close filtered-queue)
             (.close enriched-queue)
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

     :inject (fn [event]
               (.offer raw-events-queue event))

     :refs {:raw-queue raw-events-queue
            :filtered filtered-queue
            :enriched enriched-queue
            :stats stats-refs}}))

;; ============================================================================
;; Event Simulation
;; ============================================================================

(defn simulate-events
  "Simulate BPF events being written to ring buffer"
  [pipeline n-events delay-ms]
  (println (format "\nSimulating %d events with %dms delay..." n-events delay-ms))
  (dotimes [_ n-events]
    (let [event (make-raw-event
                 (inc (rand-int 4))
                 (+ 100 (rand-int 1000)))]
      ((:inject pipeline) event))
    (when (pos? delay-ms)
      (Thread/sleep delay-ms)))
  (println (format "Simulated %d events" n-events)))

(defn simulate-burst
  "Simulate a burst of events"
  [pipeline n-events]
  (println (format "\nSimulating burst of %d events..." n-events))
  (dotimes [_ n-events]
    ((:inject pipeline) (make-raw-event
                         (inc (rand-int 4))
                         (+ 100 (rand-int 1000)))))
  (println "Burst complete"))

;; ============================================================================
;; Monitoring
;; ============================================================================

(defn display-pipeline-stats
  "Display current pipeline statistics"
  [pipeline]
  (let [stats ((:stats pipeline))]
    (println "\n=== Pipeline Statistics ===")
    (println "Stage Performance:")
    (println (format "  Filter:    %s" (:filter stats)))
    (println (format "  Enrich:    %s" (:enrich stats)))
    (println (format "  Aggregate: %s" (:aggregate stats)))
    (println "Event Counters:")
    (println (format "  Syscall:    %d" (get-in stats [:counters :syscall])))
    (println (format "  Network:    %d" (get-in stats [:counters :network])))
    (println (format "  Filesystem: %d" (get-in stats [:counters :filesystem])))
    (println (format "  Process:    %d" (get-in stats [:counters :process])))
    (println (format "  Total:      %d" (get-in stats [:counters :total])))
    (println "============================\n")))

(defn display-queue-depths
  "Display current queue depths"
  [pipeline]
  (let [refs (:refs pipeline)]
    (println "\n=== Queue Depths ===")
    (println (format "  Raw events:  %d" (.size (:raw-queue refs))))
    (println (format "  Filtered:    %d" (queue-size (:filtered refs))))
    (println (format "  Enriched:    %d" (queue-size (:enriched refs))))
    (println "====================\n")))

;; ============================================================================
;; Backpressure Handling (Exercise 1)
;; ============================================================================

(defn start-filter-stage-with-backpressure
  "Filter stage with backpressure handling"
  [input-ref output-channel stats-ref & {:keys [max-queue-size drop-on-full]
                                          :or {max-queue-size 1000
                                               drop-on-full true}}]
  (let [running (atom true)
        processed (atom 0)
        filtered (atom 0)
        dropped (atom 0)]
    (future
      (try
        (while @running
          (when-let [raw-event (.deref input-ref 100 nil)]
            (swap! processed inc)
            (let [categorized (categorize-event raw-event)]
              (cond
                ;; Filter event
                (should-filter? categorized)
                (swap! filtered inc)

                ;; Backpressure - queue too full
                (and drop-on-full (>= (queue-size output-channel) max-queue-size))
                (swap! dropped inc)

                ;; Normal processing
                :else
                (conj! output-channel categorized)))))
        (catch Exception e
          (println "Filter stage error:" (.getMessage e)))
        (finally
          (println (format "Filter stage stopped. Processed: %d, Filtered: %d, Dropped: %d"
                           @processed @filtered @dropped)))))
    {:stop (fn [] (reset! running false))
     :stats (fn [] {:processed @processed
                    :filtered @filtered
                    :dropped @dropped})}))

;; ============================================================================
;; Fan-Out Pattern (Exercise 3)
;; ============================================================================

(defn start-fanout-stage
  "Distribute events across multiple output queues"
  [input-channel output-channels & {:keys [strategy]
                                    :or {strategy :round-robin}}]
  (let [running (atom true)
        processed (atom 0)
        channel-index (atom 0)
        num-channels (count output-channels)]
    (future
      (try
        (while @running
          (when-let [event (.deref input-channel 100 nil)]
            (swap! processed inc)
            (let [target-idx (case strategy
                               :round-robin (swap! channel-index #(mod (inc %) num-channels))
                               :hash (mod (hash (:pid event)) num-channels)
                               :random (rand-int num-channels)
                               0)
                  target-channel (nth output-channels target-idx)]
              (conj! target-channel event))))
        (catch Exception e
          (println "Fanout stage error:" (.getMessage e)))
        (finally
          (println (format "Fanout stage stopped. Distributed: %d events" @processed)))))
    {:stop (fn [] (reset! running false))
     :stats (fn [] {:processed @processed})}))

;; ============================================================================
;; Dead Letter Queue (Exercise 4)
;; ============================================================================

(defn start-stage-with-dlq
  "Stage that sends failed events to dead letter queue"
  [input-channel output-channel dlq-channel process-fn]
  (let [running (atom true)
        processed (atom 0)
        errors (atom 0)]
    (future
      (try
        (while @running
          (when-let [event (.deref input-channel 100 nil)]
            (try
              (swap! processed inc)
              (let [result (process-fn event)]
                (conj! output-channel result))
              (catch Exception e
                (swap! errors inc)
                (conj! dlq-channel {:event event
                                    :error (.getMessage e)
                                    :timestamp (System/currentTimeMillis)})))))
        (catch Exception e
          (println "Stage error:" (.getMessage e)))
        (finally
          (println (format "Stage stopped. Processed: %d, Errors: %d"
                           @processed @errors)))))
    {:stop (fn [] (reset! running false))
     :stats (fn [] {:processed @processed :errors @errors})}))

;; ============================================================================
;; Performance Testing
;; ============================================================================

(defn test-pipeline-throughput
  "Test pipeline throughput"
  [n-events]
  (println (format "\n=== Throughput Test (%d events) ===" n-events))

  (let [pipeline (start-pipeline)
        start-time (System/currentTimeMillis)]

    ;; Burst of events
    (simulate-burst pipeline n-events)

    ;; Wait for processing
    (println "Waiting for processing...")
    (Thread/sleep 3000)

    (let [end-time (System/currentTimeMillis)
          duration-ms (- end-time start-time)
          stats ((:stats pipeline))
          total-processed (get-in stats [:counters :total])]

      (println (format "\nResults:"))
      (println (format "  Events processed: %d" total-processed))
      (println (format "  Duration: %d ms" duration-ms))
      (println (format "  Throughput: %.2f events/sec"
                       (/ (* total-processed 1000.0) duration-ms)))

      ((:stop pipeline))

      {:processed total-processed
       :duration-ms duration-ms
       :throughput (/ (* total-processed 1000.0) duration-ms)})))

;; ============================================================================
;; Main Demo
;; ============================================================================

(defn run-demo
  "Run the pipeline demo"
  []
  (println "=== Producer-Consumer Pipeline Demo ===\n")

  (let [pipeline (start-pipeline)]
    (try
      ;; Let pipeline initialize
      (Thread/sleep 500)

      ;; Simulate events with delay
      (simulate-events pipeline 50 50)

      ;; Wait for processing
      (Thread/sleep 2000)

      ;; Display stats
      (display-pipeline-stats pipeline)
      (display-queue-depths pipeline)

      ;; Simulate burst
      (simulate-burst pipeline 100)

      ;; Wait and show final stats
      (Thread/sleep 2000)
      (display-pipeline-stats pipeline)

      (finally
        ((:stop pipeline))))))

(defn demonstrate-fanout
  "Demonstrate fan-out pattern"
  []
  (println "\n=== Fan-Out Pattern Demo ===\n")

  (let [input-queue (queue-channel 1000)
        output-channels [(queue-channel 500)
                         (queue-channel 500)
                         (queue-channel 500)]
        fanout (start-fanout-stage input-queue output-channels
                                   :strategy :round-robin)]

    ;; Send events
    (dotimes [i 30]
      (conj! input-queue {:id i :pid (+ 100 i)}))

    (Thread/sleep 500)

    ;; Check distribution
    (println "Queue distribution:")
    (doseq [[idx ch] (map-indexed vector output-channels)]
      (println (format "  Channel %d: %d events" idx (queue-size ch))))

    ((:stop fanout))

    (doseq [ch output-channels]
      (.close ch))
    (.close input-queue)))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the producer-consumer pipeline lab"
  [& args]
  (let [command (first args)]
    (case command
      "demo"
      (run-demo)

      "throughput"
      (let [n (or (some-> (second args) Integer/parseInt) 1000)]
        (test-pipeline-throughput n))

      "fanout"
      (demonstrate-fanout)

      ;; Default: full demo
      (do
        (println "Lab 15.2: Producer-Consumer Pipeline")
        (println "=====================================")
        (println "\nUsage:")
        (println "  demo                - Run pipeline demo")
        (println "  throughput [n]      - Test throughput with n events")
        (println "  fanout              - Demo fan-out pattern")
        (println)

        (run-demo)
        (test-pipeline-throughput 1000)
        (demonstrate-fanout)

        (println "\n=== Key Takeaways ===")
        (println "1. Queue channels enable multi-stage pipelines")
        (println "2. conj! for producer writes, deref for consumer reads")
        (println "3. Each stage has independent concurrency")
        (println "4. map-entry-ref accumulates statistics atomically")
        (println "5. Backpressure handling prevents queue overflow")))))

;; Run with: clj -M -m lab-15-2-producer-consumer
;; Or:       clj -M -m lab-15-2-producer-consumer throughput 5000
