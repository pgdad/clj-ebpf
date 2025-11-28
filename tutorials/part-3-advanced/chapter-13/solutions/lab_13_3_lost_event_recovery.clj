;; Lab 13.3 Solution: Lost Event Detection and Recovery
;; Robust event processing with sequence numbers, gap detection, and backpressure
;;
;; Learning Goals:
;; - Implement sequence numbers for gap detection
;; - Detect and log lost events
;; - Handle backpressure gracefully
;; - Implement recovery strategies
;; - Monitor system health

(ns lab-13-3-lost-event-recovery
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils])
  (:import [java.util.concurrent LinkedBlockingQueue TimeUnit]
           [java.time LocalTime]))

;; ============================================================================
;; Configuration
;; ============================================================================

(def RING_BUFFER_SIZE 10000)          ; Events capacity
(def DROP_LOG_SIZE 1000)              ; Drop event capacity
(def BACKPRESSURE_THRESHOLD 0.8)      ; 80% full triggers backpressure

;; Drop reasons
(def DROP_REASON_BUFFER_FULL 1)
(def DROP_REASON_RESERVE_FAILED 2)
(def DROP_REASON_BACKPRESSURE 3)

(def drop-reason-names
  {DROP_REASON_BUFFER_FULL "Buffer Full"
   DROP_REASON_RESERVE_FAILED "Reserve Failed"
   DROP_REASON_BACKPRESSURE "Backpressure"})

;; ============================================================================
;; Event Structures
;; ============================================================================

(defrecord SequencedEvent [sequence timestamp cpu event-type pid data])

(defrecord DropEvent [timestamp sequence-start sequence-end drop-count reason cpu])

(defrecord Gap [expected-seq received-seq lost-count timestamp])

;; ============================================================================
;; Sequence Number Generator
;; ============================================================================

(defn create-sequence-generator
  "Create a sequence number generator"
  []
  (atom 0))

(defn next-sequence!
  "Get next sequence number"
  [gen]
  (swap! gen inc))

(defn current-sequence
  "Get current sequence number without incrementing"
  [gen]
  @gen)

;; ============================================================================
;; Simulated Ring Buffer with Overflow
;; ============================================================================

(defn create-event-buffer
  "Create event buffer with tracking"
  [capacity]
  {:queue (LinkedBlockingQueue. capacity)
   :capacity capacity
   :submitted (atom 0)
   :dropped (atom 0)
   :overflow-log (LinkedBlockingQueue. DROP_LOG_SIZE)})

(defn buffer-usage
  "Get buffer usage as percentage"
  [buffer]
  (let [size (.size (:queue buffer))
        capacity (:capacity buffer)]
    (/ size (double capacity))))

(defn buffer-submit!
  "Try to submit event to buffer, return true if successful"
  [buffer event]
  (if (.offer (:queue buffer) event)
    (do
      (swap! (:submitted buffer) inc)
      true)
    (do
      (swap! (:dropped buffer) inc)
      false)))

(defn buffer-consume!
  "Consume event from buffer"
  [buffer timeout-ms]
  (.poll (:queue buffer) timeout-ms TimeUnit/MILLISECONDS))

(defn log-drop!
  "Log a drop event"
  [buffer drop-event]
  (.offer (:overflow-log buffer) drop-event))

;; ============================================================================
;; Producer with Sequence Numbers
;; ============================================================================

(defn create-producer
  "Create event producer with sequence numbers"
  [buffer]
  {:buffer buffer
   :sequence-gen (create-sequence-generator)
   :backpressure-active (atom false)
   :drop-stats (atom {:total 0 :consecutive 0 :last-drop-seq nil})})

(defn produce-event!
  "Produce an event with sequence number"
  [producer event-type pid & {:keys [data] :or {data nil}}]
  (let [{:keys [buffer sequence-gen backpressure-active drop-stats]} producer
        seq-num (next-sequence! sequence-gen)
        event (->SequencedEvent seq-num
                                (System/currentTimeMillis)
                                (rand-int 8)  ; Simulated CPU
                                event-type
                                pid
                                data)]

    ;; Check backpressure
    (when (>= (buffer-usage buffer) BACKPRESSURE_THRESHOLD)
      (reset! backpressure-active true))

    (when (< (buffer-usage buffer) 0.5)
      (reset! backpressure-active false))

    ;; Apply backpressure - sample 10%
    (if (and @backpressure-active
             (>= (rand) 0.1))
      ;; Drop due to backpressure
      (do
        (swap! drop-stats update :total inc)
        (log-drop! buffer (->DropEvent (System/currentTimeMillis)
                                       seq-num seq-num 1
                                       DROP_REASON_BACKPRESSURE
                                       (rand-int 8)))
        :backpressure)

      ;; Try to submit
      (if (buffer-submit! buffer event)
        :submitted
        ;; Buffer full
        (do
          (swap! drop-stats (fn [s]
                              (-> s
                                  (update :total inc)
                                  (update :consecutive inc)
                                  (assoc :last-drop-seq seq-num))))
          (log-drop! buffer (->DropEvent (System/currentTimeMillis)
                                         seq-num seq-num 1
                                         DROP_REASON_BUFFER_FULL
                                         (rand-int 8)))
          :dropped)))))

;; ============================================================================
;; Consumer with Gap Detection
;; ============================================================================

(defn create-consumer-state
  "Create consumer state for gap detection"
  []
  (atom {:expected-sequence 1
         :total-events 0
         :total-gaps 0
         :total-lost 0
         :gaps []
         :last-event-time 0}))

(defn detect-gap
  "Detect if there's a gap in sequence numbers"
  [state event]
  (let [expected (:expected-sequence @state)
        received (:sequence event)]

    (cond
      ;; Exact sequence expected
      (= received expected)
      nil

      ;; Gap detected
      (> received expected)
      (let [lost-count (- received expected)]
        (->Gap expected received lost-count (:timestamp event)))

      ;; Duplicate or out-of-order (shouldn't happen in simulation)
      :else
      nil)))

(defn process-event-with-detection!
  "Process event and detect gaps"
  [state event handler]
  (let [gap (detect-gap state event)]

    ;; Handle gap if detected
    (when gap
      (swap! state (fn [s]
                     (-> s
                         (update :total-gaps inc)
                         (update :total-lost + (:lost-count gap))
                         (update :gaps conj gap)))))

    ;; Update state
    (swap! state (fn [s]
                   (-> s
                       (update :total-events inc)
                       (assoc :expected-sequence (inc (:sequence event)))
                       (assoc :last-event-time (:timestamp event)))))

    ;; Call handler
    (handler event gap)))

;; ============================================================================
;; Recovery Strategies
;; ============================================================================

(defn read-drop-log
  "Read drop events for a sequence range"
  [buffer start-seq end-seq]
  (let [drops (atom [])]
    (doseq [drop (seq (.toArray (:overflow-log buffer)))]
      (when (and (>= (:sequence-end drop) start-seq)
                 (<= (:sequence-start drop) end-seq))
        (swap! drops conj drop)))
    @drops))

(defn attempt-recovery
  "Attempt to recover information about lost events"
  [buffer gap]
  (let [drops (read-drop-log buffer
                             (:expected-seq gap)
                             (dec (:received-seq gap)))]
    {:gap gap
     :drop-events (count drops)
     :drop-reasons (frequencies (map :reason drops))
     :recovered? false  ; In simulation, we can't truly recover
     :info (if (seq drops)
             (format "Found %d drop events in log" (count drops))
             "No drop events found in log")}))

(defn write-gap-marker
  "Log gap for downstream processing"
  [gap recovery-info]
  (println (format "\n!!! GAP DETECTED: seq %d-%d missing (%d events) !!!"
                   (:expected-seq gap)
                   (dec (:received-seq gap))
                   (:lost-count gap)))
  (println (format "    Recovery: %s" (:info recovery-info)))
  (when (seq (:drop-reasons recovery-info))
    (println (format "    Drop reasons: %s"
                     (pr-str (:drop-reasons recovery-info))))))

;; ============================================================================
;; Health Monitoring
;; ============================================================================

(defrecord HealthStats
  [events-received events-lost gaps-detected kernel-drops
   backpressure-active loss-rate-percent])

(defn calculate-health-stats
  "Calculate comprehensive health statistics"
  [consumer-state producer buffer]
  (let [state @consumer-state
        received (:total-events state)
        lost (:total-lost state)
        total (+ received lost)]
    (->HealthStats
     received
     lost
     (:total-gaps state)
     @(:dropped buffer)
     @(:backpressure-active producer)
     (if (zero? total) 0.0 (* 100.0 (/ lost (double total)))))))

(defn display-health-stats
  "Display health statistics"
  [stats]
  (println "\n=== Event Processing Health ===")
  (println (format "Events Received:  %d" (:events-received stats)))
  (println (format "Events Lost:      %d" (:events-lost stats)))
  (println (format "Gaps Detected:    %d" (:gaps-detected stats)))
  (println (format "Kernel Drops:     %d" (:kernel-drops stats)))
  (println (format "Backpressure:     %s"
                   (if (:backpressure-active stats) "ACTIVE" "Inactive")))
  (println (format "Loss Rate:        %.3f%%" (:loss-rate-percent stats)))

  ;; Alerts
  (when (pos? (:gaps-detected stats))
    (println "\n*** WARNING: Gaps detected in event stream! ***"))
  (when (:backpressure-active stats)
    (println "\n*** WARNING: Backpressure active, sampling events! ***")))

;; ============================================================================
;; Backpressure Consumer (Manual Implementation)
;; ============================================================================

(defn create-backpressure-consumer
  "Create a consumer with backpressure handling"
  [buffer handler & {:keys [poll-timeout-ms] :or {poll-timeout-ms 100}}]
  (let [consumer-state (create-consumer-state)
        running (atom true)
        stats (atom {:processed 0 :dropped 0})]

    {:state consumer-state
     :running running
     :stats stats
     :future (future
               (while @running
                 (when-let [event (buffer-consume! buffer poll-timeout-ms)]
                   (process-event-with-detection!
                    consumer-state event
                    (fn [evt gap]
                      (swap! stats update :processed inc)
                      (when gap
                        (let [recovery (attempt-recovery buffer gap)]
                          (write-gap-marker gap recovery)))
                      (handler evt))))))}))

(defn stop-consumer!
  "Stop the backpressure consumer"
  [consumer]
  (reset! (:running consumer) false)
  (future-cancel (:future consumer)))

(defn consumer-healthy?
  "Check if consumer is healthy"
  [consumer & {:keys [max-loss-rate] :or {max-loss-rate 0.05}}]
  (let [state @(:state consumer)
        received (:total-events state)
        lost (:total-lost state)]
    (or (zero? (+ received lost))
        (< (/ lost (double (+ received lost))) max-loss-rate))))

;; ============================================================================
;; Scenario Testing
;; ============================================================================

(defn run-normal-scenario
  "Run normal operation scenario"
  [duration-sec events-per-sec]
  (println (format "\n=== Normal Operation Scenario ==="))
  (println (format "Duration: %ds, Rate: %d events/sec" duration-sec events-per-sec))

  (let [buffer (create-event-buffer RING_BUFFER_SIZE)
        producer (create-producer buffer)
        consumer (create-backpressure-consumer
                  buffer
                  (fn [_event] nil)  ; No-op handler
                  :poll-timeout-ms 10)]

    ;; Generate events
    (future
      (dotimes [_ (* duration-sec events-per-sec)]
        (produce-event! producer :syscall (+ 1000 (rand-int 64535)))
        (Thread/sleep (quot 1000 events-per-sec))))

    ;; Wait for completion
    (Thread/sleep (* duration-sec 1000))
    (Thread/sleep 500)  ; Allow consumer to catch up

    ;; Display results
    (let [stats (calculate-health-stats (:state consumer) producer buffer)]
      (display-health-stats stats)
      (stop-consumer! consumer)
      stats)))

(defn run-burst-scenario
  "Run event burst scenario that causes drops"
  [burst-size burst-rate]
  (println (format "\n=== Burst Scenario ==="))
  (println (format "Burst: %d events at %d/sec" burst-size burst-rate))

  (let [buffer (create-event-buffer (quot burst-size 2))  ; Buffer smaller than burst
        producer (create-producer buffer)
        consumer (create-backpressure-consumer
                  buffer
                  (fn [_event] nil)
                  :poll-timeout-ms 1)]

    ;; Generate burst
    (dotimes [_ burst-size]
      (produce-event! producer :syscall (+ 1000 (rand-int 64535)))
      (when (pos? burst-rate)
        (Thread/sleep (quot 1000 burst-rate))))

    ;; Wait for processing
    (Thread/sleep 1000)

    ;; Display results
    (let [stats (calculate-health-stats (:state consumer) producer buffer)]
      (display-health-stats stats)

      ;; Show gaps
      (let [gaps (:gaps @(:state consumer))]
        (when (seq gaps)
          (println (format "\nGaps detected: %d" (count gaps)))
          (doseq [gap (take 5 gaps)]
            (println (format "  Seq %d-%d: %d events lost"
                             (:expected-seq gap)
                             (dec (:received-seq gap))
                             (:lost-count gap))))))

      (stop-consumer! consumer)
      stats)))

(defn run-backpressure-scenario
  "Run scenario with backpressure activation"
  [duration-sec high-rate]
  (println (format "\n=== Backpressure Scenario ==="))
  (println (format "High rate: %d/sec for %ds" high-rate duration-sec))

  (let [buffer (create-event-buffer 1000)  ; Small buffer to trigger backpressure
        producer (create-producer buffer)
        events-produced (atom 0)
        consumer (create-backpressure-consumer
                  buffer
                  (fn [_event]
                    (Thread/sleep 1))  ; Slow consumer
                  :poll-timeout-ms 10)]

    ;; Generate high-rate events
    (future
      (dotimes [_ (* duration-sec high-rate)]
        (produce-event! producer :syscall (+ 1000 (rand-int 64535)))
        (swap! events-produced inc)))

    ;; Monitor backpressure status
    (dotimes [i duration-sec]
      (Thread/sleep 1000)
      (println (format "[%ds] Buffer: %.0f%%, Backpressure: %s, Produced: %d"
                       (inc i)
                       (* 100 (buffer-usage buffer))
                       (if @(:backpressure-active producer) "ON" "off")
                       @events-produced)))

    ;; Final stats
    (let [stats (calculate-health-stats (:state consumer) producer buffer)]
      (display-health-stats stats)
      (stop-consumer! consumer)

      (println "\n=== Backpressure Analysis ===")
      (println (format "Events produced: %d" @events-produced))
      (println (format "Events received: %d" (:events-received stats)))
      (println (format "Drop rate:       %.2f%%" (:loss-rate-percent stats)))
      (when (< (:loss-rate-percent stats) 50)
        (println "SUCCESS: Backpressure kept loss rate manageable"))

      stats)))

;; ============================================================================
;; Demonstration
;; ============================================================================

(defn demonstrate-gap-detection
  "Demonstrate gap detection mechanism"
  []
  (println "\n=== Gap Detection Demonstration ===")
  (println "Manually creating events with gaps...")

  (let [state (create-consumer-state)
        events [{:sequence 1 :timestamp 1000}
                {:sequence 2 :timestamp 1001}
                {:sequence 3 :timestamp 1002}
                ;; Gap: 4, 5, 6 missing
                {:sequence 7 :timestamp 1003}
                {:sequence 8 :timestamp 1004}
                ;; Gap: 9 missing
                {:sequence 10 :timestamp 1005}]]

    (println "\nProcessing events with intentional gaps:")
    (println "SEQ   EXPECTED  RESULT")
    (println "========================")

    (doseq [event events]
      (let [expected (:expected-sequence @state)
            gap (detect-gap state event)]
        (process-event-with-detection!
         state event
         (fn [_ g]
           (println (format "%3d   %8d  %s"
                            (:sequence event)
                            expected
                            (if g
                              (format "GAP! Lost %d events" (:lost-count g))
                              "OK")))))))

    (println "\n=== Summary ===")
    (println (format "Events processed: %d" (:total-events @state)))
    (println (format "Gaps detected:    %d" (:total-gaps @state)))
    (println (format "Events lost:      %d" (:total-lost @state)))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the lost event recovery lab"
  [& args]
  (let [command (first args)]
    (case command
      "normal"
      (let [duration (or (some-> (second args) Integer/parseInt) 5)
            rate (or (some-> (nth args 2 nil) Integer/parseInt) 100)]
        (run-normal-scenario duration rate))

      "burst"
      (let [size (or (some-> (second args) Integer/parseInt) 10000)
            rate (or (some-> (nth args 2 nil) Integer/parseInt) 50000)]
        (run-burst-scenario size rate))

      "backpressure"
      (let [duration (or (some-> (second args) Integer/parseInt) 5)
            rate (or (some-> (nth args 2 nil) Integer/parseInt) 5000)]
        (run-backpressure-scenario duration rate))

      "demo"
      (demonstrate-gap-detection)

      ;; Default: full demo
      (do
        (println "Lab 13.3: Lost Event Detection and Recovery")
        (println "============================================")
        (println "\nUsage:")
        (println "  normal [duration] [rate]       - Normal operation")
        (println "  burst [size] [rate]            - Burst scenario")
        (println "  backpressure [duration] [rate] - Backpressure scenario")
        (println "  demo                           - Gap detection demo")
        (println)

        ;; Run demonstrations
        (demonstrate-gap-detection)
        (run-normal-scenario 3 500)
        (run-burst-scenario 5000 0)  ; Instant burst
        (run-backpressure-scenario 5 2000)

        (println "\n=== Key Takeaways ===")
        (println "1. Sequence numbers enable gap detection")
        (println "2. Drop logging helps diagnose issues")
        (println "3. Backpressure reduces loss rate under load")
        (println "4. Recovery strategies depend on use case")
        (println "5. Monitor health metrics continuously")))))

;; Run with: clj -M -m lab-13-3-lost-event-recovery
;; Or:       clj -M -m lab-13-3-lost-event-recovery burst 10000 50000
