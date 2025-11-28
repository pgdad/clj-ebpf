;; Lab 13.1 Solution: Multi-Ring Buffer System
;; Production-grade event routing system with multiple ring buffers by priority
;;
;; Learning Goals:
;; - Use multiple ring buffers in a single program
;; - Route events by priority/severity
;; - Detect and handle buffer overflow
;; - Monitor buffer health metrics
;; - Implement independent processing pipelines

(ns lab-13-1-multi-ring-buffer
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils])
  (:import [java.util.concurrent LinkedBlockingQueue TimeUnit ExecutorService Executors]
           [java.time LocalTime]))

;; ============================================================================
;; Event Severity Levels
;; ============================================================================

(def SEVERITY_CRITICAL 0)  ; Security violations, crashes
(def SEVERITY_ERROR 1)     ; Errors, failures
(def SEVERITY_WARNING 2)   ; Warnings, anomalies
(def SEVERITY_INFO 3)      ; Normal operations
(def SEVERITY_DEBUG 4)     ; Debug information

(def severity-names
  {SEVERITY_CRITICAL "CRITICAL"
   SEVERITY_ERROR "ERROR"
   SEVERITY_WARNING "WARNING"
   SEVERITY_INFO "INFO"
   SEVERITY_DEBUG "DEBUG"})

;; ============================================================================
;; Event Types
;; ============================================================================

(def EVENT_PROCESS_EXEC 1)
(def EVENT_FILE_OPEN 2)
(def EVENT_NETWORK_CONNECT 3)
(def EVENT_SECURITY_VIOLATION 4)
(def EVENT_RESOURCE_LIMIT 5)

(def event-type-names
  {EVENT_PROCESS_EXEC "PROCESS_EXEC"
   EVENT_FILE_OPEN "FILE_OPEN"
   EVENT_NETWORK_CONNECT "NETWORK_CONNECT"
   EVENT_SECURITY_VIOLATION "SECURITY_VIOLATION"
   EVENT_RESOURCE_LIMIT "RESOURCE_LIMIT"})

;; ============================================================================
;; Ring Buffer Configuration
;; ============================================================================

(defrecord RingBufferConfig [name size-kb priority description])

(def critical-buffer-config
  (->RingBufferConfig "critical" 128 :high "Never drop, process immediately"))

(def normal-buffer-config
  (->RingBufferConfig "normal" 512 :medium "Standard processing"))

(def debug-buffer-config
  (->RingBufferConfig "debug" 64 :low "Best effort, can drop"))

;; ============================================================================
;; Statistics Tracking
;; ============================================================================

(def STATS_CRITICAL 0)
(def STATS_NORMAL 1)
(def STATS_DEBUG 2)

(defrecord BufferStats [submitted dropped failures])

(defn create-stats-map
  "Create per-buffer statistics map"
  []
  {:critical (atom (->BufferStats 0 0 0))
   :normal (atom (->BufferStats 0 0 0))
   :debug (atom (->BufferStats 0 0 0))})

(defn increment-submitted! [stats-map buffer-type]
  (swap! (get stats-map buffer-type)
         update :submitted inc))

(defn increment-dropped! [stats-map buffer-type]
  (swap! (get stats-map buffer-type)
         update :dropped inc))

;; ============================================================================
;; Event Structure
;; ============================================================================

(defrecord Event [timestamp type severity cpu pid uid data])

(defn create-event
  "Create a new event"
  [event-type severity pid uid & {:keys [data] :or {data nil}}]
  (->Event
   (System/nanoTime)
   event-type
   severity
   (rand-int 8)  ; Simulated CPU
   pid
   uid
   data))

;; ============================================================================
;; Event Classification
;; ============================================================================

(defn classify-event-severity
  "Determine event severity based on type and context"
  [event]
  (let [{:keys [type uid pid]} event]
    (cond
      ;; Security violations → CRITICAL
      (= type EVENT_SECURITY_VIOLATION)
      SEVERITY_CRITICAL

      ;; Process exec with UID=0 → CRITICAL (root activity)
      (and (= type EVENT_PROCESS_EXEC) (= uid 0))
      SEVERITY_CRITICAL

      ;; Resource limit violations → ERROR
      (= type EVENT_RESOURCE_LIMIT)
      SEVERITY_ERROR

      ;; Network connects → INFO (unless suspicious)
      (= type EVENT_NETWORK_CONNECT)
      SEVERITY_INFO

      ;; File open → DEBUG (most common, lowest priority)
      (= type EVENT_FILE_OPEN)
      SEVERITY_DEBUG

      ;; Default → INFO
      :else
      SEVERITY_INFO)))

(defn select-buffer
  "Select appropriate buffer based on severity"
  [severity]
  (cond
    (<= severity SEVERITY_ERROR) :critical
    (= severity SEVERITY_DEBUG) :debug
    :else :normal))

;; ============================================================================
;; Simulated Ring Buffers
;; ============================================================================

(defn create-ring-buffer
  "Create a simulated ring buffer with configurable size"
  [config]
  {:config config
   :queue (LinkedBlockingQueue. (* (:size-kb config) 16))  ; ~16 events per KB
   :overflow-count (atom 0)})

(defn ring-buffer-submit
  "Submit event to ring buffer, return true if successful"
  [ring-buffer event]
  (let [queue (:queue ring-buffer)]
    (if (.offer queue event)
      true
      (do
        (swap! (:overflow-count ring-buffer) inc)
        false))))

(defn ring-buffer-consume
  "Consume events from ring buffer"
  [ring-buffer timeout-ms]
  (.poll (:queue ring-buffer) timeout-ms TimeUnit/MILLISECONDS))

(defn ring-buffer-size
  "Get current buffer size"
  [ring-buffer]
  (.size (:queue ring-buffer)))

(defn ring-buffer-capacity
  "Get buffer capacity"
  [ring-buffer]
  (+ (.size (:queue ring-buffer))
     (.remainingCapacity (:queue ring-buffer))))

(defn ring-buffer-usage
  "Get buffer usage percentage"
  [ring-buffer]
  (let [size (ring-buffer-size ring-buffer)
        capacity (ring-buffer-capacity ring-buffer)]
    (if (zero? capacity)
      0.0
      (* 100.0 (/ size capacity)))))

;; ============================================================================
;; Multi-Ring Buffer System
;; ============================================================================

(defn create-multi-ring-buffer-system
  "Create the complete multi-ring buffer system"
  []
  {:critical (create-ring-buffer critical-buffer-config)
   :normal (create-ring-buffer normal-buffer-config)
   :debug (create-ring-buffer debug-buffer-config)
   :stats (create-stats-map)})

(defn route-event
  "Route event to appropriate buffer based on severity"
  [system event]
  (let [severity (classify-event-severity event)
        buffer-type (select-buffer severity)
        ring-buffer (get system buffer-type)
        event-with-severity (assoc event :severity severity)]

    (if (ring-buffer-submit ring-buffer event-with-severity)
      (do
        (increment-submitted! (:stats system) buffer-type)
        :submitted)
      (do
        (increment-dropped! (:stats system) buffer-type)
        :dropped))))

;; ============================================================================
;; Event Generation (Simulation)
;; ============================================================================

(defn generate-random-event
  "Generate a random event for testing"
  []
  (let [event-types [EVENT_PROCESS_EXEC EVENT_FILE_OPEN EVENT_NETWORK_CONNECT
                     EVENT_SECURITY_VIOLATION EVENT_RESOURCE_LIMIT]
        weights [10 60 20 2 8]  ; Distribution percentages
        total (reduce + weights)
        r (rand-int total)
        event-type (loop [idx 0 acc 0]
                     (if (< r (+ acc (nth weights idx)))
                       (nth event-types idx)
                       (recur (inc idx) (+ acc (nth weights idx)))))
        uid (if (< (rand) 0.05) 0 (+ 1000 (rand-int 1000)))  ; 5% root
        pid (+ 1000 (rand-int 64535))]
    (create-event event-type SEVERITY_INFO pid uid)))

(defn generate-event-burst
  "Generate a burst of events (simulates high load)"
  [count]
  (repeatedly count generate-random-event))

(defn generate-debug-flood
  "Generate flood of debug events (simulates debug logging)"
  [count]
  (repeatedly count
              #(create-event EVENT_FILE_OPEN SEVERITY_DEBUG
                            (+ 1000 (rand-int 1000))
                            (+ 1000 (rand-int 1000)))))

(defn generate-security-events
  "Generate security events"
  [count]
  (repeatedly count
              #(create-event EVENT_SECURITY_VIOLATION SEVERITY_CRITICAL
                            (+ 1000 (rand-int 1000))
                            (rand-int 100))))

;; ============================================================================
;; Event Processors
;; ============================================================================

(defn process-critical-events
  "Process critical events immediately"
  [ring-buffer callback]
  (future
    (loop []
      (when-let [event (ring-buffer-consume ring-buffer 10)]
        (callback event))
      (recur))))

(defn process-normal-events
  "Batch process normal events"
  [ring-buffer callback batch-interval-ms]
  (future
    (loop []
      (Thread/sleep batch-interval-ms)
      (let [events (atom [])]
        (loop []
          (when-let [event (ring-buffer-consume ring-buffer 0)]
            (swap! events conj event)
            (recur)))
        (when (seq @events)
          (callback @events)))
      (recur))))

(defn process-debug-events
  "Best-effort debug event processing"
  [ring-buffer callback batch-interval-ms]
  (future
    (loop []
      (Thread/sleep batch-interval-ms)
      (try
        (let [events (atom [])]
          (dotimes [_ 1000]  ; Process up to 1000 at a time
            (when-let [event (ring-buffer-consume ring-buffer 0)]
              (swap! events conj event)))
          (when (seq @events)
            (callback @events)))
        (catch Exception e
          ;; Debug processing failures are non-fatal
          nil))
      (recur))))

;; ============================================================================
;; Buffer Health Monitoring
;; ============================================================================

(defn get-buffer-health
  "Get health metrics for a buffer"
  [ring-buffer stats-atom]
  (let [stats @stats-atom
        usage (ring-buffer-usage ring-buffer)
        overflow @(:overflow-count ring-buffer)]
    {:submitted (:submitted stats)
     :dropped (:dropped stats)
     :overflow overflow
     :usage-percent usage
     :queue-size (ring-buffer-size ring-buffer)
     :healthy? (and (< usage 90.0)
                    (or (zero? (:submitted stats))
                        (< (/ (:dropped stats) (max 1 (:submitted stats))) 0.01)))}))

(defn display-buffer-health
  "Display health metrics for all buffers"
  [system]
  (println "\n=== Ring Buffer Health ===")
  (println "BUFFER      SUBMITTED    DROPPED    USAGE%   OVERFLOW   STATUS")
  (println "================================================================")

  (doseq [[buffer-name stats-atom] (:stats system)]
    (let [ring-buffer (get system buffer-name)
          health (get-buffer-health ring-buffer stats-atom)
          drop-rate (if (zero? (:submitted health))
                      0.0
                      (* 100.0 (/ (:dropped health) (:submitted health))))]
      (println (format "%-11s %10d   %8d   %5.1f%%   %8d   %s"
                       (name buffer-name)
                       (:submitted health)
                       (:dropped health)
                       (:usage-percent health)
                       (:overflow health)
                       (if (:healthy? health) "OK" "WARNING")))))

  ;; Alerts
  (let [critical-stats @(get-in system [:stats :critical])]
    (when (pos? (:dropped critical-stats))
      (println "\n*** ALERT: Critical events dropped! ***"))))

;; ============================================================================
;; Scenario Testing
;; ============================================================================

(defn run-normal-load-scenario
  "Simulate normal operation"
  [system duration-sec events-per-sec]
  (println (format "\n=== Normal Load Scenario (%d events/sec for %ds) ==="
                   events-per-sec duration-sec))

  (let [start-time (System/currentTimeMillis)
        total-events (atom 0)]

    ;; Generate events at specified rate
    (dotimes [_ duration-sec]
      (let [events (generate-event-burst events-per-sec)]
        (doseq [event events]
          (route-event system event)
          (swap! total-events inc)))
      (Thread/sleep 1000))

    (println (format "Generated %d events" @total-events))
    (display-buffer-health system)))

(defn run-debug-flood-scenario
  "Simulate debug logging flood"
  [system duration-sec debug-events-per-sec normal-events-per-sec]
  (println (format "\n=== Debug Flood Scenario ==="))
  (println (format "Debug: %d/sec, Normal: %d/sec for %ds"
                   debug-events-per-sec normal-events-per-sec duration-sec))

  (dotimes [_ duration-sec]
    ;; Normal events
    (doseq [event (generate-event-burst normal-events-per-sec)]
      (route-event system event))
    ;; Debug flood
    (doseq [event (generate-debug-flood debug-events-per-sec)]
      (route-event system event))
    (Thread/sleep 1000))

  (display-buffer-health system)

  ;; Verify critical events weren't affected
  (let [critical-stats @(get-in system [:stats :critical])]
    (println "\n=== Isolation Verification ===")
    (println (format "Critical events dropped during flood: %d" (:dropped critical-stats)))
    (when (zero? (:dropped critical-stats))
      (println "SUCCESS: Debug flood did not affect critical buffer"))))

(defn run-security-burst-scenario
  "Simulate security event burst"
  [system event-count]
  (println (format "\n=== Security Burst Scenario (%d events) ===" event-count))

  ;; Generate burst of security events
  (doseq [event (generate-security-events event-count)]
    (route-event system event))

  (display-buffer-health system)

  ;; Verify all were captured
  (let [critical-stats @(get-in system [:stats :critical])]
    (println "\n=== Security Event Capture ===")
    (println (format "Security events submitted: %d" (:submitted critical-stats)))
    (println (format "Security events dropped: %d" (:dropped critical-stats)))
    (when (zero? (:dropped critical-stats))
      (println "SUCCESS: All security events captured"))))

;; ============================================================================
;; Demonstration
;; ============================================================================

(defn demonstrate-priority-routing
  "Demonstrate event priority routing"
  [system]
  (println "\n=== Priority Routing Demonstration ===")
  (println "Routing sample events...\n")

  ;; Create events of each type
  (let [events [{:type EVENT_SECURITY_VIOLATION :uid 1000 :desc "Security violation"}
                {:type EVENT_PROCESS_EXEC :uid 0 :desc "Root process exec"}
                {:type EVENT_RESOURCE_LIMIT :uid 1000 :desc "Resource limit"}
                {:type EVENT_NETWORK_CONNECT :uid 1000 :desc "Network connect"}
                {:type EVENT_FILE_OPEN :uid 1000 :desc "File open"}]]

    (println "EVENT                  UID   SEVERITY    BUFFER")
    (println "====================================================")

    (doseq [e events]
      (let [event (create-event (:type e) SEVERITY_INFO 1234 (:uid e))
            severity (classify-event-severity event)
            buffer (select-buffer severity)]
        (route-event system event)
        (println (format "%-22s %4d  %-10s  %s"
                         (:desc e)
                         (:uid e)
                         (get severity-names severity)
                         (name buffer)))))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the multi-ring buffer lab"
  [& args]
  (let [command (first args)]
    (case command
      "normal"
      (let [system (create-multi-ring-buffer-system)
            duration (or (some-> (second args) Integer/parseInt) 10)
            rate (or (some-> (nth args 2 nil) Integer/parseInt) 1000)]
        (run-normal-load-scenario system duration rate))

      "flood"
      (let [system (create-multi-ring-buffer-system)
            duration (or (some-> (second args) Integer/parseInt) 10)]
        (run-debug-flood-scenario system duration 50000 1000))

      "security"
      (let [system (create-multi-ring-buffer-system)
            count (or (some-> (second args) Integer/parseInt) 1000)]
        (run-security-burst-scenario system count))

      "demo"
      (let [system (create-multi-ring-buffer-system)]
        (demonstrate-priority-routing system))

      ;; Default: full demonstration
      (do
        (println "Lab 13.1: Multi-Ring Buffer System")
        (println "===================================")
        (println "\nUsage:")
        (println "  normal [duration] [rate]  - Normal load scenario")
        (println "  flood [duration]          - Debug flood scenario")
        (println "  security [count]          - Security burst scenario")
        (println "  demo                      - Priority routing demo")
        (println)

        (let [system (create-multi-ring-buffer-system)]
          ;; Demo priority routing
          (demonstrate-priority-routing system)

          ;; Normal load
          (run-normal-load-scenario system 5 1000)

          ;; Debug flood
          (run-debug-flood-scenario system 3 20000 500)

          ;; Security burst
          (run-security-burst-scenario system 100)

          (println "\n=== Key Takeaways ===")
          (println "1. Multiple buffers prevent priority inversion")
          (println "2. Critical events should NEVER be dropped")
          (println "3. Debug floods don't affect critical buffer")
          (println "4. Independent pipelines for different priorities"))))))

;; Run with: clj -M -m lab-13-1-multi-ring-buffer
;; Or:       clj -M -m lab-13-1-multi-ring-buffer flood 10
