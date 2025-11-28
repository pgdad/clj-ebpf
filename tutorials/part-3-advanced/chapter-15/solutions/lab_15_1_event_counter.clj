;; Lab 15.1 Solution: Event Counter Dashboard
;; Real-time event counter dashboard using map-entry-ref and map-watch-changes
;;
;; Learning Goals:
;; - Use map-entry-ref for atom-like counter access
;; - Use map-watch-changes to detect value changes
;; - Combine multiple reference types for a complete solution

(ns lab-15-1-event-counter
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils])
  (:import [java.nio ByteBuffer ByteOrder]
           [java.util.concurrent.atomic AtomicLong]
           [java.time LocalTime]))

;; ============================================================================
;; Event Type Constants
;; ============================================================================

(def EVENT-SYSCALL 1)
(def EVENT-PACKET 2)
(def EVENT-FILE-OPEN 3)
(def EVENT-FILE-CLOSE 4)

(def event-names
  {EVENT-SYSCALL "Syscalls"
   EVENT-PACKET "Packets"
   EVENT-FILE-OPEN "File Opens"
   EVENT-FILE-CLOSE "File Closes"})

;; ============================================================================
;; Simulated Map Entry Reference
;; ============================================================================
;; Since we're simulating without actual BPF, we create a mock implementation
;; that matches the clj-ebpf.refs API

(defrecord MockMapEntryRef [store key validator]
  clojure.lang.IDeref
  (deref [_]
    (get @store key 0))

  clojure.lang.IAtom
  (swap [this f]
    (swap! store update key (fn [v] (f (or v 0)))))
  (swap [this f x]
    (swap! store update key (fn [v] (f (or v 0) x))))
  (swap [this f x y]
    (swap! store update key (fn [v] (f (or v 0) x y))))
  (swap [this f x y more]
    (swap! store update key (fn [v] (apply f (or v 0) x y more))))
  (compareAndSet [this oldval newval]
    (let [current (get @store key)]
      (if (= current oldval)
        (do (swap! store assoc key newval) true)
        false)))
  (reset [this newval]
    (when (and validator (not (validator newval)))
      (throw (IllegalStateException. "Validator rejected value")))
    (swap! store assoc key newval)
    newval)

  java.io.Closeable
  (close [_]
    nil))

(defn map-entry-ref
  "Create a mock map-entry-ref for a key"
  [store key & {:keys [validator]}]
  (->MockMapEntryRef store key validator))

;; ============================================================================
;; Simulated Map Watch Changes
;; ============================================================================

(defrecord MockMapWatchChanges [store key last-value running]
  clojure.lang.IBlockingDeref
  (deref [_ timeout-ms timeout-val]
    (let [start-time (System/currentTimeMillis)
          check-interval 50]
      (loop []
        (let [current (get @store key)
              elapsed (- (System/currentTimeMillis) start-time)]
          (cond
            ;; Value changed
            (not= current @last-value)
            (do
              (reset! last-value current)
              current)

            ;; Timeout
            (>= elapsed timeout-ms)
            timeout-val

            ;; Not running
            (not @running)
            timeout-val

            ;; Keep checking
            :else
            (do
              (Thread/sleep check-interval)
              (recur)))))))

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  java.io.Closeable
  (close [_]
    (reset! running false)))

(defn map-watch-changes
  "Create a watcher that blocks until value changes"
  [store key]
  (let [initial (get @store key)]
    (->MockMapWatchChanges store key (atom initial) (atom true))))

;; ============================================================================
;; Statistics Store
;; ============================================================================

(def stats-store
  "Simulated BPF map store"
  (atom {}))

(defn init-counters!
  "Initialize all counters to zero"
  []
  (doseq [event-type [EVENT-SYSCALL EVENT-PACKET EVENT-FILE-OPEN EVENT-FILE-CLOSE]]
    (swap! stats-store assoc event-type 0))
  (println "Counters initialized"))

(defn create-counter-refs
  "Create atom-like references to each counter"
  []
  {:syscalls (map-entry-ref stats-store EVENT-SYSCALL)
   :packets (map-entry-ref stats-store EVENT-PACKET)
   :file-opens (map-entry-ref stats-store EVENT-FILE-OPEN)
   :file-closes (map-entry-ref stats-store EVENT-FILE-CLOSE)})

(defn close-counter-refs
  "Clean up all counter references"
  [refs]
  (doseq [[_ ref] refs]
    (.close ref)))

;; ============================================================================
;; Dashboard Display
;; ============================================================================

(defn display-counters
  "Display current counter values"
  [refs]
  (println "\n=== Event Statistics ===")
  (println (format "%-14s %10d" "Syscalls:" @(:syscalls refs)))
  (println (format "%-14s %10d" "Packets:" @(:packets refs)))
  (println (format "%-14s %10d" "File Opens:" @(:file-opens refs)))
  (println (format "%-14s %10d" "File Closes:" @(:file-closes refs)))
  (println "========================"))

(defn reset-all-counters!
  "Reset all counters to zero"
  [refs]
  (doseq [[name ref] refs]
    (reset! ref 0))
  (println "All counters reset"))

(defn increment-counter!
  "Increment a specific counter"
  [refs counter-key]
  (swap! (get refs counter-key) inc))

;; ============================================================================
;; Rate Calculator (Exercise 1)
;; ============================================================================

(defn calculate-rate
  "Calculate events per second for a counter"
  [refs counter-key sample-duration-ms]
  (let [initial-value @(get refs counter-key)
        _ (Thread/sleep sample-duration-ms)
        final-value @(get refs counter-key)
        delta (- final-value initial-value)
        rate (/ (* delta 1000.0) sample-duration-ms)]
    {:counter counter-key
     :initial initial-value
     :final final-value
     :delta delta
     :duration-ms sample-duration-ms
     :rate-per-sec rate}))

(defn display-rates
  "Calculate and display rates for all counters"
  [refs sample-duration-ms]
  (println (format "\n=== Event Rates (sampled over %dms) ===" sample-duration-ms))
  (doseq [counter-key [:syscalls :packets :file-opens :file-closes]]
    (let [result (calculate-rate refs counter-key sample-duration-ms)]
      (println (format "%-14s %.2f events/sec"
                       (str (name counter-key) ":")
                       (:rate-per-sec result))))))

;; ============================================================================
;; Threshold Alerts (Exercise 2)
;; ============================================================================

(defn watch-with-threshold
  "Watch a counter and call alert-fn when it exceeds threshold"
  [refs counter-key threshold alert-fn duration-ms]
  (let [event-type (case counter-key
                     :syscalls EVENT-SYSCALL
                     :packets EVENT-PACKET
                     :file-opens EVENT-FILE-OPEN
                     :file-closes EVENT-FILE-CLOSE)
        watcher (map-watch-changes stats-store event-type)
        start-time (System/currentTimeMillis)]
    (future
      (try
        (loop []
          (let [elapsed (- (System/currentTimeMillis) start-time)]
            (when (< elapsed duration-ms)
              (let [remaining (- duration-ms elapsed)
                    new-value (.deref watcher remaining :timeout)]
                (when (and (not= new-value :timeout)
                           (> new-value threshold))
                  (alert-fn counter-key new-value threshold))
                (when (not= new-value :timeout)
                  (recur))))))
        (finally
          (.close watcher))))
    watcher))

;; ============================================================================
;; Rolling Average (Exercise 3)
;; ============================================================================

(defn create-rolling-average-tracker
  "Track rolling average of counter increments"
  [refs counter-key window-size sample-interval-ms]
  (let [deltas (atom [])
        running (atom true)]
    (future
      (loop [last-value @(get refs counter-key)]
        (when @running
          (Thread/sleep sample-interval-ms)
          (let [current-value @(get refs counter-key)
                delta (- current-value last-value)]
            (swap! deltas (fn [ds]
                            (take window-size (conj ds delta))))
            (recur current-value)))))
    {:stop (fn [] (reset! running false))
     :average (fn []
                (let [ds @deltas]
                  (if (empty? ds)
                    0.0
                    (/ (reduce + ds) (double (count ds))))))}))

;; ============================================================================
;; Dashboard Controllers
;; ============================================================================

(defn start-dashboard
  "Start a dashboard that polls all counters periodically"
  [refs update-interval-ms]
  (let [running (atom true)]
    (future
      (while @running
        (display-counters refs)
        (Thread/sleep update-interval-ms)))
    (fn [] (reset! running false))))

(defn start-change-watcher
  "Start a background watcher for a specific counter"
  [refs counter-key]
  (let [running (atom true)
        event-type (case counter-key
                     :syscalls EVENT-SYSCALL
                     :packets EVENT-PACKET
                     :file-opens EVENT-FILE-OPEN
                     :file-closes EVENT-FILE-CLOSE)
        watcher (map-watch-changes stats-store event-type)]
    (future
      (try
        (while @running
          (let [new-value (.deref watcher 1000 :timeout)]
            (when (not= new-value :timeout)
              (println (format "[%s] %s changed: %d"
                               (LocalTime/now)
                               (name counter-key)
                               new-value)))))
        (finally
          (.close watcher))))
    (fn [] (reset! running false))))

;; ============================================================================
;; Event Simulator
;; ============================================================================

(defn simulate-events
  "Simulate BPF events updating counters"
  [refs duration-ms events-per-sec]
  (let [interval-ms (/ 1000 events-per-sec)
        end-time (+ (System/currentTimeMillis) duration-ms)]
    (future
      (while (< (System/currentTimeMillis) end-time)
        (let [counter-key (rand-nth [:syscalls :packets :file-opens :file-closes])
              increment (+ 1 (rand-int 5))]
          (swap! (get refs counter-key) + increment))
        (Thread/sleep (long interval-ms))))))

;; ============================================================================
;; Testing
;; ============================================================================

(defn test-counter-refs
  "Test map-entry-ref functionality"
  []
  (println "\n=== Testing map-entry-ref ===")

  (init-counters!)
  (let [refs (create-counter-refs)]
    (try
      ;; Test read
      (assert (= 0 @(:syscalls refs)) "Initial value should be 0")
      (println "Initial read: PASS")

      ;; Test reset!
      (reset! (:syscalls refs) 100)
      (assert (= 100 @(:syscalls refs)) "Value should be 100 after reset!")
      (println "reset!: PASS")

      ;; Test swap!
      (swap! (:syscalls refs) inc)
      (assert (= 101 @(:syscalls refs)) "Value should be 101 after inc")
      (println "swap! inc: PASS")

      (swap! (:syscalls refs) + 10)
      (assert (= 111 @(:syscalls refs)) "Value should be 111 after +10")
      (println "swap! + 10: PASS")

      ;; Test compare-and-set!
      (assert (compare-and-set! (:syscalls refs) 111 200)
              "CAS should succeed")
      (println "compare-and-set! success: PASS")

      (assert (not (compare-and-set! (:syscalls refs) 111 300))
              "CAS should fail with wrong expected value")
      (println "compare-and-set! fail: PASS")

      (println "\nAll tests passed!")

      (finally
        (close-counter-refs refs)))))

;; ============================================================================
;; Main Demo
;; ============================================================================

(defn run-dashboard
  "Run the complete event counter dashboard"
  []
  (println "=== Event Counter Dashboard Demo ===\n")

  (init-counters!)
  (let [refs (create-counter-refs)]
    (try
      ;; Start dashboard display
      (let [stop-dashboard (start-dashboard refs 2000)

            ;; Start change watchers
            stop-syscall-watcher (start-change-watcher refs :syscalls)
            stop-packet-watcher (start-change-watcher refs :packets)

            ;; Start event simulator
            _ (simulate-events refs 8000 10)]

        (println "\nDashboard running...")
        (println "Simulating events for 8 seconds...")

        ;; Let it run
        (Thread/sleep 8000)

        ;; Final display
        (display-counters refs)

        ;; Cleanup
        (stop-dashboard)
        (stop-syscall-watcher)
        (stop-packet-watcher)

        (println "\nDashboard stopped."))

      (finally
        (close-counter-refs refs)))))

(defn demonstrate-threshold-alerts
  "Demonstrate threshold alerting"
  []
  (println "\n=== Threshold Alert Demo ===\n")

  (init-counters!)
  (let [refs (create-counter-refs)
        alert-count (atom 0)]
    (try
      ;; Set up threshold alert
      (watch-with-threshold
       refs :syscalls 50
       (fn [counter-key value threshold]
         (swap! alert-count inc)
         (println (format "ALERT: %s exceeded threshold! Value: %d > %d"
                          (name counter-key) value threshold)))
       5000)

      ;; Rapidly increment to trigger alerts
      (dotimes [_ 20]
        (swap! (:syscalls refs) + 5)
        (Thread/sleep 100))

      (Thread/sleep 500)
      (println (format "\nTotal alerts: %d" @alert-count))

      (finally
        (close-counter-refs refs)))))

(defn demonstrate-rolling-average
  "Demonstrate rolling average tracking"
  []
  (println "\n=== Rolling Average Demo ===\n")

  (init-counters!)
  (let [refs (create-counter-refs)]
    (try
      ;; Start rolling average tracker
      (let [tracker (create-rolling-average-tracker refs :packets 10 100)]

        ;; Generate varying events
        (dotimes [i 50]
          (swap! (:packets refs) + (+ 1 (rand-int 10)))
          (when (zero? (mod i 10))
            (println (format "[%d] Rolling average: %.2f"
                             i
                             ((:average tracker)))))
          (Thread/sleep 100))

        ;; Stop tracker
        ((:stop tracker))

        (println (format "\nFinal rolling average: %.2f" ((:average tracker)))))

      (finally
        (close-counter-refs refs)))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the event counter dashboard lab"
  [& args]
  (let [command (first args)]
    (case command
      "test"
      (test-counter-refs)

      "dashboard"
      (run-dashboard)

      "threshold"
      (demonstrate-threshold-alerts)

      "rolling"
      (demonstrate-rolling-average)

      ;; Default: full demo
      (do
        (println "Lab 15.1: Event Counter Dashboard")
        (println "==================================")
        (println "\nUsage:")
        (println "  test       - Run unit tests")
        (println "  dashboard  - Run live dashboard demo")
        (println "  threshold  - Demo threshold alerts")
        (println "  rolling    - Demo rolling averages")
        (println)

        ;; Run tests first
        (test-counter-refs)

        ;; Then run demos
        (run-dashboard)
        (demonstrate-threshold-alerts)
        (demonstrate-rolling-average)

        (println "\n=== Key Takeaways ===")
        (println "1. map-entry-ref provides atom-like access to BPF map entries")
        (println "2. @, reset!, swap!, compare-and-set! work as expected")
        (println "3. map-watch-changes enables reactive updates")
        (println "4. Combine references for complete monitoring solutions")))))

;; Run with: clj -M -m lab-15-1-event-counter
;; Or:       clj -M -m lab-15-1-event-counter dashboard
