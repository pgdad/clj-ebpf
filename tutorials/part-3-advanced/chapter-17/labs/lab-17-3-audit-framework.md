# Lab 17.3: Security Audit Framework

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Create a comprehensive security audit framework for BPF programs and maps, including compliance checks, anomaly detection, and reporting.

## Prerequisites

- Completed Labs 17.1 and 17.2
- Understanding of security auditing concepts
- Familiarity with compliance requirements

## Scenario

Your organization needs to audit BPF deployments for security compliance, detect anomalous behavior, and generate reports for security reviews. This lab builds a framework that automates these tasks.

---

## Part 1: Audit Event Collection

### Step 1.1: Audit Event Types

```clojure
(ns lab-17-3.audit-framework
  (:require [clojure.string :as str]
            [clojure.set :as set])
  (:import [java.time Instant Duration]
           [java.util UUID]))

(def audit-event-types
  #{:program-load
    :program-unload
    :program-attach
    :program-detach
    :map-create
    :map-delete
    :map-access
    :capability-change
    :policy-violation
    :security-alert
    :config-change
    :access-denied})

(defrecord AuditEvent [id timestamp type severity source details])

(defn create-audit-event [type severity source details]
  (->AuditEvent (str (UUID/randomUUID))
                (Instant/now)
                type
                severity
                source
                details))

(def severity-levels
  {:debug 0
   :info 1
   :warning 2
   :error 3
   :critical 4})

(defn severity->string [severity]
  (str/upper-case (name severity)))
```

### Step 1.2: Audit Event Store

```clojure
(defprotocol IAuditStore
  (store-event [this event])
  (query-events [this criteria])
  (get-event-count [this])
  (clear-events [this]))

(defrecord InMemoryAuditStore [events max-events]
  IAuditStore
  (store-event [this event]
    (swap! events (fn [evts]
                    (let [new-evts (conj evts event)]
                      (if (> (count new-evts) max-events)
                        (vec (drop 1 new-evts))
                        new-evts)))))

  (query-events [this criteria]
    (let [{:keys [type severity since until source limit]} criteria
          events @events]
      (cond->> events
        type (filter #(= type (:type %)))
        severity (filter #(>= (severity-levels (:severity %))
                              (severity-levels severity)))
        since (filter #(.isAfter (:timestamp %) since))
        until (filter #(.isBefore (:timestamp %) until))
        source (filter #(= source (:source %)))
        limit (take limit))))

  (get-event-count [this]
    (count @events))

  (clear-events [this]
    (reset! events [])))

(defn create-audit-store [max-events]
  (->InMemoryAuditStore (atom []) max-events))
```

---

## Part 2: Security Checks

### Step 2.1: Check Definitions

```clojure
(def security-checks
  [{:id :check-root-programs
    :name "Root-Owned Programs"
    :description "Detect programs loaded by root"
    :severity :warning
    :check-fn (fn [context]
                (let [root-programs (filter #(= 0 (:uid %))
                                           (:programs context))]
                  {:passed (empty? root-programs)
                   :details {:root-programs (map :name root-programs)}}))}

   {:id :check-map-limits
    :name "Map Entry Limits"
    :description "Ensure all maps have entry limits"
    :severity :error
    :check-fn (fn [context]
                (let [unlimited (filter #(nil? (:max-entries %))
                                       (:maps context))]
                  {:passed (empty? unlimited)
                   :details {:unlimited-maps (map :name unlimited)}}))}

   {:id :check-capabilities
    :name "Minimal Capabilities"
    :description "Check for excessive capabilities"
    :severity :warning
    :check-fn (fn [context]
                (let [caps (:capabilities context)
                      excessive (set/difference caps
                                                #{:cap_bpf :cap_perfmon :cap_net_admin})]
                  {:passed (empty? excessive)
                   :details {:excessive-caps excessive}}))}

   {:id :check-audit-enabled
    :name "Audit Logging"
    :description "Verify audit logging is enabled"
    :severity :critical
    :check-fn (fn [context]
                {:passed (:audit-enabled context)
                 :details {:audit-enabled (:audit-enabled context)}})}

   {:id :check-frozen-config
    :name "Frozen Configuration"
    :description "Ensure config maps are frozen"
    :severity :warning
    :check-fn (fn [context]
                (let [config-maps (filter #(str/includes? (str (:name %)) "config")
                                         (:maps context))
                      unfrozen (filter #(not (:frozen %)) config-maps)]
                  {:passed (empty? unfrozen)
                   :details {:unfrozen-configs (map :name unfrozen)}}))}

   {:id :check-helper-whitelist
    :name "Helper Whitelist"
    :description "Check programs use only approved helpers"
    :severity :error
    :check-fn (fn [context]
                (let [allowed #{:map_lookup_elem :map_update_elem :ktime_get_ns
                               :get_current_pid_tgid :ringbuf_output}
                      programs (:programs context)
                      violations (for [prog programs
                                       helper (:helpers prog)
                                       :when (not (contains? allowed helper))]
                                   {:program (:name prog) :helper helper})]
                  {:passed (empty? violations)
                   :details {:violations violations}}))}])
```

### Step 2.2: Check Execution

```clojure
(defn run-security-check [check context]
  (let [start-time (System/nanoTime)
        result ((:check-fn check) context)
        duration-ms (/ (- (System/nanoTime) start-time) 1e6)]
    {:check-id (:id check)
     :name (:name check)
     :severity (:severity check)
     :passed (:passed result)
     :details (:details result)
     :duration-ms duration-ms}))

(defn run-all-checks [context]
  (let [results (map #(run-security-check % context) security-checks)
        passed (filter :passed results)
        failed (filter (complement :passed) results)]
    {:timestamp (Instant/now)
     :total-checks (count results)
     :passed-count (count passed)
     :failed-count (count failed)
     :results results
     :overall-status (if (empty? failed) :pass :fail)
     :highest-severity (when (seq failed)
                         (->> failed
                              (map :severity)
                              (sort-by severity-levels)
                              last))}))
```

---

## Part 3: Anomaly Detection

### Step 3.1: Baseline Collection

```clojure
(defrecord Baseline [metrics collected-at sample-count])

(defn collect-baseline [audit-store duration-ms sample-interval-ms]
  "Collect baseline metrics over a time period"
  (let [start-time (Instant/now)
        samples (atom [])
        sample-count (atom 0)]

    ;; Collect samples
    (while (< (.toMillis (Duration/between start-time (Instant/now)))
              duration-ms)
      (let [events (query-events audit-store
                                 {:since (.minus (Instant/now)
                                                 (Duration/ofMillis sample-interval-ms))})]
        (swap! samples conj
               {:timestamp (Instant/now)
                :event-count (count events)
                :event-types (frequencies (map :type events))
                :severities (frequencies (map :severity events))})
        (swap! sample-count inc))
      (Thread/sleep sample-interval-ms))

    ;; Calculate baseline statistics
    (let [s @samples
          event-counts (map :event-count s)
          avg-events (/ (reduce + event-counts) (count event-counts))
          type-freqs (apply merge-with + (map :event-types s))]
      (->Baseline
        {:avg-events-per-interval avg-events
         :max-events-per-interval (apply max event-counts)
         :event-type-distribution type-freqs
         :sample-interval-ms sample-interval-ms}
        (Instant/now)
        @sample-count))))
```

### Step 3.2: Anomaly Detection

```clojure
(def anomaly-thresholds
  {:event-rate-multiplier 3.0      ; 3x normal rate
   :new-event-type-severity :warning
   :severity-escalation-threshold 2 ; 2+ high-severity events
   :rapid-changes-threshold 10})    ; 10 changes in short period

(defn detect-event-rate-anomaly [baseline current-events interval-ms]
  (let [expected-rate (get-in baseline [:metrics :avg-events-per-interval])
        current-rate (count current-events)
        threshold (* expected-rate (:event-rate-multiplier anomaly-thresholds))]
    (when (> current-rate threshold)
      {:type :high-event-rate
       :severity :warning
       :details {:expected expected-rate
                 :actual current-rate
                 :threshold threshold}})))

(defn detect-new-event-types [baseline current-events]
  (let [known-types (set (keys (get-in baseline [:metrics :event-type-distribution])))
        current-types (set (map :type current-events))
        new-types (set/difference current-types known-types)]
    (when (seq new-types)
      {:type :new-event-types
       :severity (:new-event-type-severity anomaly-thresholds)
       :details {:new-types new-types}})))

(defn detect-severity-escalation [current-events]
  (let [high-severity (filter #(>= (severity-levels (:severity %))
                                   (severity-levels :error))
                              current-events)]
    (when (>= (count high-severity)
              (:severity-escalation-threshold anomaly-thresholds))
      {:type :severity-escalation
       :severity :error
       :details {:high-severity-count (count high-severity)
                 :events (map :id high-severity)}})))

(defn detect-rapid-changes [audit-store time-window-ms]
  (let [recent (query-events audit-store
                            {:since (.minus (Instant/now)
                                           (Duration/ofMillis time-window-ms))
                             :type :config-change})
        change-count (count recent)]
    (when (>= change-count (:rapid-changes-threshold anomaly-thresholds))
      {:type :rapid-config-changes
       :severity :warning
       :details {:change-count change-count
                 :time-window-ms time-window-ms}})))

(defn run-anomaly-detection [audit-store baseline]
  (let [interval-ms (get-in baseline [:metrics :sample-interval-ms])
        recent-events (query-events audit-store
                                    {:since (.minus (Instant/now)
                                                   (Duration/ofMillis interval-ms))})
        anomalies (remove nil?
                   [(detect-event-rate-anomaly baseline recent-events interval-ms)
                    (detect-new-event-types baseline recent-events)
                    (detect-severity-escalation recent-events)
                    (detect-rapid-changes audit-store 60000)])]
    {:timestamp (Instant/now)
     :anomalies anomalies
     :anomaly-count (count anomalies)}))
```

---

## Part 4: Compliance Reporting

### Step 4.1: Report Generation

```clojure
(defn generate-compliance-report [check-results anomaly-results audit-store]
  {:report-id (str (UUID/randomUUID))
   :generated-at (Instant/now)
   :summary {:total-checks (:total-checks check-results)
             :passed-checks (:passed-count check-results)
             :failed-checks (:failed-count check-results)
             :overall-status (:overall-status check-results)
             :anomalies-detected (:anomaly-count anomaly-results)}
   :security-checks (:results check-results)
   :anomalies (:anomalies anomaly-results)
   :audit-summary {:total-events (get-event-count audit-store)
                   :event-types (frequencies
                                  (map :type (query-events audit-store {})))}})

(defn format-check-result [result]
  (format "  [%s] %s (%s)\n      %s"
          (if (:passed result) "PASS" "FAIL")
          (:name result)
          (name (:severity result))
          (if (:passed result)
            "OK"
            (str "Issues: " (:details result)))))

(defn print-compliance-report [report]
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "         SECURITY COMPLIANCE REPORT")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (println (format "Report ID: %s" (:report-id report)))
  (println (format "Generated: %s" (:generated-at report)))

  (println "\n--- Summary ---\n")
  (let [s (:summary report)]
    (println (format "Overall Status: %s"
                     (str/upper-case (name (:overall-status s)))))
    (println (format "Checks: %d passed, %d failed"
                     (:passed-checks s) (:failed-checks s)))
    (println (format "Anomalies Detected: %d" (:anomalies-detected s))))

  (println "\n--- Security Checks ---\n")
  (doseq [result (:security-checks report)]
    (println (format-check-result result)))

  (when (seq (:anomalies report))
    (println "\n--- Anomalies ---\n")
    (doseq [anomaly (:anomalies report)]
      (println (format "  [%s] %s"
                       (str/upper-case (name (:severity anomaly)))
                       (name (:type anomaly))))
      (println (format "      Details: %s" (:details anomaly)))))

  (println "\n--- Audit Event Summary ---\n")
  (let [s (:audit-summary report)]
    (println (format "  Total events: %d" (:total-events s)))
    (println "  By type:")
    (doseq [[type count] (:event-types s)]
      (println (format "    %s: %d" (name type) count))))

  (println "\n" (apply str (repeat 60 "=")) "\n"))
```

### Step 4.2: Export Formats

```clojure
(defn export-report-json [report]
  "Export report as JSON string"
  (pr-str report))  ; Simplified - use cheshire in production

(defn export-report-csv [report]
  "Export security checks as CSV"
  (let [header "check_id,name,severity,passed,details"
        rows (for [r (:security-checks report)]
               (str/join ","
                 [(:check-id r)
                  (str "\"" (:name r) "\"")
                  (:severity r)
                  (:passed r)
                  (str "\"" (:details r) "\"")]))]
    (str/join "\n" (cons header rows))))
```

---

## Part 5: Continuous Monitoring

### Step 5.1: Audit Monitor

```clojure
(defn create-audit-monitor [audit-store baseline check-interval-ms]
  (let [running (atom true)
        alerts (atom [])]
    {:start
     (fn []
       (future
         (while @running
           ;; Run anomaly detection
           (let [anomalies (run-anomaly-detection audit-store baseline)]
             (when (seq (:anomalies anomalies))
               (doseq [anomaly (:anomalies anomalies)]
                 (swap! alerts conj
                        {:timestamp (Instant/now)
                         :anomaly anomaly})
                 (println (format "[ALERT] %s: %s"
                                  (str/upper-case (name (:severity anomaly)))
                                  (name (:type anomaly)))))))
           (Thread/sleep check-interval-ms))))

     :stop
     (fn [] (reset! running false))

     :get-alerts
     (fn [] @alerts)

     :clear-alerts
     (fn [] (reset! alerts []))}))

(defn start-continuous-audit [audit-store context check-interval-ms]
  "Start continuous security auditing"
  (let [baseline (->Baseline
                   {:avg-events-per-interval 10
                    :max-events-per-interval 50
                    :event-type-distribution {:program-load 5
                                             :map-access 20
                                             :config-change 2}
                    :sample-interval-ms check-interval-ms}
                   (Instant/now)
                   100)
        monitor (create-audit-monitor audit-store baseline check-interval-ms)]

    (println "Starting continuous audit monitoring...")
    ((:start monitor))

    monitor))
```

### Step 5.2: Alert Handlers

```clojure
(def alert-handlers
  {:log (fn [alert]
          (println (format "[%s] ALERT: %s - %s"
                          (:timestamp alert)
                          (name (get-in alert [:anomaly :type]))
                          (get-in alert [:anomaly :details]))))

   :email (fn [alert]
            ;; Simulated email sending
            (println (format "Sending email alert: %s"
                            (get-in alert [:anomaly :type]))))

   :webhook (fn [alert]
              ;; Simulated webhook
              (println (format "Sending webhook: %s"
                              (get-in alert [:anomaly :type]))))})

(defn handle-alert [alert handler-types]
  (doseq [handler-type handler-types]
    (when-let [handler (get alert-handlers handler-type)]
      (handler alert))))
```

---

## Part 6: Exercises

### Exercise 1: Custom Security Check

Add a custom security check:

```clojure
(defn exercise-custom-check []
  ;; TODO: Implement custom security check
  ;; 1. Define check criteria
  ;; 2. Implement check function
  ;; 3. Add to security-checks list
  ;; 4. Test with sample context
  )
```

### Exercise 2: Historical Analysis

Implement historical trend analysis:

```clojure
(defn exercise-historical-analysis []
  ;; TODO: Implement historical analysis
  ;; 1. Track check results over time
  ;; 2. Calculate compliance trends
  ;; 3. Identify recurring issues
  ;; 4. Generate trend reports
  )
```

### Exercise 3: Integration with SIEM

Build SIEM integration:

```clojure
(defn exercise-siem-integration []
  ;; TODO: Implement SIEM integration
  ;; 1. Format events for SIEM ingestion
  ;; 2. Support multiple SIEM formats (CEF, LEEF)
  ;; 3. Implement batch sending
  ;; 4. Handle connection failures
  )
```

---

## Part 7: Testing Your Implementation

### Test Script

```clojure
(defn test-audit-store []
  (println "Testing audit store...")

  (let [store (create-audit-store 100)]
    ;; Test storing events
    (store-event store (create-audit-event :program-load :info "test" {}))
    (store-event store (create-audit-event :map-access :debug "test" {}))

    (assert (= 2 (get-event-count store)) "Should have 2 events")

    ;; Test querying
    (let [results (query-events store {:type :program-load})]
      (assert (= 1 (count results)) "Should find 1 program-load event"))

    ;; Test clearing
    (clear-events store)
    (assert (= 0 (get-event-count store)) "Should have 0 events after clear")

    (println "Audit store tests passed!")))

(defn test-security-checks []
  (println "Testing security checks...")

  (let [context {:programs [{:name "prog1" :uid 1000 :helpers [:map_lookup_elem]}
                            {:name "prog2" :uid 0 :helpers [:map_lookup_elem]}]
                 :maps [{:name "stats" :max-entries 1000}
                        {:name "config" :max-entries 100 :frozen true}]
                 :capabilities #{:cap_bpf}
                 :audit-enabled true}
        results (run-all-checks context)]

    (assert (number? (:total-checks results)) "Should have total checks")
    (assert (number? (:passed-count results)) "Should have passed count")

    ;; Root programs check should warn
    (let [root-check (first (filter #(= :check-root-programs (:check-id %))
                                    (:results results)))]
      (assert (not (:passed root-check)) "Root check should fail"))

    (println "Security check tests passed!")))

(defn test-reporting ()
  (println "Testing reporting...")

  (let [store (create-audit-store 100)
        context {:programs [] :maps [] :capabilities #{:cap_bpf} :audit-enabled true}
        check-results (run-all-checks context)
        anomaly-results {:timestamp (Instant/now) :anomalies [] :anomaly-count 0}
        report (generate-compliance-report check-results anomaly-results store)]

    (assert (some? (:report-id report)) "Should have report ID")
    (assert (some? (:summary report)) "Should have summary")

    (println "Reporting tests passed!")))

(defn run-all-tests []
  (println "\nLab 17.3: Security Audit Framework")
  (println "===================================\n")

  (test-audit-store)
  (test-security-checks)
  (test-reporting)

  ;; Demo
  (println "\n=== Demo: Complete Audit Workflow ===\n")

  (let [store (create-audit-store 1000)
        context {:programs [{:name "monitor" :uid 1000 :helpers [:map_lookup_elem :ktime_get_ns]}
                            {:name "filter" :uid 1000 :helpers [:map_lookup_elem]}]
                 :maps [{:name "stats" :type :percpu_array :max-entries 256}
                        {:name "config" :type :hash :max-entries 100 :frozen false}]
                 :capabilities #{:cap_bpf :cap_perfmon}
                 :audit-enabled true}]

    ;; Simulate some audit events
    (doseq [_ (range 10)]
      (store-event store (create-audit-event :map-access :debug "monitor" {:key "stats"})))
    (store-event store (create-audit-event :program-load :info "loader" {:name "monitor"}))
    (store-event store (create-audit-event :config-change :warning "admin" {:key "rate-limit"}))

    ;; Run checks
    (let [check-results (run-all-checks context)
          anomaly-results {:timestamp (Instant/now) :anomalies [] :anomaly-count 0}
          report (generate-compliance-report check-results anomaly-results store)]

      (print-compliance-report report)))

  (println "\n=== All Tests Complete ==="))
```

---

## Summary

In this lab you learned:
- Building an audit event collection system
- Implementing security compliance checks
- Detecting anomalies in BPF operations
- Generating compliance reports
- Continuous security monitoring

## Next Steps

- Integrate this framework with your BPF deployments
- Add custom checks for your security requirements
- Set up alerting and SIEM integration
- Implement historical trend analysis
