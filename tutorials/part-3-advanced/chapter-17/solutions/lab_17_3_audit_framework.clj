;; Lab 17.3 Solution: Security Audit Framework
;; Create a comprehensive security audit framework for BPF programs
;;
;; Learning Goals:
;; - Build an audit event collection system
;; - Implement security compliance checks
;; - Detect anomalies in BPF operations
;; - Generate compliance reports

(ns lab-17-3-audit-framework
  (:require [clojure.string :as str]
            [clojure.set :as set])
  (:import [java.time Instant Duration]
           [java.util UUID]))

;; ============================================================================
;; Audit Event Types and Severity
;; ============================================================================

(def audit-event-types
  "Types of audit events"
  #{:program-load
    :program-unload
    :program-attach
    :program-detach
    :map-create
    :map-delete
    :map-access
    :map-update
    :capability-change
    :policy-violation
    :security-alert
    :config-change
    :access-denied
    :authentication
    :anomaly-detected})

(def severity-levels
  "Severity levels with numeric values for comparison"
  {:debug    0
   :info     1
   :warning  2
   :error    3
   :critical 4})

(defn severity->string [severity]
  (str/upper-case (name severity)))

(defn severity>=
  "Check if severity1 >= severity2"
  [severity1 severity2]
  (>= (get severity-levels severity1 0)
      (get severity-levels severity2 0)))

;; ============================================================================
;; Audit Event Records
;; ============================================================================

(defrecord AuditEvent [id timestamp type severity source details])

(defn create-audit-event
  "Create a new audit event"
  [event-type severity source details]
  (->AuditEvent
    (str (UUID/randomUUID))
    (Instant/now)
    event-type
    severity
    source
    details))

(defn event->map
  "Convert audit event to plain map"
  [event]
  {:id (:id event)
   :timestamp (str (:timestamp event))
   :type (:type event)
   :severity (:severity event)
   :source (:source event)
   :details (:details event)})

;; ============================================================================
;; Audit Event Store
;; ============================================================================

(defprotocol IAuditStore
  "Protocol for audit event storage"
  (store-event [this event])
  (query-events [this criteria])
  (get-event-count [this])
  (get-events-since [this timestamp])
  (clear-events [this]))

(defrecord InMemoryAuditStore [events max-events]
  IAuditStore
  (store-event [this event]
    (swap! events (fn [evts]
                    (let [new-evts (conj evts event)]
                      (if (> (count new-evts) max-events)
                        (vec (drop (- (count new-evts) max-events) new-evts))
                        new-evts))))
    event)

  (query-events [this criteria]
    (let [{:keys [type severity since until source limit offset]} criteria
          evts @events]
      (cond->> evts
        type (filter #(= type (:type %)))
        severity (filter #(severity>= (:severity %) severity))
        since (filter #(.isAfter (:timestamp %) since))
        until (filter #(.isBefore (:timestamp %) until))
        source (filter #(= source (:source %)))
        offset (drop offset)
        limit (take limit))))

  (get-event-count [this]
    (count @events))

  (get-events-since [this timestamp]
    (filter #(.isAfter (:timestamp %) timestamp) @events))

  (clear-events [this]
    (reset! events [])))

(defn create-audit-store
  "Create a new in-memory audit store"
  [max-events]
  (->InMemoryAuditStore (atom []) max-events))

;; ============================================================================
;; Security Checks
;; ============================================================================

(def security-checks
  "Security check definitions"
  [{:id :check-root-programs
    :name "Root-Owned Programs"
    :description "Detect programs loaded by root"
    :severity :warning
    :check-fn (fn [context]
                (let [root-programs (filter #(= 0 (:uid %))
                                            (:programs context))]
                  {:passed (empty? root-programs)
                   :details {:root-programs (map :name root-programs)
                             :count (count root-programs)}}))}

   {:id :check-map-limits
    :name "Map Entry Limits"
    :description "Ensure all maps have reasonable entry limits"
    :severity :error
    :check-fn (fn [context]
                (let [unlimited (filter #(nil? (:max-entries %))
                                        (:maps context))
                      excessive (filter #(and (:max-entries %)
                                              (> (:max-entries %) 10000000))
                                        (:maps context))]
                  {:passed (and (empty? unlimited) (empty? excessive))
                   :details {:unlimited-maps (map :name unlimited)
                             :excessive-maps (map :name excessive)}}))}

   {:id :check-capabilities
    :name "Minimal Capabilities"
    :description "Check for excessive capabilities"
    :severity :warning
    :check-fn (fn [context]
                (let [caps (:capabilities context)
                      allowed #{:cap_bpf :cap_perfmon :cap_net_admin}
                      excessive (set/difference caps allowed)]
                  {:passed (empty? excessive)
                   :details {:current-caps caps
                             :allowed-caps allowed
                             :excessive-caps excessive}}))}

   {:id :check-audit-enabled
    :name "Audit Logging"
    :description "Verify audit logging is enabled"
    :severity :critical
    :check-fn (fn [context]
                {:passed (:audit-enabled context)
                 :details {:audit-enabled (:audit-enabled context)}})}

   {:id :check-frozen-config
    :name "Frozen Configuration"
    :description "Ensure config maps are frozen after initialization"
    :severity :warning
    :check-fn (fn [context]
                (let [config-maps (filter #(str/includes? (str (:name %)) "config")
                                          (:maps context))
                      unfrozen (filter #(not (:frozen %)) config-maps)]
                  {:passed (empty? unfrozen)
                   :details {:config-maps (count config-maps)
                             :unfrozen-configs (map :name unfrozen)}}))}

   {:id :check-helper-whitelist
    :name "Helper Whitelist"
    :description "Check programs use only approved helpers"
    :severity :error
    :check-fn (fn [context]
                (let [allowed #{:map_lookup_elem :map_update_elem :map_delete_elem
                                :ktime_get_ns :get_current_pid_tgid :ringbuf_output
                                :ringbuf_reserve :ringbuf_submit :perf_event_output
                                :get_smp_processor_id :get_current_comm}
                      programs (:programs context)
                      violations (for [prog programs
                                       helper (or (:helpers prog) [])
                                       :when (not (contains? allowed helper))]
                                   {:program (:name prog) :helper helper})]
                  {:passed (empty? violations)
                   :details {:violations violations
                             :allowed-helpers allowed}}))}

   {:id :check-program-verification
    :name "Program Verification Status"
    :description "Ensure all programs passed verifier"
    :severity :critical
    :check-fn (fn [context]
                (let [unverified (filter #(not (:verified %))
                                         (:programs context))]
                  {:passed (empty? unverified)
                   :details {:unverified-programs (map :name unverified)}}))}

   {:id :check-attachment-points
    :name "Attachment Point Review"
    :description "Review programs attached to sensitive kernel points"
    :severity :warning
    :check-fn (fn [context]
                (let [sensitive-points #{"sys_enter" "sys_exit" "kprobe/do_execve"
                                         "kprobe/security_" "raw_tracepoint"}
                      programs (:programs context)
                      sensitive-attachments
                      (for [prog programs
                            :when (some #(str/includes? (str (:attach-point prog)) %)
                                        sensitive-points)]
                        {:program (:name prog)
                         :attach-point (:attach-point prog)})]
                  {:passed (empty? sensitive-attachments)
                   :details {:sensitive-attachments sensitive-attachments}}))}])

(defn run-security-check
  "Execute a single security check"
  [check context]
  (let [start-time (System/nanoTime)
        result ((:check-fn check) context)
        duration-ms (/ (- (System/nanoTime) start-time) 1e6)]
    {:check-id (:id check)
     :name (:name check)
     :description (:description check)
     :severity (:severity check)
     :passed (:passed result)
     :details (:details result)
     :duration-ms duration-ms}))

(defn run-all-checks
  "Run all security checks against a context"
  [context]
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
                              (sort-by severity-levels >)
                              first))}))

;; ============================================================================
;; Anomaly Detection
;; ============================================================================

(defrecord Baseline [metrics collected-at sample-count])

(def anomaly-thresholds
  "Thresholds for anomaly detection"
  {:event-rate-multiplier     3.0    ; 3x normal rate triggers alert
   :new-event-type-severity   :warning
   :severity-escalation-threshold 2  ; 2+ high-severity events
   :rapid-changes-threshold   10     ; 10 changes in short period
   :unusual-hour-threshold    5})    ; Events in unusual hours

(defn create-baseline
  "Create a baseline from historical data"
  [metrics sample-count]
  (->Baseline metrics (Instant/now) sample-count))

(defn collect-baseline
  "Collect baseline metrics from audit store"
  [audit-store duration-ms sample-interval-ms]
  (let [start-time (Instant/now)
        samples (atom [])
        deadline (.plusMillis start-time duration-ms)]

    ;; Collect samples over time
    (while (.isBefore (Instant/now) deadline)
      (let [window-start (.minus (Instant/now)
                                  (Duration/ofMillis sample-interval-ms))
            events (get-events-since audit-store window-start)]
        (swap! samples conj
               {:timestamp (Instant/now)
                :event-count (count events)
                :event-types (frequencies (map :type events))
                :severities (frequencies (map :severity events))}))
      (Thread/sleep sample-interval-ms))

    ;; Calculate baseline statistics
    (let [s @samples
          event-counts (map :event-count s)
          avg-events (if (seq event-counts)
                       (/ (reduce + event-counts) (count event-counts))
                       0)
          type-freqs (apply merge-with + (map :event-types s))]
      (create-baseline
        {:avg-events-per-interval avg-events
         :max-events-per-interval (if (seq event-counts)
                                    (apply max event-counts)
                                    0)
         :event-type-distribution type-freqs
         :sample-interval-ms sample-interval-ms}
        (count s)))))

(defn detect-event-rate-anomaly
  "Detect if event rate exceeds baseline"
  [baseline current-events]
  (let [expected-rate (get-in baseline [:metrics :avg-events-per-interval] 0)
        current-rate (count current-events)
        threshold (* expected-rate (:event-rate-multiplier anomaly-thresholds))]
    (when (and (pos? expected-rate) (> current-rate threshold))
      {:type :high-event-rate
       :severity :warning
       :details {:expected expected-rate
                 :actual current-rate
                 :threshold threshold
                 :excess-factor (/ current-rate expected-rate)}})))

(defn detect-new-event-types
  "Detect previously unseen event types"
  [baseline current-events]
  (let [known-types (set (keys (get-in baseline [:metrics :event-type-distribution])))
        current-types (set (map :type current-events))
        new-types (set/difference current-types known-types)]
    (when (seq new-types)
      {:type :new-event-types
       :severity (:new-event-type-severity anomaly-thresholds)
       :details {:new-types new-types
                 :known-types known-types}})))

(defn detect-severity-escalation
  "Detect multiple high-severity events"
  [current-events]
  (let [high-severity (filter #(severity>= (:severity %) :error) current-events)]
    (when (>= (count high-severity)
              (:severity-escalation-threshold anomaly-thresholds))
      {:type :severity-escalation
       :severity :error
       :details {:high-severity-count (count high-severity)
                 :events (map :id high-severity)}})))

(defn detect-rapid-changes
  "Detect rapid configuration changes"
  [audit-store time-window-ms]
  (let [window-start (.minus (Instant/now) (Duration/ofMillis time-window-ms))
        recent-changes (filter #(= :config-change (:type %))
                               (get-events-since audit-store window-start))
        change-count (count recent-changes)]
    (when (>= change-count (:rapid-changes-threshold anomaly-thresholds))
      {:type :rapid-config-changes
       :severity :warning
       :details {:change-count change-count
                 :time-window-ms time-window-ms
                 :changes (map #(select-keys % [:id :timestamp :details])
                               recent-changes)}})))

(defn detect-policy-violations
  "Detect policy violation events"
  [audit-store time-window-ms]
  (let [window-start (.minus (Instant/now) (Duration/ofMillis time-window-ms))
        violations (filter #(= :policy-violation (:type %))
                           (get-events-since audit-store window-start))]
    (when (seq violations)
      {:type :policy-violations-detected
       :severity :error
       :details {:violation-count (count violations)
                 :violations (map #(select-keys % [:id :timestamp :details])
                                  violations)}})))

(defn run-anomaly-detection
  "Run all anomaly detection checks"
  [audit-store baseline]
  (let [interval-ms (get-in baseline [:metrics :sample-interval-ms] 60000)
        window-start (.minus (Instant/now) (Duration/ofMillis interval-ms))
        recent-events (get-events-since audit-store window-start)
        anomalies (remove nil?
                   [(detect-event-rate-anomaly baseline recent-events)
                    (detect-new-event-types baseline recent-events)
                    (detect-severity-escalation recent-events)
                    (detect-rapid-changes audit-store 60000)
                    (detect-policy-violations audit-store 60000)])]
    {:timestamp (Instant/now)
     :anomalies anomalies
     :anomaly-count (count anomalies)
     :events-analyzed (count recent-events)}))

;; ============================================================================
;; Compliance Reporting
;; ============================================================================

(defn generate-compliance-report
  "Generate a comprehensive compliance report"
  [check-results anomaly-results audit-store]
  {:report-id (str (UUID/randomUUID))
   :generated-at (Instant/now)
   :summary {:total-checks (:total-checks check-results)
             :passed-checks (:passed-count check-results)
             :failed-checks (:failed-count check-results)
             :overall-status (:overall-status check-results)
             :highest-severity (:highest-severity check-results)
             :anomalies-detected (:anomaly-count anomaly-results)}
   :security-checks (:results check-results)
   :anomalies (:anomalies anomaly-results)
   :audit-summary {:total-events (get-event-count audit-store)
                   :event-types (frequencies
                                  (map :type (query-events audit-store {})))
                   :severity-distribution (frequencies
                                            (map :severity (query-events audit-store {})))}})

(defn format-check-result
  "Format a single check result for display"
  [result]
  (format "  [%s] %s (%s)\n      %s\n      %s"
          (if (:passed result) "PASS" "FAIL")
          (:name result)
          (name (:severity result))
          (:description result)
          (if (:passed result)
            "OK"
            (str "Issues: " (pr-str (:details result))))))

(defn print-compliance-report
  "Print a compliance report to console"
  [report]
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "           SECURITY COMPLIANCE REPORT")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  (println (format "Report ID: %s" (:report-id report)))
  (println (format "Generated: %s" (:generated-at report)))

  (println "\n--- Summary ---\n")
  (let [s (:summary report)]
    (println (format "Overall Status: %s"
                     (str/upper-case (name (:overall-status s)))))
    (println (format "Checks: %d passed, %d failed (of %d total)"
                     (:passed-checks s) (:failed-checks s) (:total-checks s)))
    (when (:highest-severity s)
      (println (format "Highest Severity: %s"
                       (str/upper-case (name (:highest-severity s))))))
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
      (println (format "      Details: %s" (pr-str (:details anomaly))))))

  (println "\n--- Audit Event Summary ---\n")
  (let [s (:audit-summary report)]
    (println (format "  Total events: %d" (:total-events s)))
    (println "  By type:")
    (doseq [[t c] (sort-by val > (:event-types s))]
      (println (format "    %-20s %d" (name t) c)))
    (println "  By severity:")
    (doseq [[sev c] (sort-by #(severity-levels (first %)) (:severity-distribution s))]
      (println (format "    %-10s %d" (name sev) c))))

  (println "\n" (apply str (repeat 60 "=")) "\n"))

(defn export-report-json
  "Export report as JSON-like string"
  [report]
  (pr-str (-> report
              (update :generated-at str)
              (update :security-checks #(map event->map %)))))

(defn export-report-csv
  "Export security checks as CSV"
  [report]
  (let [header "check_id,name,severity,passed,details"
        rows (for [r (:security-checks report)]
               (str/join ","
                 [(name (:check-id r))
                  (str "\"" (:name r) "\"")
                  (name (:severity r))
                  (:passed r)
                  (str "\"" (pr-str (:details r)) "\"")]))]
    (str/join "\n" (cons header rows))))

;; ============================================================================
;; Continuous Monitoring
;; ============================================================================

(defn create-audit-monitor
  "Create an audit monitor for continuous security checking"
  [audit-store baseline check-interval-ms]
  (let [running (atom true)
        alerts (atom [])
        monitor-thread (atom nil)]
    {:start
     (fn []
       (reset! running true)
       (reset! monitor-thread
         (future
           (while @running
             (try
               ;; Run anomaly detection
               (let [results (run-anomaly-detection audit-store baseline)]
                 (when (seq (:anomalies results))
                   (doseq [anomaly (:anomalies results)]
                     (swap! alerts conj
                            {:timestamp (Instant/now)
                             :anomaly anomaly})
                     (println (format "[ALERT] [%s] %s: %s"
                                      (str/upper-case (name (:severity anomaly)))
                                      (name (:type anomaly))
                                      (pr-str (:details anomaly)))))))
               (Thread/sleep check-interval-ms)
               (catch Exception e
                 (println (format "[ERROR] Monitor error: %s" (.getMessage e)))))))))

     :stop
     (fn []
       (reset! running false)
       (when @monitor-thread
         (future-cancel @monitor-thread)))

     :is-running
     (fn [] @running)

     :get-alerts
     (fn [] @alerts)

     :clear-alerts
     (fn [] (reset! alerts []))

     :get-alert-count
     (fn [] (count @alerts))}))

;; ============================================================================
;; Alert Handlers
;; ============================================================================

(def alert-handlers
  "Alert handler functions"
  {:log
   (fn [alert]
     (println (format "[%s] ALERT: %s - %s"
                      (:timestamp alert)
                      (name (get-in alert [:anomaly :type]))
                      (pr-str (get-in alert [:anomaly :details])))))

   :console
   (fn [alert]
     (let [severity (get-in alert [:anomaly :severity])]
       (println (format "\n*** SECURITY ALERT ***"))
       (println (format "Time:     %s" (:timestamp alert)))
       (println (format "Type:     %s" (name (get-in alert [:anomaly :type]))))
       (println (format "Severity: %s" (str/upper-case (name severity))))
       (println (format "Details:  %s" (pr-str (get-in alert [:anomaly :details]))))
       (println "************************\n")))

   :email
   (fn [alert]
     ;; Simulated email sending
     (println (format "[EMAIL] Sending alert email: %s"
                      (name (get-in alert [:anomaly :type])))))

   :webhook
   (fn [alert]
     ;; Simulated webhook call
     (println (format "[WEBHOOK] Sending alert to webhook: %s"
                      (name (get-in alert [:anomaly :type])))))})

(defn handle-alert
  "Handle an alert using specified handlers"
  [alert handler-types]
  (doseq [handler-type handler-types]
    (when-let [handler (get alert-handlers handler-type)]
      (try
        (handler alert)
        (catch Exception e
          (println (format "[ERROR] Handler %s failed: %s"
                           (name handler-type) (.getMessage e))))))))

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-custom-check
  "Exercise 1: Add a custom security check"
  []
  (println "\n=== Exercise 1: Custom Security Check ===\n")

  ;; Define custom check
  (def custom-check
    {:id :check-map-permissions
     :name "Map Permission Check"
     :description "Verify all maps have appropriate access controls"
     :severity :warning
     :check-fn (fn [context]
                 (let [maps (:maps context)
                       public-maps (filter #(= :public (:access %)) maps)
                       world-writable (filter #(:world-writable %) maps)]
                   {:passed (and (empty? public-maps) (empty? world-writable))
                    :details {:public-maps (map :name public-maps)
                              :world-writable-maps (map :name world-writable)}}))})

  ;; Test the custom check
  (let [context {:maps [{:name "stats" :access :private :world-writable false}
                        {:name "public_config" :access :public :world-writable false}
                        {:name "shared" :access :private :world-writable true}]}
        result (run-security-check custom-check context)]
    (println "Custom check result:")
    (println (format "  Name: %s" (:name result)))
    (println (format "  Passed: %s" (:passed result)))
    (println (format "  Details: %s" (pr-str (:details result))))))

(defn exercise-historical-analysis
  "Exercise 2: Implement historical trend analysis"
  []
  (println "\n=== Exercise 2: Historical Analysis ===\n")

  (let [audit-store (create-audit-store 1000)
        history (atom [])]

    ;; Generate some historical check results
    (println "Generating historical data...")
    (dotimes [day 7]
      (let [context {:programs [{:name "prog1" :uid 1000 :verified true}]
                     :maps [{:name "stats" :max-entries 256}]
                     :capabilities #{:cap_bpf}
                     :audit-enabled true}
            results (run-all-checks context)]
        (swap! history conj
               {:date (format "Day %d" (inc day))
                :passed (:passed-count results)
                :failed (:failed-count results)
                :status (:overall-status results)})))

    ;; Analyze trends
    (println "\nCompliance Trend Report:")
    (println (format "%-10s %10s %10s %10s" "Date" "Passed" "Failed" "Status"))
    (println (apply str (repeat 45 "-")))
    (doseq [entry @history]
      (println (format "%-10s %10d %10d %10s"
                       (:date entry)
                       (:passed entry)
                       (:failed entry)
                       (name (:status entry)))))

    ;; Calculate statistics
    (let [pass-rates (map #(/ (:passed %) (+ (:passed %) (:failed %))) @history)
          avg-pass-rate (/ (reduce + pass-rates) (count pass-rates))]
      (println (format "\nAverage pass rate: %.1f%%" (* 100 avg-pass-rate))))))

(defn exercise-siem-integration
  "Exercise 3: Build SIEM integration"
  []
  (println "\n=== Exercise 3: SIEM Integration ===\n")

  ;; CEF (Common Event Format) formatter
  (defn format-cef [event]
    (format "CEF:0|clj-ebpf|audit|1.0|%s|%s|%d|src=%s msg=%s"
            (name (:type event))
            (name (:type event))
            (get severity-levels (:severity event) 1)
            (:source event)
            (pr-str (:details event))))

  ;; LEEF (Log Event Extended Format) formatter
  (defn format-leef [event]
    (format "LEEF:1.0|clj-ebpf|audit|1.0|%s|devTime=%s\tsev=%s\tsrc=%s\tmsg=%s"
            (name (:type event))
            (:timestamp event)
            (get severity-levels (:severity event) 1)
            (:source event)
            (pr-str (:details event))))

  ;; Create test events
  (let [events [(create-audit-event :program-load :info "loader" {:name "test"})
                (create-audit-event :security-alert :error "monitor" {:reason "anomaly"})
                (create-audit-event :config-change :warning "admin" {:key "rate-limit"})]]

    (println "Events in CEF format:")
    (doseq [event events]
      (println (format "  %s" (format-cef event))))

    (println "\nEvents in LEEF format:")
    (doseq [event events]
      (println (format "  %s" (format-leef event))))

    ;; Batch sender simulation
    (println "\nSimulating batch send to SIEM:")
    (let [batch-size 2
          batches (partition-all batch-size events)]
      (doseq [[idx batch] (map-indexed vector batches)]
        (println (format "  Sending batch %d (%d events)..." (inc idx) (count batch)))
        (Thread/sleep 100)
        (println (format "  Batch %d sent successfully" (inc idx)))))))

;; ============================================================================
;; Test Functions
;; ============================================================================

(defn test-audit-store []
  (println "Testing audit store...")

  (let [store (create-audit-store 100)]
    ;; Test storing events
    (store-event store (create-audit-event :program-load :info "test" {:name "prog1"}))
    (store-event store (create-audit-event :map-access :debug "test" {:key "stats"}))
    (store-event store (create-audit-event :security-alert :error "monitor" {}))

    (assert (= 3 (get-event-count store)) "Should have 3 events")

    ;; Test querying by type
    (let [results (query-events store {:type :program-load})]
      (assert (= 1 (count results)) "Should find 1 program-load event"))

    ;; Test querying by severity
    (let [results (query-events store {:severity :warning})]
      (assert (= 1 (count results)) "Should find 1 warning+ event"))

    ;; Test clearing
    (clear-events store)
    (assert (= 0 (get-event-count store)) "Should have 0 events after clear")

    (println "Audit store tests passed!")))

(defn test-security-checks []
  (println "Testing security checks...")

  (let [context {:programs [{:name "prog1" :uid 1000 :helpers [:map_lookup_elem] :verified true}
                            {:name "prog2" :uid 0 :helpers [:map_lookup_elem] :verified true}]
                 :maps [{:name "stats" :max-entries 1000}
                        {:name "config" :max-entries 100 :frozen true}]
                 :capabilities #{:cap_bpf}
                 :audit-enabled true}
        results (run-all-checks context)]

    (assert (number? (:total-checks results)) "Should have total checks")
    (assert (number? (:passed-count results)) "Should have passed count")
    (assert (number? (:failed-count results)) "Should have failed count")

    ;; Root programs check should fail
    (let [root-check (first (filter #(= :check-root-programs (:check-id %))
                                    (:results results)))]
      (assert (not (:passed root-check)) "Root check should fail"))

    ;; Capability check should pass
    (let [cap-check (first (filter #(= :check-capabilities (:check-id %))
                                   (:results results)))]
      (assert (:passed cap-check) "Capability check should pass"))

    (println "Security check tests passed!")))

(defn test-anomaly-detection []
  (println "Testing anomaly detection...")

  (let [store (create-audit-store 100)
        baseline (create-baseline
                   {:avg-events-per-interval 5
                    :max-events-per-interval 10
                    :event-type-distribution {:program-load 2 :map-access 3}
                    :sample-interval-ms 1000}
                   10)]

    ;; Generate some events
    (dotimes [_ 20]
      (store-event store (create-audit-event :program-load :info "test" {})))

    (let [results (run-anomaly-detection store baseline)]
      (assert (>= (:anomaly-count results) 0) "Should have anomaly results"))

    (println "Anomaly detection tests passed!")))

(defn test-reporting []
  (println "Testing reporting...")

  (let [store (create-audit-store 100)
        context {:programs [] :maps [] :capabilities #{:cap_bpf} :audit-enabled true}
        check-results (run-all-checks context)
        anomaly-results {:timestamp (Instant/now) :anomalies [] :anomaly-count 0}
        report (generate-compliance-report check-results anomaly-results store)]

    (assert (some? (:report-id report)) "Should have report ID")
    (assert (some? (:summary report)) "Should have summary")
    (assert (some? (:security-checks report)) "Should have security checks")

    ;; Test export formats
    (let [csv (export-report-csv report)]
      (assert (str/includes? csv "check_id") "CSV should have header"))

    (println "Reporting tests passed!")))

(defn run-demo []
  (println "\n=== Demo: Complete Audit Workflow ===\n")

  (let [store (create-audit-store 1000)
        context {:programs [{:name "monitor" :uid 1000
                             :helpers [:map_lookup_elem :ktime_get_ns]
                             :verified true
                             :attach-point "tracepoint/syscalls/sys_enter_open"}
                            {:name "filter" :uid 1000
                             :helpers [:map_lookup_elem]
                             :verified true}]
                 :maps [{:name "stats" :type :percpu_array :max-entries 256}
                        {:name "config" :type :hash :max-entries 100 :frozen false}
                        {:name "events" :type :ringbuf :max-entries 65536}]
                 :capabilities #{:cap_bpf :cap_perfmon}
                 :audit-enabled true}]

    ;; Simulate some audit events
    (println "Generating audit events...")
    (dotimes [_ 10]
      (store-event store (create-audit-event :map-access :debug "monitor" {:key "stats"})))
    (store-event store (create-audit-event :program-load :info "loader" {:name "monitor"}))
    (store-event store (create-audit-event :program-load :info "loader" {:name "filter"}))
    (store-event store (create-audit-event :config-change :warning "admin" {:key "rate-limit"}))
    (store-event store (create-audit-event :program-attach :info "loader" {:target "tracepoint"}))

    ;; Create baseline
    (let [baseline (create-baseline
                     {:avg-events-per-interval 5
                      :max-events-per-interval 15
                      :event-type-distribution {:map-access 10 :program-load 2}
                      :sample-interval-ms 60000}
                     100)]

      ;; Run checks and anomaly detection
      (let [check-results (run-all-checks context)
            anomaly-results (run-anomaly-detection store baseline)
            report (generate-compliance-report check-results anomaly-results store)]

        (print-compliance-report report)))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the security audit framework lab"
  [& args]
  (println "Lab 17.3: Security Audit Framework")
  (println "===================================\n")

  (let [command (first args)]
    (case command
      "test"
      (do
        (test-audit-store)
        (test-security-checks)
        (test-anomaly-detection)
        (test-reporting)
        (println "\nAll tests passed!"))

      "demo"
      (run-demo)

      "exercise1"
      (exercise-custom-check)

      "exercise2"
      (exercise-historical-analysis)

      "exercise3"
      (exercise-siem-integration)

      ;; Default: run all
      (do
        (test-audit-store)
        (test-security-checks)
        (test-anomaly-detection)
        (test-reporting)
        (run-demo)
        (exercise-custom-check)
        (exercise-historical-analysis)
        (exercise-siem-integration)

        (println "\n=== Key Takeaways ===")
        (println "1. Collect and store all security-relevant events")
        (println "2. Define security checks based on compliance requirements")
        (println "3. Establish baselines for anomaly detection")
        (println "4. Generate regular compliance reports")
        (println "5. Set up continuous monitoring with alerts")))))

;; Run with: clj -M -m lab-17-3-audit-framework
