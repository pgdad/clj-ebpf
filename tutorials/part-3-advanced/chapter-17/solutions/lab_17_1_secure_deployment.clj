;; Lab 17.1 Solution: Secure BPF Deployment
;; Implement a secure BPF loader with capability management and audit logging
;;
;; Learning Goals:
;; - Manage Linux capabilities for BPF operations
;; - Implement privilege dropping after setup
;; - Build comprehensive audit logging
;; - Enforce security policies

(ns lab-17-1-secure-deployment
  (:require [clojure.set :as set]
            [clojure.string :as str])
  (:import [java.time Instant]
           [java.util UUID]))

;; ============================================================================
;; Capability Management
;; ============================================================================

(def ^:dynamic *current-capabilities*
  "Simulated capability system for unprivileged testing"
  (atom #{:cap_bpf :cap_perfmon :cap_net_admin}))

(def capability-requirements
  "Required capabilities for each BPF operation"
  {:load-program    #{:cap_bpf}
   :create-map      #{:cap_bpf}
   :attach-kprobe   #{:cap_bpf :cap_perfmon}
   :attach-xdp      #{:cap_bpf :cap_net_admin}
   :attach-tc       #{:cap_bpf :cap_net_admin}
   :pin-object      #{:cap_bpf}
   :unpin-object    #{:cap_bpf}})

(defn has-capability?
  "Check if a capability is currently held"
  [cap]
  (contains? @*current-capabilities* cap))

(defn has-capabilities?
  "Check if all specified capabilities are held"
  [caps]
  (every? has-capability? caps))

(defn drop-capability!
  "Drop a single capability"
  [cap]
  (swap! *current-capabilities* disj cap)
  (println (format "[CAPABILITY] Dropped: %s" (name cap))))

(defn drop-capabilities!
  "Drop multiple capabilities"
  [caps]
  (doseq [cap caps]
    (drop-capability! cap)))

(defn get-current-capabilities
  "Get the set of currently held capabilities"
  []
  @*current-capabilities*)

(defn reset-capabilities!
  "Reset to initial capabilities (for testing)"
  []
  (reset! *current-capabilities* #{:cap_bpf :cap_perfmon :cap_net_admin}))

(defn check-operation-allowed
  "Check if an operation is allowed with current capabilities"
  [operation]
  (let [required (get capability-requirements operation #{})]
    (if (has-capabilities? required)
      {:allowed true :operation operation}
      {:allowed false
       :operation operation
       :missing (set/difference required @*current-capabilities*)})))

(defn validate-capabilities-for-deployment
  "Check if current capabilities allow all requested operations"
  [operations]
  (let [results (for [op operations]
                  (check-operation-allowed op))
        failures (filter #(not (:allowed %)) results)]
    (if (empty? failures)
      {:valid true :operations operations}
      {:valid false
       :failures failures
       :missing-caps (apply set/union (map :missing failures))})))

(defn display-capability-status
  "Display current capability status and permissions"
  []
  (println "\n=== Capability Status ===\n")
  (println "Current capabilities:")
  (doseq [cap (sort (map name @*current-capabilities*))]
    (println (format "  - %s" cap)))
  (println)
  (println "Operation permissions:")
  (doseq [[op caps] (sort-by first capability-requirements)]
    (let [allowed (has-capabilities? caps)]
      (println (format "  %-15s %s"
                       (name op)
                       (if allowed "ALLOWED" "DENIED"))))))

;; ============================================================================
;; Audit Logging
;; ============================================================================

(def audit-log (atom []))

(defrecord AuditEntry [id timestamp type severity capabilities details])

(defn create-audit-entry
  "Create a new audit log entry"
  [event-type severity details]
  (->AuditEntry
    (str (UUID/randomUUID))
    (Instant/now)
    event-type
    severity
    (get-current-capabilities)
    details))

(defn log-audit-event
  "Log an audit event"
  ([event-type details]
   (log-audit-event event-type :info details))
  ([event-type severity details]
   (let [entry (create-audit-entry event-type severity details)]
     (swap! audit-log conj entry)
     (println (format "[AUDIT] [%s] %s: %s"
                      (str/upper-case (name severity))
                      (name event-type)
                      (pr-str details))))))

(defn get-audit-log
  "Get all audit log entries"
  []
  @audit-log)

(defn clear-audit-log
  "Clear the audit log"
  []
  (reset! audit-log []))

(defn query-audit-log
  "Query audit log with filters"
  [{:keys [type severity since limit]}]
  (cond->> @audit-log
    type (filter #(= type (:type %)))
    severity (filter #(= severity (:severity %)))
    since (filter #(.isAfter (:timestamp %) since))
    limit (take limit)))

(defn export-audit-log
  "Export audit log to file"
  [filename]
  (let [log-str (with-out-str
                  (doseq [entry @audit-log]
                    (println (format "%s [%s] %s - %s"
                                     (:timestamp entry)
                                     (str/upper-case (name (:severity entry)))
                                     (name (:type entry))
                                     (pr-str (:details entry))))))]
    (spit filename log-str)
    (println (format "Audit log exported to: %s (%d entries)"
                     filename (count @audit-log)))))

;; ============================================================================
;; Mock BPF Objects
;; ============================================================================

(defrecord MockBPFProgram [id name type loaded-at attached-to])
(defrecord MockBPFMap [id name type max-entries created-at frozen])

(defn generate-id []
  (str (UUID/randomUUID)))

;; ============================================================================
;; Secure BPF Loader
;; ============================================================================

(defrecord SecureLoader [config programs maps])

(defn create-secure-loader
  "Create a new secure BPF loader"
  [config]
  (->SecureLoader config (atom {}) (atom {})))

(defn secure-load-program
  "Load a BPF program with security checks and auditing"
  [loader program-spec]
  (let [op-check (check-operation-allowed :load-program)]
    (if (:allowed op-check)
      (let [program (->MockBPFProgram
                      (generate-id)
                      (:name program-spec)
                      (:type program-spec)
                      (Instant/now)
                      nil)]
        (swap! (:programs loader) assoc (:name program-spec) program)
        (log-audit-event :program-load
                         {:name (:name program-spec)
                          :type (:type program-spec)
                          :id (:id program)})
        {:success true :program program})
      (do
        (log-audit-event :security-violation :warning
                         {:operation :load-program
                          :missing (:missing op-check)})
        {:success false
         :error "Insufficient capabilities"
         :missing (:missing op-check)}))))

(defn secure-create-map
  "Create a BPF map with security checks"
  [loader map-spec]
  (let [op-check (check-operation-allowed :create-map)]
    (if (:allowed op-check)
      (let [bpf-map (->MockBPFMap
                      (generate-id)
                      (:name map-spec)
                      (:type map-spec)
                      (:max-entries map-spec)
                      (Instant/now)
                      false)]
        (swap! (:maps loader) assoc (:name map-spec) bpf-map)
        (log-audit-event :map-create
                         {:name (:name map-spec)
                          :type (:type map-spec)
                          :max-entries (:max-entries map-spec)
                          :id (:id bpf-map)})
        {:success true :map bpf-map})
      (do
        (log-audit-event :security-violation :warning
                         {:operation :create-map
                          :missing (:missing op-check)})
        {:success false
         :error "Insufficient capabilities"
         :missing (:missing op-check)}))))

(defn secure-attach
  "Attach program with security checks"
  [loader program attach-type target]
  (let [op-key (case attach-type
                 :kprobe :attach-kprobe
                 :xdp :attach-xdp
                 :tc :attach-tc
                 :tracepoint :attach-kprobe ; Uses same caps
                 :load-program)
        op-check (check-operation-allowed op-key)]
    (if (:allowed op-check)
      (do
        ;; Update program's attached-to field
        (when-let [prog-atom (get @(:programs loader) (:name program))]
          (swap! (:programs loader) assoc (:name program)
                 (assoc program :attached-to {:type attach-type :target target})))
        (log-audit-event :program-attach
                         {:program (:name program)
                          :attach-type attach-type
                          :target target})
        {:success true})
      (do
        (log-audit-event :security-violation :warning
                         {:operation op-key
                          :target target
                          :missing (:missing op-check)})
        {:success false
         :error "Insufficient capabilities"
         :missing (:missing op-check)}))))

(defn secure-detach
  "Detach program with security checks"
  [loader program]
  (log-audit-event :program-detach
                   {:program (:name program)})
  {:success true})

;; ============================================================================
;; Privilege Dropping
;; ============================================================================

(defn calculate-required-capabilities
  "Determine minimum capabilities needed for deployment"
  [deployment-config]
  (let [operations (:operations deployment-config)]
    (apply set/union (map #(get capability-requirements % #{}) operations))))

(defn calculate-runtime-capabilities
  "Determine capabilities needed at runtime (after initial load)"
  [deployment-config]
  ;; After loading, we typically only need pin/unpin
  (if (:persist deployment-config)
    #{:cap_bpf}
    #{}))

(defn drop-unnecessary-capabilities
  "Drop capabilities not needed after initial load"
  [deployment-config]
  (let [runtime-caps (calculate-runtime-capabilities deployment-config)
        current @*current-capabilities*
        to-drop (set/difference current runtime-caps)]
    (log-audit-event :capability-drop
                     {:dropping (set (map name to-drop))
                      :retaining (set (map name runtime-caps))})
    (drop-capabilities! to-drop)
    {:retained runtime-caps
     :dropped to-drop}))

;; ============================================================================
;; Security Policies
;; ============================================================================

(def default-security-policies
  "Configurable security policies"
  {:max-programs 10
   :max-maps 50
   :max-map-entries 1000000
   :allowed-map-types #{:hash :array :percpu_hash :percpu_array :ringbuf :lru_hash}
   :allowed-program-types #{:kprobe :tracepoint :xdp :tc :cgroup_skb}
   :require-audit-log true
   :allow-capability-escalation false
   :max-attachment-points 20})

(def ^:dynamic *security-policies* default-security-policies)

(defn check-policy
  "Check if a value complies with a policy"
  [policy-key value]
  (let [policy-value (get *security-policies* policy-key)]
    (case policy-key
      (:max-programs :max-maps :max-map-entries :max-attachment-points)
      {:passed (<= value policy-value)
       :policy policy-key
       :limit policy-value
       :actual value}

      (:allowed-map-types :allowed-program-types)
      {:passed (contains? policy-value value)
       :policy policy-key
       :allowed policy-value
       :actual value}

      :require-audit-log
      {:passed (or (not policy-value) (not (empty? @audit-log)))
       :policy policy-key}

      :allow-capability-escalation
      {:passed (or policy-value (not value))
       :policy policy-key}

      {:passed true :policy policy-key})))

(defn validate-against-policies
  "Validate a deployment spec against security policies"
  [spec]
  (let [violations (atom [])]
    ;; Check program constraints
    (when-let [programs (:programs spec)]
      (let [count-check (check-policy :max-programs (count programs))]
        (when-not (:passed count-check)
          (swap! violations conj count-check)))
      (doseq [p programs]
        (let [type-check (check-policy :allowed-program-types (:type p))]
          (when-not (:passed type-check)
            (swap! violations conj (assoc type-check :program (:name p)))))))

    ;; Check map constraints
    (when-let [maps (:maps spec)]
      (let [count-check (check-policy :max-maps (count maps))]
        (when-not (:passed count-check)
          (swap! violations conj count-check)))
      (doseq [m maps]
        (let [type-check (check-policy :allowed-map-types (:type m))]
          (when-not (:passed type-check)
            (swap! violations conj (assoc type-check :map (:name m)))))
        (when-let [entries (:max-entries m)]
          (let [entries-check (check-policy :max-map-entries entries)]
            (when-not (:passed entries-check)
              (swap! violations conj (assoc entries-check :map (:name m))))))))

    ;; Check attachment constraints
    (when-let [attachments (:attachments spec)]
      (let [count-check (check-policy :max-attachment-points (count attachments))]
        (when-not (:passed count-check)
          (swap! violations conj count-check))))

    (if (empty? @violations)
      {:valid true}
      {:valid false :violations @violations})))

;; ============================================================================
;; Secure Deployment Workflow
;; ============================================================================

(defn secure-deployment-workflow
  "Complete secure deployment workflow"
  [deployment-config]
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "         Secure BPF Deployment Workflow")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  ;; Phase 1: Validate capabilities
  (println "Phase 1: Validating capabilities...")
  (let [validation (validate-capabilities-for-deployment
                     (:operations deployment-config))]
    (if-not (:valid validation)
      (do
        (log-audit-event :deployment-failed :error
                         {:phase :capability-validation
                          :missing (:missing-caps validation)})
        (println "ERROR: Missing capabilities:")
        (doseq [cap (:missing-caps validation)]
          (println (format "  - %s" (name cap))))
        {:success false :phase :validation :error validation})

      ;; Phase 2: Validate against policies
      (do
        (println "Phase 2: Checking security policies...")
        (let [policy-check (validate-against-policies deployment-config)]
          (if-not (:valid policy-check)
            (do
              (log-audit-event :deployment-failed :error
                               {:phase :policy-validation
                                :violations (:violations policy-check)})
              (println "ERROR: Policy violations:")
              (doseq [v (:violations policy-check)]
                (println (format "  - %s: %s" (:policy v) v)))
              {:success false :phase :policy-check :error policy-check})

            ;; Phase 3: Load programs and create maps
            (do
              (println "Phase 3: Loading BPF objects...")
              (let [loader (create-secure-loader deployment-config)
                    prog-results (for [prog-spec (:programs deployment-config)]
                                   (secure-load-program loader prog-spec))
                    map-results (for [map-spec (:maps deployment-config)]
                                  (secure-create-map loader map-spec))]

                (if (every? :success (concat prog-results map-results))
                  ;; Phase 4: Attach programs
                  (do
                    (println "Phase 4: Attaching programs...")
                    (let [programs @(:programs loader)
                          attach-results
                          (for [{:keys [program type target]} (:attachments deployment-config)]
                            (if-let [prog (get programs program)]
                              (secure-attach loader prog type target)
                              {:success false :error (str "Program not found: " program)}))]

                      (if (every? :success attach-results)
                        ;; Phase 5: Drop privileges
                        (do
                          (println "Phase 5: Dropping unnecessary capabilities...")
                          (let [drop-result (drop-unnecessary-capabilities deployment-config)]
                            (println (format "Retained: %s"
                                             (set (map name (:retained drop-result)))))
                            (println (format "Dropped: %s"
                                             (set (map name (:dropped drop-result)))))

                            (log-audit-event :deployment-success
                                             {:programs (count prog-results)
                                              :maps (count map-results)
                                              :attachments (count attach-results)})

                            (display-capability-status)

                            {:success true
                             :loader loader
                             :programs (map :program prog-results)
                             :maps (map :map map-results)}))

                        (do
                          (log-audit-event :deployment-failed :error
                                           {:phase :attach})
                          {:success false :phase :attach}))))

                  (do
                    (log-audit-event :deployment-failed :error
                                     {:phase :load})
                    {:success false :phase :load}))))))))))

(defn policy-enforced-load
  "Load with policy enforcement"
  [spec]
  (log-audit-event :policy-check {:spec-name (:name spec)})

  (let [policy-result (validate-against-policies spec)]
    (if (:valid policy-result)
      (do
        (log-audit-event :policy-passed {:spec-name (:name spec)})
        (secure-deployment-workflow spec))
      (do
        (log-audit-event :policy-violation :error
                         {:violations (:violations policy-result)})
        {:success false
         :error "Policy violation"
         :violations (:violations policy-result)}))))

;; ============================================================================
;; Sample Deployment Configuration
;; ============================================================================

(def sample-deployment
  {:name "network-monitor"
   :operations [:load-program :create-map :attach-xdp :pin-object]
   :persist true
   :programs [{:name "packet-counter"
               :type :xdp}
              {:name "flow-tracker"
               :type :tc}]
   :maps [{:name "stats"
           :type :percpu_array
           :max-entries 256}
          {:name "flows"
           :type :lru_hash
           :max-entries 10000}
          {:name "config"
           :type :array
           :max-entries 64}]
   :attachments [{:program "packet-counter"
                  :type :xdp
                  :target "eth0"}
                 {:program "flow-tracker"
                  :type :tc
                  :target "eth0"}]})

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-audit-filtering
  "Exercise 1: Implement filtered audit log queries"
  []
  (println "\n=== Exercise 1: Audit Log Filtering ===\n")

  ;; Generate some test events
  (clear-audit-log)
  (log-audit-event :program-load :info {:name "prog1"})
  (log-audit-event :map-create :info {:name "map1"})
  (log-audit-event :security-violation :warning {:operation :attach})
  (log-audit-event :program-attach :info {:name "prog1" :target "eth0"})
  (log-audit-event :policy-violation :error {:policy :max-maps})

  (println "All events:")
  (doseq [entry (get-audit-log)]
    (println (format "  [%s] %s" (name (:severity entry)) (name (:type entry)))))

  (println "\nFiltered by type (security-violation):")
  (doseq [entry (query-audit-log {:type :security-violation})]
    (println (format "  [%s] %s - %s"
                     (name (:severity entry))
                     (name (:type entry))
                     (:details entry))))

  (println "\nFiltered by severity (warning and above):")
  (let [warning-up (filter #(#{:warning :error :critical} (:severity %))
                           (get-audit-log))]
    (doseq [entry warning-up]
      (println (format "  [%s] %s"
                       (name (:severity entry))
                       (name (:type entry))))))

  (println "\nAudit statistics:")
  (let [log (get-audit-log)
        by-type (frequencies (map :type log))
        by-severity (frequencies (map :severity log))]
    (println (format "  Total events: %d" (count log)))
    (println "  By type:")
    (doseq [[t c] by-type]
      (println (format "    %s: %d" (name t) c)))
    (println "  By severity:")
    (doseq [[s c] by-severity]
      (println (format "    %s: %d" (name s) c)))))

(defn exercise-elevation-request
  "Exercise 2: Implement capability elevation requests"
  []
  (println "\n=== Exercise 2: Capability Elevation ===\n")

  (let [elevation-requests (atom [])
        elevation-grants (atom {})]

    ;; Request elevation with justification
    (defn request-elevation [cap justification]
      (let [request {:id (generate-id)
                     :capability cap
                     :justification justification
                     :timestamp (Instant/now)
                     :status :pending}]
        (swap! elevation-requests conj request)
        (log-audit-event :capability-elevation-request :warning
                         {:capability cap :justification justification})
        request))

    ;; Grant temporary elevation
    (defn grant-elevation [request-id duration-ms]
      (let [expiry (.plusMillis (Instant/now) duration-ms)]
        (when-let [request (first (filter #(= request-id (:id %)) @elevation-requests))]
          (swap! elevation-grants assoc (:capability request) expiry)
          (swap! *current-capabilities* conj (:capability request))
          (log-audit-event :capability-elevation-granted :warning
                           {:capability (:capability request)
                            :expires-at expiry})
          {:granted true :expires-at expiry})))

    ;; Check and expire elevations
    (defn expire-elevations []
      (let [now (Instant/now)]
        (doseq [[cap expiry] @elevation-grants]
          (when (.isBefore expiry now)
            (swap! elevation-grants dissoc cap)
            (swap! *current-capabilities* disj cap)
            (log-audit-event :capability-elevation-expired :info
                             {:capability cap})))))

    ;; Demo
    (reset-capabilities!)
    (drop-capability! :cap_net_admin)

    (println "Current capabilities (no CAP_NET_ADMIN):")
    (println (format "  %s" @*current-capabilities*))

    (println "\nRequesting elevation for CAP_NET_ADMIN...")
    (let [request (request-elevation :cap_net_admin
                                     "Need to attach XDP program for maintenance")]
      (println (format "Request ID: %s" (:id request)))

      (println "\nGranting 5-second elevation...")
      (grant-elevation (:id request) 5000)
      (println (format "Current capabilities: %s" @*current-capabilities*))

      (println "\nWaiting for expiration...")
      (Thread/sleep 6000)
      (expire-elevations)
      (println (format "Current capabilities: %s" @*current-capabilities*)))))

(defn exercise-multi-tenant
  "Exercise 3: Implement multi-tenant capability isolation"
  []
  (println "\n=== Exercise 3: Multi-Tenant Isolation ===\n")

  (let [tenant-capabilities (atom {"tenant-a" #{:cap_bpf}
                                   "tenant-b" #{:cap_bpf :cap_perfmon}
                                   "tenant-c" #{:cap_bpf :cap_net_admin}})
        tenant-audit-logs (atom {"tenant-a" []
                                 "tenant-b" []
                                 "tenant-c" []})
        tenant-quotas (atom {"tenant-a" {:max-programs 5 :max-maps 10}
                             "tenant-b" {:max-programs 10 :max-maps 20}
                             "tenant-c" {:max-programs 3 :max-maps 5}})]

    (defn tenant-has-capability? [tenant cap]
      (contains? (get @tenant-capabilities tenant #{}) cap))

    (defn tenant-log-event [tenant event]
      (swap! tenant-audit-logs update tenant conj
             (assoc event :timestamp (Instant/now))))

    (defn tenant-check-quota [tenant resource-type current-count]
      (let [limit (get-in @tenant-quotas [tenant resource-type])]
        (< current-count limit)))

    (defn tenant-can-load-program? [tenant current-program-count]
      (and (tenant-has-capability? tenant :cap_bpf)
           (tenant-check-quota tenant :max-programs current-program-count)))

    ;; Demo
    (println "Tenant capabilities:")
    (doseq [[tenant caps] @tenant-capabilities]
      (println (format "  %s: %s" tenant caps)))

    (println "\nTenant quotas:")
    (doseq [[tenant quotas] @tenant-quotas]
      (println (format "  %s: %s" tenant quotas)))

    (println "\nAccess checks:")
    (doseq [tenant ["tenant-a" "tenant-b" "tenant-c"]]
      (println (format "  %s can load program (0 existing): %s"
                       tenant
                       (tenant-can-load-program? tenant 0)))
      (println (format "  %s has CAP_NET_ADMIN: %s"
                       tenant
                       (tenant-has-capability? tenant :cap_net_admin))))

    (println "\nCross-tenant access (blocked):")
    (println "  tenant-a trying to access tenant-b resources: DENIED")
    (tenant-log-event "tenant-a" {:type :access-denied
                                   :attempted-tenant "tenant-b"
                                   :reason "Cross-tenant access"})))

;; ============================================================================
;; Test Functions
;; ============================================================================

(defn test-capability-management []
  (println "Testing capability management...")

  ;; Test capability checking
  (reset-capabilities!)
  (assert (has-capability? :cap_bpf) "Should have CAP_BPF")
  (assert (has-capabilities? #{:cap_bpf :cap_perfmon})
          "Should have multiple capabilities")

  ;; Test operation checking
  (let [result (check-operation-allowed :load-program)]
    (assert (:allowed result) "Should allow load-program"))

  ;; Test capability dropping
  (drop-capability! :cap_perfmon)
  (assert (not (has-capability? :cap_perfmon))
          "Should have dropped CAP_PERFMON")

  (let [result (check-operation-allowed :attach-kprobe)]
    (assert (not (:allowed result)) "Should not allow attach-kprobe"))

  (println "All capability tests passed!"))

(defn test-secure-loader []
  (println "Testing secure loader...")

  (reset-capabilities!)
  (clear-audit-log)

  (let [loader (create-secure-loader {})
        result (secure-load-program loader {:name "test" :type :kprobe})]
    (assert (:success result) "Should load program with CAP_BPF"))

  ;; Should fail without CAP_BPF
  (reset! *current-capabilities* #{})
  (let [result (secure-load-program (create-secure-loader {})
                                     {:name "test" :type :kprobe})]
    (assert (not (:success result)) "Should fail without CAP_BPF")
    (assert (contains? (:missing result) :cap_bpf)
            "Should report missing CAP_BPF"))

  ;; Verify audit logging
  (assert (not (empty? (get-audit-log))) "Should have audit entries")

  (println "All secure loader tests passed!"))

(defn test-policy-enforcement []
  (println "Testing policy enforcement...")

  ;; Valid deployment
  (let [valid-spec {:programs [{:name "test" :type :xdp}]
                    :maps [{:name "data" :type :hash :max-entries 100}]}]
    (assert (:valid (validate-against-policies valid-spec))
            "Valid spec should pass"))

  ;; Invalid program type
  (let [invalid-spec {:programs [{:name "test" :type :invalid}]}]
    (assert (not (:valid (validate-against-policies invalid-spec)))
            "Invalid type should fail"))

  ;; Too many entries
  (let [invalid-spec {:maps [{:name "data" :type :hash :max-entries 999999999}]}]
    (assert (not (:valid (validate-against-policies invalid-spec)))
            "Excessive entries should fail"))

  (println "All policy tests passed!"))

(defn run-sample-deployment []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "           Secure BPF Deployment Demo")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  ;; Reset state
  (reset-capabilities!)
  (clear-audit-log)

  ;; Run deployment
  (let [result (policy-enforced-load sample-deployment)]
    (println "\n=== Deployment Result ===\n")
    (if (:success result)
      (do
        (println "Deployment successful!")
        (println (format "Loaded programs: %d" (count (:programs result))))
        (println (format "Created maps: %d" (count (:maps result)))))
      (do
        (println "Deployment failed!")
        (println (format "Phase: %s" (:phase result)))
        (println (format "Error: %s" (:error result)))))

    ;; Show audit log summary
    (println "\n=== Audit Log Summary ===\n")
    (let [log (get-audit-log)
          by-type (frequencies (map :type log))]
      (println (format "Total audit events: %d" (count log)))
      (doseq [[t c] (sort-by val > by-type)]
        (println (format "  %s: %d" (name t) c))))

    result))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the secure deployment lab"
  [& args]
  (println "Lab 17.1: Secure BPF Deployment")
  (println "================================\n")

  (let [command (first args)]
    (case command
      "test"
      (do
        (test-capability-management)
        (test-secure-loader)
        (test-policy-enforcement)
        (println "\nAll tests passed!"))

      "demo"
      (run-sample-deployment)

      "exercise1"
      (exercise-audit-filtering)

      "exercise2"
      (exercise-elevation-request)

      "exercise3"
      (exercise-multi-tenant)

      ;; Default: run all
      (do
        (test-capability-management)
        (test-secure-loader)
        (test-policy-enforcement)
        (run-sample-deployment)
        (exercise-audit-filtering)

        (println "\n=== Key Takeaways ===")
        (println "1. Always check capabilities before BPF operations")
        (println "2. Drop unnecessary privileges after initial setup")
        (println "3. Maintain comprehensive audit logs")
        (println "4. Enforce security policies for all deployments")
        (println "5. Use minimal capabilities principle")))))

;; Run with: clj -M -m lab-17-1-secure-deployment
