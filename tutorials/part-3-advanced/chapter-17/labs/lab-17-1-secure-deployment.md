# Lab 17.1: Secure BPF Deployment

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Implement a secure BPF loader with capability management, privilege dropping, and comprehensive audit logging.

## Prerequisites

- Completed Chapter 17 reading
- Understanding of Linux capabilities
- Familiarity with security concepts

## Scenario

You're deploying a BPF-based monitoring tool in a security-conscious environment. The tool must run with minimal privileges and maintain a complete audit trail of all operations.

---

## Part 1: Capability Management

### Step 1.1: Mock Capability System

```clojure
(ns lab-17-1.secure-deployment
  (:require [clojure.set :as set])
  (:import [java.time Instant]))

;; Simulated capability system for unprivileged testing
(def ^:dynamic *current-capabilities*
  (atom #{:cap_bpf :cap_perfmon :cap_net_admin}))

(def capability-requirements
  "Required capabilities for each operation"
  {:load-program #{:cap_bpf}
   :create-map #{:cap_bpf}
   :attach-kprobe #{:cap_bpf :cap_perfmon}
   :attach-xdp #{:cap_bpf :cap_net_admin}
   :pin-object #{:cap_bpf}})

(defn has-capability? [cap]
  (contains? @*current-capabilities* cap))

(defn has-capabilities? [caps]
  (every? has-capability? caps))

(defn drop-capability! [cap]
  (swap! *current-capabilities* disj cap)
  (println (format "Dropped capability: %s" cap)))

(defn drop-capabilities! [caps]
  (doseq [cap caps]
    (drop-capability! cap)))

(defn get-current-capabilities []
  @*current-capabilities*)

(defn check-operation-allowed [operation]
  (let [required (get capability-requirements operation #{})]
    (if (has-capabilities? required)
      {:allowed true}
      {:allowed false
       :missing (set/difference required @*current-capabilities*)})))
```

### Step 1.2: Capability Checker

```clojure
(defn validate-capabilities-for-deployment [operations]
  "Check if current capabilities allow all requested operations"
  (let [results (for [op operations]
                  (assoc (check-operation-allowed op) :operation op))
        failures (filter #(not (:allowed %)) results)]
    (if (empty? failures)
      {:valid true :operations operations}
      {:valid false
       :failures failures
       :missing-caps (apply set/union (map :missing failures))})))

(defn display-capability-status []
  (println "\n=== Capability Status ===\n")
  (println "Current capabilities:")
  (doseq [cap (sort @*current-capabilities*)]
    (println (format "  - %s" (name cap))))
  (println)
  (println "Operation permissions:")
  (doseq [[op caps] capability-requirements]
    (let [allowed (has-capabilities? caps)]
      (println (format "  %s: %s"
                       (name op)
                       (if allowed "ALLOWED" "DENIED"))))))
```

---

## Part 2: Secure Loader Implementation

### Step 2.1: Audit Logger

```clojure
(def audit-log (atom []))

(defn log-audit-event [event-type details]
  (let [entry {:timestamp (Instant/now)
               :type event-type
               :capabilities (get-current-capabilities)
               :details details}]
    (swap! audit-log conj entry)
    (println (format "[AUDIT] %s: %s" (name event-type) details))))

(defn get-audit-log []
  @audit-log)

(defn clear-audit-log []
  (reset! audit-log []))

(defn export-audit-log [filename]
  (let [log-str (with-out-str
                  (doseq [entry @audit-log]
                    (println entry)))]
    (spit filename log-str)
    (println (format "Audit log exported to: %s" filename))))
```

### Step 2.2: Secure BPF Loader

```clojure
(defrecord SecureLoader [config audit-log])

(defn create-secure-loader [config]
  (->SecureLoader config (atom [])))

;; Mock BPF objects for testing
(defrecord MockBPFProgram [name type loaded-at])
(defrecord MockBPFMap [name type max-entries created-at])

(defn secure-load-program
  "Load a BPF program with security checks and auditing"
  [loader program-spec]
  (let [op-check (check-operation-allowed :load-program)]
    (if (:allowed op-check)
      (do
        (log-audit-event :program-load
                         {:name (:name program-spec)
                          :type (:type program-spec)})
        {:success true
         :program (->MockBPFProgram (:name program-spec)
                                     (:type program-spec)
                                     (Instant/now))})
      (do
        (log-audit-event :security-violation
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
      (do
        (log-audit-event :map-create
                         {:name (:name map-spec)
                          :type (:type map-spec)
                          :max-entries (:max-entries map-spec)})
        {:success true
         :map (->MockBPFMap (:name map-spec)
                            (:type map-spec)
                            (:max-entries map-spec)
                            (Instant/now))})
      (do
        (log-audit-event :security-violation
                         {:operation :create-map
                          :missing (:missing op-check)})
        {:success false
         :error "Insufficient capabilities"}))))

(defn secure-attach
  "Attach program with security checks"
  [loader program attach-type target]
  (let [op-key (case attach-type
                 :kprobe :attach-kprobe
                 :xdp :attach-xdp
                 :generic)
        op-check (check-operation-allowed op-key)]
    (if (:allowed op-check)
      (do
        (log-audit-event :program-attach
                         {:program (:name program)
                          :attach-type attach-type
                          :target target})
        {:success true})
      (do
        (log-audit-event :security-violation
                         {:operation op-key
                          :target target})
        {:success false
         :error "Insufficient capabilities"}))))
```

---

## Part 3: Privilege Dropping

### Step 3.1: Post-Load Privilege Drop

```clojure
(defn calculate-required-capabilities [deployment-config]
  "Determine minimum capabilities needed for deployment"
  (let [operations (:operations deployment-config)]
    (apply set/union (map #(get capability-requirements % #{}) operations))))

(defn drop-unnecessary-capabilities [deployment-config]
  "Drop capabilities not needed after initial load"
  (let [required (calculate-required-capabilities deployment-config)
        current @*current-capabilities*
        to-drop (set/difference current required)]
    (log-audit-event :capability-drop {:dropping to-drop})
    (drop-capabilities! to-drop)
    {:retained required
     :dropped to-drop}))

(defn secure-deployment-workflow [deployment-config]
  "Complete secure deployment workflow"
  (println "\n=== Secure Deployment Workflow ===\n")

  ;; Phase 1: Validate capabilities
  (println "Phase 1: Validating capabilities...")
  (let [validation (validate-capabilities-for-deployment
                     (:operations deployment-config))]
    (if-not (:valid validation)
      (do
        (println "ERROR: Missing capabilities")
        (println "Missing:" (:missing-caps validation))
        {:success false :phase :validation :error validation})

      ;; Phase 2: Load programs and create maps
      (do
        (println "Phase 2: Loading BPF objects...")
        (let [loader (create-secure-loader deployment-config)
              programs (for [prog-spec (:programs deployment-config)]
                         (secure-load-program loader prog-spec))
              maps (for [map-spec (:maps deployment-config)]
                     (secure-create-map loader map-spec))]

          (if (every? :success (concat programs maps))
            ;; Phase 3: Attach programs
            (do
              (println "Phase 3: Attaching programs...")
              (let [attachments (for [{:keys [program type target]}
                                      (:attachments deployment-config)]
                                  (secure-attach loader
                                                 (first (filter #(= program (:name %))
                                                               (map :program programs)))
                                                 type
                                                 target))]

                (if (every? :success attachments)
                  ;; Phase 4: Drop privileges
                  (do
                    (println "Phase 4: Dropping unnecessary capabilities...")
                    (let [drop-result (drop-unnecessary-capabilities
                                        {:operations [:pin-object]})]
                      (println "Retained:" (:retained drop-result))
                      (println "Dropped:" (:dropped drop-result))
                      (display-capability-status)
                      {:success true
                       :programs (map :program programs)
                       :maps (map :map maps)}))

                  {:success false :phase :attach})))
            {:success false :phase :load}))))))
```

---

## Part 4: Security Policies

### Step 4.1: Policy Engine

```clojure
(def security-policies
  "Configurable security policies"
  {:max-programs 10
   :max-maps 50
   :max-map-entries 1000000
   :allowed-map-types #{:hash :array :percpu_hash :percpu_array}
   :allowed-program-types #{:kprobe :tracepoint :xdp}
   :require-audit-log true
   :allow-capability-escalation false})

(defn check-policy [policy-key value]
  (let [policy-value (get security-policies policy-key)]
    (case policy-key
      (:max-programs :max-maps :max-map-entries)
      (<= value policy-value)

      (:allowed-map-types :allowed-program-types)
      (contains? policy-value value)

      :require-audit-log
      (or (not policy-value) (not (empty? @audit-log)))

      :allow-capability-escalation
      (or policy-value (not value))

      true)))

(defn validate-against-policies [spec]
  (let [violations (atom [])]
    ;; Check map constraints
    (when-let [maps (:maps spec)]
      (when (> (count maps) (:max-programs security-policies))
        (swap! violations conj {:policy :max-maps
                                :value (count maps)
                                :limit (:max-maps security-policies)}))
      (doseq [m maps]
        (when-not (contains? (:allowed-map-types security-policies) (:type m))
          (swap! violations conj {:policy :allowed-map-types
                                  :value (:type m)}))))

    ;; Check program constraints
    (when-let [progs (:programs spec)]
      (when (> (count progs) (:max-programs security-policies))
        (swap! violations conj {:policy :max-programs
                                :value (count progs)
                                :limit (:max-programs security-policies)}))
      (doseq [p progs]
        (when-not (contains? (:allowed-program-types security-policies) (:type p))
          (swap! violations conj {:policy :allowed-program-types
                                  :value (:type p)}))))

    (if (empty? @violations)
      {:valid true}
      {:valid false :violations @violations})))
```

### Step 4.2: Policy-Enforced Loader

```clojure
(defn policy-enforced-load [loader spec]
  "Load with policy enforcement"
  (log-audit-event :policy-check {:spec-summary (select-keys spec [:name])})

  (let [policy-result (validate-against-policies spec)]
    (if (:valid policy-result)
      (do
        (log-audit-event :policy-passed {})
        (secure-deployment-workflow spec))
      (do
        (log-audit-event :policy-violation {:violations (:violations policy-result)})
        {:success false
         :error "Policy violation"
         :violations (:violations policy-result)}))))
```

---

## Part 5: Complete Deployment Example

### Step 5.1: Sample Deployment Configuration

```clojure
(def sample-deployment
  {:name "network-monitor"
   :operations [:load-program :create-map :attach-xdp :pin-object]
   :programs [{:name "packet-counter"
               :type :xdp}]
   :maps [{:name "stats"
           :type :percpu_array
           :max-entries 256}
          {:name "config"
           :type :hash
           :max-entries 100}]
   :attachments [{:program "packet-counter"
                  :type :xdp
                  :target "eth0"}]})

(defn run-sample-deployment []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "     Secure BPF Deployment Demo")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  ;; Reset state
  (reset! *current-capabilities* #{:cap_bpf :cap_perfmon :cap_net_admin})
  (clear-audit-log)

  ;; Run deployment
  (let [result (policy-enforced-load nil sample-deployment)]
    (println "\n=== Deployment Result ===\n")
    (if (:success result)
      (do
        (println "Deployment successful!")
        (println "Loaded programs:" (count (:programs result)))
        (println "Created maps:" (count (:maps result))))
      (do
        (println "Deployment failed!")
        (println "Error:" (:error result))))

    ;; Show audit log
    (println "\n=== Audit Log ===\n")
    (doseq [entry (get-audit-log)]
      (println (format "%s [%s] %s"
                       (:timestamp entry)
                       (name (:type entry))
                       (:details entry))))

    result))
```

---

## Part 6: Exercises

### Exercise 1: Fine-Grained Audit Logging

Implement detailed audit logging with filtering:

```clojure
(defn exercise-audit-filtering []
  ;; TODO: Implement filtered audit log queries
  ;; 1. Filter by event type
  ;; 2. Filter by time range
  ;; 3. Filter by capability involved
  ;; 4. Generate summary statistics
  )
```

### Exercise 2: Capability Elevation Requests

Implement a capability elevation request system:

```clojure
(defn exercise-elevation-request []
  ;; TODO: Implement capability elevation
  ;; 1. Request additional capability with justification
  ;; 2. Log the request
  ;; 3. Apply time-limited elevation
  ;; 4. Auto-expire elevated capabilities
  )
```

### Exercise 3: Multi-Tenant Isolation

Implement capability isolation for multiple tenants:

```clojure
(defn exercise-multi-tenant []
  ;; TODO: Implement tenant isolation
  ;; 1. Each tenant gets separate capability set
  ;; 2. Cross-tenant access is blocked
  ;; 3. Audit logs are tenant-specific
  ;; 4. Resource quotas per tenant
  )
```

---

## Part 7: Testing Your Implementation

### Test Script

```clojure
(defn test-capability-management []
  (println "Testing capability management...")

  ;; Test capability checking
  (reset! *current-capabilities* #{:cap_bpf})
  (assert (has-capability? :cap_bpf) "Should have CAP_BPF")
  (assert (not (has-capability? :cap_perfmon)) "Should not have CAP_PERFMON")

  ;; Test operation checking
  (let [result (check-operation-allowed :load-program)]
    (assert (:allowed result) "Should allow load-program"))

  (let [result (check-operation-allowed :attach-kprobe)]
    (assert (not (:allowed result)) "Should not allow attach-kprobe"))

  ;; Test capability dropping
  (reset! *current-capabilities* #{:cap_bpf :cap_perfmon})
  (drop-capability! :cap_perfmon)
  (assert (not (has-capability? :cap_perfmon)) "Should have dropped CAP_PERFMON")

  (println "All capability tests passed!"))

(defn test-secure-loader []
  (println "Testing secure loader...")

  (reset! *current-capabilities* #{:cap_bpf})
  (clear-audit-log)

  (let [loader (create-secure-loader {})
        result (secure-load-program loader {:name "test" :type :kprobe})]
    (assert (:success result) "Should load program with CAP_BPF"))

  ;; Should fail without CAP_BPF
  (reset! *current-capabilities* #{})
  (let [result (secure-load-program (create-secure-loader {})
                                     {:name "test" :type :kprobe})]
    (assert (not (:success result)) "Should fail without CAP_BPF"))

  ;; Verify audit logging
  (assert (not (empty? (get-audit-log))) "Should have audit entries")

  (println "All secure loader tests passed!"))

(defn test-policy-enforcement []
  (println "Testing policy enforcement...")

  ;; Valid deployment
  (let [valid-spec {:programs [{:name "test" :type :xdp}]
                    :maps [{:name "data" :type :hash}]}]
    (assert (:valid (validate-against-policies valid-spec))
            "Valid spec should pass"))

  ;; Invalid program type
  (let [invalid-spec {:programs [{:name "test" :type :invalid}]}]
    (assert (not (:valid (validate-against-policies invalid-spec)))
            "Invalid type should fail"))

  (println "All policy tests passed!"))

(defn run-all-tests []
  (println "\nLab 17.1: Secure BPF Deployment")
  (println "================================\n")

  (test-capability-management)
  (test-secure-loader)
  (test-policy-enforcement)

  (println "\n=== Running Sample Deployment ===")
  (run-sample-deployment)

  (println "\n=== All Tests Complete ==="))
```

---

## Summary

In this lab you learned:
- How to manage Linux capabilities for BPF operations
- Implementing a secure loader with capability checks
- Dropping privileges after initial setup
- Comprehensive audit logging for security compliance
- Policy enforcement for deployment validation

## Next Steps

- Try Lab 17.2 to learn about data sanitization
- Implement secure loaders in your production BPF tools
- Add capability management to existing deployments
