# Lab 18.3: Hot Update System

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Create a zero-downtime update system for BPF programs that allows updating individual program components without service interruption.

## Prerequisites

- Completed Labs 18.1 and 18.2
- Understanding of atomic operations
- Familiarity with version control concepts

## Scenario

You're running a production network monitoring system that cannot be interrupted. You need to update BPF programs, configuration, and handlers while traffic continues to flow without packet loss.

---

## Part 1: Hot Update Infrastructure

### Step 1.1: Version Management

```clojure
(ns lab-18-3.hot-updates
  (:require [clojure.string :as str])
  (:import [java.util UUID]
           [java.time Instant]
           [java.util.concurrent.atomic AtomicLong AtomicReference]))

;; Version tracking
(defrecord ProgramVersion [id version timestamp checksum])

(defn create-version [program-id version]
  (->ProgramVersion program-id
                    version
                    (Instant/now)
                    (hash program-id)))

(def version-registry (atom {}))

(defn register-version! [program-id version]
  (let [v (create-version program-id version)]
    (swap! version-registry assoc program-id v)
    v))

(defn get-current-version [program-id]
  (get @version-registry program-id))

(defn version-info [program-id]
  (when-let [v (get-current-version program-id)]
    (format "Program %s v%d (deployed %s)"
            (:id v) (:version v) (:timestamp v))))
```

### Step 1.2: Atomic Program Slots

```clojure
;; Simulated program array with atomic updates
(def program-slots (atom {}))

(defn get-slot [slot-id]
  (get @program-slots slot-id))

(defn atomic-set-slot! [slot-id program]
  "Atomically update a program slot"
  (let [old-program (get @program-slots slot-id)]
    (swap! program-slots assoc slot-id program)
    {:old old-program
     :new program
     :slot slot-id
     :timestamp (Instant/now)}))

(defn atomic-swap-slots! [slot-a slot-b]
  "Atomically swap two program slots"
  (swap! program-slots
         (fn [slots]
           (let [prog-a (get slots slot-a)
                 prog-b (get slots slot-b)]
             (-> slots
                 (assoc slot-a prog-b)
                 (assoc slot-b prog-a)))))
  {:swapped [slot-a slot-b]
   :timestamp (Instant/now)})
```

---

## Part 2: Update Strategies

### Step 2.1: Direct Replace

```clojure
(defn direct-replace [slot-id new-program]
  "Replace program immediately - fastest but may cause brief inconsistency"
  (println (format "Direct replace: slot %s" slot-id))
  (let [result (atomic-set-slot! slot-id new-program)]
    (register-version! slot-id
                       (inc (or (:version (get-current-version slot-id)) 0)))
    {:strategy :direct-replace
     :result result}))
```

### Step 2.2: Blue-Green Deployment

```clojure
(defrecord BlueGreenDeployment [blue-slot green-slot active-slot])

(defn create-blue-green [blue-slot green-slot]
  (->BlueGreenDeployment blue-slot green-slot (atom :blue)))

(defn get-active-slot [bg-deploy]
  (case @(:active-slot bg-deploy)
    :blue (:blue-slot bg-deploy)
    :green (:green-slot bg-deploy)))

(defn get-inactive-slot [bg-deploy]
  (case @(:active-slot bg-deploy)
    :blue (:green-slot bg-deploy)
    :green (:blue-slot bg-deploy)))

(defn blue-green-deploy [bg-deploy new-program]
  "Deploy to inactive slot, then switch"
  (println "Blue-Green deployment starting...")

  ;; Step 1: Deploy to inactive slot
  (let [inactive-slot (get-inactive-slot bg-deploy)]
    (println (format "  Deploying to inactive slot: %s" inactive-slot))
    (atomic-set-slot! inactive-slot new-program))

  ;; Step 2: Verify new program (simulated)
  (println "  Verifying new program...")
  (Thread/sleep 100)  ; Simulated verification

  ;; Step 3: Atomic switch
  (println "  Switching active slot...")
  (swap! (:active-slot bg-deploy)
         (fn [current]
           (if (= current :blue) :green :blue)))

  (println (format "  Now active: %s" @(:active-slot bg-deploy)))

  {:strategy :blue-green
   :active-slot @(:active-slot bg-deploy)
   :timestamp (Instant/now)})

(defn blue-green-rollback [bg-deploy]
  "Roll back to previous version by switching slots"
  (println "Blue-Green rollback...")
  (swap! (:active-slot bg-deploy)
         (fn [current]
           (if (= current :blue) :green :blue)))
  {:strategy :rollback
   :active-slot @(:active-slot bg-deploy)})
```

### Step 2.3: Canary Deployment

```clojure
(defrecord CanaryDeployment [main-slot canary-slot canary-percent])

(defn create-canary [main-slot canary-slot initial-percent]
  (->CanaryDeployment main-slot canary-slot (atom initial-percent)))

(defn select-slot [canary-deploy]
  "Select slot based on canary percentage"
  (let [roll (rand-int 100)]
    (if (< roll @(:canary-percent canary-deploy))
      (:canary-slot canary-deploy)
      (:main-slot canary-deploy))))

(defn canary-deploy [canary-deploy new-program]
  "Deploy to canary slot with gradual rollout"
  (println "Canary deployment starting...")

  ;; Deploy to canary slot
  (atomic-set-slot! (:canary-slot canary-deploy) new-program)
  (println (format "  Deployed to canary slot: %s" (:canary-slot canary-deploy)))

  {:strategy :canary
   :canary-slot (:canary-slot canary-deploy)
   :initial-percent @(:canary-percent canary-deploy)})

(defn adjust-canary-percent [canary-deploy new-percent]
  "Adjust the canary traffic percentage"
  (reset! (:canary-percent canary-deploy) new-percent)
  (println (format "Canary traffic: %d%%" new-percent)))

(defn promote-canary [canary-deploy]
  "Promote canary to main (100% traffic)"
  (let [canary-program (get-slot (:canary-slot canary-deploy))]
    (atomic-set-slot! (:main-slot canary-deploy) canary-program)
    (reset! (:canary-percent canary-deploy) 0)
    (println "Canary promoted to main")))

(defn gradual-canary-rollout [canary-deploy new-program steps delay-ms]
  "Gradually increase canary traffic"
  (canary-deploy canary-deploy new-program)

  (let [increment (/ 100 steps)]
    (doseq [pct (range increment 101 increment)]
      (adjust-canary-percent canary-deploy (min 100 (int pct)))
      (Thread/sleep delay-ms)))

  (promote-canary canary-deploy))
```

---

## Part 3: Configuration Hot Updates

### Step 3.1: Versioned Configuration

```clojure
(def config-store (atom {:version 0 :data {}}))

(defn get-config-version []
  (:version @config-store))

(defn get-config [key]
  (get-in @config-store [:data key]))

(defn update-config! [updates]
  "Atomically update configuration with version bump"
  (swap! config-store
         (fn [store]
           (-> store
               (update :version inc)
               (update :data merge updates))))
  {:version (get-config-version)
   :timestamp (Instant/now)})

(defn config-watcher [last-version callback]
  "Watch for configuration changes"
  (let [running (atom true)]
    (future
      (while @running
        (let [current-version (get-config-version)]
          (when (> current-version @last-version)
            (reset! last-version current-version)
            (callback @config-store)))
        (Thread/sleep 100)))
    (fn [] (reset! running false))))
```

### Step 3.2: Rule Hot Reload

```clojure
(def validation-rules (atom {:version 0 :rules []}))

(defn add-rule! [rule]
  (swap! validation-rules
         (fn [state]
           (-> state
               (update :version inc)
               (update :rules conj rule))))
  (println (format "Added rule: %s (v%d)"
                   (:name rule)
                   (:version @validation-rules))))

(defn remove-rule! [rule-name]
  (swap! validation-rules
         (fn [state]
           (-> state
               (update :version inc)
               (update :rules
                       (fn [rules]
                         (vec (remove #(= rule-name (:name %)) rules)))))))
  (println (format "Removed rule: %s" rule-name)))

(defn apply-rules [packet]
  (let [rules (:rules @validation-rules)]
    (reduce
      (fn [result rule]
        (if (:passed result)
          (let [check-result ((:check-fn rule) packet)]
            (if check-result
              result
              {:passed false :failed-rule (:name rule)}))
          result))
      {:passed true}
      rules)))
```

---

## Part 4: Update Monitoring

### Step 4.1: Update History

```clojure
(def update-history (atom []))

(defn record-update! [update-event]
  (swap! update-history conj
         (merge update-event {:recorded-at (Instant/now)})))

(defn get-update-history [& {:keys [limit since]}]
  (cond->> @update-history
    since (filter #(.isAfter (:recorded-at %) since))
    limit (take-last limit)))

(defn display-update-history []
  (println "\n=== Update History ===\n")
  (println (format "%-20s %-15s %-15s %s"
                   "Timestamp" "Strategy" "Target" "Result"))
  (println (apply str (repeat 65 "-")))
  (doseq [event (get-update-history :limit 10)]
    (println (format "%-20s %-15s %-15s %s"
                     (str (:timestamp event))
                     (name (or (:strategy event) :unknown))
                     (or (:target event) "N/A")
                     (or (:result event) "OK")))))
```

### Step 4.2: Health Checks

```clojure
(def health-checks (atom {}))

(defn register-health-check! [name check-fn]
  (swap! health-checks assoc name check-fn))

(defn run-health-checks []
  (into {}
    (for [[name check-fn] @health-checks]
      [name (try
              {:status (if (check-fn) :healthy :unhealthy)}
              (catch Exception e
                {:status :error :error (.getMessage e)}))])))

(defn wait-for-healthy [timeout-ms]
  "Wait for all health checks to pass"
  (let [start-time (System/currentTimeMillis)]
    (loop []
      (let [results (run-health-checks)
            all-healthy (every? #(= :healthy (:status %)) (vals results))
            elapsed (- (System/currentTimeMillis) start-time)]
        (cond
          all-healthy {:success true :results results}
          (> elapsed timeout-ms) {:success false :results results :reason :timeout}
          :else (do (Thread/sleep 100) (recur)))))))
```

---

## Part 5: Complete Hot Update System

### Step 5.1: Update Manager

```clojure
(defrecord UpdateManager [strategies active-strategy health-checks])

(defn create-update-manager []
  (->UpdateManager (atom {})
                   (atom nil)
                   (atom {})))

(defn register-strategy! [manager name strategy]
  (swap! (:strategies manager) assoc name strategy))

(defn set-active-strategy! [manager name]
  (reset! (:active-strategy manager) name))

(defn perform-update [manager target new-program & {:keys [verify-timeout]}]
  (let [strategy-name @(:active-strategy manager)
        strategy (get @(:strategies manager) strategy-name)]
    (if strategy
      (let [start-time (System/currentTimeMillis)
            result (strategy target new-program)]
        (record-update! {:strategy strategy-name
                         :target target
                         :timestamp (Instant/now)
                         :duration-ms (- (System/currentTimeMillis) start-time)})

        ;; Verify if requested
        (when verify-timeout
          (println "Verifying update...")
          (let [health (wait-for-healthy verify-timeout)]
            (when-not (:success health)
              (println "WARNING: Health check failed after update"))))

        result)
      {:error "No active strategy"})))
```

### Step 5.2: Full Demo

```clojure
(defn run-hot-update-demo []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "         Hot Update System Demo")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  ;; Setup
  (let [manager (create-update-manager)
        bg-deploy (create-blue-green :slot-blue :slot-green)
        canary-deploy (create-canary :slot-main :slot-canary 0)]

    ;; Register strategies
    (register-strategy! manager :direct
                        (fn [target program] (direct-replace target program)))
    (register-strategy! manager :blue-green
                        (fn [target program] (blue-green-deploy bg-deploy program)))
    (register-strategy! manager :canary
                        (fn [target program] (canary-deploy canary-deploy program)))

    ;; Initialize slots
    (atomic-set-slot! :slot-blue {:name "program-v1" :version 1})
    (atomic-set-slot! :slot-green {:name "program-v1" :version 1})
    (atomic-set-slot! :slot-main {:name "program-v1" :version 1})
    (atomic-set-slot! :slot-canary {:name "program-v1" :version 1})

    ;; Register health checks
    (register-health-check! :slots-valid
                            #(every? some? [(get-slot :slot-blue)
                                           (get-slot :slot-green)]))

    ;; Demo 1: Direct Replace
    (println "\n--- Demo 1: Direct Replace ---")
    (set-active-strategy! manager :direct)
    (perform-update manager :slot-direct {:name "program-v2" :version 2})

    ;; Demo 2: Blue-Green Deployment
    (println "\n--- Demo 2: Blue-Green Deployment ---")
    (set-active-strategy! manager :blue-green)
    (perform-update manager :any {:name "program-v2" :version 2})

    ;; Demo 3: Blue-Green Rollback
    (println "\n--- Demo 3: Blue-Green Rollback ---")
    (blue-green-rollback bg-deploy)

    ;; Demo 4: Canary Deployment
    (println "\n--- Demo 4: Canary Deployment ---")
    (set-active-strategy! manager :canary)
    (perform-update manager :any {:name "program-v3" :version 3})
    (println "\nSimulating traffic with canary:")
    (dotimes [_ 100]
      (let [slot (select-slot canary-deploy)]
        (when (= slot (:canary-slot canary-deploy))
          (print "."))))
    (println)

    ;; Gradual rollout
    (println "\nGradual canary rollout...")
    (doseq [pct [10 25 50 75 100]]
      (adjust-canary-percent canary-deploy pct)
      (Thread/sleep 200))

    ;; Demo 5: Configuration Update
    (println "\n--- Demo 5: Configuration Hot Update ---")
    (update-config! {:rate-limit 1000 :timeout-ms 5000})
    (println (format "Config updated to v%d" (get-config-version)))
    (update-config! {:rate-limit 2000})
    (println (format "Config updated to v%d" (get-config-version)))

    ;; Demo 6: Rule Hot Reload
    (println "\n--- Demo 6: Rule Hot Reload ---")
    (add-rule! {:name "size-check"
                :check-fn #(< (:size %) 9000)})
    (add-rule! {:name "port-check"
                :check-fn #(not= 23 (:port %))})
    (println "Testing rules...")
    (println "  Valid packet:" (apply-rules {:size 100 :port 80}))
    (println "  Invalid (port):" (apply-rules {:size 100 :port 23}))
    (remove-rule! "port-check")
    (println "After removing port rule:")
    (println "  Same packet:" (apply-rules {:size 100 :port 23}))

    ;; Show history
    (display-update-history)))
```

---

## Part 6: Exercises

### Exercise 1: A/B Testing

Implement A/B testing with metrics collection:

```clojure
(defn exercise-ab-testing []
  ;; TODO: Implement A/B testing
  ;; 1. Split traffic between variants
  ;; 2. Collect metrics per variant
  ;; 3. Statistical significance testing
  ;; 4. Auto-promotion of winner
  )
```

### Exercise 2: Automated Rollback

Implement automatic rollback on health check failure:

```clojure
(defn exercise-auto-rollback []
  ;; TODO: Implement auto rollback
  ;; 1. Monitor health after update
  ;; 2. Detect degradation
  ;; 3. Automatic rollback trigger
  ;; 4. Alert notification
  )
```

### Exercise 3: Update Scheduling

Implement scheduled updates with maintenance windows:

```clojure
(defn exercise-scheduled-updates []
  ;; TODO: Implement update scheduling
  ;; 1. Define maintenance windows
  ;; 2. Queue updates
  ;; 3. Execute at scheduled time
  ;; 4. Support emergency overrides
  )
```

---

## Part 7: Testing Your Implementation

### Test Script

```clojure
(defn test-version-management []
  (println "Testing version management...")
  (let [v1 (register-version! "test-prog" 1)
        v2 (register-version! "test-prog" 2)]
    (assert (= 2 (:version (get-current-version "test-prog")))
            "Should have version 2")
    (println "Version management tests passed!")))

(defn test-atomic-slots []
  (println "Testing atomic slot updates...")
  (atomic-set-slot! :test-slot {:v 1})
  (assert (= 1 (:v (get-slot :test-slot))) "Should have v=1")
  (atomic-set-slot! :test-slot {:v 2})
  (assert (= 2 (:v (get-slot :test-slot))) "Should have v=2")
  (println "Atomic slot tests passed!"))

(defn test-blue-green []
  (println "Testing blue-green deployment...")
  (let [bg (create-blue-green :blue :green)]
    (assert (= :blue (get-active-slot bg)) "Should start with blue")
    (atomic-set-slot! :green {:version 2})
    (swap! (:active-slot bg) (constantly :green))
    (assert (= :green (get-active-slot bg)) "Should switch to green")
    (println "Blue-green tests passed!")))

(defn test-canary ()
  (println "Testing canary deployment...")
  (let [canary (create-canary :main :canary 0)]
    (adjust-canary-percent canary 50)
    (let [selections (frequencies
                       (repeatedly 1000 #(select-slot canary)))]
      (assert (> (:canary selections 0) 400) "Should have ~50% canary")
      (assert (> (:main selections 0) 400) "Should have ~50% main"))
    (println "Canary tests passed!")))

(defn run-all-tests []
  (println "\nLab 18.3: Hot Update System")
  (println "===========================\n")

  (test-version-management)
  (test-atomic-slots)
  (test-blue-green)
  (test-canary)

  ;; Full demo
  (run-hot-update-demo)

  (println "\n=== All Tests Complete ==="))
```

---

## Summary

In this lab you learned:
- Implementing atomic program slot updates
- Blue-green deployment for zero-downtime updates
- Canary deployments with gradual rollout
- Configuration and rule hot reloading
- Health checking and automatic verification
- Update history and monitoring

## Next Steps

- Implement these patterns in your production BPF systems
- Add automated testing before promotion
- Build dashboards for update monitoring
