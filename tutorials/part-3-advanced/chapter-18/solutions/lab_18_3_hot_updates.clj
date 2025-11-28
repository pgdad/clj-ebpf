;; Lab 18.3 Solution: Hot Update System
;; Create a zero-downtime update system for BPF programs
;;
;; Learning Goals:
;; - Implement atomic program slot updates
;; - Blue-green deployment for zero-downtime updates
;; - Canary deployments with gradual rollout
;; - Configuration and rule hot reloading

(ns lab-18-3-hot-updates
  (:require [clojure.string :as str])
  (:import [java.util UUID]
           [java.time Instant Duration]
           [java.util.concurrent.atomic AtomicLong AtomicReference]))

;; ============================================================================
;; Version Management
;; ============================================================================

(defrecord ProgramVersion [id version timestamp checksum metadata])

(defn create-version
  "Create a new program version"
  [program-id version]
  (->ProgramVersion
    program-id
    version
    (Instant/now)
    (hash [program-id version (System/nanoTime)])
    {}))

(def version-registry
  "Registry of all program versions"
  (atom {}))

(defn register-version!
  "Register a new version of a program"
  [program-id version]
  (let [v (create-version program-id version)]
    (swap! version-registry assoc program-id v)
    v))

(defn get-current-version
  "Get current version of a program"
  [program-id]
  (get @version-registry program-id))

(defn version-info
  "Get formatted version info"
  [program-id]
  (when-let [v (get-current-version program-id)]
    (format "Program %s v%d (deployed %s)"
            (:id v) (:version v) (:timestamp v))))

;; ============================================================================
;; Atomic Program Slots
;; ============================================================================

(def program-slots
  "Simulated BPF program slots with atomic updates"
  (atom {}))

(defn get-slot
  "Get program from slot"
  [slot-id]
  (get @program-slots slot-id))

(defn atomic-set-slot!
  "Atomically update a program slot"
  [slot-id program]
  (let [old-program (get @program-slots slot-id)]
    (swap! program-slots assoc slot-id program)
    {:old old-program
     :new program
     :slot slot-id
     :timestamp (Instant/now)}))

(defn atomic-swap-slots!
  "Atomically swap two program slots"
  [slot-a slot-b]
  (swap! program-slots
         (fn [slots]
           (let [prog-a (get slots slot-a)
                 prog-b (get slots slot-b)]
             (-> slots
                 (assoc slot-a prog-b)
                 (assoc slot-b prog-a)))))
  {:swapped [slot-a slot-b]
   :timestamp (Instant/now)})

(defn list-slots
  "List all program slots"
  []
  @program-slots)

;; ============================================================================
;; Update Strategies - Direct Replace
;; ============================================================================

(defn direct-replace
  "Replace program immediately - fastest but may cause brief inconsistency"
  [slot-id new-program]
  (println (format "Direct replace: slot %s with %s"
                   slot-id (:name new-program)))
  (let [result (atomic-set-slot! slot-id new-program)
        version (inc (or (:version (get-current-version slot-id)) 0))]
    (register-version! slot-id version)
    {:strategy :direct-replace
     :result result
     :version version}))

;; ============================================================================
;; Update Strategies - Blue-Green Deployment
;; ============================================================================

(defrecord BlueGreenDeployment [blue-slot green-slot active-slot stats])

(defn create-blue-green
  "Create a blue-green deployment setup"
  [blue-slot green-slot]
  (->BlueGreenDeployment
    blue-slot
    green-slot
    (atom :blue)
    (atom {:switches 0 :rollbacks 0})))

(defn get-active-slot
  "Get currently active slot"
  [bg-deploy]
  (case @(:active-slot bg-deploy)
    :blue (:blue-slot bg-deploy)
    :green (:green-slot bg-deploy)))

(defn get-inactive-slot
  "Get currently inactive slot"
  [bg-deploy]
  (case @(:active-slot bg-deploy)
    :blue (:green-slot bg-deploy)
    :green (:blue-slot bg-deploy)))

(defn blue-green-deploy
  "Deploy to inactive slot, then switch"
  [bg-deploy new-program]
  (println "\nBlue-Green deployment starting...")

  ;; Step 1: Deploy to inactive slot
  (let [inactive-slot (get-inactive-slot bg-deploy)]
    (println (format "  1. Deploying to inactive slot: %s" inactive-slot))
    (atomic-set-slot! inactive-slot new-program))

  ;; Step 2: Verify new program (simulated)
  (println "  2. Verifying new program...")
  (Thread/sleep 100)

  ;; Step 3: Atomic switch
  (println "  3. Switching active slot...")
  (swap! (:active-slot bg-deploy)
         (fn [current]
           (if (= current :blue) :green :blue)))

  (swap! (:stats bg-deploy) update :switches inc)

  (println (format "  Now active: %s slot" (name @(:active-slot bg-deploy))))

  {:strategy :blue-green
   :active-slot @(:active-slot bg-deploy)
   :active-slot-id (get-active-slot bg-deploy)
   :timestamp (Instant/now)})

(defn blue-green-rollback
  "Roll back to previous version by switching slots"
  [bg-deploy]
  (println "\nBlue-Green rollback...")
  (let [from @(:active-slot bg-deploy)]
    (swap! (:active-slot bg-deploy)
           (fn [current]
             (if (= current :blue) :green :blue)))
    (swap! (:stats bg-deploy) update :rollbacks inc)
    (println (format "  Rolled back from %s to %s"
                     (name from)
                     (name @(:active-slot bg-deploy))))
    {:strategy :rollback
     :from from
     :to @(:active-slot bg-deploy)
     :active-slot-id (get-active-slot bg-deploy)}))

(defn get-blue-green-stats
  "Get blue-green deployment statistics"
  [bg-deploy]
  @(:stats bg-deploy))

;; ============================================================================
;; Update Strategies - Canary Deployment
;; ============================================================================

(defrecord CanaryDeployment [main-slot canary-slot canary-percent stats])

(defn create-canary
  "Create a canary deployment setup"
  [main-slot canary-slot initial-percent]
  (->CanaryDeployment
    main-slot
    canary-slot
    (atom initial-percent)
    (atom {:main-traffic 0 :canary-traffic 0})))

(defn select-slot
  "Select slot based on canary percentage"
  [canary-deploy]
  (let [roll (rand-int 100)]
    (if (< roll @(:canary-percent canary-deploy))
      (do
        (swap! (:stats canary-deploy) update :canary-traffic inc)
        (:canary-slot canary-deploy))
      (do
        (swap! (:stats canary-deploy) update :main-traffic inc)
        (:main-slot canary-deploy)))))

(defn canary-deploy
  "Deploy to canary slot with gradual rollout"
  [canary-deploy new-program]
  (println "\nCanary deployment starting...")

  ;; Deploy to canary slot
  (atomic-set-slot! (:canary-slot canary-deploy) new-program)
  (println (format "  Deployed to canary slot: %s" (:canary-slot canary-deploy)))
  (println (format "  Initial traffic: %d%%" @(:canary-percent canary-deploy)))

  {:strategy :canary
   :canary-slot (:canary-slot canary-deploy)
   :initial-percent @(:canary-percent canary-deploy)})

(defn adjust-canary-percent
  "Adjust the canary traffic percentage"
  [canary-deploy new-percent]
  (let [old-percent @(:canary-percent canary-deploy)]
    (reset! (:canary-percent canary-deploy) new-percent)
    (println (format "  Canary traffic: %d%% -> %d%%" old-percent new-percent))))

(defn promote-canary
  "Promote canary to main (copy canary program to main)"
  [canary-deploy]
  (let [canary-program (get-slot (:canary-slot canary-deploy))]
    (atomic-set-slot! (:main-slot canary-deploy) canary-program)
    (reset! (:canary-percent canary-deploy) 0)
    (println "  Canary promoted to main!")))

(defn gradual-canary-rollout
  "Gradually increase canary traffic"
  [canary-deploy new-program steps delay-ms]
  (canary-deploy canary-deploy new-program)

  (let [increment (/ 100 steps)]
    (doseq [pct (range increment 101 increment)]
      (adjust-canary-percent canary-deploy (min 100 (int pct)))
      (Thread/sleep delay-ms)))

  (promote-canary canary-deploy))

(defn get-canary-stats
  "Get canary deployment statistics"
  [canary-deploy]
  (let [stats @(:stats canary-deploy)
        total (+ (:main-traffic stats) (:canary-traffic stats))]
    (assoc stats
      :total-traffic total
      :actual-canary-percent (if (pos? total)
                               (* 100.0 (/ (:canary-traffic stats) total))
                               0.0))))

;; ============================================================================
;; Configuration Hot Updates
;; ============================================================================

(def config-store
  "Versioned configuration store"
  (atom {:version 0 :data {}}))

(defn get-config-version
  "Get current config version"
  []
  (:version @config-store))

(defn get-config
  "Get configuration value"
  [key]
  (get-in @config-store [:data key]))

(defn get-all-config
  "Get all configuration"
  []
  (:data @config-store))

(defn update-config!
  "Atomically update configuration with version bump"
  [updates]
  (swap! config-store
         (fn [store]
           (-> store
               (update :version inc)
               (update :data merge updates))))
  (println (format "Config updated to v%d: %s"
                   (get-config-version)
                   updates))
  {:version (get-config-version)
   :timestamp (Instant/now)
   :updates updates})

(defn config-watcher
  "Watch for configuration changes"
  [callback interval-ms]
  (let [running (atom true)
        last-version (atom (get-config-version))]
    (future
      (while @running
        (let [current-version (get-config-version)]
          (when (> current-version @last-version)
            (reset! last-version current-version)
            (callback {:version current-version
                       :config (get-all-config)})))
        (Thread/sleep interval-ms)))
    ;; Return stop function
    (fn [] (reset! running false))))

;; ============================================================================
;; Rule Hot Reload
;; ============================================================================

(def validation-rules
  "Hot-reloadable validation rules"
  (atom {:version 0 :rules []}))

(defn add-rule!
  "Add a validation rule"
  [rule]
  (swap! validation-rules
         (fn [state]
           (-> state
               (update :version inc)
               (update :rules conj rule))))
  (println (format "Added rule: %s (v%d)"
                   (:name rule)
                   (:version @validation-rules))))

(defn remove-rule!
  "Remove a validation rule by name"
  [rule-name]
  (swap! validation-rules
         (fn [state]
           (-> state
               (update :version inc)
               (update :rules
                       (fn [rules]
                         (vec (remove #(= rule-name (:name %)) rules)))))))
  (println (format "Removed rule: %s (v%d)"
                   rule-name
                   (:version @validation-rules))))

(defn get-rules
  "Get all validation rules"
  []
  (:rules @validation-rules))

(defn apply-rules
  "Apply all rules to a packet"
  [packet]
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

;; ============================================================================
;; Update Monitoring
;; ============================================================================

(def update-history
  "History of all updates"
  (atom []))

(defn record-update!
  "Record an update event"
  [update-event]
  (swap! update-history conj
         (assoc update-event :recorded-at (Instant/now))))

(defn get-update-history
  "Get update history with optional filters"
  [& {:keys [limit since strategy]}]
  (cond->> @update-history
    since (filter #(.isAfter (:recorded-at %) since))
    strategy (filter #(= strategy (:strategy %)))
    limit (take-last limit)))

(defn display-update-history
  "Display update history"
  []
  (println "\n=== Update History ===\n")
  (println (format "%-24s %-15s %-15s %s"
                   "Timestamp" "Strategy" "Target" "Result"))
  (println (apply str (repeat 70 "-")))
  (doseq [event (get-update-history :limit 10)]
    (println (format "%-24s %-15s %-15s %s"
                     (str (:timestamp event))
                     (name (or (:strategy event) :unknown))
                     (or (:target event) "N/A")
                     (or (:result event) "OK")))))

;; ============================================================================
;; Health Checks
;; ============================================================================

(def health-checks
  "Registered health check functions"
  (atom {}))

(defn register-health-check!
  "Register a health check"
  [name check-fn]
  (swap! health-checks assoc name check-fn)
  (println (format "Registered health check: %s" name)))

(defn run-health-checks
  "Run all health checks"
  []
  (into {}
    (for [[name check-fn] @health-checks]
      [name (try
              {:status (if (check-fn) :healthy :unhealthy)
               :timestamp (Instant/now)}
              (catch Exception e
                {:status :error
                 :error (.getMessage e)
                 :timestamp (Instant/now)}))])))

(defn all-healthy?
  "Check if all health checks pass"
  []
  (let [results (run-health-checks)]
    (every? #(= :healthy (:status %)) (vals results))))

(defn wait-for-healthy
  "Wait for all health checks to pass"
  [timeout-ms]
  (let [start-time (System/currentTimeMillis)
        deadline (+ start-time timeout-ms)]
    (loop []
      (let [results (run-health-checks)
            all-healthy (every? #(= :healthy (:status %)) (vals results))
            now (System/currentTimeMillis)]
        (cond
          all-healthy {:success true :results results}
          (> now deadline) {:success false :results results :reason :timeout}
          :else (do (Thread/sleep 100) (recur)))))))

(defn display-health-status
  "Display health check status"
  []
  (println "\n=== Health Status ===\n")
  (let [results (run-health-checks)]
    (doseq [[name result] (sort-by key results)]
      (println (format "  %-20s %s"
                       name
                       (case (:status result)
                         :healthy "[HEALTHY]"
                         :unhealthy "[UNHEALTHY]"
                         :error (str "[ERROR: " (:error result) "]")))))))

;; ============================================================================
;; Update Manager
;; ============================================================================

(defrecord UpdateManager [strategies active-strategy])

(defn create-update-manager
  "Create an update manager"
  []
  (->UpdateManager (atom {}) (atom nil)))

(defn register-strategy!
  "Register an update strategy"
  [manager name strategy-fn]
  (swap! (:strategies manager) assoc name strategy-fn)
  (println (format "Registered strategy: %s" name)))

(defn set-active-strategy!
  "Set the active update strategy"
  [manager name]
  (reset! (:active-strategy manager) name)
  (println (format "Active strategy: %s" name)))

(defn perform-update
  "Perform an update using the active strategy"
  [manager target new-program & {:keys [verify-timeout]}]
  (let [strategy-name @(:active-strategy manager)
        strategy (get @(:strategies manager) strategy-name)]
    (if strategy
      (let [start-time (System/currentTimeMillis)
            result (strategy target new-program)
            duration (- (System/currentTimeMillis) start-time)]

        ;; Record update
        (record-update! {:strategy strategy-name
                         :target target
                         :timestamp (Instant/now)
                         :duration-ms duration
                         :program-name (:name new-program)})

        ;; Verify if requested
        (when verify-timeout
          (println "Verifying update...")
          (let [health (wait-for-healthy verify-timeout)]
            (when-not (:success health)
              (println "WARNING: Health check failed after update")
              (assoc result :health-warning true))))

        result)
      {:error (str "No strategy registered: " strategy-name)})))

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-ab-testing
  "Exercise 1: A/B Testing"
  []
  (println "\n=== Exercise: A/B Testing ===\n")

  (let [ab-stats (atom {:variant-a {:requests 0 :latency-sum 0}
                        :variant-b {:requests 0 :latency-sum 0}})
        ab-test (atom {:variant-a-percent 50})

        select-variant
        (fn []
          (if (< (rand-int 100) (:variant-a-percent @ab-test))
            :variant-a
            :variant-b))

        record-metric!
        (fn [variant latency]
          (swap! ab-stats update variant
                 (fn [s]
                   (-> s
                       (update :requests inc)
                       (update :latency-sum + latency)))))]

    ;; Simulate traffic
    (println "Running A/B test with 1000 requests...")
    (dotimes [_ 1000]
      (let [variant (select-variant)
            latency (+ 10 (rand-int (if (= variant :variant-a) 20 15)))]
        (record-metric! variant latency)))

    ;; Display results
    (println "\nResults:")
    (doseq [[variant stats] @ab-stats]
      (let [avg-latency (if (pos? (:requests stats))
                          (/ (:latency-sum stats) (:requests stats))
                          0)]
        (println (format "  %s: %d requests, %.1f ms avg latency"
                         (name variant)
                         (:requests stats)
                         (double avg-latency)))))

    ;; Determine winner
    (let [stats @ab-stats
          a-avg (/ (get-in stats [:variant-a :latency-sum])
                   (get-in stats [:variant-a :requests]))
          b-avg (/ (get-in stats [:variant-b :latency-sum])
                   (get-in stats [:variant-b :requests]))]
      (println (format "\nWinner: %s (%.1f%% faster)"
                       (if (< a-avg b-avg) "variant-a" "variant-b")
                       (* 100.0 (Math/abs (/ (- a-avg b-avg) (max a-avg b-avg)))))))))

(defn exercise-auto-rollback
  "Exercise 2: Automatic Rollback"
  []
  (println "\n=== Exercise: Auto Rollback ===\n")

  (let [bg-deploy (create-blue-green :slot-blue :slot-green)
        error-rate (atom 0)
        rollback-threshold 0.1]

    ;; Initialize slots
    (atomic-set-slot! :slot-blue {:name "stable-v1" :version 1})
    (atomic-set-slot! :slot-green {:name "stable-v1" :version 1})

    ;; Register health check
    (register-health-check! :error-rate
                            #(< @error-rate rollback-threshold))

    ;; Deploy new version
    (println "Deploying potentially buggy version...")
    (blue-green-deploy bg-deploy {:name "buggy-v2" :version 2})

    ;; Simulate errors
    (println "\nSimulating traffic with errors...")
    (dotimes [i 100]
      (let [has-error (< (rand) 0.15)]
        (when has-error
          (swap! error-rate #(+ % 0.01)))
        (Thread/sleep 10)))

    (println (format "Current error rate: %.1f%%" (* 100 @error-rate)))

    ;; Check if rollback needed
    (when (> @error-rate rollback-threshold)
      (println "\nError rate exceeded threshold! Auto-rolling back...")
      (blue-green-rollback bg-deploy)
      (reset! error-rate 0)
      (println "Rollback complete, error rate reset"))

    (display-health-status)))

(defn exercise-scheduled-updates
  "Exercise 3: Scheduled Updates"
  []
  (println "\n=== Exercise: Scheduled Updates ===\n")

  (let [update-queue (atom [])
        maintenance-windows [{:day :saturday :start 2 :end 6}
                             {:day :sunday :start 2 :end 6}]

        schedule-update!
        (fn [update]
          (swap! update-queue conj (assoc update :scheduled-at (Instant/now)))
          (println (format "Scheduled update: %s" (:name update))))

        in-maintenance-window?
        (fn []
          ;; Simplified - always return true for demo
          true)

        process-updates!
        (fn []
          (when (in-maintenance-window?)
            (doseq [update @update-queue]
              (println (format "Processing: %s" (:name update))))
            (reset! update-queue [])))]

    ;; Schedule some updates
    (schedule-update! {:name "security-patch" :priority :high})
    (schedule-update! {:name "feature-update" :priority :low})
    (schedule-update! {:name "config-change" :priority :medium})

    (println "\nQueued updates:")
    (doseq [update @update-queue]
      (println (format "  - %s (priority: %s)"
                       (:name update) (name (:priority update)))))

    ;; Process updates (in maintenance window)
    (println "\nProcessing updates in maintenance window...")
    (process-updates!)

    (println (format "\nRemaining in queue: %d" (count @update-queue)))))

;; ============================================================================
;; Test Functions
;; ============================================================================

(defn test-version-management []
  (println "Testing version management...")

  (let [v1 (register-version! "test-prog" 1)
        v2 (register-version! "test-prog" 2)]
    (assert (= 2 (:version (get-current-version "test-prog")))
            "Should have version 2"))

  (println "Version management tests passed!"))

(defn test-atomic-slots []
  (println "Testing atomic slot updates...")

  (atomic-set-slot! :test-slot {:name "prog" :v 1})
  (assert (= 1 (:v (get-slot :test-slot))) "Should have v=1")

  (atomic-set-slot! :test-slot {:name "prog" :v 2})
  (assert (= 2 (:v (get-slot :test-slot))) "Should have v=2")

  (println "Atomic slot tests passed!"))

(defn test-blue-green []
  (println "Testing blue-green deployment...")

  (let [bg (create-blue-green :blue :green)]
    (assert (= :blue (get-active-slot bg)) "Should start with blue active")

    (atomic-set-slot! :blue {:version 1})
    (atomic-set-slot! :green {:version 2})

    (blue-green-deploy bg {:name "test" :version 2})
    (assert (= :green (get-active-slot bg)) "Should switch to green")

    (blue-green-rollback bg)
    (assert (= :blue (get-active-slot bg)) "Should rollback to blue"))

  (println "Blue-green tests passed!"))

(defn test-canary []
  (println "Testing canary deployment...")

  (let [canary (create-canary :main :canary 50)]
    (adjust-canary-percent canary 50)

    ;; Sample many selections
    (let [selections (frequencies
                       (repeatedly 1000 #(select-slot canary)))]
      (assert (> (:canary selections 0) 400) "Should have ~50% canary")
      (assert (> (:main selections 0) 400) "Should have ~50% main")))

  (println "Canary tests passed!"))

(defn test-config-updates []
  (println "Testing config updates...")

  (reset! config-store {:version 0 :data {}})

  (update-config! {:key1 "value1"})
  (assert (= 1 (get-config-version)) "Should be version 1")
  (assert (= "value1" (get-config "key1")) "Should have key1")

  (update-config! {:key2 "value2"})
  (assert (= 2 (get-config-version)) "Should be version 2")

  (println "Config update tests passed!"))

(defn run-demo []
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
                        (fn [_ program] (blue-green-deploy bg-deploy program)))
    (register-strategy! manager :canary
                        (fn [_ program] (canary-deploy canary-deploy program)))

    ;; Initialize slots
    (println "\nInitializing program slots...")
    (atomic-set-slot! :slot-blue {:name "program-v1" :version 1})
    (atomic-set-slot! :slot-green {:name "program-v1" :version 1})
    (atomic-set-slot! :slot-main {:name "program-v1" :version 1})
    (atomic-set-slot! :slot-canary {:name "program-v1" :version 1})

    ;; Register health checks
    (register-health-check! :slots-valid
                            #(every? some? [(get-slot :slot-blue)
                                            (get-slot :slot-green)]))
    (register-health-check! :config-valid
                            #(>= (get-config-version) 0))

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
    (let [selections (frequencies
                       (repeatedly 100 #(select-slot canary-deploy)))]
      (println (format "  Main: %d, Canary: %d"
                       (:slot-main selections 0)
                       (:slot-canary selections 0))))

    ;; Gradual rollout
    (println "\nGradual canary rollout...")
    (doseq [pct [10 25 50 75 100]]
      (adjust-canary-percent canary-deploy pct)
      (Thread/sleep 100))

    ;; Demo 5: Configuration Update
    (println "\n--- Demo 5: Configuration Hot Update ---")
    (reset! config-store {:version 0 :data {}})
    (update-config! {:rate-limit 1000 :timeout-ms 5000})
    (update-config! {:rate-limit 2000})

    ;; Demo 6: Rule Hot Reload
    (println "\n--- Demo 6: Rule Hot Reload ---")
    (reset! validation-rules {:version 0 :rules []})

    (add-rule! {:name "size-check"
                :check-fn #(< (:size %) 9000)})
    (add-rule! {:name "port-check"
                :check-fn #(not= 23 (:port %))})

    (println "\nTesting rules:")
    (println "  Valid packet:" (apply-rules {:size 100 :port 80}))
    (println "  Invalid (port):" (apply-rules {:size 100 :port 23}))

    (remove-rule! "port-check")
    (println "\nAfter removing port rule:")
    (println "  Same packet:" (apply-rules {:size 100 :port 23}))

    ;; Show status
    (display-health-status)
    (display-update-history)))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the hot update system lab"
  [& args]
  (println "Lab 18.3: Hot Update System")
  (println "============================\n")

  (let [command (first args)]
    (case command
      "test"
      (do
        (test-version-management)
        (test-atomic-slots)
        (test-blue-green)
        (test-canary)
        (test-config-updates)
        (println "\nAll tests passed!"))

      "demo"
      (run-demo)

      "exercise1"
      (exercise-ab-testing)

      "exercise2"
      (exercise-auto-rollback)

      "exercise3"
      (exercise-scheduled-updates)

      ;; Default: run all
      (do
        (test-version-management)
        (test-atomic-slots)
        (test-blue-green)
        (test-canary)
        (test-config-updates)
        (run-demo)
        (exercise-ab-testing)
        (exercise-auto-rollback)
        (exercise-scheduled-updates)

        (println "\n=== Key Takeaways ===")
        (println "1. Atomic slot updates enable zero-downtime program updates")
        (println "2. Blue-green deployment provides instant rollback capability")
        (println "3. Canary deployments reduce risk with gradual rollout")
        (println "4. Configuration and rules can be hot-reloaded")
        (println "5. Health checks verify update success")))))

;; Run with: clj -M -m lab-18-3-hot-updates
