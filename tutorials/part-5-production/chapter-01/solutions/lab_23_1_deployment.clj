(ns lab-23-1-deployment
  "Lab 23.1: Deployment Strategies

   This solution demonstrates:
   - Canary deployment with health checks
   - Blue-green deployment with rollback
   - Version management
   - Deployment state machine

   Run with: clojure -M -m lab-23-1-deployment test"
  (:require [clojure.string :as str])
  (:import [java.util UUID]))

;;; ============================================================================
;;; Part 1: Version Management
;;; ============================================================================

(defrecord ProgramVersion
  [id name version commit-hash created-at status])

(defn create-version
  "Create a new program version"
  [name version commit-hash]
  (->ProgramVersion
    (str (UUID/randomUUID))
    name
    version
    commit-hash
    (System/currentTimeMillis)
    :pending))

(def version-registry
  "Registry of program versions"
  (atom {}))

(defn register-version!
  "Register a new version"
  [version]
  (swap! version-registry assoc (:id version) version)
  version)

(defn get-version
  "Get version by ID"
  [id]
  (get @version-registry id))

(defn update-version-status!
  "Update version status"
  [id status]
  (swap! version-registry update id assoc :status status))

(defn list-versions
  "List all versions"
  []
  (vals @version-registry))

(defn active-version
  "Get the currently active version"
  []
  (first (filter #(= :active (:status %)) (list-versions))))

;;; ============================================================================
;;; Part 2: Health Checks
;;; ============================================================================

(defrecord HealthCheck
  [name check-fn timeout-ms])

(defn create-health-check
  "Create a health check"
  [name check-fn & {:keys [timeout-ms] :or {timeout-ms 5000}}]
  (->HealthCheck name check-fn timeout-ms))

(defn run-health-check
  "Run a single health check"
  [health-check]
  (try
    (let [start (System/currentTimeMillis)
          result ((:check-fn health-check))
          duration (- (System/currentTimeMillis) start)]
      {:name (:name health-check)
       :healthy result
       :duration-ms duration})
    (catch Exception e
      {:name (:name health-check)
       :healthy false
       :error (.getMessage e)})))

(defn run-all-health-checks
  "Run all health checks and return aggregate result"
  [checks]
  (let [results (map run-health-check checks)
        all-healthy (every? :healthy results)]
    {:healthy all-healthy
     :checks results}))

(def default-health-checks
  "Default health checks for BPF programs"
  [(create-health-check "program-loaded" (fn [] true))
   (create-health-check "map-accessible" (fn [] true))
   (create-health-check "no-errors" (fn [] true))])

;;; ============================================================================
;;; Part 3: Deployment State Machine
;;; ============================================================================

(def deployment-states
  #{:pending :deploying :canary :rolling-out :active :rolling-back :failed})

(def valid-transitions
  {:pending #{:deploying :failed}
   :deploying #{:canary :active :failed :rolling-back}
   :canary #{:rolling-out :rolling-back :failed}
   :rolling-out #{:active :rolling-back :failed}
   :active #{:rolling-back}
   :rolling-back #{:failed :active}
   :failed #{}})

(defn valid-transition?
  "Check if state transition is valid"
  [from to]
  (contains? (get valid-transitions from #{}) to))

(defrecord Deployment
  [id version-id strategy state started-at completed-at
   canary-percentage hosts-deployed total-hosts health-status])

(def current-deployment
  "Current deployment state"
  (atom nil))

(defn create-deployment
  "Create a new deployment"
  [version-id strategy & {:keys [canary-pct total-hosts]
                          :or {canary-pct 10 total-hosts 100}}]
  (->Deployment
    (str (UUID/randomUUID))
    version-id
    strategy
    :pending
    (System/currentTimeMillis)
    nil
    canary-pct
    0
    total-hosts
    nil))

(defn update-deployment-state!
  "Update deployment state"
  [new-state]
  (when @current-deployment
    (if (valid-transition? (:state @current-deployment) new-state)
      (do
        (swap! current-deployment assoc :state new-state)
        (when (#{:active :failed} new-state)
          (swap! current-deployment assoc :completed-at (System/currentTimeMillis)))
        true)
      (throw (ex-info "Invalid state transition"
                      {:from (:state @current-deployment) :to new-state})))))

;;; ============================================================================
;;; Part 4: Canary Deployment
;;; ============================================================================

(defn start-canary-deployment
  "Start a canary deployment"
  [version health-checks]
  (let [deployment (create-deployment (:id version) :canary)]
    (reset! current-deployment deployment)
    (update-deployment-state! :deploying)

    ;; Simulate deploying to canary hosts
    (let [canary-count (int (* (:total-hosts deployment)
                               (/ (:canary-percentage deployment) 100)))]
      (swap! current-deployment assoc :hosts-deployed canary-count)
      (update-deployment-state! :canary)

      ;; Run health checks
      (let [health (run-all-health-checks health-checks)]
        (swap! current-deployment assoc :health-status health)
        health))))

(defn promote-canary
  "Promote canary to full deployment"
  []
  (when (and @current-deployment (= :canary (:state @current-deployment)))
    (update-deployment-state! :rolling-out)
    (swap! current-deployment assoc :hosts-deployed (:total-hosts @current-deployment))
    (update-deployment-state! :active)
    (update-version-status! (:version-id @current-deployment) :active)
    true))

(defn rollback-canary
  "Rollback canary deployment"
  []
  (when @current-deployment
    (update-deployment-state! :rolling-back)
    (swap! current-deployment assoc :hosts-deployed 0)
    (update-version-status! (:version-id @current-deployment) :rolled-back)
    (update-deployment-state! :failed)
    true))

;;; ============================================================================
;;; Part 5: Blue-Green Deployment
;;; ============================================================================

(def blue-version (atom nil))
(def green-version (atom nil))
(def active-color (atom :blue))

(defn deploy-green
  "Deploy new version to green environment"
  [version health-checks]
  (reset! green-version version)
  (let [deployment (create-deployment (:id version) :blue-green)]
    (reset! current-deployment deployment)
    (update-deployment-state! :deploying)

    ;; Run health checks on green
    (let [health (run-all-health-checks health-checks)]
      (swap! current-deployment assoc :health-status health)
      (if (:healthy health)
        (do
          (update-deployment-state! :active)
          health)
        (do
          (reset! green-version nil)
          (update-deployment-state! :failed)
          health)))))

(defn switch-to-green
  "Switch traffic to green environment"
  []
  (when (and @green-version (= :active (:state @current-deployment)))
    (reset! blue-version @green-version)
    (reset! active-color :blue)
    (update-version-status! (:id @green-version) :active)
    true))

(defn rollback-to-blue
  "Rollback to blue environment"
  []
  (when @blue-version
    (reset! active-color :blue)
    (reset! green-version nil)
    true))

;;; ============================================================================
;;; Part 6: Deployment Metrics
;;; ============================================================================

(def deployment-metrics
  "Track deployment metrics"
  (atom {:total-deployments 0
         :successful 0
         :failed 0
         :rolled-back 0
         :avg-duration-ms 0}))

(defn record-deployment-result!
  "Record deployment result for metrics"
  [deployment]
  (swap! deployment-metrics
         (fn [m]
           (let [duration (- (or (:completed-at deployment) (System/currentTimeMillis))
                            (:started-at deployment))]
             (-> m
                 (update :total-deployments inc)
                 (update (case (:state deployment)
                           :active :successful
                           :failed :failed
                           :successful) inc)
                 (assoc :avg-duration-ms
                        (/ (+ (* (:avg-duration-ms m) (:total-deployments m)) duration)
                           (inc (:total-deployments m)))))))))

(defn get-deployment-metrics
  "Get deployment metrics"
  []
  @deployment-metrics)

;;; ============================================================================
;;; Part 7: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 23.1 Tests ===\n")

  ;; Test 1: Version creation
  (println "Test 1: Version Creation")
  (reset! version-registry {})
  (let [v (create-version "test-prog" "1.0.0" "abc123")]
    (assert (some? (:id v)) "id generated")
    (assert (= "test-prog" (:name v)) "name set")
    (assert (= :pending (:status v)) "initial status pending"))
  (println "  Version creation works correctly")
  (println "  PASSED\n")

  ;; Test 2: Version registry
  (println "Test 2: Version Registry")
  (reset! version-registry {})
  (let [v1 (register-version! (create-version "prog" "1.0" "aaa"))
        v2 (register-version! (create-version "prog" "2.0" "bbb"))]
    (assert (= v1 (get-version (:id v1))) "v1 retrievable")
    (assert (= v2 (get-version (:id v2))) "v2 retrievable")
    (assert (= 2 (count (list-versions))) "two versions"))
  (println "  Version registry works correctly")
  (println "  PASSED\n")

  ;; Test 3: Health checks
  (println "Test 3: Health Checks")
  (let [healthy-check (create-health-check "ok" (fn [] true))
        unhealthy-check (create-health-check "fail" (fn [] false))
        error-check (create-health-check "error" (fn [] (throw (Exception. "oops"))))]
    (assert (:healthy (run-health-check healthy-check)) "healthy check passes")
    (assert (not (:healthy (run-health-check unhealthy-check))) "unhealthy check fails")
    (assert (not (:healthy (run-health-check error-check))) "error check fails"))
  (println "  Health checks work correctly")
  (println "  PASSED\n")

  ;; Test 4: State transitions
  (println "Test 4: State Transitions")
  (assert (valid-transition? :pending :deploying) "pending->deploying valid")
  (assert (valid-transition? :canary :rolling-out) "canary->rolling-out valid")
  (assert (not (valid-transition? :pending :active)) "pending->active invalid")
  (assert (not (valid-transition? :failed :active)) "failed->active invalid")
  (println "  State transitions validated correctly")
  (println "  PASSED\n")

  ;; Test 5: Canary deployment
  (println "Test 5: Canary Deployment")
  (reset! version-registry {})
  (reset! current-deployment nil)
  (let [v (register-version! (create-version "test" "1.0" "abc"))
        health (start-canary-deployment v default-health-checks)]
    (assert (some? @current-deployment) "deployment created")
    (assert (= :canary (:state @current-deployment)) "in canary state")
    (assert (:healthy health) "health check passed"))
  (println "  Canary deployment works correctly")
  (println "  PASSED\n")

  ;; Test 6: Canary promotion
  (println "Test 6: Canary Promotion")
  (assert (promote-canary) "promotion succeeds")
  (assert (= :active (:state @current-deployment)) "now active")
  (assert (= (:total-hosts @current-deployment)
             (:hosts-deployed @current-deployment)) "all hosts deployed")
  (println "  Canary promotion works correctly")
  (println "  PASSED\n")

  ;; Test 7: Rollback
  (println "Test 7: Rollback")
  (reset! current-deployment nil)
  (let [v (register-version! (create-version "test" "2.0" "def"))]
    (start-canary-deployment v default-health-checks)
    (assert (rollback-canary) "rollback succeeds")
    (assert (= :failed (:state @current-deployment)) "marked failed")
    (assert (= 0 (:hosts-deployed @current-deployment)) "no hosts"))
  (println "  Rollback works correctly")
  (println "  PASSED\n")

  ;; Test 8: Blue-green deployment
  (println "Test 8: Blue-Green Deployment")
  (reset! blue-version nil)
  (reset! green-version nil)
  (reset! current-deployment nil)
  (let [v (register-version! (create-version "test" "3.0" "ghi"))
        health (deploy-green v default-health-checks)]
    (assert (some? @green-version) "green version set")
    (assert (:healthy health) "health check passed")
    (assert (switch-to-green) "switch succeeds")
    (assert (= @blue-version v) "blue now points to new version"))
  (println "  Blue-green deployment works correctly")
  (println "  PASSED\n")

  ;; Test 9: Deployment metrics
  (println "Test 9: Deployment Metrics")
  (reset! deployment-metrics {:total-deployments 0 :successful 0 :failed 0 :rolled-back 0 :avg-duration-ms 0})
  (record-deployment-result! {:state :active :started-at 1000 :completed-at 2000})
  (record-deployment-result! {:state :failed :started-at 2000 :completed-at 2500})
  (let [m (get-deployment-metrics)]
    (assert (= 2 (:total-deployments m)) "two deployments")
    (assert (= 1 (:successful m)) "one successful")
    (assert (= 1 (:failed m)) "one failed"))
  (println "  Deployment metrics work correctly")
  (println "  PASSED\n")

  ;; Test 10: Active version tracking
  (println "Test 10: Active Version Tracking")
  (reset! version-registry {})
  (let [v1 (register-version! (create-version "test" "1.0" "aaa"))
        v2 (register-version! (create-version "test" "2.0" "bbb"))]
    (update-version-status! (:id v2) :active)
    (let [active (active-version)]
      (assert (some? active) "active version found")
      (assert (= "2.0" (:version active)) "correct version active")))
  (println "  Active version tracking works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 8: Demo
;;; ============================================================================

(defn run-demo
  "Run demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 23.1: Deployment Strategies")
  (println (str/join "" (repeat 60 "=")) "\n")

  (reset! version-registry {})
  (reset! current-deployment nil)
  (reset! deployment-metrics {:total-deployments 0 :successful 0 :failed 0 :rolled-back 0 :avg-duration-ms 0})

  ;; Simulate canary deployment
  (println "=== Canary Deployment Demo ===\n")

  (let [v1 (register-version! (create-version "network-monitor" "1.0.0" "abc123"))]
    (println (format "1. Created version: %s v%s" (:name v1) (:version v1)))

    (println "2. Starting canary deployment (10% of hosts)...")
    (let [health (start-canary-deployment v1 default-health-checks)]
      (println (format "   Deployed to %d/%d hosts"
                       (:hosts-deployed @current-deployment)
                       (:total-hosts @current-deployment)))
      (println (format "   Health status: %s" (if (:healthy health) "HEALTHY" "UNHEALTHY")))

      (println "3. Monitoring canary for 5 seconds...")
      (Thread/sleep 100)  ; Simulated monitoring

      (println "4. Canary healthy, promoting to full deployment...")
      (promote-canary)
      (println (format "   Deployed to %d/%d hosts"
                       (:hosts-deployed @current-deployment)
                       (:total-hosts @current-deployment)))
      (println (format "   Status: %s" (name (:state @current-deployment))))
      (record-deployment-result! @current-deployment)))

  (println)

  ;; Simulate failed deployment
  (println "=== Failed Deployment Demo ===\n")

  (reset! current-deployment nil)
  (let [v2 (register-version! (create-version "network-monitor" "1.1.0" "def456"))
        bad-checks [(create-health-check "failing-check" (fn [] false))]]

    (println (format "1. Created version: %s v%s" (:name v2) (:version v2)))
    (println "2. Starting canary deployment with failing health check...")

    (let [health (start-canary-deployment v2 bad-checks)]
      (println (format "   Health status: %s" (if (:healthy health) "HEALTHY" "UNHEALTHY")))
      (println "3. Health check failed, rolling back...")
      (rollback-canary)
      (println (format "   Status: %s" (name (:state @current-deployment))))
      (record-deployment-result! @current-deployment)))

  (println)

  ;; Show metrics
  (println "=== Deployment Metrics ===\n")
  (let [m (get-deployment-metrics)]
    (println (format "Total deployments: %d" (:total-deployments m)))
    (println (format "Successful: %d" (:successful m)))
    (println (format "Failed: %d" (:failed m)))
    (println (format "Avg duration: %.0fms" (:avg-duration-ms m)))))

;;; ============================================================================
;;; Part 9: Main
;;; ============================================================================

(defn -main [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      (do
        (println "Usage: clojure -M -m lab-23-1-deployment <command>")
        (println "Commands:")
        (println "  test  - Run tests")
        (println "  demo  - Run demonstration")))))
