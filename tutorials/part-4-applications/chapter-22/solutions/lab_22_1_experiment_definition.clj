(ns lab-22-1-experiment-definition
  "Lab 22.1: Chaos Experiment Definition

   Implements chaos experiment definition and validation."
  (:require [clojure.string :as str])
  (:import [java.util UUID]))

;;; ============================================================================
;;; Part 1: Fault Types
;;; ============================================================================

(def fault-types
  "Available fault types"
  #{:network-delay      ; Add latency to network calls
    :network-drop       ; Drop network packets
    :network-corrupt    ; Corrupt network packets
    :cpu-burn           ; Consume CPU cycles
    :memory-pressure    ; Consume memory
    :disk-io-throttle   ; Throttle disk I/O
    :process-kill       ; Kill processes
    :clock-skew})       ; Skew system clock

(def blast-radius-scopes
  "Blast radius scope levels"
  #{:process :container :pod :service :namespace :cluster})

;;; ============================================================================
;;; Part 2: Experiment Definition
;;; ============================================================================

(defrecord ChaosExperiment
  [id
   name
   description
   hypothesis
   fault-config
   blast-radius
   slo-thresholds
   schedule
   status])

(defrecord FaultConfig
  [fault-type
   targets
   intensity       ; Percentage or value depending on type
   duration-ms
   ramp-up-ms])    ; Time to reach full intensity

(defrecord BlastRadius
  [scope
   max-targets
   excluded-namespaces
   excluded-services])

(defrecord SLOThresholds
  [latency-p99-ms
   error-rate-pct
   availability-pct
   throughput-min])

;;; ============================================================================
;;; Part 3: Experiment Creation
;;; ============================================================================

(defn generate-experiment-id
  "Generate unique experiment ID"
  []
  (str "exp-" (subs (str (UUID/randomUUID)) 0 8)))

(defn create-fault-config
  "Create fault configuration"
  [fault-type targets intensity duration-ms & {:keys [ramp-up-ms] :or {ramp-up-ms 0}}]
  (->FaultConfig fault-type targets intensity duration-ms ramp-up-ms))

(defn create-blast-radius
  "Create blast radius configuration"
  [scope max-targets & {:keys [excluded-namespaces excluded-services]
                        :or {excluded-namespaces #{}
                             excluded-services #{}}}]
  (->BlastRadius scope max-targets excluded-namespaces excluded-services))

(defn create-slo-thresholds
  "Create SLO thresholds"
  [& {:keys [latency-p99-ms error-rate-pct availability-pct throughput-min]
      :or {latency-p99-ms 1000
           error-rate-pct 5.0
           availability-pct 99.0
           throughput-min 0}}]
  (->SLOThresholds latency-p99-ms error-rate-pct availability-pct throughput-min))

(defn create-experiment
  "Create a chaos experiment"
  [name hypothesis fault-config blast-radius slo-thresholds
   & {:keys [description schedule]
      :or {description "" schedule nil}}]
  (->ChaosExperiment
   (generate-experiment-id)
   name
   description
   hypothesis
   fault-config
   blast-radius
   slo-thresholds
   schedule
   :pending))

;;; ============================================================================
;;; Part 4: Experiment Validation
;;; ============================================================================

(defn validate-fault-type
  "Validate fault type"
  [fault-config]
  (if (contains? fault-types (:fault-type fault-config))
    {:valid true}
    {:valid false :error (str "Invalid fault type: " (:fault-type fault-config))}))

(defn validate-intensity
  "Validate intensity is within bounds"
  [fault-config]
  (let [intensity (:intensity fault-config)]
    (cond
      (nil? intensity)
      {:valid false :error "Intensity is required"}

      (< intensity 0)
      {:valid false :error "Intensity must be >= 0"}

      (and (#{:network-drop :network-delay :cpu-burn :memory-pressure} (:fault-type fault-config))
           (> intensity 100))
      {:valid false :error "Intensity must be <= 100 for percentage-based faults"}

      :else
      {:valid true})))

(defn validate-duration
  "Validate duration is reasonable"
  [fault-config]
  (let [duration (:duration-ms fault-config)]
    (cond
      (nil? duration)
      {:valid false :error "Duration is required"}

      (< duration 1000)
      {:valid false :error "Duration must be at least 1000ms"}

      (> duration 3600000)
      {:valid false :error "Duration must be at most 1 hour"}

      :else
      {:valid true})))

(defn validate-blast-radius
  "Validate blast radius configuration"
  [blast-radius]
  (cond
    (not (contains? blast-radius-scopes (:scope blast-radius)))
    {:valid false :error (str "Invalid scope: " (:scope blast-radius))}

    (< (:max-targets blast-radius) 1)
    {:valid false :error "max-targets must be at least 1"}

    :else
    {:valid true}))

(defn validate-slo-thresholds
  "Validate SLO thresholds"
  [thresholds]
  (cond
    (< (:latency-p99-ms thresholds) 0)
    {:valid false :error "latency-p99-ms must be >= 0"}

    (or (< (:error-rate-pct thresholds) 0)
        (> (:error-rate-pct thresholds) 100))
    {:valid false :error "error-rate-pct must be between 0 and 100"}

    (or (< (:availability-pct thresholds) 0)
        (> (:availability-pct thresholds) 100))
    {:valid false :error "availability-pct must be between 0 and 100"}

    :else
    {:valid true}))

(defn validate-experiment
  "Validate entire experiment configuration"
  [experiment]
  (let [validations [(validate-fault-type (:fault-config experiment))
                     (validate-intensity (:fault-config experiment))
                     (validate-duration (:fault-config experiment))
                     (validate-blast-radius (:blast-radius experiment))
                     (validate-slo-thresholds (:slo-thresholds experiment))]]
    (if-let [error (first (filter #(not (:valid %)) validations))]
      {:valid false :error (:error error)}
      {:valid true})))

;;; ============================================================================
;;; Part 5: Experiment Store
;;; ============================================================================

(def experiment-store
  "Store for defined experiments"
  (atom {}))

(defn register-experiment!
  "Register an experiment"
  [experiment]
  (let [validation (validate-experiment experiment)]
    (if (:valid validation)
      (do
        (swap! experiment-store assoc (:id experiment) experiment)
        {:success true :experiment experiment})
      {:success false :error (:error validation)})))

(defn get-experiment
  "Get an experiment by ID"
  [id]
  (get @experiment-store id))

(defn list-experiments
  "List all experiments"
  []
  (vals @experiment-store))

(defn update-experiment-status!
  "Update experiment status"
  [id new-status]
  (when (get @experiment-store id)
    (swap! experiment-store assoc-in [id :status] new-status)))

(defn clear-experiments!
  "Clear all experiments"
  []
  (reset! experiment-store {}))

;;; ============================================================================
;;; Part 6: Experiment Templates
;;; ============================================================================

(defn network-partition-template
  "Template for network partition experiment"
  [service-name duration-ms]
  (create-experiment
   (str "Network Partition: " service-name)
   (str "System gracefully handles " service-name " unavailability")
   (create-fault-config :network-drop [service-name] 100 duration-ms)
   (create-blast-radius :service 1)
   (create-slo-thresholds :error-rate-pct 10.0 :latency-p99-ms 2000)))

(defn latency-injection-template
  "Template for latency injection experiment"
  [service-name latency-ms duration-ms]
  (create-experiment
   (str "Latency Injection: " service-name)
   (str "System handles increased latency to " service-name)
   (create-fault-config :network-delay [service-name] latency-ms duration-ms)
   (create-blast-radius :service 1)
   (create-slo-thresholds :latency-p99-ms (* 2 latency-ms))))

(defn cpu-stress-template
  "Template for CPU stress experiment"
  [service-name intensity-pct duration-ms]
  (create-experiment
   (str "CPU Stress: " service-name)
   (str "Auto-scaling handles CPU exhaustion in " service-name)
   (create-fault-config :cpu-burn [service-name] intensity-pct duration-ms)
   (create-blast-radius :container 2)
   (create-slo-thresholds :error-rate-pct 5.0)))

;;; ============================================================================
;;; Part 7: Experiment Summary
;;; ============================================================================

(defn experiment-summary
  "Generate human-readable experiment summary"
  [experiment]
  (let [fc (:fault-config experiment)
        br (:blast-radius experiment)
        slo (:slo-thresholds experiment)]
    {:name (:name experiment)
     :hypothesis (:hypothesis experiment)
     :fault (str (name (:fault-type fc)) " at " (:intensity fc) "% for "
                 (/ (:duration-ms fc) 1000) "s")
     :targets (:targets fc)
     :blast-radius (str "max " (:max-targets br) " " (name (:scope br)) "(s)")
     :slo-limits (str "latency<" (:latency-p99-ms slo) "ms, "
                      "errors<" (:error-rate-pct slo) "%, "
                      "availability>" (:availability-pct slo) "%")
     :status (:status experiment)}))

;;; ============================================================================
;;; Part 8: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 22.1 Tests ===\n")

  ;; Test 1: Fault config creation
  (println "Test 1: Fault Config Creation")
  (let [fc (create-fault-config :network-delay ["api-service"] 100 60000)]
    (assert (= :network-delay (:fault-type fc)) "correct fault type")
    (assert (= 100 (:intensity fc)) "correct intensity")
    (assert (= 60000 (:duration-ms fc)) "correct duration"))
  (println "  Fault config creation works correctly")
  (println "  PASSED\n")

  ;; Test 2: Blast radius creation
  (println "Test 2: Blast Radius Creation")
  (let [br (create-blast-radius :service 3 :excluded-namespaces #{"kube-system"})]
    (assert (= :service (:scope br)) "correct scope")
    (assert (= 3 (:max-targets br)) "correct max targets")
    (assert (contains? (:excluded-namespaces br) "kube-system") "excluded namespace"))
  (println "  Blast radius creation works correctly")
  (println "  PASSED\n")

  ;; Test 3: SLO thresholds creation
  (println "Test 3: SLO Thresholds Creation")
  (let [slo (create-slo-thresholds :latency-p99-ms 500 :error-rate-pct 1.0)]
    (assert (= 500 (:latency-p99-ms slo)) "correct latency")
    (assert (= 1.0 (:error-rate-pct slo)) "correct error rate"))
  (println "  SLO thresholds creation works correctly")
  (println "  PASSED\n")

  ;; Test 4: Experiment creation
  (println "Test 4: Experiment Creation")
  (let [exp (create-experiment
             "Test Experiment"
             "System handles fault"
             (create-fault-config :cpu-burn ["svc"] 50 30000)
             (create-blast-radius :container 1)
             (create-slo-thresholds))]
    (assert (some? (:id exp)) "has ID")
    (assert (= "Test Experiment" (:name exp)) "correct name")
    (assert (= :pending (:status exp)) "status is pending"))
  (println "  Experiment creation works correctly")
  (println "  PASSED\n")

  ;; Test 5: Fault type validation
  (println "Test 5: Fault Type Validation")
  (assert (:valid (validate-fault-type (create-fault-config :network-delay [] 0 0))) "valid type")
  (assert (not (:valid (validate-fault-type {:fault-type :invalid-type}))) "invalid type")
  (println "  Fault type validation works correctly")
  (println "  PASSED\n")

  ;; Test 6: Intensity validation
  (println "Test 6: Intensity Validation")
  (assert (:valid (validate-intensity (create-fault-config :cpu-burn [] 50 0))) "valid intensity")
  (assert (not (:valid (validate-intensity (create-fault-config :cpu-burn [] 150 0)))) "intensity > 100")
  (assert (not (:valid (validate-intensity (create-fault-config :cpu-burn [] -10 0)))) "negative intensity")
  (println "  Intensity validation works correctly")
  (println "  PASSED\n")

  ;; Test 7: Duration validation
  (println "Test 7: Duration Validation")
  (assert (:valid (validate-duration (create-fault-config :network-delay [] 0 60000))) "valid duration")
  (assert (not (:valid (validate-duration (create-fault-config :network-delay [] 0 100)))) "too short")
  (assert (not (:valid (validate-duration (create-fault-config :network-delay [] 0 7200000)))) "too long")
  (println "  Duration validation works correctly")
  (println "  PASSED\n")

  ;; Test 8: Full experiment validation
  (println "Test 8: Full Experiment Validation")
  (let [valid-exp (create-experiment
                   "Valid"
                   "Hypothesis"
                   (create-fault-config :network-delay ["svc"] 50 30000)
                   (create-blast-radius :service 1)
                   (create-slo-thresholds))]
    (assert (:valid (validate-experiment valid-exp)) "valid experiment"))
  (println "  Full experiment validation works correctly")
  (println "  PASSED\n")

  ;; Test 9: Experiment registration
  (println "Test 9: Experiment Registration")
  (clear-experiments!)
  (let [exp (create-experiment
             "Test"
             "Hypothesis"
             (create-fault-config :cpu-burn ["svc"] 50 30000)
             (create-blast-radius :container 1)
             (create-slo-thresholds))
        result (register-experiment! exp)]
    (assert (:success result) "registration succeeded")
    (assert (some? (get-experiment (:id exp))) "experiment retrievable"))
  (println "  Experiment registration works correctly")
  (println "  PASSED\n")

  ;; Test 10: Templates
  (println "Test 10: Experiment Templates")
  (let [net-exp (network-partition-template "api-service" 60000)
        lat-exp (latency-injection-template "db-service" 200 30000)
        cpu-exp (cpu-stress-template "worker-service" 80 120000)]
    (assert (= :network-drop (get-in net-exp [:fault-config :fault-type])) "network partition")
    (assert (= :network-delay (get-in lat-exp [:fault-config :fault-type])) "latency injection")
    (assert (= :cpu-burn (get-in cpu-exp [:fault-config :fault-type])) "cpu stress"))
  (println "  Experiment templates work correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 9: Demo
;;; ============================================================================

(defn demo
  "Demonstrate experiment definition"
  []
  (println "\n=== Chaos Experiment Definition Demo ===\n")
  (clear-experiments!)

  ;; Create experiments using templates
  (let [exp1 (network-partition-template "payment-service" 60000)
        exp2 (latency-injection-template "inventory-service" 500 120000)
        exp3 (cpu-stress-template "order-service" 90 180000)]

    (register-experiment! exp1)
    (register-experiment! exp2)
    (register-experiment! exp3)

    (println "Registered Experiments:")
    (doseq [exp (list-experiments)]
      (let [summary (experiment-summary exp)]
        (println (format "\n  %s" (:name summary)))
        (println (format "    Hypothesis: %s" (:hypothesis summary)))
        (println (format "    Fault: %s" (:fault summary)))
        (println (format "    Targets: %s" (:targets summary)))
        (println (format "    Blast Radius: %s" (:blast-radius summary)))
        (println (format "    SLO Limits: %s" (:slo-limits summary)))
        (println (format "    Status: %s" (name (:status summary))))))))

;;; ============================================================================
;;; Part 10: Main
;;; ============================================================================

(defn -main
  [& args]
  (case (first args)
    "test" (run-tests)
    "demo" (demo)
    (do
      (println "Usage: clojure -M -m lab-22-1-experiment-definition [test|demo]")
      (System/exit 1))))
