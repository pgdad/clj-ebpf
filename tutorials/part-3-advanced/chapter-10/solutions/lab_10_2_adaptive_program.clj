(ns lab-10-2-adaptive-program
  "Lab 10.2: Kernel Version Adaptive Program

   This solution demonstrates:
   - Runtime feature detection based on kernel capabilities
   - Adaptive code paths for different kernel versions
   - Graceful degradation for missing features
   - CO-RE field existence checks
   - Version-aware BPF program behavior

   Note: Real adaptive programs use libbpf CO-RE macros.
   This solution simulates the concepts in userspace.

   Run with: clojure -M -m lab-10-2-adaptive-program test"
  (:require [clj-ebpf.core :as ebpf]
            [clojure.string :as str])
  (:import [java.util.concurrent ConcurrentHashMap]
           [java.util.concurrent.atomic AtomicLong AtomicInteger]
           [java.time Instant]))

;;; ============================================================================
;;; Part 1: Feature Level Constants
;;; ============================================================================

(def FEATURE_MODERN 0)    ;; Kernel 6.0+ with all features
(def FEATURE_STANDARD 1)  ;; Kernel 5.8-5.15 with ring buffer
(def FEATURE_LEGACY 2)    ;; Kernel 5.2-5.7 with basic BTF
(def FEATURE_MINIMAL 3)   ;; Kernel 4.19-5.1 without BTF

(defn format-feature-level
  "Format feature level for display"
  [level]
  (case level
    0 "MODERN (6.0+)"
    1 "STANDARD (5.8-5.15)"
    2 "LEGACY (5.2-5.7)"
    3 "MINIMAL (4.19-5.1)"
    "UNKNOWN"))

;;; ============================================================================
;;; Part 2: Kernel Feature Detection
;;; ============================================================================

(def detected-features (atom nil))

(defn get-kernel-version-info
  "Parse kernel version from uname"
  []
  (try
    (let [uname (-> (Runtime/getRuntime)
                    (.exec "uname -r")
                    (.getInputStream)
                    (slurp)
                    (str/trim))]
      (if-let [[_ major minor patch] (re-find #"^(\d+)\.(\d+)\.?(\d+)?" uname)]
        {:string uname
         :major (Integer/parseInt major)
         :minor (Integer/parseInt minor)
         :patch (when patch (Integer/parseInt patch))
         :code (+ (* (Integer/parseInt major) 65536)
                  (* (Integer/parseInt minor) 256)
                  (if patch (Integer/parseInt patch) 0))}
        {:string uname :major 5 :minor 15 :patch 0 :code 0x050F00}))
    (catch Exception _
      {:string "5.15.0" :major 5 :minor 15 :patch 0 :code 0x050F00})))

(defn btf-available?
  "Check if kernel BTF is available"
  []
  (try
    (.exists (java.io.File. "/sys/kernel/btf/vmlinux"))
    (catch Exception _ false)))

(defn ringbuf-available?
  "Check if ring buffer is available (kernel 5.8+)"
  [kernel-info]
  (or (> (:major kernel-info) 5)
      (and (= (:major kernel-info) 5)
           (>= (:minor kernel-info) 8))))

(defn ktime-get-boot-ns-available?
  "Check if ktime_get_boot_ns helper is available (kernel 5.7+)"
  [kernel-info]
  (or (> (:major kernel-info) 5)
      (and (= (:major kernel-info) 5)
           (>= (:minor kernel-info) 7))))

(defn bpf-spin-lock-available?
  "Check if BPF spin locks are available (kernel 5.1+)"
  [kernel-info]
  (or (> (:major kernel-info) 5)
      (and (= (:major kernel-info) 5)
           (>= (:minor kernel-info) 1))))

(defn task-struct-has-__state?
  "Check if task_struct uses __state (kernel 5.14+)"
  [kernel-info]
  (or (> (:major kernel-info) 5)
      (and (= (:major kernel-info) 5)
           (>= (:minor kernel-info) 14))))

(defn sched-info-has-last-arrival?
  "Check if sched_info has last_arrival field (kernel 6.0+)"
  [kernel-info]
  (>= (:major kernel-info) 6))

(defn detect-kernel-features
  "Detect available kernel features"
  []
  (let [kernel-info (get-kernel-version-info)]
    {:kernel-version (:string kernel-info)
     :kernel-major (:major kernel-info)
     :kernel-minor (:minor kernel-info)
     :kernel-code (:code kernel-info)

     ;; BTF availability
     :btf-available (btf-available?)

     ;; task_struct field checks
     :has-state-field (not (task-struct-has-__state? kernel-info))
     :has-__state-field (task-struct-has-__state? kernel-info)

     ;; Scheduler info
     :has-sched-info true  ; Available since 2.6
     :has-last-arrival (sched-info-has-last-arrival? kernel-info)
     :has-sum-exec-runtime true  ; In sched_entity

     ;; Helper availability
     :has-ringbuf (ringbuf-available? kernel-info)
     :has-ktime-get-boot-ns (ktime-get-boot-ns-available? kernel-info)

     ;; Advanced features
     :has-bpf-spin-lock (bpf-spin-lock-available? kernel-info)
     :has-bpf-timer (>= (:major kernel-info) 6)}))

(defn print-detected-features
  "Pretty print detected features"
  [features]
  (println "\n=== Detected Kernel Features ===\n")
  (doseq [[feature available?] (sort-by key features)]
    (let [status (if available? "✓ YES" "✗ NO")]
      (printf "  %-25s %s\n" (name feature) status)))
  (println))

;;; ============================================================================
;;; Part 3: Feature Level Determination
;;; ============================================================================

(defn determine-feature-level
  "Determine the appropriate feature level for current kernel"
  [features]
  (cond
    ;; Modern: 6.0+ with all features
    (and (:has-last-arrival features)
         (:has-ringbuf features)
         (:has-ktime-get-boot-ns features)
         (:btf-available features))
    FEATURE_MODERN

    ;; Standard: 5.8-5.15 with ring buffer
    (and (:has-ringbuf features)
         (:btf-available features))
    FEATURE_STANDARD

    ;; Legacy: 5.2-5.7 with BTF but limited features
    (:btf-available features)
    FEATURE_LEGACY

    ;; Minimal: 4.19-5.1 without BTF
    :else
    FEATURE_MINIMAL))

;;; ============================================================================
;;; Part 4: Adaptive Data Structures
;;; ============================================================================

;; Statistics storage
(def task-stats (ConcurrentHashMap.))
(def event-counter (AtomicLong. 0))

(defn create-task-stat
  "Create a task statistics entry appropriate for feature level"
  [feature-level pid]
  (case feature-level
    ;; Modern: full statistics
    0 {:pid pid
       :runtime-ns (AtomicLong. 0)
       :context-switches (AtomicLong. 0)
       :last-arrival 0
       :boot-timestamp 0
       :state 0
       :migrations 0}

    ;; Standard: good statistics
    1 {:pid pid
       :runtime-ns (AtomicLong. 0)
       :context-switches (AtomicLong. 0)
       :timestamp 0
       :state 0}

    ;; Legacy: basic statistics
    2 {:pid pid
       :context-switches (AtomicLong. 0)
       :timestamp 0}

    ;; Minimal: just counts
    3 {:pid pid
       :context-switches (AtomicLong. 0)}))

;;; ============================================================================
;;; Part 5: Adaptive Field Readers
;;; ============================================================================

(defn read-task-state-adaptive
  "Read task state adaptively based on kernel version"
  [features task-data]
  (cond
    ;; Modern kernels use __state (unsigned int)
    (:has-__state-field features)
    {:field "__state"
     :type :u32
     :value (get task-data :state 0)}

    ;; Legacy kernels use state (volatile long)
    (:has-state-field features)
    {:field "state"
     :type :long
     :value (get task-data :state 0)}

    ;; Fallback
    :else
    {:field "unknown" :type :none :value 0}))

(defn read-runtime-stats-adaptive
  "Read scheduler runtime statistics adaptively"
  [features task-data]
  (cond
    ;; Modern: use sched_info.last_arrival (6.0+)
    (:has-last-arrival features)
    {:source "sched_info.last_arrival"
     :value (get task-data :last-arrival (System/nanoTime))}

    ;; Standard: use sched_entity.sum_exec_runtime
    (:has-sum-exec-runtime features)
    {:source "se.sum_exec_runtime"
     :value (get task-data :runtime (System/nanoTime))}

    ;; Legacy: use ktime_get_ns as proxy
    :else
    {:source "ktime_get_ns"
     :value (System/nanoTime)}))

(defn get-timestamp-adaptive
  "Get timestamp using the best available helper"
  [features]
  (if (:has-ktime-get-boot-ns features)
    {:source "ktime_get_boot_ns"
     :value (System/nanoTime)}  ; Best: boot time reference
    {:source "ktime_get_ns"
     :value (System/nanoTime)})) ; Fallback: monotonic

;;; ============================================================================
;;; Part 6: Adaptive Event Processing
;;; ============================================================================

(defn generate-sched-event
  "Generate a simulated scheduler event"
  [features]
  (let [base {:pid (+ 1 (rand-int 32768))
              :prev-pid (+ 1 (rand-int 32768))
              :prev-state (rand-int 3)
              :timestamp (System/nanoTime)
              :event-id (.incrementAndGet event-counter)}]
    (case (determine-feature-level features)
      ;; Modern: rich data
      0 (assoc base
               :runtime (+ 1000000 (rand-int 100000000))
               :last-arrival (- (System/nanoTime) (rand-int 1000000))
               :vruntime (rand-int 1000000000)
               :boot-time (- (System/nanoTime) (long (rand-int Integer/MAX_VALUE))))

      ;; Standard: good data
      1 (assoc base
               :runtime (+ 1000000 (rand-int 100000000))
               :vruntime (rand-int 1000000000))

      ;; Legacy: basic data
      2 (assoc base
               :runtime (+ 1000000 (rand-int 100000000)))

      ;; Minimal: just IDs and timestamp
      base)))

(defn process-event-modern
  "Process event using modern kernel features"
  [event stats]
  (let [{:keys [pid runtime last-arrival]} event]
    ;; Update runtime
    (.addAndGet ^AtomicLong (:runtime-ns stats) (or runtime 0))
    ;; Update context switches
    (.incrementAndGet ^AtomicLong (:context-switches stats))
    ;; Record last arrival
    (assoc stats :last-arrival (or last-arrival 0)
                 :boot-timestamp (:boot-time event 0))
    :modern-processed))

(defn process-event-standard
  "Process event using standard kernel features"
  [event stats]
  (let [{:keys [pid runtime]} event]
    ;; Update runtime
    (.addAndGet ^AtomicLong (:runtime-ns stats) (or runtime 0))
    ;; Update context switches
    (.incrementAndGet ^AtomicLong (:context-switches stats))
    :standard-processed))

(defn process-event-legacy
  "Process event using legacy kernel features"
  [event stats]
  ;; Update context switches only (no detailed runtime)
  (.incrementAndGet ^AtomicLong (:context-switches stats))
  :legacy-processed)

(defn process-event-minimal
  "Process event with minimal features"
  [event stats]
  ;; Just count context switches
  (.incrementAndGet ^AtomicLong (:context-switches stats))
  :minimal-processed)

(defn process-event-adaptive
  "Process event based on detected feature level"
  [features event]
  (let [feature-level (determine-feature-level features)
        pid (:pid event)
        stats (or (.get task-stats pid)
                  (let [new-stats (create-task-stat feature-level pid)]
                    (.put task-stats pid new-stats)
                    new-stats))]
    (case feature-level
      0 (process-event-modern event stats)
      1 (process-event-standard event stats)
      2 (process-event-legacy event stats)
      3 (process-event-minimal event stats)
      :unknown)))

;;; ============================================================================
;;; Part 7: Adaptive Monitor
;;; ============================================================================

;; Forward declaration for display-stats
(declare display-stats)

(defn run-adaptive-monitor
  "Run the adaptive scheduler monitor"
  [features duration-seconds]
  (let [feature-level (determine-feature-level features)]
    (println "\n=== Adaptive Scheduler Monitor ===\n")
    (println (format "Kernel: %s" (:kernel-version features)))
    (println (format "Feature Level: %s" (format-feature-level feature-level)))
    (println)

    ;; Show what features are being used
    (println "Active capabilities for this kernel:")
    (case feature-level
      0 (do (println "  • High-resolution boot timestamps")
            (println "  • Detailed scheduler statistics")
            (println "  • Ring buffer events")
            (println "  • Accurate CPU runtime tracking"))
      1 (do (println "  • Ring buffer events")
            (println "  • Scheduler entity runtime")
            (println "  • Basic state tracking"))
      2 (do (println "  • BTF type information")
            (println "  • Basic runtime statistics"))
      3 (do (println "  • Context switch counting only")
            (println "  • No BTF support")))

    (println (format "\nMonitoring for %d seconds..." duration-seconds))
    (println)

    ;; Run monitoring loop
    (let [start-time (System/currentTimeMillis)
          end-time (+ start-time (* duration-seconds 1000))
          event-count (atom 0)]

      (loop []
        (when (< (System/currentTimeMillis) end-time)
          (let [event (generate-sched-event features)
                result (process-event-adaptive features event)]
            (swap! event-count inc)
            (when (zero? (mod @event-count 100))
              (print (format "\rProcessed %d events..." @event-count))
              (flush)))
          (Thread/sleep (+ 5 (rand-int 15)))
          (recur)))

      (println (format "\nProcessed %d total events" @event-count)))

    ;; Display results
    (display-stats feature-level)))

(defn display-stats
  "Display collected statistics"
  [feature-level]
  (println "\n=== Task Statistics ===\n")

  (case feature-level
    ;; Modern: full stats
    0 (do
        (println "PID      Switches   Runtime(ms)  Last Arrival")
        (println "================================================")
        (doseq [[pid stats] (->> task-stats
                                 (sort-by key)
                                 (take 10))]
          (printf "%-8d %-10d %-12.2f %d\n"
                  pid
                  (.get ^AtomicLong (:context-switches stats))
                  (double (/ (.get ^AtomicLong (:runtime-ns stats)) 1000000))
                  (get stats :last-arrival 0))))

    ;; Standard: good stats
    1 (do
        (println "PID      Switches   Runtime(ms)")
        (println "================================")
        (doseq [[pid stats] (->> task-stats
                                 (sort-by key)
                                 (take 10))]
          (printf "%-8d %-10d %.2f\n"
                  pid
                  (.get ^AtomicLong (:context-switches stats))
                  (double (/ (.get ^AtomicLong (:runtime-ns stats)) 1000000)))))

    ;; Legacy/Minimal: basic stats
    (do
      (println "PID      Context Switches")
      (println "=========================")
      (doseq [[pid stats] (->> task-stats
                               (sort-by key)
                               (take 10))]
        (printf "%-8d %d\n"
                pid
                (.get ^AtomicLong (:context-switches stats)))))))

;;; ============================================================================
;;; Part 8: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 10.2 Tests ===\n")

  ;; Test 1: Feature detection
  (println "Test 1: Kernel Feature Detection")
  (let [features (detect-kernel-features)]
    (assert (string? (:kernel-version features)) "Should have kernel version")
    (assert (boolean? (:btf-available features)) "Should have BTF status")
    (println (format "  Kernel: %s" (:kernel-version features)))
    (println (format "  BTF: %s" (:btf-available features)))
    (println "  PASSED"))

  ;; Test 2: Feature level determination
  (println "\nTest 2: Feature Level Determination")
  (let [features (detect-kernel-features)
        level (determine-feature-level features)]
    (assert (<= 0 level 3) "Level should be 0-3")
    (println (format "  Determined level: %d (%s)" level (format-feature-level level)))
    (println "  PASSED"))

  ;; Test 3: Adaptive state reading
  (println "\nTest 3: Adaptive State Field Reading")
  (let [features (detect-kernel-features)
        state-info (read-task-state-adaptive features {:state 1})]
    (assert (contains? #{"state" "__state" "unknown"} (:field state-info)))
    (println (format "  Field: %s, Type: %s" (:field state-info) (:type state-info)))
    (println "  PASSED"))

  ;; Test 4: Adaptive runtime reading
  (println "\nTest 4: Adaptive Runtime Stats Reading")
  (let [features (detect-kernel-features)
        runtime-info (read-runtime-stats-adaptive features {:runtime 1000000})]
    (assert (string? (:source runtime-info)) "Should have source info")
    (println (format "  Source: %s" (:source runtime-info)))
    (println "  PASSED"))

  ;; Test 5: Timestamp source selection
  (println "\nTest 5: Adaptive Timestamp Selection")
  (let [features (detect-kernel-features)
        ts-info (get-timestamp-adaptive features)]
    (assert (contains? #{"ktime_get_ns" "ktime_get_boot_ns"} (:source ts-info)))
    (println (format "  Using: %s" (:source ts-info)))
    (println "  PASSED"))

  ;; Test 6: Event generation per level
  (println "\nTest 6: Feature-Level Event Generation")
  (doseq [level [FEATURE_MODERN FEATURE_STANDARD FEATURE_LEGACY FEATURE_MINIMAL]]
    (let [mock-features {:has-last-arrival (= level 0)
                         :has-ringbuf (< level 2)
                         :has-ktime-get-boot-ns (< level 2)
                         :btf-available (< level 3)
                         :has-__state-field true
                         :has-sum-exec-runtime true}
          event (generate-sched-event mock-features)]
      (assert (:pid event) "Event should have PID")
      (assert (:timestamp event) "Event should have timestamp")
      (printf "  Level %d: event has %d fields\n" level (count event))))
  (println "  PASSED")

  ;; Test 7: Adaptive event processing
  (println "\nTest 7: Adaptive Event Processing")
  (.clear task-stats)
  (let [features (detect-kernel-features)]
    (dotimes [_ 10]
      (let [event (generate-sched-event features)
            result (process-event-adaptive features event)]
        (assert (keyword? result) "Should return processing type")))
    (println (format "  Processed 10 events, %d unique PIDs" (.size task-stats)))
    (println "  PASSED"))

  ;; Test 8: Stats creation per level
  (println "\nTest 8: Level-Appropriate Stats Creation")
  (doseq [level [0 1 2 3]]
    (let [stats (create-task-stat level 1234)]
      (assert (:pid stats) "Should have PID")
      (assert (:context-switches stats) "Should track switches")
      (printf "  Level %d stats has %d fields\n" level (count stats))))
  (println "  PASSED")

  (println "\n=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 9: Demo
;;; ============================================================================

(defn run-demo
  "Run interactive demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 10.2: Kernel Version Adaptive Program")
  (println (str/join "" (repeat 60 "=")) "\n")

  ;; Detect and display features
  (let [features (detect-kernel-features)]
    (reset! detected-features features)
    (print-detected-features features)

    ;; Show determined feature level
    (let [level (determine-feature-level features)]
      (println (format "Selected Feature Level: %s\n" (format-feature-level level))))

    ;; Demonstrate adaptive reading
    (println "=== Adaptive Field Access Demo ===\n")

    (let [state-info (read-task-state-adaptive features {:state 0})
          runtime-info (read-runtime-stats-adaptive features {:runtime 1000})
          ts-info (get-timestamp-adaptive features)]
      (println (format "State field: %s (%s)" (:field state-info) (name (:type state-info))))
      (println (format "Runtime source: %s" (:source runtime-info)))
      (println (format "Timestamp source: %s" (:source ts-info))))

    ;; Run short monitor
    (println)
    (.clear task-stats)
    (run-adaptive-monitor features 5)))

;;; ============================================================================
;;; Part 10: Main
;;; ============================================================================

(defn -main
  "Main entry point"
  [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      "detect" (let [features (detect-kernel-features)]
                 (print-detected-features features)
                 (println (format "Feature Level: %s"
                                  (format-feature-level (determine-feature-level features)))))
      "monitor" (let [features (detect-kernel-features)
                      duration (Integer/parseInt (or (second args) "10"))]
                  (.clear task-stats)
                  (run-adaptive-monitor features duration))
      ;; Default: run demo
      (run-demo))))
