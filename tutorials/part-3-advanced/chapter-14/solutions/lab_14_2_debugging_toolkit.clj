;; Lab 14.2 Solution: Debugging Toolkit
;; Comprehensive debugging tools for BPF programs
;;
;; Learning Goals:
;; - Implement instruction-level tracing
;; - Build map inspection tools
;; - Create event replay system
;; - Profile BPF program performance
;; - Detect common errors automatically

(ns lab-14-2-debugging-toolkit
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str]
            [clojure.pprint :as pp]
            [clojure.set])
  (:import [java.time LocalTime Instant]
           [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Platform Information
;; ============================================================================

(defn get-arch-name
  "Get architecture name"
  []
  (let [arch (System/getProperty "os.arch")]
    (case arch
      "amd64" "x86_64"
      "x86_64" "x86_64"
      "aarch64" "arm64"
      arch)))

(defn get-kernel-version
  "Get kernel version"
  []
  (try
    (-> (Runtime/getRuntime)
        (.exec "uname -r")
        (.getInputStream)
        (slurp)
        (str/trim))
    (catch Exception _
      "unknown")))

(defn show-platform-info
  "Display platform information for debugging"
  []
  (println "\n=== Platform Information ===")
  (println (format "Architecture:    %s" (get-arch-name)))
  (println (format "Kernel:          %s" (get-kernel-version)))
  (println (format "Java version:    %s" (System/getProperty "java.version")))
  (println (format "OS:              %s" (System/getProperty "os.name")))
  (println (format "Available CPUs:  %d" (.. Runtime getRuntime availableProcessors))))

;; ============================================================================
;; Trace Entry Structure
;; ============================================================================

(defrecord TraceEntry [checkpoint timestamp registers notes])

(defn create-trace-entry
  "Create a trace entry"
  [checkpoint & {:keys [r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 notes]
                 :or {notes nil}}]
  (->TraceEntry checkpoint
                (System/nanoTime)
                {:r0 (or r0 0) :r1 (or r1 0) :r2 (or r2 0) :r3 (or r3 0)
                 :r4 (or r4 0) :r5 (or r5 0) :r6 (or r6 0) :r7 (or r7 0)
                 :r8 (or r8 0) :r9 (or r9 0)}
                notes))

;; ============================================================================
;; Instruction Tracer
;; ============================================================================

(defn create-tracer
  "Create a new tracer"
  []
  {:entries (atom [])
   :enabled (atom true)
   :max-entries 10000})

(defn trace!
  "Add trace entry"
  [tracer checkpoint & opts]
  (when @(:enabled tracer)
    (let [entry (apply create-trace-entry checkpoint opts)]
      (swap! (:entries tracer)
             (fn [entries]
               (if (< (count entries) (:max-entries tracer))
                 (conj entries entry)
                 entries))))))

(defn clear-trace!
  "Clear trace entries"
  [tracer]
  (reset! (:entries tracer) []))

(defn get-trace
  "Get all trace entries"
  [tracer]
  @(:entries tracer))

(defn display-trace
  "Display execution trace"
  [tracer & {:keys [limit] :or {limit 50}}]
  (println "\n=== Execution Trace ===")
  (println "CHECKPOINT  TIMESTAMP(ns)  R0        R1        R2        R3")
  (println "================================================================")

  (doseq [entry (take limit (get-trace tracer))]
    (let [regs (:registers entry)]
      (println (format "%-11d %-14d %-9x %-9x %-9x %-9x"
                       (:checkpoint entry)
                       (:timestamp entry)
                       (bit-and (:r0 regs) 0xFFFFFFFF)
                       (bit-and (:r1 regs) 0xFFFFFFFF)
                       (bit-and (:r2 regs) 0xFFFFFFFF)
                       (bit-and (:r3 regs) 0xFFFFFFFF)))))

  (when (> (count (get-trace tracer)) limit)
    (println (format "\n... %d more entries"
                     (- (count (get-trace tracer)) limit)))))

(defn analyze-trace
  "Analyze trace for patterns"
  [tracer]
  (let [entries (get-trace tracer)
        checkpoints (map :checkpoint entries)
        freq (frequencies checkpoints)
        sorted-freq (sort-by val > freq)]

    (println "\n=== Trace Analysis ===")
    (println (format "Total entries: %d" (count entries)))
    (println (format "Unique checkpoints: %d" (count freq)))

    (println "\nMost frequent checkpoints:")
    (doseq [[cp count] (take 5 sorted-freq)]
      (println (format "  Checkpoint %d: %d times" cp count)))))

;; ============================================================================
;; Map Inspector
;; ============================================================================

(defrecord MockMap [type data max-entries])

(defn create-mock-map-for-inspection
  "Create a mock map for inspection demos"
  [type max-entries]
  {:type type
   :data (atom {})
   :max-entries max-entries})

(defn mock-map-update! [m k v]
  (swap! (:data m) assoc k v))

(defn mock-map-lookup [m k]
  (get @(:data m) k))

(defn mock-map-entries [m]
  @(:data m))

(defn inspect-map
  "Detailed map inspection"
  [mock-map map-name]
  (println (format "\n=== Map: %s ===" map-name))

  (let [entries (mock-map-entries mock-map)
        entry-count (count entries)]

    (println (format "Type: %s" (:type mock-map)))
    (println (format "Max entries: %d" (:max-entries mock-map)))
    (println (format "Current entries: %d" entry-count))
    (println (format "Usage: %.1f%%" (* 100.0 (/ entry-count (:max-entries mock-map)))))

    (if (zero? entry-count)
      (println "\n  (empty)")
      (do
        (println "\nKey -> Value")
        (println (str (apply str (repeat 40 "-"))))
        (doseq [[k v] (take 10 entries)]
          (println (format "  %s -> %s" (pr-str k) (pr-str v))))

        (when (> entry-count 10)
          (println (format "\n  ... %d more entries" (- entry-count 10))))))))

(defn compare-maps
  "Compare two map snapshots"
  [before after map-name]
  (println (format "\n=== Map Changes: %s ===" map-name))

  (let [before-keys (set (keys before))
        after-keys (set (keys after))
        added (clojure.set/difference after-keys before-keys)
        removed (clojure.set/difference before-keys after-keys)
        common (clojure.set/intersection before-keys after-keys)
        modified (filter #(not= (get before %) (get after %)) common)]

    (when (seq added)
      (println "\nAdded:")
      (doseq [k added]
        (println (format "  + %s -> %s" k (get after k)))))

    (when (seq removed)
      (println "\nRemoved:")
      (doseq [k removed]
        (println (format "  - %s" k))))

    (when (seq modified)
      (println "\nModified:")
      (doseq [k modified]
        (println (format "  %s: %s -> %s" k (get before k) (get after k)))))

    (when (and (empty? added) (empty? removed) (empty? modified))
      (println "\nNo changes detected"))

    {:added (count added)
     :removed (count removed)
     :modified (count modified)}))

(defn watch-map
  "Watch map for changes"
  [mock-map map-name interval-ms duration-sec]
  (println (format "Watching map '%s' for %d seconds (interval: %dms)"
                   map-name duration-sec interval-ms))

  (let [end-time (+ (System/currentTimeMillis) (* duration-sec 1000))]
    (loop [prev-snapshot (mock-map-entries mock-map)]
      (when (< (System/currentTimeMillis) end-time)
        (Thread/sleep interval-ms)
        (let [curr-snapshot (mock-map-entries mock-map)]
          (when (not= prev-snapshot curr-snapshot)
            (println (format "\n[%s] Change detected:" (LocalTime/now)))
            (compare-maps prev-snapshot curr-snapshot map-name))
          (recur curr-snapshot))))))

;; ============================================================================
;; Event Recording and Replay
;; ============================================================================

(defrecord RecordedEvent [timestamp event-type data])

(defn create-event-recorder
  "Create an event recorder"
  []
  {:events (atom [])
   :recording (atom false)
   :max-events 100000})

(defn start-recording! [recorder]
  (reset! (:recording recorder) true)
  (println "Recording started"))

(defn stop-recording! [recorder]
  (reset! (:recording recorder) false)
  (println (format "Recording stopped (%d events)" (count @(:events recorder)))))

(defn record-event! [recorder event-type data]
  (when @(:recording recorder)
    (let [event (->RecordedEvent (System/nanoTime) event-type data)]
      (swap! (:events recorder)
             (fn [events]
               (if (< (count events) (:max-events recorder))
                 (conj events event)
                 events))))))

(defn clear-recording! [recorder]
  (reset! (:events recorder) [])
  (println "Recording cleared"))

(defn get-recorded-events [recorder]
  @(:events recorder))

(defn replay-events
  "Replay recorded events"
  [recorder handler & {:keys [speed] :or {speed 1.0}}]
  (let [events (sort-by :timestamp (get-recorded-events recorder))]
    (println (format "\n=== Replaying %d Events (speed: %.1fx) ===" (count events) speed))

    (when (seq events)
      (let [first-ts (:timestamp (first events))]
        (doseq [[idx event] (map-indexed vector events)]
          (let [delay-ns (long (/ (- (:timestamp event) first-ts) speed))
                delay-ms (quot delay-ns 1000000)]
            (when (pos? delay-ms)
              (Thread/sleep (min delay-ms 1000))))

          (let [result (handler event)]
            (println (format "[%d] %s: %s -> %s"
                             idx
                             (:event-type event)
                             (pr-str (:data event))
                             result))))))

    (println "\nReplay complete")))

(defn replay-until-failure
  "Replay events until a failure occurs"
  [recorder handler failure-pred]
  (let [events (sort-by :timestamp (get-recorded-events recorder))]
    (println (format "\n=== Replaying Until Failure (%d events) ===" (count events)))

    (loop [remaining events
           idx 0]
      (if (empty? remaining)
        (println "No failure found")
        (let [event (first remaining)
              result (handler event)]
          (if (failure-pred result)
            (do
              (println (format "\nFailure at event %d:" idx))
              (pp/pprint event)
              (println "\nResult:")
              (pp/pprint result)
              {:failed-at idx :event event :result result})
            (recur (rest remaining) (inc idx))))))))

;; ============================================================================
;; Performance Profiler
;; ============================================================================

(defrecord PerfStats [min-ns max-ns total-ns count])

(defn create-profiler
  "Create a performance profiler"
  []
  {:sections (atom {})
   :enabled (atom true)})

(defn profile-start!
  "Start profiling a section"
  [profiler section-id]
  (when @(:enabled profiler)
    (swap! (:sections profiler) assoc-in [section-id :start] (System/nanoTime))))

(defn profile-end!
  "End profiling a section"
  [profiler section-id]
  (when @(:enabled profiler)
    (let [end-time (System/nanoTime)
          start-time (get-in @(:sections profiler) [section-id :start] end-time)
          duration (- end-time start-time)]
      (swap! (:sections profiler)
             update section-id
             (fn [s]
               (let [stats (or (:stats s) (->PerfStats Long/MAX_VALUE 0 0 0))]
                 (assoc s :stats
                        (->PerfStats (min (:min-ns stats) duration)
                                    (max (:max-ns stats) duration)
                                    (+ (:total-ns stats) duration)
                                    (inc (:count stats)))))))
      duration)))

(defmacro with-profiling
  "Profile a code section"
  [profiler section-id & body]
  `(do
     (profile-start! ~profiler ~section-id)
     (try
       ~@body
       (finally
         (profile-end! ~profiler ~section-id)))))

(defn get-perf-stats
  "Get performance statistics for all sections"
  [profiler]
  (into {}
        (for [[section-id section-data] @(:sections profiler)
              :when (:stats section-data)]
          [section-id (:stats section-data)])))

(defn display-perf-stats
  "Display performance statistics"
  [profiler]
  (println "\n=== Performance Statistics ===")
  (println "SECTION    MIN(ns)     MAX(ns)     AVG(ns)     COUNT")
  (println "========================================================")

  (let [stats (get-perf-stats profiler)
        sorted-stats (sort-by key stats)]
    (doseq [[section-id stat] sorted-stats]
      (let [avg (if (pos? (:count stat))
                  (quot (:total-ns stat) (:count stat))
                  0)]
        (println (format "%-10d %-11d %-11d %-11d %d"
                         section-id
                         (:min-ns stat)
                         (:max-ns stat)
                         avg
                         (:count stat)))))))

(defn find-bottlenecks
  "Identify performance bottlenecks"
  [profiler & {:keys [top-n] :or {top-n 5}}]
  (let [stats (get-perf-stats profiler)
        sorted-by-total (sort-by (fn [[_ s]] (:total-ns s)) > stats)]

    (println (format "\n=== Top %d Bottlenecks by Total Time ===" top-n))
    (doseq [[section-id stat] (take top-n sorted-by-total)]
      (let [avg (if (pos? (:count stat))
                  (quot (:total-ns stat) (:count stat))
                  0)]
        (println (format "Section %d: %.2f ms total (avg %.2f µs, %d calls)"
                         section-id
                         (/ (:total-ns stat) 1000000.0)
                         (/ avg 1000.0)
                         (:count stat)))))))

;; ============================================================================
;; Error Detection
;; ============================================================================

(defrecord ErrorPattern [name check-fn severity])

(def common-error-patterns
  [(->ErrorPattern "Map Nearly Full"
                   (fn [ctx]
                     (for [[name m] (:maps ctx)
                           :let [usage (/ (count (mock-map-entries m))
                                          (:max-entries m))]
                           :when (> usage 0.9)]
                       {:map name :usage (* 100 usage)
                        :message (format "Map '%s' is %.1f%% full" name (* 100 usage))}))
                   :high)

   (->ErrorPattern "High Drop Rate"
                   (fn [ctx]
                     (when-let [stats (:stats ctx)]
                       (when (pos? (+ (:events stats) (:drops stats)))
                         (let [drop-rate (/ (:drops stats)
                                            (+ (:events stats) (:drops stats)))]
                           (when (> drop-rate 0.05)
                             [{:drop-rate (* 100 drop-rate)
                               :message (format "High drop rate: %.1f%%" (* 100 drop-rate))}])))))
                   :medium)

   (->ErrorPattern "Stale Entries"
                   (fn [ctx]
                     (let [now (System/currentTimeMillis)
                           max-age-ms (* 3600 1000)]  ; 1 hour
                       (for [[name m] (:maps ctx)
                             [k v] (mock-map-entries m)
                             :when (and (:timestamp v)
                                        (> (- now (:timestamp v)) max-age-ms))]
                         {:map name :key k
                          :message (format "Stale entry in '%s'" name)})))
                   :low)])

(defn run-error-detection
  "Run all error detection checks"
  [context]
  (println "\n=== Error Detection ===")

  (let [all-issues (atom [])]
    (doseq [pattern common-error-patterns]
      (let [issues ((:check-fn pattern) context)]
        (when (seq issues)
          (println (format "\n%s [%s]:" (:name pattern) (name (:severity pattern))))
          (doseq [issue issues]
            (println (format "  - %s" (:message issue)))
            (swap! all-issues conj (assoc issue
                                          :pattern (:name pattern)
                                          :severity (:severity pattern)))))))

    (if (empty? @all-issues)
      (println "\nNo issues detected")
      (println (format "\nFound %d issue(s)" (count @all-issues))))

    @all-issues))

;; ============================================================================
;; Error Diagnosis
;; ============================================================================

(defn diagnose-error
  "Diagnose a BPF-related error"
  [error-type & {:keys [details]}]
  (println "\n=== Error Diagnosis ===")
  (println (format "Error: %s" (name error-type)))

  (case error-type
    :permission
    (do
      (println "\nPossible causes:")
      (println "  - Running without CAP_BPF capability")
      (println "  - unprivileged_bpf_disabled is set")
      (println "  - SELinux/AppArmor blocking BPF")
      (println "\nSuggestions:")
      (println "  - Run with sudo or add CAP_BPF")
      (println "  - Check /proc/sys/kernel/unprivileged_bpf_disabled")
      (println "  - Review security policy logs"))

    :verifier
    (do
      (println "\nPossible causes:")
      (println "  - Invalid memory access")
      (println "  - Missing bounds check")
      (println "  - Unreachable instruction")
      (println "  - Loop not bounded")
      (println "\nSuggestions:")
      (println "  - Check verifier log for specific instruction")
      (println "  - Add bounds checks before memory access")
      (println "  - Ensure loop termination"))

    :resource
    (do
      (println "\nPossible causes:")
      (println "  - Map too large")
      (println "  - Too many maps")
      (println "  - Locked memory limit")
      (println "\nSuggestions:")
      (println "  - Reduce map sizes")
      (println "  - Check ulimit -l")
      (println "  - Review /proc/sys/kernel/bpf_stats_enabled"))

    :transient
    (do
      (println "\nPossible causes:")
      (println "  - Temporary resource contention")
      (println "  - System under load")
      (println "\nSuggestions:")
      (println "  - Retry the operation")
      (println "  - Reduce concurrent BPF operations")
      (println "  - Check system load"))

    (println "Unknown error type")))

;; ============================================================================
;; Interactive Debug Shell
;; ============================================================================

(defn debug-shell
  "Interactive debugging shell"
  [context]
  (println "\n=== BPF Debug Shell ===")
  (println "Type 'help' for commands\n")

  (let [profiler (create-profiler)
        tracer (create-tracer)
        recorder (create-event-recorder)]

    (loop []
      (print "debug> ")
      (flush)
      (let [input (read-line)
            parts (str/split (or input "") #"\s+")
            cmd (first parts)
            args (rest parts)]

        (when input
          (case cmd
            "help"
            (do
              (println "\nCommands:")
              (println "  platform        - Show platform info")
              (println "  maps            - List all maps")
              (println "  inspect <map>   - Inspect map contents")
              (println "  trace           - Show execution trace")
              (println "  perf            - Show performance stats")
              (println "  bottlenecks     - Find bottlenecks")
              (println "  errors          - Run error detection")
              (println "  diagnose <type> - Diagnose error type")
              (println "  quit            - Exit debugger"))

            "platform"
            (show-platform-info)

            "maps"
            (do
              (println "\nAvailable maps:")
              (doseq [[name _] (:maps context)]
                (println (format "  - %s" name))))

            "inspect"
            (if-let [map-name (first args)]
              (if-let [m (get (:maps context) (keyword map-name))]
                (inspect-map m map-name)
                (println (format "Map '%s' not found" map-name)))
              (println "Usage: inspect <map-name>"))

            "trace"
            (display-trace tracer)

            "perf"
            (display-perf-stats profiler)

            "bottlenecks"
            (find-bottlenecks profiler)

            "errors"
            (run-error-detection context)

            "diagnose"
            (if-let [error-type (first args)]
              (diagnose-error (keyword error-type))
              (println "Usage: diagnose <permission|verifier|resource|transient>"))

            "quit"
            (do
              (println "Exiting debugger")
              nil)

            ""
            nil

            (println "Unknown command. Type 'help' for commands"))

          (when (not= cmd "quit")
            (recur)))))))

;; ============================================================================
;; Demonstration Functions
;; ============================================================================

(defn demonstrate-tracing
  "Demonstrate the tracing functionality"
  []
  (println "\n=== Tracing Demonstration ===")

  (let [tracer (create-tracer)]
    ;; Simulate some traced operations
    (trace! tracer 1 :r0 0x1234 :r1 0x100 :notes "Entry point")
    (trace! tracer 2 :r0 0x1234 :r1 0x200 :r2 0x300 :notes "After parse")
    (trace! tracer 3 :r0 0 :notes "Lookup failed")
    (trace! tracer 4 :r0 0x5678 :r1 0x400 :notes "New entry")
    (trace! tracer 5 :r0 2 :notes "Return XDP_PASS")

    (display-trace tracer)
    (analyze-trace tracer)))

(defn demonstrate-profiling
  "Demonstrate the profiling functionality"
  []
  (println "\n=== Profiling Demonstration ===")

  (let [profiler (create-profiler)]
    ;; Simulate profiled operations
    (dotimes [_ 100]
      (with-profiling profiler 1
        (Thread/sleep 1))
      (with-profiling profiler 2
        (Thread/sleep 2))
      (with-profiling profiler 3
        (dotimes [_ 1000]
          (+ 1 1))))

    (display-perf-stats profiler)
    (find-bottlenecks profiler)))

(defn demonstrate-map-inspection
  "Demonstrate map inspection"
  []
  (println "\n=== Map Inspection Demonstration ===")

  (let [m (create-mock-map-for-inspection :hash 100)]
    ;; Populate map
    (mock-map-update! m 6 {:count 1234 :name "TCP"})
    (mock-map-update! m 17 {:count 567 :name "UDP"})
    (mock-map-update! m 1 {:count 89 :name "ICMP"})

    (inspect-map m "protocol_stats")))

(defn demonstrate-error-detection
  "Demonstrate error detection"
  []
  (println "\n=== Error Detection Demonstration ===")

  ;; Create context with potential issues
  (let [nearly-full-map (create-mock-map-for-inspection :hash 10)
        _ (dotimes [i 9]
            (mock-map-update! nearly-full-map i {:value i}))
        context {:maps {:nearly-full nearly-full-map}
                 :stats {:events 1000 :drops 100}}]

    (run-error-detection context)))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the debugging toolkit lab"
  [& args]
  (let [command (first args)]
    (case command
      "shell"
      (let [m (create-mock-map-for-inspection :hash 100)
            _ (mock-map-update! m 6 {:count 1234 :name "TCP"})
            _ (mock-map-update! m 17 {:count 567 :name "UDP"})
            context {:maps {:stats m}}]
        (debug-shell context))

      "trace"
      (demonstrate-tracing)

      "profile"
      (demonstrate-profiling)

      "inspect"
      (demonstrate-map-inspection)

      "errors"
      (demonstrate-error-detection)

      "diagnose"
      (let [error-type (keyword (or (second args) "permission"))]
        (diagnose-error error-type))

      ;; Default: full demonstration
      (do
        (println "Lab 14.2: Debugging Toolkit")
        (println "============================")
        (println "\nUsage:")
        (println "  shell               - Interactive debug shell")
        (println "  trace               - Tracing demonstration")
        (println "  profile             - Profiling demonstration")
        (println "  inspect             - Map inspection demo")
        (println "  errors              - Error detection demo")
        (println "  diagnose <type>     - Error diagnosis")
        (println)

        ;; Run all demonstrations
        (show-platform-info)
        (demonstrate-tracing)
        (demonstrate-profiling)
        (demonstrate-map-inspection)
        (demonstrate-error-detection)

        (println "\n=== Key Takeaways ===")
        (println "1. Tracing provides visibility into program execution")
        (println "2. Map inspection helps debug state issues")
        (println "3. Profiling identifies performance bottlenecks")
        (println "4. Automated error detection catches common issues")
        (println "5. Interactive shell improves debugging workflow")))))

;; Run with: clj -M -m lab-14-2-debugging-toolkit
;; Or:       clj -M -m lab-14-2-debugging-toolkit shell
