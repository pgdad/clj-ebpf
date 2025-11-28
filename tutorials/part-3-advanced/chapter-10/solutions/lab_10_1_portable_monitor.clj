(ns lab-10-1-portable-monitor
  "Lab 10.1: Portable Process Monitor using CO-RE

   This solution demonstrates:
   - CO-RE (Compile Once, Run Everywhere) concepts for BPF portability
   - Field offset relocations that work across kernel versions
   - BTF (BPF Type Format) for type information
   - task_struct field access simulation
   - Cross-kernel compatible process monitoring

   Note: Real CO-RE requires libbpf and kernel BTF support (5.2+).
   This solution simulates CO-RE concepts using available kernel info.

   Run with: clojure -M -m lab-10-1-portable-monitor test
   Note: Some features require root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as ebpf]
            [clojure.string :as str])
  (:import [java.util.concurrent ConcurrentHashMap]
           [java.util.concurrent.atomic AtomicLong AtomicInteger]
           [java.time Instant LocalDateTime ZoneId]
           [java.time.format DateTimeFormatter]))

;;; ============================================================================
;;; Part 1: BTF and CO-RE Concepts (Simulated)
;;; ============================================================================

;; BTF Type Information Database
;; In real CO-RE, this comes from /sys/kernel/btf/vmlinux
(def btf-types
  "Simulated BTF type information for common kernel structures"
  {:task_struct
   {:size 9344  ; Varies by kernel version
    :fields {:__state     {:offset 0     :size 4  :type :unsigned-int}
             :state       {:offset 0     :size 8  :type :volatile-long}  ; Legacy name
             :stack       {:offset 8     :size 8  :type :pointer}
             :pid         {:offset 1192  :size 4  :type :pid_t}
             :tgid        {:offset 1196  :size 4  :type :pid_t}
             :comm        {:offset 1504  :size 16 :type :char-array}
             :cred        {:offset 1856  :size 8  :type :pointer}
             :real_parent {:offset 1216  :size 8  :type :pointer}}}

   :cred
   {:size 176
    :fields {:uid  {:offset 4  :size 4 :type :kuid_t}
             :gid  {:offset 8  :size 4 :type :kgid_t}
             :euid {:offset 20 :size 4 :type :kuid_t}
             :egid {:offset 24 :size 4 :type :kgid_t}}}

   :sched_entity
   {:size 264
    :fields {:sum_exec_runtime {:offset 48 :size 8 :type :u64}
             :prev_sum_exec_runtime {:offset 56 :size 8 :type :u64}}}

   :mm_struct
   {:size 1024
    :fields {:start_code {:offset 168 :size 8 :type :unsigned-long}
             :end_code   {:offset 176 :size 8 :type :unsigned-long}
             :start_data {:offset 184 :size 8 :type :unsigned-long}}}})

;; Kernel version info (simulated detection)
(def kernel-versions
  "Simulated kernel version database showing field changes"
  {"5.4"  {:has-state true  :has-__state false :pid-offset 1176 :comm-offset 1472}
   "5.15" {:has-state false :has-__state true  :pid-offset 1192 :comm-offset 1504}
   "6.0"  {:has-state false :has-__state true  :pid-offset 1200 :comm-offset 1520}
   "6.5"  {:has-state false :has-__state true  :pid-offset 1208 :comm-offset 1528}})

(defn get-kernel-version
  "Get current kernel version"
  []
  (try
    (let [uname (-> (Runtime/getRuntime)
                    (.exec "uname -r")
                    (.getInputStream)
                    (slurp)
                    (str/trim))]
      (if-let [[_ major minor] (re-find #"^(\d+)\.(\d+)" uname)]
        {:string uname
         :major (Integer/parseInt major)
         :minor (Integer/parseInt minor)}
        {:string uname :major 5 :minor 15}))
    (catch Exception _
      {:string "unknown" :major 5 :minor 15})))

(defn btf-available?
  "Check if BTF is available on this system"
  []
  (try
    (.exists (java.io.File. "/sys/kernel/btf/vmlinux"))
    (catch Exception _ false)))

;;; ============================================================================
;;; Part 2: CO-RE Relocation Helpers
;;; ============================================================================

(defn core-field-offset
  "Get field offset using CO-RE relocation
   In real CO-RE, this is resolved at BPF load time from kernel BTF"
  [struct-name field-name]
  (let [struct-info (get btf-types (keyword struct-name))
        field-info (get-in struct-info [:fields (keyword field-name)])]
    (when field-info
      (:offset field-info))))

(defn core-field-exists?
  "Check if field exists in structure (CO-RE existence check)"
  [struct-name field-name]
  (let [struct-info (get btf-types (keyword struct-name))]
    (boolean (get-in struct-info [:fields (keyword field-name)]))))

(defn core-field-size
  "Get field size using CO-RE"
  [struct-name field-name]
  (let [struct-info (get btf-types (keyword struct-name))
        field-info (get-in struct-info [:fields (keyword field-name)])]
    (when field-info
      (:size field-info))))

(defn core-struct-size
  "Get structure size using CO-RE"
  [struct-name]
  (:size (get btf-types (keyword struct-name))))

;;; ============================================================================
;;; Part 3: Mock Process Information
;;; ============================================================================

(def process-events (atom []))
(def process-stats (ConcurrentHashMap.))
(def event-counter (AtomicLong. 0))

(defn generate-mock-process
  "Generate a mock process event"
  []
  (let [pid (+ 1000 (rand-int 60000))
        ppid (if (> (rand) 0.3) (+ 1 (rand-int 999)) 1)
        uid (if (> (rand) 0.5) 1000 0)
        gid uid
        commands ["bash" "ls" "cat" "grep" "find" "python3" "java" "node"
                  "vim" "git" "docker" "systemd" "sshd" "nginx" "postgres"]
        comm (rand-nth commands)]
    {:pid pid
     :ppid ppid
     :uid uid
     :gid gid
     :comm comm
     :filename (str "/usr/bin/" comm)
     :timestamp (System/nanoTime)
     :event-id (.incrementAndGet event-counter)}))

;;; ============================================================================
;;; Part 4: Portable Field Reader (CO-RE Pattern)
;;; ============================================================================

(defn read-task-field-portable
  "Read a field from task_struct using portable CO-RE approach
   This function demonstrates the pattern, actual BPF would use relocations"
  [task field-name]
  (let [offset (core-field-offset "task_struct" field-name)
        size (core-field-size "task_struct" field-name)]
    (when (and offset size)
      {:field field-name
       :offset offset
       :size size
       :value (get task (keyword field-name))})))

(defn read-cred-field-portable
  "Read field from task->cred using CO-RE (nested structure access)"
  [task field-name]
  (let [cred-offset (core-field-offset "task_struct" "cred")
        field-offset (core-field-offset "cred" field-name)]
    (when (and cred-offset field-offset)
      {:struct-chain ["task_struct" "cred"]
       :total-offset (+ cred-offset field-offset)
       :field field-name
       :value (get task (keyword field-name))})))

(defn read-task-state-adaptive
  "Adaptive task state reader - handles both 'state' and '__state' fields"
  [task]
  (cond
    ;; Modern kernels (5.14+) use __state
    (core-field-exists? "task_struct" "__state")
    {:field "__state"
     :offset (core-field-offset "task_struct" "__state")
     :value (get task :state 0)}

    ;; Legacy kernels use state
    (core-field-exists? "task_struct" "state")
    {:field "state"
     :offset (core-field-offset "task_struct" "state")
     :value (get task :state 0)}

    ;; Fallback
    :else
    {:field "unknown" :offset 0 :value 0}))

;;; ============================================================================
;;; Part 5: Process Event Processing
;;; ============================================================================

(defn format-timestamp
  "Format nanosecond timestamp for display"
  [ns-timestamp]
  (let [seconds (quot ns-timestamp 1000000000)
        ms (quot (rem ns-timestamp 1000000000) 1000000)]
    (format "%d.%03d" seconds ms)))

(defn format-process-event
  "Format process event for display"
  [event]
  (format "[%s] PID=%-6d PPID=%-6d UID=%-5d GID=%-5d %-16s %s"
          (format-timestamp (:timestamp event))
          (:pid event)
          (:ppid event)
          (:uid event)
          (:gid event)
          (:comm event)
          (:filename event)))

(defn update-process-stats!
  "Update statistics for a process"
  [event]
  (let [pid (:pid event)
        current (.get process-stats pid)]
    (if current
      (.put process-stats pid (update current :count inc))
      (.put process-stats pid {:pid pid
                               :comm (:comm event)
                               :count 1
                               :first-seen (:timestamp event)
                               :last-seen (:timestamp event)}))
    ;; Update last-seen
    (when current
      (.put process-stats pid (assoc current :last-seen (:timestamp event))))))

(defn process-event!
  "Process a single event"
  [event]
  (swap! process-events conj event)
  (update-process-stats! event)
  (println (format-process-event event)))

;;; ============================================================================
;;; Part 6: BTF Structure Inspector
;;; ============================================================================

(defn inspect-structure
  "Inspect a kernel structure's BTF layout"
  [struct-name]
  (println (format "\n=== %s Structure ===" (str/upper-case struct-name)))
  (if-let [struct-info (get btf-types (keyword struct-name))]
    (do
      (println (format "Size: %d bytes" (:size struct-info)))
      (println (format "Fields: %d" (count (:fields struct-info))))
      (println "\nOFFSET   SIZE  TYPE                    NAME")
      (println "================================================================")
      (doseq [[field-name field-info] (sort-by (comp :offset val) (:fields struct-info))]
        (printf "%-8d %-5d %-23s %s\n"
                (:offset field-info)
                (:size field-info)
                (name (:type field-info))
                (name field-name))))
    (println (format "Structure '%s' not found" struct-name))))

(defn search-field
  "Search for a field across all structures"
  [field-name-pattern]
  (println (format "\n=== Searching for '%s' ===" field-name-pattern))
  (let [pattern (re-pattern (str "(?i)" field-name-pattern))
        results (for [[struct-name struct-info] btf-types
                      [field-name field-info] (:fields struct-info)
                      :when (re-find pattern (name field-name))]
                  {:struct (name struct-name)
                   :field (name field-name)
                   :offset (:offset field-info)
                   :size (:size field-info)
                   :type (:type field-info)})]
    (if (seq results)
      (do
        (println "\nSTRUCT           FIELD            OFFSET  SIZE  TYPE")
        (println "================================================================")
        (doseq [r results]
          (printf "%-16s %-16s %-7d %-5d %s\n"
                  (:struct r) (:field r) (:offset r) (:size r) (name (:type r)))))
      (println "No matches found"))))

;;; ============================================================================
;;; Part 7: Comparison Tool
;;; ============================================================================

(defn compare-kernel-layouts
  "Compare task_struct layouts across kernel versions"
  []
  (println "\n=== task_struct Layout Comparison ===\n")
  (println "VERSION    PID OFFSET    COMM OFFSET   STATE FIELD")
  (println "=================================================")
  (doseq [[version info] (sort-by key kernel-versions)]
    (printf "%-10s %-13d %-13d %s\n"
            version
            (:pid-offset info)
            (:comm-offset info)
            (if (:has-__state info) "__state" "state"))))

(defn demonstrate-portability
  "Demonstrate CO-RE portability concepts"
  []
  (println "\n=== CO-RE Portability Demonstration ===\n")

  (println "Traditional Approach (Hardcoded Offsets):")
  (println "  // FRAGILE: Breaks on different kernel versions")
  (println "  pid = *(u32 *)(task + 1192);  // Assumes 5.15 layout")
  (println "  comm = (char *)(task + 1504); // Breaks on 5.4, 6.0+")
  (println)

  (println "CO-RE Approach (Portable):")
  (println "  // ROBUST: Works on all kernels with BTF")
  (println "  pid_offset = BPF_CORE_READ(task_struct, pid);")
  (println "  comm = BPF_CORE_READ_STR(task_struct, comm);")
  (println)

  (println "Field Resolution Example:")
  (println (format "  task_struct.pid on this kernel: offset=%d"
                   (core-field-offset "task_struct" "pid")))
  (println (format "  task_struct.comm on this kernel: offset=%d"
                   (core-field-offset "task_struct" "comm")))

  (let [state-info (read-task-state-adaptive {})]
    (println (format "  State field: '%s' at offset %d (adaptive)"
                     (:field state-info)
                     (:offset state-info)))))

;;; ============================================================================
;;; Part 8: Monitor Simulation
;;; ============================================================================

(defn run-monitor
  "Run the process monitor simulation"
  [duration-seconds]
  (println "\n=== Portable Process Monitor (CO-RE Simulation) ===\n")

  (let [kernel-info (get-kernel-version)]
    (println (format "Kernel: %s" (:string kernel-info)))
    (println (format "BTF Available: %s" (if (btf-available?) "YES" "NO (simulated)"))))

  (println "\nStarting process monitoring simulation...")
  (println "This demonstrates CO-RE patterns for cross-kernel portability\n")
  (println "TIME          PID    PPID   UID   GID   COMMAND          FILENAME")
  (println "=============================================================================")

  (let [start-time (System/currentTimeMillis)
        end-time (+ start-time (* duration-seconds 1000))]
    (loop []
      (when (< (System/currentTimeMillis) end-time)
        ;; Generate and process events at random intervals
        (dotimes [_ (inc (rand-int 3))]
          (let [event (generate-mock-process)]
            (process-event! event)))
        (Thread/sleep (+ 200 (rand-int 300)))
        (recur))))

  (println "\n=== Monitor Statistics ===")
  (println (format "Total events: %d" (count @process-events)))
  (println (format "Unique processes: %d" (.size process-stats)))

  (println "\nTop 5 processes by execution count:")
  (let [sorted-stats (->> (.values process-stats)
                          (sort-by :count >)
                          (take 5))]
    (doseq [stat sorted-stats]
      (printf "  %-16s %d executions\n" (:comm stat) (:count stat)))))

;;; ============================================================================
;;; Part 9: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 10.1 Tests ===\n")

  ;; Test 1: BTF field access
  (println "Test 1: CO-RE Field Offset Resolution")
  (let [pid-offset (core-field-offset "task_struct" "pid")
        comm-offset (core-field-offset "task_struct" "comm")]
    (assert (number? pid-offset) "pid offset should be a number")
    (assert (number? comm-offset) "comm offset should be a number")
    (println (format "  task_struct.pid offset: %d" pid-offset))
    (println (format "  task_struct.comm offset: %d" comm-offset))
    (println "  PASSED"))

  ;; Test 2: Field existence checks
  (println "\nTest 2: CO-RE Field Existence Checks")
  (let [has-pid (core-field-exists? "task_struct" "pid")
        has-comm (core-field-exists? "task_struct" "comm")
        has-nonexistent (core-field-exists? "task_struct" "nonexistent_field")]
    (assert has-pid "pid should exist")
    (assert has-comm "comm should exist")
    (assert (not has-nonexistent) "nonexistent field should not exist")
    (println "  pid exists: true")
    (println "  comm exists: true")
    (println "  nonexistent_field exists: false")
    (println "  PASSED"))

  ;; Test 3: Adaptive state reading
  (println "\nTest 3: Adaptive State Field Reading")
  (let [state-info (read-task-state-adaptive {:state 0})]
    (assert (contains? #{"state" "__state"} (:field state-info))
            "Should read either state or __state")
    (println (format "  Selected field: %s" (:field state-info)))
    (println (format "  Offset: %d" (:offset state-info)))
    (println "  PASSED"))

  ;; Test 4: Nested structure access
  (println "\nTest 4: CO-RE Nested Structure Access (task->cred->uid)")
  (let [uid-info (read-cred-field-portable {:uid 1000} "uid")]
    (assert uid-info "Should resolve nested field")
    (assert (= ["task_struct" "cred"] (:struct-chain uid-info)))
    (println (format "  Struct chain: %s" (:struct-chain uid-info)))
    (println (format "  Total offset: %d" (:total-offset uid-info)))
    (println "  PASSED"))

  ;; Test 5: Process event generation and formatting
  (println "\nTest 5: Process Event Generation")
  (let [event (generate-mock-process)
        formatted (format-process-event event)]
    (assert (pos? (:pid event)) "PID should be positive")
    (assert (not (str/blank? (:comm event))) "comm should not be blank")
    (assert (string? formatted) "Should produce formatted string")
    (println (format "  Generated event: PID=%d CMD=%s" (:pid event) (:comm event)))
    (println "  PASSED"))

  ;; Test 6: Structure inspection
  (println "\nTest 6: BTF Structure Inspection")
  (let [size (core-struct-size "task_struct")]
    (assert (pos? size) "Structure size should be positive")
    (println (format "  task_struct size: %d bytes" size))
    (println "  PASSED"))

  (println "\n=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 10: Demo and Main
;;; ============================================================================

(defn run-demo
  "Run interactive demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 10.1: Portable Process Monitor using CO-RE")
  (println (str/join "" (repeat 60 "=")) "\n")

  ;; Show kernel info
  (let [kernel (get-kernel-version)]
    (println "System Information:")
    (println (format "  Kernel: %s" (:string kernel)))
    (println (format "  BTF: %s" (if (btf-available?) "Available" "Simulated"))))

  ;; Demonstrate CO-RE concepts
  (demonstrate-portability)

  ;; Compare kernel layouts
  (compare-kernel-layouts)

  ;; Inspect key structures
  (inspect-structure "task_struct")
  (inspect-structure "cred")

  ;; Search for pid-related fields
  (search-field "pid")

  ;; Run short monitor
  (println "\n--- Running 5-second monitor simulation ---")
  (run-monitor 5))

(defn -main
  "Main entry point"
  [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      "monitor" (run-monitor (Integer/parseInt (or (second args) "10")))
      "inspect" (if (second args)
                  (inspect-structure (second args))
                  (do (inspect-structure "task_struct")
                      (inspect-structure "cred")))
      "search" (if (second args)
                 (search-field (second args))
                 (println "Usage: search <field-pattern>"))
      "compare" (compare-kernel-layouts)
      ;; Default: run demo
      (run-demo))))
