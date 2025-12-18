(ns perf-event-dsl
  "Examples demonstrating the Perf Event DSL.

   Perf event programs attach to hardware or software performance events
   and can sample CPU state, collect stack traces, and profile system
   performance.

   Usage: clj -M:dev -m perf-event-dsl
   Note: Requires CAP_PERFMON or CAP_SYS_ADMIN privileges."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.perf-event :as perf]))

;; ============================================================================
;; 1. Perf Types Demo
;; ============================================================================

(defn demo-perf-types
  "Demonstrate perf event types."
  []
  (println "\n=== Perf Event Types ===")
  (doseq [[k v] perf/perf-types]
    (println (format "  %-12s %d" (name k) v))))

;; ============================================================================
;; 2. Hardware Events Demo
;; ============================================================================

(defn demo-hardware-events
  "Demonstrate hardware performance events."
  []
  (println "\n=== Hardware Events ===")
  (doseq [[k v] perf/hardware-events]
    (println (format "  %-25s %d" (name k) v))))

;; ============================================================================
;; 3. Software Events Demo
;; ============================================================================

(defn demo-software-events
  "Demonstrate software performance events."
  []
  (println "\n=== Software Events ===")
  (doseq [[k v] perf/software-events]
    (println (format "  %-20s %d" (name k) v))))

;; ============================================================================
;; 4. Data Access Demo
;; ============================================================================

(defn demo-data-access
  "Demonstrate perf event data access."
  []
  (println "\n=== Perf Event Data Offsets ===")
  (doseq [[k v] perf/perf-event-data-offsets]
    (println (format "  %-15s offset %d" (name k) v)))

  (println "\nGet sample period:")
  (let [insn (perf/perf-get-sample-period :r6 :r0)]
    (println "  Instruction generated:" (if (bytes? insn) "yes" "no")))

  (println "\nGet event address:")
  (let [insn (perf/perf-get-addr :r6 :r0)]
    (println "  Instruction generated:" (if (bytes? insn) "yes" "no")))

  (println "\nGet instruction pointer:")
  (let [insn (perf/perf-get-ip :r6 :r0)]
    (println "  Instruction generated:" (if (bytes? insn) "yes" "no"))))

;; ============================================================================
;; 5. Helper Functions Demo
;; ============================================================================

(defn demo-helpers
  "Demonstrate perf event helper functions."
  []
  (println "\n=== Helper Functions ===")

  (println "\nGet current PID:")
  (let [insns (perf/perf-get-current-pid)]
    (println "  Instruction count:" (count insns)))

  (println "\nGet kernel time:")
  (let [insns (perf/perf-get-ktime-ns)]
    (println "  Instruction count:" (count insns))))

;; ============================================================================
;; 6. Stack ID Flags Demo
;; ============================================================================

(defn demo-stackid-flags
  "Demonstrate stack ID collection flags."
  []
  (println "\n=== Stack ID Flags ===")
  (doseq [[k v] perf/stackid-flags]
    (println (format "  %-15s 0x%x" (name k) v)))

  (println "\nCombined flags (user-stack + fast-stack-cmp):")
  (let [combined (perf/stackid-flag #{:user-stack :fast-stack-cmp})]
    (println (format "  0x%x (%d)" combined combined))))

;; ============================================================================
;; 7. Macro Demo
;; ============================================================================

(perf/defperf-event-instructions cpu-profiler
  {:type :software
   :config :cpu-clock
   :ctx-reg :r6}
  (perf/perf-get-current-pid))

(perf/defperf-event-instructions cycle-counter
  {:type :hardware
   :config :cpu-cycles}
  [])

(defn demo-macros
  "Demonstrate defperf-event-instructions macro."
  []
  (println "\n=== DSL Macros ===")

  (println "\nCPU profiler program:")
  (let [insns (cpu-profiler)]
    (println "  Instruction count:" (count insns)))

  (println "\nCycle counter program:")
  (let [insns (cycle-counter)]
    (println "  Instruction count:" (count insns))))

;; ============================================================================
;; 8. Section Names Demo
;; ============================================================================

(defn demo-section-names
  "Demonstrate section name generation."
  []
  (println "\n=== Section Names ===")
  (println "  Default:    " (perf/perf-event-section-name))
  (println "  Named:      " (perf/perf-event-section-name "my_profiler")))

;; ============================================================================
;; 9. Program Metadata Demo
;; ============================================================================

(defn demo-metadata
  "Demonstrate program metadata generation."
  []
  (println "\n=== Program Metadata ===")
  (let [info (perf/make-perf-event-info
              "cpu_profiler" :software :cpu-clock (cpu-profiler))]
    (println "  Name:      " (:name info))
    (println "  Section:   " (:section info))
    (println "  Type:      " (:type info))
    (println "  Perf Type: " (:perf-type info))
    (println "  Config:    " (:config info))))

;; ============================================================================
;; 10. Complete Program Demo
;; ============================================================================

(defn demo-complete-program
  "Demonstrate building a complete perf event program."
  []
  (println "\n=== Complete Program ===")

  (println "\nBuilding CPU profiler program:")
  (let [insns (vec (concat
                    (perf/perf-event-prologue :r6)
                    (perf/perf-get-current-pid)
                    [(dsl/mov-reg :r7 :r0)]  ; Save PID
                    (perf/perf-get-ktime-ns)
                    [(dsl/mov-reg :r8 :r0)]  ; Save timestamp
                    (perf/perf-return 0)))
        bytecode (dsl/assemble insns)]
    (println "  Instructions:" (count insns))
    (println "  Bytecode size:" (count bytecode) "bytes")))

;; ============================================================================
;; 11. Describe Event Demo
;; ============================================================================

(defn demo-describe-event
  "Demonstrate event description."
  []
  (println "\n=== Event Descriptions ===")

  (println "\nHardware events:")
  (let [info (perf/describe-perf-event :hardware)]
    (println "  Type value:" (:type-value info))
    (println "  Available configs:" (take 5 (:available-configs info)) "..."))

  (println "\nSoftware events:")
  (let [info (perf/describe-perf-event :software)]
    (println "  Type value:" (:type-value info))
    (println "  Available configs:" (take 5 (:available-configs info)) "...")))

;; ============================================================================
;; 12. Use Cases Demo
;; ============================================================================

(defn demo-use-cases
  "Demonstrate perf event use cases."
  []
  (println "\n=== Common Use Cases ===")

  (println "\n1. CPU Profiling")
  (println "   - Sample CPU cycles at regular intervals")
  (println "   - Collect stack traces for flame graphs")

  (println "\n2. Cache Analysis")
  (println "   - Monitor cache hits/misses")
  (println "   - Identify memory access patterns")

  (println "\n3. Branch Prediction")
  (println "   - Track branch mispredictions")
  (println "   - Optimize conditional code")

  (println "\n4. Context Switches")
  (println "   - Monitor scheduling behavior")
  (println "   - Identify process contention"))

;; ============================================================================
;; Main
;; ============================================================================

(defn -main
  "Run all Perf Event DSL demonstrations."
  [& args]
  (println "============================================")
  (println "  Perf Event DSL Examples")
  (println "============================================")

  (demo-perf-types)
  (demo-hardware-events)
  (demo-software-events)
  (demo-data-access)
  (demo-helpers)
  (demo-stackid-flags)
  (demo-macros)
  (demo-section-names)
  (demo-metadata)
  (demo-complete-program)
  (demo-describe-event)
  (demo-use-cases)

  (println "\n============================================")
  (println "  All Perf Event demonstrations complete!")
  (println "============================================"))
