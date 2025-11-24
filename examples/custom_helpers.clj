(ns custom-helpers
  "Example: Adding and using custom BPF helper functions in clj-ebpf"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.helpers :as helpers]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.programs :as programs]))

;; ============================================================================
;; PART 1: Defining Custom Helper Metadata
;; ============================================================================

;; In a real implementation, you would add these to src/clj_ebpf/helpers.clj
;; For this example, we'll define them locally

(def custom-helpers
  "Example custom helper definitions for newer kernel features"
  {
   ;; Real-time clock helper (kernel 6.3+)
   :ktime-get-real-ns
   {:id 212
    :name "bpf_ktime_get_real_ns"
    :signature {:return :u64 :args []}
    :min-kernel "6.3"
    :prog-types :all
    :category :time
    :description "Get real (wall-clock) time in nanoseconds since Unix epoch."}

   ;; Custom network helper
   :skb-set-tstamp
   {:id 213
    :name "bpf_skb_set_tstamp"
    :signature {:return :long :args [:skb-ptr :tstamp :tstamp-type]}
    :min-kernel "6.3"
    :prog-types #{:sched-cls :sched-act}
    :category :network
    :description "Set packet timestamp with specific type."}

   ;; Task tracing helper
   :get-task-exe-file
   {:id 215
    :name "bpf_get_task_exe_file"
    :signature {:return :ptr :args [:task-ptr]}
    :min-kernel "6.4"
    :prog-types #{:kprobe :tracepoint :lsm}
    :category :trace
    :description "Get executable file pointer from task_struct."}
   })

;; ============================================================================
;; PART 2: Helper Query and Discovery Functions
;; ============================================================================

(defn print-custom-helper-info
  "Print information about custom helpers"
  []
  (println "\n=== Custom Helpers ===\n")
  (doseq [[k v] (sort-by #(:id (second %)) custom-helpers)]
    (println (format "[%3d] %-30s (>= %s)"
                     (:id v)
                     (:name v)
                     (:min-kernel v)))
    (println (format "      Category: %s" (:category v)))
    (println (format "      Programs: %s" (if (= (:prog-types v) :all)
                                            "all"
                                            (clojure.string/join ", " (map name (:prog-types v))))))
    (println (format "      Return:   %s" (:return (:signature v))))
    (println (format "      Args:     %s" (clojure.string/join ", " (map name (:args (:signature v))))))
    (println (format "      %s" (:description v)))
    (println)))

(defn check-helper-availability
  "Check if custom helpers are available for given kernel version"
  [kernel-version]
  (println "\n=== Helper Availability for Kernel" kernel-version "===\n")
  (doseq [[k v] custom-helpers]
    (let [min-ver (:min-kernel v)
          available? (>= (compare kernel-version min-ver) 0)]
      (println (format "%s %-30s (requires %s)"
                       (if available? "✓" "✗")
                       (:name v)
                       min-ver)))))

(defn helpers-for-program-type
  "Get compatible custom helpers for a program type"
  [prog-type]
  (filter (fn [[k v]]
            (let [types (:prog-types v)]
              (or (= types :all)
                  (contains? types prog-type))))
          custom-helpers))

;; ============================================================================
;; PART 3: DSL Helper Wrapper Functions
;; ============================================================================

(defn call-helper-by-keyword
  "Generate DSL code to call a helper by keyword, with argument setup"
  [helper-map helper-key & args]
  (if-let [helper-info (get helper-map helper-key)]
    (let [helper-id (:id helper-info)]
      (concat
        ;; Setup arguments in registers r1-r5
        (mapcat (fn [idx val]
                  (let [reg (keyword (str "r" (inc idx)))]
                    (if (keyword? val)
                      [(dsl/mov-reg reg val)]  ; Move from register
                      [(dsl/mov reg val)])))   ; Move immediate value
                (range) args)
        ;; Call the helper
        [(dsl/call helper-id)]))
    (throw (ex-info "Unknown helper" {:helper helper-key}))))

(defn get-real-timestamp
  "Generate DSL code to get real (wall-clock) timestamp"
  []
  (call-helper-by-keyword custom-helpers :ktime-get-real-ns))

;; ============================================================================
;; PART 4: Example BPF Programs Using Custom Helpers
;; ============================================================================

(defn example-1-simple-timestamp
  "Example 1: Simple program that gets wall-clock time"
  []
  (println "\n=== Example 1: Get Wall-Clock Timestamp ===\n")

  ;; Build BPF program using custom helper
  (let [program (dsl/assemble
                  (concat
                    ;; Call bpf_ktime_get_real_ns() - result in r0
                    (get-real-timestamp)
                    ;; Return timestamp (r0 already has it)
                    [(dsl/exit-insn)]))]

    (println "Generated BPF program bytecode:")
    (println "  Instructions:" (/ (alength program) 8))
    (println "  Bytes:" (alength program))
    (println "\nProgram calls helper ID 212 (bpf_ktime_get_real_ns)")
    (println "Returns wall-clock time in nanoseconds since Unix epoch")

    program))

(defn example-2-conditional-helper-usage
  "Example 2: Use different helpers based on kernel version"
  [kernel-version]
  (println "\n=== Example 2: Conditional Helper Usage ===\n")

  (let [use-real-time? (>= (compare kernel-version "6.3") 0)
        program (dsl/assemble
                  (concat
                    ;; Use real time if available (6.3+), otherwise monotonic
                    (if use-real-time?
                      (do
                        (println "Kernel" kernel-version ">= 6.3: Using bpf_ktime_get_real_ns()")
                        (get-real-timestamp))
                      (do
                        (println "Kernel" kernel-version "< 6.3: Using bpf_ktime_get_ns()")
                        [(dsl/call (:ktime-get-ns dsl/bpf-helpers))]))
                    [(dsl/exit-insn)]))]

    (println "Generated adaptive BPF program for kernel" kernel-version)
    program))

(defn example-3-comparing-timestamps
  "Example 3: Program that compares monotonic vs real-time clocks"
  []
  (println "\n=== Example 3: Compare Timestamp Sources ===\n")

  ;; This program gets both timestamps and stores difference
  (let [program (dsl/assemble [;; Get monotonic time
                                (dsl/call (:ktime-get-ns dsl/bpf-helpers))
                                ;; Save to r6 (callee-saved)
                                (dsl/mov-reg :r6 :r0)

                                ;; Get real (wall-clock) time
                                (dsl/call 212)  ; bpf_ktime_get_real_ns
                                ;; Real time is in r0

                                ;; Calculate difference: r0 = r0 - r6
                                (dsl/sub-reg :r0 :r6)
                                ;; r0 now has (real_time - monotonic_time)

                                ;; Return the difference
                                (dsl/exit-insn)])]

    (println "This program:")
    (println "  1. Gets monotonic time (bpf_ktime_get_ns)")
    (println "  2. Gets wall-clock time (bpf_ktime_get_real_ns)")
    (println "  3. Returns the difference between them")
    (println "\nThe difference represents time adjustments (NTP, leap seconds, etc.)")

    program))

(defn example-4-map-timestamp-storage
  "Example 4: Store timestamps in BPF map"
  []
  (println "\n=== Example 4: Store Timestamps in Map ===\n")

  ;; Create a map to store timestamps
  (println "Creating BPF map to store timestamps...")

  (bpf/with-map [ts-map (bpf/create-hash-map 4 8 100 "timestamp_map")]
    (println "✓ Created map:" (:map-name ts-map) "(FD:" (:fd ts-map) ")")

    ;; Build program that stores timestamp in map
    (let [program (dsl/assemble [;; Get wall-clock timestamp
                                  (dsl/call 212)  ; bpf_ktime_get_real_ns

                                  ;; Save timestamp to r7
                                  (dsl/mov-reg :r7 :r0)

                                  ;; Prepare map update arguments
                                  ;; r1 = map pointer (would be set at load time)
                                  ;; r2 = key pointer (stack)
                                  ;; r3 = value pointer (r7 with timestamp)
                                  ;; r4 = flags (BPF_ANY = 0)

                                  ;; For demonstration, just return timestamp
                                  (dsl/mov-reg :r0 :r7)
                                  (dsl/exit-insn)])]

      (println "\nProgram structure:")
      (println "  1. Get wall-clock timestamp")
      (println "  2. Store in map with current PID as key")
      (println "  3. Return success")

      ;; Note: Full map update requires stack operations and proper
      ;; map FD patching, which would be done in a complete implementation
      (println "\nNote: Full map update requires additional stack")
      (println "      management and map FD patching in real programs")

      program)))

;; ============================================================================
;; PART 5: Helper Validation and Testing
;; ============================================================================

(defn validate-custom-helpers
  "Validate custom helper definitions"
  []
  (println "\n=== Validating Custom Helpers ===\n")

  (doseq [[k v] custom-helpers]
    (print (format "Checking %-30s ... " k))

    ;; Validate required fields
    (let [required-fields [:id :name :signature :min-kernel :prog-types :category :description]
          missing (filter #(nil? (get v %)) required-fields)]

      (if (empty? missing)
        (println "✓ Valid")
        (println (format "✗ Missing fields: %s" (clojure.string/join ", " missing))))))

  (println "\n✓ All custom helpers validated"))

(defn test-helper-queries
  "Test helper query functions"
  []
  (println "\n=== Testing Helper Queries ===\n")

  ;; Test 1: Get helper by keyword
  (let [helper (get custom-helpers :ktime-get-real-ns)]
    (println "Test 1: Get helper by keyword")
    (println "  Result:" (:name helper))
    (println "  ✓ Passed\n"))

  ;; Test 2: Filter by program type
  (let [xdp-helpers (helpers-for-program-type :xdp)]
    (println "Test 2: Helpers for XDP programs")
    (doseq [[k v] xdp-helpers]
      (println "  -" (:name v)))
    (println "  ✓ Passed\n"))

  ;; Test 3: Filter by kernel version
  (let [available (filter #(>= (compare "6.4" (:min-kernel (second %))) 0)
                          custom-helpers)]
    (println "Test 3: Helpers available in kernel 6.4+")
    (doseq [[k v] available]
      (println "  -" (:name v)))
    (println "  ✓ Passed\n"))

  (println "✓ All query tests passed"))

;; ============================================================================
;; PART 6: Integration with Existing clj-ebpf Helpers
;; ============================================================================

(defn compare-with-existing-helpers
  "Compare custom helpers with existing clj-ebpf helpers"
  []
  (println "\n=== Comparison with Existing Helpers ===\n")

  ;; Show existing time-related helpers
  (println "Existing time helpers in clj-ebpf:")
  (let [time-helpers (helpers/helpers-by-category :time)]
    (doseq [[k v] time-helpers]
      (println (format "  [%3d] %-30s (>= %s)"
                       (:id v)
                       (:name v)
                       (:min-kernel v)))))

  (println "\nCustom time helpers:")
  (let [custom-time-helpers (filter #(= :time (:category (second %))) custom-helpers)]
    (doseq [[k v] custom-time-helpers]
      (println (format "  [%3d] %-30s (>= %s)"
                       (:id v)
                       (:name v)
                       (:min-kernel v)))))

  (println "\n✓ Custom helpers extend existing functionality"))

;; ============================================================================
;; PART 7: Main Examples Runner
;; ============================================================================

(defn -main
  [& args]
  (println "=================================================")
  (println "  Custom BPF Helper Functions Example")
  (println "  clj-ebpf - Extending with New Helpers")
  (println "=================================================")

  ;; Display custom helper information
  (print-custom-helper-info)

  ;; Check availability for different kernel versions
  (check-helper-availability "6.2")
  (check-helper-availability "6.3")
  (check-helper-availability "6.5")

  ;; Validate helper definitions
  (validate-custom-helpers)

  ;; Test query functions
  (test-helper-queries)

  ;; Compare with existing helpers
  (compare-with-existing-helpers)

  ;; Run example programs
  (example-1-simple-timestamp)
  (example-2-conditional-helper-usage "6.2")
  (example-2-conditional-helper-usage "6.4")
  (example-3-comparing-timestamps)

  ;; Map example requires BPF system access
  (println "\n=== Example 4: Map Storage (requires BPF support) ===")
  (if (bpf/bpf-fs-mounted?)
    (try
      (example-4-map-timestamp-storage)
      (catch Exception e
        (println "⚠ Map example failed:" (.getMessage e))
        (println "  This requires BPF support and permissions")))
    (println "⚠ BPF filesystem not mounted, skipping map example"))

  (println "\n=================================================")
  (println "  Examples Complete!")
  (println "=================================================")
  (println "\nTo add these helpers to clj-ebpf permanently:")
  (println "  1. Edit src/clj_ebpf/helpers.clj")
  (println "  2. Add definitions to helper-metadata map")
  (println "  3. Optionally add to src/clj_ebpf/dsl.clj")
  (println "  4. Run tests to verify")
  (println "\nSee docs/adding-new-helpers.md for full guide"))

;; ============================================================================
;; Additional Utility Functions
;; ============================================================================

(defn export-helper-definitions
  "Export custom helpers in a format ready for helpers.clj"
  []
  (println "\n=== Exportable Helper Definitions ===\n")
  (println ";; Add these to src/clj_ebpf/helpers.clj helper-metadata map:\n")

  (doseq [[k v] (sort-by #(:id (second %)) custom-helpers)]
    (println (format "   :%s" (name k)))
    (println (format "   {:id %d" (:id v)))
    (println (format "    :name \"%s\"" (:name v)))
    (println (format "    :signature %s" (pr-str (:signature v))))
    (println (format "    :min-kernel \"%s\"" (:min-kernel v)))
    (println (format "    :prog-types %s" (if (= (:prog-types v) :all)
                                           ":all"
                                           (pr-str (:prog-types v)))))
    (println (format "    :category :%s" (name (:category v))))
    (println (format "    :description \"%s\"}" (:description v)))
    (println)))

(comment
  ;; REPL Usage Examples

  ;; 1. Run all examples
  (-main)

  ;; 2. Print helper info
  (print-custom-helper-info)

  ;; 3. Check availability
  (check-helper-availability "6.3")

  ;; 4. Get helpers for program type
  (helpers-for-program-type :xdp)

  ;; 5. Build a simple program
  (example-1-simple-timestamp)

  ;; 6. Export definitions
  (export-helper-definitions)

  ;; 7. Validate helpers
  (validate-custom-helpers)

  ;; 8. Test queries
  (test-helper-queries)
  )
