(ns lab-15-2-syscall-filtering
  "Lab 15.2: Syscall Filtering

   This solution demonstrates:
   - PID-based filtering
   - UID-based filtering
   - Syscall type filtering with bitmasks
   - Duration threshold filtering
   - Include and exclude lists

   Run with: clojure -M -m lab-15-2-syscall-filtering test"
  (:require [clojure.string :as str]
            [clojure.set :as set]))

;;; ============================================================================
;;; Part 1: Filter Configuration
;;; ============================================================================

(defrecord FilterConfig
  [enabled?
   target-pids      ; Set of PIDs to trace (nil = all)
   target-uids      ; Set of UIDs to trace (nil = all)
   syscall-include  ; Set of syscall numbers to include (nil = all)
   syscall-exclude  ; Set of syscall numbers to exclude (nil = none)
   min-duration-ns  ; Minimum duration to report (0 = all)
   comm-pattern])   ; Regex pattern for process name

(defn create-filter
  "Create a filter configuration"
  [& {:keys [enabled? pids uids include exclude min-duration comm-pattern]
      :or {enabled? true
           pids nil
           uids nil
           include nil
           exclude nil
           min-duration 0
           comm-pattern nil}}]
  (->FilterConfig
    enabled?
    (when pids (set pids))
    (when uids (set uids))
    (when include (set include))
    (when exclude (set exclude))
    min-duration
    (when comm-pattern (re-pattern comm-pattern))))

(defn filter-all
  "Create a filter that passes everything"
  []
  (create-filter :enabled? true))

(defn filter-none
  "Create a filter that blocks everything"
  []
  (create-filter :enabled? false))

;;; ============================================================================
;;; Part 2: Syscall Bitmask Operations
;;; ============================================================================

(defn syscall-to-bitmask
  "Convert syscall number to bitmask representation.
   Uses 8 longs (512 bits) to cover all syscalls."
  [syscall-nr]
  (when (and (>= syscall-nr 0) (< syscall-nr 512))
    (let [long-idx (quot syscall-nr 64)
          bit-pos (rem syscall-nr 64)]
      [long-idx (bit-shift-left 1 bit-pos)])))

(defn create-syscall-bitmask
  "Create bitmask from set of syscall numbers"
  [syscall-set]
  (let [mask (long-array 8)]
    (doseq [nr syscall-set]
      (when-let [[idx bit] (syscall-to-bitmask nr)]
        (aset mask idx (bit-or (aget mask idx) bit))))
    (vec mask)))

(defn check-syscall-bitmask
  "Check if syscall is in bitmask"
  [mask syscall-nr]
  (when-let [[idx bit] (syscall-to-bitmask syscall-nr)]
    (not (zero? (bit-and (nth mask idx) bit)))))

(defn bitmask-to-syscalls
  "Convert bitmask back to set of syscall numbers"
  [mask]
  (set
    (for [idx (range 8)
          bit-pos (range 64)
          :when (not (zero? (bit-and (nth mask idx) (bit-shift-left 1 bit-pos))))]
      (+ (* idx 64) bit-pos))))

;;; ============================================================================
;;; Part 3: Filter Application
;;; ============================================================================

(defn filter-by-pid
  "Check if event passes PID filter"
  [filter-config pid]
  (if-let [target-pids (:target-pids filter-config)]
    (contains? target-pids pid)
    true))

(defn filter-by-uid
  "Check if event passes UID filter"
  [filter-config uid]
  (if-let [target-uids (:target-uids filter-config)]
    (contains? target-uids uid)
    true))

(defn filter-by-syscall
  "Check if syscall passes include/exclude filters"
  [filter-config syscall-nr]
  (let [include (:syscall-include filter-config)
        exclude (:syscall-exclude filter-config)]
    (cond
      ;; If exclude list exists and syscall is in it, reject
      (and exclude (contains? exclude syscall-nr))
      false

      ;; If include list exists, syscall must be in it
      include
      (contains? include syscall-nr)

      ;; Otherwise, pass
      :else
      true)))

(defn filter-by-duration
  "Check if event passes duration filter"
  [filter-config duration-ns]
  (>= duration-ns (:min-duration-ns filter-config)))

(defn filter-by-comm
  "Check if process name matches pattern"
  [filter-config comm]
  (if-let [pattern (:comm-pattern filter-config)]
    (boolean (re-find pattern comm))
    true))

(defn apply-filter
  "Apply all filter criteria to an event"
  [filter-config event]
  (and (:enabled? filter-config)
       (filter-by-pid filter-config (:pid event))
       (filter-by-uid filter-config (:uid event))
       (filter-by-syscall filter-config (:syscall-nr event))
       (filter-by-comm filter-config (:comm event))
       ;; Duration filter only applies to completed events
       (if (:duration-ns event)
         (filter-by-duration filter-config (:duration-ns event))
         true)))

;;; ============================================================================
;;; Part 4: Dynamic Filter Updates
;;; ============================================================================

(def current-filter
  "Current active filter"
  (atom (filter-all)))

(defn set-filter!
  "Set the current filter"
  [filter-config]
  (reset! current-filter filter-config))

(defn get-filter
  "Get the current filter"
  []
  @current-filter)

(defn update-filter!
  "Update specific filter fields"
  [& {:as updates}]
  (swap! current-filter
         (fn [f]
           (reduce-kv
             (fn [config k v]
               (case k
                 :enabled? (assoc config :enabled? v)
                 :pids (assoc config :target-pids (when v (set v)))
                 :uids (assoc config :target-uids (when v (set v)))
                 :include (assoc config :syscall-include (when v (set v)))
                 :exclude (assoc config :syscall-exclude (when v (set v)))
                 :min-duration (assoc config :min-duration-ns v)
                 :comm-pattern (assoc config :comm-pattern (when v (re-pattern v)))
                 config))
             f
             updates))))

(defn add-pid-filter!
  "Add PID to filter"
  [pid]
  (swap! current-filter
         (fn [f]
           (assoc f :target-pids
                  (if (:target-pids f)
                    (conj (:target-pids f) pid)
                    #{pid})))))

(defn remove-pid-filter!
  "Remove PID from filter"
  [pid]
  (swap! current-filter
         (fn [f]
           (let [new-pids (disj (or (:target-pids f) #{}) pid)]
             (assoc f :target-pids (when (seq new-pids) new-pids))))))

(defn add-syscall-include!
  "Add syscall to include list"
  [syscall-nr]
  (swap! current-filter
         (fn [f]
           (assoc f :syscall-include
                  (if (:syscall-include f)
                    (conj (:syscall-include f) syscall-nr)
                    #{syscall-nr})))))

(defn add-syscall-exclude!
  "Add syscall to exclude list"
  [syscall-nr]
  (swap! current-filter
         (fn [f]
           (assoc f :syscall-exclude
                  (if (:syscall-exclude f)
                    (conj (:syscall-exclude f) syscall-nr)
                    #{syscall-nr})))))

;;; ============================================================================
;;; Part 5: Filter Presets
;;; ============================================================================

(def file-syscalls
  "Syscalls related to file operations"
  #{0 1 2 3 4 5 6 8 17 18 19 20 21 72 78 79 80 82 83 84 85 86 87 88 89 90 91 92 93 217 257 262 263})

(def network-syscalls
  "Syscalls related to network operations"
  #{41 42 43 44 45 46 47 48 49 50 288})

(def process-syscalls
  "Syscalls related to process operations"
  #{56 57 58 59 60 61 62 231})

(defn create-file-filter
  "Create filter for file operations only"
  [& {:keys [pids]}]
  (create-filter :pids pids :include file-syscalls))

(defn create-network-filter
  "Create filter for network operations only"
  [& {:keys [pids]}]
  (create-filter :pids pids :include network-syscalls))

(defn create-process-filter
  "Create filter for process operations only"
  [& {:keys [pids]}]
  (create-filter :pids pids :include process-syscalls))

(defn create-slow-syscall-filter
  "Create filter for syscalls slower than threshold"
  [min-duration-ms & {:keys [pids]}]
  (create-filter :pids pids :min-duration (* min-duration-ms 1000000)))

(defn create-error-filter
  "Create filter preset for error detection (applied post-capture)"
  []
  ;; Note: Error filtering requires ret < 0, which is checked post-event
  (create-filter :enabled? true))

;;; ============================================================================
;;; Part 6: Filter Statistics
;;; ============================================================================

(def filter-stats
  "Track filter statistics"
  (atom {:passed 0 :filtered 0 :by-pid 0 :by-uid 0 :by-syscall 0 :by-duration 0 :by-comm 0}))

(defn reset-filter-stats!
  "Reset filter statistics"
  []
  (reset! filter-stats {:passed 0 :filtered 0 :by-pid 0 :by-uid 0 :by-syscall 0 :by-duration 0 :by-comm 0}))

(defn apply-filter-with-stats
  "Apply filter and track statistics"
  [filter-config event]
  (let [pid-pass (filter-by-pid filter-config (:pid event))
        uid-pass (filter-by-uid filter-config (:uid event))
        syscall-pass (filter-by-syscall filter-config (:syscall-nr event))
        duration-pass (if (:duration-ns event)
                        (filter-by-duration filter-config (:duration-ns event))
                        true)
        comm-pass (filter-by-comm filter-config (:comm event))
        all-pass (and (:enabled? filter-config) pid-pass uid-pass syscall-pass duration-pass comm-pass)]

    ;; Update statistics
    (swap! filter-stats
           (fn [s]
             (-> s
                 (update (if all-pass :passed :filtered) inc)
                 (update :by-pid #(if pid-pass % (inc %)))
                 (update :by-uid #(if uid-pass % (inc %)))
                 (update :by-syscall #(if syscall-pass % (inc %)))
                 (update :by-duration #(if duration-pass % (inc %)))
                 (update :by-comm #(if comm-pass % (inc %))))))

    all-pass))

(defn get-filter-stats
  "Get current filter statistics"
  []
  @filter-stats)

;;; ============================================================================
;;; Part 7: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 15.2 Tests ===\n")

  ;; Test 1: Basic filter creation
  (println "Test 1: Filter Creation")
  (let [f (create-filter :pids [1234] :uids [1000] :include #{0 1 2})]
    (assert (:enabled? f) "filter enabled")
    (assert (= #{1234} (:target-pids f)) "pids set")
    (assert (= #{1000} (:target-uids f)) "uids set")
    (assert (= #{0 1 2} (:syscall-include f)) "include set"))
  (println "  Filter created with correct fields")
  (println "  PASSED\n")

  ;; Test 2: PID filtering
  (println "Test 2: PID Filtering")
  (let [f (create-filter :pids [1234 5678])]
    (assert (filter-by-pid f 1234) "pid 1234 passes")
    (assert (filter-by-pid f 5678) "pid 5678 passes")
    (assert (not (filter-by-pid f 9999)) "pid 9999 blocked"))
  (let [f (filter-all)]
    (assert (filter-by-pid f 1234) "no filter passes all"))
  (println "  PID filtering works correctly")
  (println "  PASSED\n")

  ;; Test 3: UID filtering
  (println "Test 3: UID Filtering")
  (let [f (create-filter :uids [0 1000])]
    (assert (filter-by-uid f 0) "root passes")
    (assert (filter-by-uid f 1000) "user passes")
    (assert (not (filter-by-uid f 2000)) "other blocked"))
  (println "  UID filtering works correctly")
  (println "  PASSED\n")

  ;; Test 4: Syscall include/exclude
  (println "Test 4: Syscall Include/Exclude")
  (let [f (create-filter :include #{0 1 2})]
    (assert (filter-by-syscall f 0) "read included")
    (assert (filter-by-syscall f 1) "write included")
    (assert (not (filter-by-syscall f 3)) "close excluded"))
  (let [f (create-filter :exclude #{0 1})]
    (assert (not (filter-by-syscall f 0)) "read excluded")
    (assert (filter-by-syscall f 3) "close passes"))
  (println "  Include/exclude filtering works correctly")
  (println "  PASSED\n")

  ;; Test 5: Duration filtering
  (println "Test 5: Duration Filtering")
  (let [f (create-filter :min-duration 1000000)]  ; 1ms
    (assert (filter-by-duration f 2000000) "2ms passes")
    (assert (filter-by-duration f 1000000) "1ms passes (equal)")
    (assert (not (filter-by-duration f 500000)) "0.5ms blocked"))
  (println "  Duration filtering works correctly")
  (println "  PASSED\n")

  ;; Test 6: Comm pattern filtering
  (println "Test 6: Comm Pattern Filtering")
  (let [f (create-filter :comm-pattern "^bash")]
    (assert (filter-by-comm f "bash") "bash matches")
    (assert (filter-by-comm f "bash-5.1") "bash-5.1 matches")
    (assert (not (filter-by-comm f "zsh")) "zsh blocked"))
  (let [f (create-filter :comm-pattern "curl|wget")]
    (assert (filter-by-comm f "curl") "curl matches")
    (assert (filter-by-comm f "wget") "wget matches"))
  (println "  Comm pattern filtering works correctly")
  (println "  PASSED\n")

  ;; Test 7: Combined filtering
  (println "Test 7: Combined Filtering")
  (let [f (create-filter :pids [1234] :uids [1000] :include #{0 1 2})]
    (assert (apply-filter f {:pid 1234 :uid 1000 :syscall-nr 0 :comm "test"})
            "matching event passes")
    (assert (not (apply-filter f {:pid 9999 :uid 1000 :syscall-nr 0 :comm "test"}))
            "wrong pid blocked")
    (assert (not (apply-filter f {:pid 1234 :uid 1000 :syscall-nr 99 :comm "test"}))
            "wrong syscall blocked"))
  (println "  Combined filtering works correctly")
  (println "  PASSED\n")

  ;; Test 8: Bitmask operations
  (println "Test 8: Bitmask Operations")
  (let [syscalls #{0 1 2 63 64 65 127 200}
        mask (create-syscall-bitmask syscalls)]
    (assert (check-syscall-bitmask mask 0) "syscall 0 in mask")
    (assert (check-syscall-bitmask mask 64) "syscall 64 in mask")
    (assert (check-syscall-bitmask mask 200) "syscall 200 in mask")
    (assert (not (check-syscall-bitmask mask 3)) "syscall 3 not in mask")
    (assert (= syscalls (bitmask-to-syscalls mask)) "roundtrip works"))
  (println "  Bitmask operations work correctly")
  (println "  PASSED\n")

  ;; Test 9: Dynamic filter updates
  (println "Test 9: Dynamic Filter Updates")
  (set-filter! (filter-all))
  (add-pid-filter! 1234)
  (assert (= #{1234} (:target-pids (get-filter))) "pid added")
  (add-pid-filter! 5678)
  (assert (= #{1234 5678} (:target-pids (get-filter))) "second pid added")
  (remove-pid-filter! 1234)
  (assert (= #{5678} (:target-pids (get-filter))) "pid removed")
  (set-filter! (filter-all))
  (println "  Dynamic updates work correctly")
  (println "  PASSED\n")

  ;; Test 10: Filter statistics
  (println "Test 10: Filter Statistics")
  (reset-filter-stats!)
  (let [f (create-filter :pids [1234])]
    (apply-filter-with-stats f {:pid 1234 :uid 1000 :syscall-nr 0 :comm "test"})
    (apply-filter-with-stats f {:pid 5678 :uid 1000 :syscall-nr 0 :comm "test"})
    (apply-filter-with-stats f {:pid 1234 :uid 1000 :syscall-nr 0 :comm "test"})
    (let [stats (get-filter-stats)]
      (assert (= 2 (:passed stats)) "2 passed")
      (assert (= 1 (:filtered stats)) "1 filtered")
      (assert (= 1 (:by-pid stats)) "1 by pid")))
  (println "  Filter statistics tracked correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 8: Demo
;;; ============================================================================

(defn run-demo
  "Run demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 15.2: Syscall Filtering")
  (println (str/join "" (repeat 60 "=")) "\n")

  ;; Sample events
  (let [events [{:pid 1234 :uid 1000 :syscall-nr 0 :comm "bash" :duration-ns 50000}
                {:pid 1234 :uid 1000 :syscall-nr 1 :comm "bash" :duration-ns 30000}
                {:pid 5678 :uid 1000 :syscall-nr 42 :comm "curl" :duration-ns 1500000}
                {:pid 5678 :uid 1000 :syscall-nr 44 :comm "curl" :duration-ns 200000}
                {:pid 9999 :uid 0 :syscall-nr 59 :comm "su" :duration-ns 80000}
                {:pid 1234 :uid 1000 :syscall-nr 3 :comm "bash" :duration-ns 5000}]]

    ;; Demo 1: No filter
    (println "=== Demo 1: No Filter (all pass) ===\n")
    (let [f (filter-all)
          passed (filter #(apply-filter f %) events)]
      (println (format "Events: %d, Passed: %d" (count events) (count passed))))

    (println)

    ;; Demo 2: PID filter
    (println "=== Demo 2: PID Filter (1234 only) ===\n")
    (let [f (create-filter :pids [1234])
          passed (filter #(apply-filter f %) events)]
      (println (format "Events: %d, Passed: %d" (count events) (count passed)))
      (doseq [e passed]
        (println (format "  PID=%d COMM=%s SYSCALL=%d" (:pid e) (:comm e) (:syscall-nr e)))))

    (println)

    ;; Demo 3: Network syscalls only
    (println "=== Demo 3: Network Syscalls Only ===\n")
    (let [f (create-network-filter)
          passed (filter #(apply-filter f %) events)]
      (println (format "Events: %d, Passed: %d" (count events) (count passed)))
      (doseq [e passed]
        (println (format "  PID=%d COMM=%s SYSCALL=%d" (:pid e) (:comm e) (:syscall-nr e)))))

    (println)

    ;; Demo 4: Slow syscalls
    (println "=== Demo 4: Slow Syscalls (>1ms) ===\n")
    (let [f (create-slow-syscall-filter 1)
          passed (filter #(apply-filter f %) events)]
      (println (format "Events: %d, Passed: %d" (count events) (count passed)))
      (doseq [e passed]
        (println (format "  PID=%d COMM=%s DUR=%.2fms"
                         (:pid e) (:comm e) (/ (:duration-ns e) 1000000.0)))))

    (println)

    ;; Demo 5: Root processes only
    (println "=== Demo 5: Root Processes (UID=0) ===\n")
    (let [f (create-filter :uids [0])
          passed (filter #(apply-filter f %) events)]
      (println (format "Events: %d, Passed: %d" (count events) (count passed)))
      (doseq [e passed]
        (println (format "  PID=%d COMM=%s UID=%d" (:pid e) (:comm e) (:uid e)))))

    (println)

    ;; Demo 6: Combined filters with statistics
    (println "=== Demo 6: Combined Filter with Statistics ===\n")
    (reset-filter-stats!)
    (let [f (create-filter :pids [1234 5678] :exclude #{3} :min-duration 10000)]
      (doseq [e events]
        (when (apply-filter-with-stats f e)
          (println (format "  PASS: PID=%d SYSCALL=%d DUR=%dns"
                           (:pid e) (:syscall-nr e) (:duration-ns e)))))
      (println)
      (println "Filter Statistics:")
      (let [stats (get-filter-stats)]
        (println (format "  Total passed: %d" (:passed stats)))
        (println (format "  Total filtered: %d" (:filtered stats)))
        (println (format "  Filtered by PID: %d" (:by-pid stats)))
        (println (format "  Filtered by syscall: %d" (:by-syscall stats)))
        (println (format "  Filtered by duration: %d" (:by-duration stats)))))))

;;; ============================================================================
;;; Part 9: Main
;;; ============================================================================

(defn -main [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      (do
        (println "Usage: clojure -M -m lab-15-2-syscall-filtering <command>")
        (println "Commands:")
        (println "  test  - Run tests")
        (println "  demo  - Run demonstration")))))
