# Lab 14.2: Debugging Toolkit

## Objective

Build a comprehensive debugging toolkit for BPF programs with instruction tracing, map inspection, event replay, performance profiling, and automated error detection.

## Learning Goals

- Implement instruction-level tracing
- Build map inspection tools
- Create event replay system
- Profile BPF program performance
- Detect common errors automatically
- Integrate with existing debugging tools

## Problem Statement

**Debugging BPF is hard**:
- No printf() or debugger
- Kernel context limits visibility
- Verifier errors cryptic
- Performance issues hard to diagnose
- Race conditions difficult to reproduce

**Solution**: Comprehensive toolkit for visibility and diagnostics.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│             Debugging Toolkit                       │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐                │
│  │   Tracer     │  │  Inspector   │                │
│  └──────────────┘  └──────────────┘                │
│         ↓                ↓                          │
│  ┌──────────────────────────────┐                  │
│  │      BPF Program             │                  │
│  └──────────────────────────────┘                  │
│         ↓                ↓                          │
│  ┌──────────┐    ┌──────────────┐                  │
│  │  Events  │    │     Maps     │                  │
│  └──────────┘    └──────────────┘                  │
│         ↓                ↓                          │
│  ┌──────────────────────────────┐                  │
│  │    Analysis & Reporting      │                  │
│  └──────────────────────────────┘                  │
└─────────────────────────────────────────────────────┘
```

## Implementation

```clojure
(ns testing.debug-toolkit
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.errors :as errors]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.test-utils :as tu]
            [clojure.string :as str]
            [clojure.pprint :as pp]))

;; ============================================================================
;; Platform Information (Using arch.clj)
;; ============================================================================

(defn show-platform-info
  "Display platform information for debugging"
  []
  (println "\n=== Platform Information ===")
  (println "Architecture:" arch/arch-name)
  (println "Arch keyword:" arch/current-arch)
  (println "BPF syscall:" (arch/get-syscall-nr :bpf))
  (println "Capabilities:" (if (tu/has-bpf-capabilities?) "Available" "Not available")))

;; ============================================================================
;; Instruction Tracer
;; ============================================================================

(def trace-map
  "Records program execution trace"
  {:type :array
   :key-type :u32
   :value-type :struct  ; {checkpoint:u32, r0-r9:u64[10], timestamp:u64}
   :max-entries 1000})

(defmacro trace-checkpoint
  "Insert trace checkpoint in BPF program"
  [checkpoint-id & regs]
  `[;; Store checkpoint ID
    [(bpf/mov :r1 ~checkpoint-id)]
    [(bpf/store-mem :w :r10 -4 :r1)]

    ;; Store register values
    ~@(map-indexed
        (fn [idx reg]
          `[(bpf/store-mem :dw :r10 ~(- -12 (* idx 8)) ~reg)])
        regs)

    ;; Store timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -92 :r0)]

    ;; Update trace map
    [(bpf/mov-reg :r1 (bpf/map-ref trace-map))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -96)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -4)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]])

(defn read-trace
  "Read and display execution trace"
  []
  (println "\n=== Execution Trace ===")
  (println "CHECKPOINT   R0       R1       R2       R3       TIME")
  (println "=========================================================")

  (doseq [[idx entry] (bpf/map-get-all trace-map)]
    (when (pos? (:checkpoint entry))
      (printf "%-12d %-8x %-8x %-8x %-8x %d\n"
              (:checkpoint entry)
              (bit-and (:r0 entry) 0xFFFFFFFF)
              (bit-and (:r1 entry) 0xFFFFFFFF)
              (bit-and (:r2 entry) 0xFFFFFFFF)
              (bit-and (:r3 entry) 0xFFFFFFFF)
              (:timestamp entry)))))

;; ============================================================================
;; Map Inspector
;; ============================================================================

(defn inspect-map
  "Detailed map inspection"
  [map-ref map-name]
  (println (format "\n=== Map: %s ===" map-name))

  (let [entries (bpf/map-get-all map-ref)
        entry-count (count entries)]

    (println (format "Entries: %d" entry-count))

    (if (zero? entry-count)
      (println "  (empty)")
      (do
        (println "\nKey → Value")
        (println "───────────────────────────────")
        (doseq [[k v] (take 10 entries)]  ; Show first 10
          (println (format "  %s → %s" (pr-str k) (pr-str v))))

        (when (> entry-count 10)
          (println (format "\n  ... %d more entries" (- entry-count 10))))))))

(defn compare-maps
  "Compare two map snapshots to find changes"
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
        (println (format "  + %s → %s" k (get after k)))))

    (when (seq removed)
      (println "\nRemoved:")
      (doseq [k removed]
        (println (format "  - %s" k))))

    (when (seq modified)
      (println "\nModified:")
      (doseq [k modified]
        (println (format "  %s: %s → %s" k (get before k) (get after k)))))))

(defn watch-map
  "Watch map for changes in real-time"
  [map-ref map-name interval-ms]
  (println (format "Watching map '%s' (press Ctrl-C to stop)" map-name))

  (loop [prev-snapshot (bpf/map-get-all map-ref)]
    (Thread/sleep interval-ms)
    (let [curr-snapshot (bpf/map-get-all map-ref)]
      (when (not= prev-snapshot curr-snapshot)
        (compare-maps prev-snapshot curr-snapshot map-name))
      (recur curr-snapshot))))

;; ============================================================================
;; Event Replay System
;; ============================================================================

(defrecord RecordedEvent
  [timestamp :u64
   event-type :u32
   event-data [256 :u8]])

(def recorded-events
  "Store events for replay"
  {:type :ring_buffer
   :max-entries (* 1 1024 1024)})  ; 1 MB

(defn record-event
  "Record event for later replay"
  [event]
  (let [timestamp (System/nanoTime)
        event-bytes (serialize-event event)]
    (bpf/ring-buffer-submit recorded-events
                           (merge {:timestamp timestamp
                                   :event-type (:type event)}
                                  event-bytes))))

(defn replay-events
  "Replay recorded events"
  [program]
  (println "=== Replaying Events ===\n")

  (let [events (atom [])
        _ (bpf/consume-ring-buffer recorded-events
                                   (fn [e] (swap! events conj e))
                                   {:poll-timeout-ms 100})
        sorted-events (sort-by :timestamp @events)]

    (println (format "Replaying %d events..." (count sorted-events)))

    (doseq [event sorted-events]
      (let [deserialized (deserialize-event event)
            result (inject-event program deserialized)]
        (println (format "[%d] %s → %s"
                        (:timestamp event)
                        (:event-type event)
                        (:result result)))))

    (println "\n✓ Replay complete")))

(defn replay-until-failure
  "Replay events until failure occurs"
  [program failure-predicate]
  (loop [events (get-recorded-events)
         idx 0]
    (if (empty? events)
      (println "No failure found in replay")
      (let [event (first events)
            result (inject-event program event)]
        (if (failure-predicate result)
          (do
            (println (format "\n⚠️  Failure at event %d:" idx))
            (pp/pprint event)
            (println "\nResult:")
            (pp/pprint result))
          (recur (rest events) (inc idx)))))))

;; ============================================================================
;; Performance Profiler
;; ============================================================================

(def perf-stats
  "Performance statistics"
  {:type :array
   :key-type :u32
   :value-type :struct  ; {min:u64, max:u64, total:u64, count:u64}
   :max-entries 100})   ; Track 100 checkpoints

(defmacro profile-section
  "Profile execution time of code section"
  [section-id & body]
  `[;; Start timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/mov-reg :r9 :r0)]  ; Save start time

    ;; Execute code
    ~@body

    ;; End timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/sub-reg :r0 :r9)]  ; Duration = end - start

    ;; Update stats
    [(bpf/mov :r8 ~section-id)]
    ;; ... update min/max/total/count in perf-stats map ...
    ])

(defn display-perf-stats
  "Display performance statistics"
  []
  (println "\n=== Performance Statistics ===")
  (println "SECTION  MIN(ns)  MAX(ns)  AVG(ns)  COUNT")
  (println "============================================")

  (doseq [[section-id stats] (bpf/map-get-all perf-stats)]
    (when (pos? (:count stats))
      (let [avg (/ (:total stats) (:count stats))]
        (printf "%-8d %-8d %-8d %-8d %d\n"
                section-id
                (:min stats)
                (:max stats)
                avg
                (:count stats))))))

(defn find-bottlenecks
  "Identify performance bottlenecks"
  []
  (let [stats (bpf/map-get-all perf-stats)
        sorted-by-avg (sort-by (fn [[_ s]] (/ (:total s) (:count s))) > stats)
        top-5 (take 5 sorted-by-avg)]

    (println "\n=== Top 5 Bottlenecks ===")
    (doseq [[section-id stats] top-5]
      (let [avg (/ (:total stats) (:count stats))]
        (println (format "Section %d: %.0f ns average" section-id avg))))))

;; ============================================================================
;; Error Detection (Integrated with clj-ebpf.errors)
;; ============================================================================

;; Use structured error handling from errors.clj
(defn safe-operation
  "Execute operation with retry on transient errors"
  [operation-fn & {:keys [max-retries on-error]
                   :or {max-retries 3}}]
  (errors/with-retry operation-fn
    {:max-retries max-retries
     :on-retry (fn [attempt delay e]
                 (println (format "Retry %d after %dms: %s"
                                 attempt delay (errors/error-summary e))))}))

(defn diagnose-error
  "Diagnose a BPF error using errors.clj utilities"
  [e]
  (println "\n=== Error Diagnosis ===")
  (println (errors/format-error e))

  ;; Provide specific guidance based on error type
  (cond
    (errors/permission-error? e)
    (do
      (println "\n💡 Suggestions:")
      (println "  - Run with sudo or CAP_BPF capability")
      (println "  - Check /proc/sys/kernel/unprivileged_bpf_disabled")
      (println "  - Verify SELinux/AppArmor policies"))

    (errors/resource-error? e)
    (do
      (println "\n💡 Suggestions:")
      (println "  - Reduce map sizes or entry counts")
      (println "  - Check /proc/sys/kernel/bpf_stats_enabled")
      (println "  - Review memory limits (ulimit -l)"))

    (errors/verifier-error? e)
    (do
      (println "\n💡 Suggestions:")
      (println "  - Check verifier log for specific instruction")
      (println "  - Ensure bounds checks before memory access")
      (println "  - Verify loop termination conditions"))

    (errors/transient-error? e)
    (do
      (println "\n💡 Suggestions:")
      (println "  - Use errors/with-retry for automatic retry")
      (println "  - Reduce concurrent BPF operations")
      (println "  - Check system load"))))

(def error-patterns
  "Common error patterns to detect"
  [{:name "Map Overflow"
    :check (fn [prog] (check-map-full prog))
    :severity :high}

   {:name "High Drop Rate"
    :check (fn [prog] (check-drop-rate prog))
    :severity :medium}

   {:name "Stale Data"
    :check (fn [prog] (check-stale-entries prog))
    :severity :low}

   {:name "Memory Leak"
    :check (fn [prog] (check-map-growth prog))
    :severity :high}])

(defn check-map-full [prog]
  (let [maps (:maps prog)]
    (reduce
      (fn [issues [map-name map-ref]]
        (let [entry-count (count (bpf/map-get-all map-ref))
              max-entries (:max-entries map-ref)
              usage (/ entry-count (double max-entries))]
          (if (> usage 0.9)
            (conj issues {:map map-name
                         :usage usage
                         :message (format "Map '%s' is %.0f%% full"
                                        map-name (* usage 100))})
            issues)))
      []
      maps)))

(defn check-drop-rate [prog]
  (let [stats (get-event-stats prog)
        drop-rate (/ (:drops stats) (double (+ (:events stats) (:drops stats))))]
    (when (> drop-rate 0.05)
      [{:drop-rate drop-rate
        :message (format "High drop rate: %.1f%%" (* drop-rate 100))}])))

(defn check-stale-entries [prog]
  (let [maps (:maps prog)
        max-age (* 3600 1000000000)  ; 1 hour in ns
        now (System/nanoTime)]
    (reduce
      (fn [issues [map-name map-ref]]
        (let [stale-entries (filter
                             (fn [[k v]]
                               (and (:timestamp v)
                                    (> (- now (:timestamp v)) max-age)))
                             (bpf/map-get-all map-ref))]
          (if (seq stale-entries)
            (conj issues {:map map-name
                         :count (count stale-entries)
                         :message (format "Map '%s' has %d stale entries"
                                        map-name (count stale-entries))})
            issues)))
      []
      maps)))

(defn run-error-detection
  "Run all error detection checks"
  [prog]
  (println "\n=== Error Detection ===")

  (let [all-issues (atom [])]
    (doseq [pattern error-patterns]
      (let [issues ((:check pattern) prog)]
        (when (seq issues)
          (println (format "\n%s [%s]:" (:name pattern) (:severity pattern)))
          (doseq [issue issues]
            (println (format "  ⚠️  %s" (:message issue)))
            (swap! all-issues conj (assoc issue
                                         :pattern (:name pattern)
                                         :severity (:severity pattern)))))))

    (if (empty? @all-issues)
      (println "\n✓ No issues detected")
      (println (format "\n⚠️  Found %d issues" (count @all-issues))))

    @all-issues))

;; ============================================================================
;; bpftool Integration
;; ============================================================================

(defn bpftool-prog-show [prog-id]
  "Show program details using bpftool"
  (let [output (sh/sh "bpftool" "prog" "show" "id" (str prog-id))
        lines (str/split-lines (:out output))]
    (println "\n=== bpftool Output ===")
    (doseq [line lines]
      (println line))))

(defn bpftool-prog-dump [prog-id]
  "Dump program instructions"
  (let [output (sh/sh "bpftool" "prog" "dump" "xlated" "id" (str prog-id))
        lines (str/split-lines (:out output))]
    (println "\n=== Program Instructions ===")
    (doseq [line (take 50 lines)]  ; Show first 50 instructions
      (println line))
    (when (> (count lines) 50)
      (println (format "\n... %d more instructions" (- (count lines) 50))))))

(defn bpftool-map-dump [map-id]
  "Dump map contents"
  (let [output (sh/sh "bpftool" "map" "dump" "id" (str map-id))
        lines (str/split-lines (:out output))]
    (println "\n=== Map Contents ===")
    (doseq [line lines]
      (println line))))

;; ============================================================================
;; Interactive Debugger
;; ============================================================================

(defn debug-shell
  "Interactive debugging shell"
  [program]
  (println "BPF Debug Shell (type 'help' for commands)")

  (loop []
    (print "debug> ")
    (flush)
    (let [input (read-line)
          parts (str/split input #"\s+")
          cmd (first parts)
          args (rest parts)]

      (case cmd
        "help"
        (do
          (println "Commands:")
          (println "  trace          - Show execution trace")
          (println "  maps           - List all maps")
          (println "  inspect <map>  - Inspect map contents")
          (println "  watch <map>    - Watch map for changes")
          (println "  perf           - Show performance stats")
          (println "  errors         - Run error detection")
          (println "  replay         - Replay recorded events")
          (println "  quit           - Exit debugger"))

        "trace"
        (read-trace)

        "maps"
        (doseq [[name _] (:maps program)]
          (println (format "  - %s" name)))

        "inspect"
        (when-let [map-name (first args)]
          (when-let [map-ref (get-in program [:maps (keyword map-name)])]
            (inspect-map map-ref map-name)))

        "watch"
        (when-let [map-name (first args)]
          (when-let [map-ref (get-in program [:maps (keyword map-name)])]
            (watch-map map-ref map-name 1000)))

        "perf"
        (do
          (display-perf-stats)
          (find-bottlenecks))

        "errors"
        (run-error-detection program)

        "replay"
        (replay-events program)

        "quit"
        (do
          (println "Exiting debugger")
          :exit)

        (println "Unknown command. Type 'help' for commands"))

      (when (not= :exit cmd)
        (recur)))))

;; ============================================================================
;; Main Debug Session
;; ============================================================================

(defn -main [& args]
  (let [[command prog-id-str] args
        prog-id (when prog-id-str (Integer/parseInt prog-id-str))]

    (case command
      "shell"
      (do
        (println "Loading program...")
        (let [program (load-program-by-id prog-id)]
          (debug-shell program)))

      "trace"
      (do
        (println "Enabling trace...")
        (read-trace))

      "perf"
      (do
        (display-perf-stats)
        (find-bottlenecks))

      "inspect"
      (do
        (let [program (load-program-by-id prog-id)]
          (doseq [[name map-ref] (:maps program)]
            (inspect-map map-ref (str name)))))

      "errors"
      (do
        (let [program (load-program-by-id prog-id)]
          (run-error-detection program)))

      (println "Usage: debug-toolkit <shell|trace|perf|inspect|errors> [prog-id]"))))

;; Example session:
;;
;; $ lein run -m testing.debug-toolkit shell 123
;; BPF Debug Shell (type 'help' for commands)
;; debug> maps
;;   - stats
;;   - flows
;;   - events
;; debug> inspect stats
;;
;; === Map: stats ===
;; Entries: 5
;;
;; Key → Value
;; ───────────────────────────────
;;   6 → 1234
;;   17 → 567
;;   1 → 89
;;
;; debug> perf
;;
;; === Performance Statistics ===
;; SECTION  MIN(ns)  MAX(ns)  AVG(ns)  COUNT
;; ============================================
;; 1        150      450      200      10000
;; 2        50       100      75       10000
;;
;; === Top 5 Bottlenecks ===
;; Section 1: 200 ns average
;; Section 2: 75 ns average
```

## Key Features

1. **Instruction Tracing** - Track register values at checkpoints
2. **Map Inspector** - View and compare map contents
3. **Event Replay** - Record and replay events for debugging
4. **Performance Profiler** - Measure execution time
5. **Error Detection** - Automatically find common issues using `clj-ebpf.errors`
6. **Interactive Shell** - Debug programs interactively
7. **Platform Info** - Display architecture details using `clj-ebpf.arch`

## Integration with clj-ebpf Error Handling

The debugging toolkit integrates with `clj-ebpf.errors` for structured error handling:

```clojure
;; Diagnose any BPF error
(try
  (bpf/load-program my-program)
  (catch Exception e
    (diagnose-error e)))

;; Automatic retry on transient errors
(safe-operation
  #(maps/map-lookup my-map key)
  :max-retries 5)

;; Check error types
(errors/permission-error? e)   ; Permission issues
(errors/verifier-error? e)     ; Verifier rejection
(errors/resource-error? e)     ; Resource exhaustion
(errors/transient-error? e)    ; Retriable errors
```

## Usage Examples

### Debug High Drop Rate

```clojure
;; Load program
(let [prog (load-program my-program)]

  ;; Run error detection
  (run-error-detection prog)

  ;; Inspect drop stats
  (inspect-map (get-in prog [:maps :stats]) "stats")

  ;; Watch for changes
  (watch-map (get-in prog [:maps :stats]) "stats" 1000))
```

### Profile Performance

```clojure
;; Run program with profiling enabled
(let [prog (load-program profiled-program)]

  ;; Generate load
  (generate-load 10000)

  ;; Analyze performance
  (display-perf-stats)
  (find-bottlenecks))
```

### Replay Bug

```clojure
;; Record events that trigger bug
(record-events problematic-program)

;; Replay until failure
(replay-until-failure
  fixed-program
  (fn [result] (= :error (:status result))))
```

## Challenges

1. **Live Debugging**: Debug running production programs
2. **Memory Viewer**: Visualize packet/event memory layout
3. **Diff Tool**: Compare program versions
4. **Automated Fixes**: Suggest fixes for common errors
5. **Timeline View**: Visualize events over time

## Key Takeaways

- Visibility is critical for debugging BPF
- Map-based debugging is most practical
- Event replay enables reproducing bugs
- Performance profiling finds bottlenecks
- Automated error detection catches common issues using `clj-ebpf.errors`
- Interactive tools improve debugging experience
- Use `clj-ebpf.arch` for platform-aware debugging
- Structured error handling enables automatic recovery

## clj-ebpf Modules Used

| Module | Purpose |
|--------|---------|
| `clj-ebpf.errors` | Structured error handling, retry logic, error classification |
| `clj-ebpf.arch` | Platform detection, syscall numbers |
| `clj-ebpf.test-utils` | Capability checking, test helpers |
| `clj-ebpf.maps` | Map operations for inspection |

## References

- [clj-ebpf.errors Documentation](../../api/errors.md)
- [clj-ebpf.arch Documentation](../../api/arch.md)
- [bpftool Documentation](https://github.com/libbpf/bpftool)
- [BPF Debugging](https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html)
- [Linux Tracing](https://www.kernel.org/doc/html/latest/trace/index.html)
