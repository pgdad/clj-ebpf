;; Lab 20.3 Solution: Capacity Planning
;; Learn to size and plan BPF deployments for production workloads

(ns lab-20-3-capacity-planning
  (:require [clojure.string :as str]
            [clj-ebpf.core :as ebpf])
  (:import [java.util.concurrent.atomic AtomicLong]
           [java.util Random]))

;; =============================================================================
;; Part 1: Resource Estimation - Maps
;; =============================================================================

(defn next-power-of-2
  "Round up to the next power of 2."
  [n]
  (let [n (long n)]
    (if (<= n 1)
      1
      (bit-shift-left 1
                      (- 64 (Long/numberOfLeadingZeros (dec n)))))))

(defn estimate-map-size
  "Estimate memory for a BPF map."
  [entries key-size value-size map-type]
  (let [;; Per-entry overhead varies by map type
        overhead-per-entry (case map-type
                             :hash 64           ;; Hash bucket overhead
                             :percpu-hash 128   ;; Per-CPU copies
                             :lru-hash 72       ;; LRU list pointers
                             :array 0           ;; No bucket overhead
                             :percpu-array 64   ;; Per-CPU header
                             :ringbuf 16        ;; Record header
                             32)                ;; Default
        entry-size (+ key-size value-size overhead-per-entry)
        total-bytes (* entries entry-size)
        ;; Page alignment overhead (~10%)
        with-alignment (* total-bytes 1.1)]
    {:map-type map-type
     :entries entries
     :key-size key-size
     :value-size value-size
     :entry-size entry-size
     :memory-bytes (long total-bytes)
     :memory-aligned (long with-alignment)
     :memory-kb (double (/ with-alignment 1024))
     :memory-mb (double (/ with-alignment 1024 1024))}))

(defn estimate-percpu-map-size
  "Estimate memory for per-CPU map."
  [entries key-size value-size num-cpus]
  (let [base-estimate (estimate-map-size entries key-size value-size :hash)
        percpu-total (* (:memory-aligned base-estimate) num-cpus)]
    (assoc base-estimate
           :map-type :percpu-hash
           :num-cpus num-cpus
           :total-memory-bytes (long percpu-total)
           :total-memory-mb (double (/ percpu-total 1024 1024)))))

(defn estimate-ringbuf-size
  "Estimate ring buffer size."
  [events-per-sec event-size buffer-seconds]
  (let [total-events (* events-per-sec buffer-seconds)
        ;; Ring buffer entry overhead
        entry-overhead 8  ;; Header
        total-per-event (+ event-size entry-overhead)
        total-bytes (* total-events total-per-event)
        ;; Add 20% overhead for ring buffer management
        with-overhead (* total-bytes 1.2)
        ;; Ring buffer must be power of 2
        recommended (next-power-of-2 with-overhead)]
    {:events-per-sec events-per-sec
     :event-size event-size
     :buffer-seconds buffer-seconds
     :total-events total-events
     :raw-bytes (long total-bytes)
     :with-overhead (long with-overhead)
     :recommended-size recommended
     :recommended-mb (double (/ recommended 1024 1024))}))

;; =============================================================================
;; Part 2: CPU and Memory Estimation
;; =============================================================================

(defn estimate-cpu-per-event
  "Estimate CPU cycles per event."
  [event-type complexity]
  (let [base-cycles (case event-type
                      :kprobe 500
                      :tracepoint 300
                      :xdp 100
                      :tc 150
                      :socket-filter 200
                      :perf-event 400
                      500)
        ;; Complexity multiplier
        complexity-factor (case complexity
                            :minimal 0.5
                            :simple 1.0
                            :moderate 2.0
                            :complex 4.0
                            :very-complex 8.0
                            1.0)]
    {:event-type event-type
     :base-cycles base-cycles
     :complexity complexity
     :complexity-factor complexity-factor
     :estimated-cycles (long (* base-cycles complexity-factor))}))

(defn estimate-cpu-needs
  "Estimate CPU requirements for workload."
  [events-per-sec cycles-per-event cpu-freq-ghz]
  (let [total-cycles-per-sec (* events-per-sec cycles-per-event)
        cycles-per-core-per-sec (* cpu-freq-ghz 1e9)
        ;; Account for overhead (context switches, cache misses)
        effective-cycles (* cycles-per-core-per-sec 0.7)
        cores-needed (/ total-cycles-per-sec effective-cycles)
        ;; Round up with safety margin
        recommended-cores (Math/ceil (* cores-needed 1.3))]
    {:events-per-sec events-per-sec
     :cycles-per-event cycles-per-event
     :cpu-freq-ghz cpu-freq-ghz
     :total-cycles-per-sec (long total-cycles-per-sec)
     :theoretical-cores cores-needed
     :recommended-cores (int recommended-cores)
     :cpu-utilization-pct (* 100 (/ cores-needed (max 1 recommended-cores)))}))

(defn estimate-total-memory
  "Estimate total memory requirements."
  [workload]
  (let [{:keys [maps ring-buffers per-cpu-maps num-cpus]} workload
        map-memory (reduce + (map #(get-in % [:memory-mb] 0) maps))
        ringbuf-memory (reduce + (map #(get-in % [:recommended-mb] 0) ring-buffers))
        percpu-memory (reduce + (map #(get-in % [:total-memory-mb] 0) per-cpu-maps))
        ;; Add overhead for BTF, verifier, etc.
        overhead-mb 16]
    {:map-memory-mb map-memory
     :ringbuf-memory-mb ringbuf-memory
     :percpu-memory-mb percpu-memory
     :overhead-mb overhead-mb
     :total-mb (+ map-memory ringbuf-memory percpu-memory overhead-mb)
     :recommended-mb (* 1.2 (+ map-memory ringbuf-memory percpu-memory overhead-mb))}))

;; =============================================================================
;; Part 3: Workload Profiles
;; =============================================================================

(defn create-workload-profile
  "Create a workload profile for capacity planning."
  [name config]
  {:name name
   :events-per-sec (:events-per-sec config 10000)
   :avg-event-size (:avg-event-size config 128)
   :peak-multiplier (:peak-multiplier config 3.0)
   :retention-seconds (:retention-seconds config 60)
   :maps (or (:maps config)
             [{:name "default" :entries 10000 :key-size 8 :value-size 64 :type :hash}])
   :programs (or (:programs config)
                 [{:name "default" :type :kprobe :complexity :moderate}])
   :growth-rate (:growth-rate config 1.5)  ;; Annual growth
   :num-cpus (:num-cpus config 8)
   :cpu-freq-ghz (:cpu-freq-ghz config 2.5)})

(def workload-templates
  {:network-monitoring
   {:events-per-sec 100000
    :avg-event-size 256
    :peak-multiplier 5.0
    :retention-seconds 30
    :maps [{:name "connections" :entries 1000000 :key-size 16 :value-size 64 :type :lru-hash}
           {:name "stats" :entries 10000 :key-size 8 :value-size 128 :type :percpu-hash}]
    :programs [{:name "xdp-filter" :type :xdp :complexity :moderate}
               {:name "tc-classifier" :type :tc :complexity :simple}]}

   :syscall-tracing
   {:events-per-sec 50000
    :avg-event-size 512
    :peak-multiplier 3.0
    :retention-seconds 60
    :maps [{:name "syscall-args" :entries 100000 :key-size 32 :value-size 256 :type :hash}
           {:name "process-info" :entries 50000 :key-size 8 :value-size 128 :type :hash}]
    :programs [{:name "sys-enter" :type :tracepoint :complexity :complex}
               {:name "sys-exit" :type :tracepoint :complexity :moderate}]}

   :security-audit
   {:events-per-sec 10000
    :avg-event-size 1024
    :peak-multiplier 2.0
    :retention-seconds 300
    :maps [{:name "audit-log" :entries 500000 :key-size 16 :value-size 512 :type :hash}
           {:name "policy-cache" :entries 10000 :key-size 32 :value-size 64 :type :hash}]
    :programs [{:name "file-audit" :type :kprobe :complexity :complex}
               {:name "network-audit" :type :socket-filter :complexity :moderate}]}

   :performance-profiling
   {:events-per-sec 200000
    :avg-event-size 64
    :peak-multiplier 4.0
    :retention-seconds 10
    :maps [{:name "stack-traces" :entries 100000 :key-size 8 :value-size 256 :type :hash}
           {:name "histograms" :entries 1000 :key-size 8 :value-size 128 :type :percpu-array}]
    :programs [{:name "cpu-profile" :type :perf-event :complexity :simple}
               {:name "memory-profile" :type :kprobe :complexity :moderate}]}})

;; =============================================================================
;; Part 4: Load Testing Framework
;; =============================================================================

(defn create-load-test-state
  "Create state for load testing."
  []
  {:processed (AtomicLong. 0)
   :dropped (AtomicLong. 0)
   :errors (AtomicLong. 0)
   :latency-sum (AtomicLong. 0)
   :max-latency (AtomicLong. 0)})

(defn process-test-event
  "Simulate processing a test event."
  [state complexity]
  (let [start-ns (System/nanoTime)
        ;; Simulate processing time based on complexity
        work-ns (case complexity
                  :minimal 100
                  :simple 500
                  :moderate 2000
                  :complex 10000
                  :very-complex 50000
                  1000)
        ;; Add some variance
        actual-ns (+ work-ns (rand-int (quot work-ns 2)))]
    ;; Simulate work
    (Thread/sleep 0 (min actual-ns 999999))

    (let [elapsed-ns (- (System/nanoTime) start-ns)]
      ;; Update stats
      (.incrementAndGet (:processed state))
      (.addAndGet (:latency-sum state) elapsed-ns)
      (loop []
        (let [current (.get (:max-latency state))]
          (when (and (> elapsed-ns current)
                     (not (.compareAndSet (:max-latency state) current elapsed-ns)))
            (recur))))
      {:success true :latency-ns elapsed-ns})))

(defn run-load-test
  "Run load test to determine capacity."
  [target-rate duration-sec complexity]
  (let [state (create-load-test-state)
        interval-ns (long (/ 1e9 target-rate))
        start-time (System/currentTimeMillis)
        end-time (+ start-time (* duration-sec 1000))]

    (println (format "Running load test at %d events/sec for %d seconds..."
                     target-rate duration-sec))

    ;; Generate load
    (while (< (System/currentTimeMillis) end-time)
      (try
        (process-test-event state complexity)
        (catch Exception e
          (.incrementAndGet (:errors state))))
      ;; Rate limiting - approximate
      (Thread/sleep 0 (min interval-ns 999999)))

    (let [elapsed-ms (- (System/currentTimeMillis) start-time)
          elapsed-sec (/ elapsed-ms 1000.0)
          processed (.get (:processed state))
          dropped (.get (:dropped state))
          errors (.get (:errors state))]
      {:target-rate target-rate
       :duration-sec duration-sec
       :actual-rate (/ processed elapsed-sec)
       :processed processed
       :dropped dropped
       :errors errors
       :drop-rate (if (pos? processed) (/ (double dropped) processed) 0.0)
       :error-rate (if (pos? processed) (/ (double errors) processed) 0.0)
       :avg-latency-us (if (pos? processed)
                         (/ (.get (:latency-sum state)) processed 1000.0)
                         0)
       :max-latency-us (/ (.get (:max-latency state)) 1000.0)})))

(defn find-max-capacity
  "Binary search for maximum sustainable rate."
  [complexity max-drop-rate test-duration-sec]
  (println "\nFinding maximum sustainable rate...")
  (loop [low 100
         high 100000
         best-rate 0]
    (if (< (- high low) 100)
      {:max-rate best-rate
       :complexity complexity
       :max-drop-rate max-drop-rate}
      (let [mid (quot (+ low high) 2)
            result (run-load-test mid test-duration-sec complexity)]
        (println (format "  Tested %d/sec: drop-rate=%.4f, latency=%.1fus"
                         mid (:drop-rate result) (:avg-latency-us result)))
        (if (< (:drop-rate result) max-drop-rate)
          (recur mid high mid)
          (recur low mid best-rate))))))

;; =============================================================================
;; Part 5: Capacity Report Generation
;; =============================================================================

(defn estimate-all-maps
  "Estimate resources for all maps in workload."
  [workload]
  (map (fn [m]
         (let [estimate (if (= (:type m) :percpu-hash)
                          (estimate-percpu-map-size (:entries m)
                                                    (:key-size m)
                                                    (:value-size m)
                                                    (:num-cpus workload 8))
                          (estimate-map-size (:entries m)
                                             (:key-size m)
                                             (:value-size m)
                                             (:type m :hash)))]
           (assoc estimate :name (:name m))))
       (:maps workload)))

(defn estimate-program-cpu
  "Estimate CPU for all programs in workload."
  [workload]
  (let [events-per-program (quot (:events-per-sec workload)
                                 (max 1 (count (:programs workload))))]
    (map (fn [p]
           (let [cpu-estimate (estimate-cpu-per-event (:type p) (:complexity p))
                 cpu-needs (estimate-cpu-needs events-per-program
                                               (:estimated-cycles cpu-estimate)
                                               (:cpu-freq-ghz workload 2.5))]
             (merge cpu-estimate cpu-needs {:name (:name p)})))
         (:programs workload))))

(defn generate-capacity-report
  "Generate comprehensive capacity report."
  [workload]
  (let [map-estimates (estimate-all-maps workload)
        ringbuf-estimate (estimate-ringbuf-size (:events-per-sec workload)
                                                (:avg-event-size workload)
                                                (:retention-seconds workload))
        program-cpu (estimate-program-cpu workload)
        memory-estimate (estimate-total-memory
                         {:maps map-estimates
                          :ring-buffers [ringbuf-estimate]
                          :per-cpu-maps (filter #(= :percpu-hash (:map-type %)) map-estimates)
                          :num-cpus (:num-cpus workload)})]
    {:workload-name (:name workload)
     :workload-config (select-keys workload [:events-per-sec :avg-event-size
                                             :peak-multiplier :retention-seconds])
     :map-estimates map-estimates
     :ringbuf-estimate ringbuf-estimate
     :program-cpu program-cpu
     :memory-estimate memory-estimate
     :recommendations
     {:maps (mapv (fn [m]
                    {:name (:name m)
                     :recommended-entries (* (:entries m) (:peak-multiplier workload))
                     :recommended-mb (* (:memory-mb m) (:peak-multiplier workload))})
                  map-estimates)
      :ring-buffer {:recommended-size (* (:recommended-size ringbuf-estimate)
                                         (:peak-multiplier workload))
                    :recommended-mb (* (:recommended-mb ringbuf-estimate)
                                       (:peak-multiplier workload))}
      :cpu-cores (int (Math/ceil (* (reduce + (map :recommended-cores program-cpu))
                                    (:peak-multiplier workload))))
      :memory-mb (int (Math/ceil (* (:recommended-mb memory-estimate)
                                    (:peak-multiplier workload))))}
     :scaling-factors
     {:events-growth (:growth-rate workload)
      :connections-growth (* (:growth-rate workload) 1.2)
      :storage-growth (* (:growth-rate workload) 1.5)}
     :year-1-projection
     {:events-per-sec (int (* (:events-per-sec workload) (:growth-rate workload)))
      :map-entries (mapv (fn [m]
                           {:name (:name m)
                            :entries (int (* (:entries m) (:growth-rate workload)))})
                         (:maps workload))
      :memory-mb (int (* (:recommended-mb memory-estimate)
                         (:growth-rate workload)
                         (:peak-multiplier workload)))}}))

(defn format-capacity-report
  "Format capacity report for display."
  [report]
  (let [lines (atom [])]
    (swap! lines conj (str/join "" (repeat 70 "=")))
    (swap! lines conj (format "CAPACITY PLANNING REPORT: %s" (:workload-name report)))
    (swap! lines conj (str/join "" (repeat 70 "=")))

    (swap! lines conj "\n--- Workload Configuration ---")
    (let [config (:workload-config report)]
      (swap! lines conj (format "Events/sec:         %,d" (:events-per-sec config)))
      (swap! lines conj (format "Event size:         %d bytes" (:avg-event-size config)))
      (swap! lines conj (format "Peak multiplier:    %.1fx" (:peak-multiplier config)))
      (swap! lines conj (format "Retention:          %d seconds" (:retention-seconds config))))

    (swap! lines conj "\n--- Map Estimates ---")
    (doseq [m (:map-estimates report)]
      (swap! lines conj (format "  %s (%s):" (:name m) (name (:map-type m))))
      (swap! lines conj (format "    Entries: %,d" (:entries m)))
      (swap! lines conj (format "    Memory:  %.2f MB" (:memory-mb m))))

    (swap! lines conj "\n--- Ring Buffer Estimate ---")
    (let [rb (:ringbuf-estimate report)]
      (swap! lines conj (format "  Events buffered:  %,d" (:total-events rb)))
      (swap! lines conj (format "  Recommended size: %,d bytes (%.2f MB)"
                                (:recommended-size rb) (:recommended-mb rb))))

    (swap! lines conj "\n--- CPU Estimates ---")
    (doseq [p (:program-cpu report)]
      (swap! lines conj (format "  %s (%s, %s complexity):"
                                (:name p) (name (:event-type p)) (name (:complexity p))))
      (swap! lines conj (format "    Cycles/event:    %,d" (:estimated-cycles p)))
      (swap! lines conj (format "    Recommended cores: %d" (:recommended-cores p))))

    (swap! lines conj "\n--- Memory Summary ---")
    (let [mem (:memory-estimate report)]
      (swap! lines conj (format "  Maps:         %.2f MB" (:map-memory-mb mem)))
      (swap! lines conj (format "  Ring buffers: %.2f MB" (:ringbuf-memory-mb mem)))
      (swap! lines conj (format "  Per-CPU:      %.2f MB" (:percpu-memory-mb mem)))
      (swap! lines conj (format "  Overhead:     %.2f MB" (:overhead-mb mem)))
      (swap! lines conj (format "  TOTAL:        %.2f MB" (:total-mb mem)))
      (swap! lines conj (format "  Recommended:  %.2f MB" (:recommended-mb mem))))

    (swap! lines conj "\n--- Recommendations (with peak load) ---")
    (let [rec (:recommendations report)]
      (swap! lines conj (format "  CPU Cores:    %d" (:cpu-cores rec)))
      (swap! lines conj (format "  Memory:       %d MB" (:memory-mb rec)))
      (swap! lines conj "  Maps:")
      (doseq [m (:maps rec)]
        (swap! lines conj (format "    %s: %,d entries (%.2f MB)"
                                  (:name m)
                                  (long (:recommended-entries m))
                                  (:recommended-mb m)))))

    (swap! lines conj "\n--- 1-Year Growth Projection ---")
    (let [proj (:year-1-projection report)]
      (swap! lines conj (format "  Events/sec: %,d" (:events-per-sec proj)))
      (swap! lines conj (format "  Memory:     %d MB" (:memory-mb proj)))
      (swap! lines conj "  Map entries:")
      (doseq [m (:map-entries proj)]
        (swap! lines conj (format "    %s: %,d" (:name m) (:entries m)))))

    (swap! lines conj (str "\n" (str/join "" (repeat 70 "="))))

    (str/join "\n" @lines)))

;; =============================================================================
;; Part 6: Sizing Calculator
;; =============================================================================

(defn calculate-sizing
  "Interactive sizing calculator."
  [params]
  (let [{:keys [events-per-sec event-size retention-sec
                map-entries map-key-size map-value-size
                num-cpus cpu-freq program-complexity
                peak-factor growth-factor]} params

        ;; Ring buffer
        ringbuf (estimate-ringbuf-size events-per-sec event-size retention-sec)

        ;; Main map
        main-map (estimate-map-size map-entries map-key-size map-value-size :hash)

        ;; CPU
        cpu-per-event (estimate-cpu-per-event :kprobe program-complexity)
        cpu-needs (estimate-cpu-needs events-per-sec
                                      (:estimated-cycles cpu-per-event)
                                      cpu-freq)

        ;; Total memory
        base-memory (+ (:recommended-mb ringbuf) (:memory-mb main-map) 16)]

    {:inputs params
     :ring-buffer {:size-bytes (:recommended-size ringbuf)
                   :size-mb (:recommended-mb ringbuf)}
     :map {:entries map-entries
           :size-mb (:memory-mb main-map)}
     :cpu {:cores-needed (:recommended-cores cpu-needs)
           :utilization-pct (:cpu-utilization-pct cpu-needs)}
     :memory {:base-mb base-memory
              :peak-mb (* base-memory peak-factor)
              :year-1-mb (* base-memory peak-factor growth-factor)}
     :summary {:recommended-cpu (* (:recommended-cores cpu-needs) (int peak-factor))
               :recommended-memory-mb (int (* base-memory peak-factor growth-factor 1.2))
               :recommended-ringbuf-mb (int (* (:recommended-mb ringbuf) peak-factor))
               :recommended-map-entries (int (* map-entries peak-factor growth-factor))}}))

;; =============================================================================
;; Part 7: Testing
;; =============================================================================

(defn run-tests
  "Run all capacity planning tests."
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "Running Capacity Planning Tests")
  (println (str/join "" (repeat 60 "=")))

  ;; Test map size estimation
  (println "\n=== Test: Map Size Estimation ===")
  (let [estimate (estimate-map-size 100000 8 64 :hash)]
    (println (format "Hash map (100K entries, 8+64 bytes): %.2f MB" (:memory-mb estimate))))

  (let [estimate (estimate-percpu-map-size 10000 8 128 8)]
    (println (format "Per-CPU map (10K entries, 8 CPUs): %.2f MB" (:total-memory-mb estimate))))

  ;; Test ring buffer estimation
  (println "\n=== Test: Ring Buffer Estimation ===")
  (let [estimate (estimate-ringbuf-size 50000 256 60)]
    (println (format "Ring buffer (50K/s, 256 bytes, 60s): %d bytes (%.2f MB)"
                     (:recommended-size estimate) (:recommended-mb estimate))))

  ;; Test CPU estimation
  (println "\n=== Test: CPU Estimation ===")
  (let [cpu-per-event (estimate-cpu-per-event :xdp :moderate)
        cpu-needs (estimate-cpu-needs 100000 (:estimated-cycles cpu-per-event) 2.5)]
    (println (format "XDP moderate (100K/s): %d cores (%.1f%% utilization)"
                     (:recommended-cores cpu-needs) (:cpu-utilization-pct cpu-needs))))

  ;; Test workload profile
  (println "\n=== Test: Workload Profile ===")
  (let [workload (create-workload-profile "test" (get workload-templates :network-monitoring))
        report (generate-capacity-report workload)]
    (println (format "Network monitoring profile:"))
    (println (format "  Events: %,d/sec" (get-in report [:workload-config :events-per-sec])))
    (println (format "  Memory: %.2f MB" (get-in report [:memory-estimate :recommended-mb])))
    (println (format "  CPU: %d cores" (get-in report [:recommendations :cpu-cores]))))

  ;; Test load test
  (println "\n=== Test: Load Testing ===")
  (let [result (run-load-test 1000 2 :moderate)]
    (println (format "Load test result: %,d processed, %.1f avg latency (us)"
                     (:processed result) (:avg-latency-us result))))

  (println "\n" (str/join "" (repeat 60 "=")))
  (println "All tests completed!")
  (println (str/join "" (repeat 60 "="))))

;; =============================================================================
;; Part 8: Demo Functions
;; =============================================================================

(defn demo-workload-profiles
  "Demonstrate different workload profiles."
  []
  (println "\n=== Workload Profile Comparison ===\n")

  (doseq [[profile-name config] workload-templates]
    (let [workload (create-workload-profile (name profile-name) config)
          report (generate-capacity-report workload)]
      (println (str/join "" (repeat 50 "-")))
      (println (format "Profile: %s" (name profile-name)))
      (println (format "  Events/sec:       %,d" (:events-per-sec workload)))
      (println (format "  Recommended CPU:  %d cores" (get-in report [:recommendations :cpu-cores])))
      (println (format "  Recommended RAM:  %d MB" (get-in report [:recommendations :memory-mb])))
      (println (format "  Year-1 projection: %,d events/sec, %d MB"
                       (get-in report [:year-1-projection :events-per-sec])
                       (get-in report [:year-1-projection :memory-mb])))))
  (println (str/join "" (repeat 50 "-"))))

(defn demo-sizing-calculator
  "Demonstrate sizing calculator."
  []
  (println "\n=== Sizing Calculator Demo ===\n")

  (let [params {:events-per-sec 100000
                :event-size 256
                :retention-sec 60
                :map-entries 500000
                :map-key-size 16
                :map-value-size 64
                :num-cpus 8
                :cpu-freq 2.5
                :program-complexity :moderate
                :peak-factor 3.0
                :growth-factor 1.5}
        result (calculate-sizing params)]

    (println "Input Parameters:")
    (println (format "  Events/sec: %,d" (:events-per-sec params)))
    (println (format "  Event size: %d bytes" (:event-size params)))
    (println (format "  Map entries: %,d" (:map-entries params)))
    (println (format "  Peak factor: %.1fx" (:peak-factor params)))
    (println (format "  Growth factor: %.1fx" (:growth-factor params)))

    (println "\nRecommendations:")
    (println (format "  CPU Cores: %d" (get-in result [:summary :recommended-cpu])))
    (println (format "  Memory: %d MB" (get-in result [:summary :recommended-memory-mb])))
    (println (format "  Ring Buffer: %d MB" (get-in result [:summary :recommended-ringbuf-mb])))
    (println (format "  Map Entries: %,d" (get-in result [:summary :recommended-map-entries])))))

(defn demo-capacity-report
  "Generate full capacity report."
  []
  (println "\n=== Full Capacity Report Demo ===")

  (let [workload (create-workload-profile "Production Network Monitor"
                                          (assoc (get workload-templates :network-monitoring)
                                                 :num-cpus 16
                                                 :cpu-freq-ghz 3.0
                                                 :growth-rate 2.0))
        report (generate-capacity-report workload)]
    (println (format-capacity-report report))))

(defn demo
  "Run all demos."
  []
  (demo-workload-profiles)
  (demo-sizing-calculator)
  (demo-capacity-report))

;; =============================================================================
;; Part 9: Main Entry Point
;; =============================================================================

(defn -main
  "Main entry point."
  [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (demo)
      "profiles" (demo-workload-profiles)
      "sizing" (demo-sizing-calculator)
      "report" (demo-capacity-report)
      "loadtest" (let [rate (Integer/parseInt (or (second args) "1000"))
                       duration (Integer/parseInt (or (nth args 2 nil) "5"))
                       complexity (keyword (or (nth args 3 nil) "moderate"))]
                   (let [result (run-load-test rate duration complexity)]
                     (println (format "\nResults:"))
                     (println (format "  Processed: %,d events" (:processed result)))
                     (println (format "  Actual rate: %.1f/sec" (:actual-rate result)))
                     (println (format "  Avg latency: %.1f us" (:avg-latency-us result)))
                     (println (format "  Max latency: %.1f us" (:max-latency-us result)))))
      "maxrate" (let [complexity (keyword (or (second args) "moderate"))]
                  (let [result (find-max-capacity complexity 0.001 3)]
                    (println (format "\nMaximum sustainable rate: %,d events/sec"
                                     (:max-rate result)))))
      ;; Default
      (do
        (println "Capacity Planning System")
        (println "Usage: clj -M -m lab-20-3.capacity-planning [command]")
        (println "Commands:")
        (println "  test                      - Run tests")
        (println "  demo                      - Run all demos")
        (println "  profiles                  - Compare workload profiles")
        (println "  sizing                    - Run sizing calculator")
        (println "  report                    - Generate full capacity report")
        (println "  loadtest [rate] [sec] [complexity] - Run load test")
        (println "  maxrate [complexity]      - Find max sustainable rate")
        (println "\nRunning tests by default...\n")
        (run-tests)))))

;; =============================================================================
;; Exercises
;; =============================================================================

(comment
  ;; Exercise 1: Add cost estimation
  ;; Calculate cloud infrastructure costs for recommendations

  ;; Exercise 2: Implement automated benchmarking
  ;; Create benchmarks that run against actual BPF programs

  ;; Exercise 3: Add multi-region planning
  ;; Consider geographic distribution and latency

  ;; Exercise 4: Create what-if scenario analysis
  ;; Model different growth and usage patterns

  ;; Exercise 5: Add visualization
  ;; Create charts for capacity projections
  )
