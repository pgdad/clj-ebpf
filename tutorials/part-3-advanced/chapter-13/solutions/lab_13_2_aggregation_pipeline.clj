;; Lab 13.2 Solution: Event Aggregation Pipeline
;; In-kernel event aggregation to reduce volume by 100-1000x
;;
;; Learning Goals:
;; - Implement time-window aggregation
;; - Use hash maps for counting
;; - Minimize event volume
;; - Handle map overflow gracefully
;; - Bulk export aggregated data

(ns lab-13-2-aggregation-pipeline
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils])
  (:import [java.time LocalTime Duration]
           [java.util HashMap]
           [java.net InetAddress]))

;; ============================================================================
;; Configuration
;; ============================================================================

(def AGGREGATION_WINDOW_MS 1000)  ; 1 second windows
(def MAX_FLOWS 100000)            ; Track up to 100K flows

;; ============================================================================
;; Flow Key
;; ============================================================================

(defrecord FlowKey [src-ip dst-ip src-port dst-port protocol])

(defn create-flow-key
  "Create a 5-tuple flow identifier"
  [src-ip dst-ip src-port dst-port protocol]
  (->FlowKey src-ip dst-ip src-port dst-port protocol))

(defn flow-key-str
  "String representation of flow key"
  [flow-key]
  (format "%s:%d -> %s:%d (%s)"
          (:src-ip flow-key)
          (:src-port flow-key)
          (:dst-ip flow-key)
          (:dst-port flow-key)
          (case (:protocol flow-key)
            6 "TCP"
            17 "UDP"
            1 "ICMP"
            (str "Proto-" (:protocol flow-key)))))

;; ============================================================================
;; Flow Statistics
;; ============================================================================

(defrecord FlowStats [packets bytes first-seen last-seen flags])

(defn create-initial-stats
  "Create initial flow statistics"
  [packet-size timestamp]
  (->FlowStats 1 packet-size timestamp timestamp 0))

(defn update-flow-stats
  "Update existing flow statistics"
  [stats packet-size timestamp tcp-flags]
  (-> stats
      (update :packets inc)
      (update :bytes + packet-size)
      (assoc :last-seen timestamp)
      (update :flags bit-or (or tcp-flags 0))))

;; ============================================================================
;; Aggregation Map (In-Memory Simulation)
;; ============================================================================

(defn create-aggregation-map
  "Create aggregation map with max entries"
  [max-entries]
  {:map (atom (HashMap.))
   :max-entries max-entries
   :overflow-count (atom 0)
   :window-start (atom (System/currentTimeMillis))})

(defn aggregation-map-size
  "Get current map size"
  [agg-map]
  (.size @(:map agg-map)))

(defn aggregation-map-lookup
  "Look up flow in aggregation map"
  [agg-map flow-key]
  (.get @(:map agg-map) flow-key))

(defn aggregation-map-update!
  "Update flow in aggregation map"
  [agg-map flow-key stats]
  (if-let [existing (aggregation-map-lookup agg-map flow-key)]
    ;; Update existing
    (do
      (.put @(:map agg-map) flow-key stats)
      :updated)
    ;; Try to insert new
    (if (< (aggregation-map-size agg-map) (:max-entries agg-map))
      (do
        (.put @(:map agg-map) flow-key stats)
        :inserted)
      ;; Map full
      (do
        (swap! (:overflow-count agg-map) inc)
        :overflow))))

(defn aggregation-map-export!
  "Export and clear aggregation map"
  [agg-map]
  (let [current-map @(:map agg-map)
        entries (into {} current-map)]
    ;; Clear map for next window
    (.clear current-map)
    (reset! (:window-start agg-map) (System/currentTimeMillis))
    entries))

;; ============================================================================
;; Packet Simulation
;; ============================================================================

(defn generate-ip []
  (format "%d.%d.%d.%d"
          (+ 10 (rand-int 10))
          (rand-int 256)
          (rand-int 256)
          (+ 1 (rand-int 254))))

(defn generate-packet
  "Generate a simulated network packet"
  []
  (let [protocols [6 6 6 6 17 17 1]  ; 60% TCP, 30% UDP, 10% ICMP
        common-ports [80 443 22 53 8080 3306 5432]]
    {:src-ip (generate-ip)
     :dst-ip (generate-ip)
     :src-port (+ 1024 (rand-int 64511))
     :dst-port (rand-nth common-ports)
     :protocol (rand-nth protocols)
     :size (+ 40 (rand-int 1460))  ; 40-1500 bytes
     :tcp-flags (rand-int 64)
     :timestamp (System/currentTimeMillis)}))

(defn generate-flow-packets
  "Generate packets for a specific flow"
  [flow-key count]
  (repeatedly count
              (fn []
                {:src-ip (:src-ip flow-key)
                 :dst-ip (:dst-ip flow-key)
                 :src-port (:src-port flow-key)
                 :dst-port (:dst-port flow-key)
                 :protocol (:protocol flow-key)
                 :size (+ 40 (rand-int 1460))
                 :tcp-flags (rand-int 64)
                 :timestamp (System/currentTimeMillis)})))

(defn generate-traffic
  "Generate realistic traffic pattern"
  [total-packets num-flows]
  (let [flows (repeatedly num-flows
                          #(create-flow-key (generate-ip)
                                           (generate-ip)
                                           (+ 1024 (rand-int 64511))
                                           (rand-nth [80 443 22 53])
                                           (rand-nth [6 17])))
        packets-per-flow (quot total-packets num-flows)]
    (shuffle (mapcat #(generate-flow-packets % packets-per-flow) flows))))

;; ============================================================================
;; Aggregation Logic
;; ============================================================================

(defn process-packet
  "Process a single packet - aggregate into flow stats"
  [agg-map packet]
  (let [flow-key (create-flow-key
                  (:src-ip packet)
                  (:dst-ip packet)
                  (:src-port packet)
                  (:dst-port packet)
                  (:protocol packet))]

    (if-let [existing (aggregation-map-lookup agg-map flow-key)]
      ;; Update existing flow
      (let [updated (update-flow-stats existing
                                       (:size packet)
                                       (:timestamp packet)
                                       (:tcp-flags packet))]
        (aggregation-map-update! agg-map flow-key updated))

      ;; Create new flow entry
      (let [stats (create-initial-stats (:size packet) (:timestamp packet))]
        (aggregation-map-update! agg-map flow-key stats)))))

(defn process-packets-batch
  "Process a batch of packets"
  [agg-map packets]
  (let [results (atom {:updated 0 :inserted 0 :overflow 0})]
    (doseq [packet packets]
      (let [result (process-packet agg-map packet)]
        (swap! results update result inc)))
    @results))

;; ============================================================================
;; Time Window Management
;; ============================================================================

(defn window-expired?
  "Check if current aggregation window has expired"
  [agg-map]
  (> (- (System/currentTimeMillis) @(:window-start agg-map))
     AGGREGATION_WINDOW_MS))

(defn export-window
  "Export current window and reset"
  [agg-map]
  (let [window-start @(:window-start agg-map)
        window-end (System/currentTimeMillis)
        flows (aggregation-map-export! agg-map)
        overflow @(:overflow-count agg-map)]

    ;; Reset overflow counter
    (reset! (:overflow-count agg-map) 0)

    {:window-start window-start
     :window-end window-end
     :duration-ms (- window-end window-start)
     :flow-count (count flows)
     :flows flows
     :overflow overflow}))

;; ============================================================================
;; Analysis and Reporting
;; ============================================================================

(defn analyze-window
  "Analyze exported window data"
  [window-data]
  (let [flows (:flows window-data)
        total-packets (reduce + (map (comp :packets val) flows))
        total-bytes (reduce + (map (comp :bytes val) flows))
        flow-count (count flows)]

    {:window-start (:window-start window-data)
     :window-end (:window-end window-data)
     :flow-count flow-count
     :total-packets total-packets
     :total-bytes total-bytes
     :avg-packets-per-flow (if (zero? flow-count) 0
                               (/ total-packets (double flow-count)))
     :avg-bytes-per-flow (if (zero? flow-count) 0
                             (/ total-bytes (double flow-count)))
     :overflow (:overflow window-data)}))

(defn top-flows
  "Get top N flows by packets"
  [flows n]
  (->> flows
       (sort-by (comp :packets val) >)
       (take n)))

(defn display-window-summary
  "Display summary of aggregated window"
  [analysis]
  (println (format "\n=== Window Summary [%s - %s] ==="
                   (java.time.Instant/ofEpochMilli (:window-start analysis))
                   (java.time.Instant/ofEpochMilli (:window-end analysis))))
  (println (format "Flows:               %d" (:flow-count analysis)))
  (println (format "Total Packets:       %d" (:total-packets analysis)))
  (println (format "Total Bytes:         %d" (:total-bytes analysis)))
  (println (format "Avg Packets/Flow:    %.1f" (:avg-packets-per-flow analysis)))
  (println (format "Avg Bytes/Flow:      %.1f" (:avg-bytes-per-flow analysis)))
  (when (pos? (:overflow analysis))
    (println (format "Overflow Events:     %d" (:overflow analysis)))))

(defn display-top-flows
  "Display top flows"
  [window-data n]
  (println (format "\n=== Top %d Flows by Packets ===" n))
  (println "SRC_IP             DST_IP             PORT   PROTO  PACKETS     BYTES")
  (println "=====================================================================")

  (doseq [[flow-key stats] (top-flows (:flows window-data) n)]
    (println (format "%-18s %-18s %-6d %-5s  %-10d  %d"
                     (:src-ip flow-key)
                     (:dst-ip flow-key)
                     (:dst-port flow-key)
                     (case (:protocol flow-key) 6 "TCP" 17 "UDP" 1 "ICMP" "???")
                     (:packets stats)
                     (:bytes stats)))))

;; ============================================================================
;; Reduction Analysis
;; ============================================================================

(defn calculate-reduction
  "Calculate the event reduction achieved"
  [total-packets flow-count]
  (if (zero? flow-count)
    {:reduction-ratio 0 :reduction-percent 0}
    {:reduction-ratio (/ total-packets (double flow-count))
     :reduction-percent (* 100.0 (- 1 (/ flow-count (double total-packets))))}))

(defn display-reduction-analysis
  "Display reduction analysis"
  [total-packets flow-count duration-sec]
  (let [reduction (calculate-reduction total-packets flow-count)]
    (println "\n=== Event Reduction Analysis ===")
    (println (format "Raw events (if sent individually):  %d" total-packets))
    (println (format "Aggregated summaries:               %d" flow-count))
    (println (format "Reduction ratio:                    %.1fx" (:reduction-ratio reduction)))
    (println (format "Reduction percent:                  %.2f%%" (:reduction-percent reduction)))

    (println "\n=== Bandwidth Savings ===")
    (let [raw-bytes (* total-packets 64)
          agg-bytes (* flow-count 64)
          raw-rate (double (/ raw-bytes duration-sec))
          agg-rate (double (/ agg-bytes duration-sec))]
      (println (format "Without aggregation: %.2f MB/sec" (/ raw-rate 1024.0 1024.0)))
      (println (format "With aggregation:    %.2f KB/sec" (/ agg-rate 1024.0)))
      (println (format "Bandwidth saved:     %.2f MB/sec" (/ (- raw-rate agg-rate) 1024.0 1024.0))))))

;; ============================================================================
;; Continuous Aggregation
;; ============================================================================

(defn run-aggregation-loop
  "Run continuous aggregation with periodic export"
  [agg-map packet-source duration-sec]
  (let [start-time (System/currentTimeMillis)
        end-time (+ start-time (* duration-sec 1000))
        total-packets (atom 0)
        total-windows (atom 0)]

    (println (format "Running aggregation for %d seconds..." duration-sec))

    ;; Process packets until duration expires
    (loop []
      (when (< (System/currentTimeMillis) end-time)
        ;; Generate and process packets
        (let [packets (take 1000 (packet-source))]
          (process-packets-batch agg-map packets)
          (swap! total-packets + (count packets)))

        ;; Export if window expired
        (when (window-expired? agg-map)
          (let [window-data (export-window agg-map)
                analysis (analyze-window window-data)]
            (swap! total-windows inc)
            (println (format "[Window %d] Flows: %d, Packets: %d, Reduction: %.0fx"
                             @total-windows
                             (:flow-count analysis)
                             (:total-packets analysis)
                             (:avg-packets-per-flow analysis)))))

        (Thread/sleep 10)  ; Simulate packet arrival rate
        (recur)))

    ;; Final export
    (let [final-window (export-window agg-map)
          final-analysis (analyze-window final-window)]

      (println "\n=== Final Results ===")
      (println (format "Duration:        %d seconds" duration-sec))
      (println (format "Windows:         %d" @total-windows))
      (println (format "Total packets:   %d" @total-packets))
      (println (format "Final window:    %d flows" (:flow-count final-analysis)))

      {:total-packets @total-packets
       :total-windows @total-windows
       :duration-sec duration-sec})))

;; ============================================================================
;; Scenario Testing
;; ============================================================================

(defn run-batch-scenario
  "Run batch aggregation scenario"
  [packet-count flow-count]
  (println (format "\n=== Batch Aggregation Scenario ==="))
  (println (format "Packets: %d, Expected Flows: ~%d" packet-count flow-count))

  (let [agg-map (create-aggregation-map MAX_FLOWS)
        packets (generate-traffic packet-count flow-count)
        start-time (System/currentTimeMillis)]

    ;; Process all packets
    (let [results (process-packets-batch agg-map packets)
          end-time (System/currentTimeMillis)
          duration-ms (- end-time start-time)]

      ;; Export and analyze
      (let [window-data (export-window agg-map)
            analysis (analyze-window window-data)]

        (println (format "\nProcessing time: %d ms" duration-ms))
        (println (format "Packets/sec:     %.0f" (/ (* packet-count 1000.0) duration-ms)))

        (display-window-summary analysis)
        (display-top-flows window-data 10)
        (display-reduction-analysis packet-count (:flow-count analysis) 1)

        analysis))))

(defn run-high-volume-scenario
  "Run high-volume scenario to demonstrate reduction"
  []
  (println "\n=== High Volume Scenario ===")
  (println "Simulating 1M packets across 1K connections...")

  (run-batch-scenario 1000000 1000))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the aggregation pipeline lab"
  [& args]
  (let [command (first args)]
    (case command
      "batch"
      (let [packets (or (some-> (second args) Integer/parseInt) 100000)
            flows (or (some-> (nth args 2 nil) Integer/parseInt) 1000)]
        (run-batch-scenario packets flows))

      "continuous"
      (let [duration (or (some-> (second args) Integer/parseInt) 30)]
        (let [agg-map (create-aggregation-map MAX_FLOWS)]
          (run-aggregation-loop agg-map
                               #(generate-traffic 1000 100)
                               duration)))

      "highvol"
      (run-high-volume-scenario)

      ;; Default: demo
      (do
        (println "Lab 13.2: Event Aggregation Pipeline")
        (println "=====================================")
        (println "\nUsage:")
        (println "  batch [packets] [flows]     - Batch aggregation")
        (println "  continuous [duration]       - Continuous aggregation")
        (println "  highvol                     - High volume demo")
        (println)

        ;; Quick demo
        (run-batch-scenario 50000 500)

        (println "\n=== Key Takeaways ===")
        (println "1. Aggregation reduces event volume by 100-1000x")
        (println "2. Time-window bucketing enables efficient export")
        (println "3. Hash maps provide efficient counting")
        (println "4. Essential for high-rate event sources")))))

;; Run with: clj -M -m lab-13-2-aggregation-pipeline
;; Or:       clj -M -m lab-13-2-aggregation-pipeline highvol
