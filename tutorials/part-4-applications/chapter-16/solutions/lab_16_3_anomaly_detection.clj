(ns lab-16-3-anomaly-detection
  "Lab 16.3: Network Anomaly Detection

   This solution demonstrates:
   - Port scan detection
   - SYN flood detection
   - Top talkers identification
   - Protocol distribution analysis

   Run with: clojure -M -m lab-16-3-anomaly-detection test"
  (:require [clojure.string :as str]))

;;; ============================================================================
;;; Part 1: Detection Thresholds
;;; ============================================================================

(def detection-config
  (atom {:port-scan-threshold 10        ; ports per source in window
         :syn-flood-threshold 100       ; SYNs per target in window
         :window-ms 60000               ; 1 minute window
         :top-talkers-count 10}))

;;; ============================================================================
;;; Part 2: Connection Tracking
;;; ============================================================================

(def connection-attempts
  "Track connection attempts: {src-ip -> {dst-ip -> #{ports}}}"
  (atom {}))

(def syn-packets
  "Track SYN packets: {dst-ip -> count}"
  (atom {}))

(def traffic-stats
  "Per-source traffic stats: {ip -> {:packets :bytes :last-seen}}"
  (atom {}))

(defn record-connection-attempt!
  "Record a connection attempt"
  [src-ip dst-ip dst-port timestamp]
  (swap! connection-attempts
         update src-ip
         (fn [dests]
           (update (or dests {}) dst-ip
                   (fn [ports] (conj (or ports #{}) dst-port))))))

(defn record-syn-packet!
  "Record a SYN packet"
  [dst-ip]
  (swap! syn-packets update dst-ip (fnil inc 0)))

(defn record-traffic!
  "Record traffic from a source"
  [src-ip packet-size timestamp]
  (swap! traffic-stats
         update src-ip
         (fn [stats]
           {:packets (inc (or (:packets stats) 0))
            :bytes (+ (or (:bytes stats) 0) packet-size)
            :last-seen timestamp})))

(defn clear-tracking!
  "Clear all tracking data"
  []
  (reset! connection-attempts {})
  (reset! syn-packets {})
  (reset! traffic-stats {}))

;;; ============================================================================
;;; Part 3: Port Scan Detection
;;; ============================================================================

(defn detect-port-scanners
  "Detect sources that have connected to many ports"
  []
  (let [threshold (:port-scan-threshold @detection-config)]
    (for [[src-ip destinations] @connection-attempts
          :let [total-ports (reduce + (map count (vals destinations)))]
          :when (>= total-ports threshold)]
      {:type :port-scan
       :src-ip src-ip
       :targets (count destinations)
       :ports-scanned total-ports
       :severity (cond
                   (>= total-ports 100) :critical
                   (>= total-ports 50) :high
                   (>= total-ports 20) :medium
                   :else :low)})))

(defn detect-horizontal-scan
  "Detect horizontal scan (one port, many hosts)"
  []
  (let [port-targets (atom {})]
    ;; Group by port across all sources
    (doseq [[src-ip destinations] @connection-attempts
            [dst-ip ports] destinations
            port ports]
      (swap! port-targets update port (fnil conj #{}) [src-ip dst-ip]))

    ;; Find ports with many targets from single source
    (for [[port targets] @port-targets
          :let [by-source (group-by first targets)]
          [src-ip src-targets] by-source
          :when (>= (count src-targets) 5)]
      {:type :horizontal-scan
       :src-ip src-ip
       :port port
       :targets-count (count src-targets)
       :severity :high})))

;;; ============================================================================
;;; Part 4: SYN Flood Detection
;;; ============================================================================

(defn detect-syn-flood
  "Detect targets receiving many SYN packets"
  []
  (let [threshold (:syn-flood-threshold @detection-config)]
    (for [[dst-ip count] @syn-packets
          :when (>= count threshold)]
      {:type :syn-flood
       :target-ip dst-ip
       :syn-count count
       :severity (cond
                   (>= count 1000) :critical
                   (>= count 500) :high
                   (>= count 200) :medium
                   :else :low)})))

;;; ============================================================================
;;; Part 5: Top Talkers
;;; ============================================================================

(defn get-top-talkers
  "Get top N sources by traffic"
  [& {:keys [by] :or {by :bytes}}]
  (let [n (:top-talkers-count @detection-config)
        sort-key (case by
                   :bytes :bytes
                   :packets :packets
                   :bytes)]
    (->> @traffic-stats
         (sort-by (comp sort-key second) >)
         (take n)
         (map (fn [[ip stats]]
                (merge {:ip ip} stats))))))

(defn detect-bandwidth-hogs
  "Detect sources using excessive bandwidth"
  []
  (let [top-talkers (get-top-talkers :by :bytes)
        total-bytes (reduce + (map :bytes (vals @traffic-stats)))
        threshold 0.5]  ; 50% of total
    (for [talker top-talkers
          :let [pct (if (pos? total-bytes) (/ (:bytes talker) total-bytes) 0)]
          :when (>= pct threshold)]
      {:type :bandwidth-hog
       :src-ip (:ip talker)
       :bytes (:bytes talker)
       :percentage (* 100 pct)
       :severity (if (>= pct 0.8) :high :medium)})))

;;; ============================================================================
;;; Part 6: Protocol Distribution
;;; ============================================================================

(def protocol-counts
  "Protocol distribution: {protocol -> count}"
  (atom {}))

(defn record-protocol!
  "Record a protocol"
  [protocol]
  (swap! protocol-counts update protocol (fnil inc 0)))

(defn get-protocol-distribution
  "Get protocol distribution as percentages"
  []
  (let [total (reduce + (vals @protocol-counts))]
    (if (pos? total)
      (into {} (map (fn [[p c]]
                      [p {:count c
                          :percentage (* 100.0 (/ c total))}])
                    @protocol-counts))
      {})))

(defn detect-protocol-anomaly
  "Detect unusual protocol distribution"
  []
  (let [dist (get-protocol-distribution)
        ;; Expected: TCP ~70%, UDP ~25%, ICMP ~5%
        tcp-pct (get-in dist [6 :percentage] 0)
        udp-pct (get-in dist [17 :percentage] 0)
        icmp-pct (get-in dist [1 :percentage] 0)]
    (cond
      (> icmp-pct 20)
      {:type :icmp-flood
       :icmp-percentage icmp-pct
       :severity :high}

      (> udp-pct 80)
      {:type :udp-flood
       :udp-percentage udp-pct
       :severity :medium}

      :else nil)))

;;; ============================================================================
;;; Part 7: Anomaly Aggregation
;;; ============================================================================

(defn detect-all-anomalies
  "Run all detection algorithms"
  []
  (let [port-scans (detect-port-scanners)
        h-scans (detect-horizontal-scan)
        syn-floods (detect-syn-flood)
        bw-hogs (detect-bandwidth-hogs)
        proto-anomaly (detect-protocol-anomaly)]
    (concat port-scans h-scans syn-floods bw-hogs
            (when proto-anomaly [proto-anomaly]))))

(defn format-anomaly
  "Format anomaly for display"
  [anomaly]
  (let [severity-icon (case (:severity anomaly)
                        :critical "🚨"
                        :high "⚠️"
                        :medium "⚡"
                        :low "ℹ️"
                        "?")]
    (case (:type anomaly)
      :port-scan
      (format "%s PORT SCAN: %s scanned %d ports on %d hosts"
              severity-icon
              (str/join "." (:src-ip anomaly))
              (:ports-scanned anomaly)
              (:targets anomaly))

      :horizontal-scan
      (format "%s HORIZONTAL SCAN: %s scanning port %d on %d hosts"
              severity-icon
              (str/join "." (:src-ip anomaly))
              (:port anomaly)
              (:targets-count anomaly))

      :syn-flood
      (format "%s SYN FLOOD: %s received %d SYN packets"
              severity-icon
              (str/join "." (:target-ip anomaly))
              (:syn-count anomaly))

      :bandwidth-hog
      (format "%s BANDWIDTH HOG: %s using %.1f%% of bandwidth"
              severity-icon
              (str/join "." (:src-ip anomaly))
              (:percentage anomaly))

      :icmp-flood
      (format "%s ICMP FLOOD: %.1f%% ICMP traffic"
              severity-icon
              (:icmp-percentage anomaly))

      :udp-flood
      (format "%s UDP FLOOD: %.1f%% UDP traffic"
              severity-icon
              (:udp-percentage anomaly))

      (str severity-icon " UNKNOWN: " (pr-str anomaly)))))

;;; ============================================================================
;;; Part 8: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 16.3 Tests ===\n")

  ;; Test 1: Connection tracking
  (println "Test 1: Connection Tracking")
  (clear-tracking!)
  (record-connection-attempt! [10 0 0 1] [192 168 1 1] 80 0)
  (record-connection-attempt! [10 0 0 1] [192 168 1 1] 443 0)
  (record-connection-attempt! [10 0 0 1] [192 168 1 2] 22 0)
  (let [conns (get @connection-attempts [10 0 0 1])]
    (assert (= 2 (count conns)) "2 destinations")
    (assert (= #{80 443} (get conns [192 168 1 1])) "ports tracked"))
  (println "  Connection tracking works correctly")
  (println "  PASSED\n")

  ;; Test 2: Port scan detection
  (println "Test 2: Port Scan Detection")
  (clear-tracking!)
  (swap! detection-config assoc :port-scan-threshold 5)
  (doseq [port (range 20)]
    (record-connection-attempt! [10 0 0 1] [192 168 1 1] port 0))
  (let [scans (detect-port-scanners)]
    (assert (= 1 (count scans)) "one scanner detected")
    (assert (= 20 (:ports-scanned (first scans))) "20 ports"))
  (println "  Port scan detection works correctly")
  (println "  PASSED\n")

  ;; Test 3: Horizontal scan detection
  (println "Test 3: Horizontal Scan Detection")
  (clear-tracking!)
  (doseq [i (range 10)]
    (record-connection-attempt! [10 0 0 1] [192 168 1 i] 22 0))
  (let [scans (detect-horizontal-scan)]
    (assert (= 1 (count scans)) "one h-scan detected")
    (assert (= 22 (:port (first scans))) "port 22"))
  (println "  Horizontal scan detection works correctly")
  (println "  PASSED\n")

  ;; Test 4: SYN flood detection
  (println "Test 4: SYN Flood Detection")
  (clear-tracking!)
  (swap! detection-config assoc :syn-flood-threshold 50)
  (dotimes [_ 100]
    (record-syn-packet! [192 168 1 1]))
  (let [floods (detect-syn-flood)]
    (assert (= 1 (count floods)) "one flood detected")
    (assert (= 100 (:syn-count (first floods))) "100 SYNs"))
  (println "  SYN flood detection works correctly")
  (println "  PASSED\n")

  ;; Test 5: Top talkers
  (println "Test 5: Top Talkers")
  (clear-tracking!)
  (record-traffic! [10 0 0 1] 10000 0)
  (record-traffic! [10 0 0 2] 5000 0)
  (record-traffic! [10 0 0 3] 15000 0)
  (let [top (get-top-talkers :by :bytes)]
    (assert (= [10 0 0 3] (:ip (first top))) "top talker is .3")
    (assert (= 15000 (:bytes (first top))) "correct bytes"))
  (println "  Top talkers analysis works correctly")
  (println "  PASSED\n")

  ;; Test 6: Protocol distribution
  (println "Test 6: Protocol Distribution")
  (reset! protocol-counts {})
  (dotimes [_ 70] (record-protocol! 6))   ; TCP
  (dotimes [_ 25] (record-protocol! 17))  ; UDP
  (dotimes [_ 5] (record-protocol! 1))    ; ICMP
  (let [dist (get-protocol-distribution)]
    (assert (< 69 (get-in dist [6 :percentage]) 71) "TCP ~70%")
    (assert (< 24 (get-in dist [17 :percentage]) 26) "UDP ~25%"))
  (println "  Protocol distribution works correctly")
  (println "  PASSED\n")

  ;; Test 7: Protocol anomaly detection
  (println "Test 7: Protocol Anomaly Detection")
  (reset! protocol-counts {1 50 6 30 17 20})  ; 50% ICMP
  (let [anomaly (detect-protocol-anomaly)]
    (assert (some? anomaly) "anomaly detected")
    (assert (= :icmp-flood (:type anomaly)) "ICMP flood"))
  (println "  Protocol anomaly detection works correctly")
  (println "  PASSED\n")

  ;; Test 8: Bandwidth hog detection
  (println "Test 8: Bandwidth Hog Detection")
  (clear-tracking!)
  (record-traffic! [10 0 0 1] 9000 0)  ; 90%
  (record-traffic! [10 0 0 2] 1000 0)  ; 10%
  (let [hogs (detect-bandwidth-hogs)]
    (assert (= 1 (count hogs)) "one hog")
    (assert (= [10 0 0 1] (:src-ip (first hogs))) "correct source"))
  (println "  Bandwidth hog detection works correctly")
  (println "  PASSED\n")

  ;; Test 9: All anomaly detection
  (println "Test 9: Combined Anomaly Detection")
  (clear-tracking!)
  (swap! detection-config assoc :port-scan-threshold 5 :syn-flood-threshold 10)
  (doseq [port (range 10)]
    (record-connection-attempt! [10 0 0 1] [192 168 1 1] port 0))
  (dotimes [_ 20]
    (record-syn-packet! [192 168 1 2]))
  (let [anomalies (detect-all-anomalies)]
    (assert (>= (count anomalies) 2) "at least 2 anomalies"))
  (println "  Combined detection works correctly")
  (println "  PASSED\n")

  ;; Test 10: Severity classification
  (println "Test 10: Severity Classification")
  (clear-tracking!)
  (swap! detection-config assoc :port-scan-threshold 5)
  (doseq [port (range 150)]
    (record-connection-attempt! [10 0 0 1] [192 168 1 1] port 0))
  (let [scan (first (detect-port-scanners))]
    (assert (= :critical (:severity scan)) "critical severity"))
  (println "  Severity classification works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 9: Demo
;;; ============================================================================

(defn run-demo
  "Run demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 16.3: Network Anomaly Detection")
  (println (str/join "" (repeat 60 "=")) "\n")

  (clear-tracking!)
  (reset! protocol-counts {})
  (swap! detection-config assoc :port-scan-threshold 10 :syn-flood-threshold 50)

  ;; Simulate normal traffic
  (println "=== Simulating Network Traffic ===\n")

  ;; Normal web browsing
  (dotimes [_ 100]
    (record-traffic! [192 168 1 100] (+ 500 (rand-int 1000)) 0)
    (record-protocol! 6))

  ;; Port scanner
  (doseq [port (range 1 1025)]
    (record-connection-attempt! [10 0 0 50] [192 168 1 1] port 0)
    (record-traffic! [10 0 0 50] 60 0)
    (record-protocol! 6))

  ;; SYN flood target
  (dotimes [_ 200]
    (record-syn-packet! [192 168 1 10])
    (record-traffic! [(rand-int 256) (rand-int 256) (rand-int 256) (rand-int 256)] 60 0)
    (record-protocol! 6))

  ;; Horizontal SSH scanner
  (doseq [i (range 50)]
    (record-connection-attempt! [172 16 0 5] [10 0 0 i] 22 0)
    (record-traffic! [172 16 0 5] 60 0)
    (record-protocol! 6))

  ;; Normal DNS traffic
  (dotimes [_ 50]
    (record-traffic! [192 168 1 100] 100 0)
    (record-protocol! 17))

  (println "Simulated:")
  (println "  - Normal web traffic from 192.168.1.100")
  (println "  - Port scan from 10.0.0.50 (1024 ports)")
  (println "  - SYN flood targeting 192.168.1.10 (200 SYNs)")
  (println "  - SSH horizontal scan from 172.16.0.5 (50 hosts)")
  (println "  - Normal DNS queries")
  (println)

  ;; Detect anomalies
  (println "=== Detected Anomalies ===\n")
  (let [anomalies (detect-all-anomalies)]
    (if (seq anomalies)
      (doseq [a (sort-by #(case (:severity %) :critical 0 :high 1 :medium 2 :low 3 4) anomalies)]
        (println (format-anomaly a)))
      (println "No anomalies detected"))
    (println)
    (println (format "Total anomalies: %d" (count anomalies))))

  (println)

  ;; Top talkers
  (println "=== Top Talkers ===\n")
  (println (format "%-20s %12s %12s" "SOURCE IP" "PACKETS" "BYTES"))
  (println (str/join "" (repeat 46 "-")))
  (doseq [t (take 5 (get-top-talkers :by :bytes))]
    (println (format "%-20s %,12d %,12d"
                     (str/join "." (:ip t))
                     (:packets t)
                     (:bytes t))))

  (println)

  ;; Protocol distribution
  (println "=== Protocol Distribution ===\n")
  (let [dist (get-protocol-distribution)]
    (doseq [[proto {:keys [count percentage]}] (sort-by (comp - :count second) dist)]
      (let [name (case proto 6 "TCP" 17 "UDP" 1 "ICMP" (str "Proto " proto))
            bar (str/join "" (repeat (int (/ percentage 2)) "█"))]
        (println (format "  %-6s %5.1f%% %s" name percentage bar))))))

;;; ============================================================================
;;; Part 10: Main
;;; ============================================================================

(defn -main [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      (do
        (println "Usage: clojure -M -m lab-16-3-anomaly-detection <command>")
        (println "Commands:")
        (println "  test  - Run tests")
        (println "  demo  - Run demonstration")))))
