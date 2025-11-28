(ns lab-16-2-flow-tracking
  "Lab 16.2: Flow Tracking

   This solution demonstrates:
   - 5-tuple flow key creation
   - Bidirectional flow handling
   - Per-flow statistics tracking
   - Flow aging and cleanup

   Run with: clojure -M -m lab-16-2-flow-tracking test"
  (:require [clojure.string :as str]))

;;; ============================================================================
;;; Part 1: Flow Key
;;; ============================================================================

(defrecord FlowKey
  [src-ip dst-ip src-port dst-port protocol])

(defn create-flow-key
  "Create a flow key from packet info"
  [src-ip dst-ip src-port dst-port protocol]
  (->FlowKey src-ip dst-ip src-port dst-port protocol))

(defn normalize-flow-key
  "Normalize flow key for bidirectional matching (smaller IP first)"
  [flow-key]
  (let [{:keys [src-ip dst-ip src-port dst-port protocol]} flow-key
        src-int (reduce (fn [acc b] (+ (bit-shift-left acc 8) b)) 0 src-ip)
        dst-int (reduce (fn [acc b] (+ (bit-shift-left acc 8) b)) 0 dst-ip)]
    (if (< src-int dst-int)
      flow-key
      (->FlowKey dst-ip src-ip dst-port src-port protocol))))

(defn flow-key->string
  "Format flow key as string"
  [fk]
  (format "%s:%d -> %s:%d [%s]"
          (str/join "." (:src-ip fk))
          (:src-port fk)
          (str/join "." (:dst-ip fk))
          (:dst-port fk)
          (case (:protocol fk) 6 "TCP" 17 "UDP" 1 "ICMP" "?")))

;;; ============================================================================
;;; Part 2: Flow Statistics
;;; ============================================================================

(defrecord FlowStats
  [packets bytes first-seen last-seen
   fwd-packets fwd-bytes rev-packets rev-bytes
   tcp-flags syn-count fin-count rst-count])

(defn create-flow-stats
  "Create initial flow statistics"
  [packet-size timestamp is-forward?]
  (->FlowStats
    1 packet-size timestamp timestamp
    (if is-forward? 1 0) (if is-forward? packet-size 0)
    (if is-forward? 0 1) (if is-forward? 0 packet-size)
    0 0 0 0))

(defn update-flow-stats
  "Update flow statistics with new packet"
  [stats packet-size timestamp is-forward? tcp-flags]
  (->FlowStats
    (inc (:packets stats))
    (+ (:bytes stats) packet-size)
    (:first-seen stats)
    timestamp
    (if is-forward? (inc (:fwd-packets stats)) (:fwd-packets stats))
    (if is-forward? (+ (:fwd-bytes stats) packet-size) (:fwd-bytes stats))
    (if is-forward? (:rev-packets stats) (inc (:rev-packets stats)))
    (if is-forward? (:rev-bytes stats) (+ (:rev-bytes stats) packet-size))
    (bit-or (:tcp-flags stats) (or tcp-flags 0))
    (+ (:syn-count stats) (if (and tcp-flags (pos? (bit-and tcp-flags 0x02))) 1 0))
    (+ (:fin-count stats) (if (and tcp-flags (pos? (bit-and tcp-flags 0x01))) 1 0))
    (+ (:rst-count stats) (if (and tcp-flags (pos? (bit-and tcp-flags 0x04))) 1 0))))

(defn flow-duration
  "Calculate flow duration in nanoseconds"
  [stats]
  (- (:last-seen stats) (:first-seen stats)))

(defn flow-rate
  "Calculate packets per second"
  [stats]
  (let [dur-s (/ (flow-duration stats) 1e9)]
    (if (pos? dur-s)
      (/ (:packets stats) dur-s)
      0.0)))

;;; ============================================================================
;;; Part 3: Flow Table
;;; ============================================================================

(def flow-table
  "Active flows"
  (atom {}))

(def flow-config
  "Flow tracking configuration"
  (atom {:max-flows 100000
         :idle-timeout-ns (* 30 1e9)  ; 30 seconds
         :bidirectional true}))

(defn is-forward-direction?
  "Check if packet is in forward direction for a flow"
  [flow-key original-key]
  (= (:src-ip flow-key) (:src-ip original-key)))

(defn record-packet!
  "Record a packet in the flow table"
  [flow-key packet-size timestamp & {:keys [tcp-flags]}]
  (let [normalized (if (:bidirectional @flow-config)
                     (normalize-flow-key flow-key)
                     flow-key)
        is-forward? (= (:src-ip flow-key) (:src-ip normalized))]
    (swap! flow-table
           (fn [table]
             (if-let [existing (get table normalized)]
               (assoc table normalized
                      (update-flow-stats existing packet-size timestamp is-forward? tcp-flags))
               (if (< (count table) (:max-flows @flow-config))
                 (assoc table normalized
                        (create-flow-stats packet-size timestamp is-forward?))
                 table))))))

(defn get-flow
  "Get flow statistics"
  [flow-key]
  (let [normalized (if (:bidirectional @flow-config)
                     (normalize-flow-key flow-key)
                     flow-key)]
    (get @flow-table normalized)))

(defn get-all-flows
  "Get all flows"
  []
  @flow-table)

(defn flow-count
  "Get number of active flows"
  []
  (count @flow-table))

(defn clear-flows!
  "Clear all flows"
  []
  (reset! flow-table {}))

;;; ============================================================================
;;; Part 4: Flow Aging
;;; ============================================================================

(defn age-flows!
  "Remove idle flows"
  [current-time]
  (let [timeout (:idle-timeout-ns @flow-config)]
    (swap! flow-table
           (fn [table]
             (into {}
                   (filter (fn [[_ stats]]
                             (< (- current-time (:last-seen stats)) timeout))
                           table))))))

(defn get-idle-flows
  "Get flows that have been idle longer than threshold"
  [current-time idle-threshold-ns]
  (filter (fn [[_ stats]]
            (> (- current-time (:last-seen stats)) idle-threshold-ns))
          @flow-table))

(defn get-active-flows
  "Get flows that have recent activity"
  [current-time active-threshold-ns]
  (filter (fn [[_ stats]]
            (< (- current-time (:last-seen stats)) active-threshold-ns))
          @flow-table))

;;; ============================================================================
;;; Part 5: Flow Analysis
;;; ============================================================================

(defn top-flows-by-bytes
  "Get top N flows by total bytes"
  [n]
  (->> (get-all-flows)
       (sort-by (comp :bytes second) >)
       (take n)))

(defn top-flows-by-packets
  "Get top N flows by packet count"
  [n]
  (->> (get-all-flows)
       (sort-by (comp :packets second) >)
       (take n)))

(defn top-flows-by-rate
  "Get top N flows by packet rate"
  [n]
  (->> (get-all-flows)
       (sort-by (comp flow-rate second) >)
       (take n)))

(defn flows-by-protocol
  "Group flows by protocol"
  []
  (group-by (comp :protocol first) (get-all-flows)))

(defn total-traffic
  "Calculate total traffic statistics"
  []
  (let [flows (vals (get-all-flows))]
    {:flow-count (count flows)
     :total-packets (reduce + (map :packets flows))
     :total-bytes (reduce + (map :bytes flows))
     :tcp-flows (count (filter #(= 6 (:protocol (first %))) (get-all-flows)))
     :udp-flows (count (filter #(= 17 (:protocol (first %))) (get-all-flows)))}))

;;; ============================================================================
;;; Part 6: Flow State Analysis
;;; ============================================================================

(defn tcp-flow-state
  "Determine TCP flow state from flags"
  [stats]
  (let [flags (:tcp-flags stats)]
    (cond
      (pos? (bit-and flags 0x04)) :reset      ; RST seen
      (and (pos? (:syn-count stats))
           (pos? (:fin-count stats))) :closed ; SYN and FIN seen
      (pos? (:fin-count stats)) :closing      ; FIN seen
      (pos? (:syn-count stats)) :established  ; SYN seen
      :else :unknown)))

(defn bidirectional-flow?
  "Check if flow has traffic in both directions"
  [stats]
  (and (pos? (:fwd-packets stats))
       (pos? (:rev-packets stats))))

(defn flow-asymmetry
  "Calculate flow asymmetry ratio (0 = symmetric, 1 = one-way)"
  [stats]
  (let [total (:packets stats)
        diff (Math/abs (- (:fwd-packets stats) (:rev-packets stats)))]
    (if (pos? total)
      (/ diff (double total))
      0.0)))

;;; ============================================================================
;;; Part 7: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 16.2 Tests ===\n")

  ;; Test 1: Flow key creation
  (println "Test 1: Flow Key Creation")
  (let [fk (create-flow-key [192 168 1 1] [10 0 0 1] 12345 80 6)]
    (assert (= [192 168 1 1] (:src-ip fk)) "src ip")
    (assert (= 12345 (:src-port fk)) "src port")
    (assert (= 6 (:protocol fk)) "protocol"))
  (println "  Flow key created correctly")
  (println "  PASSED\n")

  ;; Test 2: Flow key normalization
  (println "Test 2: Flow Key Normalization")
  (let [fk1 (create-flow-key [192 168 1 1] [10 0 0 1] 12345 80 6)
        fk2 (create-flow-key [10 0 0 1] [192 168 1 1] 80 12345 6)
        norm1 (normalize-flow-key fk1)
        norm2 (normalize-flow-key fk2)]
    (assert (= norm1 norm2) "normalized keys match"))
  (println "  Flow key normalization works correctly")
  (println "  PASSED\n")

  ;; Test 3: Flow stats creation
  (println "Test 3: Flow Stats Creation")
  (let [stats (create-flow-stats 100 1000000 true)]
    (assert (= 1 (:packets stats)) "packets")
    (assert (= 100 (:bytes stats)) "bytes")
    (assert (= 1 (:fwd-packets stats)) "fwd packets")
    (assert (= 0 (:rev-packets stats)) "rev packets"))
  (println "  Flow stats created correctly")
  (println "  PASSED\n")

  ;; Test 4: Flow stats update
  (println "Test 4: Flow Stats Update")
  (let [stats (-> (create-flow-stats 100 1000000 true)
                  (update-flow-stats 200 2000000 false nil)
                  (update-flow-stats 150 3000000 true 0x02))]  ; SYN
    (assert (= 3 (:packets stats)) "total packets")
    (assert (= 450 (:bytes stats)) "total bytes")
    (assert (= 2 (:fwd-packets stats)) "fwd packets")
    (assert (= 1 (:rev-packets stats)) "rev packets")
    (assert (= 1 (:syn-count stats)) "syn count"))
  (println "  Flow stats updated correctly")
  (println "  PASSED\n")

  ;; Test 5: Flow recording
  (println "Test 5: Flow Recording")
  (clear-flows!)
  (let [fk (create-flow-key [192 168 1 1] [10 0 0 1] 12345 80 6)]
    (record-packet! fk 100 1000000)
    (record-packet! fk 200 2000000)
    (let [stats (get-flow fk)]
      (assert (some? stats) "flow exists")
      (assert (= 2 (:packets stats)) "packet count")))
  (println "  Flow recording works correctly")
  (println "  PASSED\n")

  ;; Test 6: Bidirectional flow
  (println "Test 6: Bidirectional Flow")
  (clear-flows!)
  (let [fk-fwd (create-flow-key [192 168 1 1] [10 0 0 1] 12345 80 6)
        fk-rev (create-flow-key [10 0 0 1] [192 168 1 1] 80 12345 6)]
    (record-packet! fk-fwd 100 1000000)
    (record-packet! fk-rev 200 2000000)
    (assert (= 1 (flow-count)) "single flow")
    (let [stats (get-flow fk-fwd)]
      (assert (= 2 (:packets stats)) "combined packets")
      (assert (bidirectional-flow? stats) "bidirectional")))
  (println "  Bidirectional flow tracking works correctly")
  (println "  PASSED\n")

  ;; Test 7: Flow aging
  (println "Test 7: Flow Aging")
  (clear-flows!)
  (swap! flow-config assoc :idle-timeout-ns 2000000)
  (let [fk1 (create-flow-key [1 1 1 1] [2 2 2 2] 100 200 6)
        fk2 (create-flow-key [3 3 3 3] [4 4 4 4] 300 400 6)]
    (record-packet! fk1 100 1000000)  ; old flow
    (record-packet! fk2 100 4000000)  ; recent flow
    (assert (= 2 (flow-count)) "two flows")
    (age-flows! 5000000)  ; flow1 age=4000000 > 2000000, flow2 age=1000000 < 2000000
    (assert (= 1 (flow-count)) "one flow after aging"))
  (swap! flow-config assoc :idle-timeout-ns (* 30 1e9))
  (println "  Flow aging works correctly")
  (println "  PASSED\n")

  ;; Test 8: Top flows analysis
  (println "Test 8: Top Flows Analysis")
  (clear-flows!)
  (let [fk1 (create-flow-key [1 1 1 1] [2 2 2 2] 100 80 6)
        fk2 (create-flow-key [3 3 3 3] [4 4 4 4] 100 443 6)]
    (dotimes [_ 10] (record-packet! fk1 100 1000000))
    (dotimes [_ 5] (record-packet! fk2 200 1000000))
    (let [[top-flow _] (first (top-flows-by-packets 1))]
      (assert (= (:dst-port top-flow) 80) "top by packets is port 80"))
    (let [[top-flow _] (first (top-flows-by-bytes 1))]
      (assert (= (:dst-port top-flow) 80) "top by bytes is port 80")))
  (println "  Top flows analysis works correctly")
  (println "  PASSED\n")

  ;; Test 9: TCP flow state
  (println "Test 9: TCP Flow State")
  (let [stats-syn (->FlowStats 10 1000 0 0 5 500 5 500 0x02 1 0 0)
        stats-fin (->FlowStats 20 2000 0 0 10 1000 10 1000 0x03 1 1 0)
        stats-rst (->FlowStats 5 500 0 0 3 300 2 200 0x04 0 0 1)]
    (assert (= :established (tcp-flow-state stats-syn)) "established state")
    (assert (= :closed (tcp-flow-state stats-fin)) "closed state")
    (assert (= :reset (tcp-flow-state stats-rst)) "reset state"))
  (println "  TCP flow state detection works correctly")
  (println "  PASSED\n")

  ;; Test 10: Flow asymmetry
  (println "Test 10: Flow Asymmetry")
  (let [symmetric (->FlowStats 100 10000 0 0 50 5000 50 5000 0 0 0 0)
        one-way (->FlowStats 100 10000 0 0 100 10000 0 0 0 0 0 0)]
    (assert (< (flow-asymmetry symmetric) 0.1) "symmetric flow")
    (assert (> (flow-asymmetry one-way) 0.9) "one-way flow"))
  (println "  Flow asymmetry calculation works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 8: Demo
;;; ============================================================================

(defn run-demo
  "Run demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 16.2: Flow Tracking")
  (println (str/join "" (repeat 60 "=")) "\n")

  (clear-flows!)

  ;; Simulate network traffic
  (println "=== Simulating Network Traffic ===\n")

  (let [flows [{:src [192 168 1 100] :dst [93 184 216 34] :sp 45678 :dp 80 :proto 6 :pkts 150 :bytes 15000}
               {:src [192 168 1 100] :dst [8 8 8 8] :sp 54321 :dp 53 :proto 17 :pkts 20 :bytes 2000}
               {:src [192 168 1 101] :dst [172 217 14 78] :sp 43210 :dp 443 :proto 6 :pkts 500 :bytes 250000}
               {:src [10 0 0 5] :dst [10 0 0 1] :sp 22222 :dp 22 :proto 6 :pkts 1000 :bytes 100000}
               {:src [192 168 1 102] :dst [151 101 1 69] :sp 12345 :dp 443 :proto 6 :pkts 75 :bytes 8000}]]

    (doseq [f flows]
      (let [fk (create-flow-key (:src f) (:dst f) (:sp f) (:dp f) (:proto f))
            fk-rev (create-flow-key (:dst f) (:src f) (:dp f) (:sp f) (:proto f))]
        ;; Simulate bidirectional traffic
        (dotimes [i (:pkts f)]
          (let [is-fwd (< (rand) 0.6)
                key (if is-fwd fk fk-rev)
                size (+ 50 (rand-int 100))]
            (record-packet! key size (* i 1000000) :tcp-flags (when (zero? i) 0x02)))))))

  (println (format "Total flows tracked: %d" (flow-count)))
  (println)

  ;; Show traffic summary
  (let [summary (total-traffic)]
    (println "=== Traffic Summary ===")
    (println (format "  Flow count: %d" (:flow-count summary)))
    (println (format "  Total packets: %,d" (:total-packets summary)))
    (println (format "  Total bytes: %,d" (:total-bytes summary)))
    (println (format "  TCP flows: %d" (:tcp-flows summary)))
    (println (format "  UDP flows: %d" (:udp-flows summary)))
    (println))

  ;; Show top flows
  (println "=== Top 5 Flows by Bytes ===")
  (println (format "%-35s %10s %10s %8s" "FLOW" "PACKETS" "BYTES" "DIR"))
  (println (str/join "" (repeat 70 "-")))
  (doseq [[fk stats] (top-flows-by-bytes 5)]
    (println (format "%-35s %,10d %,10d %s"
                     (flow-key->string fk)
                     (:packets stats)
                     (:bytes stats)
                     (if (bidirectional-flow? stats) "BIDIR" "UNIDIR"))))
  (println)

  ;; Show flow states
  (println "=== TCP Flow States ===")
  (let [tcp-flows (filter #(= 6 (:protocol (first %))) (get-all-flows))
        states (frequencies (map (comp tcp-flow-state second) tcp-flows))]
    (doseq [[state count] states]
      (println (format "  %s: %d flows" (name state) count)))))

;;; ============================================================================
;;; Part 9: Main
;;; ============================================================================

(defn -main [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      (do
        (println "Usage: clojure -M -m lab-16-2-flow-tracking <command>")
        (println "Commands:")
        (println "  test  - Run tests")
        (println "  demo  - Run demonstration")))))
