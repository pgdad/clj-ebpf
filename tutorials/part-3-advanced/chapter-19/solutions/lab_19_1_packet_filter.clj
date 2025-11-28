;; Lab 19.1 Solution: XDP Packet Filter
;; Build a high-performance packet filter using XDP
;;
;; Learning Goals:
;; - Build a rule-based packet filter
;; - Implement blacklists for IPs, ports, and protocols
;; - Measure filter throughput and latency
;; - Statistics collection and reporting

(ns lab-19-1-packet-filter
  (:require [clojure.string :as str])
  (:import [java.util.concurrent.atomic AtomicLong]
           [java.time Instant]))

;; ============================================================================
;; XDP Action Constants
;; ============================================================================

(def XDP_ABORTED 0)
(def XDP_DROP 1)
(def XDP_PASS 2)
(def XDP_TX 3)
(def XDP_REDIRECT 4)

(defn action-name [action]
  (case action
    0 "ABORTED"
    1 "DROP"
    2 "PASS"
    3 "TX"
    4 "REDIRECT"
    "UNKNOWN"))

;; ============================================================================
;; IP Address Utilities
;; ============================================================================

(defn ip->int
  "Convert IP string to integer"
  [ip-str]
  (let [parts (str/split ip-str #"\.")
        bytes (map #(Integer/parseInt %) parts)]
    (reduce (fn [acc b] (+ (* acc 256) b)) 0 bytes)))

(defn int->ip
  "Convert integer to IP string"
  [n]
  (str/join "." [(bit-and (bit-shift-right n 24) 0xFF)
                 (bit-and (bit-shift-right n 16) 0xFF)
                 (bit-and (bit-shift-right n 8) 0xFF)
                 (bit-and n 0xFF)]))

(defn ip-in-cidr?
  "Check if IP is in CIDR range"
  [ip-int cidr-str]
  (let [[ip-part mask-part] (str/split cidr-str #"/")
        cidr-ip (ip->int ip-part)
        mask-bits (Integer/parseInt mask-part)
        mask (bit-shift-left -1 (- 32 mask-bits))]
    (= (bit-and ip-int mask)
       (bit-and cidr-ip mask))))

;; ============================================================================
;; Packet Structure
;; ============================================================================

(defrecord Packet [src-ip dst-ip src-port dst-port protocol size timestamp flags])

(defn generate-packet
  "Generate a random packet"
  []
  (->Packet
    (ip->int (str (rand-int 256) "." (rand-int 256) "."
                  (rand-int 256) "." (rand-int 256)))
    (ip->int (str (rand-int 256) "." (rand-int 256) "."
                  (rand-int 256) "." (rand-int 256)))
    (+ 1024 (rand-int 64000))
    (rand-nth [80 443 22 53 25 3306 8080 12345])
    (rand-nth [6 17 1])  ; TCP=6, UDP=17, ICMP=1
    (+ 64 (rand-int 1400))
    (System/nanoTime)
    {:syn false :ack false :fin false :rst false}))

(defn generate-attack-packet
  "Generate attack packets for testing"
  [attack-type]
  (case attack-type
    :port-scan
    (->Packet (ip->int "10.0.0.100")
              (ip->int "192.168.1.1")
              (rand-int 65536)
              (rand-int 65536)
              6 64 (System/nanoTime)
              {:syn true :ack false :fin false :rst false})

    :blacklisted-ip
    (->Packet (ip->int "192.168.1.100")
              (ip->int "10.0.0.1")
              12345 80 6 100 (System/nanoTime)
              {:syn false :ack false :fin false :rst false})

    :blocked-port
    (->Packet (ip->int "10.0.0.1")
              (ip->int "192.168.1.1")
              12345 23 6 100 (System/nanoTime)
              {:syn false :ack false :fin false :rst false})

    :syn-flood
    (->Packet (ip->int (str (rand-int 256) "." (rand-int 256) "."
                            (rand-int 256) "." (rand-int 256)))
              (ip->int "192.168.1.1")
              (rand-int 65536) 80 6 64 (System/nanoTime)
              {:syn true :ack false :fin false :rst false})

    (generate-packet)))

(defn generate-mixed-traffic
  "Generate mixed legitimate and attack traffic"
  [n attack-percent]
  (for [_ (range n)]
    (if (< (rand) attack-percent)
      (generate-attack-packet (rand-nth [:port-scan :blacklisted-ip :blocked-port :syn-flood]))
      (generate-packet))))

;; ============================================================================
;; Filter Rule System
;; ============================================================================

(defrecord FilterRule [id priority action match description])
(defrecord MatchCondition [src-ip src-cidr dst-ip dst-cidr
                           src-port dst-port protocol flags])

(defn create-match
  "Create a match condition"
  [& {:keys [src-ip src-cidr dst-ip dst-cidr src-port dst-port protocol flags]
       :or {src-ip nil src-cidr nil dst-ip nil dst-cidr nil
            src-port nil dst-port nil protocol nil flags nil}}]
  (->MatchCondition
    (when src-ip (if (string? src-ip) (ip->int src-ip) src-ip))
    src-cidr
    (when dst-ip (if (string? dst-ip) (ip->int dst-ip) dst-ip))
    dst-cidr
    src-port dst-port protocol flags))

(defn create-rule
  "Create a filter rule"
  [id priority action match & {:keys [description] :or {description ""}}]
  (->FilterRule id priority action match description))

;; ============================================================================
;; Blacklists and Rule Storage
;; ============================================================================

(def ip-blacklist (atom #{}))
(def ip-whitelist (atom #{}))
(def port-blacklist (atom #{}))
(def protocol-blacklist (atom #{}))
(def cidr-blacklist (atom #{}))
(def rule-set (atom []))

(defn add-ip-blacklist!
  "Add IP to blacklist"
  [ip]
  (let [ip-int (if (string? ip) (ip->int ip) ip)]
    (swap! ip-blacklist conj ip-int)
    (println (format "Blacklisted IP: %s" (if (string? ip) ip (int->ip ip-int))))))

(defn add-ip-whitelist!
  "Add IP to whitelist"
  [ip]
  (let [ip-int (if (string? ip) (ip->int ip) ip)]
    (swap! ip-whitelist conj ip-int)
    (println (format "Whitelisted IP: %s" (if (string? ip) ip (int->ip ip-int))))))

(defn remove-ip-blacklist!
  "Remove IP from blacklist"
  [ip]
  (swap! ip-blacklist disj (if (string? ip) (ip->int ip) ip)))

(defn add-port-blacklist!
  "Add port to blacklist"
  [port]
  (swap! port-blacklist conj port)
  (println (format "Blacklisted port: %d" port)))

(defn add-protocol-blacklist!
  "Add protocol to blacklist"
  [proto]
  (swap! protocol-blacklist conj proto)
  (println (format "Blacklisted protocol: %d" proto)))

(defn add-cidr-blacklist!
  "Add CIDR range to blacklist"
  [cidr]
  (swap! cidr-blacklist conj cidr)
  (println (format "Blacklisted CIDR: %s" cidr)))

(defn add-rule!
  "Add a filter rule"
  [rule]
  (swap! rule-set conj rule)
  (swap! rule-set (fn [rules] (vec (sort-by :priority > rules))))
  (println (format "Added rule: %s (priority %d) - %s"
                   (:id rule) (:priority rule) (:description rule))))

(defn remove-rule!
  "Remove a rule by ID"
  [rule-id]
  (swap! rule-set (fn [rules]
                    (vec (remove #(= rule-id (:id %)) rules)))))

(defn clear-rules!
  "Clear all rules and blacklists"
  []
  (reset! ip-blacklist #{})
  (reset! ip-whitelist #{})
  (reset! port-blacklist #{})
  (reset! protocol-blacklist #{})
  (reset! cidr-blacklist #{})
  (reset! rule-set []))

;; ============================================================================
;; Statistics
;; ============================================================================

(def filter-stats
  (atom {:passed (AtomicLong. 0)
         :dropped (AtomicLong. 0)
         :aborted (AtomicLong. 0)}))

(def detailed-stats
  (atom {:by-reason {}
         :by-protocol {}
         :by-port {}}))

(defn reset-stats!
  "Reset all statistics"
  []
  (.set ^AtomicLong (:passed @filter-stats) 0)
  (.set ^AtomicLong (:dropped @filter-stats) 0)
  (.set ^AtomicLong (:aborted @filter-stats) 0)
  (reset! detailed-stats {:by-reason {} :by-protocol {} :by-port {}}))

(defn record-stats!
  "Record detailed statistics"
  [packet action reason]
  (case action
    1 (.incrementAndGet ^AtomicLong (:dropped @filter-stats))
    2 (.incrementAndGet ^AtomicLong (:passed @filter-stats))
    0 (.incrementAndGet ^AtomicLong (:aborted @filter-stats))
    nil)

  (swap! detailed-stats update-in [:by-reason reason] (fnil inc 0))
  (swap! detailed-stats update-in [:by-protocol (:protocol packet) action] (fnil inc 0))
  (swap! detailed-stats update-in [:by-port (:dst-port packet) action] (fnil inc 0)))

;; ============================================================================
;; Filter Logic
;; ============================================================================

(defn check-ip-whitelist
  "Check if source IP is whitelisted"
  [packet]
  (contains? @ip-whitelist (:src-ip packet)))

(defn check-ip-blacklist
  "Check if source IP is blacklisted"
  [packet]
  (contains? @ip-blacklist (:src-ip packet)))

(defn check-cidr-blacklist
  "Check if source IP is in any blacklisted CIDR range"
  [packet]
  (some #(ip-in-cidr? (:src-ip packet) %) @cidr-blacklist))

(defn check-port-blacklist
  "Check if destination port is blacklisted"
  [packet]
  (contains? @port-blacklist (:dst-port packet)))

(defn check-protocol-blacklist
  "Check if protocol is blacklisted"
  [packet]
  (contains? @protocol-blacklist (:protocol packet)))

(defn match-rule?
  "Check if packet matches rule conditions"
  [rule packet]
  (let [m (:match rule)]
    (and
      ;; Source IP match
      (or (nil? (:src-ip m))
          (= (:src-ip m) (:src-ip packet)))
      ;; Source CIDR match
      (or (nil? (:src-cidr m))
          (ip-in-cidr? (:src-ip packet) (:src-cidr m)))
      ;; Destination IP match
      (or (nil? (:dst-ip m))
          (= (:dst-ip m) (:dst-ip packet)))
      ;; Destination CIDR match
      (or (nil? (:dst-cidr m))
          (ip-in-cidr? (:dst-ip packet) (:dst-cidr m)))
      ;; Source port match
      (or (nil? (:src-port m))
          (= (:src-port m) (:src-port packet)))
      ;; Destination port match
      (or (nil? (:dst-port m))
          (= (:dst-port m) (:dst-port packet)))
      ;; Protocol match
      (or (nil? (:protocol m))
          (= (:protocol m) (:protocol packet)))
      ;; Flags match
      (or (nil? (:flags m))
          (every? (fn [[k v]] (= v (get-in packet [:flags k]))) (:flags m))))))

(defn find-matching-rule
  "Find first matching rule (highest priority)"
  [packet]
  (first (filter #(match-rule? % packet) @rule-set)))

;; ============================================================================
;; XDP Filter Function
;; ============================================================================

(defn xdp-filter
  "Main XDP filter function - returns {:action ACTION :reason REASON}"
  [packet]
  (cond
    ;; Whitelist check (fast pass)
    (check-ip-whitelist packet)
    (do
      (record-stats! packet XDP_PASS :whitelist)
      {:action XDP_PASS :reason :whitelist})

    ;; IP blacklist check
    (check-ip-blacklist packet)
    (do
      (record-stats! packet XDP_DROP :ip-blacklist)
      {:action XDP_DROP :reason :ip-blacklist})

    ;; CIDR blacklist check
    (check-cidr-blacklist packet)
    (do
      (record-stats! packet XDP_DROP :cidr-blacklist)
      {:action XDP_DROP :reason :cidr-blacklist})

    ;; Port blacklist check
    (check-port-blacklist packet)
    (do
      (record-stats! packet XDP_DROP :port-blacklist)
      {:action XDP_DROP :reason :port-blacklist})

    ;; Protocol blacklist check
    (check-protocol-blacklist packet)
    (do
      (record-stats! packet XDP_DROP :protocol-blacklist)
      {:action XDP_DROP :reason :protocol-blacklist})

    ;; Custom rules check
    :else
    (if-let [rule (find-matching-rule packet)]
      (case (:action rule)
        :drop
        (do
          (record-stats! packet XDP_DROP (:id rule))
          {:action XDP_DROP :reason (:id rule)})

        :pass
        (do
          (record-stats! packet XDP_PASS (:id rule))
          {:action XDP_PASS :reason (:id rule)})

        ;; Default for rule
        (do
          (record-stats! packet XDP_PASS :rule-default)
          {:action XDP_PASS :reason :rule-default}))

      ;; No matching rule - default pass
      (do
        (record-stats! packet XDP_PASS :no-match)
        {:action XDP_PASS :reason :no-match}))))

;; ============================================================================
;; Statistics Display
;; ============================================================================

(defn display-filter-stats
  "Display basic filter statistics"
  []
  (let [passed (.get ^AtomicLong (:passed @filter-stats))
        dropped (.get ^AtomicLong (:dropped @filter-stats))
        total (+ passed dropped)]
    (println "\n=== XDP Filter Statistics ===\n")
    (println (format "Total packets:  %,d" total))
    (println (format "Passed:         %,d (%.1f%%)"
                     passed
                     (if (pos? total) (* 100.0 (/ passed total)) 0.0)))
    (println (format "Dropped:        %,d (%.1f%%)"
                     dropped
                     (if (pos? total) (* 100.0 (/ dropped total)) 0.0)))))

(defn display-detailed-stats
  "Display detailed statistics"
  []
  (let [stats @detailed-stats]
    (println "\n=== Drop Reasons ===\n")
    (println (format "%-25s %10s" "Reason" "Count"))
    (println (apply str (repeat 38 "-")))
    (doseq [[reason count] (sort-by val > (:by-reason stats))]
      (println (format "%-25s %,10d" (name reason) count)))

    (println "\n=== By Protocol ===\n")
    (println (format "%-10s %12s %12s" "Protocol" "Passed" "Dropped"))
    (println (apply str (repeat 38 "-")))
    (doseq [proto [6 17 1]]
      (let [passed (get-in stats [:by-protocol proto XDP_PASS] 0)
            dropped (get-in stats [:by-protocol proto XDP_DROP] 0)]
        (println (format "%-10s %,12d %,12d"
                         (case proto 6 "TCP" 17 "UDP" 1 "ICMP" "Other")
                         passed dropped))))

    (println "\n=== Top Ports ===\n")
    (println (format "%-10s %12s %12s" "Port" "Passed" "Dropped"))
    (println (apply str (repeat 38 "-")))
    (let [port-stats (:by-port stats)
          top-ports (->> port-stats
                         (map (fn [[port actions]]
                                [port (+ (get actions XDP_PASS 0)
                                         (get actions XDP_DROP 0))]))
                         (sort-by second >)
                         (take 10))]
      (doseq [[port _] top-ports]
        (let [passed (get-in port-stats [port XDP_PASS] 0)
              dropped (get-in port-stats [port XDP_DROP] 0)]
          (println (format "%-10d %,12d %,12d" port passed dropped)))))))

;; ============================================================================
;; Performance Testing
;; ============================================================================

(defn measure-throughput
  "Measure filter throughput"
  [num-packets attack-percent]
  (let [packets (generate-mixed-traffic num-packets attack-percent)
        start-time (System/nanoTime)]

    (doseq [packet packets]
      (xdp-filter packet))

    (let [elapsed-ns (- (System/nanoTime) start-time)
          elapsed-ms (/ elapsed-ns 1e6)
          pps (/ (* num-packets 1e9) elapsed-ns)]
      {:packets num-packets
       :elapsed-ms elapsed-ms
       :pps pps
       :mpps (/ pps 1e6)})))

(defn measure-latency
  "Measure filter latency"
  [num-samples]
  (let [packets (generate-mixed-traffic num-samples 0.1)
        latencies (for [packet packets]
                    (let [start (System/nanoTime)
                          _ (xdp-filter packet)
                          end (System/nanoTime)]
                      (- end start)))
        sorted-latencies (sort latencies)
        n (count sorted-latencies)]
    {:min (first sorted-latencies)
     :max (last sorted-latencies)
     :avg (/ (reduce + latencies) n)
     :p50 (nth sorted-latencies (/ n 2))
     :p90 (nth sorted-latencies (int (* 0.90 n)))
     :p99 (nth sorted-latencies (int (* 0.99 n)))}))

(defn benchmark-filter
  "Run throughput benchmark"
  []
  (println "\n=== Performance Benchmark ===\n")

  (doseq [count [10000 100000 1000000]]
    (reset-stats!)
    (let [result (measure-throughput count 0.3)]
      (println (format "Packets: %,d" (:packets result)))
      (println (format "Time: %.2f ms" (:elapsed-ms result)))
      (println (format "Throughput: %.2f Mpps\n" (:mpps result))))))

(defn display-latency-stats
  "Display latency statistics"
  []
  (let [stats (measure-latency 10000)]
    (println "\n=== Latency Statistics ===\n")
    (println (format "Min:  %,d ns (%.2f us)" (:min stats) (/ (:min stats) 1000.0)))
    (println (format "Max:  %,d ns (%.2f us)" (:max stats) (/ (:max stats) 1000.0)))
    (println (format "Avg:  %,.0f ns (%.2f us)" (double (:avg stats)) (/ (:avg stats) 1000.0)))
    (println (format "P50:  %,d ns (%.2f us)" (:p50 stats) (/ (:p50 stats) 1000.0)))
    (println (format "P90:  %,d ns (%.2f us)" (:p90 stats) (/ (:p90 stats) 1000.0)))
    (println (format "P99:  %,d ns (%.2f us)" (:p99 stats) (/ (:p99 stats) 1000.0)))))

;; ============================================================================
;; Exercises
;; ============================================================================

(defn exercise-rate-limiting
  "Exercise 1: Per-IP rate limiting"
  []
  (println "\n=== Exercise: Rate Limiting ===\n")

  (let [rate-counters (atom {})
        window-start (atom (System/currentTimeMillis))
        rate-limit 100  ; packets per second per IP
        dropped-rate (atom 0)]

    (defn check-rate-limit! [src-ip]
      (let [now (System/currentTimeMillis)]
        ;; Reset counters every second
        (when (> (- now @window-start) 1000)
          (reset! window-start now)
          (reset! rate-counters {}))

        (let [current (get @rate-counters src-ip 0)]
          (if (>= current rate-limit)
            (do (swap! dropped-rate inc) false)
            (do (swap! rate-counters update src-ip (fnil inc 0)) true)))))

    ;; Generate traffic from few IPs (to trigger rate limiting)
    (println "Generating traffic from limited IPs...")
    (dotimes [_ 500]
      (let [src-ip (ip->int (str "10.0.0." (rand-int 5)))
            packet (assoc (generate-packet) :src-ip src-ip)]
        (if (check-rate-limit! src-ip)
          (xdp-filter packet)
          nil)))

    (println (format "Rate limited packets: %d" @dropped-rate))
    (display-filter-stats)))

(defn exercise-geo-filter
  "Exercise 2: Geo-IP filtering"
  []
  (println "\n=== Exercise: Geo-IP Filtering ===\n")

  ;; Simplified geo-IP database (CIDR -> country)
  (def geo-db
    {"1.0.0.0/8"   "AU"
     "2.0.0.0/8"   "EU"
     "5.0.0.0/8"   "EU"
     "14.0.0.0/8"  "JP"
     "23.0.0.0/8"  "US"
     "31.0.0.0/8"  "EU"
     "41.0.0.0/8"  "ZA"
     "58.0.0.0/8"  "CN"
     "101.0.0.0/8" "CN"
     "103.0.0.0/8" "IN"})

  (def blocked-countries #{"CN"})

  (defn lookup-country [ip-int]
    (first (for [[cidr country] geo-db
                 :when (ip-in-cidr? ip-int cidr)]
             country)))

  (defn geo-filter [packet]
    (let [country (lookup-country (:src-ip packet))]
      (if (contains? blocked-countries country)
        {:action XDP_DROP :reason :geo-blocked :country country}
        {:action XDP_PASS})))

  ;; Test with various IPs
  (println "Testing geo filtering...")
  (let [test-ips ["58.1.2.3" "23.1.2.3" "103.1.2.3" "192.168.1.1"]]
    (doseq [ip test-ips]
      (let [packet (assoc (generate-packet) :src-ip (ip->int ip))
            result (geo-filter packet)]
        (println (format "  %s -> %s (country: %s)"
                         ip
                         (action-name (:action result))
                         (or (:country result)
                             (lookup-country (ip->int ip))
                             "Unknown")))))))

(defn exercise-conntrack
  "Exercise 3: Connection tracking"
  []
  (println "\n=== Exercise: Connection Tracking ===\n")

  (def connections (atom {}))

  (defn flow-key [packet]
    [(:src-ip packet) (:dst-ip packet)
     (:src-port packet) (:dst-port packet)
     (:protocol packet)])

  (defn reverse-flow-key [packet]
    [(:dst-ip packet) (:src-ip packet)
     (:dst-port packet) (:src-port packet)
     (:protocol packet)])

  (defn conntrack-filter [packet]
    (let [fwd-key (flow-key packet)
          rev-key (reverse-flow-key packet)
          flags (:flags packet)]

      (cond
        ;; Existing connection (forward)
        (contains? @connections fwd-key)
        (do
          (swap! connections update fwd-key assoc :last-seen (System/currentTimeMillis))
          {:action XDP_PASS :reason :established})

        ;; Existing connection (reverse - reply)
        (contains? @connections rev-key)
        (do
          (swap! connections update rev-key assoc :last-seen (System/currentTimeMillis))
          {:action XDP_PASS :reason :established-reply})

        ;; New connection (SYN)
        (and (= 6 (:protocol packet)) (:syn flags) (not (:ack flags)))
        (do
          (swap! connections assoc fwd-key {:state :syn-sent
                                            :created (System/currentTimeMillis)
                                            :last-seen (System/currentTimeMillis)})
          {:action XDP_PASS :reason :new-connection})

        ;; Invalid packet (no connection, not SYN)
        (= 6 (:protocol packet))
        {:action XDP_DROP :reason :invalid-state}

        ;; Non-TCP traffic
        :else
        {:action XDP_PASS :reason :non-tcp})))

  ;; Test connection tracking
  (println "Testing connection tracking...")

  ;; New SYN
  (let [syn-packet (assoc (generate-packet) :flags {:syn true :ack false})]
    (println (format "  SYN packet: %s" (:reason (conntrack-filter syn-packet)))))

  ;; Reply on existing connection
  (let [reply-packet (assoc (generate-packet) :flags {:syn false :ack true})]
    (println (format "  Reply packet (no conn): %s" (:reason (conntrack-filter reply-packet)))))

  (println (format "\nActive connections: %d" (count @connections))))

;; ============================================================================
;; Test Functions
;; ============================================================================

(defn test-ip-blacklist []
  (println "Testing IP blacklist...")
  (clear-rules!)
  (reset-stats!)
  (add-ip-blacklist! "192.168.1.100")

  (let [blocked-packet (->Packet (ip->int "192.168.1.100")
                                  (ip->int "10.0.0.1")
                                  12345 80 6 100 0 {})
        allowed-packet (->Packet (ip->int "192.168.1.101")
                                  (ip->int "10.0.0.1")
                                  12345 80 6 100 0 {})]

    (assert (= XDP_DROP (:action (xdp-filter blocked-packet)))
            "Should drop blacklisted IP")
    (assert (= XDP_PASS (:action (xdp-filter allowed-packet)))
            "Should pass non-blacklisted IP"))
  (println "IP blacklist tests passed!"))

(defn test-port-blacklist []
  (println "Testing port blacklist...")
  (clear-rules!)
  (reset-stats!)
  (add-port-blacklist! 23)

  (let [telnet-packet (->Packet (ip->int "10.0.0.1")
                                 (ip->int "192.168.1.1")
                                 12345 23 6 100 0 {})
        ssh-packet (->Packet (ip->int "10.0.0.1")
                              (ip->int "192.168.1.1")
                              12345 22 6 100 0 {})]

    (assert (= XDP_DROP (:action (xdp-filter telnet-packet)))
            "Should drop blocked port")
    (assert (= XDP_PASS (:action (xdp-filter ssh-packet)))
            "Should pass allowed port"))
  (println "Port blacklist tests passed!"))

(defn test-custom-rules []
  (println "Testing custom rules...")
  (clear-rules!)
  (reset-stats!)

  (add-rule! (create-rule "block-scanner" 100 :drop
                          (create-match :src-ip "10.0.0.100")
                          :description "Block known scanner"))

  (let [scanner-packet (->Packet (ip->int "10.0.0.100")
                                  (ip->int "192.168.1.1")
                                  12345 80 6 100 0 {})
        normal-packet (->Packet (ip->int "10.0.0.1")
                                 (ip->int "192.168.1.1")
                                 12345 80 6 100 0 {})]

    (assert (= XDP_DROP (:action (xdp-filter scanner-packet)))
            "Should drop matching rule")
    (assert (= XDP_PASS (:action (xdp-filter normal-packet)))
            "Should pass non-matching"))
  (println "Custom rule tests passed!"))

(defn run-demo []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "         XDP Packet Filter Demo")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  ;; Initialize
  (clear-rules!)
  (reset-stats!)

  ;; Setup blacklists
  (println "Setting up blacklists...")
  (add-ip-blacklist! "192.168.1.100")
  (add-ip-blacklist! "10.0.0.100")
  (add-cidr-blacklist! "172.16.0.0/12")
  (add-port-blacklist! 23)   ; Telnet
  (add-port-blacklist! 135)  ; Windows RPC
  (add-port-blacklist! 139)  ; NetBIOS
  (add-port-blacklist! 445)  ; SMB

  ;; Setup whitelist
  (add-ip-whitelist! "127.0.0.1")

  ;; Setup custom rules
  (println "\nSetting up rules...")
  (add-rule! (create-rule "allow-dns" 90 :pass
                          (create-match :dst-port 53 :protocol 17)
                          :description "Allow DNS"))
  (add-rule! (create-rule "allow-http" 80 :pass
                          (create-match :dst-port 80 :protocol 6)
                          :description "Allow HTTP"))
  (add-rule! (create-rule "allow-https" 80 :pass
                          (create-match :dst-port 443 :protocol 6)
                          :description "Allow HTTPS"))

  ;; Process traffic
  (println "\nProcessing 10,000 packets (20% attack traffic)...")
  (let [packets (generate-mixed-traffic 10000 0.2)]
    (doseq [packet packets]
      (xdp-filter packet)))

  ;; Display results
  (display-filter-stats)
  (display-detailed-stats)

  ;; Performance
  (benchmark-filter)
  (display-latency-stats))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the XDP packet filter lab"
  [& args]
  (println "Lab 19.1: XDP Packet Filter")
  (println "============================\n")

  (let [command (first args)]
    (case command
      "test"
      (do
        (test-ip-blacklist)
        (test-port-blacklist)
        (test-custom-rules)
        (println "\nAll tests passed!"))

      "demo"
      (run-demo)

      "exercise1"
      (exercise-rate-limiting)

      "exercise2"
      (exercise-geo-filter)

      "exercise3"
      (exercise-conntrack)

      ;; Default: run all
      (do
        (test-ip-blacklist)
        (test-port-blacklist)
        (test-custom-rules)
        (run-demo)
        (exercise-rate-limiting)
        (exercise-geo-filter)
        (exercise-conntrack)

        (println "\n=== Key Takeaways ===")
        (println "1. XDP enables high-performance packet filtering at line rate")
        (println "2. Blacklists provide fast O(1) lookups for known bad actors")
        (println "3. Custom rules enable flexible policy enforcement")
        (println "4. Statistics help monitor filter effectiveness")
        (println "5. Rate limiting and conntrack add stateful filtering")))))

;; Run with: clj -M -m lab-19-1-packet-filter
