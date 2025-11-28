# Lab 19.1: XDP Packet Filter

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Objective

Build a high-performance packet filter using XDP that can drop unwanted traffic at line rate before it reaches the kernel network stack.

## Prerequisites

- Completed Chapter 19 reading
- Understanding of network protocols
- Familiarity with XDP concepts

## Scenario

You're protecting a server from unwanted traffic. Using XDP, you'll implement a firewall that can filter millions of packets per second based on IP addresses, ports, and protocols.

---

## Part 1: Filter Rule Engine

### Step 1.1: Rule Definitions

```clojure
(ns lab-19-1.packet-filter
  (:require [clojure.string :as str])
  (:import [java.net InetAddress]))

;; Filter actions
(def XDP_ABORTED 0)
(def XDP_DROP 1)
(def XDP_PASS 2)
(def XDP_TX 3)
(def XDP_REDIRECT 4)

;; Rule structure
(defrecord FilterRule [id priority action match])

;; Match conditions
(defrecord MatchCondition [src-ip dst-ip src-port dst-port protocol])

(defn ip->int [ip-str]
  "Convert IP string to integer"
  (let [parts (str/split ip-str #"\.")
        bytes (map #(Integer/parseInt %) parts)]
    (reduce (fn [acc b] (+ (* acc 256) b)) 0 bytes)))

(defn int->ip [n]
  "Convert integer to IP string"
  (str/join "." [(bit-and (bit-shift-right n 24) 0xFF)
                 (bit-and (bit-shift-right n 16) 0xFF)
                 (bit-and (bit-shift-right n 8) 0xFF)
                 (bit-and n 0xFF)]))

(defn create-rule [id priority action match]
  (->FilterRule id priority action match))

(defn create-match [& {:keys [src-ip dst-ip src-port dst-port protocol]
                       :or {src-ip nil dst-ip nil src-port nil
                            dst-port nil protocol nil}}]
  (->MatchCondition
    (when src-ip (ip->int src-ip))
    (when dst-ip (ip->int dst-ip))
    src-port
    dst-port
    protocol))
```

### Step 1.2: Rule Storage

```clojure
;; Simulated BPF maps for rules
(def ip-blacklist (atom #{}))
(def port-blacklist (atom #{}))
(def protocol-blacklist (atom #{}))
(def rule-set (atom []))

(defn add-ip-blacklist! [ip]
  (swap! ip-blacklist conj (if (string? ip) (ip->int ip) ip))
  (println (format "Blacklisted IP: %s" ip)))

(defn remove-ip-blacklist! [ip]
  (swap! ip-blacklist disj (if (string? ip) (ip->int ip) ip)))

(defn add-port-blacklist! [port]
  (swap! port-blacklist conj port)
  (println (format "Blacklisted port: %d" port)))

(defn add-protocol-blacklist! [proto]
  (swap! protocol-blacklist conj proto)
  (println (format "Blacklisted protocol: %d" proto)))

(defn add-rule! [rule]
  (swap! rule-set conj rule)
  (swap! rule-set (fn [rules] (sort-by :priority > rules)))
  (println (format "Added rule: %s (priority %d)"
                   (:id rule) (:priority rule))))

(defn remove-rule! [rule-id]
  (swap! rule-set (fn [rules]
                    (vec (remove #(= rule-id (:id %)) rules)))))

(defn clear-rules! []
  (reset! ip-blacklist #{})
  (reset! port-blacklist #{})
  (reset! protocol-blacklist #{})
  (reset! rule-set []))
```

---

## Part 2: Packet Simulation

### Step 2.1: Packet Structure

```clojure
(defrecord Packet [src-ip dst-ip src-port dst-port protocol size timestamp])

(defn generate-packet []
  (->Packet
    (ip->int (str (rand-int 256) "." (rand-int 256) "."
                  (rand-int 256) "." (rand-int 256)))
    (ip->int (str (rand-int 256) "." (rand-int 256) "."
                  (rand-int 256) "." (rand-int 256)))
    (+ 1024 (rand-int 64000))
    (rand-nth [80 443 22 53 25 3306 8080 12345])
    (rand-nth [6 17 1])  ; TCP, UDP, ICMP
    (+ 64 (rand-int 1400))
    (System/currentTimeMillis)))

(defn generate-attack-packet [attack-type]
  (case attack-type
    :port-scan
    (->Packet (ip->int "10.0.0.100") (ip->int "192.168.1.1")
              (rand-int 65536) (rand-int 65536) 6 64
              (System/currentTimeMillis))

    :blacklisted-ip
    (->Packet (ip->int "192.168.1.100") (ip->int "10.0.0.1")
              12345 80 6 100
              (System/currentTimeMillis))

    :blocked-port
    (->Packet (ip->int "10.0.0.1") (ip->int "192.168.1.1")
              12345 23 6 100  ; Telnet port
              (System/currentTimeMillis))

    (generate-packet)))
```

### Step 2.2: Traffic Generator

```clojure
(defn generate-mixed-traffic [n attack-percent]
  "Generate mixed legitimate and attack traffic"
  (for [_ (range n)]
    (if (< (rand) attack-percent)
      (generate-attack-packet (rand-nth [:port-scan :blacklisted-ip :blocked-port]))
      (generate-packet))))
```

---

## Part 3: XDP Filter Implementation

### Step 3.1: Filter Logic

```clojure
(defn check-ip-blacklist [packet]
  "Check if source IP is blacklisted"
  (contains? @ip-blacklist (:src-ip packet)))

(defn check-port-blacklist [packet]
  "Check if destination port is blacklisted"
  (contains? @port-blacklist (:dst-port packet)))

(defn check-protocol-blacklist [packet]
  "Check if protocol is blacklisted"
  (contains? @protocol-blacklist (:protocol packet)))

(defn match-rule? [rule packet]
  "Check if packet matches rule conditions"
  (let [match (:match rule)]
    (and
      (or (nil? (:src-ip match))
          (= (:src-ip match) (:src-ip packet)))
      (or (nil? (:dst-ip match))
          (= (:dst-ip match) (:dst-ip packet)))
      (or (nil? (:src-port match))
          (= (:src-port match) (:src-port packet)))
      (or (nil? (:dst-port match))
          (= (:dst-port match) (:dst-port packet)))
      (or (nil? (:protocol match))
          (= (:protocol match) (:protocol packet))))))

(defn find-matching-rule [packet]
  "Find first matching rule (highest priority)"
  (first (filter #(match-rule? % packet) @rule-set)))
```

### Step 3.2: XDP Filter Function

```clojure
(def filter-stats (atom {:passed 0 :dropped 0 :aborted 0}))

(defn reset-stats! []
  (reset! filter-stats {:passed 0 :dropped 0 :aborted 0}))

(defn xdp-filter [packet]
  "Simulate XDP filter decision"
  (cond
    ;; Check blacklists first (fast path)
    (check-ip-blacklist packet)
    (do
      (swap! filter-stats update :dropped inc)
      {:action XDP_DROP :reason :ip-blacklist})

    (check-port-blacklist packet)
    (do
      (swap! filter-stats update :dropped inc)
      {:action XDP_DROP :reason :port-blacklist})

    (check-protocol-blacklist packet)
    (do
      (swap! filter-stats update :dropped inc)
      {:action XDP_DROP :reason :protocol-blacklist})

    ;; Check custom rules
    :else
    (if-let [rule (find-matching-rule packet)]
      (case (:action rule)
        :drop (do
                (swap! filter-stats update :dropped inc)
                {:action XDP_DROP :reason (:id rule)})
        :pass (do
                (swap! filter-stats update :passed inc)
                {:action XDP_PASS :reason (:id rule)})
        (do
          (swap! filter-stats update :passed inc)
          {:action XDP_PASS :reason :default}))
      (do
        (swap! filter-stats update :passed inc)
        {:action XDP_PASS :reason :no-match}))))
```

---

## Part 4: Filter Statistics

### Step 4.1: Statistics Collection

```clojure
(def detailed-stats (atom {:by-reason {} :by-protocol {}}))

(defn record-detailed-stats! [packet result]
  (let [reason (:reason result)
        protocol (:protocol packet)]
    (swap! detailed-stats update-in [:by-reason reason] (fnil inc 0))
    (swap! detailed-stats update-in [:by-protocol protocol (:action result)] (fnil inc 0))))

(defn xdp-filter-with-stats [packet]
  (let [result (xdp-filter packet)]
    (record-detailed-stats! packet result)
    result))
```

### Step 4.2: Statistics Display

```clojure
(defn display-filter-stats []
  (let [stats @filter-stats
        total (+ (:passed stats) (:dropped stats))]
    (println "\n=== XDP Filter Statistics ===\n")
    (println (format "Total packets:  %,d" total))
    (println (format "Passed:         %,d (%.1f%%)"
                     (:passed stats)
                     (if (pos? total) (* 100.0 (/ (:passed stats) total)) 0.0)))
    (println (format "Dropped:        %,d (%.1f%%)"
                     (:dropped stats)
                     (if (pos? total) (* 100.0 (/ (:dropped stats) total)) 0.0)))))

(defn display-detailed-stats []
  (let [stats @detailed-stats]
    (println "\n=== Drop Reasons ===\n")
    (doseq [[reason count] (sort-by val > (:by-reason stats))]
      (println (format "  %-20s %,d" (name reason) count)))

    (println "\n=== By Protocol ===\n")
    (println (format "%-10s %10s %10s" "Protocol" "Passed" "Dropped"))
    (println (apply str (repeat 35 "-")))
    (doseq [proto [6 17 1]]
      (let [passed (get-in stats [:by-protocol proto XDP_PASS] 0)
            dropped (get-in stats [:by-protocol proto XDP_DROP] 0)]
        (println (format "%-10s %10d %10d"
                         (case proto 6 "TCP" 17 "UDP" 1 "ICMP" "Other")
                         passed dropped))))))
```

---

## Part 5: Performance Testing

### Step 5.1: Throughput Measurement

```clojure
(defn measure-throughput [num-packets]
  (let [packets (generate-mixed-traffic num-packets 0.3)
        start-time (System/nanoTime)]

    (doseq [packet packets]
      (xdp-filter-with-stats packet))

    (let [elapsed-ns (- (System/nanoTime) start-time)
          elapsed-ms (/ elapsed-ns 1e6)
          pps (/ (* num-packets 1e9) elapsed-ns)]

      {:packets num-packets
       :elapsed-ms elapsed-ms
       :pps pps
       :mpps (/ pps 1e6)})))

(defn benchmark-filter []
  (println "\n=== Performance Benchmark ===\n")

  (doseq [count [10000 100000 1000000]]
    (reset-stats!)
    (reset! detailed-stats {:by-reason {} :by-protocol {}})

    (let [result (measure-throughput count)]
      (println (format "Packets: %,d" (:packets result)))
      (println (format "Time: %.2f ms" (:elapsed-ms result)))
      (println (format "Throughput: %.2f Mpps" (:mpps result)))
      (println))))
```

### Step 5.2: Latency Measurement

```clojure
(defn measure-latency [num-samples]
  (let [packets (generate-mixed-traffic num-samples 0.1)
        latencies (for [packet packets]
                    (let [start (System/nanoTime)
                          _ (xdp-filter packet)
                          end (System/nanoTime)]
                      (- end start)))]

    {:min (apply min latencies)
     :max (apply max latencies)
     :avg (/ (reduce + latencies) (count latencies))
     :p50 (nth (sort latencies) (/ (count latencies) 2))
     :p99 (nth (sort latencies) (int (* 0.99 (count latencies))))}))

(defn display-latency-stats []
  (let [stats (measure-latency 10000)]
    (println "\n=== Latency Statistics (nanoseconds) ===\n")
    (println (format "Min:  %,d ns" (:min stats)))
    (println (format "Max:  %,d ns" (:max stats)))
    (println (format "Avg:  %,.0f ns" (double (:avg stats))))
    (println (format "P50:  %,d ns" (:p50 stats)))
    (println (format "P99:  %,d ns" (:p99 stats)))))
```

---

## Part 6: Complete Demo

### Step 6.1: Full Demonstration

```clojure
(defn run-filter-demo []
  (println "\n" (apply str (repeat 60 "=")) "\n")
  (println "         XDP Packet Filter Demo")
  (println "\n" (apply str (repeat 60 "=")) "\n")

  ;; Initialize
  (clear-rules!)
  (reset-stats!)
  (reset! detailed-stats {:by-reason {} :by-protocol {}})

  ;; Setup blacklists
  (println "Setting up blacklists...")
  (add-ip-blacklist! "192.168.1.100")
  (add-ip-blacklist! "10.0.0.100")
  (add-port-blacklist! 23)   ; Telnet
  (add-port-blacklist! 135)  ; Windows RPC

  ;; Setup custom rules
  (println "\nSetting up rules...")
  (add-rule! (create-rule "block-scanner" 100 :drop
                          (create-match :src-ip "10.0.0.100")))
  (add-rule! (create-rule "allow-web" 50 :pass
                          (create-match :dst-port 80 :protocol 6)))
  (add-rule! (create-rule "allow-https" 50 :pass
                          (create-match :dst-port 443 :protocol 6)))

  ;; Process traffic
  (println "\nProcessing traffic...")
  (let [packets (generate-mixed-traffic 10000 0.2)]
    (doseq [packet packets]
      (xdp-filter-with-stats packet)))

  ;; Display results
  (display-filter-stats)
  (display-detailed-stats)

  ;; Performance
  (benchmark-filter)
  (display-latency-stats))
```

---

## Part 7: Exercises

### Exercise 1: Rate Limiting

Add per-IP rate limiting:

```clojure
(defn exercise-rate-limit []
  ;; TODO: Implement rate limiting
  ;; 1. Track packets per IP per second
  ;; 2. Drop if rate exceeds threshold
  ;; 3. Use token bucket or sliding window
  )
```

### Exercise 2: Geo-IP Filtering

Implement country-based filtering:

```clojure
(defn exercise-geo-filter []
  ;; TODO: Implement geo-IP filtering
  ;; 1. Create IP range to country mapping
  ;; 2. Block/allow by country code
  ;; 3. Handle IP range lookups efficiently
  )
```

### Exercise 3: Connection Tracking

Add stateful connection tracking:

```clojure
(defn exercise-conntrack []
  ;; TODO: Implement connection tracking
  ;; 1. Track TCP connection states
  ;; 2. Allow established connections
  ;; 3. Drop invalid packets
  )
```

---

## Part 8: Testing

```clojure
(defn test-ip-blacklist []
  (println "Testing IP blacklist...")
  (clear-rules!)
  (add-ip-blacklist! "192.168.1.100")

  (let [blocked-packet (->Packet (ip->int "192.168.1.100")
                                  (ip->int "10.0.0.1")
                                  12345 80 6 100 0)
        allowed-packet (->Packet (ip->int "192.168.1.101")
                                  (ip->int "10.0.0.1")
                                  12345 80 6 100 0)]

    (assert (= XDP_DROP (:action (xdp-filter blocked-packet)))
            "Should drop blacklisted IP")
    (assert (= XDP_PASS (:action (xdp-filter allowed-packet)))
            "Should pass non-blacklisted IP"))
  (println "IP blacklist tests passed!"))

(defn test-custom-rules []
  (println "Testing custom rules...")
  (clear-rules!)
  (add-rule! (create-rule "block-telnet" 100 :drop
                          (create-match :dst-port 23)))

  (let [telnet-packet (->Packet (ip->int "10.0.0.1")
                                 (ip->int "192.168.1.1")
                                 12345 23 6 100 0)
        ssh-packet (->Packet (ip->int "10.0.0.1")
                              (ip->int "192.168.1.1")
                              12345 22 6 100 0)]

    (assert (= XDP_DROP (:action (xdp-filter telnet-packet)))
            "Should drop telnet")
    (assert (= XDP_PASS (:action (xdp-filter ssh-packet)))
            "Should pass SSH"))
  (println "Custom rule tests passed!"))

(defn run-all-tests []
  (println "\nLab 19.1: XDP Packet Filter")
  (println "===========================\n")

  (test-ip-blacklist)
  (test-custom-rules)

  (run-filter-demo)

  (println "\n=== All Tests Complete ==="))
```

---

## Summary

In this lab you learned:
- Building a rule-based packet filter
- Implementing blacklists for IPs, ports, and protocols
- Measuring filter throughput and latency
- Statistics collection and reporting

## Next Steps

- Try Lab 19.2 to build an XDP load balancer
- Add more sophisticated matching patterns
- Implement stateful packet inspection
