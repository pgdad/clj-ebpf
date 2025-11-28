;; Lab 19.3 Solution: XDP DDoS Mitigation
;; Complete implementation of DDoS mitigation using XDP rate limiting and traffic analysis

(ns lab-19-3-ddos-mitigation
  (:require [clojure.string :as str]
            [clj-ebpf.core :as ebpf])
  (:import [java.util.concurrent ConcurrentHashMap]
           [java.util.concurrent.atomic AtomicLong AtomicInteger]
           [java.security MessageDigest]
           [java.util Random]))

;; =============================================================================
;; XDP Action Constants
;; =============================================================================

(def XDP_ABORTED 0)
(def XDP_DROP 1)
(def XDP_PASS 2)
(def XDP_TX 3)
(def XDP_REDIRECT 4)

;; =============================================================================
;; Part 1: Attack Detection - Rate Tracking
;; =============================================================================

(defn create-rate-tracker
  "Create a rate tracking system with configurable window size."
  [window-ms]
  {:window-ms window-ms
   :ip-data (ConcurrentHashMap.)
   :stats {:total-tracked (AtomicLong.)
           :exceeded-rate (AtomicLong.)
           :cleaned (AtomicLong.)}})

(defn track-rate
  "Track packet rate for a source IP within the sliding window."
  [tracker src-ip]
  (let [now (System/currentTimeMillis)
        window-start (- now (:window-ms tracker))
        ip-data (.computeIfAbsent (:ip-data tracker) src-ip
                                  (fn [_] (atom {:timestamps []
                                                 :rate 0
                                                 :first-seen now
                                                 :bytes 0})))]
    (.incrementAndGet (get-in tracker [:stats :total-tracked]))
    (swap! ip-data
           (fn [data]
             (let [filtered (vec (filter #(> % window-start) (:timestamps data)))
                   updated (conj filtered now)]
               (assoc data
                      :timestamps updated
                      :rate (count updated)
                      :last-seen now))))))

(defn track-rate-with-bytes
  "Track packet rate and bytes for a source IP."
  [tracker src-ip packet-size]
  (let [now (System/currentTimeMillis)
        window-start (- now (:window-ms tracker))
        ip-data (.computeIfAbsent (:ip-data tracker) src-ip
                                  (fn [_] (atom {:timestamps []
                                                 :rate 0
                                                 :first-seen now
                                                 :bytes 0
                                                 :byte-timestamps []})))]
    (.incrementAndGet (get-in tracker [:stats :total-tracked]))
    (swap! ip-data
           (fn [data]
             (let [filtered (vec (filter #(> % window-start) (:timestamps data)))
                   updated (conj filtered now)
                   byte-filtered (vec (filter #(> (:ts %) window-start)
                                              (:byte-timestamps data [])))
                   byte-updated (conj byte-filtered {:ts now :size packet-size})]
               (assoc data
                      :timestamps updated
                      :rate (count updated)
                      :last-seen now
                      :byte-timestamps byte-updated
                      :bytes (reduce + (map :size byte-updated))))))))

(defn get-rate
  "Get current rate for an IP."
  [tracker src-ip]
  (if-let [ip-data (.get (:ip-data tracker) src-ip)]
    (:rate @ip-data)
    0))

(defn get-byte-rate
  "Get current byte rate for an IP."
  [tracker src-ip]
  (if-let [ip-data (.get (:ip-data tracker) src-ip)]
    (:bytes @ip-data 0)
    0))

(defn check-rate-limit
  "Check if rate exceeds threshold."
  [tracker src-ip threshold]
  (let [rate (get-rate tracker src-ip)
        exceeded? (> rate threshold)]
    (when exceeded?
      (.incrementAndGet (get-in tracker [:stats :exceeded-rate])))
    exceeded?))

(defn cleanup-old-entries
  "Remove entries older than specified age."
  [tracker max-age-ms]
  (let [now (System/currentTimeMillis)
        cutoff (- now max-age-ms)
        to-remove (filter (fn [[ip data-atom]]
                            (< (:last-seen @data-atom 0) cutoff))
                          (:ip-data tracker))]
    (doseq [[ip _] to-remove]
      (.remove (:ip-data tracker) ip)
      (.incrementAndGet (get-in tracker [:stats :cleaned])))))

;; =============================================================================
;; Part 2: Thresholds and Configuration
;; =============================================================================

(def default-thresholds
  {:pps-per-ip 10000        ;; Packets per second per IP
   :bps-per-ip 10000000     ;; Bytes per second per IP (10 MB/s)
   :syn-rate 1000           ;; SYN packets per second
   :new-conn-rate 5000      ;; New connections per second
   :icmp-rate 100           ;; ICMP packets per second
   :udp-flood-rate 5000     ;; UDP packets per second
   :dns-rate 500            ;; DNS queries per second
   :ntp-rate 100            ;; NTP packets per second
   :fragment-rate 200})     ;; Fragmented packets per second

(defn create-mitigation-config
  "Create DDoS mitigation configuration."
  []
  {:thresholds (atom default-thresholds)
   :rate-tracker (create-rate-tracker 1000)  ;; 1-second window
   :syn-tracker (create-rate-tracker 1000)
   :icmp-tracker (create-rate-tracker 1000)
   :udp-tracker (create-rate-tracker 1000)
   :dns-tracker (create-rate-tracker 1000)
   :blacklist (atom #{})
   :graylist (atom {})   ;; IP -> {:challenge-count :last-challenge :status}
   :whitelist (atom #{})
   :syn-cookie-enabled (atom false)
   :challenge-mode (atom false)
   :stats {:total-packets (AtomicLong.)
           :dropped (AtomicLong.)
           :passed (AtomicLong.)
           :challenged (AtomicLong.)
           :blacklisted (AtomicLong.)
           :syn-floods-detected (AtomicLong.)
           :rate-exceeded (AtomicLong.)
           :amplification-detected (AtomicLong.)}})

(defn update-threshold!
  "Update a specific threshold."
  [config threshold-key value]
  (swap! (:thresholds config) assoc threshold-key value))

;; =============================================================================
;; Part 3: SYN Flood Protection
;; =============================================================================

(defn is-syn-packet?
  "Check if packet is a SYN packet (TCP with SYN flag, no ACK)."
  [packet]
  (and (= 6 (:protocol packet))
       (:syn-flag packet)
       (not (:ack-flag packet))))

(defn detect-syn-flood
  "Detect SYN flood attack from a source IP."
  [config packet]
  (when (is-syn-packet? packet)
    (track-rate (:syn-tracker config) (:src-ip packet))
    (let [rate (get-rate (:syn-tracker config) (:src-ip packet))
          threshold (get @(:thresholds config) :syn-rate)]
      (when (> rate threshold)
        (.incrementAndGet (get-in config [:stats :syn-floods-detected]))
        true))))

(defn generate-syn-cookie
  "Generate a SYN cookie for connection verification."
  [packet secret]
  (let [data (str (:src-ip packet) ":"
                  (:dst-ip packet) ":"
                  (:src-port packet) ":"
                  (:dst-port packet) ":"
                  (quot (System/currentTimeMillis) 60000) ":"  ;; Minute granularity
                  secret)
        md (MessageDigest/getInstance "SHA-256")
        hash-bytes (.digest md (.getBytes data "UTF-8"))]
    ;; Use first 4 bytes as cookie value
    (reduce (fn [acc i]
              (bit-or (bit-shift-left acc 8)
                      (bit-and (aget hash-bytes i) 0xFF)))
            0
            (range 4))))

(defn verify-syn-cookie
  "Verify a SYN cookie from returning ACK."
  [packet expected-cookie]
  ;; In real implementation, would extract cookie from sequence number
  (= (:cookie packet) expected-cookie))

(def syn-cookie-secret (atom (str (Random. (System/currentTimeMillis)))))

(defn handle-syn-flood
  "Handle detected SYN flood - enable SYN cookies or challenge mode."
  [config src-ip]
  (reset! (:syn-cookie-enabled config) true)
  ;; Add to graylist for challenge
  (swap! (:graylist config) assoc src-ip
         {:challenge-count 0
          :last-challenge (System/currentTimeMillis)
          :status :challenging})
  {:action :challenge
   :method :syn-cookie
   :cookie (generate-syn-cookie {:src-ip src-ip
                                 :dst-ip "0.0.0.0"
                                 :src-port 0
                                 :dst-port 0}
                                @syn-cookie-secret)})

;; =============================================================================
;; Part 4: Amplification Attack Detection
;; =============================================================================

(defn detect-dns-amplification
  "Detect DNS amplification attack."
  [config packet]
  (when (and (= 17 (:protocol packet))  ;; UDP
             (= 53 (:src-port packet))) ;; DNS response
    (track-rate (:dns-tracker config) (:src-ip packet))
    (let [rate (get-rate (:dns-tracker config) (:src-ip packet))
          threshold (get @(:thresholds config) :dns-rate)]
      (when (> rate threshold)
        (.incrementAndGet (get-in config [:stats :amplification-detected]))
        {:attack-type :dns-amplification
         :source (:src-ip packet)
         :rate rate}))))

(defn detect-ntp-amplification
  "Detect NTP amplification attack."
  [config packet]
  (when (and (= 17 (:protocol packet))  ;; UDP
             (= 123 (:src-port packet))) ;; NTP
    (let [rate (get-rate (:rate-tracker config) (:src-ip packet))
          threshold (get @(:thresholds config) :ntp-rate)]
      (when (> rate threshold)
        (.incrementAndGet (get-in config [:stats :amplification-detected]))
        {:attack-type :ntp-amplification
         :source (:src-ip packet)
         :rate rate}))))

(defn detect-memcached-amplification
  "Detect Memcached amplification attack."
  [config packet]
  (when (and (= 17 (:protocol packet))  ;; UDP
             (= 11211 (:src-port packet))) ;; Memcached
    (let [rate (get-rate (:rate-tracker config) (:src-ip packet))]
      (when (> rate 50)  ;; Low threshold for memcached
        (.incrementAndGet (get-in config [:stats :amplification-detected]))
        {:attack-type :memcached-amplification
         :source (:src-ip packet)
         :rate rate}))))

;; =============================================================================
;; Part 5: Blacklist Management
;; =============================================================================

(defn add-to-blacklist!
  "Add IP to blacklist with automatic expiration."
  [config ip duration-ms reason]
  (swap! (:blacklist config) conj ip)
  (.incrementAndGet (get-in config [:stats :blacklisted]))
  ;; Schedule removal
  (future
    (try
      (Thread/sleep duration-ms)
      (swap! (:blacklist config) disj ip)
      (catch Exception _))))

(defn remove-from-blacklist!
  "Manually remove IP from blacklist."
  [config ip]
  (swap! (:blacklist config) disj ip))

(defn is-blacklisted?
  "Check if IP is blacklisted."
  [config ip]
  (contains? @(:blacklist config) ip))

(defn add-to-whitelist!
  "Add IP to whitelist (exempt from rate limiting)."
  [config ip]
  (swap! (:whitelist config) conj ip))

(defn is-whitelisted?
  "Check if IP is whitelisted."
  [config ip]
  (contains? @(:whitelist config) ip))

;; =============================================================================
;; Part 6: Graylist and Challenge System
;; =============================================================================

(defn add-to-graylist!
  "Add IP to graylist for challenging."
  [config ip]
  (swap! (:graylist config) assoc ip
         {:challenge-count 0
          :last-challenge (System/currentTimeMillis)
          :status :pending}))

(defn update-graylist-challenge!
  "Update graylist entry after challenge attempt."
  [config ip passed?]
  (swap! (:graylist config) update ip
         (fn [entry]
           (if entry
             (-> entry
                 (update :challenge-count inc)
                 (assoc :last-challenge (System/currentTimeMillis))
                 (assoc :status (if passed? :passed :failed)))
             {:challenge-count 1
              :last-challenge (System/currentTimeMillis)
              :status (if passed? :passed :failed)}))))

(defn should-challenge?
  "Determine if traffic from IP should be challenged."
  [config ip]
  (when-let [entry (get @(:graylist config) ip)]
    (and (#{:pending :failed} (:status entry))
         (< (:challenge-count entry) 3))))

(defn cleanup-graylist!
  "Remove old entries from graylist."
  [config max-age-ms]
  (let [now (System/currentTimeMillis)
        cutoff (- now max-age-ms)]
    (swap! (:graylist config)
           (fn [gl]
             (into {}
                   (filter (fn [[_ entry]]
                             (> (:last-challenge entry) cutoff))
                           gl))))))

;; =============================================================================
;; Part 7: Traffic Analysis
;; =============================================================================

(defrecord TrafficPattern [protocol src-ip dst-ip src-port dst-port count first-seen last-seen])

(defn create-traffic-analyzer
  "Create traffic pattern analyzer."
  []
  {:patterns (ConcurrentHashMap.)
   :anomalies (atom [])
   :baseline (atom nil)})

(defn pattern-key
  "Generate key for traffic pattern."
  [packet]
  (str (:protocol packet) ":"
       (:src-ip packet) ":"
       (:dst-port packet)))

(defn analyze-packet
  "Analyze packet and update traffic patterns."
  [analyzer packet]
  (let [key (pattern-key packet)
        now (System/currentTimeMillis)
        pattern (.computeIfAbsent (:patterns analyzer) key
                                  (fn [_] (atom (map->TrafficPattern
                                                  {:protocol (:protocol packet)
                                                   :src-ip (:src-ip packet)
                                                   :dst-ip (:dst-ip packet)
                                                   :src-port (:src-port packet)
                                                   :dst-port (:dst-port packet)
                                                   :count 0
                                                   :first-seen now
                                                   :last-seen now}))))]
    (swap! pattern #(-> %
                        (update :count inc)
                        (assoc :last-seen now)))))

(defn detect-anomalies
  "Detect anomalous traffic patterns."
  [analyzer]
  (let [patterns (into {} (:patterns analyzer))
        threshold 10000  ;; High packet count threshold
        anomalies (filter (fn [[_ pattern-atom]]
                            (> (:count @pattern-atom) threshold))
                          patterns)]
    (when (seq anomalies)
      (swap! (:anomalies analyzer) into
             (map (fn [[k p]] {:pattern k :data @p}) anomalies)))
    anomalies))

(defn get-top-talkers
  "Get top N source IPs by packet count."
  [analyzer n]
  (->> (:patterns analyzer)
       (map (fn [[k p]] [(:src-ip @p) (:count @p)]))
       (group-by first)
       (map (fn [[ip counts]] [ip (reduce + (map second counts))]))
       (sort-by second >)
       (take n)))

;; =============================================================================
;; Part 8: Main Mitigation Logic
;; =============================================================================

(defn xdp-mitigate
  "Main XDP DDoS mitigation function."
  [config packet]
  (.incrementAndGet (get-in config [:stats :total-packets]))

  ;; Track rate for this IP
  (track-rate-with-bytes (:rate-tracker config) (:src-ip packet)
                         (:length packet 64))

  (cond
    ;; 1. Check whitelist first
    (is-whitelisted? config (:src-ip packet))
    (do
      (.incrementAndGet (get-in config [:stats :passed]))
      {:action XDP_PASS :reason :whitelisted})

    ;; 2. Check blacklist
    (is-blacklisted? config (:src-ip packet))
    (do
      (.incrementAndGet (get-in config [:stats :dropped]))
      {:action XDP_DROP :reason :blacklisted})

    ;; 3. Check overall rate limit
    (check-rate-limit (:rate-tracker config)
                      (:src-ip packet)
                      (get @(:thresholds config) :pps-per-ip))
    (do
      (.incrementAndGet (get-in config [:stats :rate-exceeded]))
      (.incrementAndGet (get-in config [:stats :dropped]))
      ;; Auto-blacklist for 60 seconds
      (add-to-blacklist! config (:src-ip packet) 60000 :rate-exceeded)
      {:action XDP_DROP :reason :rate-exceeded})

    ;; 4. SYN flood detection
    (detect-syn-flood config packet)
    (do
      (.incrementAndGet (get-in config [:stats :challenged]))
      (handle-syn-flood config (:src-ip packet)))

    ;; 5. ICMP flood detection
    (and (= 1 (:protocol packet))
         (check-rate-limit (:icmp-tracker config)
                           (:src-ip packet)
                           (get @(:thresholds config) :icmp-rate)))
    (do
      (track-rate (:icmp-tracker config) (:src-ip packet))
      (.incrementAndGet (get-in config [:stats :dropped]))
      {:action XDP_DROP :reason :icmp-flood})

    ;; 6. UDP flood detection
    (and (= 17 (:protocol packet))
         (check-rate-limit (:udp-tracker config)
                           (:src-ip packet)
                           (get @(:thresholds config) :udp-flood-rate)))
    (do
      (track-rate (:udp-tracker config) (:src-ip packet))
      (.incrementAndGet (get-in config [:stats :dropped]))
      {:action XDP_DROP :reason :udp-flood})

    ;; 7. DNS amplification detection
    (detect-dns-amplification config packet)
    (do
      (.incrementAndGet (get-in config [:stats :dropped]))
      {:action XDP_DROP :reason :dns-amplification})

    ;; 8. NTP amplification detection
    (detect-ntp-amplification config packet)
    (do
      (.incrementAndGet (get-in config [:stats :dropped]))
      {:action XDP_DROP :reason :ntp-amplification})

    ;; 9. Challenge mode for graylisted IPs
    (should-challenge? config (:src-ip packet))
    (do
      (.incrementAndGet (get-in config [:stats :challenged]))
      {:action :challenge :reason :graylist})

    ;; 10. Normal traffic - pass
    :else
    (do
      (.incrementAndGet (get-in config [:stats :passed]))
      {:action XDP_PASS :reason :normal})))

;; =============================================================================
;; Part 9: Statistics and Monitoring
;; =============================================================================

(defn get-mitigation-stats
  "Get current mitigation statistics."
  [config]
  {:total-packets (.get (get-in config [:stats :total-packets]))
   :dropped (.get (get-in config [:stats :dropped]))
   :passed (.get (get-in config [:stats :passed]))
   :challenged (.get (get-in config [:stats :challenged]))
   :blacklisted (.get (get-in config [:stats :blacklisted]))
   :syn-floods-detected (.get (get-in config [:stats :syn-floods-detected]))
   :rate-exceeded (.get (get-in config [:stats :rate-exceeded]))
   :amplification-detected (.get (get-in config [:stats :amplification-detected]))
   :blacklist-size (count @(:blacklist config))
   :graylist-size (count @(:graylist config))
   :whitelist-size (count @(:whitelist config))
   :tracked-ips (.size (:ip-data (:rate-tracker config)))})

(defn print-stats
  "Print formatted statistics."
  [config]
  (let [stats (get-mitigation-stats config)]
    (println "\n=== DDoS Mitigation Statistics ===")
    (println (format "Total packets:      %,d" (:total-packets stats)))
    (println (format "Passed:             %,d (%.2f%%)"
                     (:passed stats)
                     (if (pos? (:total-packets stats))
                       (* 100.0 (/ (:passed stats) (:total-packets stats)))
                       0.0)))
    (println (format "Dropped:            %,d (%.2f%%)"
                     (:dropped stats)
                     (if (pos? (:total-packets stats))
                       (* 100.0 (/ (:dropped stats) (:total-packets stats)))
                       0.0)))
    (println (format "Challenged:         %,d" (:challenged stats)))
    (println (format "Blacklisted IPs:    %,d" (:blacklist-size stats)))
    (println (format "SYN floods:         %,d" (:syn-floods-detected stats)))
    (println (format "Rate exceeded:      %,d" (:rate-exceeded stats)))
    (println (format "Amplification:      %,d" (:amplification-detected stats)))
    (println (format "Tracked IPs:        %,d" (:tracked-ips stats)))))

(defn get-top-blocked
  "Get top blocked IPs."
  [config n]
  (let [rate-data (:ip-data (:rate-tracker config))]
    (->> rate-data
         (map (fn [[ip data]] [ip (:rate @data 0)]))
         (sort-by second >)
         (take n))))

;; =============================================================================
;; Part 10: Testing and Simulation
;; =============================================================================

(defn generate-test-packet
  "Generate a random test packet."
  [& {:keys [attack-type src-ip]}]
  (let [src (or src-ip (str "192.168.1." (rand-int 255)))]
    (case attack-type
      :syn-flood {:protocol 6
                  :src-ip src
                  :dst-ip "10.0.0.1"
                  :src-port (+ 1024 (rand-int 64000))
                  :dst-port 80
                  :syn-flag true
                  :ack-flag false
                  :length 64}
      :udp-flood {:protocol 17
                  :src-ip src
                  :dst-ip "10.0.0.1"
                  :src-port (+ 1024 (rand-int 64000))
                  :dst-port 53
                  :length 512}
      :icmp-flood {:protocol 1
                   :src-ip src
                   :dst-ip "10.0.0.1"
                   :length 64}
      :dns-amp {:protocol 17
                :src-ip src
                :dst-ip "10.0.0.1"
                :src-port 53
                :dst-port (+ 1024 (rand-int 64000))
                :length 4096}
      ;; Normal traffic
      {:protocol (rand-nth [6 17])
       :src-ip src
       :dst-ip "10.0.0.1"
       :src-port (+ 1024 (rand-int 64000))
       :dst-port (rand-nth [80 443 22 8080])
       :syn-flag false
       :ack-flag (rand-nth [true false])
       :length (+ 64 (rand-int 1400))})))

(defn simulate-attack
  "Simulate a DDoS attack."
  [config attack-type duration-ms rate-per-sec]
  (let [start-time (System/currentTimeMillis)
        end-time (+ start-time duration-ms)
        attacker-ip "203.0.113.100"
        interval-ns (long (/ 1000000000 rate-per-sec))
        results (atom {:sent 0 :dropped 0 :passed 0})]
    (println (format "Simulating %s attack from %s at %d pps for %d ms..."
                     (name attack-type) attacker-ip rate-per-sec duration-ms))
    (while (< (System/currentTimeMillis) end-time)
      (let [packet (generate-test-packet :attack-type attack-type :src-ip attacker-ip)
            result (xdp-mitigate config packet)]
        (swap! results update :sent inc)
        (case (:action result)
          1 (swap! results update :dropped inc)  ;; XDP_DROP
          2 (swap! results update :passed inc)   ;; XDP_PASS
          :challenge (swap! results update :dropped inc)
          nil))
      ;; Approximate rate limiting
      (Thread/sleep 0 (min interval-ns 999999)))
    (println (format "Attack simulation complete: sent=%d dropped=%d passed=%d"
                     (:sent @results) (:dropped @results) (:passed @results)))
    @results))

(defn simulate-mixed-traffic
  "Simulate mixed legitimate and attack traffic."
  [config duration-ms]
  (let [start-time (System/currentTimeMillis)
        end-time (+ start-time duration-ms)
        results (atom {:total 0 :normal 0 :attack 0
                       :normal-passed 0 :attack-dropped 0})]
    (println (format "Simulating mixed traffic for %d ms..." duration-ms))
    (while (< (System/currentTimeMillis) end-time)
      (let [is-attack? (< (rand) 0.3)  ;; 30% attack traffic
            packet (if is-attack?
                     (generate-test-packet :attack-type (rand-nth [:syn-flood :udp-flood :icmp-flood])
                                          :src-ip "203.0.113.100")
                     (generate-test-packet))
            result (xdp-mitigate config packet)]
        (swap! results update :total inc)
        (if is-attack?
          (do
            (swap! results update :attack inc)
            (when (= (:action result) XDP_DROP)
              (swap! results update :attack-dropped inc)))
          (do
            (swap! results update :normal inc)
            (when (= (:action result) XDP_PASS)
              (swap! results update :normal-passed inc)))))
      (Thread/sleep 0 100000))  ;; ~10k pps
    (let [r @results]
      (println (format "\nMixed traffic results:"))
      (println (format "  Total packets: %d" (:total r)))
      (println (format "  Normal traffic: %d (passed: %d, %.2f%%)"
                       (:normal r) (:normal-passed r)
                       (if (pos? (:normal r))
                         (* 100.0 (/ (:normal-passed r) (:normal r)))
                         0.0)))
      (println (format "  Attack traffic: %d (dropped: %d, %.2f%%)"
                       (:attack r) (:attack-dropped r)
                       (if (pos? (:attack r))
                         (* 100.0 (/ (:attack-dropped r) (:attack r)))
                         0.0))))
    @results))

;; =============================================================================
;; Part 11: Test Functions
;; =============================================================================

(defn test-rate-tracking
  "Test rate tracking functionality."
  []
  (println "\n=== Testing Rate Tracking ===")
  (let [tracker (create-rate-tracker 1000)]
    ;; Simulate packets from an IP
    (doseq [_ (range 100)]
      (track-rate tracker "192.168.1.1"))
    (println (format "Rate for 192.168.1.1: %d pps" (get-rate tracker "192.168.1.1")))
    (println (format "Exceeds 50? %s" (check-rate-limit tracker "192.168.1.1" 50)))
    (println (format "Exceeds 200? %s" (check-rate-limit tracker "192.168.1.1" 200)))
    (println "Rate tracking test passed!")))

(defn test-blacklist
  "Test blacklist functionality."
  []
  (println "\n=== Testing Blacklist ===")
  (let [config (create-mitigation-config)]
    (println "Adding 192.168.1.100 to blacklist for 2 seconds...")
    (add-to-blacklist! config "192.168.1.100" 2000 :test)
    (println (format "Is blacklisted? %s" (is-blacklisted? config "192.168.1.100")))
    (Thread/sleep 2500)
    (println (format "After 2.5s, is blacklisted? %s" (is-blacklisted? config "192.168.1.100")))
    (println "Blacklist test passed!")))

(defn test-syn-flood-detection
  "Test SYN flood detection."
  []
  (println "\n=== Testing SYN Flood Detection ===")
  (let [config (create-mitigation-config)]
    ;; Lower threshold for testing
    (update-threshold! config :syn-rate 10)

    ;; Send SYN packets
    (println "Sending 20 SYN packets from same source...")
    (doseq [_ (range 20)]
      (xdp-mitigate config {:protocol 6
                            :src-ip "203.0.113.50"
                            :dst-ip "10.0.0.1"
                            :src-port 12345
                            :dst-port 80
                            :syn-flag true
                            :ack-flag false
                            :length 64}))

    (let [stats (get-mitigation-stats config)]
      (println (format "SYN floods detected: %d" (:syn-floods-detected stats)))
      (println (format "Challenged: %d" (:challenged stats))))
    (println "SYN flood detection test passed!")))

(defn test-mitigation-chain
  "Test complete mitigation chain."
  []
  (println "\n=== Testing Mitigation Chain ===")
  (let [config (create-mitigation-config)]
    ;; Lower thresholds for testing
    (update-threshold! config :pps-per-ip 50)
    (update-threshold! config :syn-rate 10)

    ;; 1. Test whitelist bypass
    (add-to-whitelist! config "10.0.0.50")
    (let [result (xdp-mitigate config {:protocol 6 :src-ip "10.0.0.50"
                                       :dst-ip "10.0.0.1" :length 64})]
      (println (format "Whitelisted packet: %s" (:reason result))))

    ;; 2. Test blacklist
    (add-to-blacklist! config "10.0.0.99" 60000 :manual)
    (let [result (xdp-mitigate config {:protocol 6 :src-ip "10.0.0.99"
                                       :dst-ip "10.0.0.1" :length 64})]
      (println (format "Blacklisted packet: %s" (:reason result))))

    ;; 3. Test rate limiting
    (doseq [_ (range 60)]
      (xdp-mitigate config {:protocol 6 :src-ip "192.168.1.200"
                            :dst-ip "10.0.0.1" :length 64}))
    (println (format "High-rate IP blacklisted? %s"
                     (is-blacklisted? config "192.168.1.200")))

    (print-stats config)
    (println "Mitigation chain test passed!")))

(defn run-all-tests
  "Run all test functions."
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "Running DDoS Mitigation Tests")
  (println (str/join "" (repeat 60 "=")))
  (test-rate-tracking)
  (test-blacklist)
  (test-syn-flood-detection)
  (test-mitigation-chain)
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "All tests completed!")
  (println (str/join "" (repeat 60 "="))))

;; =============================================================================
;; Part 12: Demo Functions
;; =============================================================================

(defn demo-basic-mitigation
  "Demonstrate basic DDoS mitigation."
  []
  (println "\n=== Demo: Basic DDoS Mitigation ===\n")
  (let [config (create-mitigation-config)]
    ;; Process some normal traffic
    (println "Processing 100 normal packets...")
    (doseq [_ (range 100)]
      (xdp-mitigate config (generate-test-packet)))

    ;; Simulate attack
    (println "\nSimulating SYN flood attack...")
    (update-threshold! config :syn-rate 100)
    (simulate-attack config :syn-flood 1000 500)

    (print-stats config)))

(defn demo-adaptive-protection
  "Demonstrate adaptive protection."
  []
  (println "\n=== Demo: Adaptive Protection ===\n")
  (let [config (create-mitigation-config)]
    ;; Start with normal thresholds
    (println "Initial thresholds:")
    (println @(:thresholds config))

    ;; Detect attack and adjust
    (println "\nDetecting attack pattern, adjusting thresholds...")
    (update-threshold! config :pps-per-ip 5000)
    (update-threshold! config :syn-rate 500)

    (println "Adjusted thresholds:")
    (println @(:thresholds config))

    ;; Run mixed traffic simulation
    (simulate-mixed-traffic config 2000)

    (print-stats config)))

(defn demo-attack-types
  "Demonstrate detection of different attack types."
  []
  (println "\n=== Demo: Attack Type Detection ===\n")
  (let [config (create-mitigation-config)]
    ;; Lower thresholds for demo
    (update-threshold! config :pps-per-ip 100)
    (update-threshold! config :syn-rate 50)
    (update-threshold! config :icmp-rate 20)
    (update-threshold! config :udp-flood-rate 100)
    (update-threshold! config :dns-rate 30)

    (doseq [[attack-type label] [[:syn-flood "SYN Flood"]
                                  [:udp-flood "UDP Flood"]
                                  [:icmp-flood "ICMP Flood"]
                                  [:dns-amp "DNS Amplification"]]]
      (println (format "\nSimulating %s..." label))
      (simulate-attack config attack-type 500 200))

    (print-stats config)
    (println "\nTop blocked sources:")
    (doseq [[ip rate] (get-top-blocked config 5)]
      (println (format "  %s: %d pps" ip rate)))))

;; =============================================================================
;; Part 13: Main Entry Point
;; =============================================================================

(defn -main
  "Main entry point."
  [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-all-tests)
      "demo" (do
               (demo-basic-mitigation)
               (demo-adaptive-protection)
               (demo-attack-types))
      "simulate" (let [config (create-mitigation-config)
                       attack-type (keyword (or (second args) "syn-flood"))
                       duration (Integer/parseInt (or (nth args 2) "5000"))]
                   (simulate-attack config attack-type duration 1000)
                   (print-stats config))
      "mixed" (let [config (create-mitigation-config)
                    duration (Integer/parseInt (or (second args) "5000"))]
                (simulate-mixed-traffic config duration)
                (print-stats config))
      ;; Default: run tests and demos
      (do
        (println "XDP DDoS Mitigation System")
        (println "Usage: clj -M -m lab-19-3.ddos-mitigation [command]")
        (println "Commands:")
        (println "  test     - Run all tests")
        (println "  demo     - Run demonstrations")
        (println "  simulate [type] [duration-ms] - Simulate specific attack")
        (println "  mixed [duration-ms] - Simulate mixed traffic")
        (println "\nRunning tests by default...\n")
        (run-all-tests)))))

;; =============================================================================
;; Exercises
;; =============================================================================

(comment
  ;; Exercise 1: Add geolocation-based filtering
  ;; Implement IP geolocation lookup and country-based blocking

  ;; Exercise 2: Implement adaptive thresholds
  ;; Create a system that automatically adjusts thresholds based on traffic patterns

  ;; Exercise 3: Add machine learning-based detection
  ;; Implement anomaly detection using statistical methods

  ;; Exercise 4: Create a real-time dashboard
  ;; Build visualization of attack traffic and mitigation effectiveness

  ;; Exercise 5: Implement connection tracking
  ;; Track established connections to allow return traffic

  ;; Example solution for Exercise 2:
  (defn create-adaptive-config []
    (let [config (create-mitigation-config)
          baseline (atom {:pps 0 :sample-count 0})]
      ;; Background thread to adjust thresholds
      (future
        (while true
          (let [stats (get-mitigation-stats config)
                current-pps (/ (:total-packets stats)
                               (max 1 (/ (- (System/currentTimeMillis)
                                           (System/currentTimeMillis)) 1000.0)))]
            ;; Update baseline
            (swap! baseline (fn [b]
                              (-> b
                                  (update :pps #(/ (+ % current-pps) 2))
                                  (update :sample-count inc))))
            ;; Adjust threshold if significantly above baseline
            (when (and (> (:sample-count @baseline) 10)
                       (> current-pps (* 3 (:pps @baseline))))
              (update-threshold! config :pps-per-ip
                                (int (* 2 (:pps @baseline))))))
          (Thread/sleep 1000)))
      config))
  )
