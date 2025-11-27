(ns lab-7-2-ddos-mitigation
  "Lab 7.2: XDP DDoS Mitigation

   This solution demonstrates:
   - Rate limiting with token bucket algorithm
   - SYN flood detection and mitigation
   - Per-IP packet rate tracking
   - Connection state tracking
   - Automated blocklist management

   Run with: sudo clojure -M -m lab-7-2-ddos-mitigation
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]
           [java.net InetAddress]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; XDP Return Codes
(def XDP_DROP    1)
(def XDP_PASS    2)

;; Protocol numbers
(def IPPROTO_TCP  6)
(def IPPROTO_UDP  17)
(def IPPROTO_ICMP 1)

;; TCP Flags
(def TH_FIN  0x01)
(def TH_SYN  0x02)
(def TH_RST  0x04)
(def TH_PUSH 0x08)
(def TH_ACK  0x10)
(def TH_URG  0x20)

;; Rate limiting configuration
(def RATE_LIMIT_PPS 1000)        ; Packets per second limit per IP
(def SYN_RATE_LIMIT 100)         ; SYN packets per second limit per IP
(def BLOCK_THRESHOLD 5)          ; Number of violations before blocking
(def BLOCK_DURATION_SEC 60)      ; How long to block an IP

;; Map sizes
(def MAX_TRACKED_IPS 100000)
(def MAX_BLOCKED_IPS 10000)

;;; ============================================================================
;;; Part 2: Utility Functions
;;; ============================================================================

(defn ip-string->int
  "Convert IP address string to 32-bit integer.
   Returns an unchecked int that may be negative for IPs >= 128.x.x.x"
  [ip-str]
  (let [addr (InetAddress/getByName ip-str)
        bytes (.getAddress addr)]
    (unchecked-int
      (bit-or (bit-shift-left (bit-and (aget bytes 0) 0xFF) 24)
              (bit-shift-left (bit-and (aget bytes 1) 0xFF) 16)
              (bit-shift-left (bit-and (aget bytes 2) 0xFF) 8)
              (bit-and (aget bytes 3) 0xFF)))))

(defn int->ip-string
  "Convert 32-bit integer to IP address string"
  [ip-int]
  (format "%d.%d.%d.%d"
          (bit-and (bit-shift-right ip-int 24) 0xFF)
          (bit-and (bit-shift-right ip-int 16) 0xFF)
          (bit-and (bit-shift-right ip-int 8) 0xFF)
          (bit-and ip-int 0xFF)))

(defn format-rate [rate]
  "Format rate as human-readable string"
  (cond
    (< rate 1000) (format "%.0f pps" rate)
    (< rate 1000000) (format "%.1f Kpps" (/ rate 1000.0))
    :else (format "%.1f Mpps" (/ rate 1000000.0))))

(defn tcp-flags->str
  "Convert TCP flags byte to string representation"
  [flags]
  (str/join ""
            [(when (pos? (bit-and flags TH_SYN)) "S")
             (when (pos? (bit-and flags TH_ACK)) "A")
             (when (pos? (bit-and flags TH_FIN)) "F")
             (when (pos? (bit-and flags TH_RST)) "R")
             (when (pos? (bit-and flags TH_PUSH)) "P")
             (when (pos? (bit-and flags TH_URG)) "U")]))

;;; ============================================================================
;;; Part 3: BPF Maps
;;; ============================================================================

(defn create-rate-limit-map
  "Hash map: source IP -> rate limit state
   Value structure (16 bytes):
   - tokens: 8 bytes (current token count)
   - last_update: 8 bytes (timestamp in ns)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4              ; u32 IP
                   :value-size 16           ; tokens + timestamp
                   :max-entries MAX_TRACKED_IPS
                   :map-name "rate_limit"}))

(defn create-syn-count-map
  "Hash map: source IP -> SYN count per second
   Value structure (16 bytes):
   - syn_count: 8 bytes
   - second_start: 8 bytes (timestamp)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 16
                   :max-entries MAX_TRACKED_IPS
                   :map-name "syn_count"}))

(defn create-blocked-ips-map
  "Hash map: blocked IP -> unblock timestamp"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries MAX_BLOCKED_IPS
                   :map-name "blocked_ips"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-violation-count-map
  "Hash map: source IP -> violation count"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries MAX_TRACKED_IPS
                   :map-name "violations"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-stats-map
  "Array map for global statistics:
   [0] = total_packets
   [1] = passed_packets
   [2] = dropped_rate_limit
   [3] = dropped_syn_flood
   [4] = dropped_blocked
   [5] = syn_packets
   [6] = active_connections"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 10
                   :map-name "ddos_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: XDP BPF Program
;;; ============================================================================

(defn create-ddos-mitigation-program
  "Create XDP program for DDoS mitigation.

   This simplified program demonstrates:
   1. Packet counting
   2. Basic rate limiting structure

   A full implementation would:
   - Parse IP headers to get source IP
   - Implement token bucket rate limiting
   - Track SYN packets for flood detection
   - Check against blocklist

   XDP context (xdp_md) uses 32-bit fields for data/data_end!"
  [stats-fd blocked-fd]
  (bpf/assemble
    [;; Load packet pointers from XDP context (32-bit loads!)
     (bpf/ldx :w :r2 :r1 0)         ; 0: r2 = ctx->data (32-bit)
     (bpf/ldx :w :r3 :r1 4)         ; 1: r3 = ctx->data_end (32-bit)

     ;; Bounds check for Ethernet header (14 bytes)
     (bpf/mov-reg :r4 :r2)          ; 2: r4 = data
     (bpf/add :r4 14)               ; 3: r4 += 14
     (bpf/jmp-reg :jle :r4 :r3 2)   ; 4: if r4 <= data_end, continue

     ;; Drop path (bounds check failed)
     (bpf/mov :r0 XDP_DROP)         ; 5: return XDP_DROP
     (bpf/exit-insn)                ; 6: exit

     ;; Increment total packet counter (stats[0])
     (bpf/mov :r6 0)                ; 7: r6 = 0
     (bpf/store-mem :dw :r10 -8 :r6); 8: store key

     (bpf/ld-map-fd :r1 stats-fd)   ; 9-10: load map fd
     (bpf/mov-reg :r2 :r10)         ; 11: r2 = r10
     (bpf/add :r2 -8)               ; 12: r2 = &key
     (bpf/call 1)                   ; 13: map_lookup_elem

     (bpf/jmp-imm :jeq :r0 0 3)     ; 14: if NULL, skip

     ;; Increment: (*r0)++
     (bpf/load-mem :dw :r1 :r0 0)   ; 15: r1 = *r0
     (bpf/add :r1 1)                ; 16: r1++
     (bpf/store-mem :dw :r0 0 :r1)  ; 17: *r0 = r1

     ;; Return XDP_PASS
     (bpf/mov :r0 XDP_PASS)         ; 18: return XDP_PASS
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Rate Limiting Simulation (Token Bucket)
;;; ============================================================================

(defn create-rate-limiter
  "Create a token bucket rate limiter state"
  [rate-limit]
  (atom {:tokens (double rate-limit)
         :last-update (System/nanoTime)
         :rate-limit rate-limit}))

(defn check-rate-limit
  "Check if a packet should be allowed based on rate limit.
   Returns [allowed? updated-state]"
  [limiter]
  (let [now (System/nanoTime)
        {:keys [tokens last-update rate-limit]} @limiter
        elapsed-sec (/ (- now last-update) 1e9)
        new-tokens (min rate-limit (+ tokens (* elapsed-sec rate-limit)))]
    (if (>= new-tokens 1.0)
      (do
        (swap! limiter assoc
               :tokens (- new-tokens 1.0)
               :last-update now)
        true)
      (do
        (swap! limiter assoc
               :tokens new-tokens
               :last-update now)
        false))))

;;; ============================================================================
;;; Part 6: SYN Flood Detection Simulation
;;; ============================================================================

(defn create-syn-tracker
  "Create SYN flood detection state"
  []
  (atom {:syn-counts {}      ; IP -> count
         :second-start (System/currentTimeMillis)}))

(defn track-syn-packet
  "Track a SYN packet and check for flood.
   Returns {:allowed? bool :syn-rate number}"
  [tracker src-ip]
  (let [now (System/currentTimeMillis)
        {:keys [syn-counts second-start]} @tracker]
    ;; Reset counters every second
    (when (> (- now second-start) 1000)
      (swap! tracker assoc
             :syn-counts {}
             :second-start now))

    (let [current-count (get (:syn-counts @tracker) src-ip 0)
          new-count (inc current-count)]
      (swap! tracker assoc-in [:syn-counts src-ip] new-count)
      {:allowed? (<= new-count SYN_RATE_LIMIT)
       :syn-rate new-count})))

;;; ============================================================================
;;; Part 7: Traffic Simulation
;;; ============================================================================

(defn generate-attack-traffic
  "Generate simulated attack traffic patterns"
  []
  (let [normal-ips ["192.168.1.10" "192.168.1.20" "192.168.1.30"
                    "10.0.0.100" "10.0.0.101" "10.0.0.102"]
        attacker-ips ["45.33.32.156" "104.236.201.88" "198.51.100.50"]
        now (System/currentTimeMillis)]
    (concat
      ;; Normal traffic (low rate)
      (for [_ (range 50)]
        {:src-ip (rand-nth normal-ips)
         :dst-ip "192.168.1.1"
         :protocol (rand-nth [IPPROTO_TCP IPPROTO_UDP])
         :tcp-flags (if (< (rand) 0.3) TH_SYN (bit-or TH_ACK TH_PUSH))
         :src-port (+ 10000 (rand-int 55000))
         :dst-port (rand-nth [80 443 8080])
         :timestamp now
         :type :normal})

      ;; Rate limit attack (high volume from single IPs)
      (for [_ (range 80)]
        {:src-ip (first attacker-ips)
         :dst-ip "192.168.1.1"
         :protocol IPPROTO_UDP
         :tcp-flags 0
         :src-port (rand-int 65535)
         :dst-port 53
         :timestamp now
         :type :volumetric})

      ;; SYN flood attack
      (for [_ (range 60)]
        {:src-ip (second attacker-ips)
         :dst-ip "192.168.1.1"
         :protocol IPPROTO_TCP
         :tcp-flags TH_SYN
         :src-port (rand-int 65535)
         :dst-port 80
         :timestamp now
         :type :syn-flood})

      ;; Distributed attack (many IPs)
      (for [i (range 30)]
        {:src-ip (format "203.0.113.%d" (+ 1 i))
         :dst-ip "192.168.1.1"
         :protocol IPPROTO_TCP
         :tcp-flags TH_SYN
         :src-port (rand-int 65535)
         :dst-port 443
         :timestamp now
         :type :distributed}))))

(defn simulate-mitigation
  "Simulate DDoS mitigation for a list of packets"
  [packets blocked-ips-atom]
  (let [rate-limiters (atom {})  ; IP -> rate-limiter
        syn-tracker (create-syn-tracker)
        stats (atom {:total 0
                     :passed 0
                     :dropped-rate-limit 0
                     :dropped-syn-flood 0
                     :dropped-blocked 0
                     :violations {}})
        results (atom [])]

    (doseq [pkt packets]
      (let [{:keys [src-ip tcp-flags protocol]} pkt
            is-syn (and (= protocol IPPROTO_TCP)
                        (= (bit-and tcp-flags TH_SYN) TH_SYN)
                        (zero? (bit-and tcp-flags TH_ACK)))]

        (swap! stats update :total inc)

        (cond
          ;; Check if already blocked
          (contains? @blocked-ips-atom src-ip)
          (do
            (swap! stats update :dropped-blocked inc)
            (swap! results conj (assoc pkt :action :drop :reason "blocked")))

          ;; Check SYN flood
          (and is-syn
               (let [{:keys [allowed?]} (track-syn-packet syn-tracker src-ip)]
                 (not allowed?)))
          (do
            (swap! stats update :dropped-syn-flood inc)
            (swap! stats update-in [:violations src-ip] (fnil inc 0))
            (when (>= (get-in @stats [:violations src-ip]) BLOCK_THRESHOLD)
              (swap! blocked-ips-atom conj src-ip))
            (swap! results conj (assoc pkt :action :drop :reason "syn-flood")))

          ;; Check rate limit
          :else
          (let [limiter (or (get @rate-limiters src-ip)
                            (let [l (create-rate-limiter RATE_LIMIT_PPS)]
                              (swap! rate-limiters assoc src-ip l)
                              l))
                allowed? (check-rate-limit limiter)]
            (if allowed?
              (do
                (swap! stats update :passed inc)
                (swap! results conj (assoc pkt :action :pass :reason "allowed")))
              (do
                (swap! stats update :dropped-rate-limit inc)
                (swap! stats update-in [:violations src-ip] (fnil inc 0))
                (when (>= (get-in @stats [:violations src-ip]) BLOCK_THRESHOLD)
                  (swap! blocked-ips-atom conj src-ip))
                (swap! results conj (assoc pkt :action :drop :reason "rate-limit"))))))))

    {:stats @stats
     :results @results
     :blocked @blocked-ips-atom}))

;;; ============================================================================
;;; Part 8: Statistics Display
;;; ============================================================================

(defn display-mitigation-info
  "Display DDoS mitigation configuration"
  []
  (println "\nDDoS Mitigation Configuration:")
  (println "═══════════════════════════════════════════════════════")
  (println "")
  (println "  Token Bucket Rate Limiting:")
  (println (format "    • Per-IP packet limit : %,d pps" RATE_LIMIT_PPS))
  (println (format "    • Bucket refill rate  : %,d tokens/sec" RATE_LIMIT_PPS))
  (println "")
  (println "  SYN Flood Protection:")
  (println (format "    • SYN rate limit      : %,d SYNs/sec per IP" SYN_RATE_LIMIT))
  (println (format "    • Detection window    : 1 second"))
  (println "")
  (println "  Automated Blocking:")
  (println (format "    • Violation threshold : %d violations" BLOCK_THRESHOLD))
  (println (format "    • Block duration      : %d seconds" BLOCK_DURATION_SEC))
  (println "═══════════════════════════════════════════════════════"))

(defn display-attack-stats
  "Display attack mitigation statistics"
  [{:keys [stats results blocked]}]
  (let [{:keys [total passed dropped-rate-limit dropped-syn-flood dropped-blocked]} stats
        total-dropped (+ dropped-rate-limit dropped-syn-flood dropped-blocked)]

    (println "\nMitigation Statistics:")
    (println "═══════════════════════════════════════════════════════")

    (println "\nPacket Summary:")
    (println (format "  Total packets     : %,d" total))
    (println (format "  Passed            : %,d (%.1f%%)" passed
                     (if (pos? total) (* 100.0 (/ passed total)) 0.0)))
    (println (format "  Dropped           : %,d (%.1f%%)" total-dropped
                     (if (pos? total) (* 100.0 (/ total-dropped total)) 0.0)))

    (println "\nDrop Reasons:")
    (println (format "  Rate limit exceed : %,d" dropped-rate-limit))
    (println (format "  SYN flood detect  : %,d" dropped-syn-flood))
    (println (format "  IP blocked        : %,d" dropped-blocked))

    (println "\nBlocked IPs:")
    (if (empty? blocked)
      (println "  (none)")
      (doseq [ip blocked]
        (println (format "  • %s" ip))))

    (println "\nTraffic by Type:")
    (let [by-type (frequencies (map :type results))]
      (doseq [[type cnt] (sort-by val > by-type)]
        (let [dropped-of-type (count (filter #(and (= (:type %) type)
                                                   (= (:action %) :drop))
                                             results))]
          (println (format "  %-12s : %3d packets, %3d dropped (%.0f%%)"
                           (name type) cnt dropped-of-type
                           (if (pos? cnt) (* 100.0 (/ dropped-of-type cnt)) 0.0))))))

    (println "═══════════════════════════════════════════════════════")))

(defn display-sample-events
  "Display sample packet processing events"
  [results n]
  (println "\nSample Mitigation Events:")
  (println "═══════════════════════════════════════════════════════════════════════════════════")
  (println "ACTION │ TYPE        │ SOURCE IP       │ FLAGS │ PORT  │ REASON")
  (println "───────┼─────────────┼─────────────────┼───────┼───────┼──────────────")

  (doseq [pkt (take n results)]
    (let [{:keys [src-ip tcp-flags dst-port action reason type]} pkt
          action-str (if (= action :pass) "PASS" "DROP")
          flags-str (if (zero? tcp-flags) "-" (tcp-flags->str tcp-flags))]
      (println (format "%-6s │ %-11s │ %-15s │ %-5s │ %5d │ %s"
                       action-str (name type) src-ip flags-str dst-port reason))))

  (println "═══════════════════════════════════════════════════════════════════════════════════"))

(defn display-token-bucket-diagram
  "Display token bucket algorithm explanation"
  []
  (println "\nToken Bucket Algorithm:")
  (println "═══════════════════════════════════════════════════════")
  (println "")
  (println "  ┌─────────────────────────────────────────────────────┐")
  (println "  │                                                     │")
  (println "  │    Tokens added at rate R (e.g., 1000/sec)         │")
  (println "  │                    │                                │")
  (println "  │                    ▼                                │")
  (println "  │    ┌──────────────────────────────┐                 │")
  (println "  │    │  Token Bucket (max = R)      │                 │")
  (println "  │    │  ████████████░░░░░░░░░░░░    │                 │")
  (println "  │    │  (current tokens)            │                 │")
  (println "  │    └──────────────────────────────┘                 │")
  (println "  │                    │                                │")
  (println "  │                    ▼                                │")
  (println "  │    if (tokens >= 1) {                               │")
  (println "  │        tokens--;                                    │")
  (println "  │        PASS packet                                  │")
  (println "  │    } else {                                         │")
  (println "  │        DROP packet (rate exceeded)                  │")
  (println "  │    }                                                │")
  (println "  │                                                     │")
  (println "  └─────────────────────────────────────────────────────┘")
  (println "")
  (println "═══════════════════════════════════════════════════════"))

;;; ============================================================================
;;; Part 9: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 7.2: XDP DDoS Mitigation ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [stats-map (create-stats-map)
        blocked-map (create-blocked-ips-map)
        violations-map (create-violation-count-map)]
    (println "  Stats map created (FD:" (:fd stats-map) ")")
    (println "  Blocked IPs map created (FD:" (:fd blocked-map) ")")
    (println "  Violations map created (FD:" (:fd violations-map) ")")

    ;; Initialize stats
    (doseq [i (range 10)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create XDP program
      (println "\nStep 3: Creating XDP DDoS mitigation program...")
      (let [program (create-ddos-mitigation-program (:fd stats-map)
                                                     (:fd blocked-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :xdp
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display configuration
            (println "\nStep 5: Mitigation configuration...")
            (display-mitigation-info)
            (display-token-bucket-diagram)

            ;; Step 6: Generate attack traffic
            (println "\nStep 6: Generating simulated attack traffic...")
            (let [packets (shuffle (generate-attack-traffic))
                  blocked-ips (atom #{})]
              (println (format "  Generated %d packets" (count packets)))

              ;; Step 7: Run mitigation simulation
              (println "\nStep 7: Running mitigation simulation...")
              (let [mitigation-result (simulate-mitigation packets blocked-ips)]

                ;; Step 8: Display results
                (println "\nStep 8: Displaying results...")
                (display-sample-events (:results mitigation-result) 20)
                (display-attack-stats mitigation-result)

                ;; Update BPF maps with stats
                (let [{:keys [total passed dropped-rate-limit dropped-syn-flood dropped-blocked]} (:stats mitigation-result)]
                  (bpf/map-update stats-map 0 total)
                  (bpf/map-update stats-map 1 passed)
                  (bpf/map-update stats-map 2 dropped-rate-limit)
                  (bpf/map-update stats-map 3 dropped-syn-flood)
                  (bpf/map-update stats-map 4 dropped-blocked))

                ;; Add blocked IPs to map
                (doseq [ip @blocked-ips]
                  (let [unblock-time (+ (System/currentTimeMillis) (* BLOCK_DURATION_SEC 1000))]
                    (bpf/map-update blocked-map (ip-string->int ip) unblock-time)))

                ;; Step 9: Show map contents
                (println "\nStep 9: Reading stats from BPF maps...")
                (println (format "  stats[0] (total)           = %,d" (bpf/map-lookup stats-map 0)))
                (println (format "  stats[1] (passed)          = %,d" (bpf/map-lookup stats-map 1)))
                (println (format "  stats[2] (drop-rate-limit) = %,d" (bpf/map-lookup stats-map 2)))
                (println (format "  stats[3] (drop-syn-flood)  = %,d" (bpf/map-lookup stats-map 3)))
                (println (format "  stats[4] (drop-blocked)    = %,d" (bpf/map-lookup stats-map 4)))))

            ;; Step 10: Cleanup
            (println "\nStep 10: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map stats-map)
        (bpf/close-map blocked-map)
        (bpf/close-map violations-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 7.2 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test token bucket
  (let [limiter (create-rate-limiter 10)]
    (dotimes [_ 15]
      (println (check-rate-limit limiter))))

  ;; Test SYN tracker
  (let [tracker (create-syn-tracker)]
    (dotimes [i 110]
      (println i (track-syn-packet tracker "192.168.1.1"))))
  )
