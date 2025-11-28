(ns lab-8-3-egress-firewall
  "Lab 8.3: TC Egress Firewall

   This solution demonstrates:
   - Outbound traffic filtering with TC
   - IP address and port-based blocking
   - Data exfiltration detection
   - Security policy enforcement
   - Connection logging and monitoring

   Run with: sudo clojure -M -m lab-8-3-egress-firewall
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]
           [java.net InetAddress]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; TC Actions
(def TC_ACT_OK 0)       ; Allow packet
(def TC_ACT_SHOT 2)     ; Drop packet

;; __sk_buff offsets
(def SKB_LEN 0)         ; Packet length
(def SKB_DATA 76)       ; Data pointer
(def SKB_DATA_END 80)   ; Data end pointer

;; Protocol numbers
(def ETH_P_IP 0x0800)
(def IPPROTO_ICMP 1)
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

;; Blocked ports (security risks)
(def BLOCKED_PORTS
  {23 "Telnet (insecure)"
   445 "SMB (often exploited)"
   3389 "RDP (restrict external)"
   6667 "IRC (potential C&C)"
   4444 "Metasploit default"
   31337 "Elite backdoor"})

;; Suspicious ports (log but allow)
(def SUSPICIOUS_PORTS
  {1080 "SOCKS proxy"
   3128 "Squid proxy"
   8080 "HTTP proxy"
   9050 "Tor"})

;;; ============================================================================
;;; Part 2: IP Address Utilities
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
  (let [ip (if (neg? ip-int)
             (+ ip-int 0x100000000)  ; Convert signed to unsigned
             ip-int)]
    (format "%d.%d.%d.%d"
            (bit-and (bit-shift-right ip 24) 0xFF)
            (bit-and (bit-shift-right ip 16) 0xFF)
            (bit-and (bit-shift-right ip 8) 0xFF)
            (bit-and ip 0xFF))))

;;; ============================================================================
;;; Part 3: Firewall Rules
;;; ============================================================================

(defrecord FirewallRule [id action src-ip dst-ip dst-port protocol description])

(defn create-rule
  "Create a firewall rule"
  [id action & {:keys [src-ip dst-ip dst-port protocol description]}]
  (->FirewallRule id action src-ip dst-ip dst-port protocol description))

(def default-rules
  "Default egress firewall rules"
  [(create-rule 1 :block :dst-ip "192.168.100.50" :description "Suspicious server")
   (create-rule 2 :block :dst-ip "10.0.50.100" :description "Unauthorized service")
   (create-rule 3 :block :dst-port 23 :description "Block Telnet")
   (create-rule 4 :block :dst-port 445 :description "Block SMB")
   (create-rule 5 :block :dst-port 3389 :description "Block RDP")
   (create-rule 6 :block :dst-port 6667 :description "Block IRC")
   (create-rule 7 :log :dst-port 1080 :description "Log SOCKS")
   (create-rule 8 :log :dst-port 9050 :description "Log Tor")])

;;; ============================================================================
;;; Part 4: BPF Maps
;;; ============================================================================

(defn create-blocked-ips-map
  "Hash map: blocked destination IP -> 1"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 4
                   :max-entries 1000
                   :map-name "blocked_ips"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/int->bytes
                   :value-deserializer utils/bytes->int}))

(defn create-blocked-ports-map
  "Hash map: blocked port -> 1"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 4
                   :max-entries 100
                   :map-name "blocked_ports"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/int->bytes
                   :value-deserializer utils/bytes->int}))

(defn create-stats-map
  "Array map for firewall statistics:
   [0] = {blocked_by_ip_count, blocked_by_ip_bytes}
   [1] = {blocked_by_port_count, blocked_by_port_bytes}
   [2] = {accepted_count, accepted_bytes}"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 16  ; count (u64) + bytes (u64)
                   :max-entries 3
                   :map-name "fw_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int}))

(defn create-connection-log-map
  "LRU hash map: connection tuple -> timestamp
   For tracking outbound connections"
  []
  (bpf/create-map {:map-type :lru-hash
                   :key-size 12  ; dst_ip (4) + dst_port (4) + proto (4)
                   :value-size 8  ; timestamp
                   :max-entries 10000
                   :map-name "conn_log"}))

;;; ============================================================================
;;; Part 5: TC BPF Program
;;; ============================================================================

(defn create-egress-firewall-program
  "Create TC program for egress firewall.

   Simplified program that:
   1. Validates headers
   2. Checks destination IP against blocklist
   3. Updates stats and returns appropriate action

   Jump offsets account for ld-map-fd being 2 instructions."
  [stats-fd blocked-ips-fd _blocked-ports-fd]
  (bpf/assemble
    [;; 0: r6 = skb (save context)
     (bpf/mov-reg :r6 :r1)

     ;; 1: Default stats key = 2 (allowed)
     (bpf/mov :r9 2)
     ;; 2: Default return = TC_ACT_OK (must initialize before any jumps)
     (bpf/mov :r8 TC_ACT_OK)

     ;; 3-4: Load data pointers (32-bit for TC context)
     (bpf/ldx :w :r2 :r6 SKB_DATA)      ; r2 = skb->data
     (bpf/ldx :w :r3 :r6 SKB_DATA_END)  ; r3 = skb->data_end

     ;; 5-6: Check Ethernet + IP header (14 + 20 = 34 bytes minimum)
     (bpf/mov-reg :r4 :r2)
     (bpf/add :r4 34)
     ;; 7: if too short, jump to stats update at insn 20 (skip 12)
     ;; 7+1+12 = 20 (store-mem)
     (bpf/jmp-reg :jgt :r4 :r3 12)

     ;; 8: Check EtherType (IPv4 = 0x0800)
     (bpf/ldx :h :r5 :r2 12)
     ;; 9: Not IPv4, jump to stats at insn 20 (skip 10)
     ;; 9+1+10 = 20
     (bpf/jmp-imm :jne :r5 0x0008 10)

     ;; 10: Load destination IP (offset 14 + 16 = 30)
     (bpf/ldx :w :r7 :r2 30)            ; r7 = dst_ip (network order)

     ;; 11: Store IP for map lookup
     (bpf/store-mem :dw :r10 -8 :r7)

     ;; 12: Setup map lookup
     (bpf/mov-reg :r2 :r10)
     ;; 13-14: ld-map-fd (2 instructions)
     (bpf/ld-map-fd :r1 blocked-ips-fd)
     ;; 15: add
     (bpf/add :r2 -8)
     ;; 16: call
     (bpf/call 1)                       ; bpf_map_lookup_elem

     ;; 17: if NULL (not blocked), skip to stats (skip 2 to insn 20)
     ;; When r0 == 0 (IP not in blocklist), we keep defaults (r8=OK, r9=2)
     (bpf/jmp-imm :jeq :r0 0 2)

     ;; 18: IP is blocked: stats key = 0
     (bpf/mov :r9 0)
     ;; 19: Set return to SHOT
     (bpf/mov :r8 TC_ACT_SHOT)

     ;; 20: (r8 and r9 already set appropriately)
     ;; Fall through or jumped here

     ;; 20: Store stats key for lookup
     (bpf/store-mem :dw :r10 -8 :r9)

     ;; 21-22: ld-map-fd (2 instructions)
     (bpf/ld-map-fd :r1 stats-fd)
     ;; 23: mov-reg
     (bpf/mov-reg :r2 :r10)
     ;; 24: add
     (bpf/add :r2 -8)
     ;; 25: call
     (bpf/call 1)                       ; bpf_map_lookup_elem

     ;; 26: if NULL, skip stats increment (skip 3)
     (bpf/jmp-imm :jeq :r0 0 3)

     ;; 27: load counter
     (bpf/load-mem :dw :r1 :r0 0)
     ;; 28: increment
     (bpf/add :r1 1)
     ;; 29: store counter
     (bpf/store-mem :dw :r0 0 :r1)

     ;; 30: Return action from r8
     (bpf/mov-reg :r0 :r8)
     ;; 31: exit
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 6: Traffic Simulation
;;; ============================================================================

(defn generate-connection
  "Generate a simulated outbound connection"
  [dst-ip dst-port protocol]
  {:dst-ip dst-ip
   :dst-port dst-port
   :protocol protocol
   :size (+ 64 (rand-int 1400))
   :timestamp (System/currentTimeMillis)})

(defn simulate-egress-traffic
  "Generate simulated egress traffic"
  [num-connections]
  (let [normal-destinations ["8.8.8.8" "1.1.1.1" "93.184.216.34"   ; Google DNS, Cloudflare, example.com
                              "151.101.1.140" "140.82.114.4"]       ; Reddit, GitHub
        suspicious-destinations ["192.168.100.50" "10.0.50.100"]
        normal-ports [80 443 53 8080]
        blocked-ports (keys BLOCKED_PORTS)
        suspicious-ports (keys SUSPICIOUS_PORTS)]

    (for [_ (range num-connections)]
      (let [r (rand)]
        (cond
          ;; 70% normal traffic
          (< r 0.70)
          (generate-connection (rand-nth normal-destinations)
                               (rand-nth normal-ports)
                               IPPROTO_TCP)

          ;; 10% to blocked IPs
          (< r 0.80)
          (generate-connection (rand-nth suspicious-destinations)
                               (rand-nth normal-ports)
                               IPPROTO_TCP)

          ;; 10% to blocked ports
          (< r 0.90)
          (generate-connection (rand-nth normal-destinations)
                               (rand-nth blocked-ports)
                               IPPROTO_TCP)

          ;; 10% to suspicious ports
          :else
          (generate-connection (rand-nth normal-destinations)
                               (rand-nth suspicious-ports)
                               IPPROTO_TCP))))))

(defn apply-firewall-rules
  "Apply firewall rules to connections"
  [connections blocked-ips blocked-ports]
  (let [results (atom {:accepted {:count 0 :bytes 0}
                       :blocked-ip {:count 0 :bytes 0 :ips #{}}
                       :blocked-port {:count 0 :bytes 0 :ports #{}}
                       :logged {:count 0 :bytes 0}})]

    (doseq [conn connections]
      (let [{:keys [dst-ip dst-port size]} conn
            ip-blocked? (contains? blocked-ips dst-ip)
            port-blocked? (contains? blocked-ports dst-port)
            port-suspicious? (contains? SUSPICIOUS_PORTS dst-port)]

        (cond
          ip-blocked?
          (do
            (swap! results update-in [:blocked-ip :count] inc)
            (swap! results update-in [:blocked-ip :bytes] + size)
            (swap! results update-in [:blocked-ip :ips] conj dst-ip))

          port-blocked?
          (do
            (swap! results update-in [:blocked-port :count] inc)
            (swap! results update-in [:blocked-port :bytes] + size)
            (swap! results update-in [:blocked-port :ports] conj dst-port))

          port-suspicious?
          (do
            (swap! results update-in [:logged :count] inc)
            (swap! results update-in [:logged :bytes] + size)
            (swap! results update-in [:accepted :count] inc)
            (swap! results update-in [:accepted :bytes] + size))

          :else
          (do
            (swap! results update-in [:accepted :count] inc)
            (swap! results update-in [:accepted :bytes] + size)))))

    @results))

;;; ============================================================================
;;; Part 7: Statistics Display
;;; ============================================================================

(defn format-bytes [bytes]
  (cond
    (< bytes 1024) (format "%d B" bytes)
    (< bytes 1048576) (format "%.1f KB" (/ bytes 1024.0))
    :else (format "%.2f MB" (/ bytes 1048576.0))))

(defn display-firewall-info
  "Display egress firewall information"
  [blocked-ips blocked-ports]
  (println "\nEgress Firewall Configuration:")
  (println "═══════════════════════════════════════════════════════")
  (println "")
  (println "  Security Policy: DENY-BY-DEFAULT for suspicious traffic")
  (println "")
  (println "  Blocked Destination IPs:")
  (doseq [ip blocked-ips]
    (println (format "    ✗ %s" ip)))
  (println "")
  (println "  Blocked Destination Ports:")
  (doseq [[port desc] BLOCKED_PORTS]
    (println (format "    ✗ %5d - %s" port desc)))
  (println "")
  (println "  Monitored (Logged) Ports:")
  (doseq [[port desc] SUSPICIOUS_PORTS]
    (println (format "    ⚠ %5d - %s" port desc)))
  (println "═══════════════════════════════════════════════════════"))

(defn display-firewall-results
  "Display firewall filtering results"
  [{:keys [accepted blocked-ip blocked-port logged]}]
  (let [total-blocked (+ (:count blocked-ip) (:count blocked-port))
        total (+ (:count accepted) total-blocked)]

    (println "\nFirewall Results:")
    (println "═══════════════════════════════════════════════════════")

    (println "\nTraffic Summary:")
    (println (format "  Total connections   : %,d" total))
    (println (format "  Accepted            : %,d (%.1f%%)"
                     (:count accepted)
                     (if (pos? total) (* 100.0 (/ (:count accepted) total)) 0.0)))
    (println (format "  Blocked             : %,d (%.1f%%)"
                     total-blocked
                     (if (pos? total) (* 100.0 (/ total-blocked total)) 0.0)))

    (println "\nBlocking Breakdown:")
    (println (format "  Blocked by IP       : %,d connections, %s"
                     (:count blocked-ip) (format-bytes (:bytes blocked-ip))))
    (when (seq (:ips blocked-ip))
      (println "    Blocked destinations:")
      (doseq [ip (:ips blocked-ip)]
        (println (format "      ✗ %s" ip))))

    (println (format "  Blocked by Port     : %,d connections, %s"
                     (:count blocked-port) (format-bytes (:bytes blocked-port))))
    (when (seq (:ports blocked-port))
      (println "    Blocked ports:")
      (doseq [port (:ports blocked-port)]
        (println (format "      ✗ %d (%s)" port (get BLOCKED_PORTS port "Unknown")))))

    (println "\nSecurity Monitoring:")
    (println (format "  Logged connections  : %,d (suspicious but allowed)"
                     (:count logged)))
    (when (pos? (:count logged))
      (println "    ⚠ Connections to monitored ports detected"))

    (println "═══════════════════════════════════════════════════════")))

(defn display-security-visualization
  "Display security status visualization"
  [{:keys [accepted blocked-ip blocked-port]}]
  (let [total (+ (:count accepted) (:count blocked-ip) (:count blocked-port))
        total (max 1 total)]

    (println "\nSecurity Status:")
    (println "═══════════════════════════════════════════════════════")
    (println "")
    (println "  Egress Traffic Flow:")
    (println "")
    (println "  ┌─────────────────────────────────────────────────────┐")
    (println "  │           Outbound Traffic                         │")
    (println "  │                  │                                 │")
    (println "  │                  ▼                                 │")
    (println "  │         ┌───────────────┐                          │")
    (println "  │         │   TC Egress   │                          │")
    (println "  │         │   Firewall    │                          │")
    (println "  │         └───────┬───────┘                          │")
    (println "  │                 │                                  │")
    (println "  │     ┌───────────┼───────────┐                      │")
    (println "  │     │           │           │                      │")
    (println "  │     ▼           ▼           ▼                      │")
    (println (format "  │  ┌─────┐   ┌─────┐   ┌─────┐                     │"))
    (println (format "  │  │BLOCK│   │ LOG │   │ALLOW│                     │"))
    (println (format "  │  │%3d%% │   │  ⚠  │   │%3d%% │                     │"
                     (int (/ (* (+ (:count blocked-ip) (:count blocked-port)) 100) total))
                     (int (/ (* (:count accepted) 100) total))))
    (println "  │  └─────┘   └─────┘   └─────┘                     │")
    (println "  │     │                   │                        │")
    (println "  │     ▼                   ▼                        │")
    (println "  │   DROP              TRANSMIT                     │")
    (println "  │                                                  │")
    (println "  └─────────────────────────────────────────────────────┘")
    (println "")

    (when (pos? (+ (:count blocked-ip) (:count blocked-port)))
      (println "  ⚠ Security policy violations detected!"))

    (println "═══════════════════════════════════════════════════════")))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 8.3: TC Egress Firewall ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [stats-map (create-stats-map)
        blocked-ips-map (create-blocked-ips-map)
        blocked-ports-map (create-blocked-ports-map)]
    (println "  Stats map created (FD:" (:fd stats-map) ")")
    (println "  Blocked IPs map created (FD:" (:fd blocked-ips-map) ")")
    (println "  Blocked ports map created (FD:" (:fd blocked-ports-map) ")")

    ;; Step 3: Configure firewall rules
    (println "\nStep 3: Configuring firewall rules...")
    (let [blocked-ips #{"192.168.100.50" "10.0.50.100"}
          blocked-ports (set (keys BLOCKED_PORTS))]

      ;; Add blocked IPs to map
      (doseq [ip blocked-ips]
        (bpf/map-update blocked-ips-map (ip-string->int ip) 1))
      (println (format "  Added %d blocked IPs" (count blocked-ips)))

      ;; Add blocked ports to map
      (doseq [port blocked-ports]
        (bpf/map-update blocked-ports-map port 1))
      (println (format "  Added %d blocked ports" (count blocked-ports)))

      (try
        ;; Step 4: Create TC program
        (println "\nStep 4: Creating TC egress firewall program...")
        (let [program (create-egress-firewall-program (:fd stats-map)
                                                       (:fd blocked-ips-map)
                                                       (:fd blocked-ports-map))]
          (println "  Program assembled (" (/ (count program) 8) "instructions)")

          ;; Step 5: Load program
          (println "\nStep 5: Loading program into kernel...")
          (let [prog (bpf/load-program {:prog-type :sched-cls
                                        :insns program})]
            (println "  Program loaded (FD:" (:fd prog) ")")

            (try
              ;; Step 6: Display firewall info
              (println "\nStep 6: Firewall configuration...")
              (display-firewall-info blocked-ips blocked-ports)

              ;; Step 7: Simulate traffic
              (println "\nStep 7: Simulating egress traffic...")
              (let [num-connections 200
                    _ (println (format "  Generating %d outbound connections..." num-connections))
                    connections (simulate-egress-traffic num-connections)
                    _ (println "  Applying firewall rules...")
                    results (apply-firewall-rules connections blocked-ips blocked-ports)]

                ;; Step 8: Display results
                (println "\nStep 8: Firewall results...")
                (display-firewall-results results)

                ;; Step 9: Display visualization
                (println "\nStep 9: Security visualization...")
                (display-security-visualization results)

                ;; Step 10: Update BPF maps
                (println "\nStep 10: Updating BPF maps...")
                (let [blocked-ip-bytes (byte-array 16)
                      blocked-port-bytes (byte-array 16)
                      accepted-bytes (byte-array 16)]

                  (doto (ByteBuffer/wrap blocked-ip-bytes)
                    (.order ByteOrder/LITTLE_ENDIAN)
                    (.putLong 0 (get-in results [:blocked-ip :count]))
                    (.putLong 8 (get-in results [:blocked-ip :bytes])))

                  (doto (ByteBuffer/wrap blocked-port-bytes)
                    (.order ByteOrder/LITTLE_ENDIAN)
                    (.putLong 0 (get-in results [:blocked-port :count]))
                    (.putLong 8 (get-in results [:blocked-port :bytes])))

                  (doto (ByteBuffer/wrap accepted-bytes)
                    (.order ByteOrder/LITTLE_ENDIAN)
                    (.putLong 0 (get-in results [:accepted :count]))
                    (.putLong 8 (get-in results [:accepted :bytes])))

                  (bpf/map-update stats-map 0 blocked-ip-bytes :raw-value true)
                  (bpf/map-update stats-map 1 blocked-port-bytes :raw-value true)
                  (bpf/map-update stats-map 2 accepted-bytes :raw-value true)

                  (println (format "  Stored stats: %d blocked by IP, %d blocked by port, %d accepted"
                                   (get-in results [:blocked-ip :count])
                                   (get-in results [:blocked-port :count])
                                   (get-in results [:accepted :count])))))

              ;; Step 11: Cleanup
              (println "\nStep 11: Cleanup...")
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
          (bpf/close-map blocked-ips-map)
          (bpf/close-map blocked-ports-map)
          (println "  Maps closed")))))

  (println "\n=== Lab 8.3 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test IP conversion
  (ip-string->int "192.168.100.50")
  (int->ip-string (ip-string->int "192.168.100.50"))

  ;; Test blocked ports
  BLOCKED_PORTS
  (contains? (set (keys BLOCKED_PORTS)) 23)
  )
