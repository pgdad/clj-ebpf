(ns lab-9-3-network-enforcer
  "Lab 9.3: Network Security Enforcer

   This solution demonstrates:
   - LSM (Linux Security Modules) socket hooks concepts
   - Network access control via socket_connect/socket_bind hooks
   - IP/port blocking for egress connections
   - Rate limiting per process
   - Private vs public IP restrictions
   - Privileged port binding controls

   Note: LSM BPF requires kernel 5.7+ with BTF and LSM BPF enabled.
   This solution simulates LSM concepts using tracepoints as fallback.

   Run with: sudo clojure -M -m lab-9-3-network-enforcer
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.time Instant LocalDateTime ZoneId]
           [java.time.format DateTimeFormatter]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; Socket address families
(def AF_INET 2)
(def AF_INET6 10)

;; Socket types
(def SOCK_STREAM 1)  ; TCP
(def SOCK_DGRAM 2)   ; UDP
(def SOCK_RAW 3)     ; Raw sockets

;; Well-known ports
(def PORT_FTP 21)
(def PORT_SSH 22)
(def PORT_TELNET 23)
(def PORT_SMTP 25)
(def PORT_DNS 53)
(def PORT_HTTP 80)
(def PORT_HTTPS 443)
(def PORT_SMB 445)
(def PORT_RDP 3389)
(def PORT_IRC 6667)

;; LSM return values
(def LSM_ALLOW 0)
(def EACCES 13)
(def EPERM 1)

;; Event types
(def EVENT_CONNECT_ALLOWED 1)
(def EVENT_CONNECT_BLOCKED 2)
(def EVENT_BIND_ALLOWED 3)
(def EVENT_BIND_BLOCKED 4)
(def EVENT_RATE_LIMITED 5)

;; Rate limiting
(def MAX_CONNECTIONS_PER_MIN 100)

;; Default blocked ports (dangerous services)
(def BLOCKED_PORTS
  #{PORT_TELNET   ; Telnet (unencrypted)
    135           ; Windows RPC
    139           ; NetBIOS
    PORT_SMB      ; SMB
    PORT_RDP      ; RDP
    PORT_IRC})    ; IRC (often C2)

;; Test networks for demo (RFC 5737)
(def TEST_NET_1 "192.0.2.0")    ; 192.0.2.0/24
(def TEST_NET_2 "198.51.100.0") ; 198.51.100.0/24
(def TEST_NET_3 "203.0.113.0")  ; 203.0.113.0/24

;;; ============================================================================
;;; Part 2: IP Address Utilities
;;; ============================================================================

(defn ip->u32
  "Convert IP string to 32-bit unsigned integer (host byte order)"
  [ip-str]
  (let [parts (map #(Integer/parseInt %) (str/split ip-str #"\."))]
    (reduce (fn [acc [idx val]]
              (bit-or acc (bit-shift-left val (* 8 (- 3 idx)))))
            0
            (map-indexed vector parts))))

(defn u32->ip
  "Convert 32-bit integer to IP string"
  [ip]
  (format "%d.%d.%d.%d"
          (bit-and (bit-shift-right ip 24) 0xFF)
          (bit-and (bit-shift-right ip 16) 0xFF)
          (bit-and (bit-shift-right ip 8) 0xFF)
          (bit-and ip 0xFF)))

(defn is-private-ip?
  "Check if IP is in private range (RFC 1918)"
  [ip-u32]
  (or
    ;; 10.0.0.0/8
    (= 10 (bit-and (bit-shift-right ip-u32 24) 0xFF))
    ;; 172.16.0.0/12
    (let [first-12 (bit-shift-right ip-u32 20)]
      (= 0xAC1 first-12))
    ;; 192.168.0.0/16
    (let [first-16 (bit-shift-right ip-u32 16)]
      (= 0xC0A8 first-16))))

(defn is-localhost?
  "Check if IP is localhost"
  [ip-u32]
  (= 127 (bit-and (bit-shift-right ip-u32 24) 0xFF)))

;; Custom serializers for unsigned 32-bit values
(defn u32->bytes
  "Convert unsigned 32-bit integer to bytes (little-endian)"
  [v]
  (let [n (long v)]
    (byte-array [(unchecked-byte (bit-and n 0xFF))
                 (unchecked-byte (bit-and (bit-shift-right n 8) 0xFF))
                 (unchecked-byte (bit-and (bit-shift-right n 16) 0xFF))
                 (unchecked-byte (bit-and (bit-shift-right n 24) 0xFF))])))

(defn bytes->u32
  "Convert bytes to unsigned 32-bit integer (little-endian)"
  [b]
  (bit-or (bit-and (aget b 0) 0xFF)
          (bit-shift-left (bit-and (aget b 1) 0xFF) 8)
          (bit-shift-left (bit-and (aget b 2) 0xFF) 16)
          (bit-shift-left (bit-and (aget b 3) 0xFF) 24)))

(defn is-test-network?
  "Check if IP is in test network (for demo)"
  [ip-u32]
  (let [first-24 (bit-shift-right ip-u32 8)]
    (or (= first-24 0xC00002)     ; 192.0.2.0/24
        (= first-24 0xC63364)     ; 198.51.100.0/24
        (= first-24 0xCB0071))))  ; 203.0.113.0/24

;;; ============================================================================
;;; Part 3: BPF Maps
;;; ============================================================================

(defn create-blocked-ips-map
  "Hash map: IP (u32) -> 1 (blocked)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 1
                   :max-entries 10000
                   :map-name "blocked_ips"
                   :key-serializer u32->bytes
                   :key-deserializer bytes->u32
                   :value-serializer (fn [v] (byte-array [(byte v)]))
                   :value-deserializer (fn [b] (aget b 0))}))

(defn create-blocked-ports-map
  "Hash map: Port (u16) -> 1 (blocked)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 2
                   :value-size 1
                   :max-entries 1000
                   :map-name "blocked_ports"
                   :key-serializer utils/short->bytes
                   :key-deserializer utils/bytes->short
                   :value-serializer (fn [v] (byte-array [(byte v)]))
                   :value-deserializer (fn [b] (aget b 0))}))

(defn create-stats-map
  "Array map for network statistics:
   [0] = total_connections
   [1] = blocked_connections
   [2] = allowed_connections
   [3] = rate_limited"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4
                   :map-name "net_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-rate-limit-map
  "Hash map: PID (u32) -> connection count (u32)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 4
                   :max-entries 4096
                   :map-name "rate_limit"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/int->bytes
                   :value-deserializer utils/bytes->int}))

(defn create-violations-map
  "Hash map: UID (u32) -> violation count (u64)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries 1024
                   :map-name "violations"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: BPF Program (Stats Tracker)
;;; ============================================================================

(defn create-network-stats-program
  "Create BPF program that tracks network statistics.

   This demonstrates the socket_connect LSM hook concept:
   1. Receives context with socket info
   2. Tracks connection statistics
   3. Always returns 0 (ALLOW) - monitoring only

   Note: Real LSM programs use :lsm program type, but require BTF.
   This uses :tracepoint style for broader compatibility."
  [stats-fd]
  (bpf/assemble
    [;; r6 = context pointer
     (bpf/mov-reg :r6 :r1)

     ;; Default stats key = 0 (total connections)
     (bpf/mov :r9 0)

     ;; Store stats key
     (bpf/store-mem :dw :r10 -8 :r9)

     ;; Lookup stats entry
     (bpf/ld-map-fd :r1 stats-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)
     (bpf/call 1)  ; bpf_map_lookup_elem

     ;; If NULL, skip increment
     (bpf/jmp-imm :jeq :r0 0 3)

     ;; Increment counter
     (bpf/load-mem :dw :r1 :r0 0)
     (bpf/add :r1 1)
     (bpf/store-mem :dw :r0 0 :r1)

     ;; Return 0 (LSM_ALLOW) - monitoring only
     (bpf/mov :r0 LSM_ALLOW)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Policy Evaluation
;;; ============================================================================

(defn check-blocked-ip
  "Check if IP is in blocked list"
  [ip-u32 blocked-ips-set]
  (contains? blocked-ips-set ip-u32))

(defn check-blocked-port
  "Check if port is in blocked list"
  [port blocked-ports-set]
  (contains? blocked-ports-set port))

(defn check-rate-limit
  "Check if connection rate exceeds limit"
  [pid rate-map]
  (let [count (get rate-map pid 0)]
    (> count MAX_CONNECTIONS_PER_MIN)))

(defn evaluate-connect-policy
  "Evaluate connection policy for a network connection attempt.
   Returns {:decision :allowed/:blocked :reason string}"
  [connection blocked-ips blocked-ports rate-map policy-config]
  (let [{:keys [pid uid dest-ip dest-port protocol]} connection]
    (cond
      ;; Always allow localhost
      (is-localhost? dest-ip)
      {:decision :allowed :reason "Localhost connection"}

      ;; Check blocked IPs
      (check-blocked-ip dest-ip blocked-ips)
      {:decision :blocked :reason "Blocked IP address"}

      ;; Check blocked ports
      (check-blocked-port dest-port blocked-ports)
      {:decision :blocked :reason (str "Blocked port: " dest-port)}

      ;; Check rate limit
      (check-rate-limit pid rate-map)
      {:decision :blocked :reason "Rate limit exceeded"}

      ;; Check public IP restrictions (non-standard ports)
      (and (:restrict-public-ports policy-config)
           (not (is-private-ip? dest-ip))
           (not (contains? #{PORT_HTTP PORT_HTTPS PORT_DNS PORT_SSH} dest-port)))
      {:decision :blocked :reason "Non-standard port to public IP"}

      ;; Check test network (for demo purposes - always block)
      (is-test-network? dest-ip)
      {:decision :blocked :reason "Connection to test network blocked"}

      :else
      {:decision :allowed :reason "Policy check passed"})))

(defn evaluate-bind-policy
  "Evaluate bind policy for a socket bind attempt.
   Returns {:decision :allowed/:blocked :reason string}"
  [bind-request policy-config]
  (let [{:keys [uid port]} bind-request]
    (cond
      ;; Non-root binding to privileged port
      (and (< port 1024) (not= uid 0))
      {:decision :blocked :reason "Non-root binding to privileged port"}

      ;; Check if port is in restricted list
      (contains? (:restricted-bind-ports policy-config) port)
      {:decision :blocked :reason (str "Binding to restricted port: " port)}

      :else
      {:decision :allowed :reason "Bind allowed"})))

;;; ============================================================================
;;; Part 6: Simulated Network Events
;;; ============================================================================

(defn generate-connection-event
  "Generate a simulated connection event"
  []
  (let [dest-ips [(ip->u32 "192.168.1.100")   ; Private
                  (ip->u32 "10.0.0.50")        ; Private
                  (ip->u32 "8.8.8.8")          ; Google DNS
                  (ip->u32 "1.1.1.1")          ; Cloudflare DNS
                  (ip->u32 "93.184.216.34")    ; example.com
                  (ip->u32 "192.0.2.1")        ; TEST-NET-1 (blocked)
                  (ip->u32 "198.51.100.1")     ; TEST-NET-2 (blocked)
                  (ip->u32 "127.0.0.1")]       ; Localhost
        ports [PORT_HTTP PORT_HTTPS PORT_DNS PORT_SSH
               PORT_TELNET PORT_SMB PORT_IRC  ; Blocked
               8080 8443 3000 5432 27017]     ; Non-standard
        uids [0 1000 1001 65534]]
    {:type :connect
     :pid (+ 1000 (rand-int 30000))
     :uid (rand-nth uids)
     :dest-ip (rand-nth dest-ips)
     :dest-port (rand-nth ports)
     :protocol (rand-nth [:tcp :udp])
     :timestamp (System/currentTimeMillis)
     :comm (rand-nth ["curl" "wget" "firefox" "python3" "nc" "ssh" "sshd"])}))

(defn generate-bind-event
  "Generate a simulated bind event"
  []
  (let [ports [80 443 22 8080 3000 5000 9000]
        uids [0 1000 1001]]
    {:type :bind
     :pid (+ 1000 (rand-int 30000))
     :uid (rand-nth uids)
     :port (rand-nth ports)
     :timestamp (System/currentTimeMillis)
     :comm (rand-nth ["nginx" "apache" "node" "python3" "sshd"])}))

(defn simulate-network-events
  "Simulate a mix of connect and bind events"
  [num-events]
  (repeatedly num-events
              #(if (< (rand) 0.8)
                 (generate-connection-event)
                 (generate-bind-event))))

;;; ============================================================================
;;; Part 7: Event Processing and Statistics
;;; ============================================================================

(defn process-network-event
  "Process a network event and update statistics"
  [event blocked-ips blocked-ports rate-map policy-config stats]
  (case (:type event)
    :connect
    (let [{:keys [pid]} event
          result (evaluate-connect-policy event blocked-ips blocked-ports @rate-map policy-config)]
      ;; Update rate limit tracking
      (swap! rate-map update pid (fnil inc 0))

      ;; Update statistics
      (swap! stats update :total inc)
      (if (= (:decision result) :allowed)
        (swap! stats update :allowed inc)
        (do
          (swap! stats update :blocked inc)
          (when (= (:reason result) "Rate limit exceeded")
            (swap! stats update :rate-limited inc))
          (swap! stats update-in [:blocked-by-reason (:reason result)] (fnil inc 0))
          (swap! stats update-in [:violations-by-uid (:uid event)] (fnil inc 0))))

      ;; Track by destination
      (when (= (:decision result) :blocked)
        (swap! stats update-in [:blocked-ips (:dest-ip event)] (fnil inc 0)))

      (assoc event :result result))

    :bind
    (let [result (evaluate-bind-policy event policy-config)]
      (swap! stats update :bind-attempts inc)
      (if (= (:decision result) :allowed)
        (swap! stats update :bind-allowed inc)
        (swap! stats update :bind-blocked inc))

      (assoc event :result result))))

;;; ============================================================================
;;; Part 8: Display Functions
;;; ============================================================================

(defn format-timestamp
  "Format timestamp for display"
  [ts]
  (let [instant (Instant/ofEpochMilli ts)
        ldt (LocalDateTime/ofInstant instant (ZoneId/systemDefault))
        formatter (DateTimeFormatter/ofPattern "HH:mm:ss.SSS")]
    (.format ldt formatter)))

(defn display-lsm-info
  "Display LSM network enforcer information"
  []
  (println "\nLSM Network Security Enforcer:")
  (println "===============================================")
  (println "")
  (println "  LSM Hooks:")
  (println "    socket_connect - Control outbound connections")
  (println "    socket_bind    - Control port binding")
  (println "")
  (println "  Mode: MONITORING (simulation)")
  (println "")
  (println "  Blocked Ports:")
  (println "    23 (Telnet), 135 (RPC), 139 (NetBIOS)")
  (println "    445 (SMB), 3389 (RDP), 6667 (IRC)")
  (println "")
  (println "  Blocked Networks:")
  (println "    192.0.2.0/24 (TEST-NET-1)")
  (println "    198.51.100.0/24 (TEST-NET-2)")
  (println "    203.0.113.0/24 (TEST-NET-3)")
  (println "")
  (println "  Policies:")
  (println "    - Rate limit: max 100 connections/minute")
  (println "    - Privileged ports: root only")
  (println "==============================================="))

(defn display-connect-event
  "Display a connection event"
  [event]
  (let [{:keys [pid uid dest-ip dest-port protocol comm timestamp result]} event
        {:keys [decision reason]} result
        time-str (format-timestamp timestamp)
        ip-str (u32->ip dest-ip)
        status (if (= decision :allowed) "OK " "BLK")]
    (printf "%s %s %-6d %-5d %-8s %-4s %-15s:%-5d %s\n"
            status time-str pid uid comm
            (name protocol) ip-str dest-port reason)))

(defn display-bind-event
  "Display a bind event"
  [event]
  (let [{:keys [pid uid port comm timestamp result]} event
        {:keys [decision reason]} result
        time-str (format-timestamp timestamp)
        status (if (= decision :allowed) "OK " "BLK")]
    (printf "%s %s %-6d %-5d %-8s BIND *:%-5d              %s\n"
            status time-str pid uid comm port reason)))

(defn display-event
  "Display a network event"
  [event]
  (case (:type event)
    :connect (display-connect-event event)
    :bind (display-bind-event event)))

(defn display-events-header
  "Display header for events table"
  []
  (println "\n    TIME         PID    UID   COMM     PROTO DESTINATION         RESULT")
  (println "================================================================================"))

(defn display-statistics
  "Display network statistics"
  [{:keys [total allowed blocked rate-limited bind-attempts bind-allowed bind-blocked
           blocked-by-reason violations-by-uid blocked-ips]}]
  (println "\nNetwork Statistics:")
  (println "===============================================")
  (println "  Connection Attempts:")
  (println (format "    Total      : %,d" (or total 0)))
  (println (format "    Allowed    : %,d (%.1f%%)"
                   (or allowed 0)
                   (* 100.0 (/ (or allowed 0) (max 1 (or total 1))))))
  (println (format "    Blocked    : %,d (%.1f%%)"
                   (or blocked 0)
                   (* 100.0 (/ (or blocked 0) (max 1 (or total 1))))))
  (println (format "    Rate Limited: %,d" (or rate-limited 0)))
  (println "")
  (println "  Bind Attempts:")
  (println (format "    Total      : %,d" (or bind-attempts 0)))
  (println (format "    Allowed    : %,d" (or bind-allowed 0)))
  (println (format "    Blocked    : %,d" (or bind-blocked 0)))
  (println "")
  (when (seq blocked-by-reason)
    (println "  Blocks by Reason:")
    (doseq [[reason count] (sort-by val > blocked-by-reason)]
      (println (format "    %-40s: %,d" reason count)))
    (println ""))
  (when (seq violations-by-uid)
    (println "  Violations by UID:")
    (doseq [[uid count] (sort-by val > violations-by-uid)]
      (let [uid-name (case uid
                       0 "root"
                       65534 "nobody"
                       (str "user" uid))]
        (println (format "    %-10s (UID %5d): %,d violations" uid-name uid count))))
    (println ""))
  (when (seq blocked-ips)
    (println "  Top Blocked Destinations:")
    (doseq [[ip count] (take 5 (sort-by val > blocked-ips))]
      (println (format "    %-15s: %,d attempts" (u32->ip ip) count))))
  (println "==============================================="))

(defn display-security-assessment
  "Display security assessment based on events"
  [stats]
  (let [{:keys [blocked total rate-limited violations-by-uid]} stats
        block-rate (/ (or blocked 0) (max 1 (or total 1)))]
    (println "\nSecurity Assessment:")
    (println "===============================================")

    ;; Check for high block rate
    (if (> block-rate 0.3)
      (println "  [!] HIGH: Over 30% of connections blocked")
      (println "  [OK] Block rate within normal range"))

    ;; Check for rate limiting
    (when (and rate-limited (> rate-limited 5))
      (println (format "  [!] WARNING: %d connections rate-limited" rate-limited)))

    ;; Check for non-root violations
    (let [non-root-violations (dissoc violations-by-uid 0)]
      (when (seq non-root-violations)
        (println "  [!] Policy violations by non-root users:")
        (doseq [[uid cnt] non-root-violations]
          (println (format "      UID %d: %d violations" uid cnt)))))

    (println "===============================================")))

;;; ============================================================================
;;; Part 9: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 9.3: Network Security Enforcer ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [blocked-ips-map (create-blocked-ips-map)
        blocked-ports-map (create-blocked-ports-map)
        stats-map (create-stats-map)
        rate-limit-map (create-rate-limit-map)
        violations-map (create-violations-map)]
    (println "  Blocked IPs map created (FD:" (:fd blocked-ips-map) ")")
    (println "  Blocked ports map created (FD:" (:fd blocked-ports-map) ")")
    (println "  Stats map created (FD:" (:fd stats-map) ")")
    (println "  Rate limit map created (FD:" (:fd rate-limit-map) ")")
    (println "  Violations map created (FD:" (:fd violations-map) ")")

    ;; Initialize stats
    (doseq [i (range 4)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create network stats program
      (println "\nStep 3: Creating network stats program...")
      (let [program (create-network-stats-program (:fd stats-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :tracepoint
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display LSM info
            (println "\nStep 5: LSM hook information...")
            (display-lsm-info)

            ;; Step 6: Setup blocked IPs and ports
            (println "\nStep 6: Configuring network policies...")
            (let [blocked-ips #{(ip->u32 "192.0.2.1")
                                (ip->u32 "198.51.100.1")
                                (ip->u32 "203.0.113.1")}
                  blocked-ports BLOCKED_PORTS
                  policy-config {:restrict-public-ports false
                                 :restricted-bind-ports #{}}]

              (println "  Blocked IPs:" (count blocked-ips))
              (doseq [ip blocked-ips]
                (println "    -" (u32->ip ip)))
              (println "  Blocked ports:" (count blocked-ports))
              (println "    -" (str/join ", " (sort blocked-ports)))

              ;; Update BPF maps with blocked entries
              (doseq [ip blocked-ips]
                (bpf/map-update blocked-ips-map ip (byte 1)))
              (doseq [port blocked-ports]
                (bpf/map-update blocked-ports-map (short port) (byte 1)))

              ;; Step 7: Simulate network events
              (println "\nStep 7: Simulating network events...")
              (let [num-events 60
                    _ (println (format "  Generating %d network events..." num-events))
                    events (simulate-network-events num-events)
                    rate-map (atom {})
                    stats (atom {:total 0 :allowed 0 :blocked 0 :rate-limited 0
                                 :bind-attempts 0 :bind-allowed 0 :bind-blocked 0
                                 :blocked-by-reason {} :violations-by-uid {}
                                 :blocked-ips {}})
                    processed-events (mapv #(process-network-event
                                              % blocked-ips blocked-ports
                                              rate-map policy-config stats)
                                           events)]

                ;; Step 8: Display events
                (println "\nStep 8: Network events (showing blocked first)...")
                (display-events-header)
                (let [sorted-events (sort-by (fn [e]
                                               (if (= (get-in e [:result :decision]) :blocked)
                                                 0 1))
                                             processed-events)]
                  (doseq [event (take 25 sorted-events)]
                    (display-event event))
                  (println (format "  ... and %d more events" (- num-events 25))))

                ;; Step 9: Display statistics
                (println "\nStep 9: Network statistics...")
                (display-statistics @stats)

                ;; Step 10: Security assessment
                (println "\nStep 10: Security assessment...")
                (display-security-assessment @stats)

                ;; Step 11: Update BPF maps
                (println "\nStep 11: Updating BPF maps...")
                (bpf/map-update stats-map 0 (:total @stats))
                (bpf/map-update stats-map 1 (:blocked @stats))
                (bpf/map-update stats-map 2 (:allowed @stats))
                (bpf/map-update stats-map 3 (or (:rate-limited @stats) 0))

                (println (format "  stats[0] (total)       = %,d" (bpf/map-lookup stats-map 0)))
                (println (format "  stats[1] (blocked)     = %,d" (bpf/map-lookup stats-map 1)))
                (println (format "  stats[2] (allowed)     = %,d" (bpf/map-lookup stats-map 2)))
                (println (format "  stats[3] (rate_limited)= %,d" (bpf/map-lookup stats-map 3)))))

            ;; Step 12: Cleanup
            (println "\nStep 12: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map blocked-ips-map)
        (bpf/close-map blocked-ports-map)
        (bpf/close-map stats-map)
        (bpf/close-map rate-limit-map)
        (bpf/close-map violations-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 9.3 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test IP utilities
  (ip->u32 "192.168.1.1")     ; => 3232235777
  (u32->ip 3232235777)         ; => "192.168.1.1"
  (is-private-ip? (ip->u32 "192.168.1.1"))  ; true
  (is-private-ip? (ip->u32 "8.8.8.8"))      ; false

  ;; Test policy evaluation
  (evaluate-connect-policy
    {:pid 1234 :uid 1000 :dest-ip (ip->u32 "192.0.2.1") :dest-port 80 :protocol :tcp}
    #{(ip->u32 "192.0.2.1")}
    #{}
    {}
    {})

  ;; Test bind policy
  (evaluate-bind-policy
    {:uid 1000 :port 80}
    {})
  )
