(ns lab-11-1-network-policy
  "Lab 11.1: Container Network Policy Enforcer

   This solution demonstrates:
   - Cgroup BPF concepts for container network policy
   - IP/port-based connection filtering
   - Private IP range detection (RFC 1918)
   - Policy-based network access control
   - Connection statistics tracking

   Note: Cgroup BPF requires cgroup v2 and kernel 4.10+.
   This solution simulates cgroup concepts using tracepoint as fallback.

   Run with: sudo clojure -M -m lab-11-1-network-policy
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

;; Common ports
(def PORT_DNS 53)
(def PORT_HTTP 80)
(def PORT_HTTPS 443)
(def PORT_SSH 22)

;; Policy actions
(def ACTION_ALLOW 1)
(def ACTION_DENY 0)

;; Policy types
(def POLICY_FRONTEND :frontend)
(def POLICY_DATABASE :database)
(def POLICY_WORKER :worker)

;;; ============================================================================
;;; Part 2: IP Address Utilities
;;; ============================================================================

(defn ip->u32
  "Convert IP string to 32-bit unsigned integer (host byte order)"
  [ip-str]
  (let [parts (map #(Long/parseLong %) (str/split ip-str #"\."))]
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

;; Private IP ranges (RFC 1918)
(def PRIVATE_10_START (ip->u32 "10.0.0.0"))
(def PRIVATE_10_END (ip->u32 "10.255.255.255"))
(def PRIVATE_172_START (ip->u32 "172.16.0.0"))
(def PRIVATE_172_END (ip->u32 "172.31.255.255"))
(def PRIVATE_192_START (ip->u32 "192.168.0.0"))
(def PRIVATE_192_END (ip->u32 "192.168.255.255"))
(def LOCALHOST (ip->u32 "127.0.0.1"))

(defn is-private-ip?
  "Check if IP is in private range (RFC 1918)"
  [ip-u32]
  (or
    ;; 10.0.0.0/8
    (and (>= ip-u32 PRIVATE_10_START) (<= ip-u32 PRIVATE_10_END))
    ;; 172.16.0.0/12
    (and (>= ip-u32 PRIVATE_172_START) (<= ip-u32 PRIVATE_172_END))
    ;; 192.168.0.0/16
    (and (>= ip-u32 PRIVATE_192_START) (<= ip-u32 PRIVATE_192_END))))

(defn is-localhost?
  "Check if IP is localhost"
  [ip-u32]
  (= 127 (bit-and (bit-shift-right ip-u32 24) 0xFF)))

;;; ============================================================================
;;; Part 3: Custom Serializers for Unsigned Values
;;; ============================================================================

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

;;; ============================================================================
;;; Part 4: BPF Maps
;;; ============================================================================

(defn create-allowed-ips-map
  "Hash map: IP (u32) -> 1 (allowed)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 1
                   :max-entries 10000
                   :map-name "allowed_ips"
                   :key-serializer u32->bytes
                   :key-deserializer bytes->u32
                   :value-serializer (fn [v] (byte-array [(byte v)]))
                   :value-deserializer (fn [b] (aget b 0))}))

(defn create-allowed-ports-map
  "Hash map: Port (u16) -> 1 (allowed)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 2
                   :value-size 1
                   :max-entries 1000
                   :map-name "allowed_ports"
                   :key-serializer utils/short->bytes
                   :key-deserializer utils/bytes->short
                   :value-serializer (fn [v] (byte-array [(byte v)]))
                   :value-deserializer (fn [b] (aget b 0))}))

(defn create-stats-map
  "Array map for connection statistics:
   [0] = total_connections
   [1] = allowed_connections
   [2] = denied_connections
   [3] = private_allowed"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4
                   :map-name "conn_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-violations-map
  "Hash map: Container ID (u64) -> violation count (u64)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8
                   :value-size 8
                   :max-entries 1024
                   :map-name "violations"
                   :key-serializer utils/long->bytes
                   :key-deserializer utils/bytes->long
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 5: BPF Program (Stats Tracker)
;;; ============================================================================

(defn create-connection-stats-program
  "Create BPF program that tracks connection statistics.

   This demonstrates the cgroup/sock_addr hook concept:
   1. Receives context with socket address info
   2. Tracks connection statistics per policy decision
   3. Always returns 1 (ALLOW) for monitoring

   Note: Real cgroup programs use :cgroup-sock-addr program type.
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

     ;; Return 1 (ACTION_ALLOW) - monitoring only
     (bpf/mov :r0 ACTION_ALLOW)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 6: Policy Definitions
;;; ============================================================================

(def frontend-policy
  "Policy for frontend containers - allows HTTP/HTTPS to external"
  {:name "Frontend"
   :allowed-ports #{PORT_HTTP PORT_HTTPS PORT_DNS}
   :allowed-ips #{}  ; Will be populated with specific API IPs
   :allow-private true
   :allow-public-standard-ports true})

(def database-policy
  "Policy for database containers - deny ALL external"
  {:name "Database"
   :allowed-ports #{}
   :allowed-ips #{}
   :allow-private true
   :allow-public-standard-ports false})

(def worker-policy
  "Policy for background worker containers"
  {:name "Worker"
   :allowed-ports #{5672 9000}  ; AMQP, MinIO
   :allowed-ips #{}
   :allow-private true
   :allow-public-standard-ports false})

(defn get-policy [policy-type]
  (case policy-type
    :frontend frontend-policy
    :database database-policy
    :worker worker-policy
    frontend-policy))

;;; ============================================================================
;;; Part 7: Policy Evaluation
;;; ============================================================================

(defn evaluate-connection
  "Evaluate connection against policy.
   Returns {:decision :allowed/:denied :reason string}"
  [connection policy]
  (let [{:keys [dest-ip dest-port]} connection
        {:keys [allowed-ports allowed-ips allow-private allow-public-standard-ports]} policy]
    (cond
      ;; Always allow localhost
      (is-localhost? dest-ip)
      {:decision :allowed :reason "Localhost connection"}

      ;; Always allow private IPs if policy permits
      (and allow-private (is-private-ip? dest-ip))
      {:decision :allowed :reason "Private network allowed"}

      ;; Check allowed IPs whitelist
      (contains? allowed-ips dest-ip)
      {:decision :allowed :reason "Whitelisted IP"}

      ;; Check allowed ports
      (contains? allowed-ports dest-port)
      {:decision :allowed :reason (format "Allowed port %d" dest-port)}

      ;; DNS always allowed (port 53)
      (= dest-port PORT_DNS)
      {:decision :allowed :reason "DNS traffic allowed"}

      ;; Public IP to standard ports (if enabled)
      (and allow-public-standard-ports
           (contains? #{PORT_HTTP PORT_HTTPS} dest-port))
      {:decision :allowed :reason "Standard port to public IP"}

      :else
      {:decision :denied :reason "Not in policy whitelist"})))

;;; ============================================================================
;;; Part 8: Simulated Connection Events
;;; ============================================================================

(defn generate-connection-event
  "Generate a simulated connection event"
  []
  (let [dest-ips [(ip->u32 "192.168.1.100")   ; Private
                  (ip->u32 "10.0.1.50")        ; Private (RabbitMQ)
                  (ip->u32 "10.0.2.100")       ; Private (MinIO)
                  (ip->u32 "8.8.8.8")          ; Google DNS
                  (ip->u32 "1.1.1.1")          ; Cloudflare DNS
                  (ip->u32 "93.184.216.34")    ; example.com
                  (ip->u32 "13.107.42.14")     ; Microsoft
                  (ip->u32 "142.250.80.46")    ; Google
                  (ip->u32 "127.0.0.1")]       ; Localhost
        ports [PORT_HTTP PORT_HTTPS PORT_DNS PORT_SSH
               5672 9000  ; Worker services
               8080 3306 5432 27017  ; Internal services
               6379 11211]  ; Cache
        containers ["frontend-1" "frontend-2" "database-1" "worker-1" "worker-2"]]
    {:container-id (rand-nth containers)
     :pid (+ 1000 (rand-int 30000))
     :dest-ip (rand-nth dest-ips)
     :dest-port (rand-nth ports)
     :timestamp (System/currentTimeMillis)}))

(defn simulate-connections
  "Simulate connection events from multiple containers"
  [num-events]
  (repeatedly num-events generate-connection-event))

;;; ============================================================================
;;; Part 9: Event Processing and Statistics
;;; ============================================================================

(defn get-container-policy-type
  "Determine policy type based on container ID"
  [container-id]
  (cond
    (str/starts-with? container-id "frontend") :frontend
    (str/starts-with? container-id "database") :database
    (str/starts-with? container-id "worker") :worker
    :else :frontend))

(defn process-connection-event
  "Process a connection event and update statistics"
  [event stats]
  (let [{:keys [container-id dest-ip dest-port]} event
        policy-type (get-container-policy-type container-id)
        policy (get-policy policy-type)
        result (evaluate-connection event policy)]

    ;; Update statistics
    (swap! stats update :total inc)
    (if (= (:decision result) :allowed)
      (do
        (swap! stats update :allowed inc)
        (when (is-private-ip? dest-ip)
          (swap! stats update :private-allowed inc)))
      (do
        (swap! stats update :denied inc)
        (swap! stats update-in [:violations-by-container container-id] (fnil inc 0))))

    ;; Track by policy type
    (swap! stats update-in [:by-policy policy-type (:decision result)] (fnil inc 0))

    ;; Track destinations
    (when (= (:decision result) :denied)
      (swap! stats update-in [:denied-destinations dest-ip] (fnil inc 0)))

    (assoc event
           :policy-type policy-type
           :policy-name (:name policy)
           :result result)))

;;; ============================================================================
;;; Part 10: Display Functions
;;; ============================================================================

(defn format-timestamp
  "Format timestamp for display"
  [ts]
  (let [instant (Instant/ofEpochMilli ts)
        ldt (LocalDateTime/ofInstant instant (ZoneId/systemDefault))
        formatter (DateTimeFormatter/ofPattern "HH:mm:ss.SSS")]
    (.format ldt formatter)))

(defn display-cgroup-info
  "Display cgroup network policy information"
  []
  (println "\nCgroup Network Policy Enforcer:")
  (println "===============================================")
  (println "")
  (println "  Cgroup Hook: sock_addr/connect4")
  (println "  Mode: PER-CONTAINER POLICY ENFORCEMENT")
  (println "")
  (println "  Policies:")
  (println "    Frontend: HTTP/HTTPS to anywhere + private")
  (println "    Database: Only private networks")
  (println "    Worker:   Specific services (MQ, S3)")
  (println "")
  (println "  Default Behaviors:")
  (println "    - Private IPs (RFC 1918) always allowed")
  (println "    - Localhost (127.0.0.1) always allowed")
  (println "    - DNS (port 53) always allowed")
  (println "==============================================="))

(defn display-connection-event
  "Display a connection event"
  [event]
  (let [{:keys [container-id dest-ip dest-port timestamp policy-name result]} event
        {:keys [decision reason]} result
        time-str (format-timestamp timestamp)
        ip-str (u32->ip dest-ip)
        status (if (= decision :allowed) "OK " "BLK")]
    (printf "%s %s %-12s %-10s %-15s:%-5d %s\n"
            status time-str container-id policy-name ip-str dest-port reason)))

(defn display-events-header
  "Display header for events table"
  []
  (println "\n    TIME         CONTAINER    POLICY     DESTINATION         RESULT")
  (println "================================================================================"))

(defn display-statistics
  "Display connection statistics"
  [{:keys [total allowed denied private-allowed by-policy violations-by-container denied-destinations]}]
  (println "\nConnection Statistics:")
  (println "===============================================")
  (println (format "  Total connections   : %,d" (or total 0)))
  (println (format "  Allowed             : %,d (%.1f%%)"
                   (or allowed 0)
                   (* 100.0 (/ (or allowed 0) (max 1 (or total 1))))))
  (println (format "  Denied              : %,d (%.1f%%)"
                   (or denied 0)
                   (* 100.0 (/ (or denied 0) (max 1 (or total 1))))))
  (println (format "  Private IP allowed  : %,d" (or private-allowed 0)))
  (println "")
  (println "  By Policy:")
  (doseq [[policy-type decisions] by-policy]
    (let [policy (get-policy policy-type)]
      (println (format "    %s:" (:name policy)))
      (println (format "      Allowed: %,d  Denied: %,d"
                       (get decisions :allowed 0)
                       (get decisions :denied 0)))))
  (println "")
  (when (seq violations-by-container)
    (println "  Violations by Container:")
    (doseq [[container count] (sort-by val > violations-by-container)]
      (println (format "    %-15s: %,d violations" container count)))
    (println ""))
  (when (seq denied-destinations)
    (println "  Top Denied Destinations:")
    (doseq [[ip count] (take 5 (sort-by val > denied-destinations))]
      (println (format "    %-15s: %,d attempts" (u32->ip ip) count))))
  (println "==============================================="))

(defn display-policy-summary
  "Display summary of policy effectiveness"
  [stats]
  (println "\nPolicy Effectiveness:")
  (println "===============================================")

  (let [{:keys [by-policy]} stats]
    (doseq [[policy-type decisions] by-policy]
      (let [policy (get-policy policy-type)
            allowed (get decisions :allowed 0)
            denied (get decisions :denied 0)
            total (+ allowed denied)]
        (when (pos? total)
          (println (format "  %s Policy:" (:name policy)))
          (println (format "    Allow rate: %.1f%%" (* 100.0 (/ allowed total))))
          (if (= policy-type :database)
            (if (zero? denied)
              (println "    [OK] No external connections attempted")
              (println (format "    [!] %d external connection attempts blocked" denied)))
            (when (pos? denied)
              (println (format "    [!] %d connections blocked by policy" denied))))))))

  (println "==============================================="))

;;; ============================================================================
;;; Part 11: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 11.1: Container Network Policy Enforcer ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [allowed-ips-map (create-allowed-ips-map)
        allowed-ports-map (create-allowed-ports-map)
        stats-map (create-stats-map)
        violations-map (create-violations-map)]
    (println "  Allowed IPs map created (FD:" (:fd allowed-ips-map) ")")
    (println "  Allowed ports map created (FD:" (:fd allowed-ports-map) ")")
    (println "  Stats map created (FD:" (:fd stats-map) ")")
    (println "  Violations map created (FD:" (:fd violations-map) ")")

    ;; Initialize stats
    (doseq [i (range 4)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create connection stats program
      (println "\nStep 3: Creating cgroup-style connection monitor program...")
      (let [program (create-connection-stats-program (:fd stats-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :tracepoint
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display cgroup info
            (println "\nStep 5: Cgroup hook information...")
            (display-cgroup-info)

            ;; Step 6: Configure policies
            (println "\nStep 6: Configuring container policies...")
            (println "  Frontend policy: HTTP/HTTPS + private networks")
            (println "  Database policy: Private networks only")
            (println "  Worker policy: MQ (5672) + S3 (9000) + private")

            ;; Add some specific allowed IPs for demo
            (let [api-ip (ip->u32 "1.2.3.4")]
              (bpf/map-update allowed-ips-map api-ip (byte 1))
              (println "  Added API endpoint to frontend whitelist:" (u32->ip api-ip)))

            ;; Step 7: Simulate connections
            (println "\nStep 7: Simulating container connections...")
            (let [num-events 50
                  _ (println (format "  Generating %d connection events..." num-events))
                  events (simulate-connections num-events)
                  stats (atom {:total 0 :allowed 0 :denied 0 :private-allowed 0
                               :by-policy {} :violations-by-container {}
                               :denied-destinations {}})
                  processed-events (mapv #(process-connection-event % stats) events)]

              ;; Step 8: Display events
              (println "\nStep 8: Connection events (showing denied first)...")
              (display-events-header)
              (let [sorted-events (sort-by (fn [e]
                                             (if (= (get-in e [:result :decision]) :denied)
                                               0 1))
                                           processed-events)]
                (doseq [event (take 25 sorted-events)]
                  (display-connection-event event))
                (println (format "  ... and %d more events" (- num-events 25))))

              ;; Step 9: Display statistics
              (println "\nStep 9: Connection statistics...")
              (display-statistics @stats)

              ;; Step 10: Policy summary
              (println "\nStep 10: Policy effectiveness...")
              (display-policy-summary @stats)

              ;; Step 11: Update BPF maps
              (println "\nStep 11: Updating BPF maps...")
              (bpf/map-update stats-map 0 (:total @stats))
              (bpf/map-update stats-map 1 (:allowed @stats))
              (bpf/map-update stats-map 2 (:denied @stats))
              (bpf/map-update stats-map 3 (or (:private-allowed @stats) 0))

              (println (format "  stats[0] (total)          = %,d" (bpf/map-lookup stats-map 0)))
              (println (format "  stats[1] (allowed)        = %,d" (bpf/map-lookup stats-map 1)))
              (println (format "  stats[2] (denied)         = %,d" (bpf/map-lookup stats-map 2)))
              (println (format "  stats[3] (private_allowed)= %,d" (bpf/map-lookup stats-map 3))))

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
        (bpf/close-map allowed-ips-map)
        (bpf/close-map allowed-ports-map)
        (bpf/close-map stats-map)
        (bpf/close-map violations-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 11.1 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test IP utilities
  (ip->u32 "192.168.1.1")
  (u32->ip (ip->u32 "192.168.1.1"))
  (is-private-ip? (ip->u32 "192.168.1.1"))  ; true
  (is-private-ip? (ip->u32 "8.8.8.8"))      ; false

  ;; Test policy evaluation
  (evaluate-connection
    {:dest-ip (ip->u32 "8.8.8.8") :dest-port 443}
    frontend-policy)

  (evaluate-connection
    {:dest-ip (ip->u32 "8.8.8.8") :dest-port 443}
    database-policy)
  )
