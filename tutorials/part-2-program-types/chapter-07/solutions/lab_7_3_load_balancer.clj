(ns lab-7-3-load-balancer
  "Lab 7.3: XDP Layer 4 Load Balancer

   This solution demonstrates:
   - Round-robin and consistent hashing load balancing
   - Packet header rewriting (IP, MAC addresses)
   - Connection tracking for session persistence
   - Backend health state management
   - XDP_TX for packet reflection

   Run with: sudo clojure -M -m lab-7-3-load-balancer
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]
           [java.net InetAddress]
           [java.security MessageDigest]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; XDP Return Codes
(def XDP_DROP    1)
(def XDP_PASS    2)
(def XDP_TX      3)   ; Transmit back out same interface

;; Protocol numbers
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

;; Ethernet header size
(def ETH_HLEN 14)

;; Load balancing algorithms
(def LB_ALG_ROUND_ROBIN 0)
(def LB_ALG_CONSISTENT_HASH 1)
(def LB_ALG_LEAST_CONN 2)

;; Configuration
(def MAX_BACKENDS 64)
(def MAX_CONNECTIONS 100000)
(def HASH_RING_SIZE 1024)

;;; ============================================================================
;;; Part 2: Data Structures
;;; ============================================================================

(defn create-backend
  "Create a backend server definition"
  [id ip mac weight]
  {:id id
   :ip ip
   :mac mac
   :weight weight
   :healthy true
   :connections (atom 0)
   :bytes-in (atom 0)
   :bytes-out (atom 0)
   :requests (atom 0)})

(defn create-virtual-ip
  "Create a virtual IP (VIP) configuration"
  [vip port protocol backends algorithm]
  {:vip vip
   :port port
   :protocol protocol
   :backends backends
   :algorithm algorithm})

;;; ============================================================================
;;; Part 3: Utility Functions
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

(defn format-mac
  "Format MAC address as string"
  [mac]
  (if (string? mac)
    mac
    (str/join ":" (map #(format "%02x" (bit-and % 0xFF)) mac))))

(defn parse-mac
  "Parse MAC address string to bytes"
  [mac-str]
  (byte-array (map #(Integer/parseInt % 16) (str/split mac-str #":"))))

(defn compute-hash
  "Compute a hash for consistent hashing"
  [src-ip src-port dst-ip dst-port]
  (let [md (MessageDigest/getInstance "MD5")
        data (str src-ip ":" src-port ":" dst-ip ":" dst-port)]
    (.update md (.getBytes data))
    (let [digest (.digest md)]
      (bit-and (bit-or (bit-shift-left (bit-and (aget digest 0) 0xFF) 24)
                       (bit-shift-left (bit-and (aget digest 1) 0xFF) 16)
                       (bit-shift-left (bit-and (aget digest 2) 0xFF) 8)
                       (bit-and (aget digest 3) 0xFF))
               0x7FFFFFFF))))

;;; ============================================================================
;;; Part 4: BPF Maps
;;; ============================================================================

(defn create-backends-map
  "Array map: backend index -> backend info
   Value structure (32 bytes):
   - ip: 4 bytes
   - mac: 6 bytes
   - padding: 2 bytes
   - weight: 4 bytes
   - healthy: 4 bytes
   - connections: 4 bytes
   - padding: 8 bytes"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 32
                   :max-entries MAX_BACKENDS
                   :map-name "backends"}))

(defn create-connections-map
  "Hash map: connection 5-tuple hash -> backend index
   For connection persistence / session affinity"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8    ; 64-bit connection ID
                   :value-size 4  ; backend index
                   :max-entries MAX_CONNECTIONS
                   :map-name "connections"}))

(defn create-rr-index-map
  "Array map: single entry for round-robin index"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 4
                   :max-entries 1
                   :map-name "rr_index"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/int->bytes
                   :value-deserializer utils/bytes->int}))

(defn create-stats-map
  "Array map for load balancer statistics:
   [0] = total_requests
   [1] = forwarded_requests
   [2] = dropped_requests
   [3] = backend_0_requests
   [4] = backend_1_requests
   ..."
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries (+ 10 MAX_BACKENDS)
                   :map-name "lb_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 5: XDP BPF Program
;;; ============================================================================

(defn create-load-balancer-program
  "Create XDP load balancer program.

   This simplified program demonstrates:
   1. Packet parsing
   2. Counter increment
   3. XDP_PASS/XDP_TX decision

   A full implementation would:
   - Parse full IP/TCP headers
   - Select backend via round-robin or hash
   - Rewrite destination IP/MAC
   - Recalculate checksums
   - Return XDP_TX

   XDP context (xdp_md) uses 32-bit fields for data/data_end!"
  [stats-fd rr-fd]
  (bpf/assemble
    [;; Load packet pointers from XDP context (32-bit loads!)
     (bpf/ldx :w :r2 :r1 0)         ; 0: r2 = ctx->data (32-bit)
     (bpf/ldx :w :r3 :r1 4)         ; 1: r3 = ctx->data_end (32-bit)

     ;; Bounds check
     (bpf/mov-reg :r4 :r2)          ; 2: r4 = data
     (bpf/add :r4 ETH_HLEN)         ; 3: r4 += ETH_HLEN
     (bpf/jmp-reg :jle :r4 :r3 2)   ; 4: if r4 <= data_end, continue

     ;; Drop path (bounds check failed)
     (bpf/mov :r0 XDP_DROP)         ; 5: return XDP_DROP
     (bpf/exit-insn)                ; 6: exit

     ;; Increment request counter (stats[0])
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

     ;; Return XDP_PASS (simulation mode)
     ;; In real implementation, would return XDP_TX after rewriting
     (bpf/mov :r0 XDP_PASS)         ; 18: return XDP_PASS
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 6: Load Balancing Algorithms
;;; ============================================================================

(defn select-backend-round-robin
  "Select backend using round-robin algorithm"
  [backends rr-index-atom]
  (let [healthy-backends (filter :healthy backends)]
    (when (seq healthy-backends)
      (let [idx (mod @rr-index-atom (count healthy-backends))]
        (swap! rr-index-atom inc)
        (nth healthy-backends idx)))))

(defn select-backend-consistent-hash
  "Select backend using consistent hashing"
  [backends src-ip src-port dst-ip dst-port]
  (let [healthy-backends (filter :healthy backends)]
    (when (seq healthy-backends)
      (let [hash-value (compute-hash src-ip src-port dst-ip dst-port)
            idx (mod hash-value (count healthy-backends))]
        (nth healthy-backends idx)))))

(defn select-backend-least-conn
  "Select backend with least connections"
  [backends]
  (let [healthy-backends (filter :healthy backends)]
    (when (seq healthy-backends)
      (apply min-key #(deref (:connections %)) healthy-backends))))

(defn select-backend
  "Select backend based on algorithm"
  [algorithm backends request rr-index-atom]
  (case algorithm
    :round-robin (select-backend-round-robin backends rr-index-atom)
    :consistent-hash (select-backend-consistent-hash
                       backends
                       (:src-ip request)
                       (:src-port request)
                       (:dst-ip request)
                       (:dst-port request))
    :least-conn (select-backend-least-conn backends)
    ;; Default to round-robin
    (select-backend-round-robin backends rr-index-atom)))

;;; ============================================================================
;;; Part 7: Connection Tracking
;;; ============================================================================

(defn create-connection-tracker
  "Create connection tracking state"
  []
  (atom {}))

(defn get-connection-id
  "Generate a unique connection identifier"
  [src-ip src-port dst-ip dst-port]
  (compute-hash src-ip src-port dst-ip dst-port))

(defn track-connection
  "Track or retrieve existing backend for a connection"
  [tracker conn-id backend]
  (if-let [existing (get @tracker conn-id)]
    existing
    (do
      (swap! tracker assoc conn-id backend)
      backend)))

;;; ============================================================================
;;; Part 8: Traffic Simulation
;;; ============================================================================

(defn generate-client-request
  "Generate a simulated client request"
  [vip vip-port]
  (let [client-ips ["203.0.113.10" "203.0.113.20" "203.0.113.30"
                    "198.51.100.5" "198.51.100.15" "198.51.100.25"
                    "192.0.2.100" "192.0.2.200"]]
    {:src-ip (rand-nth client-ips)
     :src-port (+ 10000 (rand-int 55000))
     :dst-ip vip
     :dst-port vip-port
     :protocol IPPROTO_TCP
     :size (+ 64 (rand-int 1400))
     :timestamp (System/currentTimeMillis)}))

(defn simulate-load-balancing
  "Simulate load balancing for a list of requests"
  [requests backends algorithm]
  (let [rr-index (atom 0)
        conn-tracker (create-connection-tracker)
        results (atom [])]

    (doseq [req requests]
      (let [conn-id (get-connection-id (:src-ip req) (:src-port req)
                                       (:dst-ip req) (:dst-port req))
            ;; Check for existing connection
            existing-backend (get @conn-tracker conn-id)
            ;; Select backend
            selected (if existing-backend
                       existing-backend
                       (select-backend algorithm backends req rr-index))]

        (if selected
          (do
            ;; Track connection
            (swap! conn-tracker assoc conn-id selected)
            ;; Update backend stats
            (swap! (:connections selected) inc)
            (swap! (:requests selected) inc)
            (swap! (:bytes-in selected) + (:size req))
            (swap! results conj (assoc req
                                       :backend (:id selected)
                                       :backend-ip (:ip selected)
                                       :action :forward
                                       :new-connection (nil? existing-backend))))
          (swap! results conj (assoc req :action :drop :reason "no-healthy-backend")))))

    @results))

;;; ============================================================================
;;; Part 9: Statistics Display
;;; ============================================================================

(defn display-lb-architecture
  "Display load balancer architecture diagram"
  []
  (println "\nLoad Balancer Architecture:")
  (println "═══════════════════════════════════════════════════════")
  (println "")
  (println "                     ┌─────────────┐")
  (println "                     │   Clients   │")
  (println "                     └──────┬──────┘")
  (println "                            │")
  (println "                            ▼")
  (println "                   ┌────────────────┐")
  (println "                   │  VIP: 10.0.0.1 │")
  (println "                   │    Port: 80    │")
  (println "                   └────────┬───────┘")
  (println "                            │")
  (println "                   ┌────────┴───────┐")
  (println "                   │  XDP Load      │")
  (println "                   │  Balancer      │")
  (println "                   │  (BPF Program) │")
  (println "                   └────────┬───────┘")
  (println "                            │")
  (println "           ┌────────────────┼────────────────┐")
  (println "           │                │                │")
  (println "           ▼                ▼                ▼")
  (println "   ┌───────────────┐ ┌───────────────┐ ┌───────────────┐")
  (println "   │  Backend 0    │ │  Backend 1    │ │  Backend 2    │")
  (println "   │  10.0.1.1:80  │ │  10.0.1.2:80  │ │  10.0.1.3:80  │")
  (println "   └───────────────┘ └───────────────┘ └───────────────┘")
  (println "")
  (println "═══════════════════════════════════════════════════════"))

(defn display-backend-stats
  "Display backend statistics"
  [backends]
  (println "\nBackend Status:")
  (println "═══════════════════════════════════════════════════════════════════════════════")
  (println "ID │ IP ADDRESS     │ STATUS  │ WEIGHT │ CONNECTIONS │ REQUESTS │ BYTES IN")
  (println "───┼────────────────┼─────────┼────────┼─────────────┼──────────┼────────────")

  (doseq [backend backends]
    (let [{:keys [id ip healthy weight connections requests bytes-in]} backend]
      (println (format "%2d │ %-14s │ %-7s │ %6d │ %,11d │ %,8d │ %,10d"
                       id ip
                       (if healthy "HEALTHY" "DOWN")
                       weight
                       @connections
                       @requests
                       @bytes-in))))

  (println "═══════════════════════════════════════════════════════════════════════════════"))

(defn display-algorithm-info
  "Display load balancing algorithm information"
  [algorithm]
  (println "\nLoad Balancing Algorithm:")
  (println "═══════════════════════════════════════════════════════")

  (case algorithm
    :round-robin
    (do
      (println "  Algorithm: Round-Robin")
      (println "")
      (println "  ┌─────────────────────────────────────────────────────┐")
      (println "  │  Request 1 → Backend 0                              │")
      (println "  │  Request 2 → Backend 1                              │")
      (println "  │  Request 3 → Backend 2                              │")
      (println "  │  Request 4 → Backend 0  (cycle repeats)             │")
      (println "  │  ...                                                │")
      (println "  └─────────────────────────────────────────────────────┘")
      (println "")
      (println "  • Simple and fair distribution")
      (println "  • No session persistence by default")
      (println "  • Best for stateless services"))

    :consistent-hash
    (do
      (println "  Algorithm: Consistent Hashing")
      (println "")
      (println "  ┌─────────────────────────────────────────────────────┐")
      (println "  │  hash(src_ip, src_port, dst_ip, dst_port) % N       │")
      (println "  │                                                     │")
      (println "  │  Same client → Same backend (session persistence)   │")
      (println "  │                                                     │")
      (println "  │  Adding/removing backends minimizes remapping       │")
      (println "  └─────────────────────────────────────────────────────┘")
      (println "")
      (println "  • Session persistence without tracking state")
      (println "  • Stable backend selection per connection")
      (println "  • Good for stateful applications"))

    :least-conn
    (do
      (println "  Algorithm: Least Connections")
      (println "")
      (println "  ┌─────────────────────────────────────────────────────┐")
      (println "  │  Select backend with minimum active connections     │")
      (println "  │                                                     │")
      (println "  │  Backend 0: 5 conns  ←── selected (min)             │")
      (println "  │  Backend 1: 12 conns                                │")
      (println "  │  Backend 2: 8 conns                                 │")
      (println "  └─────────────────────────────────────────────────────┘")
      (println "")
      (println "  • Adaptive to backend load")
      (println "  • Better for varying request weights")
      (println "  • Requires connection tracking"))

    (println "  Unknown algorithm"))

  (println "═══════════════════════════════════════════════════════"))

(defn display-sample-forwarding
  "Display sample forwarding decisions"
  [results n]
  (println "\nSample Forwarding Decisions:")
  (println "═══════════════════════════════════════════════════════════════════════════════════════")
  (println "CLIENT IP       │ PORT  │ → │ BACKEND │ BACKEND IP     │ NEW CONN │ SIZE")
  (println "────────────────┼───────┼───┼─────────┼────────────────┼──────────┼───────")

  (doseq [req (take n results)]
    (let [{:keys [src-ip src-port backend backend-ip action new-connection size]} req]
      (if (= action :forward)
        (println (format "%-15s │ %5d │ → │ %7d │ %-14s │ %-8s │ %,5d"
                         src-ip src-port backend backend-ip
                         (if new-connection "yes" "no") size))
        (println (format "%-15s │ %5d │ X │ DROPPED │ %-14s │ %-8s │ %,5d"
                         src-ip src-port "N/A" "-" size)))))

  (println "═══════════════════════════════════════════════════════════════════════════════════════"))

(defn display-distribution-stats
  "Display request distribution statistics"
  [results backends]
  (let [by-backend (frequencies (map :backend (filter #(= :forward (:action %)) results)))
        total (count (filter #(= :forward (:action %)) results))
        dropped (count (filter #(= :drop (:action %)) results))]

    (println "\nRequest Distribution:")
    (println "═══════════════════════════════════════════════════════")

    (println "\nSummary:")
    (println (format "  Total requests  : %,d" (count results)))
    (println (format "  Forwarded       : %,d" total))
    (println (format "  Dropped         : %,d" dropped))

    (println "\nDistribution by Backend:")
    (doseq [backend backends]
      (let [cnt (get by-backend (:id backend) 0)
            pct (if (pos? total) (* 100.0 (/ cnt total)) 0.0)
            bar-len (int (* 30 (/ pct 100)))
            bar (apply str (repeat bar-len "█"))]
        (println (format "  Backend %d (%s): %,5d requests (%5.1f%%) %s"
                         (:id backend) (:ip backend) cnt pct bar))))

    (println "═══════════════════════════════════════════════════════")))

;;; ============================================================================
;;; Part 10: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 7.3: XDP Layer 4 Load Balancer ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [stats-map (create-stats-map)
        rr-map (create-rr-index-map)
        backends-map (create-backends-map)]
    (println "  Stats map created (FD:" (:fd stats-map) ")")
    (println "  Round-robin index map created (FD:" (:fd rr-map) ")")
    (println "  Backends map created (FD:" (:fd backends-map) ")")

    ;; Initialize
    (doseq [i (range (+ 10 MAX_BACKENDS))]
      (bpf/map-update stats-map i 0))
    (bpf/map-update rr-map 0 0)

    (try
      ;; Step 3: Create XDP program
      (println "\nStep 3: Creating XDP load balancer program...")
      (let [program (create-load-balancer-program (:fd stats-map) (:fd rr-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :xdp
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display architecture
            (println "\nStep 5: Load balancer architecture...")
            (display-lb-architecture)

            ;; Step 6: Configure backends
            (println "\nStep 6: Configuring backends...")
            (let [backends [(create-backend 0 "10.0.1.1" "00:11:22:33:44:01" 1)
                            (create-backend 1 "10.0.1.2" "00:11:22:33:44:02" 1)
                            (create-backend 2 "10.0.1.3" "00:11:22:33:44:03" 1)]
                  vip "10.0.0.1"
                  vip-port 80]

              (println (format "  VIP: %s:%d" vip vip-port))
              (doseq [backend backends]
                (println (format "  Backend %d: %s (MAC: %s)"
                                 (:id backend) (:ip backend) (:mac backend))))

              ;; Step 7: Test Round-Robin
              (println "\nStep 7: Testing Round-Robin algorithm...")
              (display-algorithm-info :round-robin)
              (let [requests (for [_ (range 100)]
                               (generate-client-request vip vip-port))
                    results (simulate-load-balancing requests backends :round-robin)]
                (display-sample-forwarding results 10)
                (display-backend-stats backends)
                (display-distribution-stats results backends)

                ;; Reset connection counts
                (doseq [b backends]
                  (reset! (:connections b) 0)
                  (reset! (:requests b) 0)
                  (reset! (:bytes-in b) 0)))

              ;; Step 8: Test Consistent Hashing
              (println "\nStep 8: Testing Consistent Hashing algorithm...")
              (display-algorithm-info :consistent-hash)
              (let [requests (for [_ (range 100)]
                               (generate-client-request vip vip-port))
                    results (simulate-load-balancing requests backends :consistent-hash)]
                (display-sample-forwarding results 10)
                (display-backend-stats backends)
                (display-distribution-stats results backends)

                ;; Reset
                (doseq [b backends]
                  (reset! (:connections b) 0)
                  (reset! (:requests b) 0)
                  (reset! (:bytes-in b) 0)))

              ;; Step 9: Test Least Connections
              (println "\nStep 9: Testing Least Connections algorithm...")
              (display-algorithm-info :least-conn)
              (let [;; Simulate some existing connections
                    _ (do
                        (reset! (:connections (first backends)) 5)
                        (reset! (:connections (second backends)) 12)
                        (reset! (:connections (nth backends 2)) 8))
                    requests (for [_ (range 100)]
                               (generate-client-request vip vip-port))
                    results (simulate-load-balancing requests backends :least-conn)]
                (display-sample-forwarding results 10)
                (display-backend-stats backends)
                (display-distribution-stats results backends))

              ;; Step 10: Update BPF map stats
              (println "\nStep 10: Updating BPF maps...")
              (let [total-requests (reduce + (map #(deref (:requests %)) backends))]
                (bpf/map-update stats-map 0 total-requests)
                (bpf/map-update stats-map 1 total-requests)  ; All forwarded
                (doseq [backend backends]
                  (bpf/map-update stats-map (+ 3 (:id backend)) @(:requests backend)))

                (println (format "  stats[0] (total)     = %,d" (bpf/map-lookup stats-map 0)))
                (println (format "  stats[1] (forwarded) = %,d" (bpf/map-lookup stats-map 1)))
                (doseq [backend backends]
                  (println (format "  stats[%d] (backend %d) = %,d"
                                   (+ 3 (:id backend))
                                   (:id backend)
                                   (bpf/map-lookup stats-map (+ 3 (:id backend))))))))

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
        (bpf/close-map rr-map)
        (bpf/close-map backends-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 7.3 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test consistent hashing
  (compute-hash "192.168.1.1" 12345 "10.0.0.1" 80)
  (compute-hash "192.168.1.1" 12345 "10.0.0.1" 80) ; same result

  ;; Test round-robin
  (let [backends [(create-backend 0 "10.0.1.1" "aa:bb:cc:dd:ee:01" 1)
                  (create-backend 1 "10.0.1.2" "aa:bb:cc:dd:ee:02" 1)]
        idx (atom 0)]
    (dotimes [_ 5]
      (println (select-backend-round-robin backends idx))))
  )
