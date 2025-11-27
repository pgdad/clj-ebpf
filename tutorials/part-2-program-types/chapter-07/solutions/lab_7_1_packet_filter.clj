(ns lab-7-1-packet-filter
  "Lab 7.1: XDP Packet Filter

   This solution demonstrates:
   - XDP program structure and return codes
   - Parsing Ethernet, IP, and TCP/UDP headers
   - Filtering packets by IP address, port, and protocol
   - Counting filtered packets with BPF maps
   - Network byte order handling

   Run with: sudo clojure -M -m lab-7-1-packet-filter
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
(def XDP_ABORTED 0)  ; Error, packet dropped
(def XDP_DROP    1)  ; Drop the packet
(def XDP_PASS    2)  ; Pass to kernel network stack
(def XDP_TX      3)  ; Transmit back out same interface
(def XDP_REDIRECT 4) ; Redirect to another interface/CPU

;; Ethernet constants
(def ETH_HLEN 14)        ; Ethernet header length
(def ETH_P_IP 0x0800)    ; IPv4 EtherType (network byte order: 0x0008)
(def ETH_P_IPV6 0x86DD)  ; IPv6 EtherType

;; IP Protocol numbers
(def IPPROTO_ICMP 1)
(def IPPROTO_TCP  6)
(def IPPROTO_UDP  17)

(def PROTOCOL_NAMES
  {1  "ICMP"
   6  "TCP"
   17 "UDP"})

;; Header offsets (from start of packet)
(def ETH_TYPE_OFFSET 12)    ; EtherType field in Ethernet header
(def IP_PROTO_OFFSET 23)    ; Protocol field in IP header (14 + 9)
(def IP_SRC_OFFSET 26)      ; Source IP (14 + 12)
(def IP_DST_OFFSET 30)      ; Destination IP (14 + 16)
(def TCP_SRC_PORT_OFFSET 34); Source port (14 + 20)
(def TCP_DST_PORT_OFFSET 36); Destination port (14 + 20 + 2)

;; Filter configuration (example values)
(def MAX_ENTRIES 10000)

;;; ============================================================================
;;; Part 2: Utility Functions
;;; ============================================================================

(defn ip-string->int
  "Convert IP address string to 32-bit integer (network byte order).
   Returns an unchecked int that may be negative for IPs >= 128.x.x.x"
  [ip-str]
  (let [addr (InetAddress/getByName ip-str)
        bytes (.getAddress addr)]
    ;; Use unchecked-int to handle values that would overflow signed int
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

(defn swap-bytes-16
  "Convert between host and network byte order for 16-bit values"
  [val]
  (bit-or (bit-shift-left (bit-and val 0xFF) 8)
          (bit-and (bit-shift-right val 8) 0xFF)))

(defn format-mac
  "Format MAC address bytes as string"
  [bytes]
  (str/join ":" (map #(format "%02x" (bit-and % 0xFF)) bytes)))

;;; ============================================================================
;;; Part 3: BPF Maps
;;; ============================================================================

(defn create-stats-map
  "Array map for packet statistics:
   [0] = total_packets
   [1] = passed_packets
   [2] = dropped_packets
   [3] = filtered_by_ip
   [4] = filtered_by_port
   [5] = filtered_by_protocol"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 8
                   :map-name "packet_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-blocked-ips-map
  "Hash map: blocked IP (u32) -> 1 (blocked)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 4
                   :max-entries MAX_ENTRIES
                   :map-name "blocked_ips"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/int->bytes
                   :value-deserializer utils/bytes->int}))

(defn create-blocked-ports-map
  "Hash map: blocked port (u16 stored as u32) -> 1 (blocked)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 4
                   :max-entries 65536
                   :map-name "blocked_ports"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/int->bytes
                   :value-deserializer utils/bytes->int}))

;;; ============================================================================
;;; Part 4: XDP BPF Program
;;; ============================================================================

(defn create-xdp-filter-program
  "Create XDP program that filters packets.

   This program demonstrates basic XDP filtering:
   1. Parse Ethernet header
   2. Check if IPv4
   3. Parse IP header
   4. Check source IP against blocklist
   5. Update statistics

   For simplicity, this version just counts packets and
   demonstrates the XDP program structure.

   XDP context (xdp_md) offsets (32-bit fields):
   - data: offset 0 (32-bit)
   - data_end: offset 4 (32-bit)
   - data_meta: offset 8
   - ingress_ifindex: offset 12
   - rx_queue_index: offset 16

   The program:
   1. Loads data and data_end pointers (32-bit loads!)
   2. Validates packet bounds
   3. Increments packet counter
   4. Returns XDP_PASS"
  [stats-fd]
  (bpf/assemble
    [;; Load packet pointers from XDP context
     ;; r1 = ctx (xdp_md pointer)
     ;; IMPORTANT: Use 32-bit loads (:w) for xdp_md fields!
     (bpf/ldx :w :r2 :r1 0)         ; 0: r2 = ctx->data (32-bit)
     (bpf/ldx :w :r3 :r1 4)         ; 1: r3 = ctx->data_end (32-bit)

     ;; Check if we have at least ETH_HLEN bytes
     (bpf/mov-reg :r4 :r2)          ; 2: r4 = data
     (bpf/add :r4 ETH_HLEN)         ; 3: r4 = data + ETH_HLEN
     (bpf/jmp-reg :jle :r4 :r3 2)   ; 4: if r4 <= data_end, goto +2 (continue)

     ;; Drop path (bounds check failed)
     (bpf/mov :r0 XDP_DROP)         ; 5: return XDP_DROP
     (bpf/exit-insn)                ; 6: exit

     ;; Continue - Increment total packet counter (stats[0])
     (bpf/mov :r6 0)                ; 7: r6 = 0 (key)
     (bpf/store-mem :dw :r10 -8 :r6); 8: store key on stack

     ;; Map lookup
     (bpf/ld-map-fd :r1 stats-fd)   ; 9-10: load map fd (2 insns)
     (bpf/mov-reg :r2 :r10)         ; 11: r2 = r10 (frame pointer)
     (bpf/add :r2 -8)               ; 12: r2 = &key
     (bpf/call 1)                   ; 13: BPF_FUNC_map_lookup_elem

     ;; Check if lookup succeeded
     (bpf/jmp-imm :jeq :r0 0 3)     ; 14: if NULL, skip increment (goto insn 18)

     ;; Increment counter: (*r0)++
     (bpf/load-mem :dw :r1 :r0 0)   ; 15: r1 = *r0
     (bpf/add :r1 1)                ; 16: r1++
     (bpf/store-mem :dw :r0 0 :r1)  ; 17: *r0 = r1

     ;; Return XDP_PASS
     (bpf/mov :r0 XDP_PASS)         ; 18: return XDP_PASS
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Packet Simulation
;;; ============================================================================

(defn simulate-packet
  "Simulate a network packet"
  [src-ip dst-ip protocol src-port dst-port]
  {:src-ip src-ip
   :dst-ip dst-ip
   :protocol protocol
   :src-port src-port
   :dst-port dst-port
   :size (+ 64 (rand-int 1400))
   :timestamp (System/currentTimeMillis)})

(defn apply-filter-rules
  "Apply filter rules to a packet"
  [packet blocked-ips blocked-ports blocked-protocols]
  (let [{:keys [src-ip dst-ip protocol dst-port]} packet]
    (cond
      (contains? blocked-ips src-ip) {:action :drop :reason "blocked-ip"}
      (contains? blocked-ips dst-ip) {:action :drop :reason "blocked-ip"}
      (contains? blocked-ports dst-port) {:action :drop :reason "blocked-port"}
      (contains? blocked-protocols protocol) {:action :drop :reason "blocked-protocol"}
      :else {:action :pass :reason "allowed"})))

(defn simulate-traffic
  "Simulate network traffic and filtering"
  [num-packets blocked-ips blocked-ports blocked-protocols]
  (let [source-ips ["192.168.1.100" "10.0.0.50" "172.16.0.10"
                    "192.168.1.200" "8.8.8.8" "1.1.1.1"]
        dest-ips ["192.168.1.1" "10.0.0.1" "172.16.0.1"
                  "8.8.4.4" "1.0.0.1"]
        protocols [IPPROTO_TCP IPPROTO_UDP IPPROTO_ICMP]
        ports [22 80 443 8080 3389 53 25 110]]

    (for [_ (range num-packets)]
      (let [packet (simulate-packet
                     (rand-nth source-ips)
                     (rand-nth dest-ips)
                     (rand-nth protocols)
                     (rand-nth ports)
                     (rand-nth ports))
            result (apply-filter-rules packet blocked-ips blocked-ports blocked-protocols)]
        (assoc packet :result result)))))

;;; ============================================================================
;;; Part 6: Statistics Display
;;; ============================================================================

(defn display-filter-rules
  "Display current filter rules"
  [blocked-ips blocked-ports blocked-protocols]
  (println "\nActive Filter Rules:")
  (println "═══════════════════════════════════════════════════════")

  (println "\nBlocked IPs:")
  (if (empty? blocked-ips)
    (println "  (none)")
    (doseq [ip blocked-ips]
      (println (format "  • %s" ip))))

  (println "\nBlocked Ports:")
  (if (empty? blocked-ports)
    (println "  (none)")
    (doseq [port (sort blocked-ports)]
      (println (format "  • %d" port))))

  (println "\nBlocked Protocols:")
  (if (empty? blocked-protocols)
    (println "  (none)")
    (doseq [proto blocked-protocols]
      (println (format "  • %s (%d)" (get PROTOCOL_NAMES proto "Unknown") proto))))

  (println "═══════════════════════════════════════════════════════"))

(defn display-packet-stats
  "Display packet filtering statistics"
  [results]
  (let [total (count results)
        passed (count (filter #(= :pass (get-in % [:result :action])) results))
        dropped (count (filter #(= :drop (get-in % [:result :action])) results))
        by-reason (frequencies (map #(get-in % [:result :reason]) results))
        by-protocol (frequencies (map :protocol results))]

    (println "\nPacket Statistics:")
    (println "═══════════════════════════════════════════════════════")

    (println "\nSummary:")
    (println (format "  Total packets   : %,d" total))
    (println (format "  Passed          : %,d (%.1f%%)" passed (* 100.0 (/ passed total))))
    (println (format "  Dropped         : %,d (%.1f%%)" dropped (* 100.0 (/ dropped total))))

    (println "\nDropped by Reason:")
    (doseq [[reason cnt] (sort-by val > by-reason)
            :when (not= reason "allowed")]
      (println (format "  %-20s : %,d" reason cnt)))

    (println "\nBy Protocol:")
    (doseq [[proto cnt] (sort-by val > by-protocol)]
      (let [proto-name (get PROTOCOL_NAMES proto "Unknown")]
        (println (format "  %-8s : %,d packets" proto-name cnt))))

    (println "═══════════════════════════════════════════════════════")))

(defn display-sample-packets
  "Display sample packet events"
  [results n]
  (println "\nSample Packet Events:")
  (println "═══════════════════════════════════════════════════════════════════════════════")
  (println "ACTION │ PROTOCOL │ SOURCE IP          │ DEST IP            │ PORT │ REASON")
  (println "───────┼──────────┼────────────────────┼────────────────────┼──────┼────────────")

  (doseq [pkt (take n results)]
    (let [{:keys [src-ip dst-ip protocol dst-port result]} pkt
          action (if (= :pass (:action result)) "PASS" "DROP")
          proto-name (get PROTOCOL_NAMES protocol "???")]
      (println (format "%-6s │ %-8s │ %-18s │ %-18s │ %5d │ %s"
                       action proto-name src-ip dst-ip dst-port (:reason result)))))

  (println "═══════════════════════════════════════════════════════════════════════════════"))

(defn display-xdp-info
  "Display XDP program information"
  []
  (println "\nXDP Program Structure:")
  (println "═══════════════════════════════════════════════════════")
  (println "")
  (println "  ┌─────────────────────────────────────────────────────┐")
  (println "  │                   XDP Program                       │")
  (println "  │                                                     │")
  (println "  │  1. Receive packet via XDP hook                     │")
  (println "  │  2. Parse Ethernet header (14 bytes)                │")
  (println "  │  3. Check EtherType (IPv4 = 0x0800)                 │")
  (println "  │  4. Parse IP header (20+ bytes)                     │")
  (println "  │  5. Extract: src_ip, dst_ip, protocol               │")
  (println "  │  6. Parse TCP/UDP header (ports)                    │")
  (println "  │  7. Check against blocklists                        │")
  (println "  │  8. Return XDP_PASS or XDP_DROP                     │")
  (println "  │                                                     │")
  (println "  └─────────────────────────────────────────────────────┘")
  (println "")
  (println "  XDP Return Codes:")
  (println (format "    XDP_ABORTED  = %d  (Error, packet dropped)" XDP_ABORTED))
  (println (format "    XDP_DROP     = %d  (Intentionally drop packet)" XDP_DROP))
  (println (format "    XDP_PASS     = %d  (Pass to kernel stack)" XDP_PASS))
  (println (format "    XDP_TX       = %d  (Transmit back out interface)" XDP_TX))
  (println (format "    XDP_REDIRECT = %d  (Redirect to other interface)" XDP_REDIRECT))
  (println "")
  (println "  Header Offsets (from packet start):")
  (println (format "    Ethernet Type : offset %d" ETH_TYPE_OFFSET))
  (println (format "    IP Protocol   : offset %d" IP_PROTO_OFFSET))
  (println (format "    Source IP     : offset %d" IP_SRC_OFFSET))
  (println (format "    Dest IP       : offset %d" IP_DST_OFFSET))
  (println (format "    TCP/UDP Ports : offset %d-%d" TCP_SRC_PORT_OFFSET TCP_DST_PORT_OFFSET))
  (println "═══════════════════════════════════════════════════════"))

;;; ============================================================================
;;; Part 7: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 7.1: XDP Packet Filter ===\n")

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

    ;; Initialize stats
    (doseq [i (range 8)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create XDP program
      (println "\nStep 3: Creating XDP BPF program...")
      (let [program (create-xdp-filter-program (:fd stats-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :xdp
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display XDP info
            (println "\nStep 5: XDP program information...")
            (display-xdp-info)

            ;; Step 6: Configure filter rules (simulation)
            (println "\nStep 6: Configuring filter rules...")
            (let [blocked-ips #{"10.0.0.50" "192.168.1.200"}
                  blocked-ports #{22 3389}  ; SSH, RDP
                  blocked-protocols #{IPPROTO_ICMP}]

              ;; Add to maps (for demonstration)
              (doseq [ip blocked-ips]
                (bpf/map-update blocked-ips-map (ip-string->int ip) 1))
              (doseq [port blocked-ports]
                (bpf/map-update blocked-ports-map port 1))

              (display-filter-rules blocked-ips blocked-ports blocked-protocols)

              ;; Step 7: Simulate traffic
              (println "\nStep 7: Simulating network traffic...")
              (let [results (simulate-traffic 100 blocked-ips blocked-ports blocked-protocols)]

                ;; Step 8: Display results
                (println "\nStep 8: Displaying results...")
                (display-sample-packets results 15)
                (display-packet-stats results)

                ;; Update BPF map stats
                (let [total (count results)
                      passed (count (filter #(= :pass (get-in % [:result :action])) results))
                      dropped (- total passed)]
                  (bpf/map-update stats-map 0 total)
                  (bpf/map-update stats-map 1 passed)
                  (bpf/map-update stats-map 2 dropped))

                ;; Step 9: Read stats from map
                (println "\nStep 9: Reading stats from BPF map...")
                (println (format "  stats[0] (total)   = %,d" (bpf/map-lookup stats-map 0)))
                (println (format "  stats[1] (passed)  = %,d" (bpf/map-lookup stats-map 1)))
                (println (format "  stats[2] (dropped) = %,d" (bpf/map-lookup stats-map 2)))))

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
        (bpf/close-map blocked-ips-map)
        (bpf/close-map blocked-ports-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 7.1 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test IP conversion
  (ip-string->int "192.168.1.1")
  (int->ip-string (ip-string->int "192.168.1.1"))

  ;; Test byte swapping
  (swap-bytes-16 80)    ; 80 -> 20480 (network order)
  (swap-bytes-16 20480) ; back to 80
  )
