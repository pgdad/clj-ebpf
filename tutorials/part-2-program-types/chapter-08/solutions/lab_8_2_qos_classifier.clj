(ns lab-8-2-qos-classifier
  "Lab 8.2: QoS (Quality of Service) Classifier

   This solution demonstrates:
   - Packet classification by port and protocol
   - Priority assignment (interactive, normal, bulk)
   - DSCP (Differentiated Services Code Point) marking
   - Integration with Linux qdisc concepts
   - Application-aware traffic prioritization

   Run with: sudo clojure -M -m lab-8-2-qos-classifier
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; TC Actions
(def TC_ACT_OK 0)

;; Priority levels (Linux socket priorities)
(def PRIO_INTERACTIVE 0)  ; Highest - SSH, DNS, ICMP
(def PRIO_NORMAL 3)       ; Default - HTTP, HTTPS
(def PRIO_BULK 6)         ; Lowest - FTP, SMTP

;; DSCP (Differentiated Services Code Point) values
(def DSCP_EF 46)    ; Expedited Forwarding - VoIP, real-time
(def DSCP_AF41 34)  ; Assured Forwarding 41 - High priority video
(def DSCP_AF31 26)  ; Assured Forwarding 31 - Streaming data
(def DSCP_AF21 18)  ; Assured Forwarding 21 - Medium priority
(def DSCP_BE 0)     ; Best Effort - Default

;; __sk_buff offsets (for TC programs)
(def SKB_LEN 0)         ; Packet length
(def SKB_PRIORITY 32)   ; Priority field
(def SKB_DATA 76)       ; Data pointer
(def SKB_DATA_END 80)   ; Data end pointer

;; Protocol numbers
(def ETH_P_IP 0x0800)
(def IPPROTO_ICMP 1)
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

;; Traffic classification rules
(def INTERACTIVE_PORTS #{22 23 53})       ; SSH, Telnet, DNS
(def NORMAL_PORTS #{80 443 8080 8443})    ; HTTP, HTTPS
(def BULK_PORTS #{20 21 25 110 143})      ; FTP, SMTP, POP3, IMAP

;;; ============================================================================
;;; Part 2: Classification Logic
;;; ============================================================================

(defn classify-port
  "Classify traffic by destination port"
  [port]
  (cond
    (INTERACTIVE_PORTS port) {:class :interactive
                              :priority PRIO_INTERACTIVE
                              :dscp DSCP_EF}
    (NORMAL_PORTS port) {:class :normal
                         :priority PRIO_NORMAL
                         :dscp DSCP_AF21}
    (BULK_PORTS port) {:class :bulk
                       :priority PRIO_BULK
                       :dscp DSCP_BE}
    :else {:class :default
           :priority PRIO_NORMAL
           :dscp DSCP_BE}))

(defn classify-protocol
  "Classify by IP protocol"
  [proto]
  (case proto
    1  {:class :icmp :priority PRIO_INTERACTIVE :dscp DSCP_EF}  ; ICMP - network control
    6  {:class :tcp :priority PRIO_NORMAL :dscp DSCP_AF21}
    17 {:class :udp :priority PRIO_NORMAL :dscp DSCP_AF21}
    {:class :other :priority PRIO_NORMAL :dscp DSCP_BE}))

;;; ============================================================================
;;; Part 3: BPF Maps
;;; ============================================================================

(defn create-stats-map
  "Array map for classification statistics:
   [0] = interactive_count
   [1] = normal_count
   [2] = bulk_count
   [3] = total_count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4
                   :map-name "qos_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-dscp-stats-map
  "Hash map: DSCP value -> packet count"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries 64
                   :map-name "dscp_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: TC BPF Program
;;; ============================================================================

(defn create-qos-classifier-program
  "Create TC program for QoS classification.

   Simplified program that:
   1. Validates packet headers
   2. Classifies by protocol
   3. Updates stats map

   Jump offsets account for ld-map-fd being 2 instructions."
  [stats-fd]
  (bpf/assemble
    [;; 0: r6 = skb (save context)
     (bpf/mov-reg :r6 :r1)

     ;; 1: Default: classify as normal (r9 = stats key)
     (bpf/mov :r9 1)

     ;; 2-3: Load data pointers (32-bit for TC context)
     (bpf/ldx :w :r2 :r6 SKB_DATA)      ; r2 = skb->data
     (bpf/ldx :w :r3 :r6 SKB_DATA_END)  ; r3 = skb->data_end

     ;; 4-5: Check Ethernet + IP header (14 + 20 = 34 bytes minimum)
     (bpf/mov-reg :r4 :r2)
     (bpf/add :r4 34)
     ;; 6: if too short, jump to stats update at insn 18 (skip 11 instructions)
     ;; After insn 6, need to jump over: 7,8,9,10,11,12,13,14,15,16,17 = 11 insns
     (bpf/jmp-reg :jgt :r4 :r3 11)

     ;; 7: Check EtherType (IPv4 = 0x0800)
     (bpf/ldx :h :r5 :r2 12)            ; Load EtherType
     ;; 8: Not IPv4, jump to stats at insn 18 (skip 9 instructions after this)
     (bpf/jmp-imm :jne :r5 0x0008 9)

     ;; 9: Load protocol (offset 14 + 9 = 23)
     (bpf/ldx :b :r8 :r2 23)            ; r8 = protocol

     ;; 10: Check for ICMP (protocol 1) -> Interactive
     (bpf/jmp-imm :jne :r8 IPPROTO_ICMP 2)
     ;; 11: ICMP: stats key = 0 (interactive)
     (bpf/mov :r9 0)
     ;; 12: jump to stats update at insn 18 (skip 5)
     (bpf/jmp 5)

     ;; 13: Check for TCP (protocol 6) -> Normal
     (bpf/jmp-imm :jne :r8 IPPROTO_TCP 2)
     ;; 14: TCP: stats key = 1 (normal)
     (bpf/mov :r9 1)
     ;; 15: jump to stats (skip 2)
     (bpf/jmp 2)

     ;; 16: Check for UDP (protocol 17)
     (bpf/jmp-imm :jne :r8 IPPROTO_UDP 1)
     ;; 17: UDP: stats key = 1 (normal)
     (bpf/mov :r9 1)

     ;; 18: Stats update - r9 contains the stats key
     (bpf/store-mem :dw :r10 -8 :r9)

     ;; 19-20: ld-map-fd (2 instructions)
     (bpf/ld-map-fd :r1 stats-fd)
     ;; 21: mov-reg
     (bpf/mov-reg :r2 :r10)
     ;; 22: add
     (bpf/add :r2 -8)
     ;; 23: call
     (bpf/call 1)                       ; bpf_map_lookup_elem

     ;; 24: if NULL, skip 3 to exit
     (bpf/jmp-imm :jeq :r0 0 3)

     ;; 25: Increment counter
     (bpf/load-mem :dw :r1 :r0 0)
     ;; 26: add
     (bpf/add :r1 1)
     ;; 27: store
     (bpf/store-mem :dw :r0 0 :r1)

     ;; 28: Return TC_ACT_OK
     (bpf/mov :r0 TC_ACT_OK)
     ;; 29: exit
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Traffic Simulation
;;; ============================================================================

(defn generate-packet
  "Generate a simulated packet"
  [src-port dst-port protocol]
  {:src-port src-port
   :dst-port dst-port
   :protocol protocol
   :size (+ 64 (rand-int 1400))
   :timestamp (System/currentTimeMillis)})

(defn simulate-traffic
  "Generate simulated traffic mix"
  [num-packets]
  (let [traffic-mix [{:proto IPPROTO_TCP :port 22 :weight 5}    ; SSH
                     {:proto IPPROTO_TCP :port 80 :weight 30}   ; HTTP
                     {:proto IPPROTO_TCP :port 443 :weight 40}  ; HTTPS
                     {:proto IPPROTO_UDP :port 53 :weight 10}   ; DNS
                     {:proto IPPROTO_TCP :port 25 :weight 5}    ; SMTP
                     {:proto IPPROTO_ICMP :port 0 :weight 5}    ; ICMP
                     {:proto IPPROTO_TCP :port 8080 :weight 5}] ; HTTP alt
        total-weight (reduce + (map :weight traffic-mix))]

    (for [_ (range num-packets)]
      (let [r (rand-int total-weight)
            selected (loop [mix traffic-mix
                           acc 0]
                       (if-let [m (first mix)]
                         (let [new-acc (+ acc (:weight m))]
                           (if (< r new-acc)
                             m
                             (recur (rest mix) new-acc)))
                         (last traffic-mix)))]
        (generate-packet (+ 10000 (rand-int 55000))
                         (:port selected)
                         (:proto selected))))))

(defn classify-traffic
  "Classify traffic and collect statistics"
  [packets]
  (let [results (atom {:interactive {:count 0 :bytes 0}
                       :normal {:count 0 :bytes 0}
                       :bulk {:count 0 :bytes 0}
                       :by-port {}})]

    (doseq [pkt packets]
      (let [port (:dst-port pkt)
            proto (:protocol pkt)
            size (:size pkt)
            class-info (if (= proto IPPROTO_ICMP)
                        {:class :interactive :priority PRIO_INTERACTIVE :dscp DSCP_EF}
                        (classify-port port))]

        ;; Update class counts
        (swap! results update-in [(:class class-info) :count] inc)
        (swap! results update-in [(:class class-info) :bytes] + size)

        ;; Update port stats
        (swap! results update-in [:by-port port] (fnil inc 0))))

    @results))

;;; ============================================================================
;;; Part 6: Statistics Display
;;; ============================================================================

(def qos-info-text
  ["QoS Classification System:"
   "═══════════════════════════════════════════════════════"
   ""
   "  Traffic Classes:"
   "  • Interactive (Prio 0): SSH(22), DNS(53), ICMP"
   "  • Normal (Prio 3)     : HTTP(80), HTTPS(443)"
   "  • Bulk (Prio 6)       : FTP(20,21), SMTP(25)"
   ""
   "  DSCP Values: EF(46)=VoIP, AF21(18)=Standard, BE(0)=Bulk"
   "═══════════════════════════════════════════════════════"])

(defn display-qos-info
  "Display QoS classification information"
  []
  (println "")
  (doseq [line qos-info-text]
    (println line)))

(defn port-name [port]
  (case port
    22 "SSH" 53 "DNS" 80 "HTTP" 443 "HTTPS"
    25 "SMTP" 20 "FTP-data" 21 "FTP-ctrl"
    8080 "HTTP-alt" 0 "ICMP" (str "Port " port)))

(defn print-class-stats [name cnt total-count bar-char]
  (let [pct (* 100.0 (/ cnt total-count))
        bar-len (int (* 30 (/ pct 100)))]
    (println (format "  %-12s: %,6d pkts (%5.1f%%) %s"
                     name cnt pct (apply str (repeat bar-len bar-char))))))

(defn print-port-stats [[port cnt] total-count]
  (let [pct (* 100.0 (/ cnt total-count))
        bar-len (int (* 20 (/ pct 100)))]
    (println (format "  %-10s: %,6d (%5.1f%%) %s"
                     (port-name port) cnt pct
                     (apply str (repeat bar-len "#"))))))

(defn display-classification-results
  "Display traffic classification results"
  [{:keys [interactive normal bulk by-port]}]
  (let [total-count (max 1 (+ (:count interactive) (:count normal) (:count bulk)))]
    (println "\nClassification Results:")
    (println "═══════════════════════════════════════════════════════")
    (println "\nBy Priority Class:")
    (print-class-stats "Interactive" (:count interactive) total-count "#")
    (print-class-stats "Normal" (:count normal) total-count "=")
    (print-class-stats "Bulk" (:count bulk) total-count "-")
    (println "\nTop Ports:")
    (doseq [entry (->> by-port (sort-by val >) (take 6))]
      (print-port-stats entry total-count))
    (println "═══════════════════════════════════════════════════════")))

(defn display-priority-queue-diagram
  "Display priority queue visualization"
  [{:keys [interactive normal bulk]}]
  (let [total (max 1 (+ (:count interactive) (:count normal) (:count bulk)))
        hi-pct (int (/ (* (:count interactive) 100) total))
        md-pct (int (/ (* (:count normal) 100) total))
        lo-pct (int (/ (* (:count bulk) 100) total))]
    (println "\nPriority Queue Model:")
    (println "═══════════════════════════════════════════════════════")
    (println (format "  Queue Distribution: High=%d%% Med=%d%% Low=%d%%" hi-pct md-pct lo-pct))
    (println "  (High priority transmitted first)")
    (println "═══════════════════════════════════════════════════════")))

;;; ============================================================================
;;; Part 7: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 8.2: QoS Classifier ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [stats-map (create-stats-map)]
    (println "  Stats map created (FD:" (:fd stats-map) ")")

    ;; Initialize stats
    (doseq [i (range 4)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create TC program
      (println "\nStep 3: Creating TC QoS classifier program...")
      (let [program (create-qos-classifier-program (:fd stats-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :sched-cls
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display QoS info
            (println "\nStep 5: QoS classification system...")
            (display-qos-info)

            ;; Step 6: Simulate traffic
            (println "\nStep 6: Simulating traffic classification...")
            (let [num-packets 1000
                  _ (println (format "  Generating %d packets..." num-packets))
                  packets (simulate-traffic num-packets)
                  _ (println "  Classifying traffic...")
                  results (classify-traffic packets)]

              ;; Step 7: Display classification results
              (println "\nStep 7: Classification results...")
              (display-classification-results results)

              ;; Step 8: Display queue model
              (println "\nStep 8: Priority queue model...")
              (display-priority-queue-diagram results)

              ;; Step 9: Update BPF maps
              (println "\nStep 9: Updating BPF maps...")
              (bpf/map-update stats-map 0 (get-in results [:interactive :count] 0))
              (bpf/map-update stats-map 1 (get-in results [:normal :count] 0))
              (bpf/map-update stats-map 2 (get-in results [:bulk :count] 0))
              (bpf/map-update stats-map 3 num-packets)

              (println (format "  stats[0] (interactive) = %,d"
                               (bpf/map-lookup stats-map 0)))
              (println (format "  stats[1] (normal)      = %,d"
                               (bpf/map-lookup stats-map 1)))
              (println (format "  stats[2] (bulk)        = %,d"
                               (bpf/map-lookup stats-map 2)))
              (println (format "  stats[3] (total)       = %,d"
                               (bpf/map-lookup stats-map 3))))

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
        (println "  Maps closed"))))

  (println "\n=== Lab 8.2 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test classification
  (classify-port 22)   ; Interactive
  (classify-port 80)   ; Normal
  (classify-port 25)   ; Bulk
  (classify-port 9999) ; Default

  ;; Test DSCP values
  (def DSCP_EF 46)     ; 101110 binary
  (Integer/toBinaryString DSCP_EF)
  )
