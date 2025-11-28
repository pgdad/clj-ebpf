(ns lab-8-1-traffic-shaper
  "Lab 8.1: TC Traffic Shaper

   This solution demonstrates:
   - Token bucket rate limiting algorithm
   - Bandwidth limiting for egress traffic
   - TC (Traffic Control) BPF programs
   - Per-interface traffic shaping
   - Burst handling with bucket capacity

   Run with: sudo clojure -M -m lab-8-1-traffic-shaper
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; TC (Traffic Control) Actions
(def TC_ACT_OK 0)       ; Continue normal processing
(def TC_ACT_SHOT 2)     ; Drop packet
(def TC_ACT_UNSPEC -1)  ; Use default action

;; __sk_buff offsets (for TC programs)
(def SKB_LEN 0)         ; Packet length (u32)
(def SKB_DATA 76)       ; Data pointer (u32)
(def SKB_DATA_END 80)   ; Data end pointer (u32)

;; Bandwidth configuration
(def RATE_10MBPS 1250000)   ; 10 Mbps = 1,250,000 bytes/sec
(def RATE_100MBPS 12500000) ; 100 Mbps = 12,500,000 bytes/sec
(def RATE_1GBPS 125000000)  ; 1 Gbps = 125,000,000 bytes/sec

;; Token bucket parameters
(def DEFAULT_RATE_BPS RATE_10MBPS)
(def DEFAULT_BURST_FACTOR 2)  ; Allow 2 seconds of burst

;;; ============================================================================
;;; Part 2: Token Bucket Implementation
;;; ============================================================================

(defn create-token-bucket
  "Create a token bucket state"
  [rate-bps burst-seconds]
  (let [capacity (* rate-bps burst-seconds)]
    (atom {:tokens (double capacity)
           :capacity capacity
           :rate rate-bps
           :last-update (System/nanoTime)})))

(defn refill-tokens
  "Refill tokens based on elapsed time"
  [bucket]
  (let [now (System/nanoTime)
        {:keys [tokens capacity rate last-update]} @bucket
        elapsed-sec (/ (- now last-update) 1e9)
        new-tokens (min capacity (+ tokens (* rate elapsed-sec)))]
    (swap! bucket assoc
           :tokens new-tokens
           :last-update now)
    new-tokens))

(defn consume-tokens
  "Try to consume tokens for a packet. Returns true if allowed."
  [bucket packet-size]
  (let [current-tokens (refill-tokens bucket)]
    (if (>= current-tokens packet-size)
      (do
        (swap! bucket update :tokens - packet-size)
        true)
      false)))

;;; ============================================================================
;;; Part 3: BPF Maps
;;; ============================================================================

(defn create-state-map
  "Array map for rate limiter state:
   Value: {last_time (u64), tokens (u64)}"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 16
                   :max-entries 1
                   :map-name "shaper_state"}))

(defn create-stats-map
  "Array map for statistics:
   [0] = {accepted_packets (u64), accepted_bytes (u64)}
   [1] = {dropped_packets (u64), dropped_bytes (u64)}"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 16
                   :max-entries 2
                   :map-name "shaper_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int}))

(defn create-config-map
  "Array map for configuration:
   [0] = rate_bps (u64)
   [1] = capacity (u64)"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 2
                   :map-name "shaper_config"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: TC BPF Program
;;; ============================================================================

(defn create-traffic-shaper-program
  "Create TC program for bandwidth limiting.

   This simplified program demonstrates:
   1. Get packet length from skb
   2. Lookup rate limiter state
   3. Update statistics

   Note: TC programs use __sk_buff context which has different offsets
   than xdp_md. The data/data_end fields are at different positions.

   __sk_buff context (32-bit fields):
   - len: offset 0
   - data: offset 76
   - data_end: offset 80"
  [stats-fd config-fd]
  (bpf/assemble
    [;; r6 = skb (save context)
     (bpf/mov-reg :r6 :r1)

     ;; Get packet length from skb->len (offset 0)
     (bpf/ldx :w :r7 :r6 SKB_LEN)   ; r7 = packet length

     ;; Increment accepted counter (stats[0])
     ;; For this simplified version, we just count all packets
     (bpf/mov :r8 0)                ; key = 0 (accepted)
     (bpf/store-mem :dw :r10 -8 :r8)

     ;; Map lookup
     (bpf/ld-map-fd :r1 stats-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)
     (bpf/call 1)                   ; bpf_map_lookup_elem

     (bpf/jmp-imm :jeq :r0 0 3)     ; if NULL, skip

     ;; Increment packet counter
     (bpf/load-mem :dw :r1 :r0 0)
     (bpf/add :r1 1)
     (bpf/store-mem :dw :r0 0 :r1)

     ;; Return TC_ACT_OK (pass packet)
     (bpf/mov :r0 TC_ACT_OK)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Traffic Simulation
;;; ============================================================================

(defn generate-traffic
  "Generate simulated traffic for testing"
  [duration-sec rate-mbps]
  (let [bytes-per-sec (* rate-mbps 125000)  ; Mbps to bytes/sec
        avg-packet-size 1000
        packets-per-sec (/ bytes-per-sec avg-packet-size)
        total-packets (* duration-sec packets-per-sec)]
    (for [i (range (int total-packets))]
      {:id i
       :size (+ 64 (rand-int 1400))  ; 64 - 1464 bytes
       :timestamp (+ (System/currentTimeMillis)
                     (int (* 1000 (/ i packets-per-sec))))})))

(defn simulate-traffic-shaping
  "Simulate traffic shaping with token bucket"
  [packets rate-bps burst-seconds]
  (let [bucket (create-token-bucket rate-bps burst-seconds)
        results (atom {:accepted 0
                       :accepted-bytes 0
                       :dropped 0
                       :dropped-bytes 0})]

    (doseq [pkt packets]
      (let [size (:size pkt)]
        (if (consume-tokens bucket size)
          (do
            (swap! results update :accepted inc)
            (swap! results update :accepted-bytes + size))
          (do
            (swap! results update :dropped inc)
            (swap! results update :dropped-bytes + size)))))

    @results))

;;; ============================================================================
;;; Part 6: Statistics Display
;;; ============================================================================

(defn format-bandwidth [bytes-per-sec]
  "Format bandwidth in human-readable form"
  (let [bits-per-sec (* bytes-per-sec 8)]
    (cond
      (< bits-per-sec 1000) (format "%.0f bps" bits-per-sec)
      (< bits-per-sec 1000000) (format "%.1f Kbps" (/ bits-per-sec 1000.0))
      (< bits-per-sec 1000000000) (format "%.1f Mbps" (/ bits-per-sec 1000000.0))
      :else (format "%.2f Gbps" (/ bits-per-sec 1000000000.0)))))

(defn format-bytes [bytes]
  "Format bytes in human-readable form"
  (cond
    (< bytes 1024) (format "%d B" bytes)
    (< bytes 1048576) (format "%.1f KB" (/ bytes 1024.0))
    (< bytes 1073741824) (format "%.2f MB" (/ bytes 1048576.0))
    :else (format "%.2f GB" (/ bytes 1073741824.0))))

(defn display-token-bucket-info
  "Display token bucket algorithm explanation"
  [rate-bps capacity]
  (println "\nToken Bucket Traffic Shaper:")
  (println "═══════════════════════════════════════════════════════")
  (println "")
  (println "  ┌─────────────────────────────────────────────────────┐")
  (println "  │              Token Bucket Algorithm                 │")
  (println "  │                                                     │")
  (println "  │     Tokens added at constant rate R                 │")
  (println "  │                      │                              │")
  (println "  │                      ▼                              │")
  (println "  │       ┌────────────────────────────┐                │")
  (println "  │       │  ████████████░░░░░░░░░░░░  │ Bucket         │")
  (println "  │       │  (tokens)      (capacity)  │                │")
  (println "  │       └──────────────┬─────────────┘                │")
  (println "  │                      │                              │")
  (println "  │                      ▼                              │")
  (println "  │          Packet needs 'size' tokens                 │")
  (println "  │          If tokens >= size:                         │")
  (println "  │              tokens -= size; PASS                   │")
  (println "  │          Else:                                      │")
  (println "  │              DROP (rate exceeded)                   │")
  (println "  │                                                     │")
  (println "  └─────────────────────────────────────────────────────┘")
  (println "")
  (println (format "  Configuration:"))
  (println (format "    • Rate limit    : %s" (format-bandwidth rate-bps)))
  (println (format "    • Bucket capacity: %s (allows burst)" (format-bytes capacity)))
  (println "═══════════════════════════════════════════════════════"))

(defn display-shaping-results
  "Display traffic shaping results"
  [{:keys [accepted accepted-bytes dropped dropped-bytes]} duration-sec]
  (let [total-packets (+ accepted dropped)
        total-bytes (+ accepted-bytes dropped-bytes)
        accepted-rate (/ accepted-bytes duration-sec)
        dropped-rate (/ dropped-bytes duration-sec)]

    (println "\nTraffic Shaping Results:")
    (println "═══════════════════════════════════════════════════════")

    (println "\nPacket Statistics:")
    (println (format "  Total packets    : %,d" total-packets))
    (println (format "  Accepted         : %,d (%.1f%%)"
                     accepted (* 100.0 (/ accepted total-packets))))
    (println (format "  Dropped          : %,d (%.1f%%)"
                     dropped (* 100.0 (/ dropped total-packets))))

    (println "\nBandwidth Statistics:")
    (println (format "  Total traffic    : %s" (format-bytes total-bytes)))
    (println (format "  Accepted         : %s (%s average)"
                     (format-bytes accepted-bytes) (format-bandwidth accepted-rate)))
    (println (format "  Dropped          : %s (%s average)"
                     (format-bytes dropped-bytes) (format-bandwidth dropped-rate)))

    (println "\nEffective Rate:")
    (let [limit-pct (if (> total-bytes 0)
                      (* 100.0 (/ accepted-bytes total-bytes))
                      100.0)]
      (println (format "  Passed through   : %.1f%% of offered traffic" limit-pct)))

    (println "═══════════════════════════════════════════════════════")))

(defn display-rate-visualization
  "Display rate visualization"
  [offered-rate limit-rate accepted-rate dropped-rate]
  (let [max-rate (max offered-rate limit-rate)
        scale (/ 40.0 max-rate)
        offered-bar (int (* offered-rate scale))
        limit-bar (int (* limit-rate scale))
        accepted-bar (int (* accepted-rate scale))
        dropped-bar (int (* dropped-rate scale))]

    (println "\nRate Visualization:")
    (println "═══════════════════════════════════════════════════════")
    (println "")
    (println (format "  Offered:   %-40s %s"
                     (apply str (repeat offered-bar "▓"))
                     (format-bandwidth offered-rate)))
    (println (format "  Limit:     %-40s %s"
                     (apply str (concat (repeat limit-bar "─") ["│"]))
                     (format-bandwidth limit-rate)))
    (println (format "  Accepted:  %-40s %s"
                     (apply str (repeat accepted-bar "█"))
                     (format-bandwidth accepted-rate)))
    (println (format "  Dropped:   %-40s %s"
                     (apply str (repeat dropped-bar "░"))
                     (format-bandwidth dropped-rate)))
    (println "")))

;;; ============================================================================
;;; Part 7: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 8.1: TC Traffic Shaper ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [stats-map (create-stats-map)
        config-map (create-config-map)]
    (println "  Stats map created (FD:" (:fd stats-map) ")")
    (println "  Config map created (FD:" (:fd config-map) ")")

    ;; Initialize config
    (bpf/map-update config-map 0 DEFAULT_RATE_BPS)
    (bpf/map-update config-map 1 (* DEFAULT_RATE_BPS DEFAULT_BURST_FACTOR))

    (try
      ;; Step 3: Create TC program
      (println "\nStep 3: Creating TC traffic shaper program...")
      (let [program (create-traffic-shaper-program (:fd stats-map)
                                                    (:fd config-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :sched-cls
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display token bucket info
            (println "\nStep 5: Traffic shaper configuration...")
            (let [rate-bps (bpf/map-lookup config-map 0)
                  capacity (bpf/map-lookup config-map 1)]
              (display-token-bucket-info rate-bps capacity)

              ;; Step 6: Simulate traffic
              (println "\nStep 6: Simulating traffic...")
              (let [duration-sec 10
                    offered-rate-mbps 50  ; 50 Mbps offered
                    limit-rate-bps rate-bps
                    burst-seconds DEFAULT_BURST_FACTOR

                    _ (println (format "  Generating %d seconds of %d Mbps traffic..."
                                       duration-sec offered-rate-mbps))
                    packets (generate-traffic duration-sec offered-rate-mbps)
                    _ (println (format "  Generated %d packets" (count packets)))

                    _ (println "  Applying token bucket shaping...")
                    results (simulate-traffic-shaping packets limit-rate-bps burst-seconds)]

                ;; Step 7: Display results
                (println "\nStep 7: Results...")
                (display-shaping-results results duration-sec)

                ;; Step 8: Display visualization
                (println "\nStep 8: Visualization...")
                (let [offered-rate (* offered-rate-mbps 125000)
                      accepted-rate (/ (:accepted-bytes results) duration-sec)
                      dropped-rate (/ (:dropped-bytes results) duration-sec)]
                  (display-rate-visualization offered-rate limit-rate-bps
                                              accepted-rate dropped-rate))

                ;; Step 9: Update BPF map stats
                (println "\nStep 9: Updating BPF maps...")
                ;; Store stats in packed format
                (let [stats-bytes (byte-array 16)]
                  (doto (ByteBuffer/wrap stats-bytes)
                    (.order ByteOrder/LITTLE_ENDIAN)
                    (.putLong 0 (:accepted results))
                    (.putLong 8 (:accepted-bytes results)))
                  (bpf/map-update stats-map 0 stats-bytes :raw-value true))

                (let [stats-bytes (byte-array 16)]
                  (doto (ByteBuffer/wrap stats-bytes)
                    (.order ByteOrder/LITTLE_ENDIAN)
                    (.putLong 0 (:dropped results))
                    (.putLong 8 (:dropped-bytes results)))
                  (bpf/map-update stats-map 1 stats-bytes :raw-value true))

                (println (format "  Stored stats: %d accepted, %d dropped"
                                 (:accepted results) (:dropped results)))))

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
        (bpf/close-map config-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 8.1 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test token bucket
  (let [bucket (create-token-bucket 1250000 2)]  ; 10 Mbps, 2 sec burst
    (println "Initial tokens:" (:tokens @bucket))
    (println "Consume 1000:" (consume-tokens bucket 1000))
    (println "Tokens after:" (:tokens @bucket)))

  ;; Test bandwidth formatting
  (format-bandwidth 1250000)    ; 10 Mbps
  (format-bandwidth 125000000)  ; 1 Gbps
  )
