(ns lab-2-2-packet-histogram
  "Lab 2.2: Network Packet Histogram using BPF array maps

   This solution demonstrates:
   - Creating array maps for histogram data
   - XDP program basics (structure, not actual attachment)
   - Building and displaying histograms
   - Statistical analysis of captured data

   Run with: clojure -M -m lab-2-2-packet-histogram
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Configuration
;;; ============================================================================

(def bucket-size 256)   ; Bytes per bucket
(def num-buckets 64)    ; Track packets up to 16KB (64 * 256)

;; XDP return codes
(def XDP_ABORTED 0)
(def XDP_DROP 1)
(def XDP_PASS 2)
(def XDP_TX 3)
(def XDP_REDIRECT 4)

;;; ============================================================================
;;; Part 2: Map Creation
;;; ============================================================================

(defn create-histogram-map
  "Create array map for packet size histogram.
   Key: u32 (bucket index), Value: u64 (packet count)"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4           ; u32 for bucket index
                   :value-size 8         ; u64 for packet count
                   :max-entries num-buckets
                   :map-name "packet_histogram"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 3: BPF Program
;;; ============================================================================

(defn create-xdp-histogram-program
  "Create XDP program that builds packet size histogram.
   Note: This is a simple demonstration program."
  [map-fd]
  (bpf/assemble
    [;; Simple XDP program that returns XDP_PASS
     ;; Actual packet processing would parse xdp_md context
     (bpf/mov :r0 XDP_PASS)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 4: Histogram Utilities
;;; ============================================================================

(defn bucket-range
  "Get size range for bucket"
  [bucket]
  (let [start (* bucket bucket-size)
        end (+ start bucket-size -1)]
    [start end]))

(defn format-size
  "Format byte size as human-readable string"
  [bytes]
  (cond
    (>= bytes 1024) (format "%.1fK" (/ bytes 1024.0))
    :else (str bytes "B")))

(defn size-to-bucket
  "Convert packet size to bucket index"
  [size]
  (min (quot size bucket-size) (dec num-buckets)))

;;; ============================================================================
;;; Part 5: Map Operations
;;; ============================================================================

(defn initialize-buckets
  "Initialize all buckets to 0"
  [histogram-map]
  (doseq [bucket (range num-buckets)]
    (bpf/map-update histogram-map bucket 0)))

(defn increment-bucket
  "Increment packet count for a bucket"
  [histogram-map bucket]
  (let [current (or (bpf/map-lookup histogram-map bucket) 0)]
    (bpf/map-update histogram-map bucket (inc current))))

(defn record-packet
  "Record a packet of given size"
  [histogram-map packet-size]
  (let [bucket (size-to-bucket packet-size)]
    (increment-bucket histogram-map bucket)))

(defn read-histogram
  "Read histogram data from map"
  [histogram-map]
  (into []
        (for [bucket (range num-buckets)]
          (or (bpf/map-lookup histogram-map bucket) 0))))

;;; ============================================================================
;;; Part 6: Visualization
;;; ============================================================================

(defn display-histogram
  "Display histogram as text visualization"
  [histogram]
  (println "\nPacket Size Histogram:")
  (println (apply str (repeat 60 "=")))

  (let [max-count (apply max (conj histogram 1))  ; Avoid division by zero
        bar-width 40]

    ;; Find non-zero buckets
    (let [non-zero (filter #(> (histogram %) 0) (range num-buckets))]
      (when (empty? non-zero)
        (println "No packets captured yet"))

      (doseq [bucket non-zero]
        (let [count (histogram bucket)
              [start end] (bucket-range bucket)
              bar-len (int (* bar-width (/ count max-count)))
              bar (apply str (repeat bar-len "#"))]
          (println (format "%5s - %5s | %-40s %d"
                          (format-size start)
                          (format-size end)
                          bar
                          count))))))

  (println (apply str (repeat 60 "=")))
  (let [total (reduce + histogram)]
    (println "Total packets:" total)))

(defn display-statistics
  "Display summary statistics"
  [histogram]
  (let [total (reduce + histogram)
        weighted-sum (reduce + (map-indexed (fn [i cnt]
                                              (* (+ (* i bucket-size) (/ bucket-size 2)) cnt))
                                           histogram))
        avg-size (if (pos? total)
                   (/ weighted-sum total)
                   0)
        ;; Find bucket with max count
        max-bucket (->> (range num-buckets)
                        (reduce (fn [max-b b]
                                  (if (> (histogram b) (histogram max-b)) b max-b))
                                0))
        [max-start max-end] (bucket-range max-bucket)]
    (println "\nStatistics:")
    (println (apply str (repeat 45 "-")))
    (println "Total packets     :" total)
    (println "Average size      :" (format "%.1f bytes" (double avg-size)))
    (when (pos? total)
      (println "Most common range :"
               (format "%s - %s (%d packets)"
                      (format-size max-start)
                      (format-size max-end)
                      (histogram max-bucket))))

    ;; Distribution summary
    (let [small (reduce + (map histogram (range 0 4)))         ; 0-1023 bytes
          medium (reduce + (map histogram (range 4 8)))        ; 1024-2047 bytes
          large (reduce + (map histogram (range 8 num-buckets)))] ; 2048+ bytes
      (println "\nDistribution:")
      (println (format "  Small (0-1K):    %d (%.1f%%)" small (if (pos? total) (* 100.0 (/ small total)) 0.0)))
      (println (format "  Medium (1K-2K):  %d (%.1f%%)" medium (if (pos? total) (* 100.0 (/ medium total)) 0.0)))
      (println (format "  Large (2K+):     %d (%.1f%%)" large (if (pos? total) (* 100.0 (/ large total)) 0.0))))))

;;; ============================================================================
;;; Part 7: Simulation
;;; ============================================================================

(defn simulate-network-traffic
  "Simulate packet captures for testing"
  [histogram-map]
  (println "\nSimulating network traffic...")

  ;; Simulate various packet sizes with realistic distribution
  ;; - Many small packets (ACKs, DNS, etc.)
  ;; - Medium packets (HTTP headers, etc.)
  ;; - Large packets (MTU-sized for data transfer)

  ;; Small packets (40-200 bytes): TCP ACKs, DNS queries
  (doseq [_ (range 30)]
    (record-packet histogram-map (+ 40 (rand-int 160))))

  ;; Medium packets (200-600 bytes): HTTP requests/responses
  (doseq [_ (range 20)]
    (record-packet histogram-map (+ 200 (rand-int 400))))

  ;; Large packets (1400-1500 bytes): MTU-sized data
  (doseq [_ (range 40)]
    (record-packet histogram-map (+ 1400 (rand-int 100))))

  ;; Some jumbo frames (4K-8K)
  (doseq [_ (range 10)]
    (record-packet histogram-map (+ 4000 (rand-int 4000))))

  (println "  Simulated 100 packets with realistic distribution"))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 2.2: Network Packet Histogram ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create histogram map
  (println "\nStep 2: Creating histogram map...")
  (let [histogram-map (create-histogram-map)]
    (println "  Histogram map created (FD:" (:fd histogram-map) ")")
    (println "  Buckets:" num-buckets)
    (println "  Bucket size:" bucket-size "bytes")
    (println "  Max packet size tracked:" (* num-buckets bucket-size) "bytes")

    (try
      ;; Step 3: Initialize buckets
      (println "\nStep 3: Initializing buckets...")
      (initialize-buckets histogram-map)
      (println "  All" num-buckets "buckets initialized to 0")

      ;; Step 4: Create XDP program
      (println "\nStep 4: Creating XDP program...")
      (let [program (create-xdp-histogram-program (:fd histogram-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        (println "\nStep 5: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :xdp :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          ;; Step 6: Simulate network traffic
          (println "\nStep 6: XDP attachment...")
          (println "  Note: Network interface attachment requires additional setup")
          (println "  Demonstrating with simulated packet data...")
          (simulate-network-traffic histogram-map)

          ;; Step 7: Display histogram
          (println "\nStep 7: Reading histogram...")
          (let [histogram (read-histogram histogram-map)]
            (display-histogram histogram)
            (display-statistics histogram))

          ;; Step 8: Add more traffic
          (println "\nStep 8: Simulating burst of MTU-sized packets...")
          (doseq [_ (range 50)]
            (record-packet histogram-map (+ 1400 (rand-int 60))))
          (println "  Added 50 MTU-sized packets")

          ;; Display updated histogram
          (let [histogram (read-histogram histogram-map)]
            (display-histogram histogram)
            (display-statistics histogram))

          ;; Step 9: Test specific bucket access
          (println "\nStep 9: Testing specific bucket access...")
          (let [test-bucket 5  ; 1280-1535 bytes
                cnt (bpf/map-lookup histogram-map test-bucket)
                [start end] (bucket-range test-bucket)]
            (println (format "  Bucket %d (%s - %s): %d packets"
                            test-bucket
                            (format-size start)
                            (format-size end)
                            (or cnt 0))))

          ;; Cleanup
          (println "\nStep 10: Cleanup...")
          (bpf/close-program prog)
          (println "  Program closed")))

      (catch Exception e
        (println "Error:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map histogram-map)
        (println "  Map closed"))))

  (println "\n=== Lab 2.2 Complete! ===")
  true)

;;; ============================================================================
;;; Part 9: Challenge - Per-Protocol Histograms
;;; ============================================================================

(defn run-challenge []
  (println "\n=== Lab 2.2 Challenge: Per-Protocol Histograms ===\n")

  ;; Create separate histograms for TCP, UDP, and ICMP
  (let [tcp-map (bpf/create-map {:map-type :array
                                  :key-size 4
                                  :value-size 8
                                  :max-entries 32
                                  :map-name "tcp_histogram"
                                  :key-serializer utils/int->bytes
                                  :key-deserializer utils/bytes->int
                                  :value-serializer utils/long->bytes
                                  :value-deserializer utils/bytes->long})
        udp-map (bpf/create-map {:map-type :array
                                  :key-size 4
                                  :value-size 8
                                  :max-entries 32
                                  :map-name "udp_histogram"
                                  :key-serializer utils/int->bytes
                                  :key-deserializer utils/bytes->int
                                  :value-serializer utils/long->bytes
                                  :value-deserializer utils/bytes->long})]

    (println "Created per-protocol histogram maps")

    ;; Initialize
    (doseq [bucket (range 32)]
      (bpf/map-update tcp-map bucket 0)
      (bpf/map-update udp-map bucket 0))

    ;; Simulate TCP traffic (larger packets)
    (println "\nSimulating TCP traffic (data transfers)...")
    (doseq [_ (range 50)]
      (let [size (+ 1000 (rand-int 500))
            bucket (min (quot size 64) 31)]
        (let [current (or (bpf/map-lookup tcp-map bucket) 0)]
          (bpf/map-update tcp-map bucket (inc current)))))

    ;; Simulate UDP traffic (smaller packets)
    (println "Simulating UDP traffic (DNS, etc.)...")
    (doseq [_ (range 30)]
      (let [size (+ 50 (rand-int 200))
            bucket (min (quot size 64) 31)]
        (let [current (or (bpf/map-lookup udp-map bucket) 0)]
          (bpf/map-update udp-map bucket (inc current)))))

    ;; Display results
    (println "\nTCP Packet Size Distribution:")
    (let [tcp-hist (into [] (for [b (range 32)] (or (bpf/map-lookup tcp-map b) 0)))
          tcp-total (reduce + tcp-hist)]
      (doseq [b (range 32)
              :let [count (tcp-hist b)]
              :when (> count 0)]
        (println (format "  %4d-%4d bytes: %d" (* b 64) (+ (* b 64) 63) count)))
      (println "  Total TCP packets:" tcp-total))

    (println "\nUDP Packet Size Distribution:")
    (let [udp-hist (into [] (for [b (range 32)] (or (bpf/map-lookup udp-map b) 0)))
          udp-total (reduce + udp-hist)]
      (doseq [b (range 32)
              :let [count (udp-hist b)]
              :when (> count 0)]
        (println (format "  %4d-%4d bytes: %d" (* b 64) (+ (* b 64) 63) count)))
      (println "  Total UDP packets:" udp-total))

    ;; Cleanup
    (bpf/close-map tcp-map)
    (bpf/close-map udp-map)
    (println "\nChallenge maps closed"))

  (println "\n=== Challenge Complete! ==="))

(defn -main [& args]
  (run-lab)
  (run-challenge)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)
  (run-challenge)

  ;; Experiment: Logarithmic buckets
  ;; Bucket 0: 0-63 bytes
  ;; Bucket 1: 64-127 bytes
  ;; Bucket 2: 128-255 bytes
  ;; ...

  ;; Real-time visualization loop
  (defn live-histogram [histogram-map interval-ms]
    (loop []
      (Thread/sleep interval-ms)
      (let [histogram (read-histogram histogram-map)]
        (println "\033[2J\033[H")  ; Clear screen
        (display-histogram histogram))
      (recur)))
  )
