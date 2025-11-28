;; Lab 12.1 Solution: High-Performance Packet Counter
;; Demonstrates optimized packet counting with per-CPU data structures
;;
;; Learning Goals:
;; - Optimize for maximum throughput
;; - Use per-CPU data structures effectively
;; - Minimize instruction count
;; - Measure and validate performance

(ns lab-12-1-packet-counter
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Protocol Definitions
;; ============================================================================

(def protocol-names
  "IP protocol number to name mapping"
  {1  "ICMP"
   6  "TCP"
   17 "UDP"
   47 "GRE"
   50 "ESP"
   51 "AH"
   58 "ICMPv6"
   89 "OSPF"
   132 "SCTP"})

(defn protocol-name [proto]
  (get protocol-names proto (str "Protocol-" proto)))

;; ============================================================================
;; Version 1: Naive Implementation (Baseline)
;; ============================================================================
;; Problems: Hash map (slow lookups), map operation per packet, no batching

(defn create-naive-counter
  "Create naive packet counter (demonstration only)"
  []
  {:map-type :hash
   :key-type :u32      ; Protocol number
   :value-type :u64    ; Count
   :max-entries 256
   :description "Naive counter - hash map per packet (slow)"})

;; ============================================================================
;; Version 2: Optimized Implementation
;; ============================================================================
;; Uses per-CPU array for lock-free updates

(defn create-optimized-counter
  "Create optimized per-CPU packet counter"
  []
  {:map-type :percpu-array
   :key-type :u32      ; Protocol number as index
   :value-type :u64    ; Count
   :max-entries 256    ; All protocol numbers (0-255)
   :description "Optimized counter - per-CPU array (fast)"})

;; ============================================================================
;; Version 3: Ultra-Optimized Implementation
;; ============================================================================
;; Single structure with common protocols only

(defrecord ProtocolStats [tcp udp icmp other])

(defn create-ultra-counter
  "Create ultra-optimized counter for common protocols"
  []
  {:map-type :percpu-array
   :key-type :u32
   :value-type [:struct {:tcp :u64
                         :udp :u64
                         :icmp :u64
                         :other :u64}]
   :max-entries 1      ; Single global counter structure
   :description "Ultra counter - specialized per-CPU struct (fastest)"})

;; ============================================================================
;; Simulated Packet Generation
;; ============================================================================

(defn generate-packet-data
  "Generate simulated packet data for testing"
  [protocol & {:keys [src-ip dst-ip src-port dst-port size]
               :or {src-ip "192.168.1.100"
                    dst-ip "10.0.0.1"
                    src-port 12345
                    dst-port 80
                    size 64}}]
  {:protocol protocol
   :src-ip src-ip
   :dst-ip dst-ip
   :src-port src-port
   :dst-port dst-port
   :size size
   :timestamp (System/nanoTime)})

(defn generate-traffic-mix
  "Generate realistic traffic mix"
  [count]
  (let [distribution {:tcp 60    ; 60% TCP
                      :udp 30    ; 30% UDP
                      :icmp 5    ; 5% ICMP
                      :other 5}] ; 5% other
    (mapv (fn [_]
            (let [r (rand-int 100)
                  proto (cond
                          (< r 60) 6   ; TCP
                          (< r 90) 17  ; UDP
                          (< r 95) 1   ; ICMP
                          :else (rand-nth [47 50 51 89]))] ; Other
              (generate-packet-data proto)))
          (range count))))

;; ============================================================================
;; Naive Counter Implementation
;; ============================================================================

(defn naive-count-packets
  "Naive packet counting - hash map lookup per packet"
  [packets]
  (let [start-time (System/nanoTime)
        counters (atom {})]

    ;; Process each packet with hash map operations (slow)
    (doseq [packet packets]
      (let [proto (:protocol packet)]
        ;; Hash map get + put (simulates kernel hash map overhead)
        (swap! counters update proto (fnil inc 0))))

    (let [end-time (System/nanoTime)
          duration-ns (- end-time start-time)
          packet-count (count packets)
          ns-per-packet (/ duration-ns packet-count)]

      {:version "Naive"
       :packets packet-count
       :duration-ns duration-ns
       :ns-per-packet ns-per-packet
       :counters @counters})))

;; ============================================================================
;; Optimized Counter Implementation
;; ============================================================================

(defn optimized-count-packets
  "Optimized packet counting - array index lookup"
  [packets]
  (let [start-time (System/nanoTime)
        ;; Pre-allocated array (simulates per-CPU array)
        counters (long-array 256)]

    ;; Process with direct array indexing (fast)
    (doseq [packet packets]
      (let [proto (:protocol packet)]
        ;; Direct array index (no hashing, lock-free)
        (aset counters proto (inc (aget counters proto)))))

    (let [end-time (System/nanoTime)
          duration-ns (- end-time start-time)
          packet-count (count packets)
          ns-per-packet (/ duration-ns packet-count)]

      {:version "Optimized"
       :packets packet-count
       :duration-ns duration-ns
       :ns-per-packet ns-per-packet
       :counters (into {} (for [i (range 256)
                                :let [c (aget counters i)]
                                :when (pos? c)]
                            [i c]))})))

;; ============================================================================
;; Ultra-Optimized Counter Implementation
;; ============================================================================

(defn ultra-count-packets
  "Ultra-optimized packet counting - unrolled protocol switch"
  [packets]
  (let [start-time (System/nanoTime)
        ;; Single struct with common protocols only
        tcp-count (atom 0)
        udp-count (atom 0)
        icmp-count (atom 0)
        other-count (atom 0)]

    ;; Process with unrolled protocol check
    (doseq [packet packets]
      (let [proto (:protocol packet)]
        ;; Unrolled switch (minimal branches)
        (case (int proto)
          6  (swap! tcp-count inc)    ; TCP
          17 (swap! udp-count inc)    ; UDP
          1  (swap! icmp-count inc)   ; ICMP
          (swap! other-count inc))))  ; Other

    (let [end-time (System/nanoTime)
          duration-ns (- end-time start-time)
          packet-count (count packets)
          ns-per-packet (/ duration-ns packet-count)]

      {:version "Ultra"
       :packets packet-count
       :duration-ns duration-ns
       :ns-per-packet ns-per-packet
       :counters {:tcp @tcp-count
                  :udp @udp-count
                  :icmp @icmp-count
                  :other @other-count}})))

;; ============================================================================
;; Per-CPU Aggregation (Simulated)
;; ============================================================================

(defn simulate-percpu-aggregation
  "Simulate per-CPU counter aggregation"
  [num-cpus per-cpu-counters]
  (reduce (fn [acc cpu-stats]
            (merge-with + acc cpu-stats))
          {}
          per-cpu-counters))

(defn demonstrate-percpu
  "Demonstrate per-CPU data structure benefits"
  [total-packets num-cpus]
  (println "\n=== Per-CPU Counter Demonstration ===")
  (println (format "Simulating %d CPUs processing %d packets"
                   num-cpus total-packets))

  ;; Distribute packets across CPUs
  (let [packets-per-cpu (quot total-packets num-cpus)
        per-cpu-results (mapv (fn [cpu-id]
                                (let [cpu-packets (generate-traffic-mix packets-per-cpu)]
                                  {:cpu cpu-id
                                   :counters (-> (ultra-count-packets cpu-packets)
                                                 :counters)}))
                              (range num-cpus))]

    ;; Show per-CPU stats
    (println "\nPer-CPU Statistics:")
    (doseq [result per-cpu-results]
      (println (format "  CPU %d: TCP=%d UDP=%d ICMP=%d Other=%d"
                       (:cpu result)
                       (get-in result [:counters :tcp] 0)
                       (get-in result [:counters :udp] 0)
                       (get-in result [:counters :icmp] 0)
                       (get-in result [:counters :other] 0))))

    ;; Aggregate
    (let [aggregated (simulate-percpu-aggregation
                      num-cpus
                      (map :counters per-cpu-results))]
      (println "\nAggregated Statistics:")
      (println (format "  TCP:   %d (%.1f%%)" (:tcp aggregated)
                       (* 100.0 (/ (:tcp aggregated) total-packets))))
      (println (format "  UDP:   %d (%.1f%%)" (:udp aggregated)
                       (* 100.0 (/ (:udp aggregated) total-packets))))
      (println (format "  ICMP:  %d (%.1f%%)" (:icmp aggregated)
                       (* 100.0 (/ (:icmp aggregated) total-packets))))
      (println (format "  Other: %d (%.1f%%)" (:other aggregated)
                       (* 100.0 (/ (:other aggregated) total-packets))))

      aggregated)))

;; ============================================================================
;; Performance Benchmarking
;; ============================================================================

(defn run-benchmark
  "Run performance benchmark for all versions"
  [packet-count iterations]
  (println (format "\n=== Performance Benchmark (%d packets, %d iterations) ==="
                   packet-count iterations))

  ;; Generate test data once
  (let [test-packets (generate-traffic-mix packet-count)]

    ;; Run each version multiple times
    (let [results (for [version [{:name "Naive" :fn naive-count-packets}
                                 {:name "Optimized" :fn optimized-count-packets}
                                 {:name "Ultra" :fn ultra-count-packets}]]
                    (let [times (for [_ (range iterations)]
                                  (:ns-per-packet ((:fn version) test-packets)))
                          avg-ns (/ (reduce + times) iterations)
                          min-ns (apply min times)
                          max-ns (apply max times)]
                      {:version (:name version)
                       :avg-ns avg-ns
                       :min-ns min-ns
                       :max-ns max-ns}))]

      ;; Display results
      (println "\nResults:")
      (println "VERSION      AVG NS/PKT   MIN NS/PKT   MAX NS/PKT   RELATIVE")
      (println "============================================================")

      (let [baseline-ns (:avg-ns (first results))]
        (doseq [result results]
          (println (format "%-12s %10.1f   %10.1f   %10.1f   %.2fx"
                           (:version result)
                           (:avg-ns result)
                           (:min-ns result)
                           (:max-ns result)
                           (/ baseline-ns (:avg-ns result))))))

      results)))

;; ============================================================================
;; Optimization Analysis
;; ============================================================================

(defn analyze-optimizations
  "Analyze and explain optimization techniques"
  []
  (println "\n=== Optimization Analysis ===")

  (println "\n1. Per-CPU Arrays vs Hash Maps:")
  (println "   - Hash maps: O(1) average but with hash computation overhead")
  (println "   - Arrays: O(1) direct index, no hashing needed")
  (println "   - Per-CPU: No lock contention between CPUs")

  (println "\n2. Memory Access Patterns:")
  (println "   - Hash maps: Random memory access (cache unfriendly)")
  (println "   - Arrays: Sequential/predictable access (cache friendly)")

  (println "\n3. Branch Prediction:")
  (println "   - Generic protocol switch: Unpredictable branches")
  (println "   - Unrolled common protocols: Better branch prediction")

  (println "\n4. Instruction Count:")
  (println "   - Naive: ~40-50 instructions per packet")
  (println "   - Optimized: ~20-25 instructions per packet")
  (println "   - Ultra: ~15 instructions per packet (common case)")

  (println "\n5. Lock Contention:")
  (println "   - Shared counters: Lock/atomic overhead")
  (println "   - Per-CPU counters: No contention, aggregate in userspace"))

;; ============================================================================
;; Live Monitoring Display
;; ============================================================================

(defn display-live-stats
  "Display live packet statistics"
  [counters interval-sec]
  (println "\n=== Live Packet Statistics ===")
  (println "PROTOCOL     COUNT       RATE        %")
  (println "==========================================")

  (let [total (reduce + (vals counters))
        rate (if (pos? interval-sec)
               (/ total interval-sec)
               0)]

    ;; Display common protocols first
    (doseq [proto [6 17 1]]  ; TCP, UDP, ICMP
      (when-let [count (get counters proto)]
        (println (format "%-12s %10d  %8.0f/s  %5.1f%%"
                         (protocol-name proto)
                         count
                         (/ count interval-sec)
                         (* 100.0 (/ count total))))))

    ;; Display other protocols
    (let [other-protos (filter #(not (#{1 6 17} (key %))) counters)]
      (when (seq other-protos)
        (let [other-total (reduce + (vals other-protos))]
          (println (format "%-12s %10d  %8.0f/s  %5.1f%%"
                           "Other"
                           other-total
                           (/ other-total interval-sec)
                           (* 100.0 (/ other-total total)))))))

    (println "==========================================")
    (println (format "TOTAL        %10d  %8.0f/s  100.0%%" total rate))))

;; ============================================================================
;; Throughput Estimation
;; ============================================================================

(defn estimate-throughput
  "Estimate maximum throughput for each version"
  [ns-per-packet num-cpus]
  (let [packets-per-sec-per-cpu (/ 1e9 ns-per-packet)
        total-pps (* packets-per-sec-per-cpu num-cpus)
        mpps (/ total-pps 1e6)]
    {:ns-per-packet ns-per-packet
     :pps-per-cpu packets-per-sec-per-cpu
     :total-pps total-pps
     :mpps mpps}))

(defn throughput-analysis
  "Analyze throughput for different versions"
  [benchmark-results]
  (let [num-cpus (.. Runtime getRuntime availableProcessors)]
    (println (format "\n=== Throughput Analysis (%d CPUs) ===" num-cpus))
    (println "VERSION      NS/PKT   MPPS/CPU   TOTAL MPPS   10G CAPABLE")
    (println "=============================================================")

    (doseq [result benchmark-results]
      (let [est (estimate-throughput (:avg-ns result) num-cpus)
            ten-gig-capable? (>= (:total-pps est) 14880000)] ; 14.88 Mpps for 10Gbps
        (println (format "%-12s %6.1f   %8.2f   %10.2f   %s"
                         (:version result)
                         (:avg-ns result)
                         (/ (:pps-per-cpu est) 1e6)
                         (:mpps est)
                         (if ten-gig-capable? "YES" "NO")))))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the high-performance packet counter lab"
  [& args]
  (let [command (first args)]
    (case command
      "bench"
      (let [packet-count (or (some-> (second args) Integer/parseInt) 100000)
            iterations (or (some-> (nth args 2 nil) Integer/parseInt) 5)
            results (run-benchmark packet-count iterations)]
        (throughput-analysis results)
        (analyze-optimizations))

      "percpu"
      (let [packets (or (some-> (second args) Integer/parseInt) 100000)
            cpus (or (some-> (nth args 2 nil) Integer/parseInt)
                     (.. Runtime getRuntime availableProcessors))]
        (demonstrate-percpu packets cpus))

      "demo"
      (do
        (println "=== High-Performance Packet Counter Demo ===")
        (println "Generating test traffic...")

        (let [packets (generate-traffic-mix 50000)]
          (println (format "Generated %d packets" (count packets)))

          ;; Run ultra-optimized version
          (let [result (ultra-count-packets packets)]
            (display-live-stats
             {6 (get-in result [:counters :tcp] 0)
              17 (get-in result [:counters :udp] 0)
              1 (get-in result [:counters :icmp] 0)
              99 (get-in result [:counters :other] 0)}
             1.0)

            (println (format "\nProcessed %d packets in %.2f ms"
                             (:packets result)
                             (/ (:duration-ns result) 1e6))))))

      ;; Default: run full demo
      (do
        (println "Lab 12.1: High-Performance Packet Counter")
        (println "==========================================")
        (println "\nUsage:")
        (println "  bench [packet-count] [iterations] - Run benchmark")
        (println "  percpu [packets] [cpus]           - Demo per-CPU")
        (println "  demo                              - Quick demo")
        (println)

        ;; Run quick benchmark
        (let [results (run-benchmark 50000 3)]
          (throughput-analysis results)
          (analyze-optimizations)
          (demonstrate-percpu 100000 4))))))

;; Run with: clj -M -m lab-12-1-packet-counter
;; Or:       clj -M -m lab-12-1-packet-counter bench 100000 5
