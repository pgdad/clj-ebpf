(ns lab-11-2-resource-monitor
  "Lab 11.2: Container Resource Usage Monitor

   This solution demonstrates:
   - Cgroup sock_ops BPF concepts for connection monitoring
   - Per-container network statistics tracking
   - Connection lifecycle tracking (established, closed)
   - Bytes sent/received accounting
   - Prometheus-style metrics export
   - Container billing calculation

   Note: Cgroup BPF requires cgroup v2 and kernel 4.13+.
   This solution simulates cgroup concepts using tracepoint as fallback.

   Run with: sudo clojure -M -m lab-11-2-resource-monitor
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.time Instant LocalDateTime ZoneId]
           [java.time.format DateTimeFormatter]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; sock_ops operation types
(def BPF_SOCK_OPS_VOID 0)
(def BPF_SOCK_OPS_TIMEOUT_INIT 1)
(def BPF_SOCK_OPS_RWND_INIT 2)
(def BPF_SOCK_OPS_TCP_CONNECT_CB 3)
(def BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 4)
(def BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB 5)
(def BPF_SOCK_OPS_NEEDS_ECN 6)
(def BPF_SOCK_OPS_STATE_CB 7)
(def BPF_SOCK_OPS_TCP_LISTEN_CB 8)

;; TCP states
(def TCP_ESTABLISHED 1)
(def TCP_SYN_SENT 2)
(def TCP_SYN_RECV 3)
(def TCP_FIN_WAIT1 4)
(def TCP_FIN_WAIT2 5)
(def TCP_TIME_WAIT 6)
(def TCP_CLOSE 7)
(def TCP_CLOSE_WAIT 8)
(def TCP_LAST_ACK 9)
(def TCP_LISTEN 10)
(def TCP_CLOSING 11)

;; Default billing rate (per GB)
(def DEFAULT_PRICE_PER_GB 0.09)

;;; ============================================================================
;;; Part 2: BPF Maps
;;; ============================================================================

(defn create-container-stats-map
  "Hash map: Container ID (string hash) -> stats struct"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8
                   :value-size 64
                   :max-entries 1000
                   :map-name "container_stats"
                   :key-serializer utils/long->bytes
                   :key-deserializer utils/bytes->long
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-connection-count-map
  "Array map for global connection counts:
   [0] = total_established
   [1] = total_closed
   [2] = currently_active
   [3] = total_bytes_tx"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 8
                   :map-name "conn_counts"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 3: BPF Program (Stats Tracker)
;;; ============================================================================

(defn create-sockops-monitor-program
  "Create BPF program that tracks socket operations.

   This demonstrates the cgroup/sock_ops hook concept:
   1. Receives context with sock_ops info (op type, bytes, etc.)
   2. Handles connection lifecycle events
   3. Tracks per-container statistics

   Note: Real cgroup programs use :cgroup-sock-ops program type.
   This uses :tracepoint style for broader compatibility."
  [stats-fd]
  (bpf/assemble
    [;; r6 = context pointer
     (bpf/mov-reg :r6 :r1)

     ;; Default stats key = 0 (total established)
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

     ;; Return 1 (continue processing)
     (bpf/mov :r0 1)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 4: Container Statistics Structure
;;; ============================================================================

(defrecord ContainerStats
  [container-id
   connections-active
   connections-total
   connections-closed
   bytes-sent
   bytes-received
   first-seen
   last-seen])

(defn create-empty-stats
  "Create empty statistics for a container"
  [container-id]
  (->ContainerStats container-id 0 0 0 0 0
                    (System/currentTimeMillis)
                    (System/currentTimeMillis)))

;;; ============================================================================
;;; Part 5: Simulated Socket Operations
;;; ============================================================================

(defn generate-socket-event
  "Generate a simulated socket operation event"
  []
  (let [containers ["container-web-1" "container-web-2"
                    "container-api-1" "container-api-2"
                    "container-db-1" "container-worker-1"]
        ops [:connect :established :data-tx :data-rx :close]]
    {:container-id (rand-nth containers)
     :op (rand-nth ops)
     :bytes (case (rand-nth ops)
              :data-tx (rand-int 100000)
              :data-rx (rand-int 500000)
              0)
     :remote-ip (format "10.0.%d.%d" (rand-int 256) (rand-int 256))
     :remote-port (+ 1024 (rand-int 60000))
     :local-port (rand-nth [80 443 8080 3000 5432 6379])
     :timestamp (System/currentTimeMillis)}))

(defn simulate-socket-events
  "Simulate socket operation events"
  [num-events]
  (repeatedly num-events generate-socket-event))

;;; ============================================================================
;;; Part 6: Event Processing
;;; ============================================================================

(defn process-socket-event
  "Process a socket operation event and update container statistics"
  [event container-stats-atom]
  (let [{:keys [container-id op bytes]} event]
    ;; Ensure container has stats entry
    (when-not (contains? @container-stats-atom container-id)
      (swap! container-stats-atom assoc container-id
             (create-empty-stats container-id)))

    ;; Update based on operation type
    (case op
      :connect
      (swap! container-stats-atom update container-id
             (fn [stats]
               (-> stats
                   (update :connections-active inc))))

      :established
      (swap! container-stats-atom update container-id
             (fn [stats]
               (-> stats
                   (update :connections-total inc)
                   (assoc :last-seen (System/currentTimeMillis)))))

      :data-tx
      (swap! container-stats-atom update container-id
             (fn [stats]
               (-> stats
                   (update :bytes-sent + bytes)
                   (assoc :last-seen (System/currentTimeMillis)))))

      :data-rx
      (swap! container-stats-atom update container-id
             (fn [stats]
               (-> stats
                   (update :bytes-received + bytes)
                   (assoc :last-seen (System/currentTimeMillis)))))

      :close
      (swap! container-stats-atom update container-id
             (fn [stats]
               (-> stats
                   (update :connections-active #(max 0 (dec %)))
                   (update :connections-closed inc)
                   (assoc :last-seen (System/currentTimeMillis)))))

      nil)

    event))

;;; ============================================================================
;;; Part 7: Display Functions
;;; ============================================================================

(defn format-bytes
  "Format bytes to human-readable string"
  [bytes]
  (cond
    (>= bytes (* 1024 1024 1024)) (format "%.2f GB" (/ bytes (* 1024.0 1024 1024)))
    (>= bytes (* 1024 1024)) (format "%.2f MB" (/ bytes (* 1024.0 1024)))
    (>= bytes 1024) (format "%.2f KB" (/ bytes 1024.0))
    :else (format "%d B" bytes)))

(defn display-sockops-info
  "Display cgroup sock_ops information"
  []
  (println "\nCgroup Resource Usage Monitor:")
  (println "===============================================")
  (println "")
  (println "  Cgroup Hook: sock_ops")
  (println "  Mode: RESOURCE ACCOUNTING")
  (println "")
  (println "  Tracked Operations:")
  (println "    - TCP_CONNECT_CB: New connection attempts")
  (println "    - ACTIVE_ESTABLISHED_CB: Connection established")
  (println "    - PASSIVE_ESTABLISHED_CB: Incoming connection")
  (println "    - STATE_CB: Connection state changes")
  (println "")
  (println "  Metrics Collected:")
  (println "    - Connections (active, total, closed)")
  (println "    - Bytes sent/received")
  (println "    - Connection duration")
  (println "==============================================="))

(defn display-dashboard
  "Display resource usage dashboard"
  [container-stats]
  (println "\nContainer Resource Usage Dashboard:")
  (println "================================================================================")
  (println "CONTAINER          ACTIVE  TOTAL   CLOSED  TX           RX           DURATION")
  (println "================================================================================")

  (doseq [[container-id stats] (sort-by key container-stats)]
    (let [{:keys [connections-active connections-total connections-closed
                  bytes-sent bytes-received first-seen last-seen]} stats
          duration-ms (- last-seen first-seen)
          duration-sec (/ duration-ms 1000.0)]
      (printf "%-18s %-7d %-7d %-7d %-12s %-12s %.1fs\n"
              container-id
              connections-active
              connections-total
              connections-closed
              (format-bytes bytes-sent)
              (format-bytes bytes-received)
              duration-sec)))

  (println "================================================================================"))

(defn display-global-stats
  "Display global aggregate statistics"
  [container-stats]
  (let [totals (reduce (fn [acc [_ stats]]
                         (-> acc
                             (update :active + (:connections-active stats))
                             (update :total + (:connections-total stats))
                             (update :closed + (:connections-closed stats))
                             (update :bytes-tx + (:bytes-sent stats))
                             (update :bytes-rx + (:bytes-received stats))))
                       {:active 0 :total 0 :closed 0 :bytes-tx 0 :bytes-rx 0}
                       container-stats)]
    (println "\nGlobal Statistics:")
    (println "===============================================")
    (println (format "  Active connections  : %,d" (:active totals)))
    (println (format "  Total established   : %,d" (:total totals)))
    (println (format "  Total closed        : %,d" (:closed totals)))
    (println (format "  Total bytes TX      : %s" (format-bytes (:bytes-tx totals))))
    (println (format "  Total bytes RX      : %s" (format-bytes (:bytes-rx totals))))
    (println (format "  Total throughput    : %s" (format-bytes (+ (:bytes-tx totals)
                                                                    (:bytes-rx totals)))))
    (println "===============================================")))

(defn display-prometheus-metrics
  "Display metrics in Prometheus format"
  [container-stats]
  (println "\nPrometheus Metrics:")
  (println "===============================================")

  (doseq [[container-id stats] container-stats]
    (let [{:keys [connections-active connections-total connections-closed
                  bytes-sent bytes-received]} stats
          labels (format "container=\"%s\"" container-id)]
      (println (format "container_connections_active{%s} %d" labels connections-active))
      (println (format "container_connections_total{%s} %d" labels connections-total))
      (println (format "container_connections_closed{%s} %d" labels connections-closed))
      (println (format "container_bytes_sent_total{%s} %d" labels bytes-sent))
      (println (format "container_bytes_received_total{%s} %d" labels bytes-received))))

  (println "==============================================="))

(defn display-billing-report
  "Display billing report based on usage"
  [container-stats price-per-gb]
  (println "\nBilling Report:")
  (println "===============================================")
  (println (format "  Rate: $%.4f per GB" price-per-gb))
  (println "")
  (println "CONTAINER          EGRESS(GB)   INGRESS(GB)  TOTAL(GB)    COST")
  (println "---------------------------------------------------------------")

  (let [total-cost (atom 0.0)]
    (doseq [[container-id stats] (sort-by key container-stats)]
      (let [{:keys [bytes-sent bytes-received]} stats
            egress-gb (/ bytes-sent (* 1024.0 1024 1024))
            ingress-gb (/ bytes-received (* 1024.0 1024 1024))
            total-gb (+ egress-gb ingress-gb)
            cost (* total-gb price-per-gb)]
        (swap! total-cost + cost)
        (printf "%-18s %-12.6f %-12.6f %-12.6f $%.4f\n"
                container-id egress-gb ingress-gb total-gb cost)))

    (println "---------------------------------------------------------------")
    (printf "TOTAL                                                   $%.4f\n" @total-cost))

  (println "==============================================="))

(defn display-noisy-neighbors
  "Identify and display noisy neighbor containers"
  [container-stats]
  (let [sorted-by-bytes (sort-by (fn [[_ s]] (+ (:bytes-sent s) (:bytes-received s)))
                                 > container-stats)
        total-bytes (reduce (fn [acc [_ s]] (+ acc (:bytes-sent s) (:bytes-received s)))
                            0 container-stats)]
    (println "\nNoisy Neighbor Analysis:")
    (println "===============================================")

    (doseq [[container-id stats] (take 3 sorted-by-bytes)]
      (let [container-bytes (+ (:bytes-sent stats) (:bytes-received stats))
            percentage (* 100.0 (/ container-bytes (max 1 total-bytes)))]
        (printf "  %-18s: %s (%.1f%% of total)\n"
                container-id (format-bytes container-bytes) percentage)))

    (when (> (count sorted-by-bytes) 3)
      (let [top-3-bytes (reduce (fn [acc [_ s]]
                                  (+ acc (:bytes-sent s) (:bytes-received s)))
                                0 (take 3 sorted-by-bytes))
            top-3-pct (* 100.0 (/ top-3-bytes (max 1 total-bytes)))]
        (println "")
        (if (> top-3-pct 80)
          (println (format "  [!] WARNING: Top 3 containers use %.1f%% of bandwidth" top-3-pct))
          (println (format "  [OK] Bandwidth fairly distributed (top 3: %.1f%%)" top-3-pct)))))

    (println "===============================================")))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 11.2: Container Resource Usage Monitor ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [container-stats-map (create-container-stats-map)
        conn-count-map (create-connection-count-map)]
    (println "  Container stats map created (FD:" (:fd container-stats-map) ")")
    (println "  Connection count map created (FD:" (:fd conn-count-map) ")")

    ;; Initialize counts
    (doseq [i (range 8)]
      (bpf/map-update conn-count-map i 0))

    (try
      ;; Step 3: Create sockops monitor program
      (println "\nStep 3: Creating sock_ops monitor program...")
      (let [program (create-sockops-monitor-program (:fd conn-count-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :tracepoint
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display sockops info
            (println "\nStep 5: sock_ops hook information...")
            (display-sockops-info)

            ;; Step 6: Simulate socket events
            (println "\nStep 6: Simulating container network activity...")
            (let [num-events 200
                  _ (println (format "  Generating %d socket events..." num-events))
                  events (simulate-socket-events num-events)
                  container-stats (atom {})]

              ;; Process all events
              (doseq [event events]
                (process-socket-event event container-stats))

              ;; Step 7: Display dashboard
              (println "\nStep 7: Resource usage dashboard...")
              (display-dashboard @container-stats)

              ;; Step 8: Global statistics
              (println "\nStep 8: Aggregate statistics...")
              (display-global-stats @container-stats)

              ;; Step 9: Prometheus metrics
              (println "\nStep 9: Prometheus-style metrics export...")
              (display-prometheus-metrics @container-stats)

              ;; Step 10: Billing report
              (println "\nStep 10: Billing calculation...")
              (display-billing-report @container-stats DEFAULT_PRICE_PER_GB)

              ;; Step 11: Noisy neighbor analysis
              (println "\nStep 11: Noisy neighbor analysis...")
              (display-noisy-neighbors @container-stats)

              ;; Step 12: Update BPF maps
              (println "\nStep 12: Updating BPF maps with totals...")
              (let [totals (reduce (fn [acc [_ stats]]
                                     (-> acc
                                         (update :established + (:connections-total stats))
                                         (update :closed + (:connections-closed stats))
                                         (update :active + (:connections-active stats))
                                         (update :bytes-tx + (:bytes-sent stats))))
                                   {:established 0 :closed 0 :active 0 :bytes-tx 0}
                                   @container-stats)]
                (bpf/map-update conn-count-map 0 (:established totals))
                (bpf/map-update conn-count-map 1 (:closed totals))
                (bpf/map-update conn-count-map 2 (:active totals))
                (bpf/map-update conn-count-map 3 (:bytes-tx totals))

                (println (format "  counts[0] (established) = %,d" (bpf/map-lookup conn-count-map 0)))
                (println (format "  counts[1] (closed)      = %,d" (bpf/map-lookup conn-count-map 1)))
                (println (format "  counts[2] (active)      = %,d" (bpf/map-lookup conn-count-map 2)))
                (println (format "  counts[3] (bytes_tx)    = %,d" (bpf/map-lookup conn-count-map 3)))))

            ;; Step 13: Cleanup
            (println "\nStep 13: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map container-stats-map)
        (bpf/close-map conn-count-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 11.2 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test formatting
  (format-bytes 1234)           ; "1234 B"
  (format-bytes 12345)          ; "12.06 KB"
  (format-bytes 12345678)       ; "11.77 MB"
  (format-bytes 1234567890)     ; "1.15 GB"

  ;; Test event generation
  (generate-socket-event)
  )
