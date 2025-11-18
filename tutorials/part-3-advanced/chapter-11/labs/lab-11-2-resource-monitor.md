# Lab 11.2: Container Resource Usage Monitor

## Objective

Monitor network resource usage per container using cgroup/sock_ops BPF programs. Track connection counts, bytes transferred, and connection lifetimes for container billing and capacity planning.

## Learning Goals

- Use cgroup/sock_ops for connection monitoring
- Handle multiple socket operation callbacks
- Track per-container network statistics
- Calculate derived metrics (throughput, connection duration)
- Export metrics for monitoring systems

## Background

Cloud providers and platform operators need to:
- Bill customers based on network usage
- Detect resource abuse
- Plan capacity
- Monitor SLAs
- Identify noisy neighbors

Cgroup BPF provides container-level accounting without per-packet overhead.

## Architecture

```
Container A                     Container B
    │                              │
    ├─ TCP Connect                 ├─ TCP Connect
    ├─ Send 1KB                    ├─ Send 10MB
    ├─ Recv 5KB                    ├─ Recv 20MB
    └─ Close                       └─ Close
    │                              │
    ▼                              ▼
┌──────────────────────────────────────────┐
│  Cgroup BPF (sock_ops)                   │
├──────────────────────────────────────────┤
│  Callbacks:                              │
│  - TCP_CONNECT_CB → track connection    │
│  - STATE_CB → update connection state   │
│  - DATA_CB → count bytes                │
│  └─→ Per-container statistics map       │
└──────────────────────────────────────────┘
             │
             ▼
    ┌────────────────┐
    │ Statistics Map │
    ├────────────────┤
    │ Container A:   │
    │  connections:2 │
    │  bytes_tx: 6KB │
    │  bytes_rx: 25KB│
    │                │
    │ Container B:   │
    │  connections:1 │
    │  bytes_tx: 10MB│
    │  bytes_rx: 20MB│
    └────────────────┘
```

## Implementation

```clojure
(ns container.resource-monitor
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.cgroup :as cgroup]))

;; ============================================================================
;; Constants
;; ============================================================================

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

;; TCP states (for STATE_CB)
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

;; struct bpf_sock_ops offsets
(def SOCK_OPS_OFFSETS
  {:op 0                ; u32
   :family 16           ; u32
   :remote-ip4 20       ; u32
   :local-ip4 24        ; u32
   :remote-port 28      ; u32
   :local-port 32       ; u32
   :bytes-received 48   ; u64
   :bytes-acked 56})    ; u64

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def container-stats
  "Per-container cumulative statistics"
  {:type :hash
   :key-type :u64       ; Cgroup ID
   :value-type :struct  ; Statistics struct
   :max-entries 1000})

(def connection-info
  "Per-connection tracking"
  {:type :hash
   :key-type :struct    ; Connection 5-tuple
   :value-type :struct  ; Connection state
   :max-entries 100000})

(def metrics-export
  "Ring buffer for metrics export"
  {:type :ring_buffer
   :max-entries (* 512 1024)})

;; Statistics structure
(defrecord ContainerStats
  [connections-active    ; u64 - Currently active
   connections-total     ; u64 - Total established
   connections-closed    ; u64 - Total closed
   bytes-sent            ; u64 - Total bytes sent
   bytes-received        ; u64 - Total bytes received
   packets-sent          ; u64 - Estimated packets sent
   packets-received      ; u64 - Estimated packets received
   last-update])         ; u64 - Timestamp

;; Connection tracking structure
(defrecord ConnectionState
  [cgroup-id      ; u64
   start-time     ; u64
   bytes-tx       ; u64
   bytes-rx       ; u64
   state          ; u32 - TCP state
   last-seen])    ; u64

;; ============================================================================
;; Main Resource Monitor Program
;; ============================================================================

(def resource-monitor-sockops
  "Monitor socket operations for resource accounting"
  {:type :cgroup-sock-ops
   :program
   [;; Get operation type
    [(bpf/load-ctx :w :r6 (:op SOCK_OPS_OFFSETS))]
    [(bpf/store-mem :w :r10 -4 :r6)]    ; Save op

    ;; Get cgroup ID
    [(bpf/call (bpf/helper :get_current_cgroup_id))]
    [(bpf/store-mem :dw :r10 -16 :r0)]  ; Save cgroup ID
    [(bpf/mov-reg :r9 :r0)]              ; Keep in r9

    ;; Branch on operation type
    [(bpf/load-mem :w :r6 :r10 -4)]
    [(bpf/jmp-imm :jeq :r6 BPF_SOCK_OPS_TCP_CONNECT_CB :handle-connect)]
    [(bpf/jmp-imm :jeq :r6 BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB :handle-established)]
    [(bpf/jmp-imm :jeq :r6 BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB :handle-established)]
    [(bpf/jmp-imm :jeq :r6 BPF_SOCK_OPS_STATE_CB :handle-state-change)]
    [(bpf/jmp :exit)]  ; Ignore other operations

    ;; ========================================================================
    ;; Handle TCP Connect
    ;; ========================================================================

    [:handle-connect]
    ;; Extract connection 5-tuple for tracking
    [(bpf/load-ctx :w :r6 (:remote-ip4 SOCK_OPS_OFFSETS))]
    [(bpf/store-mem :w :r10 -24 :r6)]   ; remote_ip

    [(bpf/load-ctx :w :r7 (:remote-port SOCK_OPS_OFFSETS))]
    [(bpf/store-mem :w :r10 -20 :r7)]   ; remote_port

    [(bpf/load-ctx :w :r8 (:local-port SOCK_OPS_OFFSETS))]
    [(bpf/store-mem :w :r10 -16 :r8)]   ; local_port

    ;; Create connection tracking entry
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -40 :r9)]  ; cgroup_id
    [(bpf/store-mem :dw :r10 -32 :r0)]  ; start_time
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :dw :r10 -48 :r1)]  ; bytes_tx = 0
    [(bpf/store-mem :dw :r10 -56 :r1)]  ; bytes_rx = 0
    [(bpf/store-mem :w :r10 -60 :r1)]   ; state = 0

    ;; Insert into connection map
    [(bpf/mov-reg :r1 (bpf/map-ref connection-info))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -24)]                 ; Key (5-tuple)
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -60)]                 ; Value (state)
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [(bpf/jmp :exit)]

    ;; ========================================================================
    ;; Handle Established Connection
    ;; ========================================================================

    [:handle-established]
    ;; Increment total connections for cgroup
    [(bpf/mov-reg :r1 (bpf/map-ref container-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]                 ; cgroup_id
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-stats)]

    ;; Increment active and total
    [(bpf/load-mem :dw :r1 :r0 0)]      ; connections_active
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]

    [(bpf/load-mem :dw :r1 :r0 8)]      ; connections_total
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 8 :r1)]

    ;; Update last_update
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r0 56 :r0)]

    [(bpf/jmp :exit)]

    [:init-stats]
    ;; Initialize statistics for new cgroup
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r10 -80 :r1)]  ; connections_active = 1
    [(bpf/store-mem :dw :r10 -72 :r1)]  ; connections_total = 1
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :dw :r10 -64 :r1)]  ; connections_closed = 0
    [(bpf/store-mem :dw :r10 -96 :r1)]  ; bytes_sent = 0
    [(bpf/store-mem :dw :r10 -88 :r1)]  ; bytes_received = 0
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -104 :r0)] ; last_update

    [(bpf/mov-reg :r1 (bpf/map-ref container-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -104)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [(bpf/jmp :exit)]

    ;; ========================================================================
    ;; Handle State Change (including close)
    ;; ========================================================================

    [:handle-state-change]
    ;; Get bytes received and acked from sock_ops
    [(bpf/load-ctx :dw :r6 (:bytes-received SOCK_OPS_OFFSETS))]
    [(bpf/store-mem :dw :r10 -120 :r6)]

    [(bpf/load-ctx :dw :r7 (:bytes-acked SOCK_OPS_OFFSETS))]
    [(bpf/store-mem :dw :r10 -112 :r7)]

    ;; Update container stats
    [(bpf/mov-reg :r1 (bpf/map-ref container-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]

    ;; Add bytes to cumulative counters
    [(bpf/load-mem :dw :r1 :r0 32)]     ; bytes_received
    [(bpf/load-mem :dw :r2 :r10 -120)]
    [(bpf/add-reg :r1 :r2)]
    [(bpf/store-mem :dw :r0 32 :r1)]

    [(bpf/load-mem :dw :r1 :r0 24)]     ; bytes_sent
    [(bpf/load-mem :dw :r2 :r10 -112)]
    [(bpf/add-reg :r1 :r2)]
    [(bpf/store-mem :dw :r0 24 :r1)]

    ;; Check if connection is closing
    ;; (This is simplified - real implementation would check TCP state)

    [:exit]
    [(bpf/mov :r0 1)]
    [(bpf/exit)]]})

;; ============================================================================
;; Userspace Monitoring
;; ============================================================================

(defn get-container-stats
  "Get statistics for a container"
  [cgroup-id]
  (when-let [stats (bpf/map-lookup container-stats cgroup-id)]
    {:cgroup-id cgroup-id
     :connections-active (:connections-active stats)
     :connections-total (:connections-total stats)
     :connections-closed (:connections-closed stats)
     :bytes-sent (:bytes-sent stats)
     :bytes-received (:bytes-received stats)
     :throughput-tx (/ (:bytes-sent stats) 1024 1024.0)  ; MB
     :throughput-rx (/ (:bytes-received stats) 1024 1024.0)}))  ; MB

(defn display-dashboard
  "Display real-time resource usage dashboard"
  []
  (println "\n=== Container Resource Usage ===")
  (println "CGROUP_ID        ACTIVE  TOTAL   CLOSED  TX(MB)   RX(MB)")
  (println "=============================================================")

  (doseq [[cgroup-id _] (bpf/map-get-all container-stats)]
    (when-let [stats (get-container-stats cgroup-id)]
      (printf "%-16x %-7d %-7d %-7d %-8.2f %.2f\n"
              (:cgroup-id stats)
              (:connections-active stats)
              (:connections-total stats)
              (:connections-closed stats)
              (:throughput-tx stats)
              (:throughput-rx stats)))))

(defn export-prometheus-metrics
  "Export metrics in Prometheus format"
  []
  (doseq [[cgroup-id _] (bpf/map-get-all container-stats)]
    (when-let [stats (get-container-stats cgroup-id)]
      (println (format "container_connections_active{cgroup=\"%x\"} %d"
                       cgroup-id (:connections-active stats)))
      (println (format "container_connections_total{cgroup=\"%x\"} %d"
                       cgroup-id (:connections-total stats)))
      (println (format "container_bytes_sent_total{cgroup=\"%x\"} %d"
                       cgroup-id (:bytes-sent stats)))
      (println (format "container_bytes_received_total{cgroup=\"%x\"} %d"
                       cgroup-id (:bytes-received stats))))))

(defn calculate-billing
  "Calculate network costs based on usage"
  [price-per-gb]
  (println "\n=== Billing Report ===")
  (println "CGROUP_ID        EGRESS(GB)  INGRESS(GB)  COST($)")
  (println "===================================================")

  (doseq [[cgroup-id _] (bpf/map-get-all container-stats)]
    (when-let [stats (get-container-stats cgroup-id)]
      (let [egress-gb (/ (:bytes-sent stats) 1024 1024 1024.0)
            ingress-gb (/ (:bytes-received stats) 1024 1024 1024.0)
            total-gb (+ egress-gb ingress-gb)
            cost (* total-gb price-per-gb)]
        (printf "%-16x %-11.4f %-12.4f $%.2f\n"
                cgroup-id egress-gb ingress-gb cost)))))

(defn -main
  [& args]
  (let [command (first args)]
    (println "Starting container resource monitor...")

    ;; Load and attach program
    (let [prog (bpf/load-program resource-monitor-sockops)
          cgroup-path (or (second args) "/sys/fs/cgroup")]
      (bpf/attach-cgroup prog cgroup-path :sock-ops)

      (case command
        "dashboard"
        (loop []
          (display-dashboard)
          (Thread/sleep 5000)
          (recur))

        "prometheus"
        (export-prometheus-metrics)

        "billing"
        (let [price (Double/parseDouble (or (nth args 2) "0.09"))]
          (calculate-billing price))

        ;; Default
        (do
          (println "Commands: dashboard, prometheus, billing")
          (display-dashboard))))))
```

## Testing

```bash
# Start monitoring
sudo lein run -m container.resource-monitor dashboard

# Generate traffic in containers
docker exec container1 curl https://example.com/large-file
docker exec container2 iperf3 -c server.example.com
```

Expected output:
```
=== Container Resource Usage ===
CGROUP_ID        ACTIVE  TOTAL   CLOSED  TX(MB)   RX(MB)
=============================================================
abc123def456     5       42      37      125.50   1024.25
789ghi012jkl     2       15      13      10.25    50.75
```

## Challenges

1. **Per-Container Breakdown**: Map cgroup IDs to container names
2. **Historical Data**: Store time-series data
3. **Alerting**: Trigger alerts on threshold violations
4. **Cost Optimization**: Identify expensive containers
5. **Anomaly Detection**: Detect unusual network patterns

## Key Takeaways

- sock_ops provides detailed connection lifecycle tracking
- Low overhead for continuous monitoring
- Essential for multi-tenant billing
- Integrates with existing metrics systems

## References

- [BPF sock_ops](https://www.kernel.org/doc/html/latest/bpf/prog_cgroup.html#bpf-cgroup-sock-ops)
- [Container Billing](https://cloud.google.com/billing/docs/how-to/export-data-bigquery)
