# Lab 13.2: Event Aggregation Pipeline

## Objective

Implement in-kernel event aggregation to reduce event volume by 100× while preserving critical information. Demonstrate time-window aggregation, hash-based counting, and efficient bulk export.

## Problem Statement

**Scenario**: Network monitoring generates 1 million events/second:
```
[10:00:00.001] TCP connect: 192.168.1.10:35001 → 10.0.0.5:80
[10:00:00.002] TCP connect: 192.168.1.10:35002 → 10.0.0.5:80
[10:00:00.003] TCP connect: 192.168.1.10:35003 → 10.0.0.5:80
... 999,997 more events ...
```

**Problems**:
- 1M events/sec × 64 bytes = 64 MB/sec bandwidth
- Userspace can't keep up
- Ring buffer overflows
- 99% of events are redundant

**Solution**: Aggregate in kernel, send summaries:
```
[10:00:00.000-10:00:01.000] TCP connects: 192.168.1.10 → 10.0.0.5:80 (count: 1,000,000)
```

**Result**: 1M events → 1 summary (100,000× reduction!)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              BPF Kernel Space                       │
│                                                     │
│  Event → Extract Key → Hash → Update Counter       │
│                                ↓                    │
│                          Aggregation Map            │
│                      {key → {count, bytes}}         │
│                                ↓                    │
│                       (Time Window Expires)         │
│                                ↓                    │
│                          Ring Buffer                │
│                     [Summary][Summary]...           │
└─────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────┐
│            Userspace Processor                      │
│                                                     │
│  Read Summaries → Analyze → Store/Alert            │
└─────────────────────────────────────────────────────┘
```

## Learning Goals

- Implement time-window aggregation
- Use hash maps for counting
- Minimize event volume
- Handle map overflow gracefully
- Bulk export aggregated data

## Implementation

```clojure
(ns event-processing.aggregation-pipeline
  (:require [clj-ebpf.core :as bpf]))

;; ============================================================================
;; Configuration
;; ============================================================================

(def AGGREGATION_WINDOW_NS (* 1000 1000 1000))  ; 1 second
(def MAX_FLOWS 100000)                           ; Track top 100K flows

;; ============================================================================
;; Event Keys
;; ============================================================================

(defrecord FlowKey
  "5-tuple flow identifier"
  [src-ip :u32
   dst-ip :u32
   src-port :u16
   dst-port :u16
   protocol :u8
   padding [3 :u8]])  ; Align to 16 bytes

(defrecord ProcessKey
  "Process activity key"
  [uid :u32
   gid :u32
   pid :u32
   syscall :u32])

;; ============================================================================
;; Aggregation Values
;; ============================================================================

(defrecord FlowStats
  "Aggregated flow statistics"
  [packets :u64
   bytes :u64
   first-seen :u64
   last-seen :u64
   flags :u32          ; Bitmap of TCP flags seen
   padding :u32])

(defrecord ProcessStats
  "Aggregated process statistics"
  [count :u64
   total-duration-ns :u64
   min-duration-ns :u64
   max-duration-ns :u64])

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def flow-aggregation
  "Aggregates network flows"
  {:type :hash
   :key-type :struct    ; FlowKey
   :value-type :struct  ; FlowStats
   :max-entries MAX_FLOWS})

(def process-aggregation
  "Aggregates syscall activity per process"
  {:type :hash
   :key-type :struct    ; ProcessKey
   :value-type :struct  ; ProcessStats
   :max-entries 10000})

(def current-window
  "Current aggregation time window"
  {:type :array
   :key-type :u32
   :value-type :u64
   :max-entries 1})

(def aggregated-events
  "Export aggregated summaries"
  {:type :ring_buffer
   :max-entries (* 256 1024)})

(def overflow-counter
  "Track map overflow events"
  {:type :array
   :key-type :u32
   :value-type :u64
   :max-entries 1})

;; ============================================================================
;; Network Flow Aggregation
;; ============================================================================

(def flow-aggregator
  "Aggregates TCP/UDP flows"
  {:type :xdp
   :program
   [;; Load packet pointers
    [(bpf/load-ctx :dw :r2 0)]          ; data
    [(bpf/load-ctx :dw :r3 8)]          ; data_end

    ;; Bounds check: Eth + IP + TCP headers (54 bytes)
    [(bpf/mov-reg :r4 :r2)]
    [(bpf/add :r4 54)]
    [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

    ;; Check EtherType (IPv4 only)
    [(bpf/load-mem :h :r6 :r2 12)]
    [(bpf/endian-be :h :r6)]
    [(bpf/jmp-imm :jne :r6 0x0800 :pass)]

    ;; Extract 5-tuple to stack
    ;; Source IP (offset 26)
    [(bpf/load-mem :w :r6 :r2 26)]
    [(bpf/store-mem :w :r10 -16 :r6)]

    ;; Destination IP (offset 30)
    [(bpf/load-mem :w :r6 :r2 30)]
    [(bpf/store-mem :w :r10 -12 :r6)]

    ;; Protocol (offset 23)
    [(bpf/load-mem :b :r6 :r2 23)]
    [(bpf/store-mem :b :r10 -3 :r6)]

    ;; Source Port (offset 34)
    [(bpf/load-mem :h :r6 :r2 34)]
    [(bpf/endian-be :h :r6)]
    [(bpf/store-mem :h :r10 -8 :r6)]

    ;; Destination Port (offset 36)
    [(bpf/load-mem :h :r6 :r2 36)]
    [(bpf/endian-be :h :r6)]
    [(bpf/store-mem :h :r10 -6 :r6)]

    ;; Padding
    [(bpf/mov :r6 0)]
    [(bpf/store-mem :b :r10 -2 :r6)]
    [(bpf/store-mem :b :r10 -1 :r6)]
    [(bpf/store-mem :b :r10 -4 :r6)]

    ;; Lookup existing flow
    [(bpf/mov-reg :r1 (bpf/map-ref flow-aggregation))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :create-new-flow)]

    ;; ========================================================================
    ;; Update Existing Flow
    ;; ========================================================================

    [(bpf/mov-reg :r9 :r0)]  ; Save stats pointer

    ;; Increment packet count
    [(bpf/load-mem :dw :r1 :r9 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r9 0 :r1)]

    ;; Get packet length
    [(bpf/load-ctx :dw :r6 0)]   ; data
    [(bpf/load-ctx :dw :r7 8)]   ; data_end
    [(bpf/mov-reg :r8 :r7)]
    [(bpf/sub-reg :r8 :r6)]      ; r8 = packet length

    ;; Update byte count
    [(bpf/load-mem :dw :r1 :r9 8)]
    [(bpf/add-reg :r1 :r8)]
    [(bpf/store-mem :dw :r9 8 :r1)]

    ;; Update last-seen timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r9 24 :r0)]

    ;; Update TCP flags if TCP
    [(bpf/load-mem :b :r1 :r10 -3)]  ; protocol
    [(bpf/jmp-imm :jne :r1 6 :pass)] ; Not TCP

    ;; Extract TCP flags (offset 47)
    [(bpf/load-ctx :dw :r2 0)]       ; data
    [(bpf/load-mem :b :r1 :r2 47)]   ; TCP flags
    [(bpf/load-mem :w :r6 :r9 32)]   ; Current flags bitmap
    [(bpf/or-reg :r6 :r1)]           ; Merge flags
    [(bpf/store-mem :w :r9 32 :r6)]

    [(bpf/jmp :pass)]

    ;; ========================================================================
    ;; Create New Flow
    ;; ========================================================================

    [:create-new-flow]
    ;; Initialize FlowStats on stack
    [(bpf/mov :r1 1)]                ; packets = 1
    [(bpf/store-mem :dw :r10 -48 :r1)]

    ;; Calculate packet length
    [(bpf/load-ctx :dw :r6 0)]
    [(bpf/load-ctx :dw :r7 8)]
    [(bpf/mov-reg :r8 :r7)]
    [(bpf/sub-reg :r8 :r6)]
    [(bpf/store-mem :dw :r10 -40 :r8)]  ; bytes

    ;; Timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -32 :r0)]  ; first-seen
    [(bpf/store-mem :dw :r10 -24 :r0)]  ; last-seen

    ;; Flags (simplified)
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -16 :r1)]

    ;; Try to insert
    [(bpf/mov-reg :r1 (bpf/map-ref flow-aggregation))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]                 ; key
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -48)]                 ; value
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    ;; Check for overflow
    [(bpf/jmp-imm :jeq :r0 0 :pass)]

    ;; Map full! Increment overflow counter
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -52 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref overflow-counter))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -52)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :pass)]
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]

    [:pass]
    [(bpf/mov :r0 (bpf/xdp-action :pass))]
    [(bpf/exit)]]}))

;; ============================================================================
;; Userspace: Export Aggregated Data
;; ============================================================================

(defn export-aggregated-flows
  "Export current aggregation window to ring buffer"
  []
  (let [exported (atom 0)
        now (System/nanoTime)]

    (doseq [[flow-key flow-stats] (bpf/map-get-all flow-aggregation)]
      ;; Only export flows in completed window
      (when (< (:last-seen flow-stats) now)
        ;; Reserve space in ring buffer
        (when-let [event (bpf/ring-buffer-reserve aggregated-events 64)]
          ;; Pack flow key + stats
          (pack-flow-summary event flow-key flow-stats)
          (bpf/ring-buffer-submit event)
          (swap! exported inc))

        ;; Delete exported flow
        (bpf/map-delete! flow-aggregation flow-key)))

    @exported))

(defn pack-flow-summary
  "Pack flow key and stats into binary format"
  [buffer flow-key flow-stats]
  ;; Write flow key (16 bytes)
  (pack-u32 buffer 0 (:src-ip flow-key))
  (pack-u32 buffer 4 (:dst-ip flow-key))
  (pack-u16 buffer 8 (:src-port flow-key))
  (pack-u16 buffer 10 (:dst-port flow-key))
  (pack-u8 buffer 12 (:protocol flow-key))

  ;; Write flow stats (40 bytes)
  (pack-u64 buffer 16 (:packets flow-stats))
  (pack-u64 buffer 24 (:bytes flow-stats))
  (pack-u64 buffer 32 (:first-seen flow-stats))
  (pack-u64 buffer 40 (:last-seen flow-stats))
  (pack-u32 buffer 48 (:flags flow-stats)))

;; ============================================================================
;; Analysis and Reporting
;; ============================================================================

(defn analyze-aggregated-flows
  "Process aggregated flow summaries"
  []
  (let [flows (atom [])]
    (bpf/consume-ring-buffer
      aggregated-events
      (fn [data]
        (let [flow (unpack-flow-summary data)]
          (swap! flows conj flow)))
      {:poll-timeout-ms 100})

    ;; Analyze
    (let [total-flows (count @flows)
          total-packets (reduce + (map :packets @flows))
          total-bytes (reduce + (map :bytes @flows))]

      (println (format "\n=== Aggregated Flow Summary ==="))
      (println (format "Flows: %d" total-flows))
      (println (format "Packets: %d (avg %.1f per flow)"
                       total-packets
                       (if (zero? total-flows) 0
                           (/ total-packets (double total-flows)))))
      (println (format "Bytes: %d (avg %.1f per flow)"
                       total-bytes
                       (if (zero? total-flows) 0
                           (/ total-bytes (double total-flows)))))

      ;; Top talkers
      (println "\n=== Top 10 Flows by Packets ===")
      (println "SRC_IP          DST_IP          PORT   PACKETS    BYTES")
      (println "=======================================================")
      (doseq [flow (take 10 (sort-by :packets > @flows))]
        (printf "%-15s %-15s %-6d %-10d %d\n"
                (ip-to-string (:src-ip flow))
                (ip-to-string (:dst-ip flow))
                (:dst-port flow)
                (:packets flow)
                (:bytes flow))))))

;; ============================================================================
;; Time Window Management
;; ============================================================================

(defn aggregation-loop
  "Periodic export of aggregated data"
  [interval-ms]
  (loop []
    (Thread/sleep interval-ms)

    (let [start (System/currentTimeMillis)
          exported (export-aggregated-flows)
          duration (- (System/currentTimeMillis) start)
          overflow (get-overflow-count)]

      (println (format "[%s] Exported %d flows in %dms"
                       (java.time.LocalTime/now)
                       exported
                       duration))

      (when (pos? overflow)
        (log/warn "Map overflow detected:" overflow "flows dropped")))

    (recur)))

(defn get-overflow-count []
  (or (bpf/map-lookup overflow-counter 0) 0))

;; ============================================================================
;; Performance Comparison
;; ============================================================================

(defn measure-reduction
  "Compare raw vs aggregated event rates"
  [duration-sec]
  (println "\n=== Measuring Event Reduction ===\n")

  ;; Count raw events (if we sent them all)
  (let [flow-count (count (bpf/map-get-all flow-aggregation))
        total-packets (reduce + (map (comp :packets second)
                                    (bpf/map-get-all flow-aggregation)))]

    (println (format "Raw events (if sent individually): %d" total-packets))
    (println (format "Aggregated summaries: %d" flow-count))
    (println (format "Reduction ratio: %.1fx"
                     (if (zero? flow-count) 0
                         (/ total-packets (double flow-count)))))

    (println (format "\nBandwidth savings:"))
    (println (format "  Raw: %.1f MB/sec"
                     (/ (* total-packets 64) duration-sec 1024 1024)))
    (println (format "  Aggregated: %.1f KB/sec"
                     (/ (* flow-count 64) duration-sec 1024)))))

;; ============================================================================
;; Main
;; ============================================================================

(defn -main [& args]
  (let [[command interface] args]
    (println "Event Aggregation Pipeline")
    (println "===========================\n")

    ;; Load and attach
    (let [prog (bpf/load-program flow-aggregator)]
      (bpf/attach-xdp prog (or interface "eth0"))

      ;; Initialize
      (bpf/map-update! overflow-counter 0 0)

      (case (or command "monitor")
        "monitor"
        (do
          (println "Starting aggregation (1 second windows)")
          (println "Press Ctrl-C to stop\n")

          ;; Start export loop
          (future (aggregation-loop 1000))

          ;; Analyze exported data
          (loop []
            (Thread/sleep 1000)
            (analyze-aggregated-flows)
            (recur)))

        "measure"
        (do
          (println "Running for 60 seconds...")
          (Thread/sleep 60000)
          (measure-reduction 60))

        (println "Usage: monitor|measure [interface]")))))

;; Expected output:
;; === Aggregated Flow Summary ===
;; Flows: 1,523
;; Packets: 8,453,291 (avg 5,551.2 per flow)
;; Bytes: 10,234,567,890 (avg 6,718,234.5 per flow)
;;
;; === Top 10 Flows by Packets ===
;; SRC_IP          DST_IP          PORT   PACKETS    BYTES
;; =======================================================
;; 192.168.1.100   10.0.0.5        443    1234567    89012345
;; 192.168.1.101   10.0.0.5        443    987654     67890123
;; ...
;;
;; === Measuring Event Reduction ===
;; Raw events: 8,453,291
;; Aggregated summaries: 1,523
;; Reduction ratio: 5,549.6x  ← 5000× reduction!
```

## Key Concepts

1. **Time-Window Aggregation** - Bucket events by time period
2. **Hash-Based Counting** - Use hash map for efficient updates
3. **Lazy Export** - Export only when window completes
4. **Overflow Handling** - Track when map fills up
5. **Bulk Processing** - Process aggregated data in batches

## Expected Results

```
Scenario: 1M packets/sec across 1000 connections

Without aggregation:
  - 1M events/sec × 64 bytes = 64 MB/sec
  - Userspace overwhelmed
  - Ring buffer overflows

With aggregation (1 sec windows):
  - 1000 summaries/sec × 64 bytes = 64 KB/sec
  - 1000× reduction
  - No overflow
  - Complete visibility maintained
```

## Challenges

1. **Adaptive Windows**: Adjust window size based on load
2. **Top-K Tracking**: Track only top 1000 flows, evict others
3. **Count-Min Sketch**: Probabilistic counting with bounded memory
4. **Hierarchical Aggregation**: Aggregate by /24 subnet first
5. **Multi-Level Summaries**: 1-sec, 1-min, 1-hour windows

## Key Takeaways

- Aggregation reduces event volume by 100-1000×
- Essential for high-rate event sources
- Minimal information loss for most use cases
- Map overflow must be handled gracefully
- Time-window approach balances latency and reduction

## References

- [Data Aggregation](https://en.wikipedia.org/wiki/Aggregate_function)
- [Count-Min Sketch](https://en.wikipedia.org/wiki/Count%E2%80%93min_sketch)
- [Top-K Problem](https://en.wikipedia.org/wiki/Selection_algorithm)
