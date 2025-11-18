# Lab 13.3: Lost Event Detection and Recovery

## Objective

Build a robust event processing system that detects lost events, logs gaps, and implements recovery strategies. Handle buffer overflow gracefully to maintain system reliability under extreme load.

## Problem Statement

**Reality**: Ring buffers fill up, events get dropped.

**Common Causes**:
```
1. Event Burst:
   Normal: 10K events/sec
   Burst:  500K events/sec for 5 seconds
   → Buffer overflows in 2 seconds

2. Slow Consumer:
   Producer: 100K events/sec
   Consumer: 80K events/sec (blocking I/O)
   → Buffer fills in 10 seconds

3. Consumer Failure:
   Producer: Running
   Consumer: Crashed/stuck
   → Buffer fills, events dropped
```

**Consequences**:
- Data loss
- Incomplete analysis
- Compliance violations
- Silent failures (worst case!)

**Solution**: Detect, log, and recover from event loss.

## Learning Goals

- Implement sequence numbers for gap detection
- Detect and log lost events
- Handle backpressure gracefully
- Implement recovery strategies
- Monitor system health

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              BPF Producer                           │
│                                                     │
│  Event → Add Sequence # → Try Reserve               │
│                              ↓                      │
│                          Success?                   │
│                         ↙        ↘                  │
│                    Yes              No              │
│                     ↓               ↓               │
│                  Submit      Increment Drop Counter │
│                                     ↓               │
│                              Log to Drop Buffer     │
└─────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────┐
│            Userspace Consumer                       │
│                                                     │
│  Read Event → Check Sequence # → Detect Gap?       │
│                                      ↓              │
│                                   Yes/No            │
│                                      ↓              │
│                            Log Gap + Recovery       │
└─────────────────────────────────────────────────────┘
```

## Implementation

```clojure
(ns event-processing.lost-event-recovery
  (:require [clj-ebpf.core :as bpf]))

;; ============================================================================
;; Configuration
;; ============================================================================

(def RING_BUFFER_SIZE (* 256 1024))     ; 256 KB
(def DROP_LOG_SIZE (* 64 1024))         ; 64 KB for drop events
(def BACKPRESSURE_THRESHOLD 0.8)        ; 80% full triggers backpressure

;; ============================================================================
;; Event Structure
;; ============================================================================

(defrecord SequencedEvent
  "Event with sequence number for gap detection"
  [sequence :u64       ; Global sequence number
   timestamp :u64      ; Event timestamp
   cpu :u32            ; CPU that generated event
   type :u16           ; Event type
   flags :u16          ; Event flags
   pid :u32            ; Process ID
   data [32 :u8]])     ; Event-specific data

(def EVENT_SIZE 64)

(defrecord DropEvent
  "Logged when events are dropped"
  [timestamp :u64      ; When drop occurred
   sequence-start :u64 ; First dropped sequence number
   sequence-end :u64   ; Last dropped sequence number
   drop-count :u64     ; Number of events dropped
   reason :u32         ; Drop reason code
   cpu :u32])          ; CPU where drop occurred

(def DROP_EVENT_SIZE 40)

;; Drop reasons
(def DROP_REASON_BUFFER_FULL 1)
(def DROP_REASON_RESERVE_FAILED 2)
(def DROP_REASON_MAP_FULL 3)

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def event-buffer
  "Main event ring buffer"
  {:type :ring_buffer
   :max-entries RING_BUFFER_SIZE})

(def drop-log
  "Log of drop events"
  {:type :ring_buffer
   :max-entries DROP_LOG_SIZE})

(def sequence-counter
  "Global sequence number (per-CPU)"
  {:type :percpu_array
   :key-type :u32
   :value-type :u64
   :max-entries 1})

(def drop-stats
  "Per-CPU drop statistics"
  {:type :percpu_array
   :key-type :u32
   :value-type :struct  ; {total-drops:u64, last-drop-seq:u64}
   :max-entries 1})

(def backpressure-state
  "Backpressure control"
  {:type :array
   :key-type :u32
   :value-type :u32     ; 0=normal, 1=backpressure active
   :max-entries 1})

;; ============================================================================
;; BPF Program with Sequence Numbers
;; ============================================================================

(def sequenced-event-producer
  "Produces events with sequence numbers"
  {:type :tracepoint
   :category "syscalls"
   :name "sys_enter_write"
   :program
   [;; Check backpressure
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -4 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref backpressure-state))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :continue)]
    [(bpf/load-mem :w :r1 :r0 0)]
    [(bpf/jmp-imm :jne :r1 0 :apply-backpressure)]

    ;; ========================================================================
    ;; Get and Increment Sequence Number
    ;; ========================================================================

    [:continue]
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -8 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref sequence-counter))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/mov-reg :r9 :r0)]  ; Save pointer

    ;; Get current sequence
    [(bpf/load-mem :dw :r7 :r9 0)]  ; r7 = sequence number

    ;; Increment for next event
    [(bpf/mov-reg :r1 :r7)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r9 0 :r1)]

    ;; ========================================================================
    ;; Try to Reserve Space in Ring Buffer
    ;; ========================================================================

    [(bpf/mov-reg :r1 (bpf/map-ref event-buffer))]
    [(bpf/mov :r2 EVENT_SIZE)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    ;; Check if reservation succeeded
    [(bpf/jmp-imm :jne :r0 0 :fill-event)]

    ;; ========================================================================
    ;; Handle Drop
    ;; ========================================================================

    [:handle-drop]
    ;; r7 = dropped sequence number

    ;; Get drop stats
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -12 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref drop-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -12)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/mov-reg :r9 :r0)]

    ;; Increment drop count
    [(bpf/load-mem :dw :r1 :r9 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r9 0 :r1)]

    ;; Store dropped sequence number
    [(bpf/store-mem :dw :r9 8 :r7)]

    ;; Try to log drop event
    [(bpf/mov-reg :r1 (bpf/map-ref drop-log))]
    [(bpf/mov :r2 DROP_EVENT_SIZE)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]  ; Can't log, just exit
    [(bpf/mov-reg :r8 :r0)]

    ;; Fill drop event
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r8 0 :r0)]         ; timestamp

    [(bpf/store-mem :dw :r8 8 :r7)]         ; sequence-start
    [(bpf/store-mem :dw :r8 16 :r7)]        ; sequence-end

    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r8 24 :r1)]        ; drop-count

    [(bpf/mov :r1 DROP_REASON_BUFFER_FULL)]
    [(bpf/store-mem :w :r8 32 :r1)]         ; reason

    [(bpf/call (bpf/helper :get_smp_processor_id))]
    [(bpf/store-mem :w :r8 36 :r0)]         ; cpu

    ;; Submit drop event
    [(bpf/mov-reg :r1 :r8)]
    [(bpf/mov :r2 0)]
    [(bpf/call (bpf/helper :ringbuf_submit))]

    [(bpf/jmp :exit)]

    ;; ========================================================================
    ;; Fill Event
    ;; ========================================================================

    [:fill-event]
    [(bpf/mov-reg :r8 :r0)]  ; Save event pointer

    ;; Sequence number
    [(bpf/store-mem :dw :r8 0 :r7)]

    ;; Timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r8 8 :r0)]

    ;; CPU
    [(bpf/call (bpf/helper :get_smp_processor_id))]
    [(bpf/store-mem :w :r8 16 :r0)]

    ;; Type (simplified)
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :h :r8 20 :r1)]

    ;; PID
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r8 24 :r0)]

    ;; Submit
    [(bpf/mov-reg :r1 :r8)]
    [(bpf/mov :r2 0)]
    [(bpf/call (bpf/helper :ringbuf_submit))]
    [(bpf/jmp :exit)]

    ;; ========================================================================
    ;; Backpressure - Sample Instead of Drop
    ;; ========================================================================

    [:apply-backpressure]
    ;; Sample 10% of events under backpressure
    [(bpf/call (bpf/helper :get_prandom_u32))]
    [(bpf/mod :r0 100)]
    [(bpf/jmp-imm :jge :r0 10 :exit)]  ; Skip 90%
    [(bpf/jmp :continue)]              ; Process 10%

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))

;; ============================================================================
;; Userspace: Gap Detection
;; ============================================================================

(defrecord ConsumerState
  [expected-sequence    ; Next expected sequence number
   total-events         ; Total events received
   total-gaps           ; Number of gaps detected
   total-lost           ; Total lost events
   last-event-time])    ; Last event timestamp

(defn create-consumer-state []
  (atom {:expected-sequence 0
         :total-events 0
         :total-gaps 0
         :total-lost 0
         :last-event-time 0}))

(defn process-event-with-gap-detection
  "Process event and detect gaps in sequence numbers"
  [state event]
  (let [sequence (:sequence event)
        expected (:expected-sequence @state)]

    ;; Detect gap
    (if (= sequence expected)
      ;; No gap
      (swap! state update :total-events inc)

      ;; Gap detected!
      (let [gap-size (- sequence expected)
            lost-events (dec gap-size)]  ; -1 because sequence numbers are inclusive

        (swap! state
               (fn [s]
                 (-> s
                     (update :total-events inc)
                     (update :total-gaps inc)
                     (update :total-lost + lost-events))))

        ;; Log gap
        (log/warn (format "GAP DETECTED: Expected seq %d, got %d. Lost %d events."
                         expected sequence lost-events))

        ;; Attempt recovery
        (attempt-recovery expected sequence)))

    ;; Update expected sequence
    (swap! state assoc
           :expected-sequence (inc sequence)
           :last-event-time (:timestamp event))

    event))

(defn attempt-recovery
  "Attempt to recover lost events"
  [start-seq end-seq]
  ;; Recovery strategies:

  ;; 1. Check drop log
  (when-let [drop-events (read-drop-log start-seq end-seq)]
    (log/info "Drop log shows" (count drop-events) "drop events in gap"))

  ;; 2. Query kernel maps for state
  ;; If events were just dropped (not lost permanently),
  ;; aggregated state might still be available

  ;; 3. Mark gap in output
  (write-gap-marker start-seq end-seq))

(defn read-drop-log
  "Read drop events from drop log"
  [start-seq end-seq]
  (let [drops (atom [])]
    (bpf/consume-ring-buffer
      drop-log
      (fn [data]
        (let [drop (parse-drop-event data)]
          (when (and (>= (:sequence-end drop) start-seq)
                     (<= (:sequence-start drop) end-seq))
            (swap! drops conj drop))))
      {:poll-timeout-ms 10})
    @drops))

(defn parse-drop-event [data]
  {:timestamp (bytes->u64 data 0)
   :sequence-start (bytes->u64 data 8)
   :sequence-end (bytes->u64 data 16)
   :drop-count (bytes->u64 data 24)
   :reason (bytes->u32 data 32)
   :cpu (bytes->u32 data 36)})

(defn write-gap-marker
  "Write gap marker to output"
  [start-seq end-seq]
  (println (format "\n!!! GAP: sequences %d-%d missing (%d events) !!!\n"
                   start-seq end-seq (- end-seq start-seq))))

;; ============================================================================
;; Backpressure Management
;; ============================================================================

(defn monitor-buffer-pressure
  "Monitor buffer usage and apply backpressure"
  []
  (loop []
    (Thread/sleep 100)  ; Check every 100ms

    ;; Get buffer stats (pseudo-code, actual implementation varies)
    (let [buffer-usage (get-buffer-usage event-buffer)]

      (cond
        ;; High pressure: Enable backpressure
        (>= buffer-usage BACKPRESSURE_THRESHOLD)
        (do
          (bpf/map-update! backpressure-state 0 1)
          (log/warn "Backpressure ENABLED" {:usage buffer-usage}))

        ;; Low pressure: Disable backpressure
        (< buffer-usage 0.5)
        (do
          (bpf/map-update! backpressure-state 0 0)
          (log/info "Backpressure DISABLED" {:usage buffer-usage}))))

    (recur)))

(defn get-buffer-usage
  "Get current buffer usage (0.0-1.0)"
  [ring-buffer]
  ;; This would use actual libbpf API to get ring buffer stats
  ;; Simplified here
  0.5)

;; ============================================================================
;; Health Monitoring
;; ============================================================================

(defn display-health-stats
  "Display comprehensive health statistics"
  [state]
  (let [s @state
        drop-total (reduce + (map (comp :total-drops second)
                                 (bpf/map-get-all drop-stats)))
        backpressure (bpf/map-lookup backpressure-state 0)]

    (println "\n=== Event Processing Health ===")
    (println (format "Events Received:  %d" (:total-events s)))
    (println (format "Events Lost:      %d" (:total-lost s)))
    (println (format "Gaps Detected:    %d" (:total-gaps s)))
    (println (format "Kernel Drops:     %d" drop-total))
    (println (format "Backpressure:     %s" (if (pos? backpressure) "ACTIVE" "Inactive")))

    (when (pos? (:total-events s))
      (println (format "Loss Rate:        %.3f%%"
                       (* 100.0 (/ (:total-lost s)
                                  (double (+ (:total-events s) (:total-lost s))))))))

    ;; Alerts
    (when (> (:total-gaps s) 0)
      (println "\n⚠️  WARNING: Gaps detected in event stream!"))

    (when (pos? backpressure)
      (println "\n⚠️  WARNING: Backpressure active, sampling events!"))))

;; ============================================================================
;; Main Event Loop
;; ============================================================================

(defn event-processing-loop
  "Main event processing loop with gap detection"
  []
  (let [state (create-consumer-state)]

    (println "Starting event processor with gap detection...\n")

    ;; Start backpressure monitor
    (future (monitor-buffer-pressure))

    ;; Process events
    (loop []
      (bpf/consume-ring-buffer
        event-buffer
        (fn [data]
          (let [event (parse-sequenced-event data)]
            (process-event-with-gap-detection state event)

            ;; Display progress every 10K events
            (when (zero? (mod (:total-events @state) 10000))
              (display-health-stats state))))
        {:poll-timeout-ms 100})

      (recur))))

(defn parse-sequenced-event [data]
  {:sequence (bytes->u64 data 0)
   :timestamp (bytes->u64 data 8)
   :cpu (bytes->u32 data 16)
   :type (bytes->u16 data 20)
   :pid (bytes->u32 data 24)})

;; ============================================================================
;; Main
;; ============================================================================

(defn -main [& args]
  (println "Lost Event Detection and Recovery System")
  (println "=========================================\n")

  ;; Load and attach program
  (let [prog (bpf/load-program sequenced-event-producer)]
    (bpf/attach-tracepoint prog "syscalls" "sys_enter_write")

    ;; Initialize
    (bpf/map-update! backpressure-state 0 0)

    ;; Start processing
    (event-processing-loop)))

;; Example output:
;;
;; === Event Processing Health ===
;; Events Received:  987,456
;; Events Lost:      2,341
;; Gaps Detected:    3
;; Kernel Drops:     2,341
;; Backpressure:     Inactive
;; Loss Rate:        0.237%
;;
;; GAP DETECTED: Expected seq 100000, got 100523. Lost 522 events.
;; Drop log shows 1 drop events in gap
;;
;; !!! GAP: sequences 100000-100523 missing (523 events) !!!
```

## Key Concepts

1. **Sequence Numbers** - Detect gaps in event stream
2. **Drop Logging** - Separate buffer for recording drops
3. **Backpressure** - Reduce event rate when buffer fills
4. **Gap Recovery** - Attempt to fill gaps from alternative sources
5. **Health Monitoring** - Track loss rates and alert

## Expected Behavior

### Normal Operation
```
Events: 1M, Lost: 0, Gaps: 0, Loss Rate: 0.000%
```

### Under Stress
```
Events: 1M, Lost: 1234, Gaps: 5, Loss Rate: 0.123%
⚠️  WARNING: Gaps detected in event stream!

GAP DETECTED: Expected seq 500000, got 500234. Lost 233 events.
```

### With Backpressure
```
Events: 1M, Lost: 45, Gaps: 1, Loss Rate: 0.004%
⚠️  WARNING: Backpressure active, sampling events!
```

## Challenges

1. **Per-CPU Sequence Numbers**: Independent sequence per CPU
2. **Gap Filling**: Query kernel maps to reconstruct lost events
3. **Adaptive Backpressure**: Adjust sampling rate dynamically
4. **Persistent Drop Log**: Circular buffer for drop events
5. **Recovery Strategies**: Multiple strategies for different scenarios

## Key Takeaways

- Event loss is inevitable under extreme load
- Detection is critical - sequence numbers are essential
- Log drops separately for debugging
- Backpressure prevents catastrophic loss
- Recovery depends on use case
- Monitor health metrics continuously

## References

- [TCP Sequence Numbers](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Sequence_numbers)
- [Gap Detection](https://www.kernel.org/doc/html/latest/trace/events.html)
- [Backpressure](https://mechanical-sympathy.blogspot.com/2012/05/apply-back-pressure-when-overloaded.html)
