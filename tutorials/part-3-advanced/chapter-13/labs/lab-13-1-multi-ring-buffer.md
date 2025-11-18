# Lab 13.1: Multi-Ring Buffer System

## Objective

Build a production-grade event routing system that uses multiple ring buffers to separate events by priority. Demonstrate overflow handling, per-buffer monitoring, and graceful degradation.

## Learning Goals

- Use multiple ring buffers in a single program
- Route events by priority/severity
- Detect and handle buffer overflow
- Monitor buffer health metrics
- Implement independent processing pipelines

## Architecture

```
┌─────────────────────────────────────────────┐
│         BPF Event Classifier                │
│                                             │
│  Event → Analyze → Route by Priority        │
│              ↓                              │
│    ┌─────────┼─────────┐                   │
│    ↓         ↓         ↓                    │
│ Critical  Normal   Debug                    │
│  Buffer   Buffer   Buffer                   │
│  128KB    512KB    64KB                     │
│    ↓         ↓         ↓                    │
└────┼─────────┼─────────┼────────────────────┘
     │         │         │
     ↓         ↓         ↓
┌─────────────────────────────────────────────┐
│         Userspace Processors                │
│                                             │
│  Critical: Process immediately              │
│  Normal:   Batch every 100ms                │
│  Debug:    Best effort, can drop            │
└─────────────────────────────────────────────┘
```

## Problem Statement

Single buffer systems have limitations:
- **Debug floods**: Debug events fill buffer, critical events dropped
- **Priority inversion**: Low-priority events delay high-priority
- **No isolation**: One subsystem's burst affects others

**Solution**: Separate buffers with independent overflow policies.

## Implementation

```clojure
(ns event-processing.multi-ring-buffer
  (:require [clj-ebpf.core :as bpf]))

;; ============================================================================
;; Event Severity Levels
;; ============================================================================

(def SEVERITY_CRITICAL 0)  ; Security violations, crashes
(def SEVERITY_ERROR 1)     ; Errors, failures
(def SEVERITY_WARNING 2)   ; Warnings, anomalies
(def SEVERITY_INFO 3)      ; Normal operations
(def SEVERITY_DEBUG 4)     ; Debug information

;; ============================================================================
;; Event Types
;; ============================================================================

(def EVENT_PROCESS_EXEC 1)
(def EVENT_FILE_OPEN 2)
(def EVENT_NETWORK_CONNECT 3)
(def EVENT_SECURITY_VIOLATION 4)
(def EVENT_RESOURCE_LIMIT 5)

;; ============================================================================
;; Ring Buffers
;; ============================================================================

(def critical-events
  "Critical events - never drop, process immediately"
  {:type :ring_buffer
   :max-entries (* 128 1024)})   ; 128 KB

(def normal-events
  "Normal priority events - standard processing"
  {:type :ring_buffer
   :max-entries (* 512 1024)})   ; 512 KB

(def debug-events
  "Debug events - best effort, can drop"
  {:type :ring_buffer
   :max-entries (* 64 1024)})    ; 64 KB

;; ============================================================================
;; Statistics and Monitoring
;; ============================================================================

(def buffer-stats
  "Per-buffer statistics"
  {:type :array
   :key-type :u32
   :value-type :struct  ; {submitted:u64, dropped:u64, failures:u64}
   :max-entries 3})     ; One entry per buffer

(def STATS_CRITICAL 0)
(def STATS_NORMAL 1)
(def STATS_DEBUG 2)

;; ============================================================================
;; Event Structure
;; ============================================================================

(defrecord Event
  [header
   {:timestamp :u64    ; Event timestamp
    :type :u16         ; Event type
    :severity :u8      ; Severity level
    :cpu :u8}          ; CPU that generated event
   pid :u32            ; Process ID
   uid :u32            ; User ID
   data-len :u32       ; Length of additional data
   data [64 :u8]])     ; Event-specific data

(def EVENT_SIZE 96)    ; Total event size

;; ============================================================================
;; Event Classification
;; ============================================================================

(defn classify-event-severity
  "Determine event severity based on type and context"
  []
  [;; Check event type
   [(bpf/load-mem :h :r6 :r9 0)]  ; r6 = event_type (from temp storage)

   ;; Security violations → CRITICAL
   [(bpf/jmp-imm :jeq :r6 EVENT_SECURITY_VIOLATION :mark-critical)]

   ;; Process exec with UID=0 → CRITICAL
   [(bpf/jmp-imm :jne :r6 EVENT_PROCESS_EXEC :check-resource-limit)]
   [(bpf/call (bpf/helper :get_current_uid_gid))]
   [(bpf/rsh :r0 32)]
   [(bpf/jmp-imm :jeq :r0 0 :mark-critical)]  ; Root exec is critical
   [(bpf/jmp :mark-normal)]

   ;; Resource limit violations → ERROR
   [:check-resource-limit]
   [(bpf/jmp-imm :jeq :r6 EVENT_RESOURCE_LIMIT :mark-error)]

   ;; File open → DEBUG (unless special file)
   [(bpf/jmp-imm :jeq :r6 EVENT_FILE_OPEN :mark-debug)]

   ;; Network connect → INFO
   [(bpf/jmp-imm :jeq :r6 EVENT_NETWORK_CONNECT :mark-normal)]

   ;; Default → DEBUG
   [(bpf/jmp :mark-debug)]

   [:mark-critical]
   [(bpf/mov :r7 SEVERITY_CRITICAL)]
   [(bpf/jmp :severity-determined)]

   [:mark-error]
   [(bpf/mov :r7 SEVERITY_ERROR)]
   [(bpf/jmp :severity-determined)]

   [:mark-normal]
   [(bpf/mov :r7 SEVERITY_INFO)]
   [(bpf/jmp :severity-determined)]

   [:mark-debug]
   [(bpf/mov :r7 SEVERITY_DEBUG)]

   [:severity-determined]
   ;; r7 now contains severity level
   ])

;; ============================================================================
;; Main Event Router
;; ============================================================================

(def event-router
  "Routes events to appropriate ring buffer based on severity"
  {:type :tracepoint
   :category "syscalls"
   :name "sys_enter_openat"
   :program
   [;; Store event type
    [(bpf/mov :r1 EVENT_FILE_OPEN)]
    [(bpf/store-mem :h :r10 -4 :r1)]
    [(bpf/mov-reg :r9 :r10)]
    [(bpf/add :r9 -4)]

    ;; Classify event
    (classify-event-severity)
    ;; r7 = severity

    ;; Route to appropriate buffer
    [(bpf/jmp-imm :jeq :r7 SEVERITY_CRITICAL :use-critical)]
    [(bpf/jmp-imm :jeq :r7 SEVERITY_ERROR :use-critical)]  ; Errors also critical
    [(bpf/jmp-imm :jeq :r7 SEVERITY_DEBUG :use-debug)]
    ;; Default: normal buffer

    ;; ========================================================================
    ;; Normal Buffer Path
    ;; ========================================================================

    [:use-normal]
    [(bpf/mov :r9 STATS_NORMAL)]    ; Stats index
    [(bpf/store-mem :w :r10 -8 :r9)]

    ;; Reserve space in normal buffer
    [(bpf/mov-reg :r1 (bpf/map-ref normal-events))]
    [(bpf/mov :r2 EVENT_SIZE)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    [(bpf/jmp-imm :jeq :r0 0 :normal-overflow)]
    [(bpf/mov-reg :r8 :r0)]         ; Save event pointer
    [(bpf/mov :r7 SEVERITY_INFO)]   ; Restore severity
    [(bpf/jmp :fill-event)]

    [:normal-overflow]
    [(bpf/mov :r9 STATS_NORMAL)]
    [(bpf/jmp :record-drop)]

    ;; ========================================================================
    ;; Critical Buffer Path
    ;; ========================================================================

    [:use-critical]
    [(bpf/mov :r9 STATS_CRITICAL)]
    [(bpf/store-mem :w :r10 -8 :r9)]

    ;; Reserve space in critical buffer
    [(bpf/mov-reg :r1 (bpf/map-ref critical-events))]
    [(bpf/mov :r2 EVENT_SIZE)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    [(bpf/jmp-imm :jeq :r0 0 :critical-overflow)]
    [(bpf/mov-reg :r8 :r0)]
    ;; r7 already has severity
    [(bpf/jmp :fill-event)]

    [:critical-overflow]
    ;; CRITICAL: This should never happen!
    ;; Log aggressively
    [(bpf/mov :r9 STATS_CRITICAL)]
    [(bpf/jmp :record-drop)]

    ;; ========================================================================
    ;; Debug Buffer Path
    ;; ========================================================================

    [:use-debug]
    [(bpf/mov :r9 STATS_DEBUG)]
    [(bpf/store-mem :w :r10 -8 :r9)]

    ;; For debug events, use BPF_RB_NO_WAKEUP to reduce overhead
    [(bpf/mov-reg :r1 (bpf/map-ref debug-events))]
    [(bpf/mov :r2 EVENT_SIZE)]
    [(bpf/mov :r3 (bit-shift-left 1 0))]  ; BPF_RB_NO_WAKEUP
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    [(bpf/jmp-imm :jeq :r0 0 :debug-overflow)]
    [(bpf/mov-reg :r8 :r0)]
    [(bpf/mov :r7 SEVERITY_DEBUG)]
    [(bpf/jmp :fill-event)]

    [:debug-overflow]
    ;; Debug overflow is acceptable, just count it
    [(bpf/mov :r9 STATS_DEBUG)]
    [(bpf/jmp :record-drop)]

    ;; ========================================================================
    ;; Fill Event Data
    ;; ========================================================================

    [:fill-event]
    ;; r8 = event pointer
    ;; r7 = severity

    ;; Timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r8 0 :r0)]

    ;; Type (already determined)
    [(bpf/load-mem :h :r1 :r10 -4)]
    [(bpf/store-mem :h :r8 8 :r1)]

    ;; Severity
    [(bpf/store-mem :b :r8 10 :r7)]

    ;; CPU
    [(bpf/call (bpf/helper :get_smp_processor_id))]
    [(bpf/store-mem :b :r8 11 :r0)]

    ;; PID
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r8 12 :r0)]

    ;; UID
    [(bpf/call (bpf/helper :get_current_uid_gid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r8 16 :r0)]

    ;; Data length (simplified, no extra data for now)
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r8 20 :r1)]

    ;; Submit event
    [(bpf/mov-reg :r1 :r8)]
    [(bpf/mov :r2 0)]
    [(bpf/call (bpf/helper :ringbuf_submit))]

    ;; Update submitted counter
    [(bpf/load-mem :w :r9 :r10 -8)]  ; Stats index
    [(bpf/jmp :update-stats-submit)]

    ;; ========================================================================
    ;; Record Drop
    ;; ========================================================================

    [:record-drop]
    ;; r9 = stats index
    [(bpf/store-mem :w :r10 -12 :r9)]
    [(bpf/mov-reg :r1 (bpf/map-ref buffer-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -12)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]

    ;; Increment dropped counter (offset 8)
    [(bpf/load-mem :dw :r1 :r0 8)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 8 :r1)]
    [(bpf/jmp :exit)]

    ;; ========================================================================
    ;; Update Stats - Submitted
    ;; ========================================================================

    [:update-stats-submit]
    [(bpf/store-mem :w :r10 -12 :r9)]
    [(bpf/mov-reg :r1 (bpf/map-ref buffer-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -12)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]

    ;; Increment submitted counter (offset 0)
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))

;; ============================================================================
;; Userspace Processing
;; ============================================================================

(defn process-critical-events
  "Process critical events immediately"
  []
  (bpf/consume-ring-buffer
    critical-events
    (fn [event]
      (let [parsed (parse-event event)]
        (log/error "CRITICAL EVENT:" parsed)
        ;; Immediate action
        (when (= (:type parsed) EVENT_SECURITY_VIOLATION)
          (trigger-security-alert parsed))
        (when (and (= (:type parsed) EVENT_PROCESS_EXEC)
                   (= (:uid parsed) 0))
          (audit-root-exec parsed))))
    {:poll-timeout-ms 10}))  ; Poll frequently

(defn process-normal-events
  "Batch process normal events"
  []
  (loop []
    (Thread/sleep 100)  ; Batch every 100ms
    (when-let [events (bpf/ring-buffer-consume normal-events 1000)]
      (doseq [event events]
        (let [parsed (parse-event event)]
          (log/info "Event:" parsed)
          (update-metrics parsed))))
    (recur)))

(defn process-debug-events
  "Best-effort debug event processing"
  []
  (loop []
    (Thread/sleep 1000)  ; Process every second
    (try
      (when-let [events (bpf/ring-buffer-consume debug-events 10000)]
        (doseq [event events]
          (let [parsed (parse-event event)]
            (log/debug "Debug:" parsed))))
      (catch Exception e
        ;; Debug processing failures are non-fatal
        (log/warn "Debug processing failed:" (.getMessage e))))
    (recur)))

;; ============================================================================
;; Monitoring
;; ============================================================================

(defn get-buffer-stats
  "Get statistics for a specific buffer"
  [stats-index]
  (when-let [stats (bpf/map-lookup buffer-stats stats-index)]
    {:submitted (bytes->u64 stats 0)
     :dropped (bytes->u64 stats 8)
     :failures (bytes->u64 stats 16)}))

(defn display-buffer-health
  "Display health metrics for all buffers"
  []
  (println "\n=== Ring Buffer Health ===")
  (println "BUFFER      SUBMITTED    DROPPED    DROP_RATE")
  (println "===============================================")

  (let [critical-stats (get-buffer-stats STATS_CRITICAL)
        normal-stats (get-buffer-stats STATS_NORMAL)
        debug-stats (get-buffer-stats STATS_DEBUG)]

    (doseq [[name stats] [["Critical" critical-stats]
                          ["Normal" normal-stats]
                          ["Debug" debug-stats]]]
      (let [submitted (:submitted stats 0)
            dropped (:dropped stats 0)
            drop-rate (if (zero? submitted)
                       0.0
                       (* 100.0 (/ dropped (+ submitted dropped))))]
        (printf "%-11s %-12d %-10d %.2f%%\n"
                name submitted dropped drop-rate)))

    ;; Alerts
    (when (pos? (:dropped critical-stats 0))
      (println "\n⚠️  WARNING: Critical events dropped!"))))

(defn monitor-buffer-health
  "Continuous monitoring with alerts"
  []
  (loop []
    (Thread/sleep 5000)  ; Check every 5 seconds

    (let [critical-stats (get-buffer-stats STATS_CRITICAL)
          normal-stats (get-buffer-stats STATS_NORMAL)]

      ;; Alert on critical drops
      (when (pos? (:dropped critical-stats 0))
        (log/error "ALERT: Critical event buffer dropped events!"
                   {:dropped (:dropped critical-stats)}))

      ;; Warn on high normal drop rate
      (let [total (+ (:submitted normal-stats) (:dropped normal-stats))
            drop-rate (if (zero? total) 0 (/ (:dropped normal-stats) total))]
        (when (> drop-rate 0.1)
          (log/warn "Normal buffer dropping >10% of events"
                    {:drop-rate (format "%.1f%%" (* 100 drop-rate))}))))

    (recur)))

;; ============================================================================
;; Main
;; ============================================================================

(defn -main [& args]
  (println "Multi-Ring Buffer Event System")
  (println "===============================\n")

  ;; Load and attach program
  (let [prog (bpf/load-program event-router)]
    (bpf/attach-tracepoint prog "syscalls" "sys_enter_openat")

    ;; Initialize stats
    (doseq [idx [STATS_CRITICAL STATS_NORMAL STATS_DEBUG]]
      (bpf/map-update! buffer-stats idx
                      {:submitted 0 :dropped 0 :failures 0}))

    ;; Start processing threads
    (println "Starting event processors...")
    (future (process-critical-events))  ; High priority thread
    (future (process-normal-events))    ; Normal priority
    (future (process-debug-events))     ; Low priority

    ;; Start monitoring
    (future (monitor-buffer-health))

    ;; Display stats periodically
    (println "Monitoring (Ctrl-C to stop)\n")
    (loop []
      (Thread/sleep 10000)
      (display-buffer-health)
      (recur))))

;; Expected output:
;; === Ring Buffer Health ===
;; BUFFER      SUBMITTED    DROPPED    DROP_RATE
;; ===============================================
;; Critical    1250         0          0.00%
;; Normal      98234        156        0.16%
;; Debug       1234567      45678      3.57%
```

## Testing

### Generate Different Event Types

```bash
# Generate critical events (root exec)
sudo bash -c 'for i in {1..10}; do ls > /dev/null; done'

# Generate normal events
for i in {1..1000}; do cat /etc/hosts > /dev/null; done

# Generate debug flood
for i in {1..100000}; do ls > /dev/null; done
```

### Expected Behavior

1. **Critical buffer**: Never drops, processes immediately
2. **Normal buffer**: <1% drop rate under normal load
3. **Debug buffer**: Can drop 5-10% under flood, acceptable

## Challenges

1. **Dynamic Buffer Sizing**: Adjust buffer sizes based on load
2. **Priority Promotion**: Promote events from debug→normal if critical
3. **Flow Control**: Slow down event generation when buffers full
4. **Per-PID Buffers**: Separate buffers per process for isolation
5. **Compression**: Compress debug events before buffering

## Key Takeaways

- Multiple buffers prevent priority inversion
- Critical events should NEVER be dropped
- Debug events can be dropped with best-effort processing
- Monitor drop rates to detect problems early
- Independent processing pipelines scale better

## References

- [Ring Buffer API](https://nakryiko.com/posts/bpf-ringbuf/)
- [Priority Queues](https://en.wikipedia.org/wiki/Priority_queue)
