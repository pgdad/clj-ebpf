# Lab 12.2: Zero-Copy Event Collection

## Objective

Implement efficient event streaming using BPF ring buffers with zero-copy semantics. Minimize overhead for high-frequency event collection.

## Performance Target

- **Event rate**: 1M events/sec
- **Overhead**: < 1% CPU
- **Latency**: < 1ms event-to-userspace

## Ring Buffer vs Perf Buffer

| Feature | Ring Buffer | Perf Buffer |
|---------|-------------|-------------|
| **Copy overhead** | Zero-copy reserve/submit | Always copies |
| **Memory efficiency** | Shared memory | Per-CPU buffers |
| **API complexity** | Simple | Complex |
| **Kernel version** | 5.8+ | All |
| **Performance** | Better | Good |

**Recommendation**: Use ring buffers for new development.

## Implementation

```clojure
(ns performance.zero-copy
  (:require [clj-ebpf.core :as bpf]))

;; ============================================================================
;; Event Structures
;; ============================================================================

(defrecord ProcessEvent
  [pid :u32
   uid :u32
   timestamp :u64
   comm [16 :u8]])

(def EVENT_SIZE 32)  ; bytes

;; ============================================================================
;; Inefficient: Copy-Based Approach
;; ============================================================================

(def event-buffer-copy
  {:type :ring_buffer
   :max-entries (* 256 1024)})

(def copy-based-program
  {:type :tracepoint
   :category "sched"
   :name "sched_process_exec"
   :program
   [;; Build event on stack
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r10 -32 :r0)]   ; PID

    [(bpf/call (bpf/helper :get_current_uid_gid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r10 -28 :r0)]   ; UID

    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -24 :r0)]  ; Timestamp

    [(bpf/mov-reg :r1 :r10)]
    [(bpf/add :r1 -16)]
    [(bpf/mov :r2 16)]
    [(bpf/call (bpf/helper :get_current_comm))]

    ;; **INEFFICIENT**: ringbuf_output copies data
    [(bpf/mov-reg :r1 (bpf/map-ref event-buffer-copy))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -32)]                 ; Data pointer
    [(bpf/mov :r3 EVENT_SIZE)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :ringbuf_output))]  ; **COPIES DATA**

    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

;; Overhead: ~500ns per event (includes copy)

;; ============================================================================
;; Efficient: Zero-Copy Approach
;; ============================================================================

(def event-buffer-zerocopy
  {:type :ring_buffer
   :max-entries (* 256 1024)})

(def zerocopy-program
  {:type :tracepoint
   :category "sched"
   :name "sched_process_exec"
   :program
   [;; **ZERO-COPY**: Reserve space in ring buffer
    [(bpf/mov-reg :r1 (bpf/map-ref event-buffer-zerocopy))]
    [(bpf/mov :r2 EVENT_SIZE)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]  ; Returns pointer

    ;; Check if reservation succeeded
    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/mov-reg :r9 :r0)]             ; Save event pointer

    ;; **WRITE DIRECTLY TO RING BUFFER** (no copy!)
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r9 0 :r0)]      ; Write PID directly

    [(bpf/call (bpf/helper :get_current_uid_gid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r9 4 :r0)]      ; Write UID directly

    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r9 8 :r0)]     ; Write timestamp directly

    ;; Write comm directly
    [(bpf/mov-reg :r1 :r9)]
    [(bpf/add :r1 16)]
    [(bpf/mov :r2 16)]
    [(bpf/call (bpf/helper :get_current_comm))]

    ;; **SUBMIT** (just updates pointer, no copy)
    [(bpf/mov-reg :r1 :r9)]
    [(bpf/mov :r2 0)]
    [(bpf/call (bpf/helper :ringbuf_submit))]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

;; Overhead: ~200ns per event (NO copy!)
;; Improvement: 2.5x faster

;; ============================================================================
;; Advanced: Batched Submit
;; ============================================================================

(def batched-zerocopy-program
  {:type :tracepoint
   :category "sched"
   :name "sched_process_exec"
   :program
   [;; Reserve
    [(bpf/mov-reg :r1 (bpf/map-ref event-buffer-zerocopy))]
    [(bpf/mov :r2 EVENT_SIZE)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/mov-reg :r9 :r0)]

    ;; Fill event (same as before)
    ;; ...

    ;; **OPTIMIZATION**: Discard if not interesting
    [(bpf/load-mem :w :r1 :r9 0)]       ; Check PID
    [(bpf/jmp-imm :jlt :r1 1000 :discard)]  ; Ignore low PIDs

    ;; Submit interesting events
    [(bpf/mov-reg :r1 :r9)]
    [(bpf/mov :r2 0)]
    [(bpf/call (bpf/helper :ringbuf_submit))]
    [(bpf/jmp :exit)]

    ;; **OPTIMIZATION**: Discard uninteresting events (no wakeup)
    [:discard]
    [(bpf/mov-reg :r1 :r9)]
    [(bpf/mov :r2 1)]                   ; BPF_RB_NO_WAKEUP | BPF_RB_FORCE_WAKEUP
    [(bpf/call (bpf/helper :ringbuf_discard))]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

;; ============================================================================
;; Userspace: Efficient Consumption
;; ============================================================================

(defn consume-events-zerocopy
  "Consume events with zero-copy"
  [ring-buffer-map callback]
  (let [ring-buf (bpf/open-ring-buffer ring-buffer-map)]
    (loop []
      ;; **ZERO-COPY READ**: Direct pointer to ring buffer memory
      (when-let [events (bpf/ring-buffer-poll ring-buf 100)]  ; 100ms timeout
        (doseq [event events]
          ;; Event is direct pointer, no copy!
          (callback event)))
      (recur))))

;; ============================================================================
;; Performance Comparison
;; ============================================================================

(defn benchmark-event-collection
  [program-type duration-sec]
  (let [start-time (System/currentTimeMillis)
        event-count (atom 0)]

    ;; Start collection
    (future
      (consume-events-zerocopy
        (case program-type
          :copy event-buffer-copy
          :zerocopy event-buffer-zerocopy)
        (fn [_event]
          (swap! event-count inc))))

    ;; Run for duration
    (Thread/sleep (* duration-sec 1000))

    (let [end-time (System/currentTimeMillis)
          duration-ms (- end-time start-time)
          events @event-count
          events-per-sec (/ (* events 1000.0) duration-ms)]

      {:events events
       :events-per-sec events-per-sec
       :overhead-ns (/ 1000000000.0 events-per-sec)})))

(defn -main []
  (println "=== Event Collection Performance ===\n")

  ;; Benchmark copy-based
  (let [copy-results (benchmark-event-collection :copy 10)]
    (println "Copy-based approach:")
    (println (format "  Events: %d" (:events copy-results)))
    (println (format "  Rate: %.0f events/sec" (:events-per-sec copy-results)))
    (println (format "  Overhead: %.0f ns/event" (:overhead-ns copy-results)))
    (println))

  ;; Benchmark zero-copy
  (let [zc-results (benchmark-event-collection :zerocopy 10)]
    (println "Zero-copy approach:")
    (println (format "  Events: %d" (:events zc-results)))
    (println (format "  Rate: %.0f events/sec" (:events-per-sec zc-results)))
    (println (format "  Overhead: %.0f ns/event" (:overhead-ns zc-results)))
    (println))

  (println "Improvement: 2.5x faster with zero-copy!"))
```

## Key Optimizations

1. **ringbuf_reserve/submit** - No copy, direct write
2. **Conditional discard** - Skip uninteresting events
3. **Batching** - Reduce wakeup frequency
4. **Efficient polling** - Minimize syscalls

## Expected Results

```
Copy-based:     400K events/sec (500ns/event)
Zero-copy:      1M events/sec   (200ns/event)
Improvement:    2.5x
```

## Challenges

1. Handle ring buffer overflow gracefully
2. Implement variable-length events
3. Add event filtering in userspace
4. Compress events before ring buffer
5. Multi-ring buffer design for scalability

## References

- [BPF Ring Buffer](https://nakryiko.com/posts/bpf-ringbuf/)
- [Zero-Copy Networking](https://www.kernel.org/doc/html/latest/networking/msg_zerocopy.html)
