# Chapter 13: Event Processing and Ring Buffers

## Overview

Event processing is the bridge between your BPF programs running in the kernel and userspace applications. Efficient event handling is critical for production observability systems that process millions of events per second.

This chapter covers:
- Ring buffer vs perf buffer architecture
- Event ordering and timestamp handling
- Multi-buffer strategies
- Overflow handling and backpressure
- Event aggregation and filtering
- Custom serialization formats

## Event Transport Mechanisms

### Ring Buffer (BPF_MAP_TYPE_RINGBUF)

**Introduced**: Kernel 5.8

**Architecture**:
```
┌─────────────────────────────────────┐
│     Shared Ring Buffer              │
│  ┌─────────────────────────────┐   │
│  │  [Event][Event][Event]...   │   │
│  │     ↑              ↑         │   │
│  │   Producer      Consumer     │   │
│  └─────────────────────────────┘   │
│     All CPUs → Single Buffer        │
└─────────────────────────────────────┘
```

**Characteristics**:
- **Zero-copy**: reserve/submit API avoids memcpy
- **Shared memory**: Single buffer for all CPUs
- **Memory efficient**: No per-CPU buffers
- **Event ordering**: Total ordering across CPUs
- **Epoll support**: Efficient userspace polling
- **Variable size**: Events can be different sizes

**When to use**:
- New development (kernel 5.8+)
- Need event ordering across CPUs
- Variable-size events
- Memory-constrained systems

### Perf Buffer (BPF_MAP_TYPE_PERF_EVENT_ARRAY)

**Architecture**:
```
┌─────────────────────────────────────┐
│  Per-CPU Perf Buffers               │
│  CPU 0: [Event][Event][Event]       │
│  CPU 1: [Event][Event][Event]       │
│  CPU 2: [Event][Event][Event]       │
│  CPU 3: [Event][Event][Event]       │
│    No cross-CPU ordering            │
└─────────────────────────────────────┘
```

**Characteristics**:
- **Per-CPU**: Separate buffer per CPU
- **Copy-based**: Always copies data
- **Legacy support**: Works on older kernels
- **No ordering**: Events interleaved in userspace
- **Fixed size**: Typically page-aligned

**When to use**:
- Kernel version < 5.8
- Per-CPU processing preferred
- Legacy codebase compatibility

### Comparison

| Feature | Ring Buffer | Perf Buffer |
|---------|-------------|-------------|
| **Kernel version** | 5.8+ | All |
| **Memory overhead** | Low (shared) | High (per-CPU) |
| **Copy overhead** | Zero-copy | Always copies |
| **Event ordering** | Total ordering | No ordering |
| **API simplicity** | Simple | Complex |
| **Variable events** | Yes | Limited |
| **Performance** | Better | Good |

**Recommendation**: Use ring buffers for all new development on kernel 5.8+.

## Event Structure Design

### Fixed-Size Events

**Pros**:
- Predictable memory usage
- Fast allocation
- Simple parsing

**Cons**:
- Wasted space for small events
- Limited flexibility

```clojure
(defrecord NetworkEvent
  [timestamp :u64      ; 8 bytes
   src-ip :u32         ; 4 bytes
   dst-ip :u32         ; 4 bytes
   src-port :u16       ; 2 bytes
   dst-port :u16       ; 2 bytes
   protocol :u8        ; 1 byte
   flags :u8           ; 1 byte
   padding [6 :u8]])   ; 6 bytes padding → Total: 32 bytes
```

### Variable-Size Events

**Pros**:
- Efficient memory use
- Flexible data capture
- Can include strings

**Cons**:
- Complex parsing
- Variable allocation time

```clojure
(defrecord ProcessEvent
  [header
   {:size :u32        ; Total size
    :type :u16        ; Event type
    :flags :u16}      ; Flags
   pid :u32
   uid :u32
   timestamp :u64
   comm-len :u16      ; Length of comm string
   comm [:u8]])       ; Variable-length command name
```

### Type-Tagged Events

**Use case**: Multiple event types in same buffer

```clojure
(def EVENT_TYPE_NETWORK 1)
(def EVENT_TYPE_PROCESS 2)
(def EVENT_TYPE_FILE 3)

(defrecord EventHeader
  [type :u16
   size :u16
   timestamp :u64])

;; Userspace dispatcher
(defn dispatch-event [data]
  (let [header (parse-header data)
        type (:type header)]
    (case type
      1 (handle-network-event data)
      2 (handle-process-event data)
      3 (handle-file-event data))))
```

## Event Ordering and Timestamps

### Why Ordering Matters

Without ordering, causality is lost:
```
CPU 0: Process fork (t=100)
CPU 1: Process exec (t=101)
CPU 2: File open (t=102)

Userspace sees: exec, fork, open ❌ (wrong order!)
```

### Solutions

#### 1. Ring Buffer (Automatic Ordering)

Ring buffers provide total ordering automatically:
```clojure
(def event-buffer
  {:type :ring_buffer
   :max-entries (* 256 1024)})

;; Events from all CPUs ordered by submission time
```

#### 2. Timestamp-Based Reordering

For perf buffers, reorder in userspace:
```clojure
(defn reorder-events
  "Reorder events by timestamp"
  [events window-ms]
  (let [now (System/currentTimeMillis)
        cutoff (- now window-ms)]
    (->> events
         (filter #(< (:timestamp %) cutoff))
         (sort-by :timestamp))))
```

#### 3. Per-CPU Processing

Process events per-CPU without reordering:
```clojure
(defn process-per-cpu
  "Process events maintaining per-CPU context"
  [cpu-id events]
  ;; Events from same CPU are ordered
  ;; No need to merge across CPUs
  (doseq [event events]
    (update-cpu-local-state cpu-id event)))
```

## Buffer Overflow Handling

### The Problem

```
Ring buffer full → New events dropped → Data loss
```

**Causes**:
- Userspace consumer too slow
- Event burst exceeds buffer size
- Blocking syscalls in consumer

### Detection

**In BPF**:
```clojure
;; Try to reserve space
[(bpf/call (bpf/helper :ringbuf_reserve))]
[(bpf/jmp-imm :jeq :r0 0 :buffer-full)]  ; NULL = full

[:buffer-full]
;; Increment drop counter
[(bpf/load-mem :dw :r1 :r9 0)]
[(bpf/add :r1 1)]
[(bpf/store-mem :dw :r9 0 :r1)]
```

**In Userspace**:
```clojure
(defn monitor-drops []
  (let [stats (get-ring-buffer-stats)]
    (when (pos? (:drops stats))
      (log/warn "Ring buffer dropped" (:drops stats) "events"))))
```

### Mitigation Strategies

#### 1. Increase Buffer Size

```clojure
(def event-buffer
  {:type :ring_buffer
   :max-entries (* 1024 1024)})  ; 1MB → 4MB
```

**Tradeoff**: More memory, but longer processing window

#### 2. Sampling

```clojure
;; Sample 10% of events
[(bpf/call (bpf/helper :get_prandom_u32))]
[(bpf/mod :r0 100)]
[(bpf/jmp-imm :jge :r0 10 :skip)]
```

#### 3. In-Kernel Aggregation

Don't send individual events, aggregate first:
```clojure
;; Instead of: send every packet
;; Do: aggregate per connection, send summary

(def connection-stats
  {:type :hash
   :key-type :struct    ; 5-tuple
   :value-type :struct  ; {packets:u64, bytes:u64}
   :max-entries 100000})

;; Userspace polls aggregated stats (much less data)
```

#### 4. Backpressure

Signal BPF to reduce event rate:
```clojure
(def backpressure-flag
  {:type :array
   :key-type :u32
   :value-type :u32
   :max-entries 1})

;; Userspace sets flag when buffer > 80% full
(when (> buffer-usage 0.8)
  (bpf/map-update! backpressure-flag 0 1))

;; BPF program checks flag
[(bpf/call (bpf/helper :map_lookup_elem))]
[(bpf/load-mem :w :r1 :r0 0)]
[(bpf/jmp-imm :jne :r1 0 :skip)]  ; Skip if backpressure
```

## Multi-Buffer Architectures

### Pattern 1: Per-Event-Type Buffers

**Use case**: Different event types, different priorities

```clojure
(def critical-events
  {:type :ring_buffer
   :max-entries (* 128 1024)})   ; Small, high priority

(def normal-events
  {:type :ring_buffer
   :max-entries (* 512 1024)})   ; Larger

(def debug-events
  {:type :ring_buffer
   :max-entries (* 64 1024)})    ; Smallest, can drop

;; BPF program routes by severity
[(bpf/jmp-imm :jeq :r6 SEVERITY_CRITICAL :use-critical-buffer)]
[(bpf/jmp-imm :jeq :r6 SEVERITY_NORMAL :use-normal-buffer)]
```

**Benefits**:
- Critical events never dropped due to debug flood
- Independent processing rates
- Priority-based consumption

### Pattern 2: Per-Subsystem Buffers

**Use case**: Network, process, file events separate

```clojure
(def network-events {:type :ring_buffer :max-entries (* 256 1024)})
(def process-events {:type :ring_buffer :max-entries (* 128 1024)})
(def file-events {:type :ring_buffer :max-entries (* 128 1024)})

;; Separate consumers for each
(future (consume-network-events network-events))
(future (consume-process-events process-events))
(future (consume-file-events file-events))
```

**Benefits**:
- Parallel processing
- Independent failure domains
- Easier debugging

### Pattern 3: Hot/Cold Buffer Split

**Use case**: Frequent events vs rare events

```clojure
(def hot-events   ; TCP packets, system calls
  {:type :ring_buffer
   :max-entries (* 1024 1024)})  ; Large

(def cold-events  ; Process exits, module loads
  {:type :ring_buffer
   :max-entries (* 64 1024)})    ; Small

;; Hot events: streaming processor
;; Cold events: batch processor
```

## Event Aggregation Patterns

### In-Kernel Aggregation

**Goal**: Reduce event volume by aggregating before sending to userspace.

#### Pattern 1: Time-Window Aggregation

```clojure
(def stats-window
  {:type :hash
   :key-type :u64      ; Time bucket (timestamp / window_size)
   :value-type :struct ; Aggregated stats
   :max-entries 1000})

;; BPF program updates stats in current time bucket
(let [bucket (/ (bpf/helper :ktime_get_ns) WINDOW_SIZE_NS)]
  ;; Lookup bucket
  ;; Update stats
  )

;; Userspace reads completed buckets
```

**Reduction**: 1000 events → 1 summary per time window

#### Pattern 2: Count-Min Sketch

For approximate counting with bounded memory:
```clojure
(def count-min-sketch
  {:type :array
   :key-type :u32
   :value-type :u64
   :max-entries 1024})  ; Fixed size

;; Hash event to multiple indices, increment all
;; Estimate = min of all counters
```

#### Pattern 3: Top-K Tracking

Track only the most frequent items:
```clojure
(def top-k-items
  {:type :hash
   :key-type :struct   ; Item
   :value-type :u64    ; Count
   :max-entries 100})  ; Only track top 100

;; Evict least frequent on overflow
```

## Custom Serialization

### Compact Encoding

**Problem**: Standard structs waste space due to alignment.

**Solution**: Pack bits manually.

```clojure
;; Standard struct: 16 bytes (alignment padding)
(defrecord ConnInfo
  [src-ip :u32    ; 4 bytes
   dst-ip :u32    ; 4 bytes
   src-port :u16  ; 2 bytes
   dst-port :u16  ; 2 bytes
   protocol :u8   ; 1 byte
   flags :u8])    ; 1 byte + 2 bytes padding = 16 total

;; Packed: 14 bytes (no padding)
(defn pack-conn-info [src-ip dst-ip src-port dst-port protocol flags]
  ;; Manually pack into byte array
  (let [buf (byte-array 14)]
    (pack-u32 buf 0 src-ip)
    (pack-u32 buf 4 dst-ip)
    (pack-u16 buf 8 src-port)
    (pack-u16 buf 10 dst-port)
    (pack-u8 buf 12 protocol)
    (pack-u8 buf 13 flags)
    buf))

;; Savings: 12.5% space reduction
```

### Delta Encoding

For time-series data:
```clojure
;; Instead of absolute timestamps
[1234567890, 1234567891, 1234567892, ...]  ; 8 bytes each

;; Use delta encoding
[1234567890, +1, +1, +1, ...]  ; 8 bytes + 1 byte deltas

;; 87.5% reduction for monotonic timestamps!
```

### Bit Fields

Pack multiple small values:
```clojure
;; Instead of separate fields
{:protocol :u8      ; 1 byte
 :direction :u8     ; 1 byte (only need 1 bit!)
 :encrypted :u8     ; 1 byte (only need 1 bit!)
 :priority :u8}     ; 1 byte (only need 2 bits)

;; Pack into single byte
;; Bits: [protocol:4][priority:2][encrypted:1][direction:1]
(defn pack-flags [protocol direction encrypted priority]
  (bit-or
    (bit-shift-left protocol 4)
    (bit-shift-left priority 2)
    (bit-shift-left encrypted 1)
    direction))

;; 75% reduction (4 bytes → 1 byte)
```

## Buffer Sizing

### Calculating Buffer Size

```
Buffer Size = Event Rate × Event Size × Time Window

Example:
- Event rate: 100,000 events/sec
- Event size: 64 bytes
- Time window: 100ms (processing latency)

Buffer size = 100,000 × 64 × 0.1 = 640 KB
Recommended: 2× safety margin → 1.28 MB
Round up to power of 2: 2 MB
```

### Dynamic Sizing

```clojure
(defn calculate-optimal-buffer-size []
  (let [event-rate (measure-event-rate 5000)  ; 5 sec sample
        event-size (measure-avg-event-size)
        latency-p99 (measure-processing-latency-p99)]
    (* event-rate event-size latency-p99 2)))  ; 2× safety margin
```

## Production Best Practices

### 1. Always Handle Overflow

```clojure
;; Don't assume infinite buffer
[(bpf/call (bpf/helper :ringbuf_reserve))]
[(bpf/jmp-imm :jeq :r0 0 :handle-overflow)]

[:handle-overflow]
;; Track drops
;; Maybe sample
;; Don't fail silently!
```

### 2. Monitor Buffer Health

```clojure
(defn monitor-buffer-health []
  (let [stats (get-ring-buffer-stats)
        usage (/ (:used stats) (:size stats))
        drop-rate (/ (:drops stats) (:events stats))]
    (when (> usage 0.8)
      (alert "Ring buffer 80% full"))
    (when (> drop-rate 0.01)
      (alert "Dropping >1% of events"))))
```

### 3. Graceful Degradation

```clojure
(defn handle-backpressure []
  (cond
    (> buffer-usage 0.6) (set-sample-rate 0.5)   ; Sample 50%
    (> buffer-usage 0.8) (set-sample-rate 0.1)   ; Sample 10%
    (> buffer-usage 0.95) (set-sample-rate 0.01) ; Sample 1%
    :else (set-sample-rate 1.0)))                ; No sampling
```

### 4. Event Versioning

```clojure
(defrecord EventHeader
  [version :u16      ; Event format version
   type :u16         ; Event type
   size :u32])       ; Total size

;; Userspace can handle multiple versions
(defn parse-event [data]
  (let [version (read-u16 data 0)]
    (case version
      1 (parse-v1-event data)
      2 (parse-v2-event data)
      (throw (ex-info "Unknown version" {:version version})))))
```

### 5. Efficient Polling

```clojure
(defn poll-ring-buffer
  "Efficient polling with adaptive timeout"
  [ring-buf]
  (loop [timeout-ms 1]
    (if-let [events (bpf/ring-buffer-poll ring-buf timeout-ms)]
      (do
        (process-events events)
        (recur 1))  ; Reset timeout on activity
      (recur (min (* timeout-ms 2) 100)))))  ; Exponential backoff, max 100ms
```

## Labs

### Lab 13.1: Multi-Ring Buffer System

Build a multi-buffer event routing system with per-priority buffers and overflow handling.

**Skills**: Ring buffer management, event routing, overflow detection

### Lab 13.2: Event Aggregation Pipeline

Implement in-kernel aggregation to reduce event volume by 100×.

**Skills**: Time-window aggregation, hash-based counting, efficient userspace polling

### Lab 13.3: Lost Event Detection and Recovery

Handle buffer overflow gracefully with detection, logging, and recovery.

**Skills**: Drop detection, gap filling, backpressure, monitoring

## Key Takeaways

1. **Ring buffers are the future** - Use them on kernel 5.8+
2. **Overflow will happen** - Always handle it gracefully
3. **Aggregate in kernel** - Reduce event volume before userspace
4. **Monitor buffer health** - Proactive alerts prevent data loss
5. **Multi-buffer architectures** - Separate critical from debug events
6. **Timestamp everything** - Essential for ordering and debugging
7. **Version your events** - Plan for format evolution

## References

- [BPF Ring Buffer](https://nakryiko.com/posts/bpf-ringbuf/)
- [Perf Events](https://perf.wiki.kernel.org/index.php/Main_Page)
- [Event Ordering](https://www.kernel.org/doc/html/latest/trace/events.html)
- [libbpf Ring Buffer API](https://github.com/libbpf/libbpf)

---

**Next**: [Chapter 14: Testing and Debugging](../chapter-14/README.md) - Test strategies and debugging tools
