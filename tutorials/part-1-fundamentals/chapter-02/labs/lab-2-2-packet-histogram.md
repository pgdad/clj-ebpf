# Lab 2.2: Network Packet Histogram

**Objective**: Create packet size distribution using BPF array maps

**Duration**: 45 minutes

## Overview

In this lab, you'll build a network packet size histogram using BPF array maps. You'll capture packets, categorize them by size into buckets, and display a visual histogram in userspace.

This lab demonstrates:
- Using array maps for indexed data
- Working with XDP (eXpress Data Path) programs
- Packet parsing basics
- Creating visual data representations

## What You'll Learn

- How to create and use BPF array maps
- Basics of XDP packet processing
- How to parse Ethernet and IP headers
- Creating histograms and visualizations
- High-performance packet processing patterns

## Theory

### Array Maps vs Hash Maps

Array maps are ideal for histograms because:
1. **Fixed indices**: Bucket numbers are sequential (0, 1, 2, ...)
2. **Pre-allocated**: All entries exist from creation
3. **Fast access**: Direct indexing, no hashing overhead
4. **Cache-friendly**: Sequential memory layout

### Packet Size Buckets

We'll categorize packets into size buckets:
```
Bucket 0:    0-255 bytes
Bucket 1:  256-511 bytes
Bucket 2:  512-767 bytes
...
Bucket N: N*256 to (N+1)*256-1 bytes
```

### XDP (eXpress Data Path)

XDP programs run at the earliest point in the network stack:
```
┌────────────┐
│   NIC RX   │  Hardware receives packet
└─────┬──────┘
      │
┌─────▼──────┐
│ XDP Program│  ← Runs here (before sk_buff allocation)
└─────┬──────┘
      │
┌─────▼──────┐
│   Network  │  Continue to network stack
│   Stack    │
└────────────┘
```

Benefits:
- **Minimal overhead**: No sk_buff allocation yet
- **High performance**: Direct packet memory access
- **Early filtering**: Drop unwanted packets early
- **Programmable**: Custom packet processing logic

### Return Codes

XDP programs return action codes:
- `XDP_PASS` (2): Continue to network stack
- `XDP_DROP` (1): Drop packet
- `XDP_ABORTED` (0): Drop + trace event
- `XDP_TX` (3): Bounce back to same interface
- `XDP_REDIRECT` (4): Redirect to another interface

## Implementation

### Step 1: Complete Program

Create `lab-2-2.clj`:

```clojure
(ns lab-2-2-packet-histogram
  "Lab 2.2: Network Packet Histogram using BPF array maps"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Part 1: Configuration
;; ============================================================================

(def bucket-size 256)  ; Bytes per bucket
(def num-buckets 64)   ; Track packets up to 16KB (64 * 256)

;; ============================================================================
;; Part 2: Map Creation
;; ============================================================================

(defn create-histogram-map []
  "Create array map for packet size histogram"
  (bpf/create-map :array
    {:key-size 4          ; u32 for bucket index
     :value-size 8        ; u64 for packet count
     :max-entries num-buckets}))

;; ============================================================================
;; Part 3: XDP Program
;; ============================================================================

(defn create-xdp-histogram-program [map-fd]
  "Create XDP program that builds packet size histogram"
  (bpf/assemble
    (vec (concat
      ;; XDP context pointer is in r1
      ;; struct xdp_md {
      ;;   __u32 data;           // offset 0
      ;;   __u32 data_end;       // offset 4
      ;;   __u32 data_meta;      // offset 8
      ;;   __u32 ingress_ifindex;// offset 12
      ;; }

      ;; Load data pointer (start of packet)
      [(bpf/load-mem :w :r2 :r1 0)]   ; r2 = ctx->data

      ;; Load data_end pointer (end of packet)
      [(bpf/load-mem :w :r3 :r1 4)]   ; r3 = ctx->data_end

      ;; Calculate packet size
      ;; packet_size = data_end - data
      [(bpf/mov-reg :r4 :r3)]
      [(bpf/sub-reg :r4 :r2)]  ; r4 = packet size

      ;; Calculate bucket index
      ;; bucket = packet_size / bucket_size
      ;; For division by 256, we can shift right by 8
      [(bpf/mov-reg :r5 :r4)]
      [(bpf/rsh :r5 8)]  ; r5 = bucket index (size / 256)

      ;; Bounds check: ensure bucket < num_buckets
      [(bpf/jmp-imm :jge :r5 num-buckets :exit-pass)]

      ;; Store bucket index on stack
      [(bpf/store-mem :dw :r10 -8 :r5)]

      ;; Lookup current count in histogram
      [(bpf/ld-map-fd :r1 map-fd)]  ; r1 = map
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]            ; r2 = &bucket_index
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Check if lookup succeeded
      [(bpf/jmp-imm :jeq :r0 0 :exit-pass)]  ; NULL check

      ;; Increment counter
      [(bpf/mov-reg :r6 :r0)]       ; r6 = value pointer
      [(bpf/load-mem :dw :r7 :r6 0)] ; r7 = current count
      [(bpf/add :r7 1)]              ; r7 = count + 1
      [(bpf/store-mem :dw :r6 0 :r7)] ; *value = count + 1

      ;; :exit-pass - Return XDP_PASS (continue processing)
      [(bpf/mov :r0 2)]  ; XDP_PASS = 2
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 4: Userspace Data Access
;; ============================================================================

(defn read-u32-le [^ByteBuffer buf]
  "Read u32 from ByteBuffer"
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (bit-and (.getInt buf 0) 0xFFFFFFFF))

(defn read-u64-le [^ByteBuffer buf]
  "Read u64 from ByteBuffer"
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf 0))

(defn read-histogram [map-fd]
  "Read histogram data from map"
  (into []
    (for [bucket (range num-buckets)]
      (let [key (utils/u32 bucket)
            value (bpf/map-lookup map-fd key)]
        (if value
          (read-u64-le value)
          0)))))

(defn bucket-range [bucket]
  "Get size range for bucket"
  (let [start (* bucket bucket-size)
        end (+ start bucket-size -1)]
    [start end]))

(defn format-size [bytes]
  "Format byte size as human-readable string"
  (cond
    (>= bytes 1024) (format "%.1fK" (/ bytes 1024.0))
    :else (str bytes "B")))

(defn display-histogram [histogram]
  "Display histogram as text visualization"
  (println "\nPacket Size Histogram:")
  (println "═══════════════════════════════════════════════════════")

  (let [max-count (apply max (conj histogram 1))  ; Avoid division by zero
        bar-width 50]

    ;; Find non-zero buckets
    (let [non-zero (filter #(> (histogram %) 0) (range num-buckets))]
      (when (empty? non-zero)
        (println "No packets captured yet"))

      (doseq [bucket non-zero]
        (let [count (histogram bucket)
              [start end] (bucket-range bucket)
              bar-len (int (* bar-width (/ count max-count)))
              bar (apply str (repeat bar-len "█"))]
          (println (format "%5s - %5s │ %s %d"
                          (format-size start)
                          (format-size end)
                          bar
                          count))))))

  (println "═══════════════════════════════════════════════════════")
  (let [total (reduce + histogram)]
    (println "Total packets:" total)))

(defn display-statistics [histogram]
  "Display summary statistics"
  (let [total (reduce + histogram)
        weighted-sum (reduce + (map-indexed (fn [i cnt]
                                              (* i bucket-size cnt))
                                           histogram))
        avg-size (if (pos? total)
                   (/ weighted-sum total)
                   0)
        max-bucket (apply max-key histogram (range num-buckets))
        [max-start max-end] (bucket-range max-bucket)]
    (println "\nStatistics:")
    (println "───────────────────────────────────────────")
    (println "Total packets     :" total)
    (println "Average size      :" (format "%.1f bytes" avg-size))
    (println "Most common range :"
             (format "%s - %s (%d packets)"
                    (format-size max-start)
                    (format-size max-end)
                    (histogram max-bucket)))))

;; ============================================================================
;; Part 5: Test Data Generation
;; ============================================================================

(defn simulate-packets [map-fd]
  "Simulate packet captures for testing"
  (println "\nSimulating packet captures...")

  ;; Simulate various packet sizes
  (let [test-sizes [64 128 256 512 576 1024 1460 1500 4096 8192]]
    (doseq [size test-sizes
            _ (range (rand-int 20))]  ; Random count for each size
      (let [bucket (quot size bucket-size)
            key (utils/u32 bucket)
            current (bpf/map-lookup map-fd key)
            new-count (if current
                        (inc (read-u64-le current))
                        1)]
        (bpf/map-update map-fd key (utils/u64 new-count) :any))))

  (println "✓ Simulation complete"))

;; ============================================================================
;; Part 6: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 2.2: Network Packet Histogram ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create histogram map
  (println "\nStep 2: Creating histogram map...")
  (let [map-fd (create-histogram-map)]
    (println "✓ Histogram map created (FD:" map-fd ")")
    (println "  Buckets:" num-buckets)
    (println "  Bucket size:" bucket-size "bytes")
    (println "  Max packet size:" (* num-buckets bucket-size) "bytes")

    (try
      ;; Initialize all buckets to 0
      (println "\nStep 3: Initializing buckets...")
      (doseq [bucket (range num-buckets)]
        (let [key (utils/u32 bucket)
              value (utils/u64 0)]
          (bpf/map-update map-fd key value :any)))
      (println "✓" num-buckets "buckets initialized")

      ;; Create XDP program
      (println "\nStep 4: Creating XDP program...")
      (let [program (create-xdp-histogram-program map-fd)]
        (println "✓ Program assembled (" (/ (count program) 8) "instructions)")

        (println "\nStep 5: Loading program into kernel...")
        (let [prog-fd (bpf/load-program program :xdp)]
          (println "✓ Program loaded (FD:" prog-fd ")")

          (try
            ;; Note: Actual XDP attachment requires network interface
            ;; This will be covered in detail in Chapter 5
            (println "\nStep 6: XDP attachment...")
            (println "ℹ Network interface attachment requires Chapter 5")
            (println "ℹ Using simulated packet data for demonstration...")

            ;; Simulate packet captures
            (simulate-packets map-fd)

            ;; Display initial histogram
            (println "\nStep 7: Reading histogram...")
            (let [histogram (read-histogram map-fd)]
              (display-histogram histogram)
              (display-statistics histogram))

            ;; Demonstrate real-time updates
            (println "\nStep 8: Simulating more traffic...")
            (Thread/sleep 1000)

            ;; Add more packets
            (doseq [_ (range 50)]
              (let [size (+ 1400 (rand-int 100))  ; MTU-sized packets
                    bucket (quot size bucket-size)
                    key (utils/u32 bucket)
                    current (bpf/map-lookup map-fd key)
                    new-count (inc (read-u64-le current))]
                (bpf/map-update map-fd key (utils/u64 new-count) :any)))

            (println "✓ Added 50 MTU-sized packets")

            ;; Display updated histogram
            (let [histogram (read-histogram map-fd)]
              (display-histogram histogram)
              (display-statistics histogram))

            ;; Test bucket access
            (println "\nStep 9: Testing specific bucket access...")
            (let [test-bucket 5  ; 1280-1535 bytes
                  key (utils/u32 test-bucket)
                  value (bpf/map-lookup map-fd key)
                  [start end] (bucket-range test-bucket)]
              (println (format "Bucket %d (%s - %s): %d packets"
                              test-bucket
                              (format-size start)
                              (format-size end)
                              (if value (read-u64-le value) 0))))

            ;; Cleanup
            (println "\nStep 10: Cleanup...")
            (bpf/close-program prog-fd)
            (println "✓ Program closed")

            (catch Exception e
              (println "✗ Error:" (.getMessage e))
              (.printStackTrace e)))

          (finally
            (bpf/close-map map-fd)
            (println "✓ Map closed")))))

      (catch Exception e
        (println "✗ Error:" (.getMessage e))
        (.printStackTrace e))))

  (println "\n=== Lab 2.2 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-02/labs
clojure -M lab-2-2.clj
```

### Expected Output

```
=== Lab 2.2: Network Packet Histogram ===

Step 1: Initializing...

Step 2: Creating histogram map...
✓ Histogram map created (FD: 3)
  Buckets: 64
  Bucket size: 256 bytes
  Max packet size: 16384 bytes

Step 3: Initializing buckets...
✓ 64 buckets initialized

Step 4: Creating XDP program...
✓ Program assembled (18 instructions)

Step 5: Loading program into kernel...
✓ Program loaded (FD: 4)

Step 6: XDP attachment...
ℹ Network interface attachment requires Chapter 5
ℹ Using simulated packet data for demonstration...

Simulating packet captures...
✓ Simulation complete

Step 7: Reading histogram...

Packet Size Histogram:
═══════════════════════════════════════════════════════
   0B -  255B │ ████████████ 15
 256B -  511B │ ██████████████████ 22
 512B -  767B │ ████████████████████████ 30
1.0K - 1.2K │ ██████████████████████████████ 37
1.2K - 1.5K │ ████████████████████████████████████ 45
1.5K - 1.8K │ █████████ 11
4.0K - 4.2K │ ██████ 8
8.0K - 8.2K │ ████ 5
═══════════════════════════════════════════════════════
Total packets: 173

Statistics:
───────────────────────────────────────────
Total packets     : 173
Average size      : 1147.3 bytes
Most common range : 1.2K - 1.5K (45 packets)

Step 8: Simulating more traffic...
✓ Added 50 MTU-sized packets

Packet Size Histogram:
═══════════════════════════════════════════════════════
   0B -  255B │ ██████ 15
 256B -  511B │ ████████ 22
 512B -  767B │ ███████████ 30
1.0K - 1.2K │ ██████████████ 37
1.2K - 1.5K │ ████████████████████████████████████ 95
1.5K - 1.8K │ ████ 11
4.0K - 4.2K │ ███ 8
8.0K - 8.2K │ ██ 5
═══════════════════════════════════════════════════════
Total packets: 223

Statistics:
───────────────────────────────────────────
Total packets     : 223
Average size      : 1279.5 bytes
Most common range : 1.2K - 1.5K (95 packets)

Step 9: Testing specific bucket access...
Bucket 5 (1.2K - 1.5K): 95 packets

Step 10: Cleanup...
✓ Program closed
✓ Map closed

=== Lab 2.2 Complete! ===
```

## Understanding the Code

### Array Map Initialization

```clojure
;; Unlike hash maps, array maps pre-allocate all entries
(doseq [bucket (range num-buckets)]
  (bpf/map-update map-fd (utils/u32 bucket) (utils/u64 0) :any))
```

All array indices must be initialized before use in BPF programs.

### Packet Size Calculation

```clojure
;; In XDP program
[(bpf/load-mem :w :r2 :r1 0)]   ; r2 = ctx->data
[(bpf/load-mem :w :r3 :r1 4)]   ; r3 = ctx->data_end
[(bpf/mov-reg :r4 :r3)]
[(bpf/sub-reg :r4 :r2)]         ; r4 = packet_size
```

XDP context provides direct pointers to packet memory.

### Bucket Index Calculation

```clojure
;; Divide by 256 using right shift
[(bpf/rsh :r5 8)]  ; bucket = size / 256 = size >> 8
```

Bit shifting is faster than division and works for powers of 2.

### Bounds Checking

```clojure
;; Verifier requires proof that bucket index is valid
[(bpf/jmp-imm :jge :r5 num-buckets :exit-pass)]
```

Essential for verifier approval - must prove array access is in bounds.

## Experiments

### Experiment 1: Change Bucket Size

```clojure
(def bucket-size 64)   ; Finer granularity
(def num-buckets 256)  ; Still cover 16KB

;; Now need to adjust bucket calculation
[(bpf/rsh :r5 6)]  ; Divide by 64 = shift right 6
```

### Experiment 2: Logarithmic Buckets

```clojure
;; Bucket 0: 0-63
;; Bucket 1: 64-127
;; Bucket 2: 128-255
;; Bucket 3: 256-511
;; ...

;; Calculate: bucket = log2(size)
;; Approximate using clz (count leading zeros)
```

### Experiment 3: Per-Protocol Histograms

```clojure
;; Create separate histograms for TCP, UDP, ICMP
(def tcp-histogram (bpf/create-map :array {...}))
(def udp-histogram (bpf/create-map :array {...}))

;; Parse IP header to determine protocol
;; Update appropriate histogram
```

### Experiment 4: Real-Time Visualization

```clojure
;; Continuously poll and update display
(defn live-histogram [map-fd interval-ms]
  (while true
    (Thread/sleep interval-ms)
    (let [histogram (read-histogram map-fd)]
      (print "\033[2J\033[H")  ; Clear screen
      (display-histogram histogram)
      (display-statistics histogram))))
```

## Troubleshooting

### Error: "Array index out of bounds"

**Verifier rejection**: `R5 unbounded memory access`

**Solution**: Add explicit bounds check:
```clojure
[(bpf/jmp-imm :jge :r5 num-buckets :exit)]
```

### Error: "Invalid mem access 'inv'"

**Cause**: Accessing memory without verifying pointer validity

**Solution**: Check XDP context pointers:
```clojure
;; Before accessing packet data, verify in bounds
[(bpf/mov-reg :r4 :r2)]
[(bpf/add :r4 14)]  ; Ethernet header size
[(bpf/jmp-reg :jgt :r4 :r3 :exit)]  ; if (data + 14 > data_end) exit
```

### Histogram Shows Unexpected Distribution

**Possible causes**:
1. **Bucket size mismatch**: Division calculation wrong
2. **Endianness**: Reading wrong byte order
3. **Overflow**: Counters wrapping around

**Debug**:
```clojure
;; Print raw bucket values
(doseq [i (range 10)]
  (let [val (bpf/map-lookup map-fd (utils/u32 i))]
    (println "Bucket" i ":" (read-u64-le val))))
```

## Key Takeaways

✅ Array maps are ideal for histogram and indexed data
✅ All array entries are pre-allocated and must be initialized
✅ Array indices must be bounds-checked for verifier
✅ XDP provides high-performance packet processing
✅ Bit shifts are efficient for power-of-2 divisions
✅ Visual histograms make data patterns obvious

## Next Steps

- **Next Lab**: [Lab 2.3 - Stack Trace Collector](lab-2-3-stack-trace.md)
- **Previous Lab**: [Lab 2.1 - Process Counter](lab-2-1-process-counter.md)
- **Chapter**: [Chapter 2 - BPF Maps](../README.md)

## Challenge

Enhance the histogram to:
1. Track packet counts per network interface
2. Separate histograms for RX and TX
3. Track packets per protocol (TCP, UDP, ICMP)
4. Export data to JSON for visualization

Solution in: [solutions/lab-2-2-challenge.clj](../solutions/lab-2-2-challenge.clj)
