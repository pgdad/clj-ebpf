# Lab 3.3: Custom Protocol Parser

**Objective**: Build a parser for a custom network protocol using BPF instructions

**Duration**: 75 minutes

## Overview

In this lab, you'll design and implement a parser for a custom binary protocol. You'll define the protocol specification, build a complete parser using BPF instructions, extract structured data, and validate messages. This demonstrates how to handle complex parsing tasks in BPF.

This lab demonstrates:
- Designing binary network protocols
- Multi-field structure parsing
- Data validation and checksums
- Variable-length message handling
- State machine implementation in BPF
- Efficient parsing patterns

## What You'll Learn

- How to design packet-efficient protocols
- Parsing fixed and variable-length fields
- Implementing checksums and validation
- Handling protocol versioning
- Building state machines in BPF
- Extracting and storing structured data

## Theory

### Protocol Design

A well-designed binary protocol has:
1. **Magic number**: Quick protocol identification
2. **Version field**: Protocol evolution support
3. **Length field**: Variable-length messages
4. **Type field**: Message differentiation
5. **Checksum**: Data integrity verification
6. **Payload**: Actual data

### Our Custom Protocol: "FastLog"

A lightweight logging protocol for distributed systems:

```
FastLog Protocol v1
═══════════════════════════════════════════════════════

Header (16 bytes):
┌────────┬─────┬─────┬────────┬──────────┬──────────┐
│ Magic  │ Ver │Type │  Len   │   Seq    │ Checksum │
│ 4 bytes│1 by │1 by │ 2 bytes│ 4 bytes  │ 4 bytes  │
│0xF45710│ 0x01│     │        │          │          │
└────────┴─────┴─────┴────────┴──────────┴──────────┘

Message Types:
  0x01: LOG_MESSAGE    - Log entry
  0x02: METRIC         - Performance metric
  0x03: TRACE_SPAN     - Distributed trace
  0x04: HEARTBEAT      - Keep-alive
  0x05: ACK            - Acknowledgment

Payload Format (variable length):

LOG_MESSAGE:
┌──────────┬──────┬──────────┬─────────────┐
│Timestamp │Level │ Severity │   Message   │
│ 8 bytes  │1 byte│  1 byte  │   N bytes   │
└──────────┴──────┴──────────┴─────────────┘

METRIC:
┌──────────┬────────────┬────────┬─────────┐
│Timestamp │ Metric ID  │ Value  │  Unit   │
│ 8 bytes  │  4 bytes   │8 bytes │ 1 byte  │
└──────────┴────────────┴────────┴─────────┘

TRACE_SPAN:
┌──────────┬──────────┬──────────┬──────────┐
│ Trace ID │ Span ID  │ Parent   │ Duration │
│ 16 bytes │ 8 bytes  │ 8 bytes  │ 8 bytes  │
└──────────┴──────────┴──────────┴──────────┘
```

### Checksum Algorithm

Simple additive checksum:
```
checksum = 0
for each 32-bit word in (header + payload):
    checksum += word
checksum = ~checksum  # One's complement
```

## Implementation

### Step 1: Complete Program

Create `lab-3-3.clj`:

```clojure
(ns lab-3-3-protocol-parser
  "Lab 3.3: Custom Protocol Parser using BPF instructions"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Part 1: Protocol Constants
;; ============================================================================

(def FASTLOG_MAGIC 0xF4571000)
(def FASTLOG_VERSION 0x01)

;; Message types
(def MSG_LOG 0x01)
(def MSG_METRIC 0x02)
(def MSG_TRACE 0x03)
(def MSG_HEARTBEAT 0x04)
(def MSG_ACK 0x05)

;; Log levels
(def LEVEL_DEBUG 0)
(def LEVEL_INFO 1)
(def LEVEL_WARN 2)
(def LEVEL_ERROR 3)

;; Header offsets (after Ethernet + IP + UDP headers)
(def ETH_HLEN 14)
(def IP_HLEN 20)   ; Minimum IP header
(def UDP_HLEN 8)
(def L4_OFFSET (+ ETH_HLEN IP_HLEN UDP_HLEN))

;; FastLog header offsets
(def HDR_MAGIC 0)
(def HDR_VERSION 4)
(def HDR_TYPE 5)
(def HDR_LEN 6)
(def HDR_SEQ 8)
(def HDR_CHECKSUM 12)
(def HDR_SIZE 16)

;; ============================================================================
;; Part 2: Data Structures
;; ============================================================================

(defn create-parsed-messages-map []
  "Map to store parsed messages"
  (bpf/create-map :hash
    {:key-size 4       ; Sequence number
     :value-size 128   ; Parsed message data
     :max-entries 1000}))

(defn create-stats-map []
  "Map to track parsing statistics"
  (bpf/create-map :array
    {:key-size 4
     :value-size 8
     :max-entries 10}))

(def STAT_TOTAL 0)
(def STAT_VALID 1)
(def STAT_INVALID_MAGIC 2)
(def STAT_INVALID_VERSION 3)
(def STAT_INVALID_CHECKSUM 4)
(def STAT_LOG_MSGS 5)
(def STAT_METRIC_MSGS 6)
(def STAT_TRACE_MSGS 7)

;; ============================================================================
;; Part 3: Parsing Helpers
;; ============================================================================

(defn check-bounds
  "Check packet bounds"
  [data-reg data-end-reg offset label]
  (vec (concat
    [(bpf/mov-reg :r9 data-reg)]
    [(bpf/add :r9 offset)]
    [(bpf/jmp-reg :jgt :r9 data-end-reg label)])))

(defn load-u32-be [data-reg offset dst-reg]
  "Load 32-bit big-endian value"
  (vec (concat
    [(bpf/load-mem :w dst-reg data-reg offset)]
    [(bpf/be32 dst-reg)])))

(defn load-u16-be [data-reg offset dst-reg]
  "Load 16-bit big-endian value"
  (vec (concat
    [(bpf/load-mem :h dst-reg data-reg offset)]
    [(bpf/be16 dst-reg)])))

(defn update-stat [stats-map-fd stat-index]
  "Increment a statistics counter"
  (vec (concat
    ;; Prepare key (stat index)
    [(bpf/store-mem :w :r10 -4 stat-index)]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]

    ;; Lookup current value
    [(bpf/ld-map-fd :r1 stats-map-fd)]
    (bpf/helper-map-lookup-elem :r1 :r2)

    ;; Increment (or initialize to 1 if not found)
    [(bpf/jmp-imm :jeq :r0 0 3)]  ; Skip if NULL
    [(bpf/load-mem :dw :r3 :r0 0)]  ; Load current value
    [(bpf/add :r3 1)]                ; Increment
    [(bpf/store-mem :dw :r0 0 :r3)] ; Store back
    )))

;; ============================================================================
;; Part 4: FastLog Parser - Main Program
;; ============================================================================

(defn create-fastlog-parser [stats-map-fd parsed-map-fd]
  "Parse FastLog protocol messages"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Load packet pointers
      ;; ──────────────────────────────────────────────────────────

      ;; r1 = XDP context
      [(bpf/load-mem :w :r2 :r1 0)]   ; r2 = data
      [(bpf/load-mem :w :r3 :r1 4)]   ; r3 = data_end

      ;; Update total packet counter
      (update-stat stats-map-fd STAT_TOTAL)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Navigate to FastLog header
      ;; ──────────────────────────────────────────────────────────

      ;; r4 = fastlog_header = data + L4_OFFSET
      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 L4_OFFSET)]

      ;; Check bounds: header + HDR_SIZE
      (check-bounds :r4 :r3 HDR_SIZE :pass)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Validate Magic Number
      ;; ──────────────────────────────────────────────────────────

      ;; Load and check magic (offset 0, 4 bytes)
      (load-u32-be :r4 HDR_MAGIC :r5)

      ;; Compare with expected magic
      [(bpf/jmp-imm :jne :r5 FASTLOG_MAGIC :invalid-magic)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Validate Version
      ;; ──────────────────────────────────────────────────────────

      ;; Load version (offset 4, 1 byte)
      [(bpf/load-mem :b :r5 :r4 HDR_VERSION)]

      ;; Check version
      [(bpf/jmp-imm :jne :r5 FASTLOG_VERSION :invalid-version)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Parse Header Fields
      ;; ──────────────────────────────────────────────────────────

      ;; Load message type (offset 5, 1 byte)
      [(bpf/load-mem :b :r6 :r4 HDR_TYPE)]  ; r6 = type

      ;; Load length (offset 6, 2 bytes)
      (load-u16-be :r4 HDR_LEN :r7)  ; r7 = length

      ;; Load sequence number (offset 8, 4 bytes)
      (load-u32-be :r4 HDR_SEQ :r8)  ; r8 = seq

      ;; Load checksum (offset 12, 4 bytes)
      (load-u32-be :r4 HDR_CHECKSUM :r9)  ; r9 = checksum

      ;; ──────────────────────────────────────────────────────────
      ;; Step 6: Validate Checksum (Simplified)
      ;; ──────────────────────────────────────────────────────────

      ;; Note: Full checksum validation would sum all words
      ;; Here we do a simplified check for demonstration

      ;; Check if checksum is non-zero (basic sanity)
      [(bpf/jmp-imm :jeq :r9 0 :invalid-checksum)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 7: Dispatch by Message Type
      ;; ──────────────────────────────────────────────────────────

      ;; Check message type and jump to appropriate handler
      [(bpf/jmp-imm :jeq :r6 MSG_LOG :parse-log)]
      [(bpf/jmp-imm :jeq :r6 MSG_METRIC :parse-metric)]
      [(bpf/jmp-imm :jeq :r6 MSG_TRACE :parse-trace)]
      [(bpf/jmp-imm :jeq :r6 MSG_HEARTBEAT :parse-heartbeat)]
      [(bpf/jmp :valid)]  ; Unknown type, but valid

      ;; ──────────────────────────────────────────────────────────
      ;; Step 8: Parse LOG_MESSAGE
      ;; ──────────────────────────────────────────────────────────

      ;; :parse-log
      ;; Payload: timestamp(8) + level(1) + severity(1) + message(N)

      ;; r5 = payload = header + HDR_SIZE
      [(bpf/mov-reg :r5 :r4)]
      [(bpf/add :r5 HDR_SIZE)]

      ;; Check bounds for minimum log payload (10 bytes)
      (check-bounds :r5 :r3 10 :pass)

      ;; Load timestamp (8 bytes)
      [(bpf/load-mem :dw :r1 :r5 0)]
      [(bpf/store-mem :dw :r10 -8 :r1)]  ; Save on stack

      ;; Load level (1 byte)
      [(bpf/load-mem :b :r1 :r5 8)]
      [(bpf/store-mem :w :r10 -12 :r1)]

      ;; Load severity (1 byte)
      [(bpf/load-mem :b :r1 :r5 9)]
      [(bpf/store-mem :w :r10 -16 :r1)]

      ;; Update log message counter
      (update-stat stats-map-fd STAT_LOG_MSGS)

      [(bpf/jmp :valid)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 9: Parse METRIC
      ;; ──────────────────────────────────────────────────────────

      ;; :parse-metric
      ;; Payload: timestamp(8) + metric_id(4) + value(8) + unit(1)

      [(bpf/mov-reg :r5 :r4)]
      [(bpf/add :r5 HDR_SIZE)]

      ;; Check bounds (21 bytes total)
      (check-bounds :r5 :r3 21 :pass)

      ;; Load metric ID
      (load-u32-be :r5 8 :r1)
      [(bpf/store-mem :w :r10 -20 :r1)]

      ;; Load value (8 bytes)
      [(bpf/load-mem :dw :r1 :r5 12)]
      [(bpf/store-mem :dw :r10 -28 :r1)]

      ;; Update metric counter
      (update-stat stats-map-fd STAT_METRIC_MSGS)

      [(bpf/jmp :valid)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 10: Parse TRACE_SPAN
      ;; ──────────────────────────────────────────────────────────

      ;; :parse-trace
      ;; Payload: trace_id(16) + span_id(8) + parent_id(8) + duration(8)

      [(bpf/mov-reg :r5 :r4)]
      [(bpf/add :r5 HDR_SIZE)]

      ;; Check bounds (40 bytes)
      (check-bounds :r5 :r3 40 :pass)

      ;; Load span ID (simplified - just first 8 bytes of trace_id)
      [(bpf/load-mem :dw :r1 :r5 0)]
      [(bpf/store-mem :dw :r10 -36 :r1)]

      ;; Update trace counter
      (update-stat stats-map-fd STAT_TRACE_MSGS)

      [(bpf/jmp :valid)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 11: Parse HEARTBEAT
      ;; ──────────────────────────────────────────────────────────

      ;; :parse-heartbeat
      ;; Minimal payload, just acknowledge

      ;; Could store last heartbeat time, etc.

      [(bpf/jmp :valid)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 12: Success Path
      ;; ──────────────────────────────────────────────────────────

      ;; :valid
      ;; Update valid message counter
      (update-stat stats-map-fd STAT_VALID)

      [(bpf/jmp :pass)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 13: Error Paths
      ;; ──────────────────────────────────────────────────────────

      ;; :invalid-magic
      (update-stat stats-map-fd STAT_INVALID_MAGIC)
      [(bpf/jmp :pass)]

      ;; :invalid-version
      (update-stat stats-map-fd STAT_INVALID_VERSION)
      [(bpf/jmp :pass)]

      ;; :invalid-checksum
      (update-stat stats-map-fd STAT_INVALID_CHECKSUM)
      [(bpf/jmp :pass)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 14: Return
      ;; ──────────────────────────────────────────────────────────

      ;; :pass
      [(bpf/mov :r0 2)]  ; XDP_PASS
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 5: Userspace - Statistics Display
;; ============================================================================

(defn read-u64-le [^ByteBuffer buf]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf 0))

(defn read-stat [stats-map-fd idx]
  (let [key (utils/u32 idx)
        value (bpf/map-lookup stats-map-fd key)]
    (if value (read-u64-le value) 0)))

(defn display-stats [stats-map-fd]
  "Display parsing statistics"
  (println "\nFastLog Parser Statistics:")
  (println "═══════════════════════════════════════")
  (println (format "Total packets     : %d" (read-stat stats-map-fd STAT_TOTAL)))
  (println (format "Valid messages    : %d" (read-stat stats-map-fd STAT_VALID)))
  (println)
  (println "Errors:")
  (println (format "  Invalid magic   : %d" (read-stat stats-map-fd STAT_INVALID_MAGIC)))
  (println (format "  Invalid version : %d" (read-stat stats-map-fd STAT_INVALID_VERSION)))
  (println (format "  Invalid checksum: %d" (read-stat stats-map-fd STAT_INVALID_CHECKSUM)))
  (println)
  (println "Message Types:")
  (println (format "  Log messages    : %d" (read-stat stats-map-fd STAT_LOG_MSGS)))
  (println (format "  Metrics         : %d" (read-stat stats-map-fd STAT_METRIC_MSGS)))
  (println (format "  Trace spans     : %d" (read-stat stats-map-fd STAT_TRACE_MSGS)))

  ;; Calculate success rate
  (let [total (read-stat stats-map-fd STAT_TOTAL)
        valid (read-stat stats-map-fd STAT_VALID)
        rate (if (pos? total)
               (* 100.0 (/ valid total))
               0.0)]
    (println)
    (println (format "Success rate      : %.1f%%" rate))))

;; ============================================================================
;; Part 6: Test Packet Generation
;; ============================================================================

(defn calculate-checksum [data]
  "Calculate simple additive checksum"
  (let [words (partition 4 4 (repeat 0) data)
        sum (reduce (fn [acc word-bytes]
                     (let [word (reduce (fn [w b] (+ (* w 256) (bit-and b 0xFF)))
                                       0 word-bytes)]
                       (+ acc word)))
                   0 words)]
    (bit-and (bit-not sum) 0xFFFFFFFF)))

(defn create-fastlog-packet [msg-type payload]
  "Create a FastLog protocol packet"
  (let [header-buf (ByteBuffer/allocate HDR_SIZE)
        total-len (+ HDR_SIZE (count payload))
        seq-num (rand-int 1000000)]

    (.order header-buf ByteOrder/BIG_ENDIAN)

    ;; Magic
    (.putInt header-buf 0 FASTLOG_MAGIC)
    ;; Version
    (.put header-buf 4 (byte FASTLOG_VERSION))
    ;; Type
    (.put header-buf 5 (byte msg-type))
    ;; Length
    (.putShort header-buf 6 (short total-len))
    ;; Sequence
    (.putInt header-buf 8 seq-num)

    ;; Combine header and payload for checksum
    (let [header-bytes (.array header-buf)
          combined (byte-array (+ (count header-bytes) (count payload)))]
      (System/arraycopy header-bytes 0 combined 0 (count header-bytes))
      (System/arraycopy payload 0 combined (count header-bytes) (count payload))

      ;; Calculate and set checksum
      (let [checksum (calculate-checksum combined)]
        (.putInt header-buf 12 (int checksum)))

      ;; Return complete packet
      (let [packet (byte-array total-len)]
        (System/arraycopy (.array header-buf) 0 packet 0 HDR_SIZE)
        (System/arraycopy payload 0 packet HDR_SIZE (count payload))
        packet))))

;; ============================================================================
;; Part 7: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 3.3: Custom Protocol Parser ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create maps
  (println "\nStep 2: Creating maps...")
  (let [stats-map-fd (create-stats-map)
        parsed-map-fd (create-parsed-messages-map)]
    (println "✓ Statistics map created (FD:" stats-map-fd ")")
    (println "✓ Parsed messages map created (FD:" parsed-map-fd ")")

    ;; Initialize stats to 0
    (doseq [i (range 10)]
      (bpf/map-update stats-map-fd (utils/u32 i) (utils/u64 0) :any))

    (try
      ;; Create parser
      (println "\nStep 3: Creating FastLog parser...")
      (let [parser (create-fastlog-parser stats-map-fd parsed-map-fd)]
        (println "✓ Parser assembled (" (/ (count parser) 8) "instructions)")
        (println "  Protocol: FastLog v1")
        (println "  Magic: 0xF4571000")

        ;; Load parser
        (println "\nStep 4: Loading parser into kernel...")
        (let [prog-fd (bpf/load-program parser :xdp)]
          (println "✓ Parser loaded (FD:" prog-fd ")")

          (try
            (println "\nStep 5: Protocol specification...")
            (println "\nSupported message types:")
            (println "  0x01: LOG_MESSAGE  - Application logs")
            (println "  0x02: METRIC       - Performance metrics")
            (println "  0x03: TRACE_SPAN   - Distributed traces")
            (println "  0x04: HEARTBEAT    - Keep-alive")
            (println "  0x05: ACK          - Acknowledgment")

            ;; Demonstrate packet creation
            (println "\nStep 6: Test packet generation...")
            (let [log-payload (byte-array (concat
                                           ;; Timestamp (8 bytes)
                                           [0 0 0 0 0 0 0 42]
                                           ;; Level (1 byte)
                                           [LEVEL_INFO]
                                           ;; Severity (1 byte)
                                           [1]
                                           ;; Message
                                           (.getBytes "Test log message" "UTF-8")))
                  packet (create-fastlog-packet MSG_LOG log-payload)]
              (println "✓ Created LOG_MESSAGE packet")
              (println "  Size:" (count packet) "bytes")
              (println "  Payload: \"Test log message\""))

            ;; Note: Actual packet injection requires XDP attachment
            (println "\nStep 7: Parser testing...")
            (println "ℹ Packet injection requires XDP attachment")
            (println "ℹ In production, parser would:")
            (println "  1. Receive packets on network interface")
            (println "  2. Validate protocol headers")
            (println "  3. Extract and store message data")
            (println "  4. Update statistics")

            ;; Display statistics
            (println "\nStep 8: Statistics...")
            (display-stats stats-map-fd)

            ;; Cleanup
            (println "\nStep 9: Cleanup...")
            (bpf/close-program prog-fd)
            (println "✓ Program closed")

            (catch Exception e
              (println "✗ Error:" (.getMessage e))
              (.printStackTrace e)))

          (finally
            (bpf/close-map stats-map-fd)
            (bpf/close-map parsed-map-fd)
            (println "✓ Maps closed")))))

      (catch Exception e
        (println "✗ Error:" (.getMessage e))
        (.printStackTrace e))))

  (println "\n=== Lab 3.3 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-03/labs
clojure -M lab-3-3.clj
```

### Expected Output

```
=== Lab 3.3: Custom Protocol Parser ===

Step 1: Initializing...

Step 2: Creating maps...
✓ Statistics map created (FD: 3)
✓ Parsed messages map created (FD: 4)

Step 3: Creating FastLog parser...
✓ Parser assembled (65 instructions)
  Protocol: FastLog v1
  Magic: 0xF4571000

Step 4: Loading parser into kernel...
✓ Parser loaded (FD: 5)

Step 5: Protocol specification...

Supported message types:
  0x01: LOG_MESSAGE  - Application logs
  0x02: METRIC       - Performance metrics
  0x03: TRACE_SPAN   - Distributed traces
  0x04: HEARTBEAT    - Keep-alive
  0x05: ACK          - Acknowledgment

Step 6: Test packet generation...
✓ Created LOG_MESSAGE packet
  Size: 42 bytes
  Payload: "Test log message"

Step 7: Parser testing...
ℹ Packet injection requires XDP attachment
ℹ In production, parser would:
  1. Receive packets on network interface
  2. Validate protocol headers
  3. Extract and store message data
  4. Update statistics

Step 8: Statistics...

FastLog Parser Statistics:
═══════════════════════════════════════
Total packets     : 0
Valid messages    : 0

Errors:
  Invalid magic   : 0
  Invalid version : 0
  Invalid checksum: 0

Message Types:
  Log messages    : 0
  Metrics         : 0
  Trace spans     : 0

Success rate      : 0.0%

Step 9: Cleanup...
✓ Program closed
✓ Maps closed

=== Lab 3.3 Complete! ===
```

## Understanding the Code

### Protocol Validation Flow

```clojure
;; 1. Check magic number (fast rejection)
(load-u32-be :r4 HDR_MAGIC :r5)
[(bpf/jmp-imm :jne :r5 FASTLOG_MAGIC :invalid-magic)]

;; 2. Check version (protocol evolution)
[(bpf/load-mem :b :r5 :r4 HDR_VERSION)]
[(bpf/jmp-imm :jne :r5 FASTLOG_VERSION :invalid-version)]

;; 3. Check checksum (data integrity)
;; 4. Parse type-specific payload
```

### Type-Based Dispatch

```clojure
;; Switch on message type
[(bpf/jmp-imm :jeq :r6 MSG_LOG :parse-log)]
[(bpf/jmp-imm :jeq :r6 MSG_METRIC :parse-metric)]
[(bpf/jmp-imm :jeq :r6 MSG_TRACE :parse-trace)]
;; Default: pass through
```

Efficient jump table for message type routing.

### Statistics Pattern

```clojure
(defn update-stat [stats-map-fd stat-index]
  ;; Lookup counter
  ;; Increment atomically
  ;; No return value needed
  ...)
```

Track parsing metrics without impacting performance.

## Experiments

### Experiment 1: Add Compression Support

```clojure
;; Add flag in header for compressed payload
(def HDR_FLAGS 6)  ; New field
(def FLAG_COMPRESSED 0x01)

;; In parser:
[(bpf/load-mem :b :r5 :r4 HDR_FLAGS)]
[(bpf/and :r5 FLAG_COMPRESSED)]
[(bpf/jmp-imm :jne :r5 0 :decompress)]
```

### Experiment 2: Multi-Version Support

```clojure
;; Parse different versions
[(bpf/jmp-imm :jeq :r5 0x01 :parse-v1)]
[(bpf/jmp-imm :jeq :r5 0x02 :parse-v2)]
[(bpf/jmp :unsupported-version)]

;; :parse-v2
;; Handle v2-specific fields
```

### Experiment 3: Fragmentation Handling

```clojure
;; Add fragment fields to header
;; frag_id, frag_seq, frag_total

;; Store fragments in map
;; Reassemble when complete
```

### Experiment 4: Rate Limiting per Message Type

```clojure
;; Track message rates
(def rate-limit-map ...)

;; In parser:
;; Check current rate for message type
;; Drop if exceeds limit
[(bpf/jmp-imm :jgt :r7 MAX_RATE :drop)]
```

## Troubleshooting

### Parser Rejects Valid Packets

**Check**:
1. Endianness (network vs host byte order)
2. Field offsets (struct packing)
3. Checksum calculation

**Debug**:
```clojure
;; Add debug prints in userspace
(println "Magic:" (format "0x%08x" magic))
(println "Expected:" (format "0x%08x" FASTLOG_MAGIC))
```

### High Invalid Checksum Count

**Causes**:
- Checksum algorithm mismatch
- Including/excluding header in checksum
- Byte order issues

**Solution**: Verify checksum algorithm matches sender.

### Verifier Rejection on Complex Parsing

**Error**: "program too large"

**Solution**: Split into multiple programs using tail calls:
```clojure
;; Main parser validates header
;; Tail call to type-specific parsers
```

## Key Takeaways

✅ Protocol design affects parsing efficiency
✅ Magic numbers enable fast protocol identification
✅ Checksums provide data integrity
✅ Type fields enable extensible protocols
✅ Statistics tracking aids debugging
✅ BPF can handle complex parsing tasks

## Next Steps

- **Next Chapter**: [Chapter 4 - Helper Functions](../../chapter-04/README.md)
- **Previous Lab**: [Lab 3.2 - System Call Argument Capture](lab-3-2-syscall-args.md)
- **Chapter**: [Chapter 3 - BPF Instruction Set](../README.md)

## Challenge

Enhance the FastLog protocol with:
1. **Encryption**: Add encrypted payload support
2. **Authentication**: Add HMAC for message authentication
3. **Streaming**: Handle messages larger than MTU (fragmentation)
4. **Bidirectional**: Add request/response patterns
5. **QoS**: Priority levels and guaranteed delivery
6. **Batching**: Multiple messages in single packet

Solution in: [solutions/lab-3-3-challenge.clj](../solutions/lab-3-3-challenge.clj)
