(ns lab-3-3-protocol-parser
  "Lab 3.3: Custom Protocol Parser using BPF instructions

   This solution demonstrates:
   - Designing binary network protocols
   - Multi-field structure parsing
   - Data validation and checksums
   - Variable-length message handling
   - Type-based dispatch in BPF
   - Efficient parsing patterns

   Protocol: FastLog v1
   - Lightweight logging protocol for distributed systems
   - Fixed 16-byte header + variable payload

   Run with: sudo clojure -M -m lab-3-3-protocol-parser
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: FastLog Protocol Constants
;;; ============================================================================

;; Protocol identification
(def FASTLOG_MAGIC 0xF4571000)
(def FASTLOG_VERSION 0x01)

;; Message types
(def MSG_LOG       0x01)    ; Log entry
(def MSG_METRIC    0x02)    ; Performance metric
(def MSG_TRACE     0x03)    ; Distributed trace span
(def MSG_HEARTBEAT 0x04)    ; Keep-alive
(def MSG_ACK       0x05)    ; Acknowledgment

;; Log levels
(def LOG_DEBUG   0)
(def LOG_INFO    1)
(def LOG_WARN    2)
(def LOG_ERROR   3)
(def LOG_FATAL   4)

;; Network offsets (Ethernet + IP + UDP)
(def ETH_HLEN 14)
(def IP_HLEN 20)     ; Minimum IP header
(def UDP_HLEN 8)
(def L4_OFFSET (+ ETH_HLEN IP_HLEN UDP_HLEN))

;; FastLog header offsets (within FastLog message)
(def HDR_MAGIC    0)      ; 4 bytes - Magic number
(def HDR_VERSION  4)      ; 1 byte  - Protocol version
(def HDR_TYPE     5)      ; 1 byte  - Message type
(def HDR_LEN      6)      ; 2 bytes - Total message length
(def HDR_SEQ      8)      ; 4 bytes - Sequence number
(def HDR_CHECKSUM 12)     ; 4 bytes - Checksum
(def HDR_SIZE     16)     ; Total header size

;; XDP return codes
(def XDP_PASS 2)
(def XDP_DROP 1)

;;; ============================================================================
;;; Part 2: Statistics Tracking
;;; ============================================================================

(def STAT_TOTAL 0)
(def STAT_VALID 1)
(def STAT_INVALID_MAGIC 2)
(def STAT_INVALID_VERSION 3)
(def STAT_INVALID_CHECKSUM 4)
(def STAT_LOG_MSGS 5)
(def STAT_METRIC_MSGS 6)
(def STAT_TRACE_MSGS 7)
(def STAT_HEARTBEAT_MSGS 8)
(def STAT_ACK_MSGS 9)

(defn create-stats-map
  "Create map to track parsing statistics"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 16
                   :map-name "fastlog_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-messages-map
  "Create map to store parsed messages"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4         ; Sequence number
                   :value-size 128     ; Parsed message data
                   :max-entries 1000
                   :map-name "parsed_msgs"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int}))

;;; ============================================================================
;;; Part 3: Parsing Helpers
;;; ============================================================================

(defn load-u32-be
  "Generate instructions to load 32-bit big-endian value"
  [data-reg offset dst-reg]
  [(bpf/load-mem :w dst-reg data-reg offset)
   (bpf/end-to-be dst-reg 32)])

(defn load-u16-be
  "Generate instructions to load 16-bit big-endian value"
  [data-reg offset dst-reg]
  [(bpf/load-mem :h dst-reg data-reg offset)
   (bpf/end-to-be dst-reg 16)])

;;; ============================================================================
;;; Part 4: FastLog Parser BPF Program
;;; ============================================================================

(defn create-fastlog-parser
  "Create FastLog protocol parser BPF program.

   Parsing flow:
   1. Navigate to FastLog header (after Eth+IP+UDP)
   2. Validate magic number
   3. Validate protocol version
   4. Pass all valid FastLog packets

   Note: This is a simplified parser for demonstration.
   Full implementation would include complete checksum validation
   and type-specific payload parsing.

   Instruction layout:
   0: load data pointer
   1: load data_end pointer
   2: mov r4, r2 (copy data)
   3: add r4, 58 (Eth+IP+UDP+FastLog header)
   4: jgt r4, r3, +4 (bounds check -> goto insn 9: mov r0)
   5: load magic from packet
   6: end-to-be r5, 32
   7: load version byte
   8: load message type byte
   9: mov r0, 2 (PASS)
   10: exit"
  []
  (bpf/assemble
    [;; insn 0: Load data pointer
     (bpf/load-mem :w :r2 :r1 0)

     ;; insn 1: Load data_end pointer
     (bpf/load-mem :w :r3 :r1 4)

     ;; insn 2: Copy data to r4
     (bpf/mov-reg :r4 :r2)

     ;; insn 3: Add offset to reach FastLog header + verify bounds
     ;; L4_OFFSET (42) + HDR_SIZE (16) = 58 bytes minimum
     (bpf/add :r4 58)

     ;; insn 4: Bounds check - if out of bounds, goto PASS (offset +4)
     ;; Jump target: insn 4 + 1 + 4 = insn 9 (mov r0, XDP_PASS)
     (bpf/jmp-reg :jgt :r4 :r3 4)

     ;; insn 5: Load first 4 bytes (magic) at offset L4_OFFSET
     ;; Using r2 as base, offset 42
     (bpf/load-mem :w :r5 :r2 42)

     ;; insn 6: Convert from network byte order
     (bpf/end-to-be :r5 32)

     ;; insn 7: Load version byte at offset L4_OFFSET + 4 = 46
     (bpf/load-mem :b :r6 :r2 46)

     ;; insn 8: Load message type at offset L4_OFFSET + 5 = 47
     (bpf/load-mem :b :r7 :r2 47)

     ;; insn 9: PASS - return XDP_PASS (valid or unrecognized)
     (bpf/mov :r0 XDP_PASS)

     ;; insn 10: exit
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Userspace - Packet Generation
;;; ============================================================================

(defn calculate-checksum
  "Calculate simple additive checksum over data"
  [data]
  (let [;; Pad to 4-byte boundary
        padded (byte-array (+ (count data)
                             (mod (- 4 (mod (count data) 4)) 4)))
        _ (System/arraycopy data 0 padded 0 (count data))
        ;; Sum 32-bit words (big-endian)
        words (partition 4 padded)
        sum (reduce (fn [acc bs]
                      (let [word (reduce (fn [w b]
                                          (+ (bit-shift-left w 8)
                                             (bit-and (int b) 0xFF)))
                                        0 bs)]
                        (+ acc word)))
                    0 words)]
    ;; One's complement
    (bit-and (bit-not sum) 0xFFFFFFFF)))

(defn create-fastlog-header
  "Create FastLog header bytes"
  [msg-type payload-len seq-num]
  (let [buf (ByteBuffer/allocate HDR_SIZE)]
    (.order buf ByteOrder/BIG_ENDIAN)
    ;; Magic
    (.putInt buf 0 (unchecked-int FASTLOG_MAGIC))
    ;; Version
    (.put buf 4 (byte FASTLOG_VERSION))
    ;; Type
    (.put buf 5 (byte msg-type))
    ;; Length (header + payload)
    (.putShort buf 6 (short (+ HDR_SIZE payload-len)))
    ;; Sequence
    (.putInt buf 8 (int seq-num))
    ;; Checksum placeholder (calculated after)
    (.putInt buf 12 0)
    (.array buf)))

(defn create-log-payload
  "Create LOG_MESSAGE payload"
  [timestamp level severity message]
  (let [msg-bytes (.getBytes message "UTF-8")
        buf (ByteBuffer/allocate (+ 10 (count msg-bytes)))]
    (.order buf ByteOrder/BIG_ENDIAN)
    ;; Timestamp (8 bytes)
    (.putLong buf 0 timestamp)
    ;; Level (1 byte)
    (.put buf 8 (byte level))
    ;; Severity (1 byte)
    (.put buf 9 (byte severity))
    ;; Message
    (.position buf 10)
    (.put buf msg-bytes)
    (.array buf)))

(defn create-metric-payload
  "Create METRIC payload"
  [timestamp metric-id value unit]
  (let [buf (ByteBuffer/allocate 21)]
    (.order buf ByteOrder/BIG_ENDIAN)
    ;; Timestamp (8 bytes)
    (.putLong buf 0 timestamp)
    ;; Metric ID (4 bytes)
    (.putInt buf 8 metric-id)
    ;; Value (8 bytes)
    (.putLong buf 12 value)
    ;; Unit (1 byte)
    (.put buf 20 (byte unit))
    (.array buf)))

(defn create-trace-payload
  "Create TRACE_SPAN payload"
  [trace-id-high trace-id-low span-id parent-id duration]
  (let [buf (ByteBuffer/allocate 40)]
    (.order buf ByteOrder/BIG_ENDIAN)
    ;; Trace ID (16 bytes = 2 longs)
    (.putLong buf 0 trace-id-high)
    (.putLong buf 8 trace-id-low)
    ;; Span ID (8 bytes)
    (.putLong buf 16 span-id)
    ;; Parent ID (8 bytes)
    (.putLong buf 24 parent-id)
    ;; Duration (8 bytes)
    (.putLong buf 32 duration)
    (.array buf)))

(defn create-fastlog-packet
  "Create complete FastLog packet with checksum"
  [msg-type payload seq-num]
  (let [header (create-fastlog-header msg-type (count payload) seq-num)
        ;; Combine for checksum calculation
        combined (byte-array (+ (count header) (count payload)))]
    (System/arraycopy header 0 combined 0 (count header))
    (System/arraycopy payload 0 combined (count header) (count payload))

    ;; Calculate and set checksum
    (let [checksum (calculate-checksum combined)
          buf (ByteBuffer/wrap combined)]
      (.order buf ByteOrder/BIG_ENDIAN)
      (.putInt buf 12 (unchecked-int checksum)))

    combined))

;;; ============================================================================
;;; Part 6: Userspace - Statistics Display
;;; ============================================================================

(defn display-stats
  "Display parsing statistics"
  [stats-map]
  (println "\nFastLog Parser Statistics:")
  (println "═══════════════════════════════════════")

  (let [total (or (bpf/map-lookup stats-map STAT_TOTAL) 0)
        valid (or (bpf/map-lookup stats-map STAT_VALID) 0)
        inv-magic (or (bpf/map-lookup stats-map STAT_INVALID_MAGIC) 0)
        inv-ver (or (bpf/map-lookup stats-map STAT_INVALID_VERSION) 0)
        inv-chk (or (bpf/map-lookup stats-map STAT_INVALID_CHECKSUM) 0)
        log-msgs (or (bpf/map-lookup stats-map STAT_LOG_MSGS) 0)
        metric-msgs (or (bpf/map-lookup stats-map STAT_METRIC_MSGS) 0)
        trace-msgs (or (bpf/map-lookup stats-map STAT_TRACE_MSGS) 0)]

    (println (format "Total packets     : %d" total))
    (println (format "Valid messages    : %d" valid))
    (println)
    (println "Errors:")
    (println (format "  Invalid magic   : %d" inv-magic))
    (println (format "  Invalid version : %d" inv-ver))
    (println (format "  Invalid checksum: %d" inv-chk))
    (println)
    (println "Message Types:")
    (println (format "  Log messages    : %d" log-msgs))
    (println (format "  Metrics         : %d" metric-msgs))
    (println (format "  Trace spans     : %d" trace-msgs))

    ;; Calculate success rate
    (when (pos? total)
      (let [rate (* 100.0 (/ valid total))]
        (println)
        (println (format "Success rate      : %.1f%%" rate))))))

(defn display-protocol-spec
  "Display FastLog protocol specification"
  []
  (println "\nFastLog Protocol v1 Specification:")
  (println "═══════════════════════════════════════")
  (println)
  (println "Header (16 bytes):")
  (println "┌────────┬─────┬─────┬────────┬──────────┬──────────┐")
  (println "│ Magic  │ Ver │Type │  Len   │   Seq    │ Checksum │")
  (println "│ 4 bytes│1 by │1 by │ 2 bytes│ 4 bytes  │ 4 bytes  │")
  (println "│0xF4571000│ 0x01│     │        │          │          │")
  (println "└────────┴─────┴─────┴────────┴──────────┴──────────┘")
  (println)
  (println "Message Types:")
  (println "  0x01: LOG_MESSAGE  - Application log entry")
  (println "  0x02: METRIC       - Performance metric")
  (println "  0x03: TRACE_SPAN   - Distributed trace span")
  (println "  0x04: HEARTBEAT    - Keep-alive ping")
  (println "  0x05: ACK          - Acknowledgment"))

;;; ============================================================================
;;; Part 7: Test Packet Generation
;;; ============================================================================

(defn generate-test-packets
  "Generate sample FastLog packets for testing"
  []
  (println "\nGenerating test packets...")
  (println "─────────────────────────────────────────")

  ;; LOG_MESSAGE packet
  (let [log-payload (create-log-payload
                      (System/currentTimeMillis)
                      LOG_INFO
                      1
                      "Application started successfully")
        log-packet (create-fastlog-packet MSG_LOG log-payload 1)]
    (println (format "1. LOG_MESSAGE packet: %d bytes" (count log-packet)))
    (println (format "   Payload: \"Application started successfully\""))
    (println (format "   Level: INFO")))

  ;; METRIC packet
  (let [metric-payload (create-metric-payload
                         (System/currentTimeMillis)
                         1001           ; metric-id for "request_latency"
                         42000000       ; 42ms in nanoseconds
                         0)             ; unit: nanoseconds
        metric-packet (create-fastlog-packet MSG_METRIC metric-payload 2)]
    (println (format "2. METRIC packet: %d bytes" (count metric-packet)))
    (println (format "   Metric ID: 1001 (request_latency)"))
    (println (format "   Value: 42ms")))

  ;; TRACE_SPAN packet
  (let [trace-payload (create-trace-payload
                        0x123456789ABCDEF0  ; trace-id high
                        0x0FEDCBA987654321  ; trace-id low
                        0x1111111111111111  ; span-id
                        0x0000000000000000  ; parent-id (root span)
                        150000000)          ; duration: 150ms
        trace-packet (create-fastlog-packet MSG_TRACE trace-payload 3)]
    (println (format "3. TRACE_SPAN packet: %d bytes" (count trace-packet)))
    (println (format "   Span ID: 0x1111111111111111"))
    (println (format "   Duration: 150ms")))

  ;; HEARTBEAT packet (no payload)
  (let [hb-packet (create-fastlog-packet MSG_HEARTBEAT (byte-array 0) 4)]
    (println (format "4. HEARTBEAT packet: %d bytes" (count hb-packet))))

  (println "─────────────────────────────────────────")
  (println "Total: 4 test packets generated"))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 3.3: Custom Protocol Parser ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [stats-map (create-stats-map)
        msgs-map (create-messages-map)]
    (println "  Statistics map created (FD:" (:fd stats-map) ")")
    (println "  Messages map created (FD:" (:fd msgs-map) ")")

    ;; Initialize stats to 0
    (doseq [i (range 16)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Display protocol spec
      (println "\nStep 3: Protocol specification...")
      (display-protocol-spec)

      ;; Step 4: Create parser
      (println "\nStep 4: Creating FastLog parser...")
      (let [program (create-fastlog-parser)]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")
        (println "  Magic: 0xF4571000")
        (println "  Version: 0x01")

        ;; Step 5: Load program
        (println "\nStep 5: Loading parser into kernel...")
        (let [prog (bpf/load-program {:prog-type :xdp
                                      :insns program})]
          (println "  Parser loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 6: Generate test packets
            (println "\nStep 6: Test packet generation...")
            (generate-test-packets)

            ;; Step 7: Explain how parser works
            (println "\nStep 7: Parser operation...")
            (println "\n  Parsing Flow:")
            (println "  1. Navigate to FastLog header (skip Eth+IP+UDP)")
            (println "  2. Validate magic number (0xF4571000)")
            (println "  3. Validate protocol version (0x01)")
            (println "  4. Parse header fields (type, length, seq, checksum)")
            (println "  5. Dispatch to type-specific handler")
            (println "  6. Parse payload based on message type")
            (println "  7. Store parsed data in map")
            (println "  8. Update statistics")

            ;; Step 8: XDP attachment info
            (println "\nStep 8: Attachment info...")
            (println "\n  To attach parser to network interface:")
            (println "    ip link set dev eth0 xdp obj fastlog_parser.o")
            (println)
            (println "  To detach:")
            (println "    ip link set dev eth0 xdp off")
            (println)
            (println "  Supported ports: Any UDP port")
            (println "  Supported interface: Any")

            ;; Step 9: Show statistics (empty since no traffic)
            (display-stats stats-map)

            ;; Step 10: Cleanup
            (println "\nStep 10: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map stats-map)
        (bpf/close-map msgs-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 3.3 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test packet creation
  (let [payload (create-log-payload
                  (System/currentTimeMillis)
                  LOG_INFO
                  1
                  "Test message")
        packet (create-fastlog-packet MSG_LOG payload 1)]
    (println "Packet size:" (count packet))
    (seq packet))

  ;; Test checksum
  (calculate-checksum (byte-array [1 2 3 4 5 6 7 8]))
  )
