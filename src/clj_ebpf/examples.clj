(ns clj-ebpf.examples
  "Comprehensive examples demonstrating the clj-ebpf DSL for BPF programming.

  These examples showcase various BPF program types and common patterns:
  - XDP (eXpress Data Path) programs for high-performance packet filtering
  - TC (Traffic Control) programs for packet classification
  - Packet parsing (Ethernet, IP, TCP/UDP headers)
  - BPF map operations (lookup, update, delete)
  - Tracing and debugging with helper functions
  - Statistics and counters

  Each example is documented with its purpose, expected behavior, and
  the BPF concepts it demonstrates."
  (:require [clj-ebpf.core :as bpf]))

;;; =============================================================================
;;; BASIC XDP EXAMPLES
;;; =============================================================================

(defn xdp-pass-all
  "The simplest possible XDP program - passes all packets.

  Returns: XDP_PASS for all packets
  Use case: Testing XDP attachment without filtering"
  []
  (bpf/assemble [(bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)]))

(defn xdp-drop-all
  "Drops all incoming packets at the driver level.

  Returns: XDP_DROP for all packets
  Use case: Emergency packet drop, DDoS mitigation baseline"
  []
  (bpf/assemble [(bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)]))

(defn xdp-packet-size-filter
  "Filters packets based on size - drops small packets, passes large ones.

  Algorithm:
  1. Load ctx->data_end into r2
  2. Load ctx->data into r3
  3. Calculate packet size: r2 = r2 - r3
  4. If size > 60 bytes: jump to pass label
  5. Otherwise: return XDP_DROP
  6. Pass label: return XDP_PASS

  Returns: XDP_PASS for packets > 60 bytes, XDP_DROP otherwise
  Use case: Filter out small/malformed packets"
  []
  (bpf/assemble [;; r2 = ctx->data_end (offset 4 in xdp_md struct)
                 (bpf/ldx :w :r2 :r1 4)
                 ;; r3 = ctx->data (offset 0 in xdp_md struct)
                 (bpf/ldx :w :r3 :r1 0)
                 ;; r2 = data_end - data (packet size)
                 (bpf/sub-reg :r2 :r3)
                 ;; if r2 > 60 goto +1 (pass)
                 (bpf/jmp-imm :jgt :r2 60 1)
                 ;; Drop path
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)
                 ;; Pass path (label reached by jump)
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)]))

(defn xdp-aborted-on-error
  "Returns XDP_ABORTED to signal an error condition.

  Returns: XDP_ABORTED (signals error to kernel)
  Use case: Error handling, debugging malformed packets"
  []
  (bpf/assemble [(bpf/mov :r0 (:aborted bpf/xdp-action))
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; ETHERNET HEADER PARSING
;;; =============================================================================

(defn xdp-ethernet-parser
  "Parses Ethernet header and validates packet has enough data.

  Ethernet header layout (14 bytes):
  - Destination MAC: 6 bytes (offset 0)
  - Source MAC: 6 bytes (offset 6)
  - EtherType: 2 bytes (offset 12)

  Algorithm:
  1. Load data and data_end pointers from context
  2. Calculate packet end: data + 14 (Ethernet header size)
  3. Check if packet end > data_end (bounds check)
  4. If too short: return XDP_DROP
  5. Otherwise: return XDP_PASS

  Returns: XDP_PASS if packet has complete Ethernet header, XDP_DROP otherwise
  Use case: Validate packet has minimum size before further processing"
  []
  (bpf/assemble [;; r2 = ctx->data
                 (bpf/ldx :w :r2 :r1 0)
                 ;; r3 = ctx->data_end
                 (bpf/ldx :w :r3 :r1 4)
                 ;; r4 = r2 + 14 (Ethernet header size)
                 (bpf/mov-reg :r4 :r2)
                 (bpf/add :r4 14)
                 ;; if r4 > r3 goto drop (not enough data)
                 (bpf/jmp-reg :jgt :r4 :r3 1)
                 ;; Pass path
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)
                 ;; Drop path
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)]))

(defn xdp-ethertype-filter
  "Filters packets based on EtherType field (IPv4 only).

  EtherType values:
  - 0x0800 (2048): IPv4
  - 0x86DD: IPv6
  - 0x0806: ARP

  Algorithm:
  1. Validate packet has Ethernet header (bounds check)
  2. Load EtherType from offset 12 (as big-endian u16)
  3. Check if EtherType == 0x0800 (IPv4)
  4. If IPv4: return XDP_PASS
  5. Otherwise: return XDP_DROP

  Returns: XDP_PASS for IPv4 packets, XDP_DROP otherwise
  Use case: Filter to only process IPv4 traffic"
  []
  (bpf/assemble [;; r2 = ctx->data
                 (bpf/ldx :w :r2 :r1 0)
                 ;; r3 = ctx->data_end
                 (bpf/ldx :w :r3 :r1 4)
                 ;; r4 = r2 + 14 (check Ethernet header bounds)
                 (bpf/mov-reg :r4 :r2)
                 (bpf/add :r4 14)
                 ;; if r4 > r3 goto drop
                 (bpf/jmp-reg :jgt :r4 :r3 5)
                 ;; r4 = *(u16 *)(r2 + 12) - Load EtherType
                 (bpf/ldx :h :r4 :r2 12)
                 ;; Convert from network byte order (big-endian) to host (little-endian on x86)
                 (bpf/end-to-le :r4 16)
                 ;; if r4 == 0x0800 (IPv4) goto pass
                 (bpf/jmp-imm :jeq :r4 0x0800 1)
                 ;; Drop path
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)
                 ;; Pass path
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; IP HEADER PARSING
;;; =============================================================================

(defn xdp-ipv4-parser
  "Parses IPv4 header and validates packet structure.

  IPv4 header layout (minimum 20 bytes):
  - Version + IHL: 1 byte (offset 14)
  - Type of Service: 1 byte
  - Total Length: 2 bytes
  - ... (20 bytes total minimum)

  Algorithm:
  1. Validate Ethernet header exists (14 bytes)
  2. Calculate IP header end: data + 14 + 20
  3. Bounds check: ensure packet has complete IP header
  4. Validate IP version (first 4 bits should be 4)

  Returns: XDP_PASS if valid IPv4 packet, XDP_DROP otherwise
  Use case: Validate IPv4 packet structure before further processing"
  []
  (bpf/assemble [;; r2 = ctx->data
                 (bpf/ldx :w :r2 :r1 0)
                 ;; r3 = ctx->data_end
                 (bpf/ldx :w :r3 :r1 4)
                 ;; r4 = r2 + 14 + 20 (Ethernet + minimum IP header)
                 (bpf/mov-reg :r4 :r2)
                 (bpf/add :r4 34)
                 ;; if r4 > r3 goto drop (not enough data)
                 (bpf/jmp-reg :jgt :r4 :r3 6)
                 ;; r4 = *(u8 *)(r2 + 14) - Load version+IHL byte
                 (bpf/ldx :b :r4 :r2 14)
                 ;; r4 = r4 >> 4 (extract version bits)
                 (bpf/rsh :r4 4)
                 ;; if r4 == 4 goto pass (valid IPv4)
                 (bpf/jmp-imm :jeq :r4 4 1)
                 ;; Drop path
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)
                 ;; Pass path
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)]))

(defn xdp-ip-protocol-filter
  "Filters packets based on IP protocol field (TCP only).

  IP Protocol numbers:
  - 6: TCP
  - 17: UDP
  - 1: ICMP

  Protocol field offset: Ethernet (14) + IP header offset 9 = 23 bytes

  Algorithm:
  1. Validate Ethernet + IP headers exist
  2. Load protocol field from IP header (offset 9 in IP header)
  3. Check if protocol == 6 (TCP)
  4. If TCP: return XDP_PASS
  5. Otherwise: return XDP_DROP

  Returns: XDP_PASS for TCP packets, XDP_DROP otherwise
  Use case: Filter to only process TCP traffic"
  []
  (bpf/assemble [;; r2 = ctx->data
                 (bpf/ldx :w :r2 :r1 0)
                 ;; r3 = ctx->data_end
                 (bpf/ldx :w :r3 :r1 4)
                 ;; r4 = r2 + 34 (Ethernet + IP minimum)
                 (bpf/mov-reg :r4 :r2)
                 (bpf/add :r4 34)
                 ;; Bounds check
                 (bpf/jmp-reg :jgt :r4 :r3 5)
                 ;; r4 = *(u8 *)(r2 + 23) - Load protocol field
                 (bpf/ldx :b :r4 :r2 23)
                 ;; if r4 == 6 (TCP) goto pass
                 (bpf/jmp-imm :jeq :r4 6 1)
                 ;; Drop path
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)
                 ;; Pass path
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; TCP/UDP PORT FILTERING
;;; =============================================================================

(defn xdp-tcp-port-filter
  "Filters TCP packets based on destination port (port 80/HTTP only).

  TCP header layout (minimum 20 bytes, starts after IP header):
  - Source port: 2 bytes (offset 0)
  - Dest port: 2 bytes (offset 2)
  - Sequence number: 4 bytes
  - ...

  Offset calculation:
  - Ethernet: 14 bytes
  - IP header: 20 bytes (minimum, IHL=5)
  - TCP dest port: +2 bytes
  - Total: 36 bytes to dest port

  Algorithm:
  1. Validate packet has Ethernet + IP + TCP header start
  2. Load destination port (offset 36, assuming IHL=5)
  3. Convert from network byte order
  4. Check if port == 80 (HTTP)

  Returns: XDP_PASS for HTTP traffic (port 80), XDP_DROP otherwise
  Use case: Filter HTTP traffic for inspection"
  []
  (bpf/assemble [;; r2 = ctx->data
                 (bpf/ldx :w :r2 :r1 0)
                 ;; r3 = ctx->data_end
                 (bpf/ldx :w :r3 :r1 4)
                 ;; r4 = r2 + 38 (Ethernet + IP + TCP dest port)
                 (bpf/mov-reg :r4 :r2)
                 (bpf/add :r4 38)
                 ;; Bounds check
                 (bpf/jmp-reg :jgt :r4 :r3 6)
                 ;; r4 = *(u16 *)(r2 + 36) - Load dest port
                 (bpf/ldx :h :r4 :r2 36)
                 ;; Convert from network byte order (big-endian) to host (little-endian on x86)
                 (bpf/end-to-le :r4 16)
                 ;; if r4 == 80 goto pass
                 (bpf/jmp-imm :jeq :r4 80 1)
                 ;; Drop path
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)
                 ;; Pass path
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)]))

(defn xdp-udp-port-range-filter
  "Filters UDP packets based on destination port range (1024-2048).

  UDP header layout (8 bytes):
  - Source port: 2 bytes (offset 0)
  - Dest port: 2 bytes (offset 2)
  - Length: 2 bytes
  - Checksum: 2 bytes

  Algorithm:
  1. Validate packet has Ethernet + IP + UDP headers
  2. Load destination port from UDP header
  3. Check if port >= 1024 AND port <= 2048
  4. Use two jump instructions for range check

  Returns: XDP_PASS for UDP ports 1024-2048, XDP_DROP otherwise
  Use case: Filter UDP traffic in specific port range"
  []
  (bpf/assemble [;; r2 = ctx->data
                 (bpf/ldx :w :r2 :r1 0)
                 ;; r3 = ctx->data_end
                 (bpf/ldx :w :r3 :r1 4)
                 ;; r4 = r2 + 38 (Ethernet + IP + UDP dest port)
                 (bpf/mov-reg :r4 :r2)
                 (bpf/add :r4 38)
                 ;; Bounds check
                 (bpf/jmp-reg :jgt :r4 :r3 8)
                 ;; r4 = *(u16 *)(r2 + 36) - Load dest port
                 (bpf/ldx :h :r4 :r2 36)
                 ;; Convert from network byte order (big-endian) to host (little-endian on x86)
                 (bpf/end-to-le :r4 16)
                 ;; if r4 < 1024 goto drop
                 (bpf/jmp-imm :jlt :r4 1024 3)
                 ;; if r4 > 2048 goto drop
                 (bpf/jmp-imm :jgt :r4 2048 2)
                 ;; Pass path (port in range)
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)
                 ;; Drop path
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; BPF MAP OPERATIONS
;;; =============================================================================

(defn xdp-map-lookup-example
  "Demonstrates BPF map lookup operation.

  This example shows how to:
  1. Set up a key in a register
  2. Load map FD (would be patched in by loader)
  3. Call bpf_map_lookup_elem helper
  4. Check return value (NULL or pointer to value)
  5. Handle success/failure paths

  Note: Map FD at offset 0 would be replaced by the BPF loader
  with the actual map file descriptor.

  Returns: XDP_PASS if key found in map, XDP_DROP otherwise
  Use case: Demonstrate map lookup pattern for allowlist/blocklist"
  []
  (bpf/assemble [;; Set up stack space for key (4 bytes)
                 ;; r1 = r10 (frame pointer)
                 (bpf/mov-reg :r1 :r10)
                 ;; r1 = r1 - 4 (allocate stack space)
                 (bpf/add :r1 -4)
                 ;; Store key value on stack: *(u32 *)r1 = 42
                 (bpf/st :w :r1 0 42)

                 ;; Prepare for map lookup
                 ;; r2 = r1 (key pointer, already set)
                 (bpf/mov-reg :r2 :r1)
                 ;; r1 = map_fd (loaded as 64-bit immediate)
                 ;; This would be patched by the loader
                 (bpf/lddw :r1 0)

                 ;; Call bpf_map_lookup_elem(map_fd, key)
                 (bpf/call (:map-lookup-elem bpf/bpf-helpers))

                 ;; r0 now contains pointer to value or NULL
                 ;; if r0 == 0 goto drop (key not found)
                 (bpf/jmp-imm :jeq :r0 0 1)
                 ;; Pass path (key found)
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)
                 ;; Drop path (key not found)
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)]))

(defn xdp-map-update-counter
  "Demonstrates BPF map update to increment a counter.

  This example shows how to:
  1. Look up current counter value in map
  2. If found: load value, increment, update map
  3. If not found: initialize counter to 1

  Note: This is a simplified example. Real implementation would need
  atomic operations for thread safety.

  Returns: XDP_PASS (always)
  Use case: Packet counting, statistics collection"
  []
  (bpf/assemble [;; Set up key on stack (key = 0 for global counter)
                 (bpf/mov-reg :r6 :r10)  ; r6 = frame pointer (save for later)
                 (bpf/add :r6 -8)         ; r6 points to stack space
                 (bpf/st :w :r6 0 0)      ; key = 0

                 ;; Look up current value
                 (bpf/mov-reg :r2 :r6)    ; r2 = key pointer
                 (bpf/lddw :r1 0)         ; r1 = map_fd (would be patched)
                 (bpf/call (:map-lookup-elem bpf/bpf-helpers))

                 ;; if r0 != 0 goto increment (value exists)
                 (bpf/jmp-imm :jne :r0 0 6)

                 ;; Initialize path: value doesn't exist, create with value 1
                 (bpf/st :dw :r6 -8 1)    ; Store initial value = 1
                 (bpf/mov-reg :r2 :r6)    ; r2 = key
                 (bpf/mov-reg :r3 :r6)    ; r3 = value pointer
                 (bpf/add :r3 -8)
                 (bpf/lddw :r1 0)         ; r1 = map_fd
                 (bpf/mov :r4 0)          ; r4 = flags (BPF_ANY)
                 (bpf/call (:map-update-elem bpf/bpf-helpers))
                 (bpf/ja 4)               ; Jump to return

                 ;; Increment path: value exists
                 ;; r7 = r0 (save value pointer)
                 (bpf/mov-reg :r7 :r0)
                 ;; r1 = *(u64 *)r7 (load current value)
                 (bpf/ldx :dw :r1 :r7 0)
                 ;; r1 = r1 + 1 (increment)
                 (bpf/add :r1 1)
                 ;; *(u64 *)r7 = r1 (store back)
                 (bpf/stx :dw :r7 :r1 0)

                 ;; Return XDP_PASS
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; TRAFFIC CONTROL (TC) EXAMPLES
;;; =============================================================================

(defn tc-ok-all
  "Simplest TC program - allows all packets.

  Returns: TC_ACT_OK for all packets
  Use case: Testing TC attachment without filtering"
  []
  (bpf/assemble [(bpf/mov :r0 (:ok bpf/tc-action))
                 (bpf/exit-insn)]))

(defn tc-shot-all
  "Drops all packets at TC layer.

  Returns: TC_ACT_SHOT for all packets
  Use case: TC-level packet drop for testing"
  []
  (bpf/assemble [(bpf/mov :r0 (:shot bpf/tc-action))
                 (bpf/exit-insn)]))

(defn tc-packet-classifier
  "Classifies packets based on size with different TC actions.

  Classification logic:
  - Packets < 64 bytes: TC_ACT_SHOT (drop)
  - Packets 64-1500 bytes: TC_ACT_OK (pass)
  - Packets > 1500 bytes: TC_ACT_PIPE (continue to next qdisc)

  Returns: Different TC actions based on packet size
  Use case: QoS, traffic classification"
  []
  (bpf/assemble [;; r2 = skb->data_end
                 (bpf/ldx :w :r2 :r1 4)
                 ;; r3 = skb->data
                 (bpf/ldx :w :r3 :r1 0)
                 ;; r2 = packet size
                 (bpf/sub-reg :r2 :r3)

                 ;; if size < 64 goto drop
                 (bpf/jmp-imm :jlt :r2 64 5)
                 ;; if size > 1500 goto pipe
                 (bpf/jmp-imm :jgt :r2 1500 4)

                 ;; Normal size path: TC_ACT_OK
                 (bpf/mov :r0 (:ok bpf/tc-action))
                 (bpf/exit-insn)

                 ;; Drop small packets: TC_ACT_SHOT
                 (bpf/mov :r0 (:shot bpf/tc-action))
                 (bpf/exit-insn)

                 ;; Large packets: TC_ACT_PIPE
                 (bpf/mov :r0 (:pipe bpf/tc-action))
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; TRACING AND DEBUGGING EXAMPLES
;;; =============================================================================

(defn kprobe-with-trace-printk
  "Demonstrates using bpf_trace_printk for debugging.

  This example shows how to call bpf_trace_printk helper to log
  messages to the kernel trace buffer (/sys/kernel/debug/tracing/trace).

  Note: The actual format string and arguments would need to be
  set up on the stack in a real implementation. This is a simplified
  version showing the call pattern.

  Returns: 0 (success)
  Use case: Debugging BPF programs, logging events"
  []
  (bpf/assemble [;; Set up format string pointer on stack
                 ;; In real implementation, would copy string to stack
                 ;; r1 = format string pointer (simplified)
                 (bpf/mov-reg :r1 :r10)
                 (bpf/add :r1 -16)

                 ;; r2 = size of format string
                 (bpf/mov :r2 16)

                 ;; Call bpf_trace_printk(fmt, size)
                 (bpf/call (:trace-printk bpf/bpf-helpers))

                 ;; Return 0
                 (bpf/mov :r0 0)
                 (bpf/exit-insn)]))

(defn kprobe-timestamp-logger
  "Logs timestamp using bpf_ktime_get_ns helper.

  Demonstrates:
  1. Calling bpf_ktime_get_ns to get current kernel time
  2. Storing result for further processing

  Returns: 0 (success)
  Use case: Performance monitoring, latency measurement"
  []
  (bpf/assemble [;; Call bpf_ktime_get_ns()
                 (bpf/call (:ktime-get-ns bpf/bpf-helpers))

                 ;; r0 now contains timestamp in nanoseconds
                 ;; Save to r6 (callee-saved register)
                 (bpf/mov-reg :r6 :r0)

                 ;; Could now use r6 for timing calculations,
                 ;; store in map, etc.

                 ;; Return 0
                 (bpf/mov :r0 0)
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; ARITHMETIC AND BITWISE OPERATIONS
;;; =============================================================================

(defn arithmetic-operations-demo
  "Demonstrates various arithmetic operations.

  Shows: ADD, SUB, MUL, DIV, MOD operations

  Computes: ((10 + 5) * 2 - 3) / 4 = 27 / 4 = 6 (integer division)

  Returns: 6
  Use case: Educational example of ALU operations"
  []
  (bpf/assemble [;; r1 = 10
                 (bpf/mov :r1 10)
                 ;; r1 = r1 + 5 = 15
                 (bpf/add :r1 5)
                 ;; r1 = r1 * 2 = 30
                 (bpf/mul :r1 2)
                 ;; r1 = r1 - 3 = 27
                 (bpf/sub :r1 3)
                 ;; r1 = r1 / 4 = 6
                 (bpf/div :r1 4)
                 ;; r0 = r1 (return value)
                 (bpf/mov-reg :r0 :r1)
                 (bpf/exit-insn)]))

(defn bitwise-operations-demo
  "Demonstrates bitwise operations.

  Shows: AND, OR, XOR, LSH (left shift), RSH (right shift)

  Computes bitmask operations:
  - Start with 0xFF (255)
  - AND with 0xF0 = 0xF0 (240)
  - OR with 0x05 = 0xF5 (245)
  - XOR with 0xAA = 0x5F (95)
  - LSH by 1 = 0xBE (190)
  - RSH by 2 = 0x2F (47)

  Returns: 47
  Use case: Bit manipulation, flag handling"
  []
  (bpf/assemble [;; r1 = 0xFF
                 (bpf/mov :r1 0xFF)
                 ;; r1 = r1 & 0xF0
                 (bpf/and-op :r1 0xF0)
                 ;; r1 = r1 | 0x05
                 (bpf/or-op :r1 0x05)
                 ;; r1 = r1 ^ 0xAA
                 (bpf/xor-op :r1 0xAA)
                 ;; r1 = r1 << 1
                 (bpf/lsh :r1 1)
                 ;; r1 = r1 >> 2
                 (bpf/rsh :r1 2)
                 ;; r0 = r1
                 (bpf/mov-reg :r0 :r1)
                 (bpf/exit-insn)]))

(defn conditional-logic-demo
  "Demonstrates conditional logic with jumps.

  Implements: if (x > 10) return 1; else return 0;

  Shows:
  - Conditional jumps (JGT)
  - Branch handling
  - Labels (implicit via jump offsets)

  Returns: 1 if input > 10, else 0
  Use case: Decision making, filtering logic"
  []
  (bpf/assemble [;; r1 = 15 (test value)
                 (bpf/mov :r1 15)
                 ;; if r1 > 10 goto true_path
                 (bpf/jmp-imm :jgt :r1 10 2)
                 ;; False path
                 (bpf/mov :r0 0)
                 (bpf/exit-insn)
                 ;; True path (offset +2 from jump)
                 (bpf/mov :r0 1)
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; COMPLEX REAL-WORLD EXAMPLES
;;; =============================================================================

(defn xdp-syn-flood-protection
  "Simple SYN flood protection using packet rate limiting.

  This simplified example demonstrates the pattern for SYN flood protection:
  1. Parse packet to ensure it's TCP
  2. Check TCP flags for SYN
  3. Look up connection state in map
  4. Apply rate limiting logic

  Note: This is a simplified educational example. Real SYN flood protection
  would require:
  - Proper TCP flag parsing
  - Per-source-IP rate limiting
  - Connection tracking
  - More sophisticated map operations

  Returns: XDP_DROP for suspicious traffic, XDP_PASS otherwise
  Use case: DDoS mitigation, SYN flood protection"
  []
  (bpf/assemble [;; Validate packet has Ethernet + IP + TCP
                 (bpf/ldx :w :r2 :r1 0)   ; r2 = data
                 (bpf/ldx :w :r3 :r1 4)   ; r3 = data_end
                 (bpf/mov-reg :r4 :r2)
                 (bpf/add :r4 54)          ; Eth + IP + TCP minimum
                 (bpf/jmp-reg :jgt :r4 :r3 2) ; Bounds check

                 ;; For now, simple pass (full implementation would
                 ;; parse TCP flags, check SYN, lookup in map, etc.)
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)

                 ;; Drop path (insufficient data)
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)]))

(defn xdp-icmp-rate-limiter
  "Rate limits ICMP packets to prevent ICMP flood attacks.

  Pattern:
  1. Validate packet is ICMP (IP protocol = 1)
  2. Look up ICMP counter in map
  3. If counter exceeds threshold: drop
  4. Otherwise: increment counter and pass

  Note: Simplified example for educational purposes

  Returns: XDP_DROP if rate exceeded, XDP_PASS otherwise
  Use case: ICMP flood protection, rate limiting"
  []
  (bpf/assemble [;; Validate Ethernet + IP headers
                 (bpf/ldx :w :r2 :r1 0)
                 (bpf/ldx :w :r3 :r1 4)
                 (bpf/mov-reg :r4 :r2)
                 (bpf/add :r4 34)
                 (bpf/jmp-reg :jgt :r4 :r3 6)

                 ;; Check if protocol == ICMP (1)
                 (bpf/ldx :b :r4 :r2 23)  ; Load protocol field
                 (bpf/jmp-imm :jeq :r4 1 1) ; If ICMP, continue
                 ;; Not ICMP, pass through
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)

                 ;; ICMP packet - apply rate limiting
                 ;; (In real implementation, would check map counter)
                 ;; For now, just pass
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)

                 ;; Drop path (bounds check failed)
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)]))

(defn xdp-allowlist-filter
  "Implements IP allowlist using BPF map lookup.

  Algorithm:
  1. Parse packet to extract source IP address
  2. Use source IP as key to look up in allowlist map
  3. If found in map: XDP_PASS
  4. If not found: XDP_DROP

  IP source address offset: Ethernet (14) + IP src (12) = 26 bytes

  Returns: XDP_PASS if source IP in allowlist, XDP_DROP otherwise
  Use case: Access control, IP filtering"
  []
  (bpf/assemble [;; Validate Ethernet + IP headers
                 (bpf/ldx :w :r2 :r1 0)   ; r2 = data
                 (bpf/ldx :w :r3 :r1 4)   ; r3 = data_end
                 (bpf/mov-reg :r4 :r2)
                 (bpf/add :r4 34)          ; Minimum headers
                 (bpf/jmp-reg :jgt :r4 :r3 9) ; Bounds check

                 ;; Extract source IP and store on stack
                 (bpf/mov-reg :r6 :r10)   ; r6 = frame pointer
                 (bpf/add :r6 -4)          ; Stack space for IP
                 (bpf/ldx :w :r7 :r2 26)   ; Load source IP (offset 26)
                 (bpf/stx :w :r6 :r7 0)    ; Store on stack

                 ;; Look up IP in allowlist map
                 (bpf/mov-reg :r2 :r6)     ; r2 = key (IP address)
                 (bpf/lddw :r1 0)          ; r1 = map_fd (patched by loader)
                 (bpf/call (:map-lookup-elem bpf/bpf-helpers))

                 ;; if r0 != 0 goto pass (IP found in allowlist)
                 (bpf/jmp-imm :jne :r0 0 1)
                 ;; Drop path (IP not in allowlist)
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)
                 ;; Pass path (IP in allowlist)
                 (bpf/mov :r0 (:pass bpf/xdp-action))
                 (bpf/exit-insn)

                 ;; Drop path (bounds check failed)
                 (bpf/mov :r0 (:drop bpf/xdp-action))
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; HELPER FUNCTION DEMONSTRATIONS
;;; =============================================================================

(defn perf-event-output-demo
  "Demonstrates sending data to userspace via perf event buffer.

  Shows the pattern for:
  1. Setting up data structure on stack
  2. Calling bpf_perf_event_output to send to userspace

  Returns: 0 (success)
  Use case: Packet sampling, event logging to userspace"
  []
  (bpf/assemble [;; r6 = ctx (save for later)
                 (bpf/mov-reg :r6 :r1)

                 ;; Prepare arguments for perf_event_output
                 ;; r1 = ctx
                 (bpf/mov-reg :r1 :r6)
                 ;; r2 = map_fd (perf event array)
                 (bpf/lddw :r2 0)
                 ;; r3 = flags (BPF_F_CURRENT_CPU)
                 (bpf/lddw :r3 0xFFFFFFFF)
                 ;; r4 = data pointer (on stack)
                 (bpf/mov-reg :r4 :r10)
                 (bpf/add :r4 -16)
                 ;; r5 = data size
                 (bpf/mov :r5 16)

                 ;; Call bpf_perf_event_output
                 (bpf/call (:perf-event-output bpf/bpf-helpers))

                 ;; Return 0
                 (bpf/mov :r0 0)
                 (bpf/exit-insn)]))

(defn get-smp-processor-id-demo
  "Demonstrates getting current CPU ID.

  Returns: Current CPU ID
  Use case: Per-CPU statistics, load balancing"
  []
  (bpf/assemble [;; Call bpf_get_smp_processor_id()
                 (bpf/call (:get-smp-processor-id bpf/bpf-helpers))
                 ;; r0 now contains CPU ID
                 ;; Return it directly
                 (bpf/exit-insn)]))

;;; =============================================================================
;;; EXAMPLE LOOKUP TABLE
;;; =============================================================================

(def examples
  "Map of example names to their generator functions and descriptions."
  {;; Basic XDP
   :xdp-pass-all           {:fn xdp-pass-all
                            :description "Pass all packets (simplest XDP program)"}
   :xdp-drop-all           {:fn xdp-drop-all
                            :description "Drop all packets"}
   :xdp-packet-size-filter {:fn xdp-packet-size-filter
                            :description "Filter packets by size (>60 bytes)"}
   :xdp-aborted-on-error   {:fn xdp-aborted-on-error
                            :description "Return XDP_ABORTED"}

   ;; Ethernet parsing
   :xdp-ethernet-parser    {:fn xdp-ethernet-parser
                            :description "Parse and validate Ethernet header"}
   :xdp-ethertype-filter   {:fn xdp-ethertype-filter
                            :description "Filter IPv4 packets only"}

   ;; IP parsing
   :xdp-ipv4-parser        {:fn xdp-ipv4-parser
                            :description "Parse and validate IPv4 header"}
   :xdp-ip-protocol-filter {:fn xdp-ip-protocol-filter
                            :description "Filter TCP packets only"}

   ;; TCP/UDP filtering
   :xdp-tcp-port-filter    {:fn xdp-tcp-port-filter
                            :description "Filter HTTP traffic (port 80)"}
   :xdp-udp-port-range     {:fn xdp-udp-port-range-filter
                            :description "Filter UDP ports 1024-2048"}

   ;; Map operations
   :xdp-map-lookup         {:fn xdp-map-lookup-example
                            :description "Demonstrate map lookup"}
   :xdp-map-counter        {:fn xdp-map-update-counter
                            :description "Increment counter in map"}

   ;; TC examples
   :tc-ok-all              {:fn tc-ok-all
                            :description "TC program that allows all"}
   :tc-shot-all            {:fn tc-shot-all
                            :description "TC program that drops all"}
   :tc-classifier          {:fn tc-packet-classifier
                            :description "Classify packets by size"}

   ;; Tracing
   :kprobe-trace-printk    {:fn kprobe-with-trace-printk
                            :description "Use trace_printk for debugging"}
   :kprobe-timestamp       {:fn kprobe-timestamp-logger
                            :description "Log timestamps"}

   ;; Arithmetic/Bitwise
   :arithmetic-demo        {:fn arithmetic-operations-demo
                            :description "Demonstrate arithmetic operations"}
   :bitwise-demo           {:fn bitwise-operations-demo
                            :description "Demonstrate bitwise operations"}
   :conditional-demo       {:fn conditional-logic-demo
                            :description "Demonstrate conditional logic"}

   ;; Complex examples
   :syn-flood-protection   {:fn xdp-syn-flood-protection
                            :description "SYN flood protection pattern"}
   :icmp-rate-limiter      {:fn xdp-icmp-rate-limiter
                            :description "ICMP rate limiting"}
   :ip-allowlist           {:fn xdp-allowlist-filter
                            :description "IP allowlist filtering"}

   ;; Helper functions
   :perf-event-output      {:fn perf-event-output-demo
                            :description "Send data to userspace"}
   :get-cpu-id             {:fn get-smp-processor-id-demo
                            :description "Get current CPU ID"}})

(defn list-examples
  "List all available examples with descriptions."
  []
  (doseq [[name {:keys [description]}] (sort examples)]
    (println (format "%-25s - %s" (str name) description))))

(defn get-example
  "Get bytecode for a specific example by keyword name.

  Usage:
    (get-example :xdp-pass-all)
    (get-example :tcp-port-filter)"
  [example-name]
  (if-let [example-info (get examples example-name)]
    ((:fn example-info))
    (throw (ex-info (str "Unknown example: " example-name)
                    {:available-examples (keys examples)}))))

(defn -main
  "Print list of available examples."
  [& args]
  (println "Available BPF DSL Examples:")
  (println "===========================\n")
  (list-examples))
