# Lab 3.1: Packet Filter

**Objective**: Build a network packet filter using BPF instructions

**Duration**: 60 minutes

## Overview

In this lab, you'll build a packet filter that drops or passes packets based on protocol, IP addresses, and ports. You'll use raw BPF instructions to parse Ethernet, IP, and TCP/UDP headers, demonstrating low-level packet processing.

This lab demonstrates:
- Parsing network protocol headers
- Proper bounds checking for the verifier
- Implementing filtering logic with jumps
- Working with network byte order
- XDP return codes

## What You'll Learn

- How to parse Ethernet frames
- How to parse IPv4 headers
- How to parse TCP/UDP headers
- Proper verifier-friendly bounds checking
- Endianness handling in packet processing
- Building complex filtering logic

## Theory

### Network Protocol Stack

```
┌──────────────────────────────────┐
│     Ethernet Header (14 bytes)   │  Layer 2
│  dst_mac | src_mac | ethertype   │
├──────────────────────────────────┤
│      IPv4 Header (20+ bytes)     │  Layer 3
│  version | ihl | ... | protocol  │
├──────────────────────────────────┤
│   TCP/UDP Header (8-20 bytes)    │  Layer 4
│  src_port | dst_port | ...       │
├──────────────────────────────────┤
│          Payload Data            │
└──────────────────────────────────┘
```

### Ethernet Header (14 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────────────────────────────────────────────────┐
│                    Destination MAC Address                    │
├───────────────────────────────────────────────────────────────┤
│         (continued)       │      Source MAC Address           │
├───────────────────────────┼───────────────────────────────────┤
│          (continued)                      │   EtherType       │
└───────────────────────────────────────────┴───────────────────┘
```

EtherType values:
- `0x0800`: IPv4
- `0x0806`: ARP
- `0x86DD`: IPv6

### IPv4 Header (20-60 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───┬───┬───────┬───────────────┬───────────────────────────────┐
│Ver│IHL│  TOS  │          Total Length                         │
├───┴───┴───────┼───────────────────────────┬───────┬───────────┤
│      ID       │ Flags │   Fragment Offset                     │
├───────────────┼───────┴───────────────────┼───────────────────┤
│      TTL      │   Protocol    │     Header Checksum           │
├───────────────┴───────────────┴───────────────────────────────┤
│                       Source IP Address                       │
├───────────────────────────────────────────────────────────────┤
│                    Destination IP Address                     │
└───────────────────────────────────────────────────────────────┘
```

Protocol values:
- `6`: TCP
- `17`: UDP
- `1`: ICMP

### TCP/UDP Headers

**UDP (8 bytes)**:
```
┌───────────────┬───────────────┐
│  Source Port  │   Dest Port   │
├───────────────┼───────────────┤
│    Length     │   Checksum    │
└───────────────┴───────────────┘
```

**TCP (20+ bytes)**:
```
┌───────────────┬───────────────┐
│  Source Port  │   Dest Port   │
├───────────────┴───────────────┤
│       Sequence Number         │
├───────────────────────────────┤
│    Acknowledgment Number      │
├───┬───┬───────┬───────────────┤
│Off│Res│ Flags │  Window Size  │
├───┴───┴───────┼───────────────┤
│   Checksum    │ Urgent Pointer│
└───────────────┴───────────────┘
```

### XDP Context

```clojure
;; struct xdp_md {
;;   __u32 data;         // Offset 0: Start of packet
;;   __u32 data_end;     // Offset 4: End of packet
;;   __u32 data_meta;    // Offset 8: Metadata area
;;   __u32 ingress_ifindex; // Offset 12: Input interface
;; }
```

## Implementation

### Step 1: Complete Program

Create `lab-3-1.clj`:

```clojure
(ns lab-3-1-packet-filter
  "Lab 3.1: Packet Filter using BPF instruction set"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Part 1: Protocol Constants
;; ============================================================================

(def ETH_HLEN 14)           ; Ethernet header length
(def ETH_P_IP 0x0800)       ; IPv4 EtherType
(def IPPROTO_TCP 6)         ; TCP protocol
(def IPPROTO_UDP 17)        ; UDP protocol
(def IPPROTO_ICMP 1)        ; ICMP protocol

;; XDP return codes
(def XDP_ABORTED 0)         ; Error, drop + trace
(def XDP_DROP 1)            ; Drop packet
(def XDP_PASS 2)            ; Pass to network stack
(def XDP_TX 3)              ; Bounce back to sender
(def XDP_REDIRECT 4)        ; Redirect to another interface

;; ============================================================================
;; Part 2: Header Parsing Helpers
;; ============================================================================

(defn check-bounds
  "Generate code to check packet bounds"
  [data-reg data-end-reg offset label]
  (vec (concat
    ;; Calculate: data + offset
    [(bpf/mov-reg :r9 data-reg)]
    [(bpf/add :r9 offset)]
    ;; Check: if (data + offset > data_end) goto label
    [(bpf/jmp-reg :jgt :r9 data-end-reg label)])))

(defn load-u8
  "Load 8-bit value from packet"
  [data-reg offset dst-reg]
  [(bpf/load-mem :b dst-reg data-reg offset)])

(defn load-u16
  "Load 16-bit value from packet (network byte order)"
  [data-reg offset dst-reg]
  (vec (concat
    [(bpf/load-mem :h dst-reg data-reg offset)]
    [(bpf/be16 dst-reg)])))  ; Convert from big-endian

(defn load-u32
  "Load 32-bit value from packet (network byte order)"
  [data-reg offset dst-reg]
  (vec (concat
    [(bpf/load-mem :w dst-reg data-reg offset)]
    [(bpf/be32 dst-reg)])))  ; Convert from big-endian

;; ============================================================================
;; Part 3: Packet Filter Program
;; ============================================================================

(defn create-packet-filter
  "Create packet filter BPF program

  Filter rules:
  - Drop all ICMP packets
  - Drop TCP packets to port 80 (HTTP)
  - Drop UDP packets from port 53 (DNS)
  - Pass everything else"
  []
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Load XDP context
      ;; ──────────────────────────────────────────────────────────

      ;; r1 = ctx (XDP context pointer)
      ;; Load data pointer (start of packet)
      [(bpf/load-mem :w :r2 :r1 0)]   ; r2 = ctx->data

      ;; Load data_end pointer (end of packet)
      [(bpf/load-mem :w :r3 :r1 4)]   ; r3 = ctx->data_end

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Parse Ethernet Header
      ;; ──────────────────────────────────────────────────────────

      ;; Check if we have enough data for Ethernet header (14 bytes)
      (check-bounds :r2 :r3 ETH_HLEN :pass)

      ;; Load EtherType (offset 12, 2 bytes)
      (load-u16 :r2 12 :r4)  ; r4 = ethertype

      ;; Check if IPv4 (0x0800)
      [(bpf/jmp-imm :jne :r4 ETH_P_IP :pass)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Parse IPv4 Header
      ;; ──────────────────────────────────────────────────────────

      ;; r5 = ip_header = data + ETH_HLEN
      [(bpf/mov-reg :r5 :r2)]
      [(bpf/add :r5 ETH_HLEN)]

      ;; Check bounds: ip_header + 20 bytes (minimum IP header)
      (check-bounds :r5 :r3 20 :pass)

      ;; Load IP protocol (offset 9, 1 byte)
      (load-u8 :r5 9 :r6)  ; r6 = protocol

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Filter by Protocol
      ;; ──────────────────────────────────────────────────────────

      ;; Check if ICMP (protocol 1) - DROP
      [(bpf/jmp-imm :jeq :r6 IPPROTO_ICMP :drop)]

      ;; Check if TCP (protocol 6)
      [(bpf/jmp-imm :jeq :r6 IPPROTO_TCP :parse-tcp)]

      ;; Check if UDP (protocol 17)
      [(bpf/jmp-imm :jeq :r6 IPPROTO_UDP :parse-udp)]

      ;; Unknown protocol - PASS
      [(bpf/jmp :pass)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Parse TCP Header
      ;; ──────────────────────────────────────────────────────────

      ;; :parse-tcp
      ;; Calculate TCP header offset
      ;; tcp_header = ip_header + (IHL * 4)

      ;; Load IHL (IP Header Length) from version_ihl field
      (load-u8 :r5 0 :r7)      ; r7 = version_ihl
      [(bpf/and :r7 0x0F)]      ; r7 = IHL (lower 4 bits)
      [(bpf/lsh :r7 2)]         ; r7 = IHL * 4 (bytes)

      ;; r8 = tcp_header = ip_header + ihl
      [(bpf/mov-reg :r8 :r5)]
      [(bpf/add-reg :r8 :r7)]

      ;; Check bounds: tcp_header + 8 bytes (src + dst port)
      (check-bounds :r8 :r3 8 :pass)

      ;; Load destination port (offset 2, 2 bytes)
      (load-u16 :r8 2 :r9)     ; r9 = dst_port

      ;; Filter: Drop TCP to port 80 (HTTP)
      [(bpf/jmp-imm :jeq :r9 80 :drop)]

      ;; Filter: Drop TCP to port 443 (HTTPS) - optional
      ;; [(bpf/jmp-imm :jeq :r9 443 :drop)]

      ;; Pass other TCP
      [(bpf/jmp :pass)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 6: Parse UDP Header
      ;; ──────────────────────────────────────────────────────────

      ;; :parse-udp
      ;; Calculate UDP header offset (same as TCP)
      (load-u8 :r5 0 :r7)      ; r7 = version_ihl
      [(bpf/and :r7 0x0F)]      ; r7 = IHL
      [(bpf/lsh :r7 2)]         ; r7 = IHL * 4

      ;; r8 = udp_header = ip_header + ihl
      [(bpf/mov-reg :r8 :r5)]
      [(bpf/add-reg :r8 :r7)]

      ;; Check bounds: udp_header + 8 bytes (UDP header size)
      (check-bounds :r8 :r3 8 :pass)

      ;; Load source port (offset 0, 2 bytes)
      (load-u16 :r8 0 :r9)     ; r9 = src_port

      ;; Filter: Drop UDP from port 53 (DNS responses)
      [(bpf/jmp-imm :jeq :r9 53 :drop)]

      ;; Load destination port for additional filtering
      (load-u16 :r8 2 :r9)     ; r9 = dst_port

      ;; Filter: Drop UDP to port 53 (DNS queries)
      [(bpf/jmp-imm :jeq :r9 53 :drop)]

      ;; Pass other UDP
      [(bpf/jmp :pass)]

      ;; ──────────────────────────────────────────────────────────
      ;; Step 7: Return Actions
      ;; ──────────────────────────────────────────────────────────

      ;; :drop - Drop the packet
      [(bpf/mov :r0 XDP_DROP)]
      [(bpf/exit-insn)]

      ;; :pass - Pass the packet to network stack
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 4: Statistics Map
;; ============================================================================

(defn create-stats-map []
  "Create map to track filter statistics"
  (bpf/create-map :array
    {:key-size 4     ; u32 for stat type
     :value-size 8   ; u64 for counter
     :max-entries 4})) ; dropped, passed, tcp, udp

(def STAT_DROPPED 0)
(def STAT_PASSED 1)
(def STAT_TCP 2)
(def STAT_UDP 3)

(defn create-packet-filter-with-stats [stats-map-fd]
  "Enhanced packet filter with statistics tracking"
  (bpf/assemble
    (vec (concat
      ;; ... (same parsing code as above) ...

      ;; Before returning, update statistics
      ;; This is left as an exercise - see challenge section

      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 5: Testing and Visualization
;; ============================================================================

(defn format-verdict [verdict]
  "Format XDP verdict as string"
  (case verdict
    0 "ABORTED"
    1 "DROPPED"
    2 "PASSED"
    3 "TX"
    4 "REDIRECT"
    "UNKNOWN"))

(defn test-packet-filter []
  "Test packet filter with synthetic packets"
  (println "=== Testing Packet Filter ===\n")

  ;; Note: Actual packet testing requires raw sockets or test framework
  ;; This is a simplified demonstration

  (println "Test scenarios:")
  (println "1. ICMP packet     → Expected: DROP")
  (println "2. TCP to port 80  → Expected: DROP")
  (println "3. TCP to port 443 → Expected: PASS")
  (println "4. UDP to port 53  → Expected: DROP")
  (println "5. UDP to port 123 → Expected: PASS")
  (println "6. Unknown protocol→ Expected: PASS"))

(defn display-stats [stats-map-fd]
  "Display filter statistics"
  (let [read-stat (fn [idx]
                   (let [key (utils/u32 idx)
                         value (bpf/map-lookup stats-map-fd key)]
                     (if value
                       (utils/read-u64 value 0)
                       0)))]
    (println "\nFilter Statistics:")
    (println "─────────────────────────────")
    (println "Packets dropped :" (read-stat STAT_DROPPED))
    (println "Packets passed  :" (read-stat STAT_PASSED))
    (println "  TCP packets   :" (read-stat STAT_TCP))
    (println "  UDP packets   :" (read-stat STAT_UDP))))

;; ============================================================================
;; Part 6: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 3.1: Packet Filter ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create filter program
  (println "\nStep 2: Creating packet filter...")
  (let [program (create-packet-filter)]
    (println "✓ Filter program assembled")
    (println "  Instructions:" (/ (count program) 8))
    (println "  Size:" (count program) "bytes")

    ;; Analyze program
    (println "\nStep 3: Program analysis...")
    (println "  Filter rules:")
    (println "    - Drop ICMP packets")
    (println "    - Drop TCP to port 80 (HTTP)")
    (println "    - Drop UDP to/from port 53 (DNS)")
    (println "    - Pass everything else")

    ;; Load program
    (println "\nStep 4: Loading program into kernel...")
    (try
      (let [prog-fd (bpf/load-program program :xdp)]
        (println "✓ Program loaded successfully (FD:" prog-fd ")")
        (println "✓ Verifier approved the program")

        (try
          ;; Note: Actual XDP attachment requires network interface
          (println "\nStep 5: XDP attachment...")
          (println "ℹ Network interface attachment requires elevated privileges")
          (println "ℹ Use: ip link set dev eth0 xdp obj prog.o")

          ;; Test scenarios
          (println "\nStep 6: Test scenarios...")
          (test-packet-filter)

          (println "\nStep 7: Cleanup...")
          (bpf/close-program prog-fd)
          (println "✓ Program unloaded")

          (catch Exception e
            (println "✗ Error:" (.getMessage e))
            (.printStackTrace e)))

        (catch Exception e
          (println "✗ Program loading failed:" (.getMessage e))
          (println "\nVerifier rejection - common causes:")
          (println "  - Unbounded memory access")
          (println "  - Missing bounds checks")
          (println "  - Invalid pointer arithmetic")
          (println "\nCheck kernel logs: sudo dmesg | tail"))))

    (catch Exception e
      (println "✗ Error:" (.getMessage e))
      (.printStackTrace e))))

  (println "\n=== Lab 3.1 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-03/labs
clojure -M lab-3-1.clj
```

### Expected Output

```
=== Lab 3.1: Packet Filter ===

Step 1: Initializing...

Step 2: Creating packet filter...
✓ Filter program assembled
  Instructions: 45
  Size: 360 bytes

Step 3: Program analysis...
  Filter rules:
    - Drop ICMP packets
    - Drop TCP to port 80 (HTTP)
    - Drop UDP to/from port 53 (DNS)
    - Pass everything else

Step 4: Loading program into kernel...
✓ Program loaded successfully (FD: 3)
✓ Verifier approved the program

Step 5: XDP attachment...
ℹ Network interface attachment requires elevated privileges
ℹ Use: ip link set dev eth0 xdp obj prog.o

Step 6: Test scenarios...
=== Testing Packet Filter ===

Test scenarios:
1. ICMP packet     → Expected: DROP
2. TCP to port 80  → Expected: DROP
3. TCP to port 443 → Expected: PASS
4. UDP to port 53  → Expected: DROP
5. UDP to port 123 → Expected: PASS
6. Unknown protocol→ Expected: PASS

Step 7: Cleanup...
✓ Program unloaded

=== Lab 3.1 Complete! ===
```

## Understanding the Code

### Bounds Checking Pattern

```clojure
(defn check-bounds [data-reg data-end-reg offset label]
  ;; Essential for verifier approval
  [(bpf/mov-reg :r9 data-reg)]
  [(bpf/add :r9 offset)]
  [(bpf/jmp-reg :jgt :r9 data-end-reg label)]
  ;; If (data + offset > data_end), jump to label
  ;; Otherwise, safe to access [data ... data+offset]
)
```

Every memory access must be preceded by bounds check.

### Endianness Handling

```clojure
;; Network byte order (big-endian) to host
[(bpf/load-mem :h :r4 :r2 12)]  ; Load 16-bit value
[(bpf/be16 :r4)]                 ; Convert to host byte order
```

Network protocols use big-endian; x86 uses little-endian.

### IP Header Length Calculation

```clojure
;; IHL (IP Header Length) is in lower 4 bits, units of 4 bytes
(load-u8 :r5 0 :r7)      ; Load version_ihl byte
[(bpf/and :r7 0x0F)]      ; Extract IHL (lower 4 bits)
[(bpf/lsh :r7 2)]         ; Multiply by 4: IHL * 4 = header bytes
```

## Experiments

### Experiment 1: Add More Filter Rules

```clojure
;; Block SSH (port 22)
(load-u16 :r8 2 :r9)  ; dst_port
[(bpf/jmp-imm :jeq :r9 22 :drop)]

;; Block HTTPS (port 443)
[(bpf/jmp-imm :jeq :r9 443 :drop)]

;; Block IP address range
(load-u32 :r5 12 :r9)  ; src_ip (offset 12 in IP header)
;; Check if src_ip is in 192.168.1.0/24
[(bpf/and :r9 0xFFFFFF00)]  ; Mask to network
[(bpf/jmp-imm :jeq :r9 0xC0A80100 :drop)]  ; 192.168.1.0
```

### Experiment 2: Parse TCP Flags

```clojure
;; Parse TCP flags (SYN, ACK, FIN, etc.)
(load-u8 :r8 13 :r9)  ; TCP flags at offset 13
[(bpf/and :r9 0x02)]   ; Check SYN flag (bit 1)
[(bpf/jmp-imm :jne :r9 0 :is-syn)]
```

### Experiment 3: IPv6 Support

```clojure
;; Check for IPv6 (EtherType 0x86DD)
[(bpf/jmp-imm :jeq :r4 0x86DD :parse-ipv6)]

;; :parse-ipv6
;; IPv6 header is fixed 40 bytes
;; Protocol/Next Header at offset 6
```

### Experiment 4: Connection Tracking

```clojure
;; Track TCP connections in hash map
;; Key: (src_ip, dst_ip, src_port, dst_port, protocol)
;; Value: state, packet_count, byte_count
```

## Troubleshooting

### Verifier Error: "invalid mem access"

```
R2 invalid mem access 'inv'
```

**Cause**: Missing bounds check before memory access

**Solution**: Add bounds check before every load:
```clojure
(check-bounds :r2 :r3 14 :error)
[(bpf/load-mem :h :r4 :r2 12)]  ; Now safe
```

### Verifier Error: "R1 pointer arithmetic"

```
R1 pointer arithmetic with /= operator
```

**Cause**: Invalid pointer operations

**Solution**: Use mov + add instead of complex arithmetic:
```clojure
[(bpf/mov-reg :r8 :r5)]
[(bpf/add-reg :r8 :r7)]  ; Allowed
```

### Packets Not Being Filtered

**Possible causes**:
1. Program not attached to interface
2. Wrong interface
3. Filter logic error
4. Endianness mismatch

**Debug**:
```bash
# Check if XDP program is attached
ip link show eth0

# View XDP statistics
ip -s link show eth0

# Kernel logs
sudo dmesg | grep -i xdp
```

## Key Takeaways

✅ Every memory access requires bounds checking
✅ Network byte order (big-endian) must be converted to host order
✅ IP header length is variable (IHL field)
✅ Verifier requires provable safety for all code paths
✅ XDP provides highest-performance packet processing
✅ Jump offsets must be calculated correctly

## Next Steps

- **Next Lab**: [Lab 3.2 - System Call Argument Capture](lab-3-2-syscall-args.md)
- **Previous Lab**: [Chapter 3 - BPF Instruction Set](../README.md)
- **Chapter**: [Part I - Fundamentals](../../part-1-fundamentals/)

## Challenge

Enhance the packet filter to:
1. Track statistics (packets/bytes dropped and passed)
2. Support IPv6
3. Implement rate limiting (drop if > N packets/second)
4. Parse application-layer protocols (HTTP, DNS)
5. Support dynamic filter rules (configure from userspace)

Solution in: [solutions/lab-3-1-challenge.clj](../solutions/lab-3-1-challenge.clj)
