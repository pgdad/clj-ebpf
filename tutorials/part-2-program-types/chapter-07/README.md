# Chapter 7: XDP (eXpress Data Path)

**Duration**: 4-5 hours | **Difficulty**: Advanced

## Learning Objectives

By the end of this chapter, you will:
- Understand XDP architecture and performance characteristics
- Parse and modify network packets at line rate
- Implement high-performance packet filtering and forwarding
- Use XDP actions (DROP, PASS, TX, REDIRECT, ABORTED)
- Build production-grade network applications
- Optimize XDP programs for maximum throughput
- Handle XDP metadata and multi-buffer packets

## Prerequisites

- Completed [Chapter 6: Tracepoints](../chapter-06/)
- Strong understanding of networking (TCP/IP, Ethernet)
- Familiarity with network byte order (big-endian)
- Basic knowledge of network performance concepts
- Experience with packet analysis tools (tcpdump, Wireshark)

## 7.1 What is XDP?

### Overview

**XDP (eXpress Data Path)** is a BPF hook in the network driver for ultra-fast packet processing:
- **Earliest hook point**: Runs before sk_buff allocation
- **Zero-copy**: Direct access to DMA buffers
- **Line-rate processing**: Millions of packets per second per core
- **Programmable**: Full BPF instruction set
- **Safe**: Verified by BPF verifier

### Traditional vs XDP Packet Path

```
Traditional Linux Network Stack:
┌─────────────────────────────────────────────────────┐
│ NIC Hardware                                        │
│   ├─ DMA to kernel memory                          │
│   ├─ IRQ                                            │  ← Overhead
│   └─ sk_buff allocation                            │  ← Memory
└─────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────┐
│ Network Stack (netfilter, routing, etc.)           │  ← Complexity
└─────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────┐
│ Application (socket)                                │
└─────────────────────────────────────────────────────┘

XDP Path:
┌─────────────────────────────────────────────────────┐
│ NIC Hardware                                        │
│   ├─ DMA to kernel memory                          │
│   └─ XDP BPF PROGRAM ← YOU ARE HERE!               │  ← Immediate
└─────────────────────────────────────────────────────┘
         ↓
    Decision made in nanoseconds:
    - DROP:     Discard immediately
    - PASS:     Continue to network stack
    - TX:       Send back out same interface
    - REDIRECT: Forward to another interface
    - ABORTED:  Error, drop + trace
```

### Performance Numbers

Real-world XDP performance:

| Action | Packets/sec (single core) | Latency |
|--------|---------------------------|---------|
| **XDP_DROP** | 20-30 million pps | ~50ns |
| **XDP_TX** (bounce back) | 15-20 million pps | ~100ns |
| **XDP_REDIRECT** | 10-15 million pps | ~200ns |
| **Network stack** | 1-2 million pps | ~5μs |
| **iptables DROP** | 500k-1M pps | ~10μs |

**Key Insight**: XDP is 10-30x faster than traditional packet processing!

## 7.2 XDP Architecture

### XDP Modes

XDP can operate in three modes:

#### 1. Native XDP (Offload)
```
┌───────────────┐
│  NIC Hardware │ ← XDP runs in NIC (if supported)
└───────────────┘
```
- **Fastest**: Hardware offload
- **Limited**: Only on supported NICs (Netronome, Mellanox)
- **Restrictions**: Limited BPF features

#### 2. Native XDP (Driver)
```
┌───────────────┐
│ NIC Driver    │ ← XDP runs in driver RX path
└───────────────┘
```
- **Fast**: Before sk_buff allocation
- **Common**: Most modern drivers support it
- **Recommended**: Best balance of speed and compatibility

#### 3. Generic XDP (SKB)
```
┌───────────────┐
│ Network Stack │ ← XDP runs after sk_buff allocation
└───────────────┘
```
- **Slowest**: After sk_buff allocation
- **Compatible**: Works on any NIC
- **Development**: Useful for testing

### Checking XDP Support

```bash
# Check if driver supports native XDP
ethtool -i eth0 | grep driver
# Common XDP-capable drivers: mlx5, i40e, ixgbe, virtio_net

# Check current XDP program
ip link show eth0
# Look for "xdp" or "xdpgeneric"

# Load XDP program
ip link set dev eth0 xdp obj my_prog.o sec xdp

# Load in generic mode (fallback)
ip link set dev eth0 xdpgeneric obj my_prog.o sec xdp

# Unload XDP program
ip link set dev eth0 xdp off
```

## 7.3 XDP Context Structure

### xdp_md Structure

XDP programs receive a context pointer of type `struct xdp_md`:

```c
struct xdp_md {
    __u32 data;           // Start of packet data
    __u32 data_end;       // End of packet data
    __u32 data_meta;      // Metadata area (before data)
    __u32 ingress_ifindex; // Incoming interface
    __u32 rx_queue_index; // RX queue number
    __u32 egress_ifindex; // For XDP_REDIRECT
};
```

### Memory Layout

```
XDP Packet Buffer:
┌────────────────┬─────────────────────────────────┬─────────────┐
│   Metadata     │        Packet Data              │  Headroom   │
│   (optional)   │   (Ethernet + IP + payload)     │  (unused)   │
└────────────────┴─────────────────────────────────┴─────────────┘
 ↑               ↑                                  ↑
 data_meta       data                               data_end

Rules:
1. data_meta <= data <= data_end
2. All memory accesses MUST be bounds-checked
3. No access before data_meta or after data_end
```

### Accessing Packet Data

In BPF assembly, the context (r1) contains pointers:

```clojure
;; XDP program entry
;; r1 = ctx (pointer to struct xdp_md)

;; Load data pointer
[(bpf/load-mem :w :r2 :r1 0)]   ; data offset = 0
;; r2 now points to start of packet

;; Load data_end pointer
[(bpf/load-mem :w :r3 :r1 4)]   ; data_end offset = 4
;; r3 now points to end of packet

;; CRITICAL: All packet access must be bounds-checked!
;; Example: Read first byte
[(bpf/mov-reg :r4 :r2)]
[(bpf/add :r4 1)]  ; r4 = data + 1
[(bpf/jmp-reg :jgt :r4 :r3 :invalid)]  ; if (data + 1) > data_end, invalid
[(bpf/load-mem :b :r5 :r2 0)]  ; r5 = *data (safe)
```

## 7.4 XDP Return Codes

XDP programs must return one of five action codes:

### XDP_ABORTED (0)
```
Use: Error condition, should not happen in production
Effect: Packet dropped + trace event
When: Program error, invalid packet
```

### XDP_DROP (1)
```
Use: Intentionally discard packet
Effect: Packet freed immediately
When: DDoS mitigation, filtering, rate limiting
Performance: Fastest action (~50ns)
```

### XDP_PASS (2)
```
Use: Continue to normal network stack
Effect: Packet proceeds to protocol processing
When: Packet passed filter, needs kernel handling
Performance: Normal stack overhead
```

### XDP_TX (3)
```
Use: Transmit packet back out same interface
Effect: Packet sent back to sender
When: Packet reflection, load balancer response
Performance: Very fast (~100ns)
Example: Anti-DDoS SYN cookies, echo server
```

### XDP_REDIRECT (4)
```
Use: Forward packet to different interface
Effect: Packet sent to another NIC or CPU
When: Routing, load balancing, traffic steering
Performance: Fast (~200ns)
Requires: bpf_redirect() or bpf_redirect_map()
```

### Returning Actions in clj-ebpf

```clojure
;; Return XDP_DROP
[(bpf/mov :r0 1)]
[(bpf/exit-insn)]

;; Return XDP_PASS
[(bpf/mov :r0 2)]
[(bpf/exit-insn)]

;; Return XDP_TX
[(bpf/mov :r0 3)]
[(bpf/exit-insn)]

;; Return XDP_REDIRECT (after calling bpf_redirect)
(bpf/helper-redirect :target-ifindex)
;; r0 now contains return code
[(bpf/exit-insn)]
```

## 7.5 Packet Parsing

### Ethernet Header

All packets start with an Ethernet header (14 bytes):

```
Ethernet Header (14 bytes):
┌──────────────┬──────────────┬──────────┐
│ Dst MAC (6)  │ Src MAC (6)  │ Type (2) │
└──────────────┴──────────────┴──────────┘
 0              6              12         14

EtherType values:
- 0x0800: IPv4
- 0x0806: ARP
- 0x86DD: IPv6
- 0x8100: VLAN
```

### IPv4 Header

For IPv4 packets (20+ bytes):

```
IPv4 Header (minimum 20 bytes):
┌────┬────┬─────┬─────┬────┬────┬────┬────┬───────┬───────┬────────┬────────┐
│Ver │IHL │TOS  │Len  │ID  │Flg │Off │TTL │Proto  │Chksum │SrcIP   │DstIP   │
│ 4b │ 4b │  8b │ 16b │16b │ 3b │13b │ 8b │  8b   │  16b  │  32b   │  32b   │
└────┴────┴─────┴─────┴────┴────┴────┴────┴───────┴───────┴────────┴────────┘
 0    0.5   1     2     4    6    6.3  8    9       10      12       16       20

Protocol values:
- 1:  ICMP
- 6:  TCP
- 17: UDP
```

### TCP Header

For TCP packets (20+ bytes after IP):

```
TCP Header (minimum 20 bytes):
┌─────────┬─────────┬─────────┬─────────┬───────┬──────┬─────────┬─────────┐
│Src Port │Dst Port │ Seq     │ Ack     │Offset │Flags │ Window  │Checksum │
│   16b   │   16b   │   32b   │   32b   │  4b   │  8b  │   16b   │   16b   │
└─────────┴─────────┴─────────┴─────────┴───────┴──────┴─────────┴─────────┘
 0         2         4         8         12      13     14        16         20

TCP Flags (1 byte at offset 13):
- 0x01: FIN
- 0x02: SYN
- 0x04: RST
- 0x08: PSH
- 0x10: ACK
- 0x20: URG
```

### Parsing Example in clj-ebpf

```clojure
(defn parse-ethernet-ipv4-tcp [ctx-reg]
  "Parse Ethernet, IPv4, and TCP headers with bounds checking"
  (vec (concat
    ;; Load data and data_end
    [(bpf/load-mem :w :r2 ctx-reg 0)]   ; data
    [(bpf/load-mem :w :r3 ctx-reg 4)]   ; data_end
    [(bpf/mov-reg :r6 :r2)]  ; r6 = eth header

    ;; Check: data + 14 (Ethernet) <= data_end
    [(bpf/mov-reg :r4 :r2)]
    [(bpf/add :r4 14)]
    [(bpf/jmp-reg :jgt :r4 :r3 :invalid)]

    ;; Read EtherType (offset 12, big-endian)
    [(bpf/load-mem :h :r5 :r6 12)]
    [(bpf/endian-be :h :r5)]  ; Convert to host byte order

    ;; Check if IPv4 (0x0800)
    [(bpf/jmp-imm :jne :r5 0x0800 :not-ipv4)]

    ;; r7 = IP header (data + 14)
    [(bpf/mov-reg :r7 :r6)]
    [(bpf/add :r7 14)]

    ;; Check: IP header + 20 <= data_end
    [(bpf/mov-reg :r4 :r7)]
    [(bpf/add :r4 20)]
    [(bpf/jmp-reg :jgt :r4 :r3 :invalid)]

    ;; Read IP protocol (offset 9 in IP header)
    [(bpf/load-mem :b :r5 :r7 9)]

    ;; Check if TCP (6)
    [(bpf/jmp-imm :jne :r5 6 :not-tcp)]

    ;; Calculate TCP header offset
    ;; IP header length is in IHL field (4 bits, offset 0)
    [(bpf/load-mem :b :r5 :r7 0)]
    [(bpf/and :r5 0x0F)]  ; Mask IHL
    [(bpf/lsh :r5 2)]     ; IHL * 4 = header length
    [(bpf/mov-reg :r8 :r7)]
    [(bpf/add-reg :r8 :r5)]  ; r8 = TCP header

    ;; Check: TCP header + 20 <= data_end
    [(bpf/mov-reg :r4 :r8)]
    [(bpf/add :r4 20)]
    [(bpf/jmp-reg :jgt :r4 :r3 :invalid)]

    ;; Now we have:
    ;; r6 = Ethernet header
    ;; r7 = IP header
    ;; r8 = TCP header
    ;; All bounds-checked!

    ;; Continue processing...
    )))
```

## 7.6 Packet Modification

XDP allows zero-copy packet modification before transmission:

### Modifying Headers

```clojure
;; Example: Swap source and destination IP addresses
(defn swap-ip-addresses [ip-header-reg]
  (vec (concat
    ;; Read source IP (offset 12)
    [(bpf/load-mem :w :r4 ip-header-reg 12)]
    ;; Read destination IP (offset 16)
    [(bpf/load-mem :w :r5 ip-header-reg 16)]

    ;; Swap them
    [(bpf/store-mem :w ip-header-reg 12 :r5)]  ; src = old dst
    [(bpf/store-mem :w ip-header-reg 16 :r4)]  ; dst = old src
    )))

;; Example: Decrement TTL
(defn decrement-ttl [ip-header-reg]
  (vec (concat
    ;; Read TTL (offset 8)
    [(bpf/load-mem :b :r4 ip-header-reg 8)]
    ;; Decrement
    [(bpf/sub :r4 1)]
    ;; Write back
    [(bpf/store-mem :b ip-header-reg 8 :r4)]
    ;; Note: Should recalculate IP checksum!
    )))
```

### Checksum Recalculation

After modifying IP or TCP headers, checksums must be updated:

```clojure
;; Use BPF helper for checksum
(bpf/helper-csum-diff
  old-value-ptr    ; Pointer to old value
  old-value-size   ; Size
  new-value-ptr    ; Pointer to new value
  new-value-size   ; Size
  initial-csum)    ; Initial checksum value
;; Returns: New checksum in r0
```

### Adjusting Packet Size

```clojure
;; Add headroom (for encapsulation)
(bpf/helper-xdp-adjust-head
  ctx-reg
  delta)  ; Negative = add space, Positive = remove space

;; Add tailroom (for padding)
(bpf/helper-xdp-adjust-tail
  ctx-reg
  delta)  ; Positive = add space, Negative = remove space
```

## 7.7 XDP Maps and State

XDP programs can use all BPF map types:

### Per-CPU Maps for Performance

```clojure
;; Avoid lock contention with per-CPU maps
(def stats-fd (bpf/create-map :percpu-array
                               {:key-size 4
                                :value-size 8
                                :max-entries 256}))

;; Each CPU has its own copy of the array
;; No locks, no contention!
```

### LRU Maps for Connection Tracking

```clojure
;; Automatically evict old entries
(def conn-track-fd (bpf/create-map :lru-hash
                                    {:key-size 16  ; src_ip + dst_ip + ports
                                     :value-size 24 ; timestamps, counters
                                     :max-entries 1000000}))
```

### DevMaps for Redirection

```clojure
;; Map interface indexes for XDP_REDIRECT
(def devmap-fd (bpf/create-map :devmap
                                {:key-size 4
                                 :value-size 4
                                 :max-entries 256}))

;; Populate: key = arbitrary ID, value = ifindex
(bpf/map-update devmap-fd 0 eth0-ifindex)
(bpf/map-update devmap-fd 1 eth1-ifindex)

;; In XDP program:
[(bpf/ld-map-fd :r1 devmap-fd)]
[(bpf/mov :r2 0)]  ; key
(bpf/helper-redirect-map :r1 :r2)
```

## 7.8 XDP Performance Optimization

### Best Practices

1. **Minimize Memory Access**: Cache frequently used values in registers

   ```clojure
   ;; Bad: Multiple loads
   [(bpf/load-mem :w :r4 :r7 12)]  ; Load src IP
   ;; ... do stuff ...
   [(bpf/load-mem :w :r4 :r7 12)]  ; Load again!

   ;; Good: Load once, keep in register
   [(bpf/load-mem :w :r4 :r7 12)]  ; r4 = src IP
   [(bpf/mov-reg :r9 :r4)]         ; Save in r9 if needed
   ```

2. **Use Per-CPU Maps**: Eliminate lock contention

3. **Early Exit**: Filter out packets as soon as possible

   ```clojure
   ;; Check protocol first (common case: not interesting)
   [(bpf/load-mem :b :r5 :r7 9)]   ; IP protocol
   [(bpf/jmp-imm :jne :r5 6 :pass)] ; If not TCP, pass immediately
   ;; ... expensive TCP processing ...
   ```

4. **Avoid Loops**: Use tail calls for iteration

5. **Use Batch Operations**: Process multiple packets together

6. **Profile and Measure**: Use BPF timers and statistics

### Common Pitfalls

1. **Unbounded Loops**: Verifier will reject
   ```clojure
   ;; Bad: Infinite loop
   ;; :loop
   ;; [(bpf/jmp :loop)]

   ;; Good: Bounded iteration with tail calls or unrolling
   ```

2. **Missing Bounds Checks**: Instant rejection
   ```clojure
   ;; Bad: No check
   [(bpf/load-mem :b :r5 :r2 0)]  ; REJECTED!

   ;; Good: Always check
   [(bpf/jmp-reg :jgt :r2 :r3 :invalid)]
   [(bpf/load-mem :b :r5 :r2 0)]  ; OK
   ```

3. **Large Stack Usage**: Limit 512 bytes
   ```clojure
   ;; Stack usage: count negative offsets from r10
   ;; Keep structs small!
   ```

## 7.9 XDP vs TC (Traffic Control)

| Feature | XDP | TC (cls_bpf) |
|---------|-----|--------------|
| **Hook Point** | Driver RX | After sk_buff |
| **Performance** | Fastest | Fast |
| **Direction** | RX only | RX and TX |
| **Metadata** | Minimal | Full sk_buff |
| **Use Case** | Filtering, early drop | QoS, shaping, egress |

When to use XDP:
- Maximum performance required
- Early packet filtering/dropping
- DDoS mitigation
- Simple forwarding/load balancing

When to use TC:
- Need egress processing
- Complex packet classification
- QoS and traffic shaping
- Need sk_buff metadata

## 7.10 clj-ebpf XDP API

### Loading and Attaching

```clojure
(require '[clj-ebpf.core :as bpf])

;; Create XDP program
(def prog-bytes (bpf/assemble xdp-instructions))

;; Load as XDP program
(def prog-fd (bpf/load-program prog-bytes :xdp))

;; Attach to interface
(def link-fd (bpf/attach-xdp prog-fd "eth0"))
;; Or force generic mode:
;; (def link-fd (bpf/attach-xdp prog-fd "eth0" {:mode :generic}))

;; Detach
(bpf/detach-xdp link-fd)

;; Close
(bpf/close-program prog-fd)
```

### Reading Statistics

```clojure
;; XDP programs often use maps for statistics
(let [stats (bpf/map-lookup stats-fd (int-array [0]))]
  (println "Packets processed:" (aget stats 0))
  (println "Packets dropped:" (aget stats 1)))
```

## Labs

This chapter includes three hands-on labs:

### Lab 7.1: Basic Packet Filter
Drop packets based on IP/port criteria

### Lab 7.2: DDoS Mitigation
Rate limiting and SYN flood protection

### Lab 7.3: Layer 4 Load Balancer
Distribute traffic across backend servers

## Navigation

- **Next**: [Lab 7.1 - Basic Packet Filter](labs/lab-7-1-packet-filter.md)
- **Previous**: [Chapter 6 - Tracepoints](../chapter-06/README.md)
- **Up**: [Part II - Program Types](../../part-2-program-types/)
- **Home**: [Tutorial Home](../../README.md)

## Additional Resources

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Cilium XDP Guide](https://docs.cilium.io/en/latest/bpf/#xdp)
- [Kernel XDP Documentation](https://www.kernel.org/doc/html/latest/networking/xdp.html)
- [XDP Paper (SIGCOMM'18)](https://dl.acm.org/doi/10.1145/3281411.3281443)
- [Performance Numbers](https://www.netdevconf.org/0x13/session.html?talk-xdp-future)
