# Chapter 8: TC (Traffic Control)

**Duration**: 4-5 hours | **Difficulty**: Advanced

## Learning Objectives

By the end of this chapter, you will:
- Understand Linux Traffic Control (TC) architecture
- Attach BPF programs to ingress and egress hooks
- Implement traffic shaping and rate limiting
- Build Quality of Service (QoS) classifiers
- Use TC actions for packet manipulation
- Understand TC vs XDP tradeoffs
- Implement egress filtering and monitoring

## Prerequisites

- Completed [Chapter 7: XDP](../chapter-07/)
- Understanding of Linux networking stack
- Knowledge of QoS concepts
- Familiarity with traffic shaping algorithms

## 8.1 What is TC (Traffic Control)?

### Overview

**Traffic Control (TC)** is Linux's subsystem for controlling network traffic:
- **QoS**: Prioritize important traffic
- **Shaping**: Control bandwidth usage
- **Policing**: Enforce rate limits
- **Classification**: Categorize packets
- **Marking**: Set packet priority (DSCP, ToS)

BPF programs attach to TC via **cls_bpf** (classifier) and **act_bpf** (action).

### Linux Traffic Control Stack

```
┌─────────────────────────────────────────────────────────┐
│                    User Space                           │
│  tc command: configure qdiscs, classes, filters         │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                    Kernel Space                         │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │            Queueing Disciplines (qdisc)         │    │
│  │  ├─ Root qdisc (e.g., htb, fq_codel)           │    │
│  │  ├─ Classes (bandwidth allocation)              │    │
│  │  ├─ Filters (packet classification) ← cls_bpf  │    │
│  │  └─ Actions (packet operations) ← act_bpf      │    │
│  └────────────────────────────────────────────────┘    │
│                                                          │
│  Ingress (RX):                    Egress (TX):          │
│  ┌──────────┐                    ┌──────────┐          │
│  │   NIC    │───→ Ingress qdisc  │ Egress   │          │
│  │ Hardware │     (cls_bpf)      │ qdisc    │───→ NIC  │
│  └──────────┘                    │(cls_bpf) │          │
│                                   └──────────┘          │
└─────────────────────────────────────────────────────────┘
```

### TC vs XDP

| Feature | XDP | TC (cls_bpf) |
|---------|-----|--------------|
| **Hook Location** | NIC driver (earliest) | After sk_buff allocation |
| **Direction** | Ingress only | Ingress AND egress |
| **Performance** | Fastest (~50ns) | Fast (~200-500ns) |
| **Packet Context** | xdp_md (minimal) | __sk_buff (full metadata) |
| **Metadata Access** | Limited | Full (VLAN, priority, mark, etc.) |
| **Use Cases** | Early drop, simple forward | QoS, shaping, complex classification |
| **Packet Modification** | Yes (limited headroom) | Yes (full sk_buff API) |
| **Integration** | Standalone | Full TC subsystem |

**When to Use TC**:
- Need egress (TX) processing
- Complex packet classification
- Traffic shaping and QoS
- Need full sk_buff metadata
- Integration with existing TC infrastructure

**When to Use XDP**:
- Maximum performance (ingress only)
- Early packet filtering
- Simple forwarding/load balancing

## 8.2 TC Architecture

### Queueing Disciplines (qdiscs)

Every network interface has qdiscs that control how packets are queued:

```
Default qdisc (pfifo_fast):
┌─────────────────────────────────┐
│  Priority Band 0 (TOS 0)        │ ← High priority
│  Priority Band 1 (TOS 1-3)      │ ← Normal priority
│  Priority Band 2 (TOS 4-7)      │ ← Low priority
└─────────────────────────────────┘

HTB (Hierarchical Token Bucket):
┌─────────────────────────────────┐
│          Root Class             │
│  ┌───────────┬───────────┐      │
│  │ Class 1   │ Class 2   │      │
│  │ 100 Mbps  │ 50 Mbps   │      │
│  └───────────┴───────────┘      │
└─────────────────────────────────┘
```

### TC Filters (Classifiers)

Filters classify packets and direct them to classes or actions:

```bash
# View current filters
tc filter show dev eth0 ingress
tc filter show dev eth0 egress

# Common filter types
# - u32: Match packet fields
# - flower: Flow-based matching
# - bpf: BPF program (cls_bpf)
```

### TC Actions

Actions are operations performed on packets:

| Action | Effect |
|--------|--------|
| **ok** | Accept packet, continue |
| **shot** | Drop packet |
| **stolen** | Consume packet (no further processing) |
| **redirect** | Forward to another interface |
| **pipe** | Continue to next action |
| **reclassify** | Reclassify packet |

## 8.3 TC BPF Context Structure

### __sk_buff Structure

TC BPF programs receive `struct __sk_buff *`:

```c
struct __sk_buff {
    __u32 len;              // Packet length
    __u32 pkt_type;         // Packet type (HOST, BROADCAST, etc.)
    __u32 mark;             // Packet mark (fwmark)
    __u32 queue_mapping;    // Queue index
    __u32 protocol;         // EtherType (network byte order!)
    __u32 vlan_present;     // VLAN tag present
    __u32 vlan_tci;         // VLAN TCI
    __u32 vlan_proto;       // VLAN protocol
    __u32 priority;         // Packet priority
    __u32 ingress_ifindex;  // Incoming interface
    __u32 ifindex;          // Current interface
    __u32 tc_index;         // TC index
    __u32 cb[5];            // Control buffer (scratch space)
    __u32 hash;             // Packet hash
    __u32 tc_classid;       // TC classid
    __u32 data;             // Pointer to packet data
    __u32 data_end;         // Pointer to end of packet data
    __u32 napi_id;          // NAPI ID

    // ... many more fields ...
};
```

### Accessing Packet Data

Similar to XDP, but uses __sk_buff:

```clojure
;; TC BPF program entry
;; r1 = ctx (struct __sk_buff *)

;; Access packet data
;; data and data_end are at different offsets than XDP!

;; Load data pointer (offset 76 in __sk_buff on x86_64)
[(bpf/load-mem :w :r2 :r1 76)]   ; data

;; Load data_end pointer (offset 80)
[(bpf/load-mem :w :r3 :r1 80)]   ; data_end

;; Now parse packet (same as XDP)
[(bpf/mov-reg :r4 :r2)]
[(bpf/add :r4 14)]  ; Ethernet header
[(bpf/jmp-reg :jgt :r4 :r3 :drop)]
[(bpf/load-mem :b :r5 :r2 0)]  ; First byte (safe)
```

**IMPORTANT**: __sk_buff field offsets may vary by architecture and kernel version. Use BTF or constants from kernel headers.

### Reading Metadata

```clojure
;; Read packet mark (offset 20)
[(bpf/load-mem :w :r5 :r1 20)]  ; r5 = skb->mark

;; Read priority (offset 32)
[(bpf/load-mem :w :r5 :r1 32)]  ; r5 = skb->priority

;; Read incoming interface (offset 24)
[(bpf/load-mem :w :r5 :r1 24)]  ; r5 = skb->ingress_ifindex

;; Read protocol (offset 16)
[(bpf/load-mem :w :r5 :r1 16)]  ; r5 = skb->protocol (network byte order!)
[(bpf/endian-be :h :r5)]        ; Convert to host order
```

### Setting Metadata

```clojure
;; Set packet mark
[(bpf/mov :r5 42)]
[(bpf/store-mem :w :r1 20 :r5)]  ; skb->mark = 42

;; Set priority
[(bpf/mov :r5 1)]
[(bpf/store-mem :w :r1 32 :r5)]  ; skb->priority = 1 (high)

;; Set TC classid (for qdisc classification)
[(bpf/mov :r5 0x00010002)]  ; Major:minor (1:2)
[(bpf/store-mem :w :r1 68 :r5)]  ; skb->tc_classid
```

## 8.4 TC Return Codes

TC BPF programs return action codes:

### TC_ACT_OK (0)
```
Effect: Accept packet, continue processing
Use: Normal packet flow
```

### TC_ACT_SHOT (-1 or 2)
```
Effect: Drop packet
Use: Filtering, policy enforcement
```

### TC_ACT_STOLEN (4)
```
Effect: Consume packet (stop processing)
Use: When you've handled packet completely
```

### TC_ACT_REDIRECT (7)
```
Effect: Forward packet to another interface
Use: Routing, mirroring
Requires: bpf_redirect() helper
```

### TC_ACT_UNSPEC (-1)
```
Effect: Unspecified (typically drop)
Use: Error conditions
```

### Returning Actions in clj-ebpf

```clojure
;; Accept packet
[(bpf/mov :r0 0)]  ; TC_ACT_OK
[(bpf/exit-insn)]

;; Drop packet
[(bpf/mov :r0 2)]  ; TC_ACT_SHOT
[(bpf/exit-insn)]

;; Redirect to interface
[(bpf/mov :r2 target-ifindex)]
(bpf/helper-redirect :r2)
;; r0 now contains return code
[(bpf/exit-insn)]
```

## 8.5 Attaching TC BPF Programs

### Using tc Command

```bash
# Add clsact qdisc (required for BPF)
tc qdisc add dev eth0 clsact

# Attach BPF to ingress
tc filter add dev eth0 ingress \
   bpf direct-action \
   obj my_prog.o sec classifier

# Attach BPF to egress
tc filter add dev eth0 egress \
   bpf direct-action \
   obj my_prog.o sec classifier

# View filters
tc filter show dev eth0 ingress
tc filter show dev eth0 egress

# Remove filter
tc filter del dev eth0 ingress

# Remove qdisc (removes all filters)
tc qdisc del dev eth0 clsact
```

### Direct-Action Mode

**direct-action**: BPF program returns action directly (no separate action)

```bash
# With direct-action (modern, recommended)
tc filter add dev eth0 ingress bpf direct-action obj prog.o

# Without direct-action (legacy, requires separate action)
tc filter add dev eth0 ingress bpf obj prog.o action bpf obj act.o
```

## 8.6 Common TC Patterns

### Pattern 1: Packet Classification by Port

```clojure
(defn create-port-classifier [high-prio-ports]
  "Classify packets by destination port, set priority"
  (bpf/assemble
    (vec (concat
      ;; r6 = skb
      [(bpf/mov-reg :r6 :r1)]

      ;; Load packet data pointers
      [(bpf/load-mem :w :r2 :r6 76)]  ; data
      [(bpf/load-mem :w :r3 :r6 80)]  ; data_end

      ;; Parse to TCP/UDP port
      ;; ... (Ethernet + IP + TCP/UDP parsing) ...

      ;; Read destination port
      [(bpf/load-mem :h :r9 :r8 2)]  ; dst_port
      [(bpf/endian-be :h :r9)]

      ;; Check if high-priority port (e.g., 443 for HTTPS)
      [(bpf/jmp-imm :jeq :r9 443 :high-priority)]
      [(bpf/jmp-imm :jeq :r9 22 :high-priority)]
      [(bpf/jmp :normal-priority)]

      ;; :high-priority - Set skb->priority = 1
      [(bpf/mov :r5 1)]
      [(bpf/store-mem :w :r6 32 :r5)]
      [(bpf/jmp :accept)]

      ;; :normal-priority - Set skb->priority = 3
      [(bpf/mov :r5 3)]
      [(bpf/store-mem :w :r6 32 :r5)]

      ;; :accept
      [(bpf/mov :r0 0)]  ; TC_ACT_OK
      [(bpf/exit-insn)]))))
```

### Pattern 2: Traffic Shaping with Rate Limiting

```clojure
(defn create-rate-limiter [rate-limit-fd max-rate-bps]
  "Limit egress traffic to max_rate_bps"
  (bpf/assemble
    (vec (concat
      ;; Get current time
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]  ; current_time

      ;; Lookup rate state
      [(bpf/mov :r5 0)]
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 rate-limit-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Token bucket algorithm
      ;; State: {last_time (u64), tokens (u64)}
      [(bpf/jmp-imm :jne :r0 0 :have-state)]

      ;; Initialize state
      [(bpf/store-mem :dw :r10 -16 :r9)]      ; last_time = now
      [(bpf/mov :r5 max-rate-bps)]
      [(bpf/store-mem :dw :r10 -8 :r5)]       ; tokens = max_rate

      [(bpf/ld-map-fd :r1 rate-limit-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      [(bpf/jmp :accept)]

      ;; :have-state
      ;; Calculate tokens to add based on time elapsed
      ;; Consume tokens for this packet
      ;; If tokens < packet_size: DROP
      ;; Else: ACCEPT
      ;; ... (token bucket logic) ...

      ;; :drop
      [(bpf/mov :r0 2)]  ; TC_ACT_SHOT
      [(bpf/exit-insn)]

      ;; :accept
      [(bpf/mov :r0 0)]  ; TC_ACT_OK
      [(bpf/exit-insn)]))))
```

### Pattern 3: Packet Mirroring

```clojure
(defn create-packet-mirror [mirror-ifindex]
  "Clone and send packets to monitoring interface"
  (bpf/assemble
    (vec (concat
      ;; Clone packet
      [(bpf/mov-reg :r1 :r1)]  ; skb (already in r1)
      [(bpf/mov :r2 mirror-ifindex)]
      [(bpf/mov :r3 0)]  ; flags
      (bpf/helper-clone-redirect :r1 :r2 :r3)

      ;; Original packet continues normally
      [(bpf/mov :r0 0)]  ; TC_ACT_OK
      [(bpf/exit-insn)]))))
```

### Pattern 4: DSCP Marking for QoS

```clojure
(defn create-dscp-marker [dscp-value]
  "Mark packets with DSCP value for QoS"
  (bpf/assemble
    (vec (concat
      ;; Parse to IP header
      ;; ... (bounds checking) ...

      ;; Read ToS byte (offset 1 in IP header)
      [(bpf/load-mem :b :r5 :r7 1)]

      ;; Clear DSCP bits (upper 6 bits)
      [(bpf/and :r5 0x03)]

      ;; Set new DSCP value
      [(bpf/mov :r4 dscp-value)]
      [(bpf/lsh :r4 2)]  ; Shift to DSCP position
      [(bpf/or-reg :r5 :r4)]

      ;; Write back ToS
      [(bpf/store-mem :b :r7 1 :r5)]

      ;; Recalculate IP checksum (or let hardware do it)
      ;; ...

      [(bpf/mov :r0 0)]  ; TC_ACT_OK
      [(bpf/exit-insn)]))))
```

## 8.7 Traffic Shaping Algorithms

### Token Bucket

```
Capacity: C tokens
Refill rate: R tokens/second

Packet arrival:
1. Add tokens: tokens += R * elapsed_time
2. Cap at C
3. If tokens >= packet_size:
   - Consume tokens
   - Send packet
4. Else:
   - Drop or queue packet
```

### Hierarchical Token Bucket (HTB)

```
         Root (100 Mbps)
           /        \
   Class A          Class B
   (60 Mbps)        (40 Mbps)
      /    \           /    \
   Web    SSH      Video   Other
  (40M)  (20M)     (30M)   (10M)
```

### Fair Queueing

```
Per-flow queues:
┌─────────┐ ┌─────────┐ ┌─────────┐
│ Flow 1  │ │ Flow 2  │ │ Flow 3  │
└────┬────┘ └────┬────┘ └────┬────┘
     └───────────┴───────────┘
              Round-robin
                  ↓
               Transmit
```

## 8.8 TC BPF Helpers

TC programs have access to specialized helpers:

### bpf_skb_load_bytes
```clojure
;; Load bytes from packet
[(bpf/mov-reg :r1 skb-reg)]
[(bpf/mov :r2 offset)]
[(bpf/mov-reg :r3 dst-ptr)]
[(bpf/mov :r4 size)]
(bpf/helper-skb-load-bytes :r1 :r2 :r3 :r4)
```

### bpf_skb_store_bytes
```clojure
;; Store bytes to packet
[(bpf/mov-reg :r1 skb-reg)]
[(bpf/mov :r2 offset)]
[(bpf/mov-reg :r3 src-ptr)]
[(bpf/mov :r4 size)]
[(bpf/mov :r5 0)]  ; flags
(bpf/helper-skb-store-bytes :r1 :r2 :r3 :r4 :r5)
```

### bpf_skb_change_proto
```clojure
;; Change packet protocol
[(bpf/mov-reg :r1 skb-reg)]
[(bpf/mov :r2 new-proto)]  ; e.g., ETH_P_IPV6
[(bpf/mov :r3 0)]  ; flags
(bpf/helper-skb-change-proto :r1 :r2 :r3)
```

### bpf_redirect
```clojure
;; Redirect packet to another interface
[(bpf/mov :r2 target-ifindex)]
[(bpf/mov :r3 0)]  ; flags
(bpf/helper-redirect :r2 :r3)
```

### bpf_skb_vlan_push/pop
```clojure
;; Push VLAN tag
[(bpf/mov-reg :r1 skb-reg)]
[(bpf/mov :r2 vlan-proto)]  ; ETH_P_8021Q
[(bpf/mov :r3 vlan-tci)]
(bpf/helper-skb-vlan-push :r1 :r2 :r3)

;; Pop VLAN tag
[(bpf/mov-reg :r1 skb-reg)]
(bpf/helper-skb-vlan-pop :r1)
```

## 8.9 clj-ebpf TC API

### Loading and Attaching

```clojure
(require '[clj-ebpf.core :as bpf])

;; Create TC program
(def prog-bytes (bpf/assemble tc-instructions))

;; Load as TC (classifier) program
(def prog-fd (bpf/load-program prog-bytes :sched-cls))

;; Attach to ingress
(def link-fd (bpf/attach-tc prog-fd "eth0" :ingress))

;; Attach to egress
(def link-fd (bpf/attach-tc prog-fd "eth0" :egress))

;; Detach
(bpf/detach-tc link-fd)

;; Close
(bpf/close-program prog-fd)
```

## Labs

This chapter includes three hands-on labs:

### Lab 8.1: Traffic Shaper
Implement bandwidth limiting for egress traffic

### Lab 8.2: QoS Classifier
Prioritize traffic based on protocol and port

### Lab 8.3: Egress Firewall
Filter outbound connections with policy enforcement

## Navigation

- **Next**: [Lab 8.1 - Traffic Shaper](labs/lab-8-1-traffic-shaper.md)
- **Previous**: [Chapter 7 - XDP](../chapter-07/README.md)
- **Up**: [Part II - Program Types](../../part-2-program-types/)
- **Home**: [Tutorial Home](../../README.md)

## Additional Resources

- [Linux TC Documentation](https://tldp.org/HOWTO/Traffic-Control-HOWTO/)
- [TC BPF Programs](https://docs.cilium.io/en/latest/bpf/#tc-traffic-control)
- [Kernel TC Documentation](https://www.kernel.org/doc/html/latest/networking/tc-actions-env-rules.html)
- [HTB Guide](https://linux-ip.net/articles/htb/)
- [BPF and TC](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)
