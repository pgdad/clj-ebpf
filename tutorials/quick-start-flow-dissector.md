# Quick Start: FLOW_DISSECTOR Custom Packet Parsing

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Learning Objectives

By the end of this tutorial, you will:
- Understand FLOW_DISSECTOR program architecture and use cases
- Know how to parse packet headers for flow identification
- Use DSL helpers for bpf_flow_keys field access
- Understand the attachment process via network namespaces
- Build custom protocol parsers for RSS/ECMP hashing

## Prerequisites

- Basic clj-ebpf knowledge (maps, programs, DSL)
- Understanding of network protocols (Ethernet, IP, TCP/UDP)
- Familiarity with packet parsing concepts
- Linux kernel 4.2+ (for basic support), 5.0+ (for BPF link attachment)
- Root privileges for running examples

## Introduction

### What is FLOW_DISSECTOR?

FLOW_DISSECTOR (BPF_PROG_TYPE_FLOW_DISSECTOR) enables **custom packet parsing** for flow identification. The kernel uses flow information for:
- **RSS (Receive Side Scaling)**: Distribute packets across CPU cores
- **ECMP routing**: Choose path for multi-path routing
- **Flow-based load balancing**: Consistent packet distribution

FLOW_DISSECTOR programs override the kernel's built-in C-based flow dissector, allowing custom protocol handling.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Incoming Packet                               │
│              (needs flow classification)                            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               v
┌─────────────────────────────────────────────────────────────────────┐
│                  FLOW_DISSECTOR BPF Program                         │
│                                                                     │
│  Input Context (__sk_buff):                                        │
│    - data (packet data pointer)                                    │
│    - data_end (end of packet)                                      │
│    - flow_keys (pointer to output structure)                       │
│                                                                     │
│  Output (bpf_flow_keys):                                           │
│    - nhoff (network header offset)                                 │
│    - thoff (transport header offset)                               │
│    - addr_proto (ETH_P_IP, ETH_P_IPV6)                            │
│    - ip_proto (TCP, UDP, etc.)                                     │
│    - ipv4_src, ipv4_dst (or ipv6_*)                               │
│    - sport, dport (source/dest ports)                              │
│                                                                     │
│  Actions:                                                          │
│    - BPF_OK (0): Success, use filled flow_keys                    │
│    - BPF_DROP (-1): Stop dissection                                │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 v                         v
┌────────────────────────────┐   ┌───────────────────────────────────┐
│   BPF_DROP                 │   │   BPF_OK                           │
│   Fall back to kernel      │   │   Use program's flow_keys          │
│   dissector               │   │   for RSS/ECMP hashing            │
└────────────────────────────┘   └───────────────────────────────────┘
```

### Use Cases

| Use Case | Description |
|----------|-------------|
| Custom encapsulation | Parse GRE, VXLAN, custom tunnels |
| Non-standard headers | Handle proprietary protocol headers |
| Protocol-aware hashing | Custom flow identification for specific protocols |
| Debugging | Trace packet classification decisions |
| Application-layer hashing | Hash based on application protocol fields |

---

## Part 1: Understanding bpf_flow_keys Structure

### Output Structure

FLOW_DISSECTOR programs fill the `bpf_flow_keys` structure:

```clojure
(require '[clj-ebpf.dsl.flow-dissector :as fd])

;; Flow keys field offsets
fd/flow-keys-offsets
;; => {:nhoff          0    ; Network header offset (u16)
;;     :thoff          2    ; Transport header offset (u16)
;;     :addr-proto     4    ; Address protocol ETH_P_IP/IPV6 (u16)
;;     :is-frag        6    ; Is fragment flag (u8)
;;     :is-first-frag  7    ; Is first fragment flag (u8)
;;     :is-encap       8    ; Is encapsulated flag (u8)
;;     :ip-proto       9    ; IP protocol TCP/UDP/etc (u8)
;;     :n-proto        10   ; Network protocol (u16)
;;     :sport          12   ; Source port (u16)
;;     :dport          14   ; Destination port (u16)
;;     :ipv4-src       16   ; IPv4 source address (u32)
;;     :ipv4-dst       20   ; IPv4 destination address (u32)
;;     :ipv6-src       16   ; IPv6 source (overlaps ipv4-src)
;;     :ipv6-dst       32   ; IPv6 destination
;;     :flags          48   ; Flags (u32)
;;     :flow-label     52}  ; IPv6 flow label (u32)
```

### Key Fields for Flow Identification

The kernel uses these fields for 5-tuple flow hashing:
- **addr_proto**: Address family (0x0800 for IPv4, 0x86DD for IPv6)
- **ip_proto**: L4 protocol (6=TCP, 17=UDP)
- **ipv4_src/dst** or **ipv6_src/dst**: IP addresses
- **sport/dport**: Source and destination ports

---

## Part 2: Building FLOW_DISSECTOR Programs

### Basic Program Structure

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.flow-dissector :as fd])

;; Minimal FLOW_DISSECTOR program: return BPF_OK
(def minimal-insns
  (vec (concat
        ;; Prologue - save context, load data pointers
        (fd/flow-dissector-prologue :r6 :r2 :r3)
        ;; Return OK
        (fd/flow-dissector-ok))))

;; Assemble to bytecode
(def bytecode (dsl/assemble minimal-insns))
```

### The Prologue

The prologue saves the context pointer and loads packet data pointers:

```clojure
(fd/flow-dissector-prologue :r6 :r2 :r3)
;; - r6: Saved __sk_buff context pointer
;; - r2: Packet data pointer (from ctx->data)
;; - r3: Packet data_end pointer (from ctx->data_end)
```

### Getting the flow_keys Pointer

```clojure
;; Load flow_keys pointer from context
(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)
;; - r6: Context register
;; - r7: Destination for flow_keys pointer
```

---

## Part 3: Parsing Ethernet Headers

### Using the Parse Helper

```clojure
(def ethernet-parser
  (vec (concat
        ;; Prologue
        (fd/flow-dissector-prologue :r6 :r2 :r3)

        ;; Get flow_keys pointer
        [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

        ;; Parse Ethernet header (14 bytes)
        ;; Sets nhoff = 14 and n_proto from ethertype
        (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)

        ;; Return OK
        (fd/flow-dissector-ok))))
```

### Manual Ethernet Parsing

```clojure
;; Parse Ethernet manually
(def manual-ethernet
  (vec (concat
        (fd/flow-dissector-prologue :r6 :r2 :r3)
        [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

        ;; Bounds check: need 14 bytes for Ethernet header
        (fd/flow-dissector-bounds-check :r2 :r3 14 3)
        (fd/flow-dissector-drop)  ; Fail if too short

        ;; Set nhoff = 14 (Ethernet header size)
        [(dsl/mov :r0 14)
         (fd/flow-keys-set-nhoff :r7 :r0)]

        ;; Load ethertype from offset 12 (2 bytes)
        [(dsl/ldx :h :r0 :r2 12)
         (fd/flow-keys-set-n-proto :r7 :r0)]

        (fd/flow-dissector-ok))))
```

---

## Part 4: Parsing IPv4 Headers

### Using the Parse Helper

```clojure
(def ipv4-parser
  (vec (concat
        (fd/flow-dissector-prologue :r6 :r2 :r3)
        [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

        ;; Parse Ethernet first
        (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)

        ;; Parse IPv4 (starting at offset 14)
        ;; Sets addr_proto, ip_proto, addresses, and thoff
        (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)

        (fd/flow-dissector-ok))))
```

### What parse-ipv4 Sets

The IPv4 parser fills these flow_keys fields:
- **addr_proto** = 0x0800 (ETH_P_IP)
- **ip_proto** = protocol field from IP header
- **ipv4_src** = source address
- **ipv4_dst** = destination address
- **thoff** = 14 + (IHL * 4) (transport header offset)

---

## Part 5: Parsing Transport Layer Ports

### TCP/UDP Port Parsing

```clojure
;; Parse TCP ports (source and destination)
(fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)
;; - r2/r3: data/data_end pointers
;; - r7: flow_keys pointer
;; - 34: transport header offset (14 eth + 20 ip min)
;; - r0: temp register

;; UDP ports use same function (same layout)
(fd/flow-dissector-parse-udp-ports :r2 :r3 :r7 34 :r0)
```

### Complete TCP/IPv4 Dissector

```clojure
(def tcp-ipv4-dissector
  (vec (concat
        ;; Setup
        (fd/flow-dissector-prologue :r6 :r2 :r3)
        [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

        ;; Parse Ethernet (nhoff = 14, n_proto = ethertype)
        (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)

        ;; Parse IPv4 (addr_proto, ip_proto, addresses, thoff)
        (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)

        ;; Parse TCP/UDP ports (sport, dport)
        (fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)

        ;; Success
        (fd/flow-dissector-ok))))
```

---

## Part 6: Using Program Builder

### build-flow-dissector-program

```clojure
(def built-dissector
  (fd/build-flow-dissector-program
   {:ctx-reg :r6
    :data-reg :r2
    :data-end-reg :r3
    :body [;; Get flow_keys pointer
           (fd/flow-dissector-get-flow-keys-ptr :r6 :r7)
           ;; Set network header offset
           (dsl/mov :r0 14)
           (fd/flow-keys-set-nhoff :r7 :r0)
           ;; Set address protocol (IPv4)
           (dsl/mov :r0 0x0800)
           (fd/flow-keys-set-addr-proto :r7 :r0)]
    :default-action :ok}))

;; built-dissector is assembled bytecode (byte array)
```

---

## Part 7: Using defprogram Macro

```clojure
(require '[clj-ebpf.macros :refer [defprogram]])
(require '[clj-ebpf.dsl.flow-dissector :as fd])

(defprogram flow-dissector-ipv4
  "FLOW_DISSECTOR for IPv4 packets with TCP/UDP."
  :type :flow-dissector
  :license "GPL"
  :body (vec (concat
              ;; Prologue
              (fd/flow-dissector-prologue :r6 :r2 :r3)

              ;; Get flow_keys pointer
              [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

              ;; Parse Ethernet header
              (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)

              ;; Parse IPv4 header
              (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)

              ;; Parse ports
              (fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)

              ;; Return OK
              (fd/flow-dissector-ok))))
```

---

## Part 8: Flow Keys Field Access

### Writing Fields

```clojure
;; Set header offsets
(fd/flow-keys-set-nhoff :r7 :r0)   ; Network header offset
(fd/flow-keys-set-thoff :r7 :r0)   ; Transport header offset

;; Set protocol info
(fd/flow-keys-set-addr-proto :r7 :r0)  ; ETH_P_IP or ETH_P_IPV6
(fd/flow-keys-set-ip-proto :r7 :r0)    ; TCP (6), UDP (17), etc
(fd/flow-keys-set-n-proto :r7 :r0)     ; Network protocol

;; Set ports (returns vector of 2 instructions)
(fd/flow-keys-set-ports :r7 :r0 :r1)   ; sport and dport

;; Set IPv4 addresses (returns vector of 2 instructions)
(fd/flow-keys-set-ipv4-addrs :r7 :r0 :r1)  ; src and dst

;; Set flags
(fd/flow-keys-set-is-frag :r7 :r0)
(fd/flow-keys-set-is-first-frag :r7 :r0)
(fd/flow-keys-set-is-encap :r7 :r0)
```

### Reading Fields

```clojure
;; Load fields from flow_keys
(fd/flow-keys-load-u8 :r7 :r0 :ip-proto)   ; 8-bit field
(fd/flow-keys-load-u16 :r7 :r0 :nhoff)     ; 16-bit field
(fd/flow-keys-load-u32 :r7 :r0 :ipv4-src)  ; 32-bit field
```

### Low-Level Store Operations

```clojure
;; Store specific sizes
(fd/flow-keys-store-u8 :r7 :is-frag :r0)   ; 8-bit store
(fd/flow-keys-store-u16 :r7 :nhoff :r0)    ; 16-bit store
(fd/flow-keys-store-u32 :r7 :ipv4-src :r0) ; 32-bit store
```

---

## Part 9: Bounds Checking

### Why Bounds Checking Matters

BPF verifier requires proof that packet access is safe. Use bounds checks before reading packet data:

```clojure
;; Check if offset bytes are accessible
(fd/flow-dissector-bounds-check :r2 :r3 14 3)
;; - r2: data pointer
;; - r3: data_end pointer
;; - 14: bytes needed
;; - 3: instructions to skip on failure

;; Pattern: bounds check then fallback
(vec (concat
      (fd/flow-dissector-bounds-check :r2 :r3 14 3)
      (fd/flow-dissector-drop)  ; Skip here on failure
      ;; ... continue parsing on success
      ))
```

---

## Part 10: Attaching FLOW_DISSECTOR Programs

### Using attach-flow-dissector

```clojure
(require '[clj-ebpf.programs :as progs])

;; Load the program
(def fd-prog
  (progs/load-program
   {:prog-type :flow-dissector
    :insns bytecode
    :license "GPL"
    :prog-name "my_dissector"}))

;; Attach to current network namespace
(def attached-prog
  (progs/attach-flow-dissector fd-prog {}))

;; Or specify namespace path
(def attached-prog
  (progs/attach-flow-dissector fd-prog
    {:netns-path "/proc/self/ns/net"}))

;; Or use pre-opened FD
(def attached-prog
  (progs/attach-flow-dissector fd-prog
    {:netns-fd netns-fd}))
```

### Detaching

```clojure
;; Detach FLOW_DISSECTOR program
(progs/detach-flow-dissector attached-prog)

;; Or close program (detaches automatically)
(progs/close-program attached-prog)
```

---

## Part 11: Complete Example

### Full IPv4/TCP/UDP Flow Dissector

```clojure
(ns my-flow-dissector
  (:require [clj-ebpf.programs :as progs]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.flow-dissector :as fd]))

;; Build complete flow dissector
(def dissector-bytecode
  (dsl/assemble
   (vec (concat
         ;; Setup: save context, load data pointers
         (fd/flow-dissector-prologue :r6 :r2 :r3)

         ;; Get flow_keys pointer
         [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

         ;; Parse Ethernet header
         ;; Sets: nhoff = 14, n_proto = ethertype
         (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)

         ;; Parse IPv4 header
         ;; Sets: addr_proto, ip_proto, addresses, thoff
         (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)

         ;; Parse transport ports
         ;; Sets: sport, dport
         (fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)

         ;; Return success
         (fd/flow-dissector-ok)))))

;; Load and attach (requires root)
(comment
  (def prog
    (progs/load-program
     {:prog-type :flow-dissector
      :insns dissector-bytecode
      :license "GPL"}))

  (def attached
    (progs/attach-flow-dissector prog {}))

  ;; Now all packets in this netns use our dissector
  ;; for flow hashing (RSS, ECMP)

  ;; Later: cleanup
  (progs/close-program attached))
```

---

## DSL Reference

### Context and Setup

| Function | Description |
|----------|-------------|
| `flow-dissector-prologue` | Save context, load data pointers |
| `flow-dissector-get-flow-keys-ptr` | Get flow_keys output pointer |
| `flow-dissector-load-ctx-field` | Load __sk_buff field |

### Flow Keys Writing

| Function | Description |
|----------|-------------|
| `flow-keys-set-nhoff` | Set network header offset |
| `flow-keys-set-thoff` | Set transport header offset |
| `flow-keys-set-addr-proto` | Set address protocol |
| `flow-keys-set-ip-proto` | Set IP protocol |
| `flow-keys-set-n-proto` | Set network protocol |
| `flow-keys-set-ports` | Set sport and dport |
| `flow-keys-set-ipv4-addrs` | Set IPv4 src and dst |
| `flow-keys-set-is-frag` | Set fragment flag |
| `flow-keys-set-is-encap` | Set encapsulation flag |

### Parsing Helpers

| Function | Description |
|----------|-------------|
| `flow-dissector-parse-ethernet` | Parse Ethernet header |
| `flow-dissector-parse-ipv4` | Parse IPv4 header |
| `flow-dissector-parse-tcp-ports` | Parse TCP/UDP ports |
| `flow-dissector-parse-udp-ports` | Parse UDP ports |
| `flow-dissector-bounds-check` | Packet bounds check |

### Return Patterns

| Function | Description |
|----------|-------------|
| `flow-dissector-ok` | Return BPF_OK (0) |
| `flow-dissector-drop` | Return BPF_DROP (-1) |

---

## Protocol Constants

### Ethernet Protocols

```clojure
fd/ethernet-protocols
;; => {:ipv4  0x0800
;;     :ipv6  0x86DD
;;     :arp   0x0806
;;     :vlan  0x8100
;;     :mpls  0x8847
;;     :pppoe 0x8864}
```

### IP Protocols

```clojure
fd/ip-protocols
;; => {:icmp   1
;;     :tcp    6
;;     :udp    17
;;     :gre    47
;;     :icmpv6 58
;;     :sctp   132}
```

### Header Sizes

```clojure
fd/ethernet-header-size  ; 14
fd/ipv4-header-min-size  ; 20
fd/ipv6-header-size      ; 40
fd/tcp-header-min-size   ; 20
fd/udp-header-size       ; 8
```

---

## Troubleshooting

### Common Issues

1. **"Permission denied"**
   - Need root or CAP_NET_ADMIN + CAP_BPF

2. **"Operation not permitted" on attach**
   - Kernel 5.0+ required for BPF link attachment
   - Earlier kernels may have different attachment method

3. **Program load fails with bounds check error**
   - Add bounds checks before packet access
   - Ensure all packet reads are within data/data_end

4. **Flow hashing not working as expected**
   - Verify all 5-tuple fields are set correctly
   - Check byte order (network byte order for IPs/ports)

### Debugging

```bash
# Check kernel version
uname -r

# List FLOW_DISSECTOR programs
sudo bpftool prog list | grep flow_dissector

# Check BPF links
sudo bpftool link list

# View program details
sudo bpftool prog show id <prog-id>
```

---

## Summary

You learned:
- bpf_flow_keys structure and fields
- Parsing Ethernet, IPv4, and TCP/UDP headers
- Using DSL helpers for field access
- Bounds checking for safe packet access
- Attaching to network namespaces

---

## Next Steps

- **[SK_LOOKUP Tutorial](quick-start-sk-lookup.md)** - Programmable socket lookup
- **[XSKMAP Tutorial](quick-start-xskmap.md)** - AF_XDP zero-copy

---

## Reference

### Kernel Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| FLOW_DISSECTOR programs | 4.2 |
| BPF link attachment | 5.0 |
| Full feature support | 5.8+ |

### bpf_flow_keys Field Offsets

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| nhoff | 0 | 2 | Network header offset |
| thoff | 2 | 2 | Transport header offset |
| addr_proto | 4 | 2 | ETH_P_IP/IPV6 |
| is_frag | 6 | 1 | Fragment flag |
| is_first_frag | 7 | 1 | First fragment flag |
| is_encap | 8 | 1 | Encapsulated flag |
| ip_proto | 9 | 1 | TCP/UDP/etc |
| n_proto | 10 | 2 | Network protocol |
| sport | 12 | 2 | Source port |
| dport | 14 | 2 | Destination port |
| ipv4_src | 16 | 4 | IPv4 source |
| ipv4_dst | 20 | 4 | IPv4 destination |
| ipv6_src | 16 | 16 | IPv6 source |
| ipv6_dst | 32 | 16 | IPv6 destination |
| flags | 48 | 4 | Flags |
| flow_label | 52 | 4 | IPv6 flow label |
