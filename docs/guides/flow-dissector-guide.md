# FLOW_DISSECTOR Guide: Custom Packet Parsing

This guide covers FLOW_DISSECTOR programs for custom packet parsing and flow identification.

## Overview

FLOW_DISSECTOR (BPF_PROG_TYPE_FLOW_DISSECTOR) enables:

- **Custom packet parsing** - Override built-in flow dissector
- **Protocol-specific hashing** - Handle non-standard headers
- **RSS optimization** - Custom flow identification for Receive Side Scaling
- **ECMP routing** - Custom flow keys for multi-path routing

## Creating FLOW_DISSECTOR Programs

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.flow-dissector :as fd])

;; Build program bytecode
(def bytecode
  (dsl/assemble
    (vec (concat
          (fd/flow-dissector-prologue :r6 :r2 :r3)
          [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
          ;; ... parsing logic ...
          (fd/flow-dissector-ok)))))
```

## Attaching to Network Namespace

```clojure
(require '[clj-ebpf.programs :as progs])

;; Load program
(def prog
  (progs/load-program
    {:prog-type :flow-dissector
     :insns bytecode
     :license "GPL"}))

;; Attach to current namespace
(progs/attach-flow-dissector prog {})

;; Or specific namespace
(progs/attach-flow-dissector prog {:netns-path "/proc/1234/ns/net"})
```

## DSL Reference

### Context and Setup

| Function | Description |
|----------|-------------|
| `flow-dissector-prologue` | Save context, load data/data_end |
| `flow-dissector-get-flow-keys-ptr` | Get flow_keys output pointer |
| `flow-dissector-load-ctx-field` | Load __sk_buff field |

### Flow Keys Writing

| Function | Description |
|----------|-------------|
| `flow-keys-set-nhoff` | Set network header offset |
| `flow-keys-set-thoff` | Set transport header offset |
| `flow-keys-set-addr-proto` | Set address protocol (ETH_P_*) |
| `flow-keys-set-ip-proto` | Set IP protocol (TCP/UDP) |
| `flow-keys-set-n-proto` | Set network protocol |
| `flow-keys-set-ports` | Set source and dest ports |
| `flow-keys-set-ipv4-addrs` | Set IPv4 addresses |
| `flow-keys-set-is-frag` | Set fragment flag |
| `flow-keys-set-is-encap` | Set encapsulation flag |

### Flow Keys Reading

| Function | Description |
|----------|-------------|
| `flow-keys-load-u8` | Load 8-bit field |
| `flow-keys-load-u16` | Load 16-bit field |
| `flow-keys-load-u32` | Load 32-bit field |

### Parsing Helpers

| Function | Description |
|----------|-------------|
| `flow-dissector-parse-ethernet` | Parse Ethernet header |
| `flow-dissector-parse-ipv4` | Parse IPv4 header |
| `flow-dissector-parse-tcp-ports` | Parse TCP ports |
| `flow-dissector-parse-udp-ports` | Parse UDP ports |
| `flow-dissector-bounds-check` | Packet bounds check |

### Return Patterns

| Function | Returns | Description |
|----------|---------|-------------|
| `flow-dissector-ok` | 0 | BPF_OK - success |
| `flow-dissector-drop` | -1 | BPF_DROP - stop dissection |

## bpf_flow_keys Structure

```
struct bpf_flow_keys {
    __u16 nhoff;           // offset 0:  Network header offset
    __u16 thoff;           // offset 2:  Transport header offset
    __u16 addr_proto;      // offset 4:  ETH_P_IP (0x0800) or ETH_P_IPV6
    __u8  is_frag;         // offset 6:  Is fragment
    __u8  is_first_frag;   // offset 7:  Is first fragment
    __u8  is_encap;        // offset 8:  Is encapsulated
    __u8  ip_proto;        // offset 9:  TCP (6), UDP (17)
    __be16 n_proto;        // offset 10: Network protocol
    __be16 sport;          // offset 12: Source port
    __be16 dport;          // offset 14: Destination port
    union {
        struct {
            __be32 ipv4_src;   // offset 16
            __be32 ipv4_dst;   // offset 20
        };
        struct {
            __u32 ipv6_src[4]; // offset 16
            __u32 ipv6_dst[4]; // offset 32
        };
    };
    __u32 flags;           // offset 48
    __be32 flow_label;     // offset 52 (IPv6)
};
```

## Complete Examples

### Basic Ethernet/IPv4 Dissector

```clojure
(def ipv4-dissector
  (dsl/assemble
    (vec (concat
          (fd/flow-dissector-prologue :r6 :r2 :r3)
          [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
          (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)
          (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)
          (fd/flow-dissector-ok)))))
```

### Full 5-Tuple Dissector

```clojure
(def full-dissector
  (dsl/assemble
    (vec (concat
          (fd/flow-dissector-prologue :r6 :r2 :r3)
          [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
          (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)
          (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)
          (fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)
          (fd/flow-dissector-ok)))))
```

### Using Program Builder

```clojure
(def custom-dissector
  (fd/build-flow-dissector-program
    {:ctx-reg :r6
     :data-reg :r2
     :data-end-reg :r3
     :body [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)
            (dsl/mov :r0 14)
            (fd/flow-keys-set-nhoff :r7 :r0)]
     :default-action :ok}))
```

## Protocol Constants

### Ethernet (ETH_P_*)

| Protocol | Value |
|----------|-------|
| IPv4 | 0x0800 |
| IPv6 | 0x86DD |
| ARP | 0x0806 |
| VLAN | 0x8100 |
| MPLS | 0x8847 |

### IP Protocols

| Protocol | Value |
|----------|-------|
| ICMP | 1 |
| TCP | 6 |
| UDP | 17 |
| GRE | 47 |
| ICMPv6 | 58 |
| SCTP | 132 |

### Header Sizes

| Header | Size (bytes) |
|--------|--------------|
| Ethernet | 14 |
| IPv4 (min) | 20 |
| IPv6 | 40 |
| TCP (min) | 20 |
| UDP | 8 |

## Kernel Version Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| FLOW_DISSECTOR programs | 4.2 |
| BPF link attachment | 5.0 |
| Full feature support | 5.8+ |

## Troubleshooting

### Common Issues

1. **"Permission denied"** - Need root or CAP_NET_ADMIN + CAP_BPF

2. **"Operation not permitted"** - Kernel 5.0+ required for BPF link

3. **Bounds check errors** - Add bounds checks before packet access

4. **Flow hashing not working** - Verify all 5-tuple fields are set

### Debugging Commands

```bash
# List FLOW_DISSECTOR programs
sudo bpftool prog list | grep flow_dissector

# List BPF links
sudo bpftool link list

# Check kernel version
uname -r
```

## See Also

- [Quick Start Tutorial](../tutorials/quick-start-flow-dissector.md)
- [Example: flow_dissector_custom.clj](../examples/flow_dissector_custom.clj)
- [SK_LOOKUP Guide](sk-lookup-guide.md)
