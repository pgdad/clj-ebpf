# XSKMAP Guide: AF_XDP Zero-Copy Networking

This guide covers XSKMAP for high-performance packet delivery to userspace using AF_XDP.

## Overview

XSKMAP (XDP Socket Map) is the kernel-side component of AF_XDP, enabling:

- **Zero-copy packet delivery** - Packets go directly to userspace memory
- **Kernel bypass** - Skip TCP/IP stack for matched packets
- **High throughput** - Millions of packets per second
- **Low latency** - Sub-microsecond delivery

## Creating XSKMAP

```clojure
(require '[clj-ebpf.maps :as maps])

(def xsk-map
  (maps/create-xsk-map max-entries
    :map-name "xsks_map"))   ; Optional BPF map name
```

**Parameters:**
- `max-entries` - Number of XSK sockets (typically matches RX queues)
- `:map-name` - Optional name for the BPF map

**Map Structure:**
- Key: u32 queue index
- Value: XSK socket file descriptor

## XDP Redirect to XSK

### Basic Redirect

```clojure
(require '[clj-ebpf.dsl.xdp :as xdp])

;; Redirect to XSK at specific queue index
(xdp/xdp-redirect-to-xsk map-fd 0)
;; Returns instructions ending with exit

;; Redirect using queue index from register
(xdp/xdp-redirect-to-xsk map-fd :r4)
```

### Redirect by RX Queue (Common Pattern)

```clojure
;; Load rx_queue_index and redirect to matching XSK
(xdp/xdp-redirect-to-xsk-by-queue ctx-reg map-fd)

;; With custom temp register and fallback flags
(xdp/xdp-redirect-to-xsk-by-queue ctx-reg map-fd :r5 2)
```

### Loading RX Queue Index

```clojure
;; Load rx_queue_index from xdp_md context
(xdp/xdp-load-ctx-field :r1 :rx-queue-index :r4)
;; Generates: ldx w r4 r1 16
```

## DSL Reference

### Map Functions

| Function | Description |
|----------|-------------|
| `maps/create-xsk-map` | Create XSKMAP for AF_XDP |

### XDP Helpers

| Function | Description |
|----------|-------------|
| `xdp/xdp-redirect-to-xsk` | Redirect to XSK at index |
| `xdp/xdp-redirect-to-xsk-by-queue` | Redirect based on rx_queue_index |
| `xdp/xdp-redirect-map` | Generic redirect_map helper |
| `xdp/xdp-load-ctx-field` | Load xdp_md fields |

### xdp_md Context Offsets

| Field | Offset | Description |
|-------|--------|-------------|
| `:data` | 0 | Packet data start |
| `:data-end` | 4 | Packet data end |
| `:data-meta` | 8 | Metadata area |
| `:ingress-ifindex` | 12 | Ingress interface |
| `:rx-queue-index` | 16 | RX queue (XSKMAP key) |
| `:egress-ifindex` | 20 | Egress interface |

## Complete Examples

### Redirect All Packets

```clojure
(ns example.xsk-all
  (:require [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as progs]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.xdp :as xdp]))

;; 1. Create XSKMAP
(def xsk-map (maps/create-xsk-map 4 :map-name "xsks"))

;; 2. Build XDP program
(def xdp-bytecode
  (dsl/assemble
    (vec (concat
          ;; Save context, load rx_queue_index
          [(dsl/mov-reg :r6 :r1)
           (dsl/ldx :w :r4 :r6 16)]
          ;; Redirect to XSK at queue index
          (xdp/xdp-redirect-to-xsk (:fd xsk-map) :r4)))))

;; 3. Load and attach
(def xdp-prog
  (progs/load-program
    {:prog-type :xdp
     :insns xdp-bytecode
     :license "GPL"}))

(progs/attach-xdp xdp-prog "eth0" :mode :native)

;; 4. Add XSK sockets to map (after creating AF_XDP sockets)
;; (maps/map-update xsk-map 0 xsk-fd-queue-0)
;; (maps/map-update xsk-map 1 xsk-fd-queue-1)
```

### Selective Redirect (UDP Only)

```clojure
(def xdp-udp-only
  (dsl/assemble
    [(dsl/mov-reg :r6 :r1)
     ;; Load data pointers
     (dsl/ldx :w :r2 :r6 0)
     (dsl/ldx :w :r3 :r6 4)

     ;; Bounds check for Ethernet + IP (34 bytes)
     (dsl/mov-reg :r0 :r2)
     (dsl/add :r0 34)
     (dsl/jmp-reg :jgt :r0 :r3 2)
     (dsl/mov :r0 2)           ; XDP_PASS
     (dsl/exit-insn)

     ;; Check IP protocol (offset 23) - UDP = 17
     (dsl/ldx :b :r4 :r2 23)
     (dsl/jmp-imm :jne :r4 17 2)
     (dsl/mov :r0 2)           ; XDP_PASS if not UDP
     (dsl/exit-insn)

     ;; UDP - redirect to XSK
     (dsl/ldx :w :r4 :r6 16)   ; rx_queue_index
     (dsl/ld-map-fd :r1 xsk-map-fd)
     (dsl/mov-reg :r2 :r4)
     (dsl/mov :r3 2)           ; XDP_PASS fallback
     (dsl/call 51)
     (dsl/exit-insn)]))
```

## AF_XDP Architecture

```
                    Userspace
    ┌─────────────────────────────────────────┐
    │            Application                   │
    │  ┌────────┐ ┌────────┐ ┌────┐ ┌────┐   │
    │  │ Fill   │ │Complete│ │ RX │ │ TX │   │
    │  │ Ring   │ │ Ring   │ │Ring│ │Ring│   │
    │  └───┬────┘ └───┬────┘ └──┬─┘ └──┬─┘   │
    └──────┴──────────┴─────────┴──────┴──────┘
                      │
                 UMEM (Shared)
                      │
    ┌─────────────────┴────────────────────────┐
    │                Kernel                     │
    │  ┌────────────────────────────────────┐  │
    │  │           XDP Program               │  │
    │  │  bpf_redirect_map(&xskmap, q, 0)   │  │
    │  └─────────────────┬──────────────────┘  │
    │                    │                      │
    │  ┌─────────────────┴──────────────────┐  │
    │  │             XSKMAP                  │  │
    │  │  [0] -> XSK queue 0                │  │
    │  │  [1] -> XSK queue 1                │  │
    │  └─────────────────┬──────────────────┘  │
    │                    │                      │
    │  ┌─────────────────┴──────────────────┐  │
    │  │           NIC Driver                │  │
    │  │      Queue 0    Queue 1   ...      │  │
    │  └────────────────────────────────────┘  │
    └──────────────────────────────────────────┘
```

## Kernel Version Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| XSKMAP | 4.18 |
| AF_XDP | 4.18 |
| Need-wakeup flag | 5.3 |
| Shared UMEM | 5.4 |
| Multi-buffer XDP | 5.11 |

## Helper Function ID

| Helper | ID | Description |
|--------|-----|-------------|
| `bpf_redirect_map` | 51 | Redirect to DEVMAP/CPUMAP/XSKMAP |

## Performance Tips

1. **Use native XDP mode** for best performance
2. **Pin XSK threads to CPUs** matching RX queues
3. **Enable busy polling** for lowest latency
4. **Batch ring operations** for throughput
5. **Size UMEM appropriately** (4096+ frames)

## Troubleshooting

### Common Issues

1. **"Permission denied"** - Need root or CAP_NET_ADMIN + CAP_BPF
2. **"Invalid argument" on map update** - XSK must be bound first
3. **No packets received** - Check XDP attachment and map contents

### Debugging Commands

```bash
# List XDP programs
sudo bpftool prog list | grep xdp

# List maps
sudo bpftool map list

# Dump XSKMAP
sudo bpftool map dump id <id>

# Check XDP on interface
ip link show eth0
```

## See Also

- [Quick Start Tutorial](../tutorials/quick-start-xskmap.md)
- [Example: xdp_xsk_redirect.clj](../examples/xdp_xsk_redirect.clj)
- [XDP Redirect Guide](xdp-redirect-guide.md)
- [SOCKMAP Guide](sockmap-guide.md)
