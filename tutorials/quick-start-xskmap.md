# Quick Start: AF_XDP Zero-Copy Networking with XSKMAP

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Learning Objectives

By the end of this tutorial, you will:
- Understand AF_XDP architecture and zero-copy packet delivery
- Know when to use XSKMAP for high-performance networking
- Build XDP programs that redirect to AF_XDP sockets
- Use DSL helpers for XSK redirection patterns
- Understand the complete AF_XDP setup workflow

## Prerequisites

- Basic clj-ebpf knowledge (maps, programs, DSL)
- Understanding of XDP programs
- Familiarity with network packet processing
- Linux kernel 4.18+ (5.3+ recommended)
- Root privileges for running examples

## Introduction

### What is AF_XDP?

AF_XDP (Address Family XDP) is a high-performance networking technology that enables:

- **Zero-copy packet delivery** - Packets go directly to userspace memory
- **Kernel bypass** - Skip the TCP/IP stack for matched packets
- **Millions of packets per second** - 10x-100x faster than traditional sockets
- **Sub-microsecond latency** - Minimal processing overhead

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       Userspace                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Application                             │    │
│  │   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌───────┐ │    │
│  │   │  Fill   │  │Complete │  │   RX    │  │  TX   │ │    │
│  │   │  Ring   │  │  Ring   │  │  Ring   │  │ Ring  │ │    │
│  │   └────┬────┘  └────┬────┘  └────┬────┘  └───┬───┘ │    │
│  └────────┼───────────┼───────────┼────────────┼─────┘    │
│           └───────────┴───────────┴────────────┘           │
│                           │                                 │
│                      UMEM (Shared Memory)                   │
└───────────────────────────┼─────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────┐
│                       Kernel                                 │
│  ┌────────────────────────┼────────────────────────────┐    │
│  │                 XDP Program                          │    │
│  │    if (match) bpf_redirect_map(&xskmap, queue, 0)   │    │
│  └────────────────────────┼────────────────────────────┘    │
│                           │                                  │
│  ┌────────────────────────┼────────────────────────────┐    │
│  │                    XSKMAP                            │    │
│  │  [0] -> XSK socket for queue 0                      │    │
│  │  [1] -> XSK socket for queue 1                      │    │
│  └────────────────────────┼────────────────────────────┘    │
│                           │                                  │
│  ┌────────────────────────┼────────────────────────────┐    │
│  │                 NIC Driver                           │    │
│  │            RX Queue 0  RX Queue 1  ...              │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Purpose |
|-----------|---------|
| **XSKMAP** | BPF map linking queue indices to XSK sockets |
| **UMEM** | Shared memory region for packet buffers |
| **Fill Ring** | App provides empty buffers to kernel |
| **RX Ring** | Kernel delivers received packets to app |
| **TX Ring** | App submits packets for transmission |
| **Completion Ring** | Kernel notifies app of TX completion |

---

## Part 1: Understanding XSKMAP

### What is XSKMAP?

XSKMAP is a BPF map type that stores references to AF_XDP sockets. XDP programs use `bpf_redirect_map()` with XSKMAP to redirect packets to userspace.

```clojure
(require '[clj-ebpf.maps :as maps])

;; Create XSKMAP for 4 RX queues
(def xsk-map (maps/create-xsk-map 4 :map-name "xsks_map"))
```

### Map Structure

- **Key**: Queue index (u32) - typically matches the NIC's RX queue
- **Value**: XSK socket file descriptor (kernel converts to internal structure)
- **Max entries**: Number of RX queues you want to support

### When to Use XSKMAP

| Use Case | Benefit |
|----------|---------|
| Packet capture | Zero-copy capture at line rate |
| Custom protocols | Bypass kernel stack for custom processing |
| Load balancers | High-throughput L4 load balancing |
| Network functions | NFV with minimal latency |
| Trading systems | Ultra-low latency market data |

---

## Part 2: XDP Programs for XSKMAP

### Basic Redirect Pattern

The simplest pattern redirects all packets to XSK based on their RX queue:

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.xdp :as xdp])

;; XDP program: redirect all packets to XSK
(def redirect-all-insns
  [(dsl/mov-reg :r6 :r1)           ; Save context (xdp_md)
   (dsl/ldx :w :r4 :r6 16)         ; r4 = xdp_md->rx_queue_index
   (dsl/ld-map-fd :r1 5)           ; r1 = xskmap fd (placeholder)
   (dsl/mov-reg :r2 :r4)           ; r2 = key (queue index)
   (dsl/mov :r3 2)                 ; r3 = flags (XDP_PASS fallback)
   (dsl/call 51)                   ; bpf_redirect_map
   (dsl/exit-insn)])               ; Return result
```

### Using DSL Helpers

clj-ebpf provides convenient helpers for XSK redirection:

```clojure
;; Redirect to XSK at specific queue index
(xdp/xdp-redirect-to-xsk map-fd 0)
;; Returns instructions with exit

;; Redirect using queue index from register
(xdp/xdp-redirect-to-xsk map-fd :r4)

;; Complete pattern: load queue index and redirect
(xdp/xdp-redirect-to-xsk-by-queue :r6 map-fd)
;; Loads rx_queue_index from context and redirects
```

### XDP Context Fields

The `xdp_md` context contains the RX queue index needed for XSKMAP:

```clojure
;; xdp_md structure offsets
(xdp/xdp-md-offset :data)            ; => 0
(xdp/xdp-md-offset :data-end)        ; => 4
(xdp/xdp-md-offset :data-meta)       ; => 8
(xdp/xdp-md-offset :ingress-ifindex) ; => 12
(xdp/xdp-md-offset :rx-queue-index)  ; => 16  <-- Key for XSKMAP
(xdp/xdp-md-offset :egress-ifindex)  ; => 20

;; Load rx_queue_index
(xdp/xdp-load-ctx-field :r1 :rx-queue-index :r4)
;; Generates: ldx w r4 r1 16
```

---

## Part 3: Building XDP Programs

### Complete Redirect-All Program

```clojure
(defn build-xsk-redirect-all
  "Build XDP program that redirects all packets to XSK."
  [map-fd]
  (dsl/assemble
    (vec (concat
          ;; Save context
          [(dsl/mov-reg :r6 :r1)]
          ;; Load rx_queue_index
          [(dsl/ldx :w :r4 :r6 16)]
          ;; Redirect to XSK at queue index
          (xdp/xdp-redirect-to-xsk map-fd :r4)))))

;; Usage:
(def bytecode (build-xsk-redirect-all (:fd xsk-map)))
```

### Selective Redirect (Filter Specific Traffic)

```clojure
(defn build-xsk-udp-only
  "Redirect only UDP packets to XSK, pass others to kernel."
  [map-fd]
  (dsl/assemble
    [(dsl/mov-reg :r6 :r1)
     ;; Load data pointers
     (dsl/ldx :w :r2 :r6 0)      ; data
     (dsl/ldx :w :r3 :r6 4)      ; data_end

     ;; Bounds check: Ethernet + IP headers (34 bytes)
     (dsl/mov-reg :r0 :r2)
     (dsl/add :r0 34)
     (dsl/jmp-reg :jgt :r0 :r3 2)
     (dsl/mov :r0 2)             ; XDP_PASS
     (dsl/exit-insn)

     ;; Check IP protocol at offset 23 (UDP = 17)
     (dsl/ldx :b :r4 :r2 23)
     (dsl/jmp-imm :jne :r4 17 2)
     (dsl/mov :r0 2)             ; XDP_PASS if not UDP
     (dsl/exit-insn)

     ;; UDP packet - redirect to XSK
     (dsl/ldx :w :r4 :r6 16)     ; rx_queue_index
     (dsl/ld-map-fd :r1 map-fd)
     (dsl/mov-reg :r2 :r4)
     (dsl/mov :r3 2)             ; fallback = XDP_PASS
     (dsl/call 51)
     (dsl/exit-insn)]))
```

### Using Declarative Macros

```clojure
(require '[clj-ebpf.macros :refer [defmap-spec defprogram]])

(defmap-spec xsk-sockets
  "XSKMAP for AF_XDP sockets"
  :type :xskmap
  :key-size 4
  :value-size 4
  :max-entries 64)

(defprogram xdp-xsk-redirect
  "Redirect all packets to XSK by queue"
  :type :xdp
  :license "GPL"
  :body [(dsl/mov-reg :r6 :r1)
         (dsl/ldx :w :r4 :r6 16)
         (dsl/ld-map-fd :r1 0)    ; Placeholder
         (dsl/mov-reg :r2 :r4)
         (dsl/mov :r3 2)
         (dsl/call 51)
         (dsl/exit-insn)])
```

---

## Part 4: Complete AF_XDP Setup

### Step-by-Step Process

```clojure
;; 1. Create XSKMAP
(def xsk-map (maps/create-xsk-map 4 :map-name "xsks"))

;; 2. Build and load XDP program
(def xdp-bytecode (build-xsk-redirect-all (:fd xsk-map)))
(def xdp-prog
  (bpf/load-program
    {:prog-type :xdp
     :insns xdp-bytecode
     :license "GPL"
     :prog-name "xsk_redirect"}))

;; 3. Attach XDP program to interface
(bpf/attach-xdp xdp-prog "eth0" :mode :skb)  ; or :native

;; 4. Create AF_XDP sockets (external to clj-ebpf)
;; For each RX queue:
;;   fd = socket(AF_XDP, SOCK_RAW, 0)
;;   bind(fd, interface, queue)
;;   maps/map-update xsk-map queue-idx fd

;; 5. Process packets from XSK RX ring
;; poll(xsk_fd) -> read from RX ring -> process
```

### What clj-ebpf Provides

| Component | clj-ebpf Support |
|-----------|------------------|
| XSKMAP creation | `create-xsk-map` |
| XDP program building | DSL + helpers |
| XDP attachment | `attach-xdp` |
| Map updates | `map-update` |

### What Requires External Tools

| Component | External Library |
|-----------|-----------------|
| AF_XDP socket creation | libbpf, libxdp, or raw syscalls |
| UMEM setup | mmap + setsockopt |
| Ring buffer management | libxdp or custom implementation |

---

## Part 5: DSL Reference

### XSKMAP Functions

```clojure
;; Create XSKMAP
(maps/create-xsk-map max-entries :map-name "name")
```

### XDP Redirect Helpers

```clojure
;; Redirect to XSK at index (immediate or register)
(xdp/xdp-redirect-to-xsk map-fd key)
(xdp/xdp-redirect-to-xsk map-fd key flags)

;; Redirect by rx_queue_index (common pattern)
(xdp/xdp-redirect-to-xsk-by-queue ctx-reg map-fd)
(xdp/xdp-redirect-to-xsk-by-queue ctx-reg map-fd tmp-reg)
(xdp/xdp-redirect-to-xsk-by-queue ctx-reg map-fd tmp-reg flags)

;; Generic redirect_map (works with DEVMAP, CPUMAP, XSKMAP)
(xdp/xdp-redirect-map map-fd key flags)
(xdp/xdp-redirect-map-with-action map-fd key flags)
```

### Context Field Access

```clojure
;; Load any xdp_md field
(xdp/xdp-load-ctx-field ctx-reg field dst-reg)

;; Available fields
:data            ; Packet data start
:data-end        ; Packet data end
:data-meta       ; Metadata area
:ingress-ifindex ; Ingress interface
:rx-queue-index  ; RX queue (for XSKMAP key)
:egress-ifindex  ; Egress interface
```

---

## Part 6: Performance Optimization

### XDP Modes

```clojure
;; SKB mode - works everywhere, lower performance
(bpf/attach-xdp prog "eth0" :mode :skb)

;; Native mode - requires driver support, best performance
(bpf/attach-xdp prog "eth0" :mode :native)

;; Offload mode - runs on NIC hardware (limited support)
(bpf/attach-xdp prog "eth0" :mode :offload)
```

### Best Practices

1. **Match XSK sockets to RX queues**
   ```clojure
   ;; One XSK socket per queue for best performance
   (doseq [queue (range num-queues)]
     (maps/map-update xsk-map queue (create-xsk-socket queue)))
   ```

2. **Pin threads to CPUs**
   ```
   Queue 0 -> CPU 0 -> XSK thread 0
   Queue 1 -> CPU 1 -> XSK thread 1
   ```

3. **Use busy polling for lowest latency**

4. **Batch operations on rings**

5. **Size UMEM appropriately** (4096+ frames typical)

---

## Part 7: Troubleshooting

### Common Issues

1. **"Permission denied"**
   - Run with root or CAP_NET_ADMIN + CAP_BPF

2. **"Invalid argument" on map update**
   - XSK socket must be bound before adding to XSKMAP
   - Queue index must be valid

3. **No packets received**
   - Verify XDP program is attached: `ip link show`
   - Check XSK socket is in map: `bpftool map dump`
   - Ensure packets match filter criteria

4. **Poor performance**
   - Use native XDP mode if supported
   - Check CPU pinning
   - Verify no packet drops: `ethtool -S`

### Debugging

```bash
# List XDP programs
sudo bpftool prog list | grep xdp

# List maps
sudo bpftool map list | grep xskmap

# Dump XSKMAP contents
sudo bpftool map dump id <map-id>

# Check XDP attachment
ip link show eth0
```

---

## Summary

You learned how to:
- Create XSKMAP for AF_XDP socket storage
- Build XDP programs that redirect to XSK
- Use DSL helpers for common XSK patterns
- Understand the complete AF_XDP architecture
- Optimize for high performance

---

## Next Steps

- **[XDP Redirect Tutorial](quick-start-xdp-redirect.md)** - DEVMAP and CPUMAP
- **[Socket Redirect Tutorial](quick-start-sockmap.md)** - SOCKMAP/SOCKHASH
- **[Performance Guide](../docs/guides/performance.md)** - Optimization techniques

---

## Reference

### Kernel Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| XSKMAP | 4.18 |
| AF_XDP | 4.18 |
| Need-wakeup flag | 5.3 |
| Shared UMEM | 5.4 |
| Multi-buffer XDP | 5.11 |

### Helper Functions

| Helper | ID | Description |
|--------|-----|-------------|
| `bpf_redirect_map` | 51 | Redirect to DEVMAP/CPUMAP/XSKMAP |

### Related Resources

- [Kernel AF_XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [libxdp](https://github.com/xdp-project/xdp-tools/tree/master/lib/libxdp)
- [AF_XDP Tutorial](https://github.com/xdp-project/xdp-tutorial/tree/master/advanced03-AF_XDP)
