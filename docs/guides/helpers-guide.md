# BPF Helper Functions Guide

This guide covers the comprehensive set of helper functions available in clj-ebpf for building production-ready BPF programs. These helpers generate optimized BPF instruction sequences for common operations.

## Table of Contents

1. [Packet Bounds Checking](#1-packet-bounds-checking)
2. [Checksum Calculation](#2-checksum-calculation)
3. [Ring Buffer Operations](#3-ring-buffer-operations)
4. [IPv6 Address Loading](#4-ipv6-address-loading)
5. [Time and Random Numbers](#5-time-and-random-numbers)
6. [Token Bucket Rate Limiting](#6-token-bucket-rate-limiting)
7. [Memory Operations](#7-memory-operations)
8. [BPF Map Helpers](#8-bpf-map-helpers)

---

## 1. Packet Bounds Checking

**Namespace:** `clj-ebpf.net.bounds`

Bounds checking is **critical** for BPF verifier acceptance. Every packet access must be verified to be within bounds before reading or writing data.

### Core Functions

```clojure
(require '[clj-ebpf.net.bounds :as bounds])

;; Basic bounds check with numeric jump offset
(bounds/build-bounds-check data-reg end-reg offset size fail-jump-offset)

;; Bounds check with label-based jump (use with asm/assemble-with-labels)
(bounds/build-bounds-check-label data-reg end-reg offset size fail-label)
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `data-reg` | Register containing packet data start (e.g., `:r6`) |
| `end-reg` | Register containing packet data end (e.g., `:r7`) |
| `offset` | Byte offset from data start |
| `size` | Number of bytes to access |
| `fail-jump-offset` | Instructions to jump forward on failure |
| `fail-label` | Keyword label to jump to on failure |

### Convenience Functions

```clojure
;; Check for specific header types
(bounds/check-eth-header :r6 :r7 :drop)    ; 14 bytes
(bounds/check-ipv4-header :r6 :r7 :drop)   ; 20 bytes after ETH
(bounds/check-ipv6-header :r6 :r7 :drop)   ; 40 bytes after ETH
(bounds/check-tcp-header :r6 :r7 l4-off :drop)
(bounds/check-udp-header :r6 :r7 l4-off :drop)
```

### Example: XDP with Bounds Checking

```clojure
(def xdp-program
  (concat
    ;; Load packet pointers
    [(dsl/ldx :dw :r6 :r1 0)    ; data
     (dsl/ldx :dw :r7 :r1 8)]   ; data_end

    ;; Check Ethernet header
    (bounds/check-eth-header :r6 :r7 :drop)

    ;; Check IPv4 header (34 bytes total)
    (bounds/build-bounds-check-label :r6 :r7 0 34 :drop)

    ;; Process packet...
    [(dsl/mov :r0 2)  ; XDP_PASS
     (dsl/exit-insn)]

    [(asm/label :drop)
     (dsl/mov :r0 1)  ; XDP_DROP
     (dsl/exit-insn)]))
```

---

## 2. Checksum Calculation

**Namespace:** `clj-ebpf.net.checksum`

Checksums must be updated when modifying packet headers. The kernel provides efficient helper functions for incremental checksum updates.

### Constants

```clojure
checksum/BPF-F-PSEUDO-HDR      ; 0x10 - Include pseudo-header in L4 checksum
checksum/BPF-F-MARK-MANGLED-0  ; 0x20 - Mark checksum as mangled
checksum/BPF-F-MARK-ENFORCE    ; 0x40 - Enforce checksum verification
checksum/BPF-F-RECOMPUTE-CSUM  ; 0x01 - Recompute full checksum (expensive)
```

### L3 Checksum (IP Header) - TC/SKB Only

```clojure
;; Update IP checksum for 4-byte value change
(checksum/l3-csum-replace-4 skb-reg csum-offset old-val-reg new-val-reg)

;; Update IP checksum for 2-byte value change
(checksum/l3-csum-replace-2 skb-reg csum-offset old-val-reg new-val-reg)
```

### L4 Checksum (TCP/UDP) - TC/SKB Only

```clojure
;; Update TCP/UDP checksum for 4-byte value change
(checksum/l4-csum-replace-4 skb-reg csum-offset old-val-reg new-val-reg pseudo-hdr?)

;; Update TCP/UDP checksum for 2-byte value change
(checksum/l4-csum-replace-2 skb-reg csum-offset old-val-reg new-val-reg pseudo-hdr?)
```

### Checksum Diff (XDP Compatible)

```clojure
;; Calculate checksum difference
(checksum/csum-diff from-ptr-reg from-size to-ptr-reg to-size seed-reg)
```

### Example: NAT Checksum Update

```clojure
;; After changing source IP in a NAT operation:
(concat
  ;; 1. Update IP header checksum
  (checksum/l3-csum-replace-4 :r6 24 :r2 :r3)

  ;; 2. Update TCP checksum with pseudo-header flag
  (checksum/l4-csum-replace-4 :r6 50 :r2 :r3 true))
```

---

## 3. Ring Buffer Operations

**Namespace:** `clj-ebpf.ringbuf`

Ring buffers are the modern way to stream events from BPF to userspace, replacing the older perf buffers.

### Constants

```clojure
ringbuf/BPF-RB-NO-WAKEUP      ; 1 - Don't wake up userspace
ringbuf/BPF-RB-FORCE-WAKEUP   ; 2 - Force wakeup
```

### Core Operations

```clojure
;; Reserve space in ring buffer
(ringbuf/build-ringbuf-reserve map-fd size flags)
;; Returns: pointer to reserved space in r0, or NULL

;; Submit reserved data
(ringbuf/build-ringbuf-submit data-ptr-reg flags)

;; Discard reserved data (on error)
(ringbuf/build-ringbuf-discard data-ptr-reg flags)

;; Direct output (reserve + copy + submit)
(ringbuf/build-ringbuf-output map-fd stack-offset size flags)
```

### Example: Event Streaming

```clojure
(def event-emitter
  (concat
    ;; Reserve 64 bytes
    (ringbuf/build-ringbuf-reserve 10 64 0)

    ;; Check if reservation succeeded
    [(asm/jmp-imm :jeq :r0 0 :no_space)]
    [(dsl/mov-reg :r6 :r0)]  ; Save pointer

    ;; Fill event data
    [(dsl/mov :r0 1)
     (dsl/stx :w :r6 :r0 0)]  ; event_type = 1

    (time/build-ktime-get-ns)
    [(dsl/stx :dw :r6 :r0 8)]  ; timestamp

    ;; Submit event
    (ringbuf/build-ringbuf-submit :r6 0)

    [(dsl/mov :r0 0)
     (dsl/exit-insn)]

    [(asm/label :no_space)
     (dsl/mov :r0 1)
     (dsl/exit-insn)]))
```

---

## 4. IPv6 Address Loading

**Namespace:** `clj-ebpf.net.ipv6`

IPv6 addresses are 128-bit and require special handling. These helpers also support dual-stack scenarios with IPv4-mapped IPv6 addresses.

### Constants

```clojure
ipv6/IPV6-HLEN      ; 40 - IPv6 header length
ipv6/IPV6-ADDR-LEN  ; 16 - IPv6 address length
ipv6/IPV6-OFF-SRC   ; 8  - Source address offset in IPv6 header
ipv6/IPV6-OFF-DST   ; 24 - Destination address offset in IPv6 header
```

### Core Operations

```clojure
;; Load 16-byte IPv6 address from packet to stack
(ipv6/build-load-ipv6-address pkt-ptr-reg offset stack-offset)

;; Load IPv4 address in IPv6-compatible format (::ffff:x.x.x.x)
(ipv6/build-load-ipv4-unified pkt-ptr-reg offset stack-offset)

;; Copy IPv6 address between stack locations
(ipv6/build-copy-ipv6-address src-stack-off dst-stack-off)
```

### Convenience Functions

```clojure
;; Load source/dest from IPv6 header
(ipv6/build-load-ipv6-src ipv6-hdr-reg stack-offset)
(ipv6/build-load-ipv6-dst ipv6-hdr-reg stack-offset)

;; Load IPv4 source/dest in unified format
(ipv6/build-load-ipv4-src-unified ipv4-hdr-reg stack-offset)
(ipv6/build-load-ipv4-dst-unified ipv4-hdr-reg stack-offset)
```

### Example: Dual-Stack Key Building

```clojure
;; Build a 16-byte key for map lookup that works for both IPv4 and IPv6
(concat
  ;; Zero the key area first
  (mem/build-zero-bytes -32 16)

  ;; Check ethertype and load address
  [(dsl/ldx :h :r0 :r7 12)]
  [(asm/jmp-imm :jne :r0 0xDD86 :ipv4)]  ; 0x86DD = IPv6 (big-endian)

  ;; IPv6: Load source address
  (ipv6/build-load-ipv6-address :r7 22 -32)
  [(asm/jmp :lookup)]

  ;; IPv4: Load source in unified format
  [(asm/label :ipv4)]
  (ipv6/build-load-ipv4-unified :r7 26 -32)

  [(asm/label :lookup)]
  ;; Now stack[-32] has 16-byte key for either protocol
  (maps/build-map-lookup 10 -32))
```

---

## 5. Time and Random Numbers

**Namespace:** `clj-ebpf.time`

Essential for rate limiting, timeouts, connection tracking, and load balancing.

### Time Functions

```clojure
;; Get monotonic timestamp (nanoseconds)
(time/build-ktime-get-ns)

;; Alternative time sources
(time/build-ktime-get-boot-ns)    ; Includes suspend time
(time/build-ktime-get-coarse-ns)  ; Lower overhead, less precise
(time/build-ktime-get-tai-ns)     ; TAI (no leap seconds)
(time/build-jiffies64)            ; Kernel jiffies counter
```

### Random Number Generation

```clojure
;; Get random 32-bit value
(time/build-get-prandom-u32)

;; Get random value in range [0, n-1]
(time/build-random-mod n)

;; Get random percentage [0-99]
(time/build-random-percentage)

;; Get random boolean (0 or 1)
(time/build-random-bool)
```

### Convenience Patterns

```clojure
;; Store timestamp to stack location
(time/build-store-timestamp stack-offset)

;; Load elapsed time since stored timestamp
(time/build-load-elapsed-ns stack-offset dest-reg)

;; Update timestamp in structure
(time/build-update-timestamp ptr-reg field-offset)
```

### Example: Weighted Load Balancing

```clojure
(def weighted-lb
  (concat
    ;; Get random percentage [0-99]
    (time/build-random-weighted-select)

    ;; Backend selection: 30% -> B0, 50% -> B1, 20% -> B2
    [(dsl/jmp-imm :jlt :r0 30 4)   ; if r0 < 30, backend 0
     (dsl/jmp-imm :jlt :r0 80 2)   ; if r0 < 80, backend 1
     (dsl/mov :r0 2)               ; backend 2
     (dsl/exit-insn)
     (dsl/mov :r0 0)               ; backend 0
     (dsl/exit-insn)
     (dsl/mov :r0 1)               ; backend 1
     (dsl/exit-insn)]))
```

---

## 6. Token Bucket Rate Limiting

**Namespace:** `clj-ebpf.rate-limit`

Comprehensive rate limiting using the token bucket algorithm for DDoS protection, API rate limiting, and traffic shaping.

### Constants

```clojure
rate-limit/TOKEN-SCALE    ; 1000 - For sub-second precision
rate-limit/NS-PER-SEC     ; 1000000000
rate-limit/US-PER-SEC     ; 1000000
rate-limit/MAX-ELAPSED-US ; 10000000 - Overflow protection
```

### Simple Rate Limiting (Hardcoded Rate)

```clojure
;; rate and burst are in requests/second
(rate-limit/build-simple-rate-limit
  bucket-map-fd   ; FD for bucket LRU hash map
  key-stack-off   ; Stack offset where lookup key is stored
  scratch-off     ; Stack offset for scratch space (24 bytes)
  rate            ; Requests per second (e.g., 100)
  burst           ; Maximum burst (e.g., 200)
  pass-label      ; Label to jump to on pass
  drop-label)     ; Label to jump to on rate limit
```

### Configurable Rate Limiting (Runtime Config)

```clojure
;; Rate read from config map at runtime
(rate-limit/build-rate-limit-check
  config-map-fd   ; FD for rate_limit_config array map
  config-index    ; Index in config map
  bucket-map-fd   ; FD for bucket LRU hash map
  key-stack-off   ; Stack offset for key
  scratch-off     ; Stack offset for scratch (32 bytes)
  pass-label      ; Pass label
  drop-label)     ; Drop label
```

### Userspace Config Encoding

```clojure
;; Encode config for map update
(rate-limit/encode-rate-limit-config rate burst)
;; Returns: 16-byte array

;; Disable rate limiting
(rate-limit/rate-disabled-config)
;; Returns: 16 bytes of zeros
```

### Example: XDP Rate Limiter

```clojure
(def xdp-rate-limiter
  (concat
    [(dsl/mov-reg :r6 :r1)]
    [(dsl/ldx :dw :r7 :r6 0)
     (dsl/ldx :dw :r8 :r6 8)]

    (bounds/build-bounds-check-label :r7 :r8 0 34 :pass)

    ;; Extract source IP as key
    [(dsl/ldx :w :r0 :r7 26)
     (dsl/stx :w :r10 :r0 -16)]

    ;; Apply rate limiting: 100 req/s, burst 200
    (rate-limit/build-simple-rate-limit 20 -16 -32 100 200 :pass :drop)

    [(asm/label :pass)
     (dsl/mov :r0 2)  ; XDP_PASS
     (dsl/exit-insn)]

    [(asm/label :drop)
     (dsl/mov :r0 1)  ; XDP_DROP
     (dsl/exit-insn)]))
```

---

## 7. Memory Operations

**Namespace:** `clj-ebpf.memory`

Efficient memory operations for zeroing, copying, and initializing data structures on the BPF stack.

### Zeroing Memory

```clojure
;; Zero contiguous bytes (size must be multiple of 4)
(mem/build-zero-bytes stack-offset num-bytes)

;; Zero with automatic 4-byte alignment
(mem/build-zero-struct stack-offset size)
```

### Copying Memory

```clojure
;; Copy using 4-byte operations
(mem/build-memcpy-stack src-offset dst-offset num-bytes)

;; Copy using 8-byte operations (more efficient)
(mem/build-memcpy-stack-dw src-offset dst-offset num-bytes)
```

### Setting Memory

```clojure
;; Fill with byte value (size must be multiple of 4)
(mem/build-memset stack-offset byte-value num-bytes)

;; Fill with 64-bit value (size must be multiple of 8)
(mem/build-memset-dw stack-offset value num-bytes)
```

### Storing Immediate Values

```clojure
;; Store 32-bit immediate
(mem/build-store-immediate-w stack-offset value)

;; Store 64-bit immediate
(mem/build-store-immediate-dw stack-offset value)
```

### Structure Operations

```clojure
;; Initialize structure: zero then set fields
(mem/build-init-struct stack-offset size {field-offset1 value1
                                          field-offset2 value2})

;; Field access from pointer
(mem/build-load-struct-field-w ptr-reg field-offset dst-reg)
(mem/build-load-struct-field-dw ptr-reg field-offset dst-reg)
(mem/build-store-struct-field-w ptr-reg field-offset src-reg)
(mem/build-store-struct-field-dw ptr-reg field-offset src-reg)
```

### Example: Conntrack Key Initialization

```clojure
(def init-conntrack-key
  (concat
    ;; Zero 40-byte conntrack key structure
    (mem/build-zero-bytes -64 40)

    ;; Set protocol field at offset 0
    [(dsl/mov :r0 6)  ; TCP
     (dsl/stx :w :r10 :r0 -64)]

    ;; Copy addresses from packet
    (mem/build-memcpy-stack -80 -56 8)))  ; src + dst IPs
```

---

## 8. BPF Map Helpers

**Namespace:** `clj-ebpf.maps.helpers`

Perform map operations from within BPF programs.

### Constants

```clojure
maps/BPF-ANY      ; 0 - Create or update
maps/BPF-NOEXIST  ; 1 - Create only (fail if exists)
maps/BPF-EXIST    ; 2 - Update only (fail if not exists)
```

### Core Operations

```clojure
;; Lookup key, returns pointer to value or NULL
(maps/build-map-lookup map-fd key-stack-offset)

;; Update/insert entry
(maps/build-map-update map-fd key-offset value-offset flags)

;; Delete entry
(maps/build-map-delete map-fd key-stack-offset)
```

### Example: Counter with Lookup-or-Create

```clojure
(def counter-program
  (concat
    ;; Store key
    [(dsl/mov :r0 0x0A000001)  ; 10.0.0.1
     (dsl/stx :w :r10 :r0 -16)]

    ;; Initialize value to 1
    [(dsl/mov :r0 1)
     (dsl/stx :dw :r10 :r0 -32)]

    ;; Try to create (NOEXIST)
    (maps/build-map-update 10 -16 -32 maps/BPF-NOEXIST)
    [(asm/jmp-imm :jne :r0 0 :exists)]
    [(asm/jmp :done)]

    ;; Entry exists, increment
    [(asm/label :exists)]
    (maps/build-map-lookup 10 -16)
    [(asm/jmp-imm :jeq :r0 0 :done)]
    [(dsl/ldx :dw :r1 :r0 0)
     (dsl/add :r1 1)
     (dsl/stx :dw :r0 :r1 0)]

    [(asm/label :done)
     (dsl/mov :r0 0)
     (dsl/exit-insn)]))
```

---

## Running the Tutorial

To see all these helpers in action, run the interactive tutorial:

```bash
clojure -M:examples -m helpers-tutorial
```

This will demonstrate each helper with practical examples and show the generated instruction counts.

## Best Practices

1. **Always check bounds** before packet access
2. **Use labels** (`asm/jmp-imm`) for cleaner control flow
3. **Minimize register usage** - BPF only has r0-r10
4. **Use dword operations** when possible for efficiency
5. **Initialize memory** before use to satisfy the verifier
6. **Check map lookup returns** for NULL before dereferencing
7. **Use rate limiting** for any public-facing service

## See Also

- [Test files](../../test/) for comprehensive API coverage
- [Examples directory](../../examples/) for complete programs
- [Adding New Helpers](../adding-new-helpers.md) for extending the library
