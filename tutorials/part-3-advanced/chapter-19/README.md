# Chapter 19: XDP Advanced Topics

**Duration**: 3-4 hours | **Difficulty**: Advanced

This chapter covers advanced XDP (eXpress Data Path) programming techniques for high-performance packet processing at the network driver level.

## Learning Objectives

By the end of this chapter, you will:
- Understand XDP program modes (native, generic, offload)
- Implement advanced packet parsing and modification
- Build XDP load balancers and firewalls
- Use XDP metadata and hints
- Optimize XDP programs for line-rate performance
- Debug and profile XDP programs

## Prerequisites

- Completed Chapters 10-18
- Understanding of network protocols (Ethernet, IP, TCP/UDP)
- Familiarity with packet processing concepts

---

## 19.1 XDP Fundamentals Review

### XDP Actions

| Action | Value | Description |
|--------|-------|-------------|
| XDP_ABORTED | 0 | Error occurred, packet dropped |
| XDP_DROP | 1 | Drop packet silently |
| XDP_PASS | 2 | Pass to normal network stack |
| XDP_TX | 3 | Bounce packet back out same interface |
| XDP_REDIRECT | 4 | Redirect to another interface/CPU |

### XDP Operating Modes

1. **Native XDP**: Runs in driver, maximum performance
2. **Generic XDP**: Runs in network stack, works everywhere
3. **Offloaded XDP**: Runs on network card hardware

```clojure
;; Attach with mode selection
(bpf/attach-xdp program "eth0" :mode :native)    ; Best performance
(bpf/attach-xdp program "eth0" :mode :generic)   ; Fallback
(bpf/attach-xdp program "eth0" :mode :offload)   ; Hardware offload
```

---

## 19.2 Packet Parsing

### Ethernet Header Parsing

```clojure
(def eth-header-size 14)

;; Ethernet header offsets
(def eth-dst-offset 0)    ; 6 bytes
(def eth-src-offset 6)    ; 6 bytes
(def eth-type-offset 12)  ; 2 bytes

(def xdp-parse-eth
  [;; Load context
   [(bpf/load-ctx :dw :r2 0)]      ; data
   [(bpf/load-ctx :dw :r3 8)]      ; data_end

   ;; Bounds check for Ethernet header
   [(bpf/mov-reg :r4 :r2)]
   [(bpf/add :r4 eth-header-size)]
   [(bpf/jmp-reg :jgt :r4 :r3 :drop)]

   ;; Read EtherType
   [(bpf/load-mem :h :r5 :r2 eth-type-offset)]
   ;; r5 now contains EtherType (big-endian)
   ])
```

### IP Header Parsing

```clojure
(def ip-header-min-size 20)

;; IP header offsets
(def ip-ver-ihl-offset 0)
(def ip-proto-offset 9)
(def ip-src-offset 12)
(def ip-dst-offset 16)

(def xdp-parse-ip
  [;; Check for IPv4 (0x0800)
   [(bpf/jmp-imm :jne :r5 0x0800 :not-ipv4)]

   ;; r2 points to start of packet, advance past Ethernet
   [(bpf/mov-reg :r6 :r2)]
   [(bpf/add :r6 eth-header-size)]  ; r6 = IP header start

   ;; Bounds check for IP header
   [(bpf/mov-reg :r4 :r6)]
   [(bpf/add :r4 ip-header-min-size)]
   [(bpf/jmp-reg :jgt :r4 :r3 :drop)]

   ;; Get IP header length (IHL * 4)
   [(bpf/load-mem :b :r7 :r6 ip-ver-ihl-offset)]
   [(bpf/and :r7 0x0F)]
   [(bpf/lsh :r7 2)]  ; r7 = IP header length

   ;; Bounds check for variable header
   [(bpf/mov-reg :r4 :r6)]
   [(bpf/add-reg :r4 :r7)]
   [(bpf/jmp-reg :jgt :r4 :r3 :drop)]

   ;; Read protocol
   [(bpf/load-mem :b :r8 :r6 ip-proto-offset)]
   ;; r8 = IP protocol (6=TCP, 17=UDP, 1=ICMP)

   ;; Read source and destination IPs
   [(bpf/load-mem :w :r9 :r6 ip-src-offset)]   ; r9 = src IP
   ])
```

### TCP/UDP Header Parsing

```clojure
(def tcp-src-port-offset 0)
(def tcp-dst-port-offset 2)
(def tcp-flags-offset 13)

(def udp-src-port-offset 0)
(def udp-dst-port-offset 2)

(def xdp-parse-l4
  [;; r6 = IP header start, r7 = IP header length
   ;; Calculate L4 header start
   [(bpf/mov-reg :r1 :r6)]
   [(bpf/add-reg :r1 :r7)]  ; r1 = L4 header start

   ;; Bounds check for L4 header (minimum 8 bytes)
   [(bpf/mov-reg :r4 :r1)]
   [(bpf/add :r4 8)]
   [(bpf/jmp-reg :jgt :r4 :r3 :drop)]

   ;; Read ports (same offset for TCP and UDP)
   [(bpf/load-mem :h :r2 :r1 0)]  ; src port
   [(bpf/load-mem :h :r3 :r1 2)]  ; dst port
   ])
```

---

## 19.3 Packet Modification

### Checksum Helpers

```clojure
(defn xdp-update-csum [offset old-value new-value]
  "Generate instructions to incrementally update checksum"
  [;; l3_csum_replace helper
   [(bpf/mov-reg :r1 :r6)]           ; IP header pointer
   [(bpf/mov :r2 offset)]            ; Checksum offset
   [(bpf/mov old-value :r3)]         ; Old value
   [(bpf/mov new-value :r4)]         ; New value
   [(bpf/mov :r5 2)]                 ; Size (2 = 16-bit)
   [(bpf/call (bpf/helper :l3_csum_replace))]])
```

### NAT Implementation

```clojure
(def xdp-snat
  "Source NAT: Rewrite source IP"
  [;; Assuming r6 = IP header, r9 = original src IP

   ;; Store new source IP
   [(bpf/mov :r1 0xC0A80101)]  ; 192.168.1.1
   [(bpf/store-mem :w :r6 ip-src-offset :r1)]

   ;; Update IP checksum (incremental)
   [(bpf/mov-reg :r1 :r6)]           ; skb pointer
   [(bpf/add :r1 10)]                ; IP checksum offset
   [(bpf/mov-reg :r3 :r9)]           ; old src IP
   [(bpf/mov :r4 0xC0A80101)]        ; new src IP
   [(bpf/mov :r5 4)]                 ; 4 bytes
   [(bpf/call (bpf/helper :l3_csum_replace))]

   ;; Update L4 checksum if TCP/UDP
   ;; ...
   ])
```

### Packet Growing/Shrinking

```clojure
(def xdp-adjust-head
  "Adjust packet head (add/remove headers)"
  [;; bpf_xdp_adjust_head(xdp_md, delta)
   ;; Positive delta: remove bytes from head
   ;; Negative delta: add bytes to head

   ;; Example: Add 4 bytes to head (for encapsulation)
   [(bpf/mov-reg :r1 :r10)]        ; xdp_md context
   [(bpf/mov :r2 -4)]              ; Add 4 bytes
   [(bpf/call (bpf/helper :xdp_adjust_head))]
   [(bpf/jmp-imm :jne :r0 0 :error)]

   ;; Reload data pointers (they changed!)
   [(bpf/load-ctx :dw :r2 0)]      ; new data
   [(bpf/load-ctx :dw :r3 8)]      ; new data_end
   ])
```

---

## 19.4 XDP Redirect

### Same-Interface Redirect (TX)

```clojure
(def xdp-bounce
  "Bounce packet back out same interface"
  [;; Swap MAC addresses
   ;; ... (swap src/dst MAC)

   ;; Return XDP_TX
   [(bpf/mov :r0 3)]  ; XDP_TX
   [(bpf/exit)]])
```

### Cross-Interface Redirect

```clojure
;; Device map for redirect targets
(def devmap
  {:type :devmap
   :key-type :u32
   :value-type :u32  ; ifindex
   :max-entries 64})

(def xdp-redirect-map
  [;; Look up redirect target
   [(bpf/mov :r1 0)]                      ; Key (index into devmap)
   [(bpf/mov-reg :r2 (bpf/map-ref devmap))]
   [(bpf/call (bpf/helper :map_lookup_elem))]
   [(bpf/jmp-imm :jeq :r0 0 :pass)]       ; No target, pass

   ;; Redirect to target interface
   [(bpf/mov-reg :r2 (bpf/map-ref devmap))]
   [(bpf/mov :r3 0)]                      ; Key
   [(bpf/mov :r4 0)]                      ; Flags
   [(bpf/call (bpf/helper :redirect_map))]
   [(bpf/exit)]

   [:pass]
   [(bpf/mov :r0 2)]  ; XDP_PASS
   [(bpf/exit)]])
```

### CPU Redirect (XDP_REDIRECT with CPUMAP)

```clojure
(def cpumap
  {:type :cpumap
   :key-type :u32
   :value-type :u32  ; Queue size
   :max-entries 64})

(def xdp-cpu-redirect
  "Redirect to specific CPU for processing"
  [;; Calculate target CPU (e.g., hash of flow)
   ;; r5 = hash value from earlier
   [(bpf/and :r5 0x3)]  ; Mask to 4 CPUs

   ;; Redirect to CPU
   [(bpf/mov-reg :r2 (bpf/map-ref cpumap))]
   [(bpf/mov-reg :r3 :r5)]                 ; CPU index
   [(bpf/mov :r4 0)]                       ; Flags
   [(bpf/call (bpf/helper :redirect_map))]
   [(bpf/exit)]])
```

---

## 19.5 XDP Metadata

### Metadata Area

XDP metadata area allows passing information between XDP and later stages:

```clojure
;; Metadata layout
(def metadata-struct
  {:timestamp :u64
   :rx-queue :u32
   :mark :u32})

(def xdp-set-metadata
  [;; Grow metadata area
   [(bpf/mov-reg :r1 :r10)]         ; xdp_md
   [(bpf/mov :r2 -16)]              ; 16 bytes metadata
   [(bpf/call (bpf/helper :xdp_adjust_meta))]
   [(bpf/jmp-imm :jne :r0 0 :skip-meta)]

   ;; Get metadata pointer
   [(bpf/load-ctx :dw :r1 16)]      ; data_meta
   [(bpf/load-ctx :dw :r2 0)]       ; data

   ;; Verify metadata area exists
   [(bpf/mov-reg :r3 :r1)]
   [(bpf/add :r3 16)]
   [(bpf/jmp-reg :jgt :r3 :r2 :skip-meta)]

   ;; Write timestamp
   [(bpf/call (bpf/helper :ktime_get_ns))]
   [(bpf/store-mem :dw :r1 0 :r0)]

   ;; Write mark
   [(bpf/mov :r3 0x1234)]
   [(bpf/store-mem :w :r1 12 :r3)]

   [:skip-meta]])
```

### Reading Metadata in TC

```clojure
(def tc-read-metadata
  "Read XDP metadata in TC program"
  [;; Check for metadata
   [(bpf/load-ctx :dw :r1 76)]      ; data_meta (TC context offset)
   [(bpf/load-ctx :dw :r2 80)]      ; data

   ;; Verify metadata space
   [(bpf/mov-reg :r3 :r1)]
   [(bpf/add :r3 16)]
   [(bpf/jmp-reg :jgt :r3 :r2 :no-meta)]

   ;; Read timestamp
   [(bpf/load-mem :dw :r4 :r1 0)]   ; timestamp
   ;; Read mark
   [(bpf/load-mem :w :r5 :r1 12)]   ; mark

   [:no-meta]])
```

---

## 19.6 XDP Performance Optimization

### Minimize Instruction Count

```clojure
;; Bad: Multiple bounds checks
(def inefficient-parse
  [[(bpf/jmp-reg :jgt :r4 :r3 :drop)]  ; Check 1
   ;; ... access ...
   [(bpf/jmp-reg :jgt :r5 :r3 :drop)]  ; Check 2
   ;; ... access ...
   [(bpf/jmp-reg :jgt :r6 :r3 :drop)]  ; Check 3
   ])

;; Good: Combined bounds check
(def efficient-parse
  [;; Single check for all accesses
   [(bpf/mov-reg :r4 :r2)]
   [(bpf/add :r4 MAX_OFFSET)]
   [(bpf/jmp-reg :jgt :r4 :r3 :drop)]
   ;; All accesses are now safe
   ])
```

### Use Per-CPU Maps

```clojure
(def percpu-stats
  {:type :percpu_array
   :key-type :u32
   :value-type [:struct {:packets :u64 :bytes :u64}]
   :max-entries 1})

;; Atomic increment without locking
(def xdp-update-stats
  [[(bpf/mov :r1 0)]
   [(bpf/mov-reg :r2 (bpf/map-ref percpu-stats))]
   [(bpf/call (bpf/helper :map_lookup_elem))]
   [(bpf/jmp-imm :jeq :r0 0 :skip)]
   [(bpf/atomic-add :dw :r0 1 0)]     ; packets++
   [(bpf/atomic-add :dw :r0 :r7 8)]   ; bytes += pkt_len
   [:skip]])
```

### Avoid Map Lookups in Fast Path

```clojure
;; Bad: Map lookup for every packet
(def slow-check
  [[(bpf/call (bpf/helper :map_lookup_elem))]
   ;; ... decision based on lookup ...
   ])

;; Good: Cache common cases
(def fast-check
  [;; Quick check for common case
   [(bpf/jmp-imm :jne :r5 0x0800 :slow-path)]  ; Not IPv4
   ;; ... fast path for IPv4 ...

   [:slow-path]
   ;; Map lookup only for uncommon cases
   [(bpf/call (bpf/helper :map_lookup_elem))]])
```

---

## 19.7 Debugging XDP Programs

### Using bpf_trace_printk

```clojure
(def xdp-debug
  [;; Print debug info (limited to 3 args)
   ;; Note: Use sparingly, significant overhead
   [(bpf/mov-reg :r1 fmt-string-ptr)]
   [(bpf/mov :r2 4)]                 ; fmt string len
   [(bpf/mov-reg :r3 :r5)]           ; arg1: packet length
   [(bpf/call (bpf/helper :trace_printk))]])

;; Read output: cat /sys/kernel/debug/tracing/trace_pipe
```

### XDP Statistics

```clojure
(def xdp-action-stats
  {:type :percpu_array
   :key-type :u32
   :value-type :u64
   :max-entries 5})  ; One per XDP action

(defn record-action [action]
  [[(bpf/mov :r1 action)]
   [(bpf/mov-reg :r2 (bpf/map-ref xdp-action-stats))]
   [(bpf/call (bpf/helper :map_lookup_elem))]
   [(bpf/jmp-imm :jeq :r0 0 :skip)]
   [(bpf/atomic-add :dw :r0 1 0)]
   [:skip]])

(defn get-xdp-stats []
  (for [action [:aborted :drop :pass :tx :redirect]]
    {action (reduce + (bpf/map-lookup-percpu xdp-action-stats
                                              (xdp-action-value action)))}))
```

---

## Labs

### Lab 19.1: XDP Packet Filter

Build a high-performance packet filter using XDP.

[Go to Lab 19.1](labs/lab-19-1-packet-filter.md)

### Lab 19.2: XDP Load Balancer

Implement a layer-4 load balancer with XDP redirect.

[Go to Lab 19.2](labs/lab-19-2-load-balancer.md)

### Lab 19.3: XDP DDoS Mitigation

Create a DDoS mitigation system using XDP rate limiting.

[Go to Lab 19.3](labs/lab-19-3-ddos-mitigation.md)

---

## Key Takeaways

1. **Early Processing**: XDP runs before memory allocation, maximum efficiency
2. **Careful Parsing**: Always bounds check before memory access
3. **Actions Matter**: Choose the right action for each packet
4. **Metadata**: Pass information to later processing stages
5. **Performance**: Minimize instructions, use per-CPU data
6. **Debugging**: Use statistics maps, trace_printk sparingly

## References

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [XDP Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)
- [Cilium XDP Guide](https://docs.cilium.io/en/stable/bpf/)
