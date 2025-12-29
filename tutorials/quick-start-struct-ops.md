# Quick Start: BPF STRUCT_OPS for TCP Congestion Control

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Learning Objectives

By the end of this tutorial, you will:
- Understand BPF STRUCT_OPS architecture and workflow
- Know how to implement TCP congestion control callbacks
- Use DSL helpers for tcp_sock field access
- Build custom congestion control algorithms in pure Clojure
- Understand the registration and lifecycle of struct_ops

## Prerequisites

- Basic clj-ebpf knowledge (maps, programs, DSL)
- Understanding of TCP congestion control concepts
- Linux kernel 5.6+ with BTF support (5.13+ recommended for TCP CC)
- Root privileges for running examples
- CAP_BPF + CAP_NET_ADMIN capabilities

## Introduction

### What is BPF STRUCT_OPS?

BPF STRUCT_OPS allows BPF programs to **replace kernel function pointers** defined in structures. The primary use case is implementing custom TCP congestion control algorithms entirely in BPF, without writing kernel modules.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                      STRUCT_OPS Workflow                            │
└─────────────────────────────────────────────────────────────────────┘

  1. Load BPF programs for each callback (type: STRUCT_OPS)
        │
        v
┌─────────────────────────────────────────────────────────────────────┐
│   2. Create STRUCT_OPS map                                          │
│      - map_type = BPF_MAP_TYPE_STRUCT_OPS (27)                      │
│      - btf_vmlinux_value_type_id = BTF ID of target struct         │
│      - value_size = sizeof(struct tcp_congestion_ops)              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               v
┌─────────────────────────────────────────────────────────────────────┐
│   3. Update map with struct containing program FDs                  │
│      Programs are attached at their respective callback offsets    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               v
┌─────────────────────────────────────────────────────────────────────┐
│   4. Create BPF link to register struct_ops                         │
│      bpf_link_create(0, map_fd, BPF_STRUCT_OPS, ...)               │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               v
┌─────────────────────────────────────────────────────────────────────┐
│   5. Algorithm is now available!                                    │
│      sysctl -w net.ipv4.tcp_congestion_control=my_bpf_cc           │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Differences from Other BPF Program Types

| Aspect | Regular BPF (kprobe, XDP) | BPF STRUCT_OPS |
|--------|--------------------------|---------------|
| Purpose | Tracing, filtering | Implement kernel interfaces |
| Trigger | Events (syscall, packet) | Kernel function calls |
| Attach target | Function/tracepoint | Struct function pointer |
| Lifecycle | Per-event | Per-connection |
| Use case | Observability | Custom algorithms |

### TCP Congestion Control Callbacks

| Callback | Signature | Description |
|----------|-----------|-------------|
| `ssthresh` | `u32 (struct sock *sk)` | Calculate slow start threshold |
| `cong_avoid` | `void (struct sock *sk, u32 ack, u32 acked)` | Congestion avoidance algorithm |
| `set_state` | `void (struct sock *sk, u8 new_state)` | Handle state transitions |
| `cwnd_event` | `void (struct sock *sk, enum tcp_ca_event ev)` | Handle cwnd events |
| `pkts_acked` | `void (struct sock *sk, struct ack_sample *sample)` | Process RTT from ACKs |
| `undo_cwnd` | `u32 (struct sock *sk)` | Undo cwnd reduction |
| `init` | `void (struct sock *sk)` | Initialize new connection |
| `release` | `void (struct sock *sk)` | Clean up connection |

---

## Part 1: Understanding TCP Congestion Control

### Key TCP Socket Fields

TCP congestion control algorithms work with fields in `struct tcp_sock`:

```clojure
(require '[clj-ebpf.dsl.struct-ops :as struct-ops])

;; Field offsets (kernel-version dependent, use BTF in production)
struct-ops/tcp-sock-offsets
;; => {:snd-cwnd 256       ; Congestion window (packets)
;;     :snd-ssthresh 260   ; Slow start threshold
;;     :srtt-us 268        ; Smoothed RTT in microseconds
;;     :mdev-us 272        ; RTT mean deviation
;;     :packets-out 336    ; Packets currently in flight
;;     :ca-state 232       ; Congestion avoidance state
;;     ...}
```

### Congestion Avoidance States

```clojure
struct-ops/tcp-ca-states
;; => {:open 0       ; Normal operation
;;     :disorder 1  ; SACK or dupacks detected
;;     :cwr 2       ; Congestion Window Reduced (ECN)
;;     :recovery 3  ; Fast recovery
;;     :loss 4}     ; Loss recovery (RTO)
```

### Key Algorithm: AIMD

The classic TCP Reno algorithm uses **Additive Increase Multiplicative Decrease**:

1. **Slow Start**: Double cwnd every RTT until hitting ssthresh
2. **Congestion Avoidance**: Increase cwnd by 1/cwnd per ACK (linear growth)
3. **On Loss**: Set ssthresh = cwnd/2, reduce cwnd

---

## Part 2: Building Callback Programs

### Example 1: ssthresh Callback

The `ssthresh` callback calculates the new slow start threshold after loss:

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.struct-ops :as struct-ops])

;; Classic AIMD: ssthresh = max(cwnd/2, 2)
(def aimd-ssthresh-insns
  (vec (concat
        ;; Prologue: save sock pointer in r6
        (struct-ops/ssthresh-prologue :r6)

        ;; AIMD calculation
        (struct-ops/aimd-ssthresh :r6 :r7)

        ;; Return result (in r0)
        (struct-ops/struct-ops-return))))

;; Assemble to bytecode
(def aimd-ssthresh-bytecode
  (dsl/assemble aimd-ssthresh-insns))
```

Let's break down `aimd-ssthresh`:

```clojure
;; What aimd-ssthresh generates:
(defn aimd-ssthresh [sk-reg tmp-reg]
  (vec (concat
        ;; Load snd_cwnd into tmp-reg
        [(struct-ops/tcp-sock-load-cwnd sk-reg tmp-reg)]
        ;; Divide by 2 (right shift)
        [(dsl/rsh tmp-reg 1)]
        ;; Ensure at least 2
        [(dsl/jmp-imm :jge tmp-reg 2 1)  ; if tmp >= 2, skip next
         (dsl/mov tmp-reg 2)]            ; else: tmp = 2
        ;; Move result to r0 for return
        [(dsl/mov-reg :r0 tmp-reg)])))
```

### Example 2: cong_avoid Callback

The congestion avoidance callback adjusts cwnd based on ACKs:

```clojure
(def cong-avoid-insns
  (vec (concat
        ;; Prologue: sk in r6, ack in r7, acked in r8
        (struct-ops/cong-avoid-prologue :r6 :r7 :r8)

        ;; Check if in slow start (cwnd < ssthresh)
        (struct-ops/slow-start-check :r6 :r9 :r1 3)

        ;; In slow start: increment cwnd by 1
        (struct-ops/increment-cwnd :r6 :r2)

        ;; Return void
        (struct-ops/struct-ops-return-void))))
```

### Example 3: init Callback

Initialize connection state:

```clojure
(def init-insns
  (vec (concat
        ;; Save sock pointer
        (struct-ops/init-prologue :r6)

        ;; Set initial ssthresh if needed
        ;; (usually not needed, kernel sets defaults)

        ;; Return void
        (struct-ops/struct-ops-return-void))))
```

### Example 4: Complete Minimal Algorithm

Using the provided templates:

```clojure
(def my-cc-programs
  {:ssthresh   (dsl/assemble (struct-ops/minimal-ssthresh-program))
   :cong-avoid (dsl/assemble (struct-ops/minimal-cong-avoid-program))
   :init       (dsl/assemble (struct-ops/minimal-init-program))
   :release    (dsl/assemble (struct-ops/minimal-release-program))
   :undo-cwnd  (dsl/assemble (struct-ops/minimal-undo-cwnd-program))})
```

---

## Part 3: Reading TCP Socket Fields

### Loading Fields

```clojure
;; Load 32-bit field
(struct-ops/tcp-sock-load-u32 :r6 :r0 :snd-cwnd)

;; Load 16-bit field
(struct-ops/tcp-sock-load-u16 :r6 :r0 :mss-cache)

;; Load 8-bit field
(struct-ops/tcp-sock-load-u8 :r6 :r0 :ca-state)
```

### Convenience Functions

```clojure
;; Load snd_cwnd
(struct-ops/tcp-sock-load-cwnd :r6 :r7)

;; Load snd_ssthresh
(struct-ops/tcp-sock-load-ssthresh :r6 :r8)

;; Load srtt_us (smoothed RTT)
(struct-ops/tcp-sock-load-srtt :r6 :r9)

;; Load CA state
(struct-ops/tcp-sock-load-ca-state :r6 :r1)
```

### Storing Fields

```clojure
;; Store snd_cwnd
(struct-ops/tcp-sock-store-cwnd :r6 :r7)

;; Store snd_ssthresh
(struct-ops/tcp-sock-store-ssthresh :r6 :r8)
```

---

## Part 4: Return Patterns

### For u32 Returning Callbacks

```clojure
;; Return immediate value
(struct-ops/struct-ops-return-imm 42)

;; Return register value
(struct-ops/struct-ops-return-reg :r7)

;; Just exit (return r0)
(struct-ops/struct-ops-return)
```

### For void Returning Callbacks

```clojure
;; Return void (sets r0 = 0 and exits)
(struct-ops/struct-ops-return-void)
```

---

## Part 5: Building a Custom Algorithm

### Vegas-Style RTT-Based Algorithm

TCP Vegas uses RTT measurements to detect congestion before loss:

```clojure
(def vegas-ssthresh-insns
  "Vegas keeps cwnd stable, so ssthresh is often just current cwnd."
  (vec (concat
        (struct-ops/ssthresh-prologue :r6)

        ;; Load current cwnd
        [(struct-ops/tcp-sock-load-cwnd :r6 :r7)]

        ;; Return 3/4 of cwnd (Vegas is less aggressive)
        [(dsl/mov-reg :r8 :r7)
         (dsl/rsh :r8 2)           ; r8 = cwnd/4
         (dsl/sub :r7 :r8)         ; r7 = cwnd - cwnd/4 = 3/4 cwnd]

        ;; Ensure at least 2
        [(dsl/jmp-imm :jge :r7 2 1)
         (dsl/mov :r7 2)]

        (struct-ops/struct-ops-return-reg :r7))))
```

### DCTCP-Style ECN-Based Algorithm

For data center networks with ECN:

```clojure
(def dctcp-cwnd-event-insns
  "Handle ECN marks for DCTCP-style algorithm."
  (vec (concat
        (struct-ops/cwnd-event-prologue :r6 :r7)

        ;; Check if ECN CE (Congestion Experienced)
        [(dsl/jmp-imm :jne :r7
                      (get struct-ops/tcp-ca-events :ecn-is-ce)
                      2)]

        ;; On ECN CE: could track marking rate
        ;; For now, just continue

        (struct-ops/struct-ops-return-void))))
```

---

## Part 6: Registration (Conceptual)

### Full Registration Flow

```clojure
(require '[clj-ebpf.programs :as progs]
         '[clj-ebpf.maps :as maps]
         '[clj-ebpf.btf :as btf])

;; 1. Get BTF info for tcp_congestion_ops
(def tcp-ops-btf-id (btf/find-struct-type-id "tcp_congestion_ops"))
(def tcp-ops-size (btf/get-struct-size tcp-ops-btf-id))

;; 2. Create STRUCT_OPS map
(def struct-ops-map
  (maps/create-struct-ops-map "tcp_congestion_ops"
    {:btf-vmlinux-value-type-id tcp-ops-btf-id
     :value-size tcp-ops-size}))

;; 3. Load callback programs
(def ssthresh-prog
  (progs/load-struct-ops-program
    (dsl/assemble (struct-ops/minimal-ssthresh-program))
    "tcp_congestion_ops"
    "ssthresh"
    {:btf-id (btf/find-callback-btf-id "ssthresh")}))

;; 4. Register the algorithm
(progs/with-struct-ops [my-cc struct-ops-map
                        {:ssthresh ssthresh-prog}
                        {:algo-name "my_bpf_cc"}]
  ;; Algorithm is now available!
  ;; sysctl -w net.ipv4.tcp_congestion_control=my_bpf_cc
  (Thread/sleep 60000))
```

---

## Part 7: Program Metadata

### Section Names

For ELF output compatibility:

```clojure
(struct-ops/tcp-cong-ops-section-name "ssthresh")
;; => "struct_ops/tcp_congestion_ops/ssthresh"

(struct-ops/struct-ops-section-name "tcp_congestion_ops" "init")
;; => "struct_ops/tcp_congestion_ops/init"
```

### Program Info

```clojure
(struct-ops/make-tcp-cong-ops-info
  "my_ssthresh"           ; Program name
  "ssthresh"              ; Callback name
  (struct-ops/minimal-ssthresh-program))  ; Instructions

;; => {:name "my_ssthresh"
;;     :section "struct_ops/tcp_congestion_ops/ssthresh"
;;     :type :struct-ops
;;     :struct-name "tcp_congestion_ops"
;;     :callback "ssthresh"
;;     :instructions [...]}
```

---

## Part 8: Callback Reference

### Callback Metadata

```clojure
struct-ops/tcp-congestion-ops-callbacks
;; => {:ssthresh     {:args 1 :return :u32  :required false}
;;     :cong-avoid   {:args 3 :return :void :required false}
;;     :set-state    {:args 2 :return :void :required false}
;;     :cwnd-event   {:args 2 :return :void :required false}
;;     :pkts-acked   {:args 2 :return :void :required false}
;;     :undo-cwnd    {:args 1 :return :u32  :required false}
;;     :init         {:args 1 :return :void :required false}
;;     :release      {:args 1 :return :void :required false}
;;     ...}

;; Get info for a specific callback
(struct-ops/get-callback-info :ssthresh)
;; => {:args 1 :return :u32 :required false}
```

---

## Summary

### Key Concepts

1. **STRUCT_OPS** allows BPF to implement kernel function pointers
2. **TCP congestion control** is the primary use case
3. **Program type** is `:struct-ops` (26)
4. **Map type** is `:struct-ops` (27)

### Callback Prologues

| Callback | Prologue Function | Arguments |
|----------|-------------------|-----------|
| `ssthresh` | `ssthresh-prologue` | sk |
| `cong_avoid` | `cong-avoid-prologue` | sk, ack, acked |
| `set_state` | `set-state-prologue` | sk, new_state |
| `cwnd_event` | `cwnd-event-prologue` | sk, event |
| `pkts_acked` | `pkts-acked-prologue` | sk, sample |
| `undo_cwnd` | `undo-cwnd-prologue` | sk |
| `init` | `init-prologue` | sk |
| `release` | `release-prologue` | sk |

### Kernel Requirements

- Linux 5.6+ for basic STRUCT_OPS
- Linux 5.13+ for TCP congestion control
- BTF support required
- CAP_BPF + CAP_NET_ADMIN capabilities

### Next Steps

1. Study existing algorithms: Reno, Cubic, BBR
2. Experiment with RTT-based approaches
3. Consider ECN for data center networks
4. Profile your algorithm with real traffic

### Resources

- [Linux kernel TCP congestion control](https://www.kernel.org/doc/html/latest/networking/tcp.html)
- [BBR congestion control](https://queue.acm.org/detail.cfm?id=3022184)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [clj-ebpf STRUCT_OPS example](../examples/struct_ops_tcp_cc.clj)
