(ns examples.struct-ops-tcp-cc
  "Example: BPF STRUCT_OPS for TCP Congestion Control

   This example demonstrates BPF STRUCT_OPS, which allows BPF programs
   to implement kernel function pointers. The primary use case is
   implementing custom TCP congestion control algorithms entirely in BPF.

   TCP Congestion Control Overview:
   - Congestion control algorithms manage how fast TCP sends data
   - They adjust the congestion window (cwnd) and slow start threshold (ssthresh)
   - Common algorithms: Reno, Cubic, BBR, Vegas

   Key Callbacks in tcp_congestion_ops:
   - ssthresh: Calculate new slow start threshold after loss
   - cong_avoid: Increase cwnd during congestion avoidance
   - set_state: Handle state transitions
   - cwnd_event: Handle cwnd events
   - init/release: Connection setup/teardown

   NOTE: Actual STRUCT_OPS programs require:
   - Root privileges (CAP_BPF + CAP_NET_ADMIN)
   - Kernel 5.6+ for basic STRUCT_OPS
   - Kernel 5.13+ for TCP congestion control in BPF
   - BTF support enabled

   This example focuses on program construction patterns.

   Run with: clj -M:examples -e \"(load-file \\\"examples/struct_ops_tcp_cc.clj\\\")\"
             or: clj -M -m examples.struct-ops-tcp-cc"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.struct-ops :as struct-ops]
            [clj-ebpf.macros :refer [defprogram]]))

;; ============================================================================
;; STRUCT_OPS Architecture
;; ============================================================================
;;
;; STRUCT_OPS allows BPF to replace kernel function pointers:
;;
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │                      STRUCT_OPS Workflow                            │
;;   └─────────────────────────────────────────────────────────────────────┘
;;
;;   1. Load BPF programs for each callback (type: STRUCT_OPS)
;;         │
;;         v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │   2. Create STRUCT_OPS map                                          │
;;   │      - map_type = BPF_MAP_TYPE_STRUCT_OPS (27)                      │
;;   │      - btf_vmlinux_value_type_id = BTF ID of target struct         │
;;   │      - value_size = sizeof(struct tcp_congestion_ops)              │
;;   └──────────────────────────────┬──────────────────────────────────────┘
;;                                  │
;;                                  v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │   3. Update map with struct containing program FDs                  │
;;   │      Programs are attached at their respective callback offsets    │
;;   └──────────────────────────────┬──────────────────────────────────────┘
;;                                  │
;;                                  v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │   4. Create BPF link to register struct_ops                         │
;;   │      bpf_link_create(0, map_fd, BPF_STRUCT_OPS, ...)               │
;;   └──────────────────────────────┬──────────────────────────────────────┘
;;                                  │
;;                                  v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │   5. Algorithm is now available!                                    │
;;   │      sysctl -w net.ipv4.tcp_congestion_control=my_bpf_cc           │
;;   └─────────────────────────────────────────────────────────────────────┘

;; ============================================================================
;; TCP Congestion Control Concepts
;; ============================================================================

(println "\n=== TCP Congestion Control Concepts ===")

(println "
TCP Congestion Control manages the rate at which TCP sends data.
Key variables in struct tcp_sock:

  snd_cwnd     - Congestion window (packets that can be in flight)
  snd_ssthresh - Slow start threshold
  srtt_us      - Smoothed RTT (round-trip time) in microseconds
  mdev_us      - RTT mean deviation (jitter)
  packets_out  - Packets currently in flight
  retrans_out  - Retransmitted packets in flight
  sacked_out   - SACKed packets
  lost_out     - Lost packets (according to SACK)")

;; ============================================================================
;; TCP CA States and Events
;; ============================================================================

(println "\n=== TCP Congestion Avoidance States ===")

(println "\nTCP CA states:")
(doseq [[k v] (sort-by val struct-ops/tcp-ca-states)]
  (println (format "  %-10s -> %d" (name k) v)))

(println "\nTCP CA events:")
(doseq [[k v] (sort-by val struct-ops/tcp-ca-events)]
  (println (format "  %-14s -> %d" (name k) v)))

;; ============================================================================
;; TCP Socket Field Offsets
;; ============================================================================

(println "\n=== TCP Socket Field Offsets ===")

(println "\nCommon tcp_sock field offsets:")
(doseq [[k v] (sort-by val struct-ops/tcp-sock-offsets)]
  (println (format "  %-14s at offset %4d" (name k) v)))

(println "\nNote: Offsets may vary by kernel version. Use BTF for portability.")

;; ============================================================================
;; Example 1: Minimal ssthresh Callback
;; ============================================================================

(println "\n=== Example 1: Minimal ssthresh ===")

(def minimal-ssthresh-insns
  "Most basic ssthresh implementation - returns cwnd/2 (min 2).
   This is classic TCP Reno behavior."
  (struct-ops/minimal-ssthresh-program))

(println "Minimal ssthresh instructions:" (count minimal-ssthresh-insns))
(println "Assembled bytecode size:" (count (dsl/assemble minimal-ssthresh-insns)) "bytes")

;; ============================================================================
;; Example 2: Custom AIMD ssthresh
;; ============================================================================

(println "\n=== Example 2: Custom AIMD ssthresh ===")

(def aimd-ssthresh-insns
  "AIMD (Additive Increase Multiplicative Decrease) ssthresh.
   On congestion, reduce cwnd by half, minimum 2.

   This is the classic TCP Reno algorithm:
   ssthresh = max(cwnd / 2, 2)"
  (vec (concat
        ;; Save socket pointer
        (struct-ops/ssthresh-prologue :r6)

        ;; AIMD calculation: cwnd / 2, min 2
        (struct-ops/aimd-ssthresh :r6 :r7)

        ;; Return the result
        (struct-ops/struct-ops-return))))

(println "AIMD ssthresh instructions:" (count aimd-ssthresh-insns))
(println "Assembled bytecode size:" (count (dsl/assemble aimd-ssthresh-insns)) "bytes")

;; ============================================================================
;; Example 3: Passthrough ssthresh
;; ============================================================================

(println "\n=== Example 3: Passthrough ssthresh ===")

(def passthrough-ssthresh-insns
  "Return the current ssthresh value unchanged."
  (struct-ops/passthrough-ssthresh-program))

(println "Passthrough ssthresh instructions:" (count passthrough-ssthresh-insns))
(println "Assembled bytecode size:" (count (dsl/assemble passthrough-ssthresh-insns)) "bytes")

;; ============================================================================
;; Example 4: cong_avoid Callback
;; ============================================================================

(println "\n=== Example 4: Congestion Avoidance ===")

(def cong-avoid-insns
  "Congestion avoidance callback - called to adjust cwnd.

   Signature: void cong_avoid(struct sock *sk, u32 ack, u32 acked)

   In slow start: cwnd += acked (exponential growth)
   In congestion avoidance: cwnd += 1/cwnd per ack (linear growth)"
  (vec (concat
        ;; Save arguments: sk in r6, ack in r7, acked in r8
        (struct-ops/cong-avoid-prologue :r6 :r7 :r8)

        ;; Check if we're in slow start (cwnd < ssthresh)
        ;; If cwnd >= ssthresh, skip to congestion avoidance
        (struct-ops/slow-start-check :r6 :r9 :r1 3)

        ;; Slow start: increment cwnd by 1 (simplified)
        (struct-ops/increment-cwnd :r6 :r2)

        ;; Return void
        (struct-ops/struct-ops-return-void))))

(println "cong_avoid instructions:" (count cong-avoid-insns))
(println "Assembled bytecode size:" (count (dsl/assemble cong-avoid-insns)) "bytes")

;; ============================================================================
;; Example 5: init Callback
;; ============================================================================

(println "\n=== Example 5: Init Callback ===")

(def init-insns
  "Initialize connection state.

   Signature: void init(struct sock *sk)

   Called when a new connection is established.
   Typically sets initial cwnd, ssthresh, etc."
  (vec (concat
        ;; Save socket pointer
        (struct-ops/init-prologue :r6)

        ;; Could set initial values here
        ;; For now, just return

        ;; Return void
        (struct-ops/struct-ops-return-void))))

(println "init instructions:" (count init-insns))
(println "Assembled bytecode size:" (count (dsl/assemble init-insns)) "bytes")

;; ============================================================================
;; Example 6: release Callback
;; ============================================================================

(println "\n=== Example 6: Release Callback ===")

(def release-insns
  "Release connection resources.

   Signature: void release(struct sock *sk)

   Called when a connection is closed.
   Clean up any per-connection state."
  (struct-ops/minimal-release-program))

(println "release instructions:" (count release-insns))
(println "Assembled bytecode size:" (count (dsl/assemble release-insns)) "bytes")

;; ============================================================================
;; Example 7: set_state Callback
;; ============================================================================

(println "\n=== Example 7: set_state Callback ===")

(def set-state-insns
  "Handle state transitions.

   Signature: void set_state(struct sock *sk, u8 new_state)

   States: Open, Disorder, CWR, Recovery, Loss
   Used for algorithms that need to track state changes."
  (vec (concat
        ;; Save sk and new_state
        (struct-ops/set-state-prologue :r6 :r7)

        ;; Check if entering Loss state
        [(dsl/jmp-imm :jne :r7 (get struct-ops/tcp-ca-states :loss) 2)]

        ;; In Loss state: could reset congestion window
        ;; For now, just continue

        ;; Return void
        (struct-ops/struct-ops-return-void))))

(println "set_state instructions:" (count set-state-insns))

;; ============================================================================
;; Example 8: cwnd_event Callback
;; ============================================================================

(println "\n=== Example 8: cwnd_event Callback ===")

(def cwnd-event-insns
  "Handle congestion window events.

   Signature: void cwnd_event(struct sock *sk, enum tcp_ca_event ev)

   Events include TX_START, CWND_RESTART, COMPLETE_CWR, LOSS, etc."
  (vec (concat
        ;; Save sk and event
        (struct-ops/cwnd-event-prologue :r6 :r7)

        ;; Could handle specific events here
        ;; Example: reset cwnd on CWND_RESTART

        ;; Return void
        (struct-ops/struct-ops-return-void))))

(println "cwnd_event instructions:" (count cwnd-event-insns))

;; ============================================================================
;; Example 9: undo_cwnd Callback
;; ============================================================================

(println "\n=== Example 9: undo_cwnd Callback ===")

(def undo-cwnd-insns
  "Undo cwnd reduction (e.g., after false loss detection).

   Signature: u32 undo_cwnd(struct sock *sk)

   Returns the new cwnd value. Typically returns the saved cwnd
   from before the reduction."
  (struct-ops/minimal-undo-cwnd-program))

(println "undo_cwnd instructions:" (count undo-cwnd-insns))

;; ============================================================================
;; Example 10: pkts_acked Callback
;; ============================================================================

(println "\n=== Example 10: pkts_acked Callback ===")

(def pkts-acked-insns
  "Called when packets are acknowledged.

   Signature: void pkts_acked(struct sock *sk, const struct ack_sample *sample)

   The sample contains RTT information for algorithms like Vegas or BBR
   that use RTT measurements for congestion detection."
  (vec (concat
        ;; Save sk and sample pointer
        (struct-ops/pkts-acked-prologue :r6 :r7)

        ;; Could read RTT from sample here
        ;; struct ack_sample has rtt_us, pkts_acked, etc.

        ;; Return void
        (struct-ops/struct-ops-return-void))))

(println "pkts_acked instructions:" (count pkts-acked-insns))

;; ============================================================================
;; Example 11: TCP Socket Field Access
;; ============================================================================

(println "\n=== Example 11: TCP Socket Field Access ===")

(def field-access-insns
  "Demonstrate reading and writing TCP socket fields."
  (vec (concat
        (struct-ops/ssthresh-prologue :r6)

        ;; Read various fields
        [(struct-ops/tcp-sock-load-cwnd :r6 :r7)        ; Load snd_cwnd
         (struct-ops/tcp-sock-load-ssthresh :r6 :r8)    ; Load snd_ssthresh
         (struct-ops/tcp-sock-load-srtt :r6 :r9)        ; Load srtt_us
         (struct-ops/tcp-sock-load-ca-state :r6 :r1)]   ; Load CA state

        ;; Return cwnd as the result
        [(dsl/mov-reg :r0 :r7)]
        (struct-ops/struct-ops-return))))

(println "Field access instructions:" (count field-access-insns))
(println "Assembled bytecode size:" (count (dsl/assemble field-access-insns)) "bytes")

;; ============================================================================
;; Example 12: Using defprogram Macro
;; ============================================================================

(println "\n=== Example 12: Using defprogram Macro ===")

(defprogram bpf-reno-ssthresh
  "BPF Reno ssthresh - classic AIMD algorithm."
  :type :struct-ops
  :license "GPL"
  :body (vec (concat
              (struct-ops/ssthresh-prologue :r6)
              (struct-ops/aimd-ssthresh :r6 :r7)
              (struct-ops/struct-ops-return))))

(println "defprogram spec created:" (:name bpf-reno-ssthresh))
(println "Program type:" (:type bpf-reno-ssthresh))

;; ============================================================================
;; Example 13: Callback Metadata
;; ============================================================================

(println "\n=== Example 13: Callback Metadata ===")

(println "\nTCP congestion ops callbacks:")
(doseq [[callback info] (sort-by key struct-ops/tcp-congestion-ops-callbacks)]
  (println (format "  %-14s args: %d, return: %-6s, required: %s"
                   (name callback)
                   (:args info)
                   (name (:return info))
                   (:required info))))

;; ============================================================================
;; Example 14: Section Names
;; ============================================================================

(println "\n=== Example 14: Section Names ===")

(println "\nELF section names for tcp_congestion_ops:")
(doseq [callback ["ssthresh" "cong_avoid" "set_state" "cwnd_event"
                  "pkts_acked" "undo_cwnd" "init" "release"]]
  (println (format "  %s" (struct-ops/tcp-cong-ops-section-name callback))))

;; ============================================================================
;; Example 15: Program Info Metadata
;; ============================================================================

(println "\n=== Example 15: Program Info Metadata ===")

(def ssthresh-info
  (struct-ops/make-tcp-cong-ops-info
   "my_ssthresh"
   "ssthresh"
   (struct-ops/minimal-ssthresh-program)))

(println "STRUCT_OPS program info:")
(println "  Name:" (:name ssthresh-info))
(println "  Section:" (:section ssthresh-info))
(println "  Type:" (:type ssthresh-info))
(println "  Struct:" (:struct-name ssthresh-info))
(println "  Callback:" (:callback ssthresh-info))

;; ============================================================================
;; Example 16: Complete Algorithm Set
;; ============================================================================

(println "\n=== Example 16: Complete Algorithm Set ===")

(def my-cc-programs
  "A complete set of callbacks for a simple congestion control algorithm."
  {:ssthresh    (dsl/assemble (struct-ops/minimal-ssthresh-program))
   :cong-avoid  (dsl/assemble (struct-ops/minimal-cong-avoid-program))
   :init        (dsl/assemble (struct-ops/minimal-init-program))
   :release     (dsl/assemble (struct-ops/minimal-release-program))
   :undo-cwnd   (dsl/assemble (struct-ops/minimal-undo-cwnd-program))})

(println "Complete algorithm with" (count my-cc-programs) "callbacks:")
(doseq [[callback bytecode] my-cc-programs]
  (println (format "  %-12s %4d bytes" (name callback) (count bytecode))))

;; ============================================================================
;; Conceptual Usage Example
;; ============================================================================

(println "\n=== Conceptual Usage (Requires Root + Kernel 5.13+) ===")

(println "
;; Real-world usage would look like:

(require '[clj-ebpf.programs :as progs]
         '[clj-ebpf.maps :as maps]
         '[clj-ebpf.btf :as btf])

;; 1. Get BTF info for tcp_congestion_ops
(def tcp-ops-btf (btf/find-struct-type-id \"tcp_congestion_ops\"))
(def tcp-ops-size (btf/get-struct-size tcp-ops-btf))

;; 2. Create STRUCT_OPS map
(def struct-ops-map
  (maps/create-struct-ops-map \"tcp_congestion_ops\"
    {:btf-vmlinux-value-type-id tcp-ops-btf
     :value-size tcp-ops-size}))

;; 3. Load callback programs
(def ssthresh-prog
  (progs/load-struct-ops-program
    (dsl/assemble (struct-ops/minimal-ssthresh-program))
    \"tcp_congestion_ops\"
    \"ssthresh\"
    {:btf-id (btf/find-callback-btf-id \"ssthresh\")}))

;; 4. Register the algorithm
(progs/with-struct-ops [my-cc struct-ops-map
                         {:ssthresh ssthresh-prog
                          :init init-prog
                          ...}
                         {:algo-name \"my_bpf_cc\"}]
  ;; Algorithm is now available!
  ;; Use: sysctl -w net.ipv4.tcp_congestion_control=my_bpf_cc
  (Thread/sleep 60000))

;; Cleanup is automatic with with-struct-ops
")

;; ============================================================================
;; TCP Congestion Control Patterns
;; ============================================================================

(println "\n=== Common Algorithm Patterns ===")

(println "
1. AIMD (Reno-style):
   - On loss: ssthresh = cwnd / 2
   - In slow start: cwnd += 1 per ACK
   - In cong avoid: cwnd += 1 / cwnd per ACK

2. BBR-style:
   - Estimate bottleneck bandwidth
   - Use pacing instead of cwnd limiting
   - Probe for higher bandwidth periodically

3. Vegas-style:
   - Compare expected throughput to actual
   - If diff > threshold, reduce cwnd
   - Uses RTT measurements from pkts_acked

4. DCTCP-style:
   - Use ECN marks to detect congestion
   - Proportional reduction based on marking rate
   - Good for data center networks
")

;; ============================================================================
;; Summary
;; ============================================================================

(println "\n=== Summary ===")
(println "
BPF STRUCT_OPS enables custom TCP congestion control in BPF:

Key concepts:
- Program type: STRUCT_OPS (26)
- Map type: BPF_MAP_TYPE_STRUCT_OPS (27)
- Attach type: BPF_STRUCT_OPS (44)

Key callbacks:
- ssthresh: Calculate slow start threshold after loss
- cong_avoid: Adjust cwnd during congestion avoidance
- set_state/cwnd_event: Handle state transitions
- pkts_acked: Process RTT measurements
- init/release: Connection lifecycle

TCP socket fields:
- snd_cwnd: Current congestion window
- snd_ssthresh: Slow start threshold
- srtt_us: Smoothed RTT in microseconds
- packets_out: Packets in flight

Kernel requirements:
- Linux 5.6+ for basic STRUCT_OPS
- Linux 5.13+ for TCP congestion control
- BTF support required
- CAP_BPF + CAP_NET_ADMIN capabilities

This example demonstrated:
- Callback prologue patterns
- TCP socket field access
- AIMD algorithm implementation
- Section names for ELF output
- Program metadata creation
")

(defn -main [& _args]
  (println "\n=== BPF STRUCT_OPS TCP CC Example Complete ==="))
