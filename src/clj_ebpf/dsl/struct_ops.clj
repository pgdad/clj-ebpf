(ns clj-ebpf.dsl.struct-ops
  "DSL helpers for BPF STRUCT_OPS programs.

   STRUCT_OPS allows BPF programs to implement kernel function pointers
   defined in structures. The primary use case is implementing TCP
   congestion control algorithms entirely in BPF.

   Common struct_ops targets:
   - tcp_congestion_ops: TCP congestion control algorithms
   - bpf_struct_ops: Generic struct_ops infrastructure

   TCP Congestion Control Callbacks:
   - ssthresh: Calculate slow start threshold
   - cong_avoid: Congestion avoidance algorithm
   - set_state: Handle state changes
   - cwnd_event: Handle congestion window events
   - pkts_acked: Handle ACK events
   - undo_cwnd: Undo congestion window changes
   - cong_control: Main congestion control logic

   Example:
     ;; Simple ssthresh implementation
     (def ssthresh-prog
       (dsl/assemble
         (vec (concat
               (struct-ops/struct-ops-prologue :r6)
               ;; Return tp->snd_cwnd (just pass through)
               [(struct-ops/tcp-sock-load-cwnd :r6 :r0)]
               (struct-ops/struct-ops-return)))))"
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; TCP Congestion Control Constants
;; ============================================================================

(def tcp-ca-states
  "TCP Congestion Avoidance states (from tcp.h)"
  {:open         0   ; Normal state
   :disorder     1   ; In all the respects it is 'Open', but requires a bit more attention
   :cwr          2   ; cwr/ecn/etc
   :recovery     3   ; FRTO, etc.
   :loss         4})  ; Loss recovery

(def tcp-ca-events
  "TCP Congestion Avoidance events"
  {:tx-start     0   ; First transmit when no packets in flight
   :cwnd-restart 1   ; Congestion window restart
   :complete-cwr 2   ; End of congestion window reduction
   :loss         3   ; Loss timeout
   :ecn-no-ce    4   ; ECN no CE
   :ecn-is-ce    5   ; ECN CE
   :delay-ack    6   ; Delayed ACK
   :non-delay-ack 7}) ; Non-delayed ACK

(def tcp-ca-ack-flags
  "Flags for in_ack_event callback"
  {:slow          (bit-shift-left 1 0)  ; In slow path
   :ecn           (bit-shift-left 1 1)  ; ECN encoded in IP header
   :ece           (bit-shift-left 1 2)  ; ECE in TCP header
   :delay-ack     (bit-shift-left 1 3)})  ; Delayed ACK mode

;; ============================================================================
;; TCP Socket Field Offsets
;; ============================================================================

(def tcp-sock-offsets
  "Common offsets in struct tcp_sock.
   Note: These are approximate and kernel-version dependent.
   Use BTF for production code."
  {:snd-cwnd        256   ; u32 snd_cwnd
   :snd-ssthresh    260   ; u32 snd_ssthresh
   :srtt-us         268   ; u32 srtt_us (smoothed RTT << 3)
   :mdev-us         272   ; u32 mdev_us (medium deviation)
   :rttvar-us       276   ; u32 rttvar_us
   :packets-out     336   ; u32 packets_out
   :retrans-out     340   ; u32 retrans_out
   :sacked-out      344   ; u32 sacked_out
   :lost-out        348   ; u32 lost_out
   :rcv-wnd         204   ; u32 rcv_wnd
   :snd-wnd         208   ; u32 snd_wnd
   :mss-cache       212   ; u16 mss_cache
   :ecn-flags       220   ; u8 ecn_flags
   :ca-state        232}) ; u8 icsk_ca_state

;; ============================================================================
;; Struct Ops Prologue
;; ============================================================================

(defn struct-ops-prologue
  "Generate standard struct_ops program prologue.

   For TCP congestion control, the first argument (r1) is
   struct sock * (which is at the base of tcp_sock).

   Parameters:
   - sk-reg: Register to save sock pointer (e.g., :r6)

   Returns vector of instructions."
  [sk-reg]
  [(dsl/mov-reg sk-reg :r1)])

(defn struct-ops-prologue-2arg
  "Generate prologue for callbacks with 2 arguments.

   Parameters:
   - sk-reg: Register to save sock pointer
   - arg2-reg: Register to save second argument

   Returns vector of instructions."
  [sk-reg arg2-reg]
  [(dsl/mov-reg sk-reg :r1)
   (dsl/mov-reg arg2-reg :r2)])

(defn struct-ops-prologue-3arg
  "Generate prologue for callbacks with 3 arguments.

   Parameters:
   - sk-reg: Register to save sock pointer
   - arg2-reg: Register to save second argument
   - arg3-reg: Register to save third argument

   Returns vector of instructions."
  [sk-reg arg2-reg arg3-reg]
  [(dsl/mov-reg sk-reg :r1)
   (dsl/mov-reg arg2-reg :r2)
   (dsl/mov-reg arg3-reg :r3)])

;; ============================================================================
;; TCP Socket Field Access
;; ============================================================================

(defn tcp-sock-offset
  "Get offset for a tcp_sock field.

   Parameters:
   - field: Field keyword

   Returns offset or throws on invalid field."
  [field]
  (or (get tcp-sock-offsets field)
      (throw (ex-info "Unknown tcp_sock field"
                      {:field field
                       :valid-fields (keys tcp-sock-offsets)}))))

(defn tcp-sock-load-u32
  "Load a 32-bit field from tcp_sock.

   Parameters:
   - sk-reg: Register containing sock pointer
   - dst-reg: Destination register
   - field: Field keyword (e.g., :snd-cwnd)

   Returns ldx instruction."
  [sk-reg dst-reg field]
  (dsl/ldx :w dst-reg sk-reg (tcp-sock-offset field)))

(defn tcp-sock-load-u16
  "Load a 16-bit field from tcp_sock.

   Parameters:
   - sk-reg: Register containing sock pointer
   - dst-reg: Destination register
   - field: Field keyword

   Returns ldx instruction."
  [sk-reg dst-reg field]
  (dsl/ldx :h dst-reg sk-reg (tcp-sock-offset field)))

(defn tcp-sock-load-u8
  "Load an 8-bit field from tcp_sock.

   Parameters:
   - sk-reg: Register containing sock pointer
   - dst-reg: Destination register
   - field: Field keyword

   Returns ldx instruction."
  [sk-reg dst-reg field]
  (dsl/ldx :b dst-reg sk-reg (tcp-sock-offset field)))

(defn tcp-sock-store-u32
  "Store a 32-bit value to tcp_sock field.

   Parameters:
   - sk-reg: Register containing sock pointer
   - field: Field keyword
   - value-reg: Register containing value to store

   Returns stx instruction."
  [sk-reg field value-reg]
  (dsl/stx :w sk-reg value-reg (tcp-sock-offset field)))

;; Convenience functions for common fields

(defn tcp-sock-load-cwnd
  "Load snd_cwnd from tcp_sock."
  [sk-reg dst-reg]
  (tcp-sock-load-u32 sk-reg dst-reg :snd-cwnd))

(defn tcp-sock-load-ssthresh
  "Load snd_ssthresh from tcp_sock."
  [sk-reg dst-reg]
  (tcp-sock-load-u32 sk-reg dst-reg :snd-ssthresh))

(defn tcp-sock-load-srtt
  "Load srtt_us from tcp_sock (smoothed RTT in usec << 3)."
  [sk-reg dst-reg]
  (tcp-sock-load-u32 sk-reg dst-reg :srtt-us))

(defn tcp-sock-load-packets-out
  "Load packets_out from tcp_sock."
  [sk-reg dst-reg]
  (tcp-sock-load-u32 sk-reg dst-reg :packets-out))

(defn tcp-sock-load-ca-state
  "Load icsk_ca_state from tcp_sock."
  [sk-reg dst-reg]
  (tcp-sock-load-u8 sk-reg dst-reg :ca-state))

(defn tcp-sock-store-cwnd
  "Store value to snd_cwnd in tcp_sock."
  [sk-reg value-reg]
  (tcp-sock-store-u32 sk-reg :snd-cwnd value-reg))

(defn tcp-sock-store-ssthresh
  "Store value to snd_ssthresh in tcp_sock."
  [sk-reg value-reg]
  (tcp-sock-store-u32 sk-reg :snd-ssthresh value-reg))

;; ============================================================================
;; Return Patterns
;; ============================================================================

(defn struct-ops-return
  "Generate return instructions for struct_ops callback.

   Returns r0 and exits."
  []
  [(dsl/exit-insn)])

(defn struct-ops-return-imm
  "Generate instructions to return immediate value.

   Parameters:
   - value: Immediate value to return

   Returns vector of instructions."
  [value]
  [(dsl/mov :r0 value)
   (dsl/exit-insn)])

(defn struct-ops-return-reg
  "Generate instructions to return register value.

   Parameters:
   - reg: Register containing return value

   Returns vector of instructions."
  [reg]
  [(dsl/mov-reg :r0 reg)
   (dsl/exit-insn)])

(defn struct-ops-return-void
  "Generate instructions for void return (returns 0).

   Returns vector of instructions."
  []
  [(dsl/mov :r0 0)
   (dsl/exit-insn)])

;; ============================================================================
;; TCP Congestion Control Callback Helpers
;; ============================================================================

(defn ssthresh-prologue
  "Prologue for ssthresh callback.

   Signature: u32 (*ssthresh)(struct sock *sk)

   Parameters:
   - sk-reg: Register to save sock pointer

   Returns vector of instructions."
  [sk-reg]
  (struct-ops-prologue sk-reg))

(defn cong-avoid-prologue
  "Prologue for cong_avoid callback.

   Signature: void (*cong_avoid)(struct sock *sk, u32 ack, u32 acked)

   Parameters:
   - sk-reg: Register to save sock pointer
   - ack-reg: Register to save ack parameter
   - acked-reg: Register to save acked parameter

   Returns vector of instructions."
  [sk-reg ack-reg acked-reg]
  (struct-ops-prologue-3arg sk-reg ack-reg acked-reg))

(defn set-state-prologue
  "Prologue for set_state callback.

   Signature: void (*set_state)(struct sock *sk, u8 new_state)

   Parameters:
   - sk-reg: Register to save sock pointer
   - state-reg: Register to save new_state parameter

   Returns vector of instructions."
  [sk-reg state-reg]
  (struct-ops-prologue-2arg sk-reg state-reg))

(defn cwnd-event-prologue
  "Prologue for cwnd_event callback.

   Signature: void (*cwnd_event)(struct sock *sk, enum tcp_ca_event ev)

   Parameters:
   - sk-reg: Register to save sock pointer
   - event-reg: Register to save event parameter

   Returns vector of instructions."
  [sk-reg event-reg]
  (struct-ops-prologue-2arg sk-reg event-reg))

(defn pkts-acked-prologue
  "Prologue for pkts_acked callback.

   Signature: void (*pkts_acked)(struct sock *sk, const struct ack_sample *sample)

   Parameters:
   - sk-reg: Register to save sock pointer
   - sample-reg: Register to save sample pointer

   Returns vector of instructions."
  [sk-reg sample-reg]
  (struct-ops-prologue-2arg sk-reg sample-reg))

(defn undo-cwnd-prologue
  "Prologue for undo_cwnd callback.

   Signature: u32 (*undo_cwnd)(struct sock *sk)

   Parameters:
   - sk-reg: Register to save sock pointer

   Returns vector of instructions."
  [sk-reg]
  (struct-ops-prologue sk-reg))

(defn cong-control-prologue
  "Prologue for cong_control callback.

   Signature: void (*cong_control)(struct sock *sk, const struct rate_sample *rs)

   Parameters:
   - sk-reg: Register to save sock pointer
   - rs-reg: Register to save rate_sample pointer

   Returns vector of instructions."
  [sk-reg rs-reg]
  (struct-ops-prologue-2arg sk-reg rs-reg))

(defn init-prologue
  "Prologue for init callback.

   Signature: void (*init)(struct sock *sk)

   Parameters:
   - sk-reg: Register to save sock pointer

   Returns vector of instructions."
  [sk-reg]
  (struct-ops-prologue sk-reg))

(defn release-prologue
  "Prologue for release callback.

   Signature: void (*release)(struct sock *sk)

   Parameters:
   - sk-reg: Register to save sock pointer

   Returns vector of instructions."
  [sk-reg]
  (struct-ops-prologue sk-reg))

;; ============================================================================
;; Common Algorithm Patterns
;; ============================================================================

(defn aimd-ssthresh
  "Generate AIMD (Additive Increase Multiplicative Decrease) ssthresh.

   This is the classic TCP Reno behavior:
   ssthresh = max(cwnd/2, 2)

   Parameters:
   - sk-reg: Register containing sock pointer
   - tmp-reg: Temporary register for calculations

   Returns vector of instructions."
  [sk-reg tmp-reg]
  (vec (concat
        ;; Load cwnd
        [(tcp-sock-load-cwnd sk-reg tmp-reg)]
        ;; Divide by 2 (right shift)
        [(dsl/rsh tmp-reg 1)]
        ;; Ensure at least 2
        [(dsl/jmp-imm :jge tmp-reg 2 1)
         (dsl/mov tmp-reg 2)]
        ;; Return value in r0
        [(dsl/mov-reg :r0 tmp-reg)])))

(defn slow-start-check
  "Check if in slow start (cwnd < ssthresh).

   Parameters:
   - sk-reg: Register containing sock pointer
   - cwnd-reg: Register to load cwnd into
   - ssthresh-reg: Register to load ssthresh into
   - slow-start-skip: Instructions to skip if NOT in slow start

   Returns vector of instructions."
  [sk-reg cwnd-reg ssthresh-reg slow-start-skip]
  [(tcp-sock-load-cwnd sk-reg cwnd-reg)
   (tcp-sock-load-ssthresh sk-reg ssthresh-reg)
   (dsl/jmp-reg :jge cwnd-reg ssthresh-reg slow-start-skip)])

(defn increment-cwnd
  "Increment cwnd by 1 (slow start).

   Parameters:
   - sk-reg: Register containing sock pointer
   - tmp-reg: Temporary register

   Returns vector of instructions."
  [sk-reg tmp-reg]
  [(tcp-sock-load-cwnd sk-reg tmp-reg)
   (dsl/add tmp-reg 1)
   (tcp-sock-store-cwnd sk-reg tmp-reg)])

;; ============================================================================
;; Program Templates
;; ============================================================================

(defn minimal-ssthresh-program
  "Generate minimal ssthresh program (returns cwnd/2, min 2).

   This implements basic AIMD behavior."
  []
  (vec (concat
        (ssthresh-prologue :r6)
        (aimd-ssthresh :r6 :r7)
        (struct-ops-return))))

(defn passthrough-ssthresh-program
  "Generate ssthresh program that returns current ssthresh."
  []
  (vec (concat
        (ssthresh-prologue :r6)
        [(tcp-sock-load-ssthresh :r6 :r0)]
        (struct-ops-return))))

(defn minimal-cong-avoid-program
  "Generate minimal cong_avoid program (void return)."
  []
  (vec (concat
        (cong-avoid-prologue :r6 :r7 :r8)
        (struct-ops-return-void))))

(defn minimal-init-program
  "Generate minimal init program (void return)."
  []
  (vec (concat
        (init-prologue :r6)
        (struct-ops-return-void))))

(defn minimal-release-program
  "Generate minimal release program (void return)."
  []
  (vec (concat
        (release-prologue :r6)
        (struct-ops-return-void))))

(defn minimal-undo-cwnd-program
  "Generate minimal undo_cwnd program (returns current cwnd)."
  []
  (vec (concat
        (undo-cwnd-prologue :r6)
        [(tcp-sock-load-cwnd :r6 :r0)]
        (struct-ops-return))))

;; ============================================================================
;; Struct Ops Metadata
;; ============================================================================

(def tcp-congestion-ops-callbacks
  "TCP congestion control operation callbacks."
  {:ssthresh      {:args 1 :return :u32 :required false}
   :cong-avoid    {:args 3 :return :void :required false}
   :set-state     {:args 2 :return :void :required false}
   :cwnd-event    {:args 2 :return :void :required false}
   :in-ack-event  {:args 2 :return :void :required false}
   :pkts-acked    {:args 2 :return :void :required false}
   :min-tso-segs  {:args 1 :return :u32 :required false}
   :cong-control  {:args 2 :return :void :required false}
   :undo-cwnd     {:args 1 :return :u32 :required false}
   :sndbuf-expand {:args 1 :return :u32 :required false}
   :get-info      {:args 3 :return :size-t :required false}
   :init          {:args 1 :return :void :required false}
   :release       {:args 1 :return :void :required false}})

(defn get-callback-info
  "Get information about a TCP congestion control callback.

   Parameters:
   - callback: Callback keyword (e.g., :ssthresh)

   Returns map with :args, :return, :required."
  [callback]
  (get tcp-congestion-ops-callbacks callback))

;; ============================================================================
;; Section Names
;; ============================================================================

(defn struct-ops-section-name
  "Generate ELF section name for struct_ops program.

   Parameters:
   - struct-name: Target struct name (e.g., \"tcp_congestion_ops\")
   - callback: Callback name (e.g., \"ssthresh\")

   Returns section name string."
  [struct-name callback]
  (str "struct_ops/" struct-name "/" callback))

(defn tcp-cong-ops-section-name
  "Generate ELF section name for TCP congestion control callback.

   Parameters:
   - callback: Callback name (e.g., \"ssthresh\")

   Returns section name string."
  [callback]
  (struct-ops-section-name "tcp_congestion_ops" callback))

;; ============================================================================
;; Program Info
;; ============================================================================

(defn make-struct-ops-info
  "Create struct_ops program metadata.

   Parameters:
   - prog-name: Program name
   - struct-name: Target struct name
   - callback: Callback name
   - instructions: Vector of instructions

   Returns map with program metadata."
  [prog-name struct-name callback instructions]
  {:name prog-name
   :section (struct-ops-section-name struct-name callback)
   :type :struct-ops
   :struct-name struct-name
   :callback callback
   :instructions instructions})

(defn make-tcp-cong-ops-info
  "Create TCP congestion control program metadata.

   Parameters:
   - prog-name: Program name
   - callback: Callback name
   - instructions: Vector of instructions

   Returns map with program metadata."
  [prog-name callback instructions]
  (make-struct-ops-info prog-name "tcp_congestion_ops" callback instructions))
