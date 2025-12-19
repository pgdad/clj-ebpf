(ns clj-ebpf.net.tcp
  "TCP packet parsing and manipulation helpers for eBPF programs."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]))

;; ============================================================================
;; TCP Header Field Access
;; ============================================================================

(defn load-field
  "Load a TCP header field into dst-reg.

   dst-reg: Destination register
   tcp-hdr-reg: Register pointing to start of TCP header
   field: Field keyword (:sport, :dport, :seq, etc.)
   size: :b (byte), :h (half-word), :w (word)"
  [dst-reg tcp-hdr-reg field size]
  (let [offset (net/tcp-offset field)]
    [(dsl/ldx size dst-reg tcp-hdr-reg offset)]))

(defn load-sport
  "Load TCP source port into dst-reg (network byte order).

   dst-reg: Destination register
   tcp-hdr-reg: Register pointing to TCP header"
  [dst-reg tcp-hdr-reg]
  (load-field dst-reg tcp-hdr-reg :sport :h))

(defn load-dport
  "Load TCP destination port into dst-reg (network byte order).

   dst-reg: Destination register
   tcp-hdr-reg: Register pointing to TCP header"
  [dst-reg tcp-hdr-reg]
  (load-field dst-reg tcp-hdr-reg :dport :h))

(defn load-ports
  "Load TCP source and destination ports.
   Ports are loaded in network byte order.

   sport-reg: Register for source port
   dport-reg: Register for destination port
   tcp-hdr-reg: Register pointing to TCP header"
  [sport-reg dport-reg tcp-hdr-reg]
  [(dsl/ldx :h sport-reg tcp-hdr-reg (net/tcp-offset :sport))
   (dsl/ldx :h dport-reg tcp-hdr-reg (net/tcp-offset :dport))])

(defn load-ports-host
  "Load TCP source and destination ports in host byte order.

   sport-reg: Register for source port (host order)
   dport-reg: Register for destination port (host order)
   tcp-hdr-reg: Register pointing to TCP header"
  [sport-reg dport-reg tcp-hdr-reg]
  [(dsl/ldx :h sport-reg tcp-hdr-reg (net/tcp-offset :sport))
   (dsl/end-to-be sport-reg 16)
   (dsl/ldx :h dport-reg tcp-hdr-reg (net/tcp-offset :dport))
   (dsl/end-to-be dport-reg 16)])

(defn load-seq
  "Load TCP sequence number into dst-reg (network byte order).

   dst-reg: Destination register
   tcp-hdr-reg: Register pointing to TCP header"
  [dst-reg tcp-hdr-reg]
  (load-field dst-reg tcp-hdr-reg :seq :w))

(defn load-ack-seq
  "Load TCP acknowledgment number into dst-reg (network byte order).

   dst-reg: Destination register
   tcp-hdr-reg: Register pointing to TCP header"
  [dst-reg tcp-hdr-reg]
  (load-field dst-reg tcp-hdr-reg :ack-seq :w))

(defn load-flags
  "Load TCP flags byte into register.

   dst-reg: Destination register
   tcp-hdr-reg: Register pointing to TCP header"
  [dst-reg tcp-hdr-reg]
  [(dsl/ldx :b dst-reg tcp-hdr-reg (net/tcp-offset :flags))])

(defn load-data-offset
  "Load TCP data offset (header length in 32-bit words) into dst-reg.

   dst-reg: Destination register
   tcp-hdr-reg: Register pointing to TCP header"
  [dst-reg tcp-hdr-reg]
  [(dsl/ldx :b dst-reg tcp-hdr-reg (net/tcp-offset :data-off))
   (dsl/rsh dst-reg 4)       ; Upper 4 bits contain data offset
   (dsl/and dst-reg 0x0F)])

(defn load-header-len
  "Load TCP header length in bytes into dst-reg.

   dst-reg: Destination register
   tcp-hdr-reg: Register pointing to TCP header"
  [dst-reg tcp-hdr-reg]
  [(dsl/ldx :b dst-reg tcp-hdr-reg (net/tcp-offset :data-off))
   (dsl/rsh dst-reg 4)       ; Upper 4 bits contain data offset
   (dsl/and dst-reg 0x0F)
   (dsl/lsh dst-reg 2)])     ; Multiply by 4 for bytes

(defn load-window
  "Load TCP window size into dst-reg (network byte order).

   dst-reg: Destination register
   tcp-hdr-reg: Register pointing to TCP header"
  [dst-reg tcp-hdr-reg]
  (load-field dst-reg tcp-hdr-reg :window :h))

;; ============================================================================
;; TCP Header Field Storage
;; ============================================================================

(defn store-field
  "Store value to TCP header field.

   tcp-hdr-reg: Register pointing to TCP header start
   field: Field keyword
   src-reg: Register containing value to store
   size: :b, :h, or :w"
  [tcp-hdr-reg field src-reg size]
  (let [offset (net/tcp-offset field)]
    [(dsl/stx size tcp-hdr-reg src-reg offset)]))

(defn store-sport
  "Store TCP source port (expects network byte order).

   tcp-hdr-reg: Register pointing to TCP header
   port-reg: Register containing port (network order)"
  [tcp-hdr-reg port-reg]
  (store-field tcp-hdr-reg :sport port-reg :h))

(defn store-dport
  "Store TCP destination port (expects network byte order).

   tcp-hdr-reg: Register pointing to TCP header
   port-reg: Register containing port (network order)"
  [tcp-hdr-reg port-reg]
  (store-field tcp-hdr-reg :dport port-reg :h))

(defn store-port-host
  "Store TCP port from host byte order value.

   tcp-hdr-reg: Register pointing to TCP header
   field: :sport or :dport
   port-reg: Register containing port (host order)
   scratch-reg: Scratch register for byte order conversion"
  [tcp-hdr-reg field port-reg scratch-reg]
  (let [offset (net/tcp-offset field)]
    [(dsl/mov-reg scratch-reg port-reg)
     (dsl/end-to-be scratch-reg 16)      ; Convert to network order
     (dsl/stx :h tcp-hdr-reg scratch-reg offset)]))

;; ============================================================================
;; TCP Flag Checks
;; ============================================================================

(defn is-syn
  "Check if TCP SYN flag is set.
   Jumps to syn-label if SYN is set, falls through otherwise.

   flags-reg: Register containing TCP flags
   syn-label: Label offset to jump to if SYN"
  [flags-reg syn-label]
  [(dsl/jmp-imm :jset flags-reg net/TCP-SYN syn-label)])

(defn is-ack
  "Check if TCP ACK flag is set.

   flags-reg: Register containing TCP flags
   ack-label: Label offset to jump to if ACK"
  [flags-reg ack-label]
  [(dsl/jmp-imm :jset flags-reg net/TCP-ACK ack-label)])

(defn is-fin
  "Check if TCP FIN flag is set.

   flags-reg: Register containing TCP flags
   fin-label: Label offset to jump to if FIN"
  [flags-reg fin-label]
  [(dsl/jmp-imm :jset flags-reg net/TCP-FIN fin-label)])

(defn is-rst
  "Check if TCP RST flag is set.

   flags-reg: Register containing TCP flags
   rst-label: Label offset to jump to if RST"
  [flags-reg rst-label]
  [(dsl/jmp-imm :jset flags-reg net/TCP-RST rst-label)])

(defn is-psh
  "Check if TCP PSH flag is set.

   flags-reg: Register containing TCP flags
   psh-label: Label offset to jump to if PSH"
  [flags-reg psh-label]
  [(dsl/jmp-imm :jset flags-reg net/TCP-PSH psh-label)])

(defn is-syn-only
  "Check if only SYN flag is set (connection initiation).
   Jumps to syn-only-label if SYN is set and ACK is not.

   flags-reg: Register containing TCP flags
   scratch-reg: Scratch register
   syn-only-label: Label offset to jump to if SYN-only"
  [flags-reg scratch-reg syn-only-label]
  [(dsl/mov-reg scratch-reg flags-reg)
   (dsl/and scratch-reg (bit-or net/TCP-SYN net/TCP-ACK))
   (dsl/jmp-imm :jeq scratch-reg net/TCP-SYN syn-only-label)])

(defn is-syn-ack
  "Check if SYN and ACK flags are both set.

   flags-reg: Register containing TCP flags
   scratch-reg: Scratch register
   syn-ack-label: Label offset to jump to if SYN+ACK"
  [flags-reg scratch-reg syn-ack-label]
  (let [syn-ack (bit-or net/TCP-SYN net/TCP-ACK)]
    [(dsl/mov-reg scratch-reg flags-reg)
     (dsl/and scratch-reg syn-ack)
     (dsl/jmp-imm :jeq scratch-reg syn-ack syn-ack-label)]))

;; ============================================================================
;; Port Checks
;; ============================================================================

(defn is-dport
  "Check if destination port matches (network byte order comparison).

   dport-reg: Register containing destination port (network order)
   port: Port number (will be converted to network order)
   match-label: Label to jump to if ports match"
  [dport-reg port match-label]
  ;; Convert port to network byte order for comparison
  (let [port-be (bit-or (bit-shift-left (bit-and port 0xFF) 8)
                        (bit-shift-right (bit-and port 0xFF00) 8))]
    [(dsl/jmp-imm :jeq dport-reg port-be match-label)]))

(defn is-sport
  "Check if source port matches (network byte order comparison).

   sport-reg: Register containing source port (network order)
   port: Port number (will be converted to network order)
   match-label: Label to jump to if ports match"
  [sport-reg port match-label]
  (let [port-be (bit-or (bit-shift-left (bit-and port 0xFF) 8)
                        (bit-shift-right (bit-and port 0xFF00) 8))]
    [(dsl/jmp-imm :jeq sport-reg port-be match-label)]))

;; ============================================================================
;; Convenience Functions
;; ============================================================================

(defn parse-tcp-header
  "Parse TCP header and check bounds.
   Returns instructions that:
   1. Check bounds for minimum TCP header (20 bytes)
   2. Load source and destination ports

   tcp-hdr-reg: Register pointing to TCP header start
   data-end-reg: Register containing data_end pointer
   sport-reg: Register to store source port
   dport-reg: Register to store destination port
   fail-label: Label to jump to on bounds failure
   scratch-reg: Scratch register for bounds check"
  [tcp-hdr-reg data-end-reg sport-reg dport-reg fail-label scratch-reg]
  (concat
   (net/check-bounds tcp-hdr-reg data-end-reg net/TCP-MIN-HLEN fail-label scratch-reg)
   (load-ports sport-reg dport-reg tcp-hdr-reg)))

(defn get-payload-ptr
  "Calculate pointer to TCP payload.
   Requires knowing TCP header length (data offset).

   payload-reg: Register to store payload pointer
   tcp-hdr-reg: Register pointing to TCP header
   tcp-hlen-reg: Register containing TCP header length in bytes"
  [payload-reg tcp-hdr-reg tcp-hlen-reg]
  [(dsl/mov-reg payload-reg tcp-hdr-reg)
   (dsl/add-reg payload-reg tcp-hlen-reg)])
