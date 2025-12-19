(ns clj-ebpf.net.nat
  "NAT (Network Address Translation) primitives for eBPF programs.

   Provides high-level operations for DNAT (Destination NAT) and
   SNAT (Source NAT) that combine packet modification with checksum
   updates.

   These helpers are primarily designed for TC/SKB programs that
   have access to kernel checksum helper functions."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]
            [clj-ebpf.net.checksum :as csum]))

;; ============================================================================
;; DNAT (Destination NAT) - TC/SKB Programs
;; ============================================================================

(defn dnat-ip
  "Generate instructions for Destination NAT - IP address only.
   Rewrites destination IP and updates checksums.

   For TC programs only (requires SKB for checksum helpers).

   skb-reg: SKB pointer register (callee-saved, e.g., :r6)
   data-reg: Packet data pointer register
   ip-hdr-offset: Offset to IP header from packet start (typically 14)
   l4-hdr-offset: Offset to L4 header from packet start
   l4-proto: :tcp or :udp
   old-daddr-reg: Register with original dest IP
   new-daddr-reg: Register with new dest IP
   scratch-reg: Scratch register for calculations

   Clobbers: r0-r5, scratch-reg"
  [skb-reg data-reg ip-hdr-offset l4-hdr-offset l4-proto
   old-daddr-reg new-daddr-reg scratch-reg]
  (concat
   ;; Calculate IP header pointer and store new destination IP
   [(dsl/mov-reg scratch-reg data-reg)
    (dsl/add scratch-reg (+ ip-hdr-offset (net/ipv4-offset :daddr)))
    (dsl/stx :w scratch-reg new-daddr-reg 0)]

   ;; Update IP checksum
   (csum/update-ip-checksum skb-reg ip-hdr-offset old-daddr-reg new-daddr-reg)

   ;; Update L4 checksum (includes pseudo-header with IP addresses)
   (case l4-proto
     :tcp (csum/update-tcp-checksum-for-ip skb-reg l4-hdr-offset old-daddr-reg new-daddr-reg)
     :udp (csum/update-udp-checksum-for-ip skb-reg l4-hdr-offset old-daddr-reg new-daddr-reg))))

(defn dnat-port
  "Generate instructions to rewrite destination port.

   For TC programs only.

   skb-reg: SKB pointer register
   data-reg: Packet data pointer register
   l4-hdr-offset: Offset to L4 header from packet start
   l4-proto: :tcp or :udp
   old-port-reg: Register with original port (network order)
   new-port-reg: Register with new port (network order)
   scratch-reg: Scratch register

   Clobbers: r0-r5, scratch-reg"
  [skb-reg data-reg l4-hdr-offset l4-proto old-port-reg new-port-reg scratch-reg]
  (let [port-offset (case l4-proto
                      :tcp (net/tcp-offset :dport)
                      :udp (net/udp-offset :dport))]
    (concat
     ;; Store new port
     [(dsl/mov-reg scratch-reg data-reg)
      (dsl/add scratch-reg (+ l4-hdr-offset port-offset))
      (dsl/stx :h scratch-reg new-port-reg 0)]

     ;; Update L4 checksum
     (case l4-proto
       :tcp (csum/update-tcp-checksum-for-port skb-reg l4-hdr-offset old-port-reg new-port-reg)
       :udp (csum/update-udp-checksum-for-port skb-reg l4-hdr-offset old-port-reg new-port-reg)))))

(defn full-dnat
  "Complete DNAT operation: rewrite both IP and port.
   Convenience wrapper combining dnat-ip and dnat-port.

   For TC programs only.

   skb-reg: SKB pointer register
   data-reg: Packet data pointer register
   ip-hdr-offset: Offset to IP header (typically 14)
   l4-hdr-offset: Offset to L4 header
   l4-proto: :tcp or :udp
   old-daddr-reg: Register with original dest IP
   new-daddr-reg: Register with new dest IP
   old-dport-reg: Register with original dest port (network order)
   new-dport-reg: Register with new dest port (network order)
   scratch-reg: Scratch register

   Clobbers: r0-r5, scratch-reg"
  [skb-reg data-reg ip-hdr-offset l4-hdr-offset l4-proto
   old-daddr-reg new-daddr-reg old-dport-reg new-dport-reg scratch-reg]
  (concat
   (dnat-ip skb-reg data-reg ip-hdr-offset l4-hdr-offset l4-proto
            old-daddr-reg new-daddr-reg scratch-reg)
   (dnat-port skb-reg data-reg l4-hdr-offset l4-proto
              old-dport-reg new-dport-reg scratch-reg)))

;; ============================================================================
;; SNAT (Source NAT) - TC/SKB Programs
;; ============================================================================

(defn snat-ip
  "Generate instructions for Source NAT - IP address only.
   Rewrites source IP and updates checksums.

   For TC programs only.

   skb-reg: SKB pointer register
   data-reg: Packet data pointer register
   ip-hdr-offset: Offset to IP header from packet start
   l4-hdr-offset: Offset to L4 header from packet start
   l4-proto: :tcp or :udp
   old-saddr-reg: Register with original source IP
   new-saddr-reg: Register with new source IP
   scratch-reg: Scratch register

   Clobbers: r0-r5, scratch-reg"
  [skb-reg data-reg ip-hdr-offset l4-hdr-offset l4-proto
   old-saddr-reg new-saddr-reg scratch-reg]
  (concat
   ;; Store new source IP
   [(dsl/mov-reg scratch-reg data-reg)
    (dsl/add scratch-reg (+ ip-hdr-offset (net/ipv4-offset :saddr)))
    (dsl/stx :w scratch-reg new-saddr-reg 0)]

   ;; Update IP checksum
   (csum/update-ip-checksum skb-reg ip-hdr-offset old-saddr-reg new-saddr-reg)

   ;; Update L4 checksum
   (case l4-proto
     :tcp (csum/update-tcp-checksum-for-ip skb-reg l4-hdr-offset old-saddr-reg new-saddr-reg)
     :udp (csum/update-udp-checksum-for-ip skb-reg l4-hdr-offset old-saddr-reg new-saddr-reg))))

(defn snat-port
  "Generate instructions to rewrite source port.

   For TC programs only.

   skb-reg: SKB pointer register
   data-reg: Packet data pointer register
   l4-hdr-offset: Offset to L4 header from packet start
   l4-proto: :tcp or :udp
   old-port-reg: Register with original port (network order)
   new-port-reg: Register with new port (network order)
   scratch-reg: Scratch register

   Clobbers: r0-r5, scratch-reg"
  [skb-reg data-reg l4-hdr-offset l4-proto old-port-reg new-port-reg scratch-reg]
  (let [port-offset (case l4-proto
                      :tcp (net/tcp-offset :sport)
                      :udp (net/udp-offset :sport))]
    (concat
     ;; Store new port
     [(dsl/mov-reg scratch-reg data-reg)
      (dsl/add scratch-reg (+ l4-hdr-offset port-offset))
      (dsl/stx :h scratch-reg new-port-reg 0)]

     ;; Update L4 checksum
     (case l4-proto
       :tcp (csum/update-tcp-checksum-for-port skb-reg l4-hdr-offset old-port-reg new-port-reg)
       :udp (csum/update-udp-checksum-for-port skb-reg l4-hdr-offset old-port-reg new-port-reg)))))

(defn full-snat
  "Complete SNAT operation: rewrite both IP and port.

   For TC programs only.

   skb-reg: SKB pointer register
   data-reg: Packet data pointer register
   ip-hdr-offset: Offset to IP header
   l4-hdr-offset: Offset to L4 header
   l4-proto: :tcp or :udp
   old-saddr-reg: Register with original source IP
   new-saddr-reg: Register with new source IP
   old-sport-reg: Register with original source port (network order)
   new-sport-reg: Register with new source port (network order)
   scratch-reg: Scratch register

   Clobbers: r0-r5, scratch-reg"
  [skb-reg data-reg ip-hdr-offset l4-hdr-offset l4-proto
   old-saddr-reg new-saddr-reg old-sport-reg new-sport-reg scratch-reg]
  (concat
   (snat-ip skb-reg data-reg ip-hdr-offset l4-hdr-offset l4-proto
            old-saddr-reg new-saddr-reg scratch-reg)
   (snat-port skb-reg data-reg l4-hdr-offset l4-proto
              old-sport-reg new-sport-reg scratch-reg)))

;; ============================================================================
;; Full NAT (both directions)
;; ============================================================================

(defn full-nat
  "Perform both SNAT and DNAT in one operation.
   Useful for implementing a NAT gateway or load balancer.

   For TC programs only.

   skb-reg: SKB pointer register
   data-reg: Packet data pointer register
   ip-hdr-offset: Offset to IP header
   l4-hdr-offset: Offset to L4 header
   l4-proto: :tcp or :udp
   old-saddr-reg: Original source IP
   new-saddr-reg: New source IP
   old-daddr-reg: Original dest IP
   new-daddr-reg: New dest IP
   old-sport-reg: Original source port (network order)
   new-sport-reg: New source port (network order)
   old-dport-reg: Original dest port (network order)
   new-dport-reg: New dest port (network order)
   scratch-reg: Scratch register

   Clobbers: r0-r5, scratch-reg"
  [skb-reg data-reg ip-hdr-offset l4-hdr-offset l4-proto
   old-saddr-reg new-saddr-reg old-daddr-reg new-daddr-reg
   old-sport-reg new-sport-reg old-dport-reg new-dport-reg
   scratch-reg]
  (concat
   (full-snat skb-reg data-reg ip-hdr-offset l4-hdr-offset l4-proto
              old-saddr-reg new-saddr-reg old-sport-reg new-sport-reg scratch-reg)
   (full-dnat skb-reg data-reg ip-hdr-offset l4-hdr-offset l4-proto
              old-daddr-reg new-daddr-reg old-dport-reg new-dport-reg scratch-reg)))

;; ============================================================================
;; XDP NAT Helpers (Direct Packet Access)
;; ============================================================================

;; Note: XDP programs must use bpf_csum_diff or manual checksum calculation
;; since bpf_l3/l4_csum_replace are not available.

(defn xdp-rewrite-daddr
  "Rewrite destination IP address in XDP program.
   Does NOT update checksums - caller must handle checksum updates.

   data-reg: Packet data pointer
   ip-hdr-offset: Offset to IP header
   new-daddr-reg: Register with new destination IP
   scratch-reg: Scratch register"
  [data-reg ip-hdr-offset new-daddr-reg scratch-reg]
  [(dsl/mov-reg scratch-reg data-reg)
   (dsl/add scratch-reg (+ ip-hdr-offset (net/ipv4-offset :daddr)))
   (dsl/stx :w scratch-reg new-daddr-reg 0)])

(defn xdp-rewrite-saddr
  "Rewrite source IP address in XDP program.
   Does NOT update checksums - caller must handle checksum updates.

   data-reg: Packet data pointer
   ip-hdr-offset: Offset to IP header
   new-saddr-reg: Register with new source IP
   scratch-reg: Scratch register"
  [data-reg ip-hdr-offset new-saddr-reg scratch-reg]
  [(dsl/mov-reg scratch-reg data-reg)
   (dsl/add scratch-reg (+ ip-hdr-offset (net/ipv4-offset :saddr)))
   (dsl/stx :w scratch-reg new-saddr-reg 0)])

(defn xdp-rewrite-dport
  "Rewrite destination port in XDP program.
   Does NOT update checksums.

   data-reg: Packet data pointer
   l4-hdr-offset: Offset to L4 header
   l4-proto: :tcp or :udp
   new-port-reg: Register with new port (network order)
   scratch-reg: Scratch register"
  [data-reg l4-hdr-offset l4-proto new-port-reg scratch-reg]
  (let [port-offset (case l4-proto
                      :tcp (net/tcp-offset :dport)
                      :udp (net/udp-offset :dport))]
    [(dsl/mov-reg scratch-reg data-reg)
     (dsl/add scratch-reg (+ l4-hdr-offset port-offset))
     (dsl/stx :h scratch-reg new-port-reg 0)]))

(defn xdp-rewrite-sport
  "Rewrite source port in XDP program.
   Does NOT update checksums.

   data-reg: Packet data pointer
   l4-hdr-offset: Offset to L4 header
   l4-proto: :tcp or :udp
   new-port-reg: Register with new port (network order)
   scratch-reg: Scratch register"
  [data-reg l4-hdr-offset l4-proto new-port-reg scratch-reg]
  (let [port-offset (case l4-proto
                      :tcp (net/tcp-offset :sport)
                      :udp (net/udp-offset :sport))]
    [(dsl/mov-reg scratch-reg data-reg)
     (dsl/add scratch-reg (+ l4-hdr-offset port-offset))
     (dsl/stx :h scratch-reg new-port-reg 0)]))
