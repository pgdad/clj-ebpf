(ns clj-ebpf.net.checksum
  "Checksum calculation helpers for eBPF programs.

   These helpers use BPF kernel helper functions for efficient
   checksum updates. Most are designed for TC/SKB programs."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]))

;; ============================================================================
;; BPF Helper Function Numbers
;; ============================================================================

(def BPF-FUNC-csum-diff 28)
(def BPF-FUNC-l3-csum-replace 10)
(def BPF-FUNC-l4-csum-replace 11)
(def BPF-FUNC-csum-update 40)

;; Checksum flags
(def BPF-F-PSEUDO-HDR 0x10)     ; Update pseudo-header checksum
(def BPF-F-MARK-MANGLED-0 0x20) ; Mark checksum as mangled
(def BPF-F-MARK-ENFORCE 0x40)   ; Enforce checksum verification

;; ============================================================================
;; L3 (IP) Checksum Helpers - TC/SKB Programs
;; ============================================================================

(defn l3-csum-replace-4
  "Generate instructions to update L3 (IP) checksum for a 4-byte value change.
   Uses bpf_l3_csum_replace kernel helper.

   For TC programs only (requires SKB).

   skb-reg: SKB pointer register (typically :r1 saved to callee-saved reg)
   csum-offset: Offset to checksum field from packet start
   old-val-reg: Register with old 4-byte value
   new-val-reg: Register with new 4-byte value

   Clobbers: r1-r5, r0 (return value)"
  [skb-reg csum-offset old-val-reg new-val-reg]
  ;; bpf_l3_csum_replace(skb, offset, from, to, flags)
  ;; r1 = skb, r2 = offset, r3 = from, r4 = to, r5 = flags (4 for 4-byte)
  [(dsl/mov-reg :r1 skb-reg)
   (dsl/mov :r2 csum-offset)
   (dsl/mov-reg :r3 old-val-reg)
   (dsl/mov-reg :r4 new-val-reg)
   (dsl/mov :r5 4)                      ; flags = 4 for 4-byte values
   (dsl/call BPF-FUNC-l3-csum-replace)])

(defn l3-csum-replace-2
  "Generate instructions to update L3 checksum for a 2-byte value change.

   skb-reg: SKB pointer register
   csum-offset: Offset to checksum field from packet start
   old-val-reg: Register with old 2-byte value
   new-val-reg: Register with new 2-byte value

   Clobbers: r1-r5, r0"
  [skb-reg csum-offset old-val-reg new-val-reg]
  [(dsl/mov-reg :r1 skb-reg)
   (dsl/mov :r2 csum-offset)
   (dsl/mov-reg :r3 old-val-reg)
   (dsl/mov-reg :r4 new-val-reg)
   (dsl/mov :r5 2)                      ; flags = 2 for 2-byte values
   (dsl/call BPF-FUNC-l3-csum-replace)])

;; ============================================================================
;; L4 (TCP/UDP) Checksum Helpers - TC/SKB Programs
;; ============================================================================

(defn l4-csum-replace-4
  "Generate instructions to update L4 (TCP/UDP) checksum for a 4-byte value change.
   Uses bpf_l4_csum_replace kernel helper.

   For TC programs only (requires SKB).

   skb-reg: SKB pointer register
   csum-offset: Offset to checksum field from packet start
   old-val-reg: Register with old 4-byte value
   new-val-reg: Register with new 4-byte value
   pseudo-hdr?: If true, include BPF_F_PSEUDO_HDR flag (for IP address changes)

   Clobbers: r1-r5, r0"
  [skb-reg csum-offset old-val-reg new-val-reg pseudo-hdr?]
  (let [flags (if pseudo-hdr?
                (bit-or 4 BPF-F-PSEUDO-HDR)
                4)]
    [(dsl/mov-reg :r1 skb-reg)
     (dsl/mov :r2 csum-offset)
     (dsl/mov-reg :r3 old-val-reg)
     (dsl/mov-reg :r4 new-val-reg)
     (dsl/mov :r5 flags)
     (dsl/call BPF-FUNC-l4-csum-replace)]))

(defn l4-csum-replace-2
  "Generate instructions to update L4 checksum for a 2-byte value change.

   skb-reg: SKB pointer register
   csum-offset: Offset to checksum field from packet start
   old-val-reg: Register with old 2-byte value
   new-val-reg: Register with new 2-byte value
   pseudo-hdr?: If true, include BPF_F_PSEUDO_HDR flag

   Clobbers: r1-r5, r0"
  [skb-reg csum-offset old-val-reg new-val-reg pseudo-hdr?]
  (let [flags (if pseudo-hdr?
                (bit-or 2 BPF-F-PSEUDO-HDR)
                2)]
    [(dsl/mov-reg :r1 skb-reg)
     (dsl/mov :r2 csum-offset)
     (dsl/mov-reg :r3 old-val-reg)
     (dsl/mov-reg :r4 new-val-reg)
     (dsl/mov :r5 flags)
     (dsl/call BPF-FUNC-l4-csum-replace)]))

;; ============================================================================
;; Convenience Wrappers
;; ============================================================================

(defn update-ip-checksum
  "Update IP checksum after changing a 4-byte field (e.g., saddr or daddr).

   skb-reg: SKB pointer register
   ip-hdr-offset: Offset to IP header from packet start (typically 14)
   old-val-reg: Register with old value
   new-val-reg: Register with new value

   Clobbers: r1-r5, r0"
  [skb-reg ip-hdr-offset old-val-reg new-val-reg]
  (let [csum-offset (+ ip-hdr-offset (net/ipv4-offset :check))]
    (l3-csum-replace-4 skb-reg csum-offset old-val-reg new-val-reg)))

(defn update-tcp-checksum-for-ip
  "Update TCP checksum after IP address change.
   TCP checksum includes pseudo-header with IP addresses.

   skb-reg: SKB pointer register
   l4-hdr-offset: Offset to TCP header from packet start
   old-ip-reg: Register with old IP address
   new-ip-reg: Register with new IP address

   Clobbers: r1-r5, r0"
  [skb-reg l4-hdr-offset old-ip-reg new-ip-reg]
  (let [csum-offset (+ l4-hdr-offset (net/tcp-offset :check))]
    (l4-csum-replace-4 skb-reg csum-offset old-ip-reg new-ip-reg true)))

(defn update-udp-checksum-for-ip
  "Update UDP checksum after IP address change.
   UDP checksum includes pseudo-header with IP addresses.

   skb-reg: SKB pointer register
   l4-hdr-offset: Offset to UDP header from packet start
   old-ip-reg: Register with old IP address
   new-ip-reg: Register with new IP address

   Clobbers: r1-r5, r0"
  [skb-reg l4-hdr-offset old-ip-reg new-ip-reg]
  (let [csum-offset (+ l4-hdr-offset (net/udp-offset :check))]
    (l4-csum-replace-4 skb-reg csum-offset old-ip-reg new-ip-reg true)))

(defn update-tcp-checksum-for-port
  "Update TCP checksum after port change.

   skb-reg: SKB pointer register
   l4-hdr-offset: Offset to TCP header from packet start
   old-port-reg: Register with old port (network order)
   new-port-reg: Register with new port (network order)

   Clobbers: r1-r5, r0"
  [skb-reg l4-hdr-offset old-port-reg new-port-reg]
  (let [csum-offset (+ l4-hdr-offset (net/tcp-offset :check))]
    (l4-csum-replace-2 skb-reg csum-offset old-port-reg new-port-reg false)))

(defn update-udp-checksum-for-port
  "Update UDP checksum after port change.

   skb-reg: SKB pointer register
   l4-hdr-offset: Offset to UDP header from packet start
   old-port-reg: Register with old port (network order)
   new-port-reg: Register with new port (network order)

   Clobbers: r1-r5, r0"
  [skb-reg l4-hdr-offset old-port-reg new-port-reg]
  (let [csum-offset (+ l4-hdr-offset (net/udp-offset :check))]
    (l4-csum-replace-2 skb-reg csum-offset old-port-reg new-port-reg false)))

;; ============================================================================
;; XDP Checksum Helpers (manual calculation)
;; ============================================================================

;; Note: XDP programs don't have access to bpf_l3_csum_replace and
;; bpf_l4_csum_replace. They must use bpf_csum_diff or calculate manually.

(defn csum-diff
  "Generate instructions to compute checksum difference.
   Uses bpf_csum_diff kernel helper.

   Works in both XDP and TC programs.

   from-ptr-reg: Pointer to old data (can be stack or map value)
   from-size: Size of old data in bytes (must be multiple of 4)
   to-ptr-reg: Pointer to new data
   to-size: Size of new data in bytes (must be multiple of 4)
   seed-reg: Initial checksum value (0 for new calculation)

   Returns: Checksum difference in r0

   Clobbers: r1-r5, r0"
  [from-ptr-reg from-size to-ptr-reg to-size seed-reg]
  ;; bpf_csum_diff(from, from_size, to, to_size, seed)
  [(dsl/mov-reg :r1 from-ptr-reg)
   (dsl/mov :r2 from-size)
   (dsl/mov-reg :r3 to-ptr-reg)
   (dsl/mov :r4 to-size)
   (dsl/mov-reg :r5 seed-reg)
   (dsl/call BPF-FUNC-csum-diff)])

;; ============================================================================
;; Manual Checksum Calculation (for XDP)
;; ============================================================================

(defn fold-csum-32
  "Fold a 32-bit checksum value into 16 bits.
   Used after accumulating checksum values.

   csum-reg: Register containing 32-bit checksum (will be modified to 16-bit)"
  [csum-reg scratch-reg]
  ;; while (csum >> 16)
  ;;   csum = (csum & 0xffff) + (csum >> 16)
  ;; Simplified: do it twice which handles most cases
  [(dsl/mov-reg scratch-reg csum-reg)
   (dsl/rsh scratch-reg 16)
   (dsl/and csum-reg 0xFFFF)
   (dsl/add-reg csum-reg scratch-reg)
   ;; Second fold
   (dsl/mov-reg scratch-reg csum-reg)
   (dsl/rsh scratch-reg 16)
   (dsl/and csum-reg 0xFFFF)
   (dsl/add-reg csum-reg scratch-reg)])

(defn negate-csum
  "Negate checksum (one's complement).

   csum-reg: Register containing checksum (will be negated)"
  [csum-reg]
  [(dsl/xor-op csum-reg 0xFFFF)
   (dsl/and csum-reg 0xFFFF)])
