(ns clj-ebpf.net.ipv4
  "IPv4 packet parsing and manipulation helpers for eBPF programs."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]))

;; ============================================================================
;; IPv4 Header Field Access
;; ============================================================================

(defn load-field
  "Load an IPv4 header field into dst-reg.

   dst-reg: Destination register
   ip-hdr-reg: Register pointing to start of IP header
   field: Field keyword (:protocol, :saddr, :daddr, etc.)
   size: :b (byte), :h (half-word), :w (word)"
  [dst-reg ip-hdr-reg field size]
  (let [offset (net/ipv4-offset field)]
    [(dsl/ldx size dst-reg ip-hdr-reg offset)]))

(defn load-ihl
  "Load IPv4 header length (in bytes) into dst-reg.
   Extracts IHL field and multiplies by 4.

   dst-reg: Destination register for header length
   ip-hdr-reg: Register pointing to IP header start"
  [dst-reg ip-hdr-reg]
  [(dsl/ldx :b dst-reg ip-hdr-reg (net/ipv4-offset :version-ihl))
   (dsl/and dst-reg 0x0F)    ; Mask to get IHL (lower 4 bits)
   (dsl/lsh dst-reg 2)])     ; Multiply by 4

(defn load-protocol
  "Load IP protocol number into dst-reg.

   dst-reg: Destination register
   ip-hdr-reg: Register pointing to IP header"
  [dst-reg ip-hdr-reg]
  (load-field dst-reg ip-hdr-reg :protocol :b))

(defn load-saddr
  "Load source IP address into dst-reg.

   dst-reg: Destination register
   ip-hdr-reg: Register pointing to IP header"
  [dst-reg ip-hdr-reg]
  (load-field dst-reg ip-hdr-reg :saddr :w))

(defn load-daddr
  "Load destination IP address into dst-reg.

   dst-reg: Destination register
   ip-hdr-reg: Register pointing to IP header"
  [dst-reg ip-hdr-reg]
  (load-field dst-reg ip-hdr-reg :daddr :w))

(defn load-ttl
  "Load TTL field into dst-reg.

   dst-reg: Destination register
   ip-hdr-reg: Register pointing to IP header"
  [dst-reg ip-hdr-reg]
  (load-field dst-reg ip-hdr-reg :ttl :b))

(defn load-total-len
  "Load total length field into dst-reg (network byte order).

   dst-reg: Destination register
   ip-hdr-reg: Register pointing to IP header"
  [dst-reg ip-hdr-reg]
  (load-field dst-reg ip-hdr-reg :tot-len :h))

(defn parse-addrs
  "Load source and destination IPs into registers.

   saddr-reg: Register for source IP
   daddr-reg: Register for destination IP
   ip-hdr-reg: Register pointing to IP header"
  [saddr-reg daddr-reg ip-hdr-reg]
  [(dsl/ldx :w saddr-reg ip-hdr-reg (net/ipv4-offset :saddr))
   (dsl/ldx :w daddr-reg ip-hdr-reg (net/ipv4-offset :daddr))])

;; ============================================================================
;; IPv4 Header Field Storage
;; ============================================================================

(defn store-field
  "Store value to IPv4 header field.

   ip-hdr-reg: Register pointing to IP header start
   field: Field keyword
   src-reg: Register containing value to store
   size: :b, :h, or :w"
  [ip-hdr-reg field src-reg size]
  (let [offset (net/ipv4-offset field)]
    [(dsl/stx size ip-hdr-reg src-reg offset)]))

(defn store-saddr
  "Store source IP address.

   ip-hdr-reg: Register pointing to IP header
   addr-reg: Register containing new source IP"
  [ip-hdr-reg addr-reg]
  (store-field ip-hdr-reg :saddr addr-reg :w))

(defn store-daddr
  "Store destination IP address.

   ip-hdr-reg: Register pointing to IP header
   addr-reg: Register containing new destination IP"
  [ip-hdr-reg addr-reg]
  (store-field ip-hdr-reg :daddr addr-reg :w))

(defn store-ttl
  "Store TTL field.

   ip-hdr-reg: Register pointing to IP header
   ttl-reg: Register containing new TTL value"
  [ip-hdr-reg ttl-reg]
  (store-field ip-hdr-reg :ttl ttl-reg :b))

;; ============================================================================
;; Protocol Checks
;; ============================================================================

(defn is-tcp
  "Check if IP protocol is TCP.
   Jumps to tcp-label if TCP, falls through otherwise.

   proto-reg: Register containing protocol number
   tcp-label: Label offset to jump to if TCP"
  [proto-reg tcp-label]
  [(dsl/jmp-imm :jeq proto-reg net/IPPROTO-TCP tcp-label)])

(defn is-udp
  "Check if IP protocol is UDP.
   Jumps to udp-label if UDP, falls through otherwise.

   proto-reg: Register containing protocol number
   udp-label: Label offset to jump to if UDP"
  [proto-reg udp-label]
  [(dsl/jmp-imm :jeq proto-reg net/IPPROTO-UDP udp-label)])

(defn is-icmp
  "Check if IP protocol is ICMP.
   Jumps to icmp-label if ICMP, falls through otherwise.

   proto-reg: Register containing protocol number
   icmp-label: Label offset to jump to if ICMP"
  [proto-reg icmp-label]
  [(dsl/jmp-imm :jeq proto-reg net/IPPROTO-ICMP icmp-label)])

;; ============================================================================
;; L4 Header Pointer Calculation
;; ============================================================================

(defn get-l4-ptr-fixed
  "Calculate L4 header pointer assuming fixed 20-byte IP header (no options).

   l4-ptr-reg: Register to store L4 header pointer
   ip-hdr-reg: Register pointing to IP header"
  [l4-ptr-reg ip-hdr-reg]
  [(dsl/mov-reg l4-ptr-reg ip-hdr-reg)
   (dsl/add l4-ptr-reg net/IPV4-MIN-HLEN)])

(defn get-l4-ptr-dynamic
  "Calculate L4 header pointer using IHL field (handles IP options).

   l4-ptr-reg: Register to store L4 header pointer
   ip-hdr-reg: Register pointing to IP header
   ihl-reg: Register to store IHL (will be modified)"
  [l4-ptr-reg ip-hdr-reg ihl-reg]
  (concat
   ;; Get IHL in bytes
   (load-ihl ihl-reg ip-hdr-reg)
   ;; l4-ptr = ip-hdr + ihl
   [(dsl/mov-reg l4-ptr-reg ip-hdr-reg)
    (dsl/add-reg l4-ptr-reg ihl-reg)]))

;; ============================================================================
;; Convenience Functions
;; ============================================================================

(defn parse-ipv4-header
  "Parse IPv4 header and check bounds.
   Returns instructions that:
   1. Check bounds for minimum IP header (20 bytes)
   2. Load protocol into proto-reg
   3. Calculate L4 header pointer (fixed offset)

   ip-hdr-reg: Register pointing to IP header start
   data-end-reg: Register containing data_end pointer
   proto-reg: Register to store protocol
   l4-ptr-reg: Register to store L4 header pointer
   fail-label: Label to jump to on bounds failure
   scratch-reg: Scratch register for bounds check"
  [ip-hdr-reg data-end-reg proto-reg l4-ptr-reg fail-label scratch-reg]
  (concat
   ;; Check we have at least minimum IP header
   (net/check-bounds ip-hdr-reg data-end-reg net/IPV4-MIN-HLEN fail-label scratch-reg)
   ;; Load protocol
   (load-protocol proto-reg ip-hdr-reg)
   ;; Calculate L4 pointer (assuming no options for simplicity)
   (get-l4-ptr-fixed l4-ptr-reg ip-hdr-reg)))

(defn parse-ipv4-header-dynamic
  "Parse IPv4 header with dynamic IHL (handles IP options).
   Returns instructions that:
   1. Check bounds for minimum IP header
   2. Load IHL and check bounds for actual header size
   3. Load protocol
   4. Calculate L4 header pointer

   ip-hdr-reg: Register pointing to IP header start
   data-end-reg: Register containing data_end pointer
   proto-reg: Register to store protocol
   l4-ptr-reg: Register to store L4 header pointer
   ihl-reg: Register for IHL (scratch)
   fail-label: Label to jump to on bounds failure
   scratch-reg: Scratch register for bounds check"
  [ip-hdr-reg data-end-reg proto-reg l4-ptr-reg ihl-reg fail-label scratch-reg]
  (concat
   ;; Check minimum IP header bounds first
   (net/check-bounds ip-hdr-reg data-end-reg net/IPV4-MIN-HLEN fail-label scratch-reg)
   ;; Load IHL
   (load-ihl ihl-reg ip-hdr-reg)
   ;; Check actual header size bounds
   (net/check-bounds-dynamic ip-hdr-reg data-end-reg ihl-reg fail-label scratch-reg)
   ;; Load protocol
   (load-protocol proto-reg ip-hdr-reg)
   ;; Calculate L4 pointer
   [(dsl/mov-reg l4-ptr-reg ip-hdr-reg)
    (dsl/add-reg l4-ptr-reg ihl-reg)]))

(defn decrement-ttl
  "Decrement TTL by 1 and check for zero.
   Jumps to drop-label if TTL reaches 0.

   ip-hdr-reg: Register pointing to IP header
   ttl-reg: Register to use for TTL (will be modified)
   drop-label: Label to jump to if TTL is 0"
  [ip-hdr-reg ttl-reg drop-label]
  (concat
   ;; Load TTL
   (load-ttl ttl-reg ip-hdr-reg)
   ;; Check if already 0 or 1
   [(dsl/jmp-imm :jle ttl-reg 1 drop-label)]
   ;; Decrement
   [(dsl/sub ttl-reg 1)]
   ;; Store back
   (store-ttl ip-hdr-reg ttl-reg)))
