(ns clj-ebpf.net.ipv6
  "IPv6 address loading helpers for packet parsing.

   IPv6 addresses are 16 bytes and require multiple load/store operations.
   These helpers simplify loading IPv6 addresses from packets to stack
   and provide a 'unified' format for dual-stack (IPv4/IPv6) handling.

   Usage:
     (require '[clj-ebpf.net.ipv6 :as ipv6])

     ;; Load IPv6 source address from packet to stack
     (ipv6/build-load-ipv6-address :r9 ipv6/IPV6-OFF-SRC -84)

     ;; Load IPv4 address in unified 16-byte format
     (ipv6/build-load-ipv4-unified :r9 12 -84)"
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; IPv6 Header Constants
;; ============================================================================

(def ^:const IPV6-OFF-VERSION       0)   ; Version, Traffic Class, Flow Label
(def ^:const IPV6-OFF-PAYLOAD-LEN   4)   ; Payload length
(def ^:const IPV6-OFF-NEXT-HEADER   6)   ; Next header protocol
(def ^:const IPV6-OFF-HOP-LIMIT     7)   ; Hop limit (TTL equivalent)
(def ^:const IPV6-OFF-SRC           8)   ; Source address (16 bytes)
(def ^:const IPV6-OFF-DST          24)   ; Destination address (16 bytes)
(def ^:const IPV6-HLEN             40)   ; IPv6 header length (no extensions)
(def ^:const IPV6-ADDR-LEN         16)   ; IPv6 address length

;; ============================================================================
;; IPv4 Header Constants (for unified format)
;; ============================================================================

(def ^:const IPV4-OFF-SRC          12)   ; Source address offset in IPv4 header
(def ^:const IPV4-OFF-DST          16)   ; Destination address offset in IPv4 header
(def ^:const IPV4-ADDR-LEN          4)   ; IPv4 address length

;; ============================================================================
;; IPv6 Address Loading
;; ============================================================================

(defn build-load-ipv6-address
  "Generate instructions to load a 16-byte IPv6 address from packet to stack.

   Loads 4 consecutive 32-bit words from packet memory and stores them
   contiguously on the stack.

   Args:
     src-reg: Register pointing to the IP header (or base for offset)
     header-offset: Offset from src-reg to the address field
                    (e.g., IPV6-OFF-SRC=8 for source, IPV6-OFF-DST=24 for dest)
     stack-offset: Stack offset where to store (stores 16 bytes starting here)

   Uses: r0 as scratch (clobbered)

   Returns: Vector of 8 instructions

   Example:
     ;; r9 points to IPv6 header, load source address to stack[-84]
     (build-load-ipv6-address :r9 IPV6-OFF-SRC -84)
     ;; Loads from r9+8, r9+12, r9+16, r9+20
     ;; Stores to stack[-84], stack[-80], stack[-76], stack[-72]"
  [src-reg header-offset stack-offset]
  [(dsl/ldx :w :r0 src-reg (+ header-offset 0))
   (dsl/stx :w :r10 :r0 stack-offset)
   (dsl/ldx :w :r0 src-reg (+ header-offset 4))
   (dsl/stx :w :r10 :r0 (+ stack-offset 4))
   (dsl/ldx :w :r0 src-reg (+ header-offset 8))
   (dsl/stx :w :r10 :r0 (+ stack-offset 8))
   (dsl/ldx :w :r0 src-reg (+ header-offset 12))
   (dsl/stx :w :r10 :r0 (+ stack-offset 12))])

(defn build-load-ipv6-address-adjusted
  "Load IPv6 address with offset adjustment for non-standard pointer positions.

   Use when src-reg doesn't point to the IP header start. The base-offset
   adjusts for the difference.

   Args:
     src-reg: Register pointing to packet data (may not be at IP header)
     base-offset: Adjustment from src-reg to IP header start (can be negative)
     field-offset: Field offset within IPv6 header (IPV6-OFF-SRC or IPV6-OFF-DST)
     stack-offset: Stack destination

   Uses: r0 as scratch

   Returns: Vector of 8 instructions

   Example:
     ;; r9 = data + 58 (pointing at L4 header)
     ;; IPv6 header at data + 14
     ;; Adjustment: 14 - 58 = -44
     (build-load-ipv6-address-adjusted :r9 -44 IPV6-OFF-SRC -56)"
  [src-reg base-offset field-offset stack-offset]
  (let [off (+ base-offset field-offset)]
    [(dsl/ldx :w :r0 src-reg (+ off 0))
     (dsl/stx :w :r10 :r0 stack-offset)
     (dsl/ldx :w :r0 src-reg (+ off 4))
     (dsl/stx :w :r10 :r0 (+ stack-offset 4))
     (dsl/ldx :w :r0 src-reg (+ off 8))
     (dsl/stx :w :r10 :r0 (+ stack-offset 8))
     (dsl/ldx :w :r0 src-reg (+ off 12))
     (dsl/stx :w :r10 :r0 (+ stack-offset 12))]))

;; ============================================================================
;; Unified Format (IPv4 in 16-byte format)
;; ============================================================================

(defn build-load-ipv4-unified
  "Load 4-byte IPv4 address into 16-byte unified format.

   Creates IPv4-mapped address: zeros first 12 bytes, then stores 4-byte IPv4.
   This allows using the same data structures for IPv4 and IPv6.

   The format is: 00 00 00 00 00 00 00 00 00 00 00 00 <IPv4 address>

   Args:
     src-reg: Register pointing to IP header
     header-offset: Offset to IPv4 address (12 for src, 16 for dst in IPv4 header)
     stack-offset: Stack destination for 16-byte unified address

   Uses: r0 as scratch

   Returns: Vector of 5 instructions

   Example:
     ;; Load IPv4 source (at header+12) in unified format
     (build-load-ipv4-unified :r9 12 -84)
     ;; Result at stack[-84..-69]: 00 00 00 00 00 00 00 00 00 00 00 00 AA BB CC DD"
  [src-reg header-offset stack-offset]
  [(dsl/mov :r0 0)
   (dsl/stx :dw :r10 :r0 stack-offset)           ; zero bytes 0-7
   (dsl/stx :w :r10 :r0 (+ stack-offset 8))      ; zero bytes 8-11
   (dsl/ldx :w :r0 src-reg header-offset)        ; load 4-byte IPv4
   (dsl/stx :w :r10 :r0 (+ stack-offset 12))])   ; store at bytes 12-15

(defn build-load-ipv4-src-unified
  "Load IPv4 source address in unified 16-byte format.

   Convenience wrapper around build-load-ipv4-unified for source address.

   Args:
     ip-hdr-reg: Register pointing to IPv4 header
     stack-offset: Stack destination for 16-byte unified address

   Returns: Vector of 5 instructions"
  [ip-hdr-reg stack-offset]
  (build-load-ipv4-unified ip-hdr-reg IPV4-OFF-SRC stack-offset))

(defn build-load-ipv4-dst-unified
  "Load IPv4 destination address in unified 16-byte format.

   Convenience wrapper around build-load-ipv4-unified for destination address.

   Args:
     ip-hdr-reg: Register pointing to IPv4 header
     stack-offset: Stack destination for 16-byte unified address

   Returns: Vector of 5 instructions"
  [ip-hdr-reg stack-offset]
  (build-load-ipv4-unified ip-hdr-reg IPV4-OFF-DST stack-offset))

;; ============================================================================
;; Address Copying
;; ============================================================================

(defn build-copy-ipv6-address
  "Copy 16-byte address from one stack location to another.

   Useful for saving original addresses before modification.

   Args:
     src-stack-offset: Source stack offset
     dst-stack-offset: Destination stack offset

   Uses: r0 as scratch

   Returns: Vector of 8 instructions"
  [src-stack-offset dst-stack-offset]
  [(dsl/ldx :w :r0 :r10 src-stack-offset)
   (dsl/stx :w :r10 :r0 dst-stack-offset)
   (dsl/ldx :w :r0 :r10 (+ src-stack-offset 4))
   (dsl/stx :w :r10 :r0 (+ dst-stack-offset 4))
   (dsl/ldx :w :r0 :r10 (+ src-stack-offset 8))
   (dsl/stx :w :r10 :r0 (+ dst-stack-offset 8))
   (dsl/ldx :w :r0 :r10 (+ src-stack-offset 12))
   (dsl/stx :w :r10 :r0 (+ dst-stack-offset 12))])

(defn build-store-ipv6-address
  "Store 16-byte address from stack back to packet.

   Useful for NAT or address rewriting.

   Args:
     stack-offset: Source stack offset
     dst-reg: Register pointing to destination in packet
     header-offset: Offset from dst-reg to write location

   Uses: r0 as scratch

   Returns: Vector of 8 instructions"
  [stack-offset dst-reg header-offset]
  [(dsl/ldx :w :r0 :r10 stack-offset)
   (dsl/stx :w dst-reg :r0 (+ header-offset 0))
   (dsl/ldx :w :r0 :r10 (+ stack-offset 4))
   (dsl/stx :w dst-reg :r0 (+ header-offset 4))
   (dsl/ldx :w :r0 :r10 (+ stack-offset 8))
   (dsl/stx :w dst-reg :r0 (+ header-offset 8))
   (dsl/ldx :w :r0 :r10 (+ stack-offset 12))
   (dsl/stx :w dst-reg :r0 (+ header-offset 12))])

;; ============================================================================
;; Convenience Functions
;; ============================================================================

(defn build-load-ipv6-src
  "Load IPv6 source address from packet to stack.

   Args:
     ip-hdr-reg: Register pointing to IPv6 header
     stack-offset: Stack destination

   Returns: Vector of 8 instructions"
  [ip-hdr-reg stack-offset]
  (build-load-ipv6-address ip-hdr-reg IPV6-OFF-SRC stack-offset))

(defn build-load-ipv6-dst
  "Load IPv6 destination address from packet to stack.

   Args:
     ip-hdr-reg: Register pointing to IPv6 header
     stack-offset: Stack destination

   Returns: Vector of 8 instructions"
  [ip-hdr-reg stack-offset]
  (build-load-ipv6-address ip-hdr-reg IPV6-OFF-DST stack-offset))
