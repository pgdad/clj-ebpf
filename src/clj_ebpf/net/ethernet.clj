(ns clj-ebpf.net.ethernet
  "Ethernet frame parsing and manipulation helpers for eBPF programs."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]))

;; ============================================================================
;; Ethernet Header Fields
;; ============================================================================

(defn load-dst-mac
  "Load destination MAC address (6 bytes) into two registers.
   First 4 bytes into dst-reg-hi, last 2 bytes into dst-reg-lo.

   dst-reg-hi: Register for first 4 bytes
   dst-reg-lo: Register for last 2 bytes
   data-reg: Register pointing to Ethernet header"
  [dst-reg-hi dst-reg-lo data-reg]
  [(dsl/ldx :w dst-reg-hi data-reg (net/eth-offset :dst-mac))
   (dsl/ldx :h dst-reg-lo data-reg (+ (net/eth-offset :dst-mac) 4))])

(defn load-src-mac
  "Load source MAC address (6 bytes) into two registers.

   src-reg-hi: Register for first 4 bytes
   src-reg-lo: Register for last 2 bytes
   data-reg: Register pointing to Ethernet header"
  [src-reg-hi src-reg-lo data-reg]
  [(dsl/ldx :w src-reg-hi data-reg (net/eth-offset :src-mac))
   (dsl/ldx :h src-reg-lo data-reg (+ (net/eth-offset :src-mac) 4))])

(defn load-ethertype
  "Load ethertype into dst-reg (network byte order).
   For comparison, use the network-order constants.
   Assumes bounds already checked for ETH_HLEN bytes.

   dst-reg: Destination register for ethertype
   data-reg: Register pointing to packet data start"
  [dst-reg data-reg]
  [(dsl/ldx :h dst-reg data-reg (net/eth-offset :ethertype))])

(defn load-ethertype-host
  "Load ethertype into dst-reg and convert to host byte order.
   Assumes bounds already checked for ETH_HLEN bytes.

   dst-reg: Destination register for ethertype
   data-reg: Register pointing to packet data start"
  [dst-reg data-reg]
  [(dsl/ldx :h dst-reg data-reg (net/eth-offset :ethertype))
   (dsl/end-to-be dst-reg 16)])

;; ============================================================================
;; Ethertype Checks
;; ============================================================================

;; Network byte order constants for comparison
(def ^:const ETH-P-IP-BE 0x0008)      ; 0x0800 in network byte order
(def ^:const ETH-P-IPV6-BE 0xDD86)    ; 0x86DD in network byte order
(def ^:const ETH-P-ARP-BE 0x0608)     ; 0x0806 in network byte order

(defn is-ipv4
  "Generate instructions to check if packet is IPv4.
   Jumps to ipv4-label if IPv4, falls through otherwise.
   Uses network byte order comparison (no conversion needed).

   ethertype-reg: Register containing ethertype (network order)
   ipv4-label: Label offset to jump to if IPv4"
  [ethertype-reg ipv4-label]
  [(dsl/jmp-imm :jeq ethertype-reg ETH-P-IP-BE ipv4-label)])

(defn is-ipv6
  "Generate instructions to check if packet is IPv6.
   Jumps to ipv6-label if IPv6, falls through otherwise.

   ethertype-reg: Register containing ethertype (network order)
   ipv6-label: Label offset to jump to if IPv6"
  [ethertype-reg ipv6-label]
  [(dsl/jmp-imm :jeq ethertype-reg ETH-P-IPV6-BE ipv6-label)])

(defn is-arp
  "Generate instructions to check if packet is ARP.
   Jumps to arp-label if ARP, falls through otherwise.

   ethertype-reg: Register containing ethertype (network order)
   arp-label: Label offset to jump to if ARP"
  [ethertype-reg arp-label]
  [(dsl/jmp-imm :jeq ethertype-reg ETH-P-ARP-BE arp-label)])

(defn is-not-ipv4
  "Generate instructions to check if packet is NOT IPv4.
   Jumps to not-ipv4-label if not IPv4, falls through if IPv4.

   ethertype-reg: Register containing ethertype (network order)
   not-ipv4-label: Label offset to jump to if not IPv4"
  [ethertype-reg not-ipv4-label]
  [(dsl/jmp-imm :jne ethertype-reg ETH-P-IP-BE not-ipv4-label)])

;; ============================================================================
;; MAC Address Manipulation
;; ============================================================================

(defn swap-macs
  "Swap source and destination MAC addresses.
   Uses 6 scratch registers or stack.

   data-reg: Register pointing to Ethernet header
   scratch-regs: Vector of 4 scratch registers [hi1 lo1 hi2 lo2]"
  [data-reg [hi1 lo1 hi2 lo2]]
  (concat
   ;; Load dst MAC into hi1/lo1
   (load-dst-mac hi1 lo1 data-reg)
   ;; Load src MAC into hi2/lo2
   (load-src-mac hi2 lo2 data-reg)
   ;; Store hi2/lo2 (old src) to dst position
   [(dsl/stx :w data-reg hi2 (net/eth-offset :dst-mac))
    (dsl/stx :h data-reg lo2 (+ (net/eth-offset :dst-mac) 4))]
   ;; Store hi1/lo1 (old dst) to src position
   [(dsl/stx :w data-reg hi1 (net/eth-offset :src-mac))
    (dsl/stx :h data-reg lo1 (+ (net/eth-offset :src-mac) 4))]))

(defn store-dst-mac
  "Store destination MAC address from two registers.

   data-reg: Register pointing to Ethernet header
   mac-hi: Register containing first 4 bytes
   mac-lo: Register containing last 2 bytes"
  [data-reg mac-hi mac-lo]
  [(dsl/stx :w data-reg mac-hi (net/eth-offset :dst-mac))
   (dsl/stx :h data-reg mac-lo (+ (net/eth-offset :dst-mac) 4))])

(defn store-src-mac
  "Store source MAC address from two registers.

   data-reg: Register pointing to Ethernet header
   mac-hi: Register containing first 4 bytes
   mac-lo: Register containing last 2 bytes"
  [data-reg mac-hi mac-lo]
  [(dsl/stx :w data-reg mac-hi (net/eth-offset :src-mac))
   (dsl/stx :h data-reg mac-lo (+ (net/eth-offset :src-mac) 4))])

;; ============================================================================
;; Convenience Functions
;; ============================================================================

(defn parse-ethernet
  "Parse Ethernet header and extract ethertype.
   Returns instructions that:
   1. Check bounds for Ethernet header
   2. Load ethertype into dst-reg

   data-reg: Register containing packet data pointer
   data-end-reg: Register containing data_end pointer
   ethertype-reg: Register to store ethertype
   fail-label: Label to jump to if bounds check fails
   scratch-reg: Scratch register for bounds check"
  [data-reg data-end-reg ethertype-reg fail-label scratch-reg]
  (concat
   (net/check-bounds data-reg data-end-reg net/ETH-HLEN fail-label scratch-reg)
   (load-ethertype ethertype-reg data-reg)))

(defn get-ip-header-ptr
  "Calculate pointer to IP header (after Ethernet header).

   ip-ptr-reg: Register to store IP header pointer
   data-reg: Register containing packet data pointer"
  [ip-ptr-reg data-reg]
  [(dsl/mov-reg ip-ptr-reg data-reg)
   (dsl/add ip-ptr-reg net/ETH-HLEN)])
