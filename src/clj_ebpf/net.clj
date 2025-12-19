(ns clj-ebpf.net
  "Networking helpers for eBPF programs.

   Provides reusable primitives for packet parsing, manipulation,
   and checksum operations for load balancers, NAT gateways,
   firewalls, and other networking applications."
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Protocol Constants
;; ============================================================================

;; Ethernet types
(def ETH-P-IP 0x0800)      ; IPv4
(def ETH-P-IPV6 0x86DD)    ; IPv6
(def ETH-P-ARP 0x0806)     ; ARP
(def ETH-P-8021Q 0x8100)   ; 802.1Q VLAN
(def ETH-P-8021AD 0x88A8)  ; 802.1ad QinQ

;; Header sizes
(def ETH-HLEN 14)          ; Ethernet header length
(def ETH-ALEN 6)           ; Ethernet address length

;; IP protocols
(def IPPROTO-ICMP 1)
(def IPPROTO-TCP 6)
(def IPPROTO-UDP 17)
(def IPPROTO-GRE 47)
(def IPPROTO-ICMPV6 58)
(def IPPROTO-SCTP 132)

;; Header sizes
(def IPV4-MIN-HLEN 20)     ; Minimum IPv4 header (no options)
(def IPV6-HLEN 40)         ; Fixed IPv6 header
(def TCP-MIN-HLEN 20)      ; Minimum TCP header (no options)
(def UDP-HLEN 8)           ; UDP header length
(def ICMP-HLEN 8)          ; ICMP header length

;; TCP Flags
(def TCP-FIN 0x01)
(def TCP-SYN 0x02)
(def TCP-RST 0x04)
(def TCP-PSH 0x08)
(def TCP-ACK 0x10)
(def TCP-URG 0x20)
(def TCP-ECE 0x40)
(def TCP-CWR 0x80)

;; XDP action codes
(def XDP-ABORTED 0)
(def XDP-DROP 1)
(def XDP-PASS 2)
(def XDP-TX 3)
(def XDP-REDIRECT 4)

;; TC action codes
(def TC-ACT-OK 0)
(def TC-ACT-RECLASSIFY 1)
(def TC-ACT-SHOT 2)
(def TC-ACT-PIPE 3)
(def TC-ACT-STOLEN 4)
(def TC-ACT-QUEUED 5)
(def TC-ACT-REPEAT 6)
(def TC-ACT-REDIRECT 7)

;; ============================================================================
;; Packet Offset Helpers
;; ============================================================================

(defn eth-offset
  "Return offset within Ethernet header.

   field: :dst-mac, :src-mac, :ethertype"
  [field]
  (case field
    :dst-mac 0
    :src-mac 6
    :ethertype 12))

(defn ipv4-offset
  "Return offset within IPv4 header (from IP header start).

   field: :version-ihl, :tos, :tot-len, :id, :frag-off,
          :ttl, :protocol, :check, :saddr, :daddr"
  [field]
  (case field
    :version-ihl 0
    :tos 1
    :dscp 1          ; Same byte as TOS
    :ecn 1           ; Same byte as TOS (lower 2 bits)
    :tot-len 2
    :id 4
    :frag-off 6
    :ttl 8
    :protocol 9
    :check 10
    :saddr 12
    :daddr 16))

(defn ipv6-offset
  "Return offset within IPv6 header (from IP header start).

   field: :version-tc-flow, :payload-len, :next-header,
          :hop-limit, :saddr, :daddr"
  [field]
  (case field
    :version-tc-flow 0
    :payload-len 4
    :next-header 6
    :hop-limit 7
    :saddr 8
    :daddr 24))

(defn tcp-offset
  "Return offset within TCP header (from TCP header start).

   field: :sport, :dport, :seq, :ack-seq, :data-off,
          :flags, :window, :check, :urg-ptr"
  [field]
  (case field
    :sport 0
    :dport 2
    :seq 4
    :ack-seq 8
    :data-off 12
    :flags 13
    :window 14
    :check 16
    :urg-ptr 18))

(defn udp-offset
  "Return offset within UDP header (from UDP header start).

   field: :sport, :dport, :len, :check"
  [field]
  (case field
    :sport 0
    :dport 2
    :len 4
    :check 6))

(defn icmp-offset
  "Return offset within ICMP header (from ICMP header start).

   field: :type, :code, :check, :rest-of-header"
  [field]
  (case field
    :type 0
    :code 1
    :check 2
    :rest-of-header 4))

;; ============================================================================
;; Bounds Checking Helpers
;; ============================================================================

(defn check-bounds
  "Generate instructions to verify packet has required bytes.
   Returns instructions that jump to fail-label if bounds check fails.

   data-reg: Register containing packet data pointer
   data-end-reg: Register containing data_end pointer
   offset: Number of bytes needed from data pointer
   fail-label: Label offset to jump to on failure (positive integer)
   scratch-reg: Scratch register for calculation"
  [data-reg data-end-reg offset fail-label scratch-reg]
  ;; r_scratch = data + offset
  ;; if r_scratch > data_end goto fail
  [(dsl/mov-reg scratch-reg data-reg)
   (dsl/add scratch-reg offset)
   (dsl/jmp-reg :jgt scratch-reg data-end-reg fail-label)])

(defn check-bounds-dynamic
  "Generate bounds check with dynamic offset in register.

   data-reg: Register containing packet data pointer
   data-end-reg: Register containing data_end pointer
   offset-reg: Register containing offset value
   fail-label: Label offset to jump to on failure (positive integer)
   scratch-reg: Scratch register for calculation"
  [data-reg data-end-reg offset-reg fail-label scratch-reg]
  [(dsl/mov-reg scratch-reg data-reg)
   (dsl/add-reg scratch-reg offset-reg)
   (dsl/jmp-reg :jgt scratch-reg data-end-reg fail-label)])

;; ============================================================================
;; XDP vs TC Context Helpers
;; ============================================================================

(defn xdp-load-data-ptrs
  "Load data and data_end pointers from XDP context.
   XDP md: data at offset 0, data_end at offset 8 (64-bit pointers).

   data-reg: Register to store data pointer
   data-end-reg: Register to store data_end pointer
   ctx-reg: XDP context register (typically :r1)"
  [data-reg data-end-reg ctx-reg]
  [(dsl/ldx :dw data-reg ctx-reg 0)
   (dsl/ldx :dw data-end-reg ctx-reg 8)])

(defn tc-load-data-ptrs
  "Load data and data_end pointers from TC/SKB context.
   SKB: data at offset 76, data_end at offset 80 (32-bit offsets in SKB).

   data-reg: Register to store data pointer
   data-end-reg: Register to store data_end pointer
   ctx-reg: SKB context register (typically :r1)"
  [data-reg data-end-reg ctx-reg]
  [(dsl/ldx :w data-reg ctx-reg 76)
   (dsl/ldx :w data-end-reg ctx-reg 80)])

;; ============================================================================
;; Common Instruction Sequences
;; ============================================================================

(defn return-action
  "Generate instructions to return an action code and exit.

   action: Action code (XDP-PASS, TC-ACT-OK, etc.)"
  [action]
  [(dsl/mov :r0 action)
   (dsl/exit-insn)])

(defn save-ctx
  "Save context pointer to callee-saved register.
   BPF calling convention: r1-r5 are clobbered by helper calls.

   ctx-reg: Register containing context (typically :r1)
   save-reg: Callee-saved register to save to (r6-r9)"
  [ctx-reg save-reg]
  [(dsl/mov-reg save-reg ctx-reg)])

;; ============================================================================
;; Byte Order Helpers
;; ============================================================================

(defn load-be16
  "Load 16-bit value from packet and convert to host byte order.

   dst-reg: Destination register
   src-reg: Register pointing to memory
   offset: Offset from src-reg"
  [dst-reg src-reg offset]
  [(dsl/ldx :h dst-reg src-reg offset)
   (dsl/end-to-be dst-reg 16)])

(defn load-be32
  "Load 32-bit value from packet and convert to host byte order.

   dst-reg: Destination register
   src-reg: Register pointing to memory
   offset: Offset from src-reg"
  [dst-reg src-reg offset]
  [(dsl/ldx :w dst-reg src-reg offset)
   (dsl/end-to-be dst-reg 32)])

(defn store-be16
  "Convert 16-bit value to network byte order and store.

   dst-reg: Register pointing to memory
   offset: Offset from dst-reg
   src-reg: Register containing value (host order)
   scratch-reg: Scratch register for conversion"
  [dst-reg offset src-reg scratch-reg]
  [(dsl/mov-reg scratch-reg src-reg)
   (dsl/end-to-be scratch-reg 16)
   (dsl/stx :h dst-reg offset scratch-reg)])

(defn store-be32
  "Convert 32-bit value to network byte order and store.

   dst-reg: Register pointing to memory
   offset: Offset from dst-reg
   src-reg: Register containing value (host order)
   scratch-reg: Scratch register for conversion"
  [dst-reg offset src-reg scratch-reg]
  [(dsl/mov-reg scratch-reg src-reg)
   (dsl/end-to-be scratch-reg 32)
   (dsl/stx :w dst-reg offset scratch-reg)])
