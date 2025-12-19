(ns clj-ebpf.net.udp
  "UDP packet parsing and manipulation helpers for eBPF programs."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]))

;; ============================================================================
;; UDP Header Field Access
;; ============================================================================

(defn load-field
  "Load a UDP header field into dst-reg.

   dst-reg: Destination register
   udp-hdr-reg: Register pointing to start of UDP header
   field: Field keyword (:sport, :dport, :len, :check)
   size: :b (byte), :h (half-word)"
  [dst-reg udp-hdr-reg field size]
  (let [offset (net/udp-offset field)]
    [(dsl/ldx size dst-reg udp-hdr-reg offset)]))

(defn load-sport
  "Load UDP source port into dst-reg (network byte order).

   dst-reg: Destination register
   udp-hdr-reg: Register pointing to UDP header"
  [dst-reg udp-hdr-reg]
  (load-field dst-reg udp-hdr-reg :sport :h))

(defn load-dport
  "Load UDP destination port into dst-reg (network byte order).

   dst-reg: Destination register
   udp-hdr-reg: Register pointing to UDP header"
  [dst-reg udp-hdr-reg]
  (load-field dst-reg udp-hdr-reg :dport :h))

(defn load-ports
  "Load UDP source and destination ports.
   Ports are loaded in network byte order.

   sport-reg: Register for source port
   dport-reg: Register for destination port
   udp-hdr-reg: Register pointing to UDP header"
  [sport-reg dport-reg udp-hdr-reg]
  [(dsl/ldx :h sport-reg udp-hdr-reg (net/udp-offset :sport))
   (dsl/ldx :h dport-reg udp-hdr-reg (net/udp-offset :dport))])

(defn load-ports-host
  "Load UDP source and destination ports in host byte order.

   sport-reg: Register for source port (host order)
   dport-reg: Register for destination port (host order)
   udp-hdr-reg: Register pointing to UDP header"
  [sport-reg dport-reg udp-hdr-reg]
  [(dsl/ldx :h sport-reg udp-hdr-reg (net/udp-offset :sport))
   (dsl/end-to-be sport-reg 16)
   (dsl/ldx :h dport-reg udp-hdr-reg (net/udp-offset :dport))
   (dsl/end-to-be dport-reg 16)])

(defn load-length
  "Load UDP length field into dst-reg (network byte order).

   dst-reg: Destination register
   udp-hdr-reg: Register pointing to UDP header"
  [dst-reg udp-hdr-reg]
  (load-field dst-reg udp-hdr-reg :len :h))

(defn load-length-host
  "Load UDP length field in host byte order.

   dst-reg: Destination register
   udp-hdr-reg: Register pointing to UDP header"
  [dst-reg udp-hdr-reg]
  [(dsl/ldx :h dst-reg udp-hdr-reg (net/udp-offset :len))
   (dsl/end-to-be dst-reg 16)])

(defn load-checksum
  "Load UDP checksum field into dst-reg.

   dst-reg: Destination register
   udp-hdr-reg: Register pointing to UDP header"
  [dst-reg udp-hdr-reg]
  (load-field dst-reg udp-hdr-reg :check :h))

;; ============================================================================
;; UDP Header Field Storage
;; ============================================================================

(defn store-field
  "Store value to UDP header field.

   udp-hdr-reg: Register pointing to UDP header start
   field: Field keyword
   src-reg: Register containing value to store
   size: :h for all UDP fields"
  [udp-hdr-reg field src-reg size]
  (let [offset (net/udp-offset field)]
    [(dsl/stx size udp-hdr-reg src-reg offset)]))

(defn store-sport
  "Store UDP source port (expects network byte order).

   udp-hdr-reg: Register pointing to UDP header
   port-reg: Register containing port (network order)"
  [udp-hdr-reg port-reg]
  (store-field udp-hdr-reg :sport port-reg :h))

(defn store-dport
  "Store UDP destination port (expects network byte order).

   udp-hdr-reg: Register pointing to UDP header
   port-reg: Register containing port (network order)"
  [udp-hdr-reg port-reg]
  (store-field udp-hdr-reg :dport port-reg :h))

(defn store-port-host
  "Store UDP port from host byte order value.

   udp-hdr-reg: Register pointing to UDP header
   field: :sport or :dport
   port-reg: Register containing port (host order)
   scratch-reg: Scratch register for byte order conversion"
  [udp-hdr-reg field port-reg scratch-reg]
  (let [offset (net/udp-offset field)]
    [(dsl/mov-reg scratch-reg port-reg)
     (dsl/end-to-be scratch-reg 16)      ; Convert to network order
     (dsl/stx :h udp-hdr-reg scratch-reg offset)]))

(defn store-length
  "Store UDP length field (expects network byte order).

   udp-hdr-reg: Register pointing to UDP header
   len-reg: Register containing length (network order)"
  [udp-hdr-reg len-reg]
  (store-field udp-hdr-reg :len len-reg :h))

(defn store-checksum
  "Store UDP checksum field.

   udp-hdr-reg: Register pointing to UDP header
   csum-reg: Register containing checksum"
  [udp-hdr-reg csum-reg]
  (store-field udp-hdr-reg :check csum-reg :h))

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
;; Common UDP Port Constants (network byte order)
;; ============================================================================

(def ^:const DNS-PORT-BE 0x3500)      ; Port 53 in network byte order
(def ^:const DHCP-SERVER-PORT-BE 0x4300) ; Port 67
(def ^:const DHCP-CLIENT-PORT-BE 0x4400) ; Port 68
(def ^:const NTP-PORT-BE 0x7B00)      ; Port 123
(def ^:const SNMP-PORT-BE 0xA100)     ; Port 161

(defn is-dns
  "Check if destination port is DNS (53).

   dport-reg: Register containing destination port (network order)
   dns-label: Label to jump to if DNS"
  [dport-reg dns-label]
  [(dsl/jmp-imm :jeq dport-reg DNS-PORT-BE dns-label)])

(defn is-dhcp-request
  "Check if this is a DHCP request (dport 67).

   dport-reg: Register containing destination port (network order)
   dhcp-label: Label to jump to if DHCP request"
  [dport-reg dhcp-label]
  [(dsl/jmp-imm :jeq dport-reg DHCP-SERVER-PORT-BE dhcp-label)])

;; ============================================================================
;; Convenience Functions
;; ============================================================================

(defn parse-udp-header
  "Parse UDP header and check bounds.
   Returns instructions that:
   1. Check bounds for UDP header (8 bytes)
   2. Load source and destination ports

   udp-hdr-reg: Register pointing to UDP header start
   data-end-reg: Register containing data_end pointer
   sport-reg: Register to store source port
   dport-reg: Register to store destination port
   fail-label: Label to jump to on bounds failure
   scratch-reg: Scratch register for bounds check"
  [udp-hdr-reg data-end-reg sport-reg dport-reg fail-label scratch-reg]
  (concat
   (net/check-bounds udp-hdr-reg data-end-reg net/UDP-HLEN fail-label scratch-reg)
   (load-ports sport-reg dport-reg udp-hdr-reg)))

(defn get-payload-ptr
  "Calculate pointer to UDP payload.
   UDP header is always 8 bytes.

   payload-reg: Register to store payload pointer
   udp-hdr-reg: Register pointing to UDP header"
  [payload-reg udp-hdr-reg]
  [(dsl/mov-reg payload-reg udp-hdr-reg)
   (dsl/add payload-reg net/UDP-HLEN)])

(defn get-payload-len
  "Calculate UDP payload length from UDP length field.
   Payload length = UDP length - 8

   len-reg: Register to store payload length (also used as scratch)
   udp-hdr-reg: Register pointing to UDP header"
  [len-reg udp-hdr-reg]
  (concat
   (load-length-host len-reg udp-hdr-reg)
   [(dsl/sub len-reg net/UDP-HLEN)]))
