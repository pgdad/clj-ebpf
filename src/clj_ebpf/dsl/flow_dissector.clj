(ns clj-ebpf.dsl.flow-dissector
  "High-level FLOW_DISSECTOR DSL for BPF programs.

   FLOW_DISSECTOR programs implement custom packet parsing logic for the
   kernel networking stack. They're used for flow hashing (RSS, ECMP routing)
   and can override the built-in C-based flow dissector.

   Context: __sk_buff (same as TC programs)
   Output: struct bpf_flow_keys (written via skb->flow_keys pointer)

   Return values:
   - BPF_OK (0): Continue/success
   - BPF_DROP (-1): Stop dissection

   Use cases:
   - Custom protocol parsing (e.g., GRE, custom encapsulation)
   - Non-standard header handling
   - Protocol-specific flow hashing
   - Debugging packet classification

   Example:
     (defprogram my-flow-dissector
       :type :flow-dissector
       :license \"GPL\"
       :body (concat
               (flow-dissector-prologue :r6 :r2 :r3)
               ;; Parse headers and fill flow_keys
               (flow-dissector-ok)))"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.tc :as tc]))

;; ============================================================================
;; FLOW_DISSECTOR Return Values
;; ============================================================================

(def flow-dissector-verdict
  "FLOW_DISSECTOR return values."
  {:ok   0     ; BPF_OK - Continue/success
   :drop -1})  ; BPF_DROP - Stop dissection

(defn flow-dissector-action
  "Get FLOW_DISSECTOR action value.

   Parameters:
   - action: :ok (0) or :drop (-1)

   Returns integer value."
  [action]
  (or (get flow-dissector-verdict action)
      (throw (ex-info "Unknown FLOW_DISSECTOR action" {:action action}))))

;; ============================================================================
;; struct bpf_flow_keys Offsets
;; ============================================================================
;;
;; From linux/bpf.h - struct bpf_flow_keys:
;;
;; struct bpf_flow_keys {
;;     __u16 nhoff;           // Network header offset
;;     __u16 thoff;           // Transport header offset
;;     __u16 addr_proto;      // Address protocol (ETH_P_IP, ETH_P_IPV6)
;;     __u8  is_frag;         // Is fragment
;;     __u8  is_first_frag;   // Is first fragment
;;     __u8  is_encap;        // Is encapsulated
;;     __u8  ip_proto;        // IP protocol (TCP, UDP, etc.)
;;     __be16 n_proto;        // Network protocol
;;     __be16 sport;          // Source port
;;     __be16 dport;          // Destination port
;;     union {
;;         struct {
;;             __be32 ipv4_src;
;;             __be32 ipv4_dst;
;;         };
;;         struct {
;;             __u32 ipv6_src[4];
;;             __u32 ipv6_dst[4];
;;         };
;;     };
;;     __u32 flags;
;;     __be32 flow_label;
;; };

(def flow-keys-offsets
  "Offsets in bpf_flow_keys structure.

   This structure is passed to FLOW_DISSECTOR programs for output.
   The program fills in these fields based on packet parsing."
  {:nhoff          0     ; Network header offset (u16)
   :thoff          2     ; Transport header offset (u16)
   :addr-proto     4     ; Address protocol - ETH_P_IP (0x0800), ETH_P_IPV6 (0x86DD) (u16)
   :is-frag        6     ; Is fragment flag (u8)
   :is-first-frag  7     ; Is first fragment flag (u8)
   :is-encap       8     ; Is encapsulated flag (u8)
   :ip-proto       9     ; IP protocol - TCP (6), UDP (17), etc. (u8)
   :n-proto        10    ; Network protocol (u16, network byte order)
   :sport          12    ; Source port (u16, network byte order)
   :dport          14    ; Destination port (u16, network byte order)
   :ipv4-src       16    ; IPv4 source address (u32, network byte order)
   :ipv4-dst       20    ; IPv4 destination address (u32, network byte order)
   :ipv6-src       16    ; IPv6 source address (16 bytes, overlaps with ipv4-src)
   :ipv6-dst       32    ; IPv6 destination address (16 bytes)
   :flags          48    ; Flags (u32)
   :flow-label     52})  ; IPv6 flow label (u32, network byte order)

(defn flow-keys-offset
  "Get offset for bpf_flow_keys field.

   Parameters:
   - field: Field keyword from flow-keys-offsets

   Returns integer offset."
  [field]
  (or (get flow-keys-offsets field)
      (throw (ex-info "Unknown bpf_flow_keys field" {:field field}))))

;; ============================================================================
;; Flow Keys Flags
;; ============================================================================

(def flow-keys-flags
  "Flags for bpf_flow_keys.flags field."
  {:frag       0x0001   ; Is a fragment
   :first-frag 0x0002   ; Is first fragment
   :encap      0x0004}) ; Is encapsulated

;; ============================================================================
;; Protocol Constants
;; ============================================================================

(def ethernet-protocols
  "Common Ethernet protocol values (ETH_P_*)."
  {:ipv4   0x0800    ; ETH_P_IP
   :ipv6   0x86DD    ; ETH_P_IPV6
   :arp    0x0806    ; ETH_P_ARP
   :vlan   0x8100    ; ETH_P_8021Q
   :mpls   0x8847    ; ETH_P_MPLS_UC
   :pppoe  0x8864})  ; ETH_P_PPP_SES

(def ip-protocols
  "IP protocol numbers."
  {:icmp     1
   :tcp      6
   :udp      17
   :gre      47
   :icmpv6   58
   :sctp     132})

;; ============================================================================
;; Reuse __sk_buff from TC
;; ============================================================================

;; FLOW_DISSECTOR uses __sk_buff context same as TC
(def skb-offsets tc/skb-offsets)
(def skb-offset tc/skb-offset)

;; ============================================================================
;; Context and Flow Keys Access
;; ============================================================================

(defn flow-dissector-prologue
  "Generate FLOW_DISSECTOR program prologue.

   Saves context and loads data pointers from __sk_buff.

   Parameters:
   - ctx-save-reg: Register to save __sk_buff pointer
   - data-reg: Register for packet data pointer
   - data-end-reg: Register for data_end pointer

   Returns vector of instructions."
  [ctx-save-reg data-reg data-end-reg]
  (vec (concat
        [(dsl/mov-reg ctx-save-reg :r1)]
        (tc/tc-load-data-pointers :r1 data-reg data-end-reg))))

(defn flow-dissector-load-ctx-field
  "Load a field from __sk_buff context.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register
   - field: Field keyword from skb-offsets

   Returns ldx instruction."
  [ctx-reg dst-reg field]
  (tc/tc-load-ctx-field ctx-reg field dst-reg))

(defn flow-dissector-get-flow-keys-ptr
  "Load pointer to flow_keys from __sk_buff.

   The flow_keys field in __sk_buff contains a pointer to the
   bpf_flow_keys structure that the dissector should fill.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register for flow_keys pointer

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (dsl/ldx :dw dst-reg ctx-reg (skb-offset :flow-keys)))

;; ============================================================================
;; Flow Keys Field Access (Writing)
;; ============================================================================

(defn flow-keys-store-u8
  "Store 8-bit value to flow_keys field.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - field: Field keyword
   - value-reg: Register containing value to store

   Returns stx instruction."
  [keys-reg field value-reg]
  (dsl/stx :b keys-reg value-reg (flow-keys-offset field)))

(defn flow-keys-store-u16
  "Store 16-bit value to flow_keys field.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - field: Field keyword
   - value-reg: Register containing value to store

   Returns stx instruction."
  [keys-reg field value-reg]
  (dsl/stx :h keys-reg value-reg (flow-keys-offset field)))

(defn flow-keys-store-u32
  "Store 32-bit value to flow_keys field.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - field: Field keyword
   - value-reg: Register containing value to store

   Returns stx instruction."
  [keys-reg field value-reg]
  (dsl/stx :w keys-reg value-reg (flow-keys-offset field)))

(defn flow-keys-set-nhoff
  "Set network header offset in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - value-reg: Register containing offset value

   Returns stx instruction."
  [keys-reg value-reg]
  (flow-keys-store-u16 keys-reg :nhoff value-reg))

(defn flow-keys-set-thoff
  "Set transport header offset in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - value-reg: Register containing offset value

   Returns stx instruction."
  [keys-reg value-reg]
  (flow-keys-store-u16 keys-reg :thoff value-reg))

(defn flow-keys-set-addr-proto
  "Set address protocol in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - value-reg: Register containing protocol (ETH_P_IP, ETH_P_IPV6)

   Returns stx instruction."
  [keys-reg value-reg]
  (flow-keys-store-u16 keys-reg :addr-proto value-reg))

(defn flow-keys-set-ip-proto
  "Set IP protocol in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - value-reg: Register containing protocol (TCP=6, UDP=17, etc.)

   Returns stx instruction."
  [keys-reg value-reg]
  (flow-keys-store-u8 keys-reg :ip-proto value-reg))

(defn flow-keys-set-n-proto
  "Set network protocol in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - value-reg: Register containing protocol (network byte order)

   Returns stx instruction."
  [keys-reg value-reg]
  (flow-keys-store-u16 keys-reg :n-proto value-reg))

(defn flow-keys-set-ports
  "Set source and destination ports in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - sport-reg: Register containing source port
   - dport-reg: Register containing destination port

   Returns vector of instructions."
  [keys-reg sport-reg dport-reg]
  [(flow-keys-store-u16 keys-reg :sport sport-reg)
   (flow-keys-store-u16 keys-reg :dport dport-reg)])

(defn flow-keys-set-ipv4-addrs
  "Set IPv4 source and destination addresses in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - src-reg: Register containing source IPv4 address
   - dst-reg: Register containing destination IPv4 address

   Returns vector of instructions."
  [keys-reg src-reg dst-reg]
  [(flow-keys-store-u32 keys-reg :ipv4-src src-reg)
   (flow-keys-store-u32 keys-reg :ipv4-dst dst-reg)])

(defn flow-keys-set-is-frag
  "Set is_frag flag in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - value-reg: Register containing flag value (0 or 1)

   Returns stx instruction."
  [keys-reg value-reg]
  (flow-keys-store-u8 keys-reg :is-frag value-reg))

(defn flow-keys-set-is-first-frag
  "Set is_first_frag flag in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - value-reg: Register containing flag value (0 or 1)

   Returns stx instruction."
  [keys-reg value-reg]
  (flow-keys-store-u8 keys-reg :is-first-frag value-reg))

(defn flow-keys-set-is-encap
  "Set is_encap flag in flow_keys.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - value-reg: Register containing flag value (0 or 1)

   Returns stx instruction."
  [keys-reg value-reg]
  (flow-keys-store-u8 keys-reg :is-encap value-reg))

;; ============================================================================
;; Flow Keys Field Access (Reading)
;; ============================================================================

(defn flow-keys-load-u8
  "Load 8-bit value from flow_keys field.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - dst-reg: Destination register
   - field: Field keyword

   Returns ldx instruction."
  [keys-reg dst-reg field]
  (dsl/ldx :b dst-reg keys-reg (flow-keys-offset field)))

(defn flow-keys-load-u16
  "Load 16-bit value from flow_keys field.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - dst-reg: Destination register
   - field: Field keyword

   Returns ldx instruction."
  [keys-reg dst-reg field]
  (dsl/ldx :h dst-reg keys-reg (flow-keys-offset field)))

(defn flow-keys-load-u32
  "Load 32-bit value from flow_keys field.

   Parameters:
   - keys-reg: Register containing flow_keys pointer
   - dst-reg: Destination register
   - field: Field keyword

   Returns ldx instruction."
  [keys-reg dst-reg field]
  (dsl/ldx :w dst-reg keys-reg (flow-keys-offset field)))

;; ============================================================================
;; Return Patterns
;; ============================================================================

(defn flow-dissector-ok
  "Generate instructions to return BPF_OK (success).

   Returns vector of instructions."
  []
  [(dsl/mov :r0 0)  ; BPF_OK
   (dsl/exit-insn)])

(defn flow-dissector-drop
  "Generate instructions to return BPF_DROP (stop dissection).

   Returns vector of instructions."
  []
  [(dsl/mov :r0 -1)  ; BPF_DROP
   (dsl/exit-insn)])

;; ============================================================================
;; Common Parsing Patterns
;; ============================================================================

(defn flow-dissector-bounds-check
  "Generate bounds check for packet access.

   Parameters:
   - data-reg: Register with data pointer
   - data-end-reg: Register with data_end pointer
   - offset: Offset to check (must be accessible)
   - fail-insns: Number of instructions to skip on bounds check failure

   Returns vector of instructions."
  [data-reg data-end-reg offset fail-insns]
  (vec (concat
        [(dsl/mov-reg :r0 data-reg)
         (dsl/add :r0 offset)
         (dsl/jmp-reg :jgt :r0 data-end-reg fail-insns)])))

(def ethernet-header-size 14)
(def ipv4-header-min-size 20)
(def ipv6-header-size 40)
(def tcp-header-min-size 20)
(def udp-header-size 8)

(defn flow-dissector-parse-ethernet
  "Generate instructions to parse Ethernet header and check ethertype.

   Sets up:
   - Network header offset (nhoff) = 14
   - Network protocol (n_proto) from ethertype

   Parameters:
   - data-reg: Register with data pointer
   - data-end-reg: Register with data_end pointer
   - keys-reg: Register with flow_keys pointer
   - tmp-reg: Temporary register

   Returns vector of instructions (succeeds or falls through to drop)."
  [data-reg data-end-reg keys-reg tmp-reg]
  (vec (concat
        ;; Bounds check for Ethernet header
        (flow-dissector-bounds-check data-reg data-end-reg ethernet-header-size 3)
        ;; Bounds check failed - return drop
        (flow-dissector-drop)

        ;; Set nhoff = 14 (Ethernet header size)
        [(dsl/mov tmp-reg ethernet-header-size)
         (flow-keys-set-nhoff keys-reg tmp-reg)]

        ;; Load ethertype (offset 12, 2 bytes, network byte order)
        [(dsl/ldx :h tmp-reg data-reg 12)
         (flow-keys-set-n-proto keys-reg tmp-reg)])))

(defn flow-dissector-parse-ipv4
  "Generate instructions to parse IPv4 header.

   Sets up:
   - addr_proto = ETH_P_IP
   - ip_proto from IPv4 header
   - ipv4_src and ipv4_dst
   - Transport header offset (thoff)

   Parameters:
   - data-reg: Register with data pointer
   - data-end-reg: Register with data_end pointer
   - keys-reg: Register with flow_keys pointer
   - nhoff: Network header offset (usually 14 for Ethernet)
   - tmp-reg: Temporary register
   - tmp-reg2: Second temporary register

   Returns vector of instructions."
  [data-reg data-end-reg keys-reg nhoff tmp-reg tmp-reg2]
  (let [ip-offset nhoff
        proto-offset (+ ip-offset 9)
        src-offset (+ ip-offset 12)
        dst-offset (+ ip-offset 16)
        ihl-offset ip-offset]
    (vec (concat
          ;; Bounds check for minimum IP header
          (flow-dissector-bounds-check data-reg data-end-reg (+ ip-offset ipv4-header-min-size) 3)
          (flow-dissector-drop)

          ;; Set addr_proto = ETH_P_IP (0x0800)
          [(dsl/mov tmp-reg 0x0800)
           (flow-keys-set-addr-proto keys-reg tmp-reg)]

          ;; Load IP protocol
          [(dsl/ldx :b tmp-reg data-reg proto-offset)
           (flow-keys-set-ip-proto keys-reg tmp-reg)]

          ;; Load source IP
          [(dsl/ldx :w tmp-reg data-reg src-offset)
           (flow-keys-store-u32 keys-reg :ipv4-src tmp-reg)]

          ;; Load destination IP
          [(dsl/ldx :w tmp-reg data-reg dst-offset)
           (flow-keys-store-u32 keys-reg :ipv4-dst tmp-reg)]

          ;; Calculate transport header offset: nhoff + (IHL * 4)
          ;; IHL is lower 4 bits of first byte
          [(dsl/ldx :b tmp-reg data-reg ihl-offset)
           (dsl/and-op tmp-reg 0x0F)   ; Mask to get IHL
           (dsl/lsh tmp-reg 2)           ; Multiply by 4
           (dsl/add tmp-reg nhoff)       ; Add network header offset
           (flow-keys-set-thoff keys-reg tmp-reg)]))))

(defn flow-dissector-parse-tcp-ports
  "Generate instructions to parse TCP source and destination ports.

   Parameters:
   - data-reg: Register with data pointer
   - data-end-reg: Register with data_end pointer
   - keys-reg: Register with flow_keys pointer
   - thoff: Transport header offset
   - tmp-reg: Temporary register

   Returns vector of instructions."
  [data-reg data-end-reg keys-reg thoff tmp-reg]
  (vec (concat
        ;; Bounds check for TCP header (at least 4 bytes for ports)
        (flow-dissector-bounds-check data-reg data-end-reg (+ thoff 4) 3)
        (flow-dissector-drop)

        ;; Load source port (offset 0 from transport header)
        [(dsl/ldx :h tmp-reg data-reg thoff)
         (flow-keys-store-u16 keys-reg :sport tmp-reg)]

        ;; Load destination port (offset 2 from transport header)
        [(dsl/ldx :h tmp-reg data-reg (+ thoff 2))
         (flow-keys-store-u16 keys-reg :dport tmp-reg)])))

(defn flow-dissector-parse-udp-ports
  "Generate instructions to parse UDP source and destination ports.

   Same as TCP ports (both have ports at same offsets).

   Parameters:
   - data-reg: Register with data pointer
   - data-end-reg: Register with data_end pointer
   - keys-reg: Register with flow_keys pointer
   - thoff: Transport header offset
   - tmp-reg: Temporary register

   Returns vector of instructions."
  [data-reg data-end-reg keys-reg thoff tmp-reg]
  ;; UDP port layout is same as TCP
  (flow-dissector-parse-tcp-ports data-reg data-end-reg keys-reg thoff tmp-reg))

;; ============================================================================
;; Program Builder
;; ============================================================================

(defn build-flow-dissector-program
  "Build a complete FLOW_DISSECTOR program.

   Parameters:
   - opts: Map with:
     :ctx-reg - Register to save context (default :r6)
     :data-reg - Register for data pointer (default :r2)
     :data-end-reg - Register for data_end (default :r3)
     :body - Vector of body instructions
     :default-action - :ok or :drop (default :ok)

   Returns assembled program bytes."
  [{:keys [ctx-reg data-reg data-end-reg body default-action]
    :or {ctx-reg :r6 data-reg :r2 data-end-reg :r3 default-action :ok}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue
         (flow-dissector-prologue ctx-reg data-reg data-end-reg)
         ;; Body
         body
         ;; Default action
         (if (= default-action :ok)
           (flow-dissector-ok)
           (flow-dissector-drop))))))

;; ============================================================================
;; Section Names and Metadata
;; ============================================================================

(defn flow-dissector-section-name
  "Generate ELF section name for FLOW_DISSECTOR program.

   Returns \"flow_dissector\" or \"flow_dissector/<name>\"."
  ([]
   "flow_dissector")
  ([name]
   (str "flow_dissector/" name)))

(defn make-flow-dissector-info
  "Create program metadata for a FLOW_DISSECTOR program.

   Parameters:
   - program-name: Name for the BPF program
   - instructions: Program instructions

   Returns map with program metadata."
  [program-name instructions]
  {:name program-name
   :section (flow-dissector-section-name program-name)
   :type :flow-dissector
   :instructions instructions})

;; ============================================================================
;; Byte Order Utilities (reused from sk-lookup)
;; ============================================================================

(defn htons
  "Convert 16-bit value from host to network byte order (big-endian).

   Parameters:
   - value: 16-bit integer

   Returns network byte order value."
  [value]
  (bit-or (bit-shift-left (bit-and value 0xFF) 8)
          (bit-and (bit-shift-right value 8) 0xFF)))

(defn ntohs
  "Convert 16-bit value from network to host byte order.

   Parameters:
   - value: 16-bit integer in network byte order

   Returns host byte order value."
  [value]
  (htons value))

(defn htonl
  "Convert 32-bit value from host to network byte order (big-endian).

   Parameters:
   - value: 32-bit integer

   Returns network byte order value."
  [value]
  (bit-or (bit-shift-left (bit-and value 0xFF) 24)
          (bit-shift-left (bit-and (bit-shift-right value 8) 0xFF) 16)
          (bit-shift-left (bit-and (bit-shift-right value 16) 0xFF) 8)
          (bit-and (bit-shift-right value 24) 0xFF)))

(defn ntohl
  "Convert 32-bit value from network to host byte order.

   Parameters:
   - value: 32-bit integer in network byte order

   Returns host byte order value."
  [value]
  (htonl value))
