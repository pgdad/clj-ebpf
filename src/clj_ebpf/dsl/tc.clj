(ns clj-ebpf.dsl.tc
  "High-level TC (Traffic Control) DSL for BPF programs.

   TC programs run on the traffic control layer and can be attached to
   qdisc (queueing discipline) ingress/egress points. They operate on
   sk_buff and provide access to more metadata than XDP.

   TC Actions:
   - TC_ACT_OK       (0): Continue processing
   - TC_ACT_SHOT     (2): Drop packet
   - TC_ACT_UNSPEC   (-1): Use default action
   - TC_ACT_PIPE     (3): Continue to next action
   - TC_ACT_RECLASSIFY (1): Restart classification
   - TC_ACT_REDIRECT (7): Redirect packet

   TC programs use __sk_buff as context, which provides richer
   packet metadata than XDP's xdp_md.

   Example:
     (deftc-instructions simple-filter
       {:default-action :ok}
       ;; All packets passed
       [])"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.xdp :as xdp]))

;; ============================================================================
;; TC Actions
;; ============================================================================

(def tc-actions
  "TC action return values."
  {:unspec     -1  ; Use default action
   :ok         0   ; Continue processing (TC_ACT_OK)
   :reclassify 1   ; Restart classification
   :shot       2   ; Drop packet (TC_ACT_SHOT)
   :pipe       3   ; Continue to next action
   :stolen     4   ; Packet stolen, no further processing
   :queued     5   ; Packet queued for later
   :repeat     6   ; Repeat action
   :redirect   7}) ; Redirect packet

(defn tc-action
  "Get TC action value by keyword.

   Parameters:
   - action: Action keyword (:ok, :shot, :redirect, etc.)

   Returns integer action value.

   Example:
     (tc-action :shot)  ;; => 2"
  [action]
  (or (get tc-actions action)
      (throw (ex-info "Unknown TC action" {:action action}))))

;; ============================================================================
;; __sk_buff Structure Offsets
;; ============================================================================

;; struct __sk_buff {
;;   __u32 len;              // offset 0
;;   __u32 pkt_type;         // offset 4
;;   __u32 mark;             // offset 8
;;   __u32 queue_mapping;    // offset 12
;;   __u32 protocol;         // offset 16
;;   __u32 vlan_present;     // offset 20
;;   __u32 vlan_tci;         // offset 24
;;   __u32 vlan_proto;       // offset 28
;;   __u32 priority;         // offset 32
;;   __u32 ingress_ifindex;  // offset 36
;;   __u32 ifindex;          // offset 40
;;   __u32 tc_index;         // offset 44
;;   __u32 cb[5];            // offset 48-68
;;   __u32 hash;             // offset 68
;;   __u32 tc_classid;       // offset 72
;;   __u32 data;             // offset 76
;;   __u32 data_end;         // offset 80
;;   __u32 napi_id;          // offset 84
;;   __u32 family;           // offset 88
;;   __u32 remote_ip4;       // offset 92
;;   __u32 local_ip4;        // offset 96
;;   __u32 remote_ip6[4];    // offset 100-116
;;   __u32 local_ip6[4];     // offset 116-132
;;   __u32 remote_port;      // offset 132
;;   __u32 local_port;       // offset 136
;;   __u32 data_meta;        // offset 140
;;   ...
;; };

(def skb-offsets
  "__sk_buff structure field offsets."
  {:len             0    ; Packet length
   :pkt-type        4    ; Packet type
   :mark            8    ; Packet mark (fwmark)
   :queue-mapping   12   ; TX queue mapping
   :protocol        16   ; Protocol (ETH_P_*)
   :vlan-present    20   ; VLAN tag present flag
   :vlan-tci        24   ; VLAN TCI
   :vlan-proto      28   ; VLAN protocol
   :priority        32   ; Packet priority
   :ingress-ifindex 36   ; Ingress interface index
   :ifindex         40   ; Current interface index
   :tc-index        44   ; TC index
   :cb              48   ; Control buffer (5 x u32, offsets 48-68)
   :hash            68   ; Packet hash
   :tc-classid      72   ; TC classid
   :data            76   ; Packet data start
   :data-end        80   ; Packet data end
   :napi-id         84   ; NAPI ID
   :family          88   ; Address family
   :remote-ip4      92   ; Remote IPv4 address
   :local-ip4       96   ; Local IPv4 address
   :remote-ip6      100  ; Remote IPv6 address (16 bytes)
   :local-ip6       116  ; Local IPv6 address (16 bytes)
   :remote-port     132  ; Remote port
   :local-port      136  ; Local port
   :data-meta       140  ; Metadata area start
   :flow-keys       144  ; Flow keys
   :tstamp          152  ; Timestamp
   :wire-len        160  ; Original packet length
   :gso-segs        164  ; GSO segments
   :gso-size        168  ; GSO size
   :tstamp-type     172  ; Timestamp type
   :hwtstamp        176}) ; Hardware timestamp

(defn skb-offset
  "Get offset for __sk_buff field.

   Parameters:
   - field: Field keyword

   Returns offset in bytes."
  [field]
  (or (get skb-offsets field)
      (throw (ex-info "Unknown __sk_buff field" {:field field}))))

;; ============================================================================
;; TC Context Access
;; ============================================================================

(defn tc-load-ctx-field
  "Load a field from __sk_buff context.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer (typically :r1 at entry)
   - field: Field keyword from skb-offsets
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg field dst-reg]
  (let [offset (skb-offset field)]
    (dsl/ldx :w dst-reg ctx-reg offset)))

(defn tc-load-data-pointers
  "Load data and data_end pointers from __sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - data-reg: Destination register for data pointer
   - data-end-reg: Destination register for data_end pointer

   Returns vector of instructions.

   Example:
     (tc-load-data-pointers :r1 :r2 :r3)
     ;; r2 = data, r3 = data_end"
  [ctx-reg data-reg data-end-reg]
  [(tc-load-ctx-field ctx-reg :data data-reg)
   (tc-load-ctx-field ctx-reg :data-end data-end-reg)])

(defn tc-prologue
  "Generate standard TC program prologue.

   Saves context and loads data pointers.

   Parameters:
   - ctx-save-reg: Register to save __sk_buff pointer (optional)
   - data-reg: Register for data pointer
   - data-end-reg: Register for data_end pointer

   Returns vector of instructions."
  ([data-reg data-end-reg]
   (tc-prologue nil data-reg data-end-reg))
  ([ctx-save-reg data-reg data-end-reg]
   (vec (concat
         (when ctx-save-reg
           [(dsl/mov-reg ctx-save-reg :r1)])
         (tc-load-data-pointers :r1 data-reg data-end-reg)))))

;; ============================================================================
;; TC-Specific Field Access
;; ============================================================================

(defn tc-get-mark
  "Get packet mark (fwmark) from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc-load-ctx-field ctx-reg :mark dst-reg))

(defn tc-set-mark
  "Set packet mark (fwmark) in sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - value-reg: Register containing mark value

   Returns stx instruction."
  [ctx-reg value-reg]
  (dsl/stx :w ctx-reg value-reg (skb-offset :mark)))

(defn tc-get-priority
  "Get packet priority from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc-load-ctx-field ctx-reg :priority dst-reg))

(defn tc-set-priority
  "Set packet priority in sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - value-reg: Register containing priority value

   Returns stx instruction."
  [ctx-reg value-reg]
  (dsl/stx :w ctx-reg value-reg (skb-offset :priority)))

(defn tc-get-tc-classid
  "Get TC classid from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc-load-ctx-field ctx-reg :tc-classid dst-reg))

(defn tc-set-tc-classid
  "Set TC classid in sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - value-reg: Register containing classid value

   Returns stx instruction."
  [ctx-reg value-reg]
  (dsl/stx :w ctx-reg value-reg (skb-offset :tc-classid)))

(defn tc-get-protocol
  "Get protocol (ETH_P_*) from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc-load-ctx-field ctx-reg :protocol dst-reg))

(defn tc-get-ifindex
  "Get interface index from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc-load-ctx-field ctx-reg :ifindex dst-reg))

(defn tc-get-len
  "Get packet length from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc-load-ctx-field ctx-reg :len dst-reg))

(defn tc-get-hash
  "Get packet hash from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc-load-ctx-field ctx-reg :hash dst-reg))

;; ============================================================================
;; Bounds Checking (reuse XDP bounds check)
;; ============================================================================

(def tc-bounds-check
  "Generate verifier-friendly bounds check for TC programs.
   Same as XDP bounds check since both use data/data_end pointers."
  xdp/xdp-bounds-check)

;; ============================================================================
;; Packet Data Access (reuse from XDP)
;; ============================================================================

(def tc-load-byte xdp/xdp-load-byte)
(def tc-load-half xdp/xdp-load-half)
(def tc-load-word xdp/xdp-load-word)

;; ============================================================================
;; Protocol Parsing (reuse from XDP)
;; ============================================================================

;; TC uses same packet parsing as XDP
(def tc-parse-ethernet xdp/xdp-parse-ethernet)
(def tc-parse-ipv4 xdp/xdp-parse-ipv4)
(def tc-parse-ipv6 xdp/xdp-parse-ipv6)
(def tc-parse-tcp xdp/xdp-parse-tcp)
(def tc-parse-udp xdp/xdp-parse-udp)

;; Protocol constants
(def ethernet-header-size xdp/ethernet-header-size)
(def ipv4-header-min-size xdp/ipv4-header-min-size)
(def ipv6-header-size xdp/ipv6-header-size)
(def tcp-header-min-size xdp/tcp-header-min-size)
(def udp-header-size xdp/udp-header-size)

;; Header offsets
(def ethernet-offsets xdp/ethernet-offsets)
(def ipv4-offsets xdp/ipv4-offsets)
(def ipv6-offsets xdp/ipv6-offsets)
(def tcp-offsets xdp/tcp-offsets)
(def udp-offsets xdp/udp-offsets)

;; Protocol values
(def ethertypes xdp/ethertypes)
(def ip-protocols xdp/ip-protocols)
(def tcp-flags xdp/tcp-flags)

;; ============================================================================
;; TC Helper Functions
;; ============================================================================

(defn tc-redirect
  "Generate call to bpf_redirect helper.

   Redirects packet to another interface.

   Parameters:
   - ifindex: Interface index to redirect to
   - flags: Redirect flags (usually 0)

   Returns vector of instructions."
  [ifindex flags]
  [(dsl/mov :r1 ifindex)
   (dsl/mov :r2 flags)
   (dsl/call 23)])  ; BPF_FUNC_redirect

(defn tc-clone-redirect
  "Generate call to bpf_clone_redirect helper.

   Clones and redirects packet to another interface.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - ifindex: Interface index to redirect to
   - flags: Redirect flags

   Returns vector of instructions."
  [ctx-reg ifindex flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 ifindex)
   (dsl/mov :r3 flags)
   (dsl/call 13)])  ; BPF_FUNC_clone_redirect

(defn tc-skb-store-bytes
  "Generate call to bpf_skb_store_bytes helper.

   Stores bytes into packet data.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - offset: Offset into packet
   - data-reg: Register with pointer to data
   - len: Length to store
   - flags: Flags (usually 0)

   Returns vector of instructions."
  [ctx-reg offset data-reg len flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 offset)
   (dsl/mov-reg :r3 data-reg)
   (dsl/mov :r4 len)
   (dsl/mov :r5 flags)
   (dsl/call 9)])  ; BPF_FUNC_skb_store_bytes

(defn tc-skb-load-bytes
  "Generate call to bpf_skb_load_bytes helper.

   Loads bytes from packet data.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - offset: Offset into packet
   - dst-reg: Register with pointer to destination buffer
   - len: Length to load

   Returns vector of instructions."
  [ctx-reg offset dst-reg len]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 offset)
   (dsl/mov-reg :r3 dst-reg)
   (dsl/mov :r4 len)
   (dsl/call 26)])  ; BPF_FUNC_skb_load_bytes

(defn tc-skb-change-head
  "Generate call to bpf_skb_change_head helper.

   Adjusts packet headroom.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - len-diff: Bytes to add (positive) or remove (negative)
   - flags: Flags (usually 0)

   Returns vector of instructions."
  [ctx-reg len-diff flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 len-diff)
   (dsl/mov :r3 flags)
   (dsl/call 43)])  ; BPF_FUNC_skb_change_head

(defn tc-skb-change-tail
  "Generate call to bpf_skb_change_tail helper.

   Adjusts packet tail.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - new-len: New packet length
   - flags: Flags (usually 0)

   Returns vector of instructions."
  [ctx-reg new-len flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 new-len)
   (dsl/mov :r3 flags)
   (dsl/call 38)])  ; BPF_FUNC_skb_change_tail

(defn tc-l3-csum-replace
  "Generate call to bpf_l3_csum_replace helper.

   Updates L3 (IP) checksum.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - offset: Offset to checksum field
   - from: Old value
   - to: New value
   - flags: Size flags

   Returns vector of instructions."
  [ctx-reg offset from to flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 offset)
   (dsl/mov :r3 from)
   (dsl/mov :r4 to)
   (dsl/mov :r5 flags)
   (dsl/call 10)])  ; BPF_FUNC_l3_csum_replace

(defn tc-l4-csum-replace
  "Generate call to bpf_l4_csum_replace helper.

   Updates L4 (TCP/UDP) checksum.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - offset: Offset to checksum field
   - from: Old value
   - to: New value
   - flags: Size and pseudo-header flags

   Returns vector of instructions."
  [ctx-reg offset from to flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 offset)
   (dsl/mov :r3 from)
   (dsl/mov :r4 to)
   (dsl/mov :r5 flags)
   (dsl/call 11)])  ; BPF_FUNC_l4_csum_replace

;; ============================================================================
;; TC Program Builders
;; ============================================================================

(defn build-tc-program
  "Build a complete TC program with standard structure.

   Parameters:
   - opts: Map with:
     :ctx-reg - Register to save __sk_buff pointer (optional)
     :data-reg - Register for data pointer (default :r2)
     :data-end-reg - Register for data_end (default :r3)
     :body - Vector of body instructions
     :default-action - Default return action (default :ok)

   Returns assembled program bytes."
  [{:keys [ctx-reg data-reg data-end-reg body default-action]
    :or {data-reg :r2 data-end-reg :r3 default-action :ok}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue
         (tc-prologue ctx-reg data-reg data-end-reg)
         ;; Body
         body
         ;; Default action
         [(dsl/mov :r0 (tc-action default-action))
          (dsl/exit-insn)]))))

(defmacro deftc-instructions
  "Define a TC program as a function returning instructions.

   Parameters:
   - fn-name: Name for the defined function
   - options: Map with:
     :ctx-reg - Register to save context (optional)
     :data-reg - Register for data pointer (default :r2)
     :data-end-reg - Register for data_end (default :r3)
     :default-action - Default return action (default :ok)
   - body: Body expressions (should return vectors of instructions)

   Example:
     (deftc-instructions drop-all
       {:default-action :shot}
       [])"
  [fn-name options & body]
  (let [data-reg (or (:data-reg options) :r2)
        data-end-reg (or (:data-end-reg options) :r3)
        default-action (or (:default-action options) :ok)]
    `(defn ~fn-name
       ~(str "TC program.\n"
             "Default action: " default-action)
       []
       (vec (concat
             (tc-prologue ~(:ctx-reg options) ~data-reg ~data-end-reg)
             ~@body
             [(dsl/mov :r0 ~(tc-action default-action))
              (dsl/exit-insn)])))))

;; ============================================================================
;; Section Names and Metadata
;; ============================================================================

(defn tc-section-name
  "Generate ELF section name for TC program.

   Parameters:
   - direction: :ingress or :egress
   - interface: Optional interface name

   Returns section name like \"tc\" or \"tc/ingress/eth0\""
  ([]
   "tc")
  ([direction]
   (str "tc/" (name direction)))
  ([direction interface]
   (str "tc/" (name direction) "/" interface)))

(defn make-tc-program-info
  "Create program metadata for a TC program.

   Parameters:
   - program-name: Name for the BPF program
   - instructions: Program instructions
   - direction: :ingress or :egress (optional)
   - interface: Optional interface name

   Returns map with program metadata."
  ([program-name instructions]
   {:name program-name
    :section (tc-section-name)
    :type :tc
    :instructions instructions})
  ([program-name instructions direction]
   {:name program-name
    :section (tc-section-name direction)
    :type :tc
    :direction direction
    :instructions instructions})
  ([program-name instructions direction interface]
   {:name program-name
    :section (tc-section-name direction interface)
    :type :tc
    :direction direction
    :interface interface
    :instructions instructions}))

;; ============================================================================
;; Common TC Patterns
;; ============================================================================

(defn tc-return-action
  "Generate instructions to return a TC action.

   Parameters:
   - action: Action keyword or integer

   Returns vector of [mov, exit] instructions."
  [action]
  (let [val (if (keyword? action) (tc-action action) action)]
    [(dsl/mov :r0 val)
     (dsl/exit-insn)]))

(defn tc-mark-packet
  "Generate instructions to set packet mark.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - mark: Mark value to set

   Returns vector of instructions."
  [ctx-reg mark]
  [(dsl/mov :r0 mark)
   (tc-set-mark ctx-reg :r0)])

(defn tc-classify-packet
  "Generate instructions to set TC classid.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - major: Major classid (upper 16 bits)
   - minor: Minor classid (lower 16 bits)

   Returns vector of instructions."
  [ctx-reg major minor]
  (let [classid (bit-or (bit-shift-left major 16) minor)]
    [(dsl/mov :r0 classid)
     (tc-set-tc-classid ctx-reg :r0)]))

;; ============================================================================
;; IP Address Helper (reuse from XDP)
;; ============================================================================

(def ipv4-to-int xdp/ipv4-to-int)

(defn tc-match-mark
  "Generate instructions to match packet mark.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - mark: Mark value to match
   - action-on-match: TC action if mark matches

   Returns vector of instructions."
  [ctx-reg mark action-on-match]
  [(tc-get-mark ctx-reg :r0)
   (dsl/jmp-imm :jne :r0 mark 2)
   (dsl/mov :r0 (tc-action action-on-match))
   (dsl/exit-insn)])
