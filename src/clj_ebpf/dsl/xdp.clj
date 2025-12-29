(ns clj-ebpf.dsl.xdp
  "High-level XDP (eXpress Data Path) DSL for BPF programs.

   XDP programs run at the earliest point in the network stack, before
   the kernel allocates an sk_buff. This makes them extremely fast for
   packet filtering, forwarding, and modification.

   XDP Actions:
   - XDP_ABORTED (0): Error, packet dropped
   - XDP_DROP    (1): Silently drop packet
   - XDP_PASS    (2): Pass to normal network stack
   - XDP_TX      (3): Transmit back out same interface
   - XDP_REDIRECT(4): Redirect to another interface or CPU

   Example:
     (defxdp-instructions simple-drop
       {:action :drop}
       ;; All packets dropped
       [])"
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; XDP Actions
;; ============================================================================

(def xdp-actions
  "XDP action return values."
  {:aborted  0   ; Error, packet dropped
   :drop     1   ; Drop packet
   :pass     2   ; Pass to network stack
   :tx       3   ; Transmit back out same interface
   :redirect 4}) ; Redirect to another interface

(defn xdp-action
  "Get XDP action value by keyword.

   Parameters:
   - action: Action keyword (:drop, :pass, :tx, :redirect, :aborted)

   Returns integer action value.

   Example:
     (xdp-action :drop)  ;; => 1"
  [action]
  (or (get xdp-actions action)
      (throw (ex-info "Unknown XDP action" {:action action}))))

;; ============================================================================
;; xdp_md Structure Offsets
;; ============================================================================

;; struct xdp_md {
;;   __u32 data;           // offset 0
;;   __u32 data_end;       // offset 4
;;   __u32 data_meta;      // offset 8
;;   __u32 ingress_ifindex; // offset 12
;;   __u32 rx_queue_index;  // offset 16
;;   __u32 egress_ifindex;  // offset 20
;; };

(def xdp-md-offsets
  "xdp_md structure field offsets."
  {:data            0   ; Packet data start
   :data-end        4   ; Packet data end
   :data-meta       8   ; Metadata area (before data)
   :ingress-ifindex 12  ; Ingress interface index
   :rx-queue-index  16  ; RX queue index
   :egress-ifindex  20}) ; Egress interface index (for TX/redirect)

(defn xdp-md-offset
  "Get offset for xdp_md field.

   Parameters:
   - field: Field keyword

   Returns offset in bytes."
  [field]
  (or (get xdp-md-offsets field)
      (throw (ex-info "Unknown xdp_md field" {:field field}))))

;; ============================================================================
;; Protocol Header Offsets
;; ============================================================================

(def ethernet-header-size 14)
(def ipv4-header-min-size 20)
(def ipv6-header-size 40)
(def tcp-header-min-size 20)
(def udp-header-size 8)
(def icmp-header-size 8)

;; Ethernet header offsets
(def ethernet-offsets
  {:dst-mac    0    ; 6 bytes - destination MAC
   :src-mac    6    ; 6 bytes - source MAC
   :ethertype  12}) ; 2 bytes - protocol type

;; EtherType values
(def ethertypes
  {:ipv4    0x0800
   :arp     0x0806
   :ipv6    0x86DD
   :vlan    0x8100
   :qinq    0x88A8})

;; IPv4 header offsets (no options)
(def ipv4-offsets
  {:version-ihl   0   ; 1 byte - version (4 bits) + header length (4 bits)
   :tos           1   ; 1 byte - type of service / DSCP
   :total-length  2   ; 2 bytes - total packet length
   :id            4   ; 2 bytes - identification
   :flags-frag    6   ; 2 bytes - flags + fragment offset
   :ttl           8   ; 1 byte - time to live
   :protocol      9   ; 1 byte - protocol number
   :checksum      10  ; 2 bytes - header checksum
   :src-addr      12  ; 4 bytes - source IP
   :dst-addr      16}) ; 4 bytes - destination IP

;; IPv6 header offsets
(def ipv6-offsets
  {:version-class-flow 0  ; 4 bytes - version, traffic class, flow label
   :payload-length     4  ; 2 bytes - payload length
   :next-header        6  ; 1 byte - next header (like IPv4 protocol)
   :hop-limit          7  ; 1 byte - hop limit (like IPv4 TTL)
   :src-addr           8  ; 16 bytes - source address
   :dst-addr           24}) ; 16 bytes - destination address

;; TCP header offsets
(def tcp-offsets
  {:src-port    0   ; 2 bytes - source port
   :dst-port    2   ; 2 bytes - destination port
   :seq         4   ; 4 bytes - sequence number
   :ack         8   ; 4 bytes - acknowledgment number
   :data-offset 12  ; 1 byte (upper 4 bits) - data offset
   :flags       13  ; 1 byte - TCP flags
   :window      14  ; 2 bytes - window size
   :checksum    16  ; 2 bytes - checksum
   :urgent      18}) ; 2 bytes - urgent pointer

;; TCP flags
(def tcp-flags
  {:fin 0x01
   :syn 0x02
   :rst 0x04
   :psh 0x08
   :ack 0x10
   :urg 0x20
   :ece 0x40
   :cwr 0x80})

;; UDP header offsets
(def udp-offsets
  {:src-port 0   ; 2 bytes - source port
   :dst-port 2   ; 2 bytes - destination port
   :length   4   ; 2 bytes - UDP length
   :checksum 6}) ; 2 bytes - checksum

;; IP protocol numbers
(def ip-protocols
  {:icmp   1
   :tcp    6
   :udp    17
   :icmpv6 58})

;; ============================================================================
;; XDP Context Access
;; ============================================================================

(defn xdp-load-ctx-field
  "Load a field from xdp_md context.

   Parameters:
   - ctx-reg: Register containing xdp_md pointer (typically :r1 at entry)
   - field: Field keyword from xdp-md-offsets
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg field dst-reg]
  (let [offset (xdp-md-offset field)]
    (dsl/ldx :w dst-reg ctx-reg offset)))

(defn xdp-load-data-pointers
  "Load data and data_end pointers from xdp_md.

   Parameters:
   - ctx-reg: Register containing xdp_md pointer
   - data-reg: Destination register for data pointer
   - data-end-reg: Destination register for data_end pointer

   Returns vector of instructions.

   Example:
     (xdp-load-data-pointers :r1 :r2 :r3)
     ;; r2 = data, r3 = data_end"
  [ctx-reg data-reg data-end-reg]
  [(xdp-load-ctx-field ctx-reg :data data-reg)
   (xdp-load-ctx-field ctx-reg :data-end data-end-reg)])

(defn xdp-prologue
  "Generate standard XDP program prologue.

   Saves context and loads data pointers.

   Parameters:
   - ctx-save-reg: Register to save xdp_md pointer (optional)
   - data-reg: Register for data pointer
   - data-end-reg: Register for data_end pointer

   Returns vector of instructions."
  ([data-reg data-end-reg]
   (xdp-prologue nil data-reg data-end-reg))
  ([ctx-save-reg data-reg data-end-reg]
   (vec (concat
         (when ctx-save-reg
           [(dsl/mov-reg ctx-save-reg :r1)])
         (xdp-load-data-pointers :r1 data-reg data-end-reg)))))

;; ============================================================================
;; Bounds Checking
;; ============================================================================

(defn xdp-bounds-check
  "Generate verifier-friendly bounds check.

   This is CRITICAL for XDP programs. The verifier requires bounds checks
   before accessing any packet data.

   Parameters:
   - data-reg: Register containing current data pointer
   - data-end-reg: Register containing data_end pointer
   - size: Number of bytes we want to access
   - action-on-fail: XDP action if check fails (default :pass)

   Returns vector of instructions that:
   - Computes data + size
   - Compares with data_end
   - Returns action-on-fail if bounds exceeded

   Example:
     (xdp-bounds-check :r2 :r3 14 :pass)
     ;; If r2 + 14 > r3, return XDP_PASS"
  ([data-reg data-end-reg size]
   (xdp-bounds-check data-reg data-end-reg size :pass))
  ([data-reg data-end-reg size action-on-fail]
   (let [action-val (xdp-action action-on-fail)]
     [(dsl/mov-reg :r0 data-reg)
      (dsl/add :r0 size)
      (dsl/jmp-reg :jgt :r0 data-end-reg 2)
      (dsl/mov :r0 action-val)
      (dsl/exit-insn)])))

(defn xdp-bounds-check-var
  "Generate bounds check with variable offset.

   Parameters:
   - data-reg: Current data pointer
   - data-end-reg: Data end pointer
   - offset-reg: Register containing offset to add
   - action-on-fail: XDP action if check fails

   Returns vector of instructions."
  ([data-reg data-end-reg offset-reg]
   (xdp-bounds-check-var data-reg data-end-reg offset-reg :pass))
  ([data-reg data-end-reg offset-reg action-on-fail]
   (let [action-val (xdp-action action-on-fail)]
     [(dsl/mov-reg :r0 data-reg)
      (dsl/add-reg :r0 offset-reg)
      (dsl/jmp-reg :jgt :r0 data-end-reg 2)
      (dsl/mov :r0 action-val)
      (dsl/exit-insn)])))

;; ============================================================================
;; Packet Data Access
;; ============================================================================

(defn xdp-load-byte
  "Load a byte from packet at offset.

   IMPORTANT: Caller must ensure bounds check was done first!

   Parameters:
   - data-reg: Register containing data pointer
   - offset: Byte offset from data
   - dst-reg: Destination register

   Returns ldx instruction."
  [data-reg offset dst-reg]
  (dsl/ldx :b dst-reg data-reg offset))

(defn xdp-load-half
  "Load a half-word (2 bytes) from packet at offset.

   Note: Network byte order (big-endian).
   Use bswap16 if you need host byte order.

   Parameters:
   - data-reg: Register containing data pointer
   - offset: Byte offset from data
   - dst-reg: Destination register

   Returns ldx instruction."
  [data-reg offset dst-reg]
  (dsl/ldx :h dst-reg data-reg offset))

(defn xdp-load-word
  "Load a word (4 bytes) from packet at offset.

   Note: Network byte order (big-endian).
   Use bswap32 if you need host byte order.

   Parameters:
   - data-reg: Register containing data pointer
   - offset: Byte offset from data
   - dst-reg: Destination register

   Returns ldx instruction."
  [data-reg offset dst-reg]
  (dsl/ldx :w dst-reg data-reg offset))

;; ============================================================================
;; Ethernet Header Parsing
;; ============================================================================

(defn xdp-parse-ethernet
  "Parse Ethernet header and extract EtherType.

   Parameters:
   - data-reg: Register containing data pointer
   - data-end-reg: Register containing data_end
   - ethertype-reg: Destination for EtherType value

   Returns vector of instructions including bounds check.

   After execution:
   - ethertype-reg contains EtherType (in network byte order)
   - Returns XDP_PASS if packet too small"
  [data-reg data-end-reg ethertype-reg]
  (vec (concat
        ;; Bounds check for Ethernet header
        (xdp-bounds-check data-reg data-end-reg ethernet-header-size :pass)
        ;; Load EtherType (at offset 12, 2 bytes)
        [(xdp-load-half data-reg (:ethertype ethernet-offsets) ethertype-reg)])))

(defn xdp-load-src-mac
  "Load source MAC address bytes.

   Parameters:
   - data-reg: Data pointer (after Ethernet bounds check)
   - dst-regs: Vector of 6 registers for each MAC byte

   Returns vector of ldx instructions."
  [data-reg dst-regs]
  (vec (for [i (range 6)]
         (xdp-load-byte data-reg (+ (:src-mac ethernet-offsets) i)
                        (nth dst-regs i)))))

(defn xdp-load-dst-mac
  "Load destination MAC address bytes.

   Parameters:
   - data-reg: Data pointer (after Ethernet bounds check)
   - dst-regs: Vector of 6 registers for each MAC byte

   Returns vector of ldx instructions."
  [data-reg dst-regs]
  (vec (for [i (range 6)]
         (xdp-load-byte data-reg (+ (:dst-mac ethernet-offsets) i)
                        (nth dst-regs i)))))

;; ============================================================================
;; IPv4 Header Parsing
;; ============================================================================

(defn xdp-parse-ipv4
  "Parse IPv4 header at given offset.

   Parameters:
   - data-reg: Data pointer
   - data-end-reg: Data end pointer
   - l3-offset: Offset to IPv4 header (typically 14 for Ethernet)
   - protocol-reg: Destination for IP protocol
   - src-ip-reg: Destination for source IP (optional)
   - dst-ip-reg: Destination for destination IP (optional)

   Returns vector of instructions including bounds check."
  ([data-reg data-end-reg l3-offset protocol-reg]
   (xdp-parse-ipv4 data-reg data-end-reg l3-offset protocol-reg nil nil))
  ([data-reg data-end-reg l3-offset protocol-reg src-ip-reg dst-ip-reg]
   (vec (concat
         ;; Bounds check for IPv4 header
         (xdp-bounds-check data-reg data-end-reg
                           (+ l3-offset ipv4-header-min-size) :pass)
         ;; Load protocol
         [(xdp-load-byte data-reg (+ l3-offset (:protocol ipv4-offsets))
                         protocol-reg)]
         ;; Load source IP if requested
         (when src-ip-reg
           [(xdp-load-word data-reg (+ l3-offset (:src-addr ipv4-offsets))
                           src-ip-reg)])
         ;; Load destination IP if requested
         (when dst-ip-reg
           [(xdp-load-word data-reg (+ l3-offset (:dst-addr ipv4-offsets))
                           dst-ip-reg)])))))

(defn xdp-get-ipv4-header-length
  "Get IPv4 header length in bytes (including options).

   Parameters:
   - data-reg: Data pointer
   - l3-offset: Offset to IPv4 header
   - dst-reg: Destination register for header length

   Note: Caller should multiply by 4 after loading IHL nibble.

   Returns vector of instructions."
  [data-reg l3-offset dst-reg]
  [(xdp-load-byte data-reg l3-offset dst-reg)
   (dsl/and dst-reg 0x0f)  ; Extract IHL (lower 4 bits)
   (dsl/lsh dst-reg 2)])   ; Multiply by 4

;; ============================================================================
;; IPv6 Header Parsing
;; ============================================================================

(defn xdp-parse-ipv6
  "Parse IPv6 header at given offset.

   Parameters:
   - data-reg: Data pointer
   - data-end-reg: Data end pointer
   - l3-offset: Offset to IPv6 header (typically 14)
   - next-header-reg: Destination for next header value

   Returns vector of instructions."
  [data-reg data-end-reg l3-offset next-header-reg]
  (vec (concat
        ;; Bounds check for IPv6 header
        (xdp-bounds-check data-reg data-end-reg
                          (+ l3-offset ipv6-header-size) :pass)
        ;; Load next header
        [(xdp-load-byte data-reg (+ l3-offset (:next-header ipv6-offsets))
                        next-header-reg)])))

;; ============================================================================
;; TCP/UDP Header Parsing
;; ============================================================================

(defn xdp-parse-tcp
  "Parse TCP header at given offset.

   Parameters:
   - data-reg: Data pointer
   - data-end-reg: Data end pointer
   - l4-offset: Offset to TCP header
   - src-port-reg: Destination for source port (optional)
   - dst-port-reg: Destination for destination port (optional)
   - flags-reg: Destination for TCP flags (optional)

   Returns vector of instructions."
  [data-reg data-end-reg l4-offset & {:keys [src-port dst-port flags]}]
  (vec (concat
        ;; Bounds check for TCP header
        (xdp-bounds-check data-reg data-end-reg
                          (+ l4-offset tcp-header-min-size) :pass)
        ;; Load source port if requested
        (when src-port
          [(xdp-load-half data-reg (+ l4-offset (:src-port tcp-offsets))
                          src-port)])
        ;; Load destination port if requested
        (when dst-port
          [(xdp-load-half data-reg (+ l4-offset (:dst-port tcp-offsets))
                          dst-port)])
        ;; Load flags if requested
        (when flags
          [(xdp-load-byte data-reg (+ l4-offset (:flags tcp-offsets))
                          flags)]))))

(defn xdp-parse-udp
  "Parse UDP header at given offset.

   Parameters:
   - data-reg: Data pointer
   - data-end-reg: Data end pointer
   - l4-offset: Offset to UDP header
   - src-port-reg: Destination for source port (optional)
   - dst-port-reg: Destination for destination port (optional)

   Returns vector of instructions."
  [data-reg data-end-reg l4-offset & {:keys [src-port dst-port]}]
  (vec (concat
        ;; Bounds check for UDP header
        (xdp-bounds-check data-reg data-end-reg
                          (+ l4-offset udp-header-size) :pass)
        ;; Load source port if requested
        (when src-port
          [(xdp-load-half data-reg (+ l4-offset (:src-port udp-offsets))
                          src-port)])
        ;; Load destination port if requested
        (when dst-port
          [(xdp-load-half data-reg (+ l4-offset (:dst-port udp-offsets))
                          dst-port)]))))

;; ============================================================================
;; XDP Helper Functions
;; ============================================================================

(defn xdp-adjust-head
  "Generate call to bpf_xdp_adjust_head helper.

   Moves the packet data pointer by delta bytes.
   Positive delta adds headroom, negative removes.

   Parameters:
   - ctx-reg: Register containing xdp_md pointer
   - delta: Bytes to adjust (can be negative)

   Returns vector of instructions."
  [ctx-reg delta]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 delta)
   (dsl/call 44)])  ; BPF_FUNC_xdp_adjust_head

(defn xdp-adjust-tail
  "Generate call to bpf_xdp_adjust_tail helper.

   Moves the packet data_end pointer by delta bytes.

   Parameters:
   - ctx-reg: Register containing xdp_md pointer
   - delta: Bytes to adjust

   Returns vector of instructions."
  [ctx-reg delta]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 delta)
   (dsl/call 65)])  ; BPF_FUNC_xdp_adjust_tail

(defn xdp-adjust-meta
  "Generate call to bpf_xdp_adjust_meta helper.

   Adjusts metadata area before packet data.

   Parameters:
   - ctx-reg: Register containing xdp_md pointer
   - delta: Bytes to adjust

   Returns vector of instructions."
  [ctx-reg delta]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov :r2 delta)
   (dsl/call 54)])  ; BPF_FUNC_xdp_adjust_meta

;; ============================================================================
;; XDP Program Builders
;; ============================================================================

(defn build-xdp-program
  "Build a complete XDP program with standard structure.

   Parameters:
   - opts: Map with:
     :ctx-reg - Register to save xdp_md pointer (optional)
     :data-reg - Register for data pointer (default :r2)
     :data-end-reg - Register for data_end (default :r3)
     :body - Vector of body instructions
     :default-action - Default return action (default :pass)

   Returns assembled program bytes."
  [{:keys [ctx-reg data-reg data-end-reg body default-action]
    :or {data-reg :r2 data-end-reg :r3 default-action :pass}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue
         (xdp-prologue ctx-reg data-reg data-end-reg)
         ;; Body
         body
         ;; Default action
         [(dsl/mov :r0 (xdp-action default-action))
          (dsl/exit-insn)]))))

(defmacro defxdp-instructions
  "Define an XDP program as a function returning instructions.

   Parameters:
   - fn-name: Name for the defined function
   - options: Map with:
     :ctx-reg - Register to save context (optional)
     :data-reg - Register for data pointer (default :r2)
     :data-end-reg - Register for data_end (default :r3)
     :default-action - Default return action (default :pass)
   - body: Body expressions (should return vectors of instructions)

   Example:
     (defxdp-instructions drop-all
       {:default-action :drop}
       [])"
  [fn-name options & body]
  (let [data-reg (or (:data-reg options) :r2)
        data-end-reg (or (:data-end-reg options) :r3)
        default-action (or (:default-action options) :pass)]
    `(defn ~fn-name
       ~(str "XDP program.\n"
             "Default action: " default-action)
       []
       (vec (concat
             (xdp-prologue ~(:ctx-reg options) ~data-reg ~data-end-reg)
             ~@body
             [(dsl/mov :r0 ~(xdp-action default-action))
              (dsl/exit-insn)])))))

;; ============================================================================
;; Section Names and Metadata
;; ============================================================================

(defn xdp-section-name
  "Generate ELF section name for XDP program.

   Parameters:
   - interface: Optional interface name for attachment hint

   Returns section name like \"xdp\" or \"xdp/eth0\""
  ([]
   "xdp")
  ([interface]
   (str "xdp/" interface)))

(defn make-xdp-program-info
  "Create program metadata for an XDP program.

   Parameters:
   - program-name: Name for the BPF program
   - instructions: Program instructions
   - interface: Optional interface name

   Returns map with program metadata."
  ([program-name instructions]
   (make-xdp-program-info program-name instructions nil))
  ([program-name instructions interface]
   (cond-> {:name program-name
            :section (if interface (xdp-section-name interface) (xdp-section-name))
            :type :xdp
            :instructions instructions}
     interface (assoc :interface interface))))

;; ============================================================================
;; Common XDP Patterns
;; ============================================================================

(defn xdp-return-action
  "Generate instructions to return an XDP action.

   Parameters:
   - action: Action keyword or integer

   Returns vector of [mov, exit] instructions."
  [action]
  (let [val (if (keyword? action) (xdp-action action) action)]
    [(dsl/mov :r0 val)
     (dsl/exit-insn)]))

(defn xdp-drop-if-port
  "Generate instructions to drop packets to/from a specific port.

   Parameters:
   - data-reg: Data pointer
   - data-end-reg: Data end pointer
   - l4-offset: Layer 4 header offset
   - port-offset: Offset within L4 header (0 for src, 2 for dst)
   - port: Port number to match
   - is-tcp: true for TCP, false for UDP

   Returns vector of instructions."
  [data-reg data-end-reg l4-offset port-offset port is-tcp]
  (let [l4-size (if is-tcp tcp-header-min-size udp-header-size)]
    (vec (concat
          ;; Bounds check
          (xdp-bounds-check data-reg data-end-reg (+ l4-offset l4-size) :pass)
          ;; Load port
          [(xdp-load-half data-reg (+ l4-offset port-offset) :r0)]
          ;; Compare and drop if match (port in network byte order)
          [(dsl/jmp-imm :jne :r0 port 2)
           (dsl/mov :r0 (xdp-action :drop))
           (dsl/exit-insn)]))))

(defn xdp-pass-only-tcp
  "Generate instructions that pass only TCP packets.

   Drops all non-TCP packets.

   Parameters:
   - data-reg: Data pointer
   - data-end-reg: Data end pointer

   Returns vector of instructions."
  [data-reg data-end-reg]
  (vec (concat
        ;; Check Ethernet header
        (xdp-bounds-check data-reg data-end-reg ethernet-header-size :drop)
        ;; Load EtherType
        [(xdp-load-half data-reg (:ethertype ethernet-offsets) :r4)]
        ;; Check if IPv4 (0x0800)
        [(dsl/jmp-imm :jne :r4 (:ipv4 ethertypes) 2)
         (dsl/mov :r0 (xdp-action :drop))
         (dsl/exit-insn)]
        ;; Check IPv4 header
        (xdp-bounds-check data-reg data-end-reg
                          (+ ethernet-header-size ipv4-header-min-size) :drop)
        ;; Load protocol
        [(xdp-load-byte data-reg (+ ethernet-header-size (:protocol ipv4-offsets)) :r4)]
        ;; Check if TCP (6)
        [(dsl/jmp-imm :jeq :r4 (:tcp ip-protocols) 2)
         (dsl/mov :r0 (xdp-action :drop))
         (dsl/exit-insn)])))

;; ============================================================================
;; Byte Order Helpers
;; ============================================================================

(defn xdp-bswap16
  "Byte swap 16-bit value (network to host order or vice versa).

   Parameters:
   - reg: Register to byte-swap in place

   Returns vector of instructions (manual swap since BPF doesn't have bswap16)."
  [reg]
  ;; For 16-bit: swap bytes manually
  ;; r0 = (val >> 8) | ((val & 0xff) << 8)
  [(dsl/mov-reg :r0 reg)
   (dsl/and :r0 0xff)
   (dsl/lsh :r0 8)
   (dsl/rsh reg 8)
   (dsl/or-reg reg :r0)])

(defn xdp-bswap32
  "Byte swap 32-bit value.

   Parameters:
   - reg: Register containing 32-bit value
   - tmp-reg: Temporary register for computation (unused, kept for API compat)

   Returns BPF endianness instruction."
  [reg tmp-reg]
  ;; BPF has built-in endianness conversion
  [(dsl/end-to-be reg 32)])

;; ============================================================================
;; IP Address Helpers
;; ============================================================================

(defn ipv4-to-int
  "Convert IPv4 address string to integer (network byte order).

   Parameters:
   - ip-str: IP address string like \"192.168.1.1\"

   Returns 32-bit integer."
  [ip-str]
  (let [parts (map #(Integer/parseInt %) (clojure.string/split ip-str #"\."))]
    (bit-or
     (bit-shift-left (nth parts 0) 24)
     (bit-shift-left (nth parts 1) 16)
     (bit-shift-left (nth parts 2) 8)
     (nth parts 3))))

(defn xdp-match-ipv4
  "Generate instructions to match IPv4 source or destination.

   Parameters:
   - data-reg: Data pointer
   - data-end-reg: Data end pointer
   - ip-addr: IP address integer (network byte order)
   - match-src: true for source, false for destination
   - action-on-match: Action if IP matches

   Returns vector of instructions."
  [data-reg data-end-reg ip-addr match-src action-on-match]
  (let [field-offset (if match-src :src-addr :dst-addr)
        offset (+ ethernet-header-size (get ipv4-offsets field-offset))]
    (vec (concat
          ;; Bounds check
          (xdp-bounds-check data-reg data-end-reg
                            (+ ethernet-header-size ipv4-header-min-size) :pass)
          ;; Load IP address
          [(xdp-load-word data-reg offset :r4)]
          ;; Compare and return action if match
          [(dsl/jmp-imm :jne :r4 ip-addr 2)
           (dsl/mov :r0 (xdp-action action-on-match))
           (dsl/exit-insn)]))))

;; ============================================================================
;; XDP Redirect Helpers (DEVMAP, CPUMAP, XSKMAP)
;; ============================================================================

(defn xdp-redirect
  "Generate call to bpf_redirect helper.

   Redirects packet to another interface by ifindex.

   Parameters:
   - ifindex: Interface index to redirect to (or register containing it)
   - flags: Flags (typically 0)

   Returns vector of instructions.

   Note: Program must return XDP_REDIRECT (4) after calling this.

   Example:
     (concat (xdp-redirect 2 0)    ; Redirect to ifindex 2
             [(dsl/mov :r0 4)      ; XDP_REDIRECT
              (dsl/exit-insn)])"
  [ifindex flags]
  (if (keyword? ifindex)
    ;; ifindex is in a register
    [(dsl/mov-reg :r1 ifindex)
     (dsl/mov :r2 flags)
     (dsl/call 23)]  ; BPF_FUNC_redirect
    ;; ifindex is immediate
    [(dsl/mov :r1 ifindex)
     (dsl/mov :r2 flags)
     (dsl/call 23)]))

(defn xdp-redirect-map
  "Generate call to bpf_redirect_map helper.

   Redirects packet using a DEVMAP, CPUMAP, or XSKMAP lookup.
   This is the preferred way to redirect packets when using redirect maps.

   Parameters:
   - map-fd: File descriptor of the redirect map
   - key: Map key (index in DEVMAP/CPUMAP) - integer or register keyword
   - flags: Flags (typically 0)

   Returns vector of instructions.

   The helper returns XDP_REDIRECT on success, or XDP_ABORTED on failure.
   You should return r0 directly after calling this.

   Example with DEVMAP:
     ;; Redirect to interface at index 1 in dev-map
     (concat (xdp-redirect-map (:fd dev-map) 1 0)
             [(dsl/exit-insn)])  ; Return value from redirect_map

   Example with dynamic key:
     ;; Key computed in :r5
     (concat (xdp-redirect-map (:fd dev-map) :r5 0)
             [(dsl/exit-insn)])"
  [map-fd key flags]
  (if (keyword? key)
    ;; key is in a register
    [(dsl/ld-map-fd :r1 map-fd)
     (dsl/mov-reg :r2 key)
     (dsl/mov :r3 flags)
     (dsl/call 51)]  ; BPF_FUNC_redirect_map
    ;; key is immediate
    [(dsl/ld-map-fd :r1 map-fd)
     (dsl/mov :r2 key)
     (dsl/mov :r3 flags)
     (dsl/call 51)]))

(defn xdp-redirect-map-with-action
  "Generate XDP redirect_map call with proper return.

   Convenience function that includes the exit instruction.
   Returns the result of bpf_redirect_map directly.

   Parameters:
   - map-fd: File descriptor of redirect map
   - key: Map key (integer or register keyword)
   - flags: Flags (default 0)

   Returns vector of instructions ending with exit.

   Example:
     (xdp-redirect-map-with-action (:fd dev-map) 0 0)"
  ([map-fd key]
   (xdp-redirect-map-with-action map-fd key 0))
  ([map-fd key flags]
   (vec (concat
         (xdp-redirect-map map-fd key flags)
         [(dsl/exit-insn)]))))

(defn xdp-redirect-to-cpu
  "Generate XDP redirect to a specific CPU using CPUMAP.

   Convenience function for CPU redirection.

   Parameters:
   - cpumap-fd: File descriptor of CPUMAP
   - cpu-index: Target CPU index (integer or register)
   - flags: Flags (default 0)

   Returns vector of instructions with exit."
  ([cpumap-fd cpu-index]
   (xdp-redirect-to-cpu cpumap-fd cpu-index 0))
  ([cpumap-fd cpu-index flags]
   (xdp-redirect-map-with-action cpumap-fd cpu-index flags)))

(defn xdp-redirect-to-interface
  "Generate XDP redirect to interface using DEVMAP.

   Convenience function for interface redirection.

   Parameters:
   - devmap-fd: File descriptor of DEVMAP
   - map-index: Index in DEVMAP (integer or register)
   - flags: Flags (default 0)

   Returns vector of instructions with exit."
  ([devmap-fd map-index]
   (xdp-redirect-to-interface devmap-fd map-index 0))
  ([devmap-fd map-index flags]
   (xdp-redirect-map-with-action devmap-fd map-index flags)))

(defn xdp-redirect-to-xsk
  "Generate XDP redirect to AF_XDP socket using XSKMAP.

   Convenience function for redirecting packets to userspace via AF_XDP.
   Typically used with the RX queue index as the key.

   Parameters:
   - xskmap-fd: File descriptor of XSKMAP
   - queue-index: Queue index in XSKMAP (integer or register keyword)
   - flags: Flags (default XDP_PASS=2 as fallback action if no socket)

   Returns vector of instructions with exit.

   Common pattern - redirect based on RX queue:
     ;; Load rx_queue_index from xdp_md context
     (xdp-load-ctx-field :r1 :rx-queue-index :r4)
     ;; Redirect to XSK socket for this queue
     (xdp-redirect-to-xsk xsk-map-fd :r4)

   Note: If no XSK socket is registered at the queue index, the packet
   falls back to the action specified in flags (default: XDP_PASS)."
  ([xskmap-fd queue-index]
   (xdp-redirect-to-xsk xskmap-fd queue-index 2))  ; XDP_PASS as fallback
  ([xskmap-fd queue-index flags]
   (xdp-redirect-map-with-action xskmap-fd queue-index flags)))

(defn xdp-redirect-to-xsk-by-queue
  "Generate XDP program fragment that redirects to XSK based on rx_queue_index.

   This is the most common AF_XDP pattern: redirect packets to the XSK
   socket registered for the queue they arrived on.

   Parameters:
   - ctx-reg: Register containing xdp_md pointer
   - xskmap-fd: File descriptor of XSKMAP
   - tmp-reg: Temporary register for queue index (default :r4)
   - flags: Fallback flags (default XDP_PASS=2)

   Returns vector of instructions that:
   1. Loads rx_queue_index from context
   2. Calls bpf_redirect_map with XSKMAP
   3. Exits with the redirect result

   Example:
     ;; In XDP program body after prologue:
     (xdp-redirect-to-xsk-by-queue :r6 (:fd xsk-map))"
  ([ctx-reg xskmap-fd]
   (xdp-redirect-to-xsk-by-queue ctx-reg xskmap-fd :r4 2))
  ([ctx-reg xskmap-fd tmp-reg]
   (xdp-redirect-to-xsk-by-queue ctx-reg xskmap-fd tmp-reg 2))
  ([ctx-reg xskmap-fd tmp-reg flags]
   (vec (concat
         ;; Load rx_queue_index from xdp_md
         [(xdp-load-ctx-field ctx-reg :rx-queue-index tmp-reg)]
         ;; Redirect to XSK at this queue index
         (xdp-redirect-to-xsk xskmap-fd tmp-reg flags)))))
