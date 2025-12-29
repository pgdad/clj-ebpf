(ns clj-ebpf.dsl.socket
  "High-level Socket Filter DSL for BPF programs.

   Socket filter programs can be attached to sockets to filter
   incoming packets. They run on each packet and decide whether
   to pass or drop it.

   Return values:
   - 0: Drop the packet
   - >0: Number of bytes to pass (use packet length to pass all)

   Socket filters use __sk_buff as context (same as TC).

   Example:
     (defsocket-filter-instructions allow-all
       {:default-action :accept}
       [])"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.tc :as tc]))

;; ============================================================================
;; Socket Filter Return Values
;; ============================================================================

(def socket-filter-actions
  "Socket filter return values."
  {:reject 0      ; Drop the packet
   :accept -1})   ; Accept (return packet length)

(defn socket-action
  "Get socket filter action value.

   Parameters:
   - action: :reject (0) or :accept (packet length)

   Returns integer value.

   Note: :accept returns -1 as a marker; you should return
   actual packet length for accept. Use socket-accept for this."
  [action]
  (or (get socket-filter-actions action)
      (throw (ex-info "Unknown socket filter action" {:action action}))))

;; ============================================================================
;; Reuse __sk_buff from TC
;; ============================================================================

;; Socket filters use __sk_buff same as TC
(def skb-offsets tc/skb-offsets)
(def skb-offset tc/skb-offset)

;; Reuse context access
(def socket-load-ctx-field tc/tc-load-ctx-field)
(def socket-load-data-pointers tc/tc-load-data-pointers)

;; Reuse packet parsing
(def socket-parse-ethernet tc/tc-parse-ethernet)
(def socket-parse-ipv4 tc/tc-parse-ipv4)
(def socket-parse-ipv6 tc/tc-parse-ipv6)
(def socket-parse-tcp tc/tc-parse-tcp)
(def socket-parse-udp tc/tc-parse-udp)

;; Reuse bounds checking
(def socket-bounds-check tc/tc-bounds-check)

;; Reuse protocol constants
(def ethernet-header-size tc/ethernet-header-size)
(def ipv4-header-min-size tc/ipv4-header-min-size)
(def ipv6-header-size tc/ipv6-header-size)
(def tcp-header-min-size tc/tcp-header-min-size)
(def udp-header-size tc/udp-header-size)

(def ethernet-offsets tc/ethernet-offsets)
(def ipv4-offsets tc/ipv4-offsets)
(def ipv6-offsets tc/ipv6-offsets)
(def tcp-offsets tc/tcp-offsets)
(def udp-offsets tc/udp-offsets)

(def ethertypes tc/ethertypes)
(def ip-protocols tc/ip-protocols)
(def tcp-flags tc/tcp-flags)

;; ============================================================================
;; Socket Filter Prologue
;; ============================================================================

(defn socket-prologue
  "Generate standard socket filter prologue.

   Saves context and loads data pointers.

   Parameters:
   - ctx-save-reg: Register to save __sk_buff pointer (optional)
   - data-reg: Register for data pointer
   - data-end-reg: Register for data_end pointer

   Returns vector of instructions."
  ([data-reg data-end-reg]
   (socket-prologue nil data-reg data-end-reg))
  ([ctx-save-reg data-reg data-end-reg]
   (tc/tc-prologue ctx-save-reg data-reg data-end-reg)))

;; ============================================================================
;; Socket Filter Specific Operations
;; ============================================================================

(defn socket-get-len
  "Get packet length from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc/tc-get-len ctx-reg dst-reg))

(defn socket-get-protocol
  "Get protocol from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc/tc-get-protocol ctx-reg dst-reg))

(defn socket-get-ifindex
  "Get interface index from sk_buff.

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (tc/tc-get-ifindex ctx-reg dst-reg))

;; ============================================================================
;; Socket Filter Return Patterns
;; ============================================================================

(defn socket-accept
  "Generate instructions to accept packet (return packet length).

   Parameters:
   - ctx-reg: Register containing __sk_buff pointer

   Returns vector of instructions that returns the packet length."
  [ctx-reg]
  [(socket-get-len ctx-reg :r0)
   (dsl/exit-insn)])

(defn socket-accept-bytes
  "Generate instructions to accept specific number of bytes.

   Parameters:
   - num-bytes: Number of bytes to accept

   Returns vector of instructions."
  [num-bytes]
  [(dsl/mov :r0 num-bytes)
   (dsl/exit-insn)])

(defn socket-reject
  "Generate instructions to reject/drop packet.

   Returns vector of instructions."
  []
  [(dsl/mov :r0 0)
   (dsl/exit-insn)])

;; ============================================================================
;; Socket Filter Builders
;; ============================================================================

(defn build-socket-filter
  "Build a complete socket filter program.

   Parameters:
   - opts: Map with:
     :ctx-reg - Register to save __sk_buff pointer (optional)
     :data-reg - Register for data pointer (default :r2)
     :data-end-reg - Register for data_end (default :r3)
     :body - Vector of body instructions
     :default-action - :accept or :reject (default :accept)

   Returns assembled program bytes."
  [{:keys [ctx-reg data-reg data-end-reg body default-action]
    :or {data-reg :r2 data-end-reg :r3 default-action :accept}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue
         (socket-prologue ctx-reg data-reg data-end-reg)
         ;; Body
         body
         ;; Default action
         (if (= default-action :accept)
           ;; Accept: return packet length
           [(tc/tc-get-len (or ctx-reg :r1) :r0)
            (dsl/exit-insn)]
           ;; Reject: return 0
           [(dsl/mov :r0 0)
            (dsl/exit-insn)])))))

(defmacro defsocket-filter-instructions
  "Define a socket filter program as a function returning instructions.

   Parameters:
   - fn-name: Name for the defined function
   - options: Map with:
     :ctx-reg - Register to save context (optional)
     :data-reg - Register for data pointer (default :r2)
     :data-end-reg - Register for data_end (default :r3)
     :default-action - :accept or :reject (default :accept)
   - body: Body expressions (should return vectors of instructions)

   Example:
     (defsocket-filter-instructions accept-all
       {:default-action :accept}
       [])"
  [fn-name options & body]
  (let [ctx-reg (:ctx-reg options)
        data-reg (or (:data-reg options) :r2)
        data-end-reg (or (:data-end-reg options) :r3)
        default-action (or (:default-action options) :accept)]
    `(defn ~fn-name
       ~(str "Socket filter program.\n"
             "Default action: " default-action)
       []
       (vec (concat
             (socket-prologue ~ctx-reg ~data-reg ~data-end-reg)
             ~@body
             ~(if (= default-action :accept)
                `[(tc/tc-get-len ~(or ctx-reg :r1) :r0)
                  (dsl/exit-insn)]
                `[(dsl/mov :r0 0)
                  (dsl/exit-insn)]))))))

;; ============================================================================
;; Common Socket Filter Patterns
;; ============================================================================

(defn socket-filter-by-port
  "Generate filter to match TCP/UDP port.

   Parameters:
   - data-reg: Register with data pointer
   - data-end-reg: Register with data_end pointer
   - ip-offset: IP header offset (usually ethernet-header-size)
   - port: Port number to match (host byte order)
   - src-or-dst: :src or :dst
   - accept-on-match: Accept if port matches (true) or reject (false)

   Returns vector of instructions.

   Note: This assumes TCP/UDP header follows IP header directly.
   For variable-length IP headers, calculate IHL first."
  [data-reg data-end-reg ip-offset port src-or-dst accept-on-match]
  (let [;; Assume minimum IP header (20 bytes) for simplicity
        transport-offset (+ ip-offset 20)
        port-offset (case src-or-dst
                     :src 0   ; Source port at offset 0
                     :dst 2)] ; Dest port at offset 2
    (vec (concat
          ;; Bounds check for transport header
          (socket-bounds-check data-reg data-end-reg transport-offset 4 "reject")
          ;; Load port (network byte order)
          [(dsl/ldx :h :r0 data-reg (+ transport-offset port-offset))]
          ;; Compare (need to convert port to network byte order)
          (let [port-be (bit-or (bit-shift-left (bit-and port 0xFF) 8)
                               (bit-and (bit-shift-right port 8) 0xFF))]
            [(dsl/jmp-imm (if accept-on-match :jeq :jne) :r0 port-be 2)
             (dsl/mov :r0 0)  ; Reject/Accept depending on match
             (dsl/exit-insn)])))))

(defn socket-filter-by-protocol
  "Generate filter to match IP protocol.

   Parameters:
   - data-reg: Register with data pointer
   - data-end-reg: Register with data_end pointer
   - protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP)
   - accept-on-match: Accept if protocol matches (true) or reject (false)

   Returns vector of instructions."
  [data-reg data-end-reg protocol accept-on-match]
  (let [ip-offset ethernet-header-size
        proto-offset (+ ip-offset 9)]  ; Protocol field at offset 9 in IP header
    (vec (concat
          ;; Bounds check for protocol field
          (socket-bounds-check data-reg data-end-reg ip-offset 10 "reject")
          ;; Load protocol
          [(dsl/ldx :b :r0 data-reg proto-offset)]
          ;; Compare
          [(dsl/jmp-imm (if accept-on-match :jeq :jne) :r0 protocol 2)
           (dsl/mov :r0 0)
           (dsl/exit-insn)]))))

;; ============================================================================
;; Section Names and Metadata
;; ============================================================================

(defn socket-filter-section-name
  "Generate ELF section name for socket filter.

   Returns \"socket\" or \"socket/<name>\"."
  ([]
   "socket")
  ([name]
   (str "socket/" name)))

(defn make-socket-filter-info
  "Create program metadata for a socket filter.

   Parameters:
   - program-name: Name for the BPF program
   - instructions: Program instructions

   Returns map with program metadata."
  [program-name instructions]
  {:name program-name
   :section (socket-filter-section-name program-name)
   :type :socket-filter
   :instructions instructions})

;; ============================================================================
;; IP Address Helpers
;; ============================================================================

(def ipv4-to-int tc/ipv4-to-int)

(defn socket-filter-by-ip
  "Generate filter to match source or destination IP.

   Parameters:
   - data-reg: Register with data pointer
   - data-end-reg: Register with data_end pointer
   - ip-addr: IP address as integer
   - src-or-dst: :src or :dst
   - accept-on-match: Accept if IP matches

   Returns vector of instructions."
  [data-reg data-end-reg ip-addr src-or-dst accept-on-match]
  (let [ip-offset ethernet-header-size
        addr-offset (case src-or-dst
                     :src (+ ip-offset 12)   ; Source IP at offset 12
                     :dst (+ ip-offset 16))] ; Dest IP at offset 16
    (vec (concat
          ;; Bounds check
          (socket-bounds-check data-reg data-end-reg ip-offset 20 "reject")
          ;; Load IP address
          [(dsl/ldx :w :r0 data-reg addr-offset)]
          ;; Compare
          [(dsl/jmp-imm (if accept-on-match :jeq :jne) :r0 ip-addr 2)
           (dsl/mov :r0 0)
           (dsl/exit-insn)]))))

;; ============================================================================
;; SK_SKB Program Support (SOCKMAP/SOCKHASH Stream Redirection)
;; ============================================================================

;; SK_SKB programs use __sk_buff context (same as socket filter and TC)
;; They're attached to SOCKMAP/SOCKHASH for stream parsing and verdict

(def sk-skb-verdict
  "SK_SKB verdict return values."
  {:drop    0   ; SK_DROP - Drop the data
   :pass    1   ; SK_PASS - Pass to socket
   :redirect 2}) ; SK_REDIRECT (not actually used - redirect happens via helper)

(defn sk-skb-action
  "Get SK_SKB action value."
  [action]
  (or (get sk-skb-verdict action)
      (throw (ex-info "Unknown SK_SKB action" {:action action}))))

(defn sk-skb-prologue
  "Generate SK_SKB program prologue.

   SK_SKB programs receive __sk_buff as context, same as socket filters.

   Parameters:
   - ctx-reg: Register to save context pointer (optional)
   - data-reg: Register for data pointer
   - data-end-reg: Register for data_end pointer

   Returns vector of instructions."
  ([data-reg data-end-reg]
   (sk-skb-prologue nil data-reg data-end-reg))
  ([ctx-reg data-reg data-end-reg]
   ;; Same as socket filter / TC prologue
   (socket-prologue ctx-reg data-reg data-end-reg)))

(defn sk-redirect-map
  "Generate instructions for bpf_sk_redirect_map helper (SK_SKB).

   Redirects stream data to a socket in SOCKMAP.

   Parameters:
   - map-fd: SOCKMAP file descriptor
   - key: Key or register containing key
   - flags: Flags value (usually 0)

   Returns vector of instruction bytes.

   Usage in SK_SKB verdict program:
     (sk-redirect-map sockmap-fd 0 0)
     (dsl/exit-insn)"
  [map-fd key flags]
  (let [map-insns (dsl/ld-map-fd :r1 map-fd)
        key-insns (if (keyword? key)
                    [(dsl/mov-reg :r2 key)]
                    [(dsl/mov :r2 key)])
        flags-insns [(dsl/mov :r3 flags)]
        call-insns [(dsl/call 52)]]  ; bpf_sk_redirect_map
    (vec (concat [map-insns] key-insns flags-insns call-insns))))

(defn sk-redirect-hash
  "Generate instructions for bpf_sk_redirect_hash helper (SK_SKB).

   Redirects stream data to a socket in SOCKHASH.

   Parameters:
   - map-fd: SOCKHASH file descriptor
   - key-ptr-reg: Register containing pointer to key
   - flags: Flags value (usually 0)

   Returns vector of instruction bytes."
  [map-fd key-ptr-reg flags]
  (let [map-insns (dsl/ld-map-fd :r1 map-fd)
        key-insns [(dsl/mov-reg :r2 key-ptr-reg)]
        flags-insns [(dsl/mov :r3 flags)]
        call-insns [(dsl/call 72)]]  ; bpf_sk_redirect_hash
    (vec (concat [map-insns] key-insns flags-insns call-insns))))

(defn sock-map-update
  "Generate instructions for bpf_sock_map_update helper.

   Updates SOCKMAP with current socket. Used in sockops or cgroup programs
   to add sockets to the map.

   Parameters:
   - map-fd: SOCKMAP file descriptor
   - key: Key or register containing key
   - flags: Update flags (usually BPF_ANY = 0)

   Returns vector of instruction bytes."
  [map-fd key flags]
  (let [;; r1 = map ptr, r2 = sk (from context), r3 = key, r4 = flags
        map-insns (dsl/ld-map-fd :r2 map-fd)
        key-insns (if (keyword? key)
                    [(dsl/mov-reg :r3 key)]
                    [(dsl/mov :r3 key)])
        flags-insns [(dsl/mov :r4 flags)]
        call-insns [(dsl/call 53)]]  ; bpf_sock_map_update
    (vec (concat [map-insns] key-insns flags-insns call-insns))))

(defn sock-hash-update
  "Generate instructions for bpf_sock_hash_update helper.

   Updates SOCKHASH with current socket.

   Parameters:
   - map-fd: SOCKHASH file descriptor
   - key-ptr-reg: Register containing pointer to key
   - flags: Update flags (usually BPF_ANY = 0)

   Returns vector of instruction bytes."
  [map-fd key-ptr-reg flags]
  (let [map-insns (dsl/ld-map-fd :r2 map-fd)
        key-insns [(dsl/mov-reg :r3 key-ptr-reg)]
        flags-insns [(dsl/mov :r4 flags)]
        call-insns [(dsl/call 70)]]  ; bpf_sock_hash_update
    (vec (concat [map-insns] key-insns flags-insns call-insns))))

;; ============================================================================
;; SK_MSG Program Support (SOCKMAP/SOCKHASH Message Redirection)
;; ============================================================================

;; SK_MSG programs use sk_msg_md context for sendmsg/sendfile operations

(def sk-msg-offsets
  "Offsets in sk_msg_md context structure."
  {:data            0     ; Pointer to message data start
   :data-end        8     ; Pointer to message data end
   :family          16    ; Socket family (AF_INET, AF_INET6, etc)
   :remote-ip4      20    ; Remote IPv4 address
   :local-ip4       24    ; Local IPv4 address
   :remote-ip6      28    ; Remote IPv6 address (16 bytes)
   :local-ip6       44    ; Local IPv6 address (16 bytes)
   :remote-port     60    ; Remote port
   :local-port      64    ; Local port
   :size            68    ; Total message size
   :sk              72})  ; Socket pointer (for helpers)

(defn sk-msg-offset
  "Get offset for sk_msg_md field."
  [field]
  (or (get sk-msg-offsets field)
      (throw (ex-info "Unknown sk_msg_md field" {:field field}))))

(def sk-msg-verdict
  "SK_MSG verdict return values."
  {:drop    0   ; SK_DROP - Drop message
   :pass    1}) ; SK_PASS - Pass message

(defn sk-msg-action
  "Get SK_MSG action value."
  [action]
  (or (get sk-msg-verdict action)
      (throw (ex-info "Unknown SK_MSG action" {:action action}))))

(defn sk-msg-prologue
  "Generate SK_MSG program prologue.

   SK_MSG programs receive sk_msg_md as context.

   Parameters:
   - ctx-reg: Register to save context pointer (required for SK_MSG)
   - data-reg: Register for data pointer
   - data-end-reg: Register for data_end pointer

   Returns vector of instructions."
  [ctx-reg data-reg data-end-reg]
  [(dsl/mov-reg ctx-reg :r1)  ; Save context pointer
   (dsl/ldx :dw data-reg ctx-reg (sk-msg-offset :data))
   (dsl/ldx :dw data-end-reg ctx-reg (sk-msg-offset :data-end))])

(defn sk-msg-load-field
  "Load a field from sk_msg_md context.

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register
   - field: Field keyword from sk-msg-offsets

   Returns ldx instruction."
  [ctx-reg dst-reg field]
  (let [offset (sk-msg-offset field)
        size (cond
               (#{:data :data-end :sk} field) :dw      ; 64-bit pointers
               (#{:remote-ip6 :local-ip6} field) :dw   ; Read first 8 bytes
               :else :w)]                               ; 32-bit values
    (dsl/ldx size dst-reg ctx-reg offset)))

(defn msg-redirect-map
  "Generate instructions for bpf_msg_redirect_map helper (SK_MSG).

   Redirects message to a socket in SOCKMAP.

   Parameters:
   - ctx-reg: Register containing sk_msg_md pointer
   - map-fd: SOCKMAP file descriptor
   - key: Key or register containing key
   - flags: Flags value (usually 0)

   Returns vector of instruction bytes.

   Usage in SK_MSG verdict program:
     (msg-redirect-map :r6 sockmap-fd 0 0)
     (dsl/exit-insn)"
  [ctx-reg map-fd key flags]
  (let [ctx-insns [(dsl/mov-reg :r1 ctx-reg)]
        map-insns (dsl/ld-map-fd :r2 map-fd)
        key-insns (if (keyword? key)
                    [(dsl/mov-reg :r3 key)]
                    [(dsl/mov :r3 key)])
        flags-insns [(dsl/mov :r4 flags)]
        call-insns [(dsl/call 60)]]  ; bpf_msg_redirect_map
    (vec (concat ctx-insns [map-insns] key-insns flags-insns call-insns))))

(defn msg-redirect-hash
  "Generate instructions for bpf_msg_redirect_hash helper (SK_MSG).

   Redirects message to a socket in SOCKHASH.

   Parameters:
   - ctx-reg: Register containing sk_msg_md pointer
   - map-fd: SOCKHASH file descriptor
   - key-ptr-reg: Register containing pointer to key
   - flags: Flags value (usually 0)

   Returns vector of instruction bytes."
  [ctx-reg map-fd key-ptr-reg flags]
  (let [ctx-insns [(dsl/mov-reg :r1 ctx-reg)]
        map-insns (dsl/ld-map-fd :r2 map-fd)
        key-insns [(dsl/mov-reg :r3 key-ptr-reg)]
        flags-insns [(dsl/mov :r4 flags)]
        call-insns [(dsl/call 71)]]  ; bpf_msg_redirect_hash
    (vec (concat ctx-insns [map-insns] key-insns flags-insns call-insns))))

;; ============================================================================
;; SK_SKB and SK_MSG Return Patterns
;; ============================================================================

(defn sk-skb-pass
  "Generate instructions to pass data to socket (SK_PASS).

   Returns vector of instructions."
  []
  [(dsl/mov :r0 1)  ; SK_PASS
   (dsl/exit-insn)])

(defn sk-skb-drop
  "Generate instructions to drop data (SK_DROP).

   Returns vector of instructions."
  []
  [(dsl/mov :r0 0)  ; SK_DROP
   (dsl/exit-insn)])

(defn sk-msg-pass
  "Generate instructions to pass message (SK_PASS).

   Returns vector of instructions."
  []
  [(dsl/mov :r0 1)  ; SK_PASS
   (dsl/exit-insn)])

(defn sk-msg-drop
  "Generate instructions to drop message (SK_DROP).

   Returns vector of instructions."
  []
  [(dsl/mov :r0 0)  ; SK_DROP
   (dsl/exit-insn)])

;; ============================================================================
;; Convenience Redirect-and-Return Patterns
;; ============================================================================

(defn sk-redirect-map-with-fallback
  "Generate SK_SKB redirect with fallback to pass.

   Redirects to SOCKMAP, falls back to SK_PASS if redirect fails.

   Parameters:
   - map-fd: SOCKMAP file descriptor
   - key: Key value or register

   Returns vector of instruction bytes."
  [map-fd key]
  (vec (concat
        (sk-redirect-map map-fd key 0)
        ;; bpf_sk_redirect_map returns SK_PASS on success, SK_DROP on failure
        ;; We just return whatever the helper returned
        [(dsl/exit-insn)])))

(defn msg-redirect-map-with-fallback
  "Generate SK_MSG redirect with fallback to pass.

   Parameters:
   - ctx-reg: Register containing context pointer
   - map-fd: SOCKMAP file descriptor
   - key: Key value or register

   Returns vector of instruction bytes."
  [ctx-reg map-fd key]
  (vec (concat
        (msg-redirect-map ctx-reg map-fd key 0)
        [(dsl/exit-insn)])))

;; ============================================================================
;; Section Names for SK_SKB and SK_MSG
;; ============================================================================

(defn sk-skb-section-name
  "Generate ELF section name for SK_SKB program.

   Parameters:
   - type: :parser or :verdict
   - name: Optional program name"
  ([type]
   (case type
     :parser "sk_skb/stream_parser"
     :verdict "sk_skb/stream_verdict"))
  ([type name]
   (str (sk-skb-section-name type) "/" name)))

(defn sk-msg-section-name
  "Generate ELF section name for SK_MSG program."
  ([]
   "sk_msg")
  ([name]
   (str "sk_msg/" name)))
