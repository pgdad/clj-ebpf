(ns clj-ebpf.dsl.sk-lookup
  "High-level SK_LOOKUP DSL for BPF programs.

   SK_LOOKUP programs enable programmable socket lookup. When the kernel
   needs to find a socket for an incoming packet (e.g., TCP SYN or UDP),
   it typically searches listening sockets by IP/Port. SK_LOOKUP programs
   run before this search and can select a specific socket to receive the
   packet, bypassing standard bind rules.

   Use cases:
   - Bind multiple services to the same IP:port on different addresses
   - Implement custom load balancing logic
   - Service mesh socket steering
   - Multi-tenant socket dispatch

   Context: struct bpf_sk_lookup
   Return values:
   - SK_PASS (1): Continue with normal socket lookup
   - SK_DROP (0): Drop the packet

   The key helper is bpf_sk_assign which assigns a socket to handle
   the incoming connection.

   Example:
     (defprogram my-sk-lookup
       :type :sk-lookup
       :license \"GPL\"
       :body (concat
               (sk-lookup-prologue :r6)
               ;; Check local port
               [(sk-lookup-load-field :r6 :r7 :local-port)]
               ;; If port 8080, assign to our socket
               [(dsl/jmp-imm :jne :r7 8080 5)]
               ;; ... load socket and assign ...
               (sk-lookup-pass)))"
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; SK_LOOKUP Return Values
;; ============================================================================

(def sk-lookup-verdict
  "SK_LOOKUP verdict return values."
  {:drop 0     ; SK_DROP - Drop the packet
   :pass 1})   ; SK_PASS - Continue with normal lookup (or use assigned socket)

(defn sk-lookup-action
  "Get SK_LOOKUP action value.

   Parameters:
   - action: :drop (0) or :pass (1)

   Returns integer value."
  [action]
  (or (get sk-lookup-verdict action)
      (throw (ex-info "Unknown SK_LOOKUP action" {:action action}))))

;; ============================================================================
;; bpf_sk_lookup Context Structure
;; ============================================================================
;;
;; From linux/bpf.h - struct bpf_sk_lookup:
;;
;; struct bpf_sk_lookup {
;;     union {
;;         __bpf_md_ptr(struct bpf_sock *, sk);  /* Selected socket */
;;         __u64 :64;
;;     };
;;     __u32 family;         /* Protocol family (AF_INET, AF_INET6) */
;;     __u32 protocol;       /* IP protocol (IPPROTO_TCP, IPPROTO_UDP) */
;;     __u32 remote_ip4;     /* Network byte order */
;;     __u32 remote_ip6[4];  /* Network byte order */
;;     __be16 remote_port;   /* Network byte order */
;;     __u16 :16;            /* Padding */
;;     __u32 local_ip4;      /* Network byte order */
;;     __u32 local_ip6[4];   /* Network byte order */
;;     __u32 local_port;     /* Host byte order */
;;     __u32 ingress_ifindex; /* Ingress interface */
;; };

(def sk-lookup-offsets
  "Offsets in bpf_sk_lookup context structure.

   Note: All IP addresses and remote_port are in network byte order.
   local_port is in host byte order."
  {:sk              0      ; Selected socket pointer (8 bytes on 64-bit)
   :family          8      ; Protocol family (AF_INET=2, AF_INET6=10)
   :protocol        12     ; IP protocol (TCP=6, UDP=17)
   :remote-ip4      16     ; Remote IPv4 address
   :remote-ip6      20     ; Remote IPv6 address (16 bytes, offsets 20-35)
   :remote-port     36     ; Remote port (network byte order)
   ;; 2 bytes padding at offset 38
   :local-ip4       40     ; Local IPv4 address
   :local-ip6       44     ; Local IPv6 address (16 bytes, offsets 44-59)
   :local-port      60     ; Local port (host byte order)
   :ingress-ifindex 64})   ; Ingress interface index

(defn sk-lookup-offset
  "Get offset for bpf_sk_lookup field.

   Parameters:
   - field: Field keyword from sk-lookup-offsets

   Returns integer offset."
  [field]
  (or (get sk-lookup-offsets field)
      (throw (ex-info "Unknown bpf_sk_lookup field" {:field field}))))

;; ============================================================================
;; Protocol Constants
;; ============================================================================

(def address-families
  "Address family constants."
  {:af-inet  2     ; IPv4
   :af-inet6 10})  ; IPv6

(def ip-protocols
  "IP protocol constants."
  {:tcp 6
   :udp 17})

;; ============================================================================
;; SK_LOOKUP Prologue
;; ============================================================================

(defn sk-lookup-prologue
  "Generate SK_LOOKUP program prologue.

   Saves the context pointer for later use.

   Parameters:
   - ctx-save-reg: Register to save bpf_sk_lookup pointer

   Returns vector of instructions."
  [ctx-save-reg]
  [(dsl/mov-reg ctx-save-reg :r1)])

;; ============================================================================
;; Context Field Access
;; ============================================================================

(defn sk-lookup-load-field
  "Load a field from bpf_sk_lookup context.

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register
   - field: Field keyword from sk-lookup-offsets

   Returns ldx instruction or vector of instructions."
  [ctx-reg dst-reg field]
  (let [offset (sk-lookup-offset field)
        ;; Determine size based on field
        size (cond
               (= field :sk) :dw           ; 64-bit pointer
               (#{:remote-port} field) :h  ; 16-bit
               :else :w)]                  ; 32-bit
    (dsl/ldx size dst-reg ctx-reg offset)))

(defn sk-lookup-get-family
  "Load protocol family from context.

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (sk-lookup-load-field ctx-reg dst-reg :family))

(defn sk-lookup-get-protocol
  "Load IP protocol from context.

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (sk-lookup-load-field ctx-reg dst-reg :protocol))

(defn sk-lookup-get-local-port
  "Load local port from context (host byte order).

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (sk-lookup-load-field ctx-reg dst-reg :local-port))

(defn sk-lookup-get-remote-port
  "Load remote port from context (network byte order).

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (sk-lookup-load-field ctx-reg dst-reg :remote-port))

(defn sk-lookup-get-local-ip4
  "Load local IPv4 address from context (network byte order).

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (sk-lookup-load-field ctx-reg dst-reg :local-ip4))

(defn sk-lookup-get-remote-ip4
  "Load remote IPv4 address from context (network byte order).

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (sk-lookup-load-field ctx-reg dst-reg :remote-ip4))

(defn sk-lookup-get-ifindex
  "Load ingress interface index from context.

   Parameters:
   - ctx-reg: Register containing context pointer
   - dst-reg: Destination register

   Returns ldx instruction."
  [ctx-reg dst-reg]
  (sk-lookup-load-field ctx-reg dst-reg :ingress-ifindex))

;; ============================================================================
;; Helper Functions
;; ============================================================================

(defn sk-assign
  "Generate instructions for bpf_sk_assign helper.

   Assigns a socket to handle the incoming connection.
   The socket must be a listening socket obtained via bpf_sk_lookup_tcp
   or bpf_sk_lookup_udp, or from a SOCKMAP/SOCKHASH.

   Parameters:
   - ctx-reg: Register containing bpf_sk_lookup context
   - sk-reg: Register containing socket pointer
   - flags: Flags (usually 0)

   Helper signature:
     long bpf_sk_assign(struct bpf_sk_lookup *ctx,
                        struct bpf_sock *sk, u64 flags)

   Returns:
     0 on success, negative error on failure

   Returns vector of instruction bytes."
  [ctx-reg sk-reg flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov-reg :r2 sk-reg)
   (dsl/mov :r3 flags)
   (dsl/call 124)])  ; bpf_sk_assign

(defn sk-lookup-tcp
  "Generate instructions for bpf_sk_lookup_tcp helper.

   Looks up a TCP socket by 4-tuple. Returns socket pointer or NULL.
   The returned socket must be released with bpf_sk_release.

   Parameters:
   - ctx-reg: Register containing context pointer
   - tuple-ptr-reg: Register containing pointer to bpf_sock_tuple
   - tuple-size: Size of the tuple structure
   - netns: Network namespace (0 for current, or netns cookie)
   - flags: Lookup flags

   Returns vector of instruction bytes."
  [ctx-reg tuple-ptr-reg tuple-size netns flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov-reg :r2 tuple-ptr-reg)
   (dsl/mov :r3 tuple-size)
   (dsl/mov :r4 netns)
   (dsl/mov :r5 flags)
   (dsl/call 84)])  ; bpf_sk_lookup_tcp

(defn sk-lookup-udp
  "Generate instructions for bpf_sk_lookup_udp helper.

   Looks up a UDP socket by 4-tuple. Returns socket pointer or NULL.
   The returned socket must be released with bpf_sk_release.

   Parameters:
   - ctx-reg: Register containing context pointer
   - tuple-ptr-reg: Register containing pointer to bpf_sock_tuple
   - tuple-size: Size of the tuple structure
   - netns: Network namespace (0 for current, or netns cookie)
   - flags: Lookup flags

   Returns vector of instruction bytes."
  [ctx-reg tuple-ptr-reg tuple-size netns flags]
  [(dsl/mov-reg :r1 ctx-reg)
   (dsl/mov-reg :r2 tuple-ptr-reg)
   (dsl/mov :r3 tuple-size)
   (dsl/mov :r4 netns)
   (dsl/mov :r5 flags)
   (dsl/call 85)])  ; bpf_sk_lookup_udp

(defn sk-release
  "Generate instructions for bpf_sk_release helper.

   Releases a socket reference obtained from bpf_sk_lookup_tcp/udp.
   Must be called for every socket obtained from lookup helpers.

   Parameters:
   - sk-reg: Register containing socket pointer

   Returns vector of instruction bytes."
  [sk-reg]
  [(dsl/mov-reg :r1 sk-reg)
   (dsl/call 86)])  ; bpf_sk_release

;; ============================================================================
;; SK_LOOKUP Return Patterns
;; ============================================================================

(defn sk-lookup-pass
  "Generate instructions to pass (continue with normal/assigned socket).

   Returns SK_PASS (1).

   Returns vector of instructions."
  []
  [(dsl/mov :r0 1)  ; SK_PASS
   (dsl/exit-insn)])

(defn sk-lookup-drop
  "Generate instructions to drop the packet.

   Returns SK_DROP (0).

   Returns vector of instructions."
  []
  [(dsl/mov :r0 0)  ; SK_DROP
   (dsl/exit-insn)])

;; ============================================================================
;; Common SK_LOOKUP Patterns
;; ============================================================================

(defn sk-lookup-check-port
  "Generate instructions to check local port and branch.

   Parameters:
   - ctx-reg: Register containing context pointer
   - tmp-reg: Temporary register for port value
   - port: Port number to match (host byte order)
   - skip-count: Number of instructions to skip if port matches

   Returns vector of instructions."
  [ctx-reg tmp-reg port skip-count]
  [(sk-lookup-get-local-port ctx-reg tmp-reg)
   (dsl/jmp-imm :jeq tmp-reg port skip-count)])

(defn sk-lookup-check-protocol
  "Generate instructions to check IP protocol and branch.

   Parameters:
   - ctx-reg: Register containing context pointer
   - tmp-reg: Temporary register for protocol value
   - protocol: :tcp or :udp (or raw protocol number)
   - skip-count: Number of instructions to skip if protocol matches

   Returns vector of instructions."
  [ctx-reg tmp-reg protocol skip-count]
  (let [proto-num (if (keyword? protocol)
                    (get ip-protocols protocol)
                    protocol)]
    [(sk-lookup-get-protocol ctx-reg tmp-reg)
     (dsl/jmp-imm :jeq tmp-reg proto-num skip-count)]))

(defn sk-lookup-assign-and-pass
  "Generate instructions to assign socket and return SK_PASS.

   Common pattern for SK_LOOKUP programs that select a socket.

   Parameters:
   - ctx-reg: Register containing context pointer
   - sk-reg: Register containing socket pointer

   Returns vector of instructions."
  [ctx-reg sk-reg]
  (vec (concat
        (sk-assign ctx-reg sk-reg 0)
        ;; Check if assignment succeeded (r0 == 0)
        [(dsl/jmp-imm :jne :r0 0 2)]
        ;; Success - return SK_PASS
        [(dsl/mov :r0 1)
         (dsl/exit-insn)]
        ;; Failure - still return SK_PASS to let kernel do normal lookup
        [(dsl/mov :r0 1)
         (dsl/exit-insn)])))

;; ============================================================================
;; Socket Lookup with SOCKMAP
;; ============================================================================

(defn sk-lookup-from-sockmap
  "Generate instructions to lookup socket from SOCKMAP by key.

   Uses bpf_map_lookup_elem to get socket from SOCKMAP.

   Parameters:
   - map-fd: SOCKMAP file descriptor
   - key-reg: Register containing key (or will hold key after stack store)
   - result-reg: Register for result socket pointer

   Note: This is a simplified pattern. For real use, you need to
   store the key on stack and pass a pointer to map_lookup_elem.

   Returns vector of instruction bytes."
  [map-fd key-reg result-reg]
  ;; This is a conceptual helper - actual implementation requires
  ;; stack manipulation for the key pointer
  (vec (concat
        (dsl/ld-map-fd :r1 map-fd)
        ;; r2 should point to key on stack
        ;; For now, assume key-reg contains the key value
        ;; Real implementation would need: stx key to stack, lea r2 to stack
        [(dsl/mov-reg :r2 key-reg)
         (dsl/call 1)]  ; bpf_map_lookup_elem
        ;; Result in r0, move to result-reg if different
        (when (not= result-reg :r0)
          [(dsl/mov-reg result-reg :r0)]))))

;; ============================================================================
;; Program Builders
;; ============================================================================

(defn build-sk-lookup-program
  "Build a complete SK_LOOKUP program.

   Parameters:
   - opts: Map with:
     :ctx-reg - Register to save context (default :r6)
     :body - Vector of body instructions
     :default-action - :pass or :drop (default :pass)

   Returns assembled program bytes."
  [{:keys [ctx-reg body default-action]
    :or {ctx-reg :r6 default-action :pass}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue
         (sk-lookup-prologue ctx-reg)
         ;; Body
         body
         ;; Default action
         (if (= default-action :pass)
           (sk-lookup-pass)
           (sk-lookup-drop))))))

;; ============================================================================
;; Section Names and Metadata
;; ============================================================================

(defn sk-lookup-section-name
  "Generate ELF section name for SK_LOOKUP program.

   Returns \"sk_lookup\" or \"sk_lookup/<name>\"."
  ([]
   "sk_lookup")
  ([name]
   (str "sk_lookup/" name)))

(defn make-sk-lookup-info
  "Create program metadata for an SK_LOOKUP program.

   Parameters:
   - program-name: Name for the BPF program
   - instructions: Program instructions

   Returns map with program metadata."
  [program-name instructions]
  {:name program-name
   :section (sk-lookup-section-name program-name)
   :type :sk-lookup
   :instructions instructions})

;; ============================================================================
;; Byte Order Utilities
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
  (htons value))  ; Same operation for x86 (little-endian)

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
  (htonl value))  ; Same operation for x86 (little-endian)

(defn ipv4-to-int
  "Convert IPv4 address string to integer.

   Parameters:
   - ip-str: IPv4 address string (e.g., \"192.168.1.1\")

   Returns integer representation."
  [ip-str]
  (let [parts (clojure.string/split ip-str #"\.")
        bytes (map #(Integer/parseInt %) parts)]
    (reduce (fn [acc b] (bit-or (bit-shift-left acc 8) b)) 0 bytes)))
