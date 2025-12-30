(ns clj-ebpf.ctx
  "BPF context structure field offsets.

   This namespace provides pre-defined offsets for common BPF context
   structures, eliminating the need to manually look up kernel headers.

   IMPORTANT NOTES:

   1. **Byte Order**: Some fields are in NETWORK byte order (big-endian),
      while others are in HOST byte order (native). This is documented
      for each field that requires attention.

   2. **Architecture**: These offsets assume 64-bit systems where
      `__bpf_md_ptr` expands to 8 bytes.

   3. **Kernel Version**: Based on Linux 6.x kernel structures. While
      kernel developers try to maintain ABI stability, always verify
      against your target kernel version.

   Structures included:
   - `bpf-sock-ops` - bpf_sock_ops for SOCK_OPS programs
   - `bpf-sock` - bpf_sock for socket programs
   - `sk-msg` - sk_msg_md for SK_MSG programs (from socket.clj)
   - `sk-buff` - __sk_buff for TC/socket filter programs (from tc.clj)
   - `xdp-md` - xdp_md for XDP programs (from xdp.clj)
   - `bpf-sk-lookup` - bpf_sk_lookup for SK_LOOKUP programs

   Usage:
     (require '[clj-ebpf.ctx :as ctx])
     (dsl/ldx :w :r2 :r1 (:local-port ctx/bpf-sock-ops))  ; Load local port

   See also:
   - clj-ebpf.dsl.tc for __sk_buff access functions
   - clj-ebpf.dsl.xdp for xdp_md access functions
   - clj-ebpf.dsl.socket for sk_msg_md access functions"
  (:require [clj-ebpf.dsl.tc :as tc]
            [clj-ebpf.dsl.xdp :as xdp]
            [clj-ebpf.dsl.socket :as socket]
            [clj-ebpf.dsl.sk-lookup :as sk-lookup]))

;; ============================================================================
;; bpf_sock_ops - Socket Operations Context
;; ============================================================================
;;
;; Used by SOCK_OPS programs (BPF_PROG_TYPE_SOCK_OPS) for socket-level
;; operations like connection establishment, data transfer, etc.
;;
;; struct bpf_sock_ops {
;;     __u32 op;                    // offset 0
;;     union {                      // offset 4
;;         __u32 args[4];
;;         __u32 reply;
;;         __u32 replylong[4];
;;     };                           // 16 bytes
;;     __u32 family;                // offset 20
;;     __u32 remote_ip4;            // offset 24 (network byte order)
;;     __u32 local_ip4;             // offset 28 (network byte order)
;;     __u32 remote_ip6[4];         // offset 32 (network byte order)
;;     __u32 local_ip6[4];          // offset 48 (network byte order)
;;     __u32 remote_port;           // offset 64 (network byte order)
;;     __u32 local_port;            // offset 68 (HOST byte order!)
;;     __u32 is_fullsock;           // offset 72
;;     __u32 snd_cwnd;              // offset 76
;;     __u32 srtt_us;               // offset 80
;;     __u32 bpf_sock_ops_cb_flags; // offset 84
;;     __u32 state;                 // offset 88
;;     __u32 rtt_min;               // offset 92
;;     __u32 snd_ssthresh;          // offset 96
;;     __u32 rcv_nxt;               // offset 100
;;     __u32 snd_nxt;               // offset 104
;;     __u32 snd_una;               // offset 108
;;     __u32 mss_cache;             // offset 112
;;     __u32 ecn_flags;             // offset 116
;;     __u32 rate_delivered;        // offset 120
;;     __u32 rate_interval_us;      // offset 124
;;     __u32 packets_out;           // offset 128
;;     __u32 retrans_out;           // offset 132
;;     __u32 total_retrans;         // offset 136
;;     __u32 segs_in;               // offset 140
;;     __u32 data_segs_in;          // offset 144
;;     __u32 segs_out;              // offset 148
;;     __u32 data_segs_out;         // offset 152
;;     __u32 lost_out;              // offset 156
;;     __u32 sacked_out;            // offset 160
;;     __u32 sk_txhash;             // offset 164
;;     __u64 bytes_received;        // offset 168
;;     __u64 bytes_acked;           // offset 176
;;     __bpf_md_ptr(struct bpf_sock *, sk);  // offset 184
;;     ...
;; };

(def bpf-sock-ops
  "bpf_sock_ops structure field offsets for SOCK_OPS programs.

   BYTE ORDER NOTES:
   - remote_ip4, local_ip4, remote_ip6, local_ip6: NETWORK byte order
   - remote_port: NETWORK byte order
   - local_port: HOST byte order (!)

   Usage:
     ;; Load operation code
     (dsl/ldx :w :r2 :r1 (:op ctx/bpf-sock-ops))

     ;; Load local port (host byte order - no conversion needed)
     (dsl/ldx :w :r2 :r1 (:local-port ctx/bpf-sock-ops))

     ;; Load remote port (network byte order - may need ntohs)
     (dsl/ldx :w :r2 :r1 (:remote-port ctx/bpf-sock-ops))"
  {:op                  0    ; Operation code (BPF_SOCK_OPS_*)
   :args                4    ; Union: args[4], reply, replylong[4]
   :reply               4    ; Same as args (union)
   :replylong           4    ; Same as args (union)
   :family              20   ; Address family (AF_INET, AF_INET6)
   :remote-ip4          24   ; Remote IPv4 (NETWORK byte order)
   :local-ip4           28   ; Local IPv4 (NETWORK byte order)
   :remote-ip6          32   ; Remote IPv6 (NETWORK byte order, 16 bytes)
   :local-ip6           48   ; Local IPv6 (NETWORK byte order, 16 bytes)
   :remote-port         64   ; Remote port (NETWORK byte order)
   :local-port          68   ; Local port (HOST byte order!)
   :is-fullsock         72   ; Is full socket (vs request socket)
   :snd-cwnd            76   ; Congestion window
   :srtt-us             80   ; Smoothed RTT in microseconds
   :cb-flags            84   ; bpf_sock_ops_cb_flags
   :state               88   ; TCP state
   :rtt-min             92   ; Minimum RTT
   :snd-ssthresh        96   ; Slow start threshold
   :rcv-nxt             100  ; Next expected receive sequence
   :snd-nxt             104  ; Next send sequence
   :snd-una             108  ; First unacknowledged sequence
   :mss-cache           112  ; Maximum segment size
   :ecn-flags           116  ; ECN flags
   :rate-delivered      120  ; Rate delivered
   :rate-interval-us    124  ; Rate interval in microseconds
   :packets-out         128  ; Packets in flight
   :retrans-out         132  ; Retransmitted packets
   :total-retrans       136  ; Total retransmissions
   :segs-in             140  ; Segments received
   :data-segs-in        144  ; Data segments received
   :segs-out            148  ; Segments sent
   :data-segs-out       152  ; Data segments sent
   :lost-out            156  ; Lost packets
   :sacked-out          160  ; SACK'd packets
   :sk-txhash           164  ; TX hash
   :bytes-received      168  ; Bytes received (u64)
   :bytes-acked         176  ; Bytes acknowledged (u64)
   :sk                  184  ; bpf_sock pointer (8 bytes)
   })

;; SOCK_OPS operation codes
(def sock-ops-op
  "SOCK_OPS operation codes (op field values)."
  {:void                     0  ; Reserved
   :timeout-init             1  ; Timeout init
   :rwnd-init                2  ; Receive window init
   :tcp-connect-cb           3  ; TCP connect callback
   :active-established-cb    4  ; Active established
   :passive-established-cb   5  ; Passive established
   :needs-ecn                6  ; Needs ECN
   :base-rtt                 7  ; Base RTT
   :rto-cb                   8  ; RTO callback
   :retrans-cb               9  ; Retrans callback
   :state-cb                 10 ; State change callback
   :tcp-listen-cb            11 ; TCP listen callback
   :rtt-cb                   12 ; RTT callback
   :parse-hdr-opt-cb         13 ; Parse header option
   :hdr-opt-len-cb           14 ; Header option length
   :write-hdr-opt-cb         15 ; Write header option
   })

;; ============================================================================
;; bpf_sock - Socket Info Structure
;; ============================================================================
;;
;; Generic socket information, accessible from various program types.
;;
;; struct bpf_sock {
;;     __u32 bound_dev_if;        // offset 0
;;     __u32 family;              // offset 4
;;     __u32 type;                // offset 8
;;     __u32 protocol;            // offset 12
;;     __u32 mark;                // offset 16
;;     __u32 priority;            // offset 20
;;     __u32 src_ip4;             // offset 24 (network byte order)
;;     __u32 src_ip6[4];          // offset 28 (network byte order)
;;     __u32 src_port;            // offset 44 (HOST byte order)
;;     __u32 dst_port;            // offset 48 (network byte order)
;;     __u32 dst_ip4;             // offset 52 (network byte order)
;;     __u32 dst_ip6[4];          // offset 56 (network byte order)
;;     __u32 state;               // offset 72
;;     __s32 rx_queue_mapping;    // offset 76
;; };

(def bpf-sock
  "bpf_sock structure field offsets.

   BYTE ORDER NOTES:
   - src_ip4, dst_ip4, src_ip6, dst_ip6: NETWORK byte order
   - dst_port: NETWORK byte order
   - src_port: HOST byte order (!)

   Usage:
     ;; Load source port (host byte order)
     (dsl/ldx :w :r2 :r1 (:src-port ctx/bpf-sock))

     ;; Load destination port (network byte order - may need ntohs)
     (dsl/ldx :w :r2 :r1 (:dst-port ctx/bpf-sock))"
  {:bound-dev-if       0    ; Bound device interface index
   :family             4    ; Address family (AF_INET, AF_INET6)
   :type               8    ; Socket type (SOCK_STREAM, SOCK_DGRAM)
   :protocol           12   ; Protocol (IPPROTO_TCP, IPPROTO_UDP)
   :mark               16   ; Socket mark
   :priority           20   ; Socket priority
   :src-ip4            24   ; Source IPv4 (NETWORK byte order)
   :src-ip6            28   ; Source IPv6 (NETWORK byte order, 16 bytes)
   :src-port           44   ; Source port (HOST byte order!)
   :dst-port           48   ; Destination port (NETWORK byte order)
   :dst-ip4            52   ; Destination IPv4 (NETWORK byte order)
   :dst-ip6            56   ; Destination IPv6 (NETWORK byte order, 16 bytes)
   :state              72   ; Socket state
   :rx-queue-mapping   76   ; RX queue mapping
   })

;; ============================================================================
;; Re-exported Structures from Other Namespaces
;; ============================================================================

;; __sk_buff - Used by TC, Socket Filter, SK_SKB programs
(def sk-buff
  "__sk_buff structure field offsets.

   BYTE ORDER NOTES:
   - remote_ip4, local_ip4, remote_ip6, local_ip6: NETWORK byte order
   - remote_port: NETWORK byte order
   - local_port: HOST byte order (!)

   See clj-ebpf.dsl.tc for access functions."
  tc/skb-offsets)

(def sk-buff-offset
  "Get offset for __sk_buff field."
  tc/skb-offset)

;; xdp_md - Used by XDP programs
(def xdp-md
  "xdp_md structure field offsets.

   See clj-ebpf.dsl.xdp for access functions."
  xdp/xdp-md-offsets)

(def xdp-md-offset
  "Get offset for xdp_md field."
  xdp/xdp-md-offset)

;; sk_msg_md - Used by SK_MSG programs
(def sk-msg
  "sk_msg_md structure field offsets.

   BYTE ORDER NOTES:
   - remote_ip4, local_ip4, remote_ip6, local_ip6: NETWORK byte order
   - remote_port: NETWORK byte order
   - local_port: HOST byte order (!)

   See clj-ebpf.dsl.socket for access functions."
  socket/sk-msg-offsets)

(def sk-msg-offset
  "Get offset for sk_msg_md field."
  socket/sk-msg-offset)

;; bpf_sk_lookup - Used by SK_LOOKUP programs
(def bpf-sk-lookup
  "bpf_sk_lookup structure field offsets.

   BYTE ORDER NOTES:
   - local_ip4, remote_ip4, local_ip6, remote_ip6: NETWORK byte order
   - local_port, remote_port: HOST byte order for both (!)

   See clj-ebpf.dsl.sk-lookup for access functions."
  sk-lookup/sk-lookup-offsets)

(def bpf-sk-lookup-offset
  "Get offset for bpf_sk_lookup field."
  sk-lookup/sk-lookup-offset)

;; ============================================================================
;; Protocol Header Offsets (Re-exported)
;; ============================================================================

(def ethernet-offsets
  "Ethernet header field offsets."
  xdp/ethernet-offsets)

(def ipv4-offsets
  "IPv4 header field offsets."
  xdp/ipv4-offsets)

(def ipv6-offsets
  "IPv6 header field offsets."
  xdp/ipv6-offsets)

(def tcp-offsets
  "TCP header field offsets."
  xdp/tcp-offsets)

(def udp-offsets
  "UDP header field offsets."
  xdp/udp-offsets)

;; ============================================================================
;; Header Size Constants
;; ============================================================================

(def ethernet-header-size
  "Ethernet header size: 14 bytes"
  14)

(def ipv4-header-min-size
  "Minimum IPv4 header size (no options): 20 bytes"
  20)

(def ipv6-header-size
  "IPv6 header size: 40 bytes"
  40)

(def tcp-header-min-size
  "Minimum TCP header size (no options): 20 bytes"
  20)

(def udp-header-size
  "UDP header size: 8 bytes"
  8)

;; ============================================================================
;; Helper Functions
;; ============================================================================

(defn sock-ops-offset
  "Get offset for bpf_sock_ops field.

   Parameters:
   - field: Field keyword

   Returns offset in bytes."
  [field]
  (or (get bpf-sock-ops field)
      (throw (ex-info "Unknown bpf_sock_ops field"
                      {:field field
                       :available (keys bpf-sock-ops)}))))

(defn sock-offset
  "Get offset for bpf_sock field.

   Parameters:
   - field: Field keyword

   Returns offset in bytes."
  [field]
  (or (get bpf-sock field)
      (throw (ex-info "Unknown bpf_sock field"
                      {:field field
                       :available (keys bpf-sock)}))))

;; ============================================================================
;; Address Family Constants
;; ============================================================================

(def address-family
  "Address family constants."
  {:unspec     0   ; AF_UNSPEC
   :unix       1   ; AF_UNIX
   :local      1   ; AF_LOCAL (same as UNIX)
   :inet       2   ; AF_INET (IPv4)
   :inet6      10  ; AF_INET6 (IPv6)
   :netlink    16  ; AF_NETLINK
   :packet     17  ; AF_PACKET
   })

;; ============================================================================
;; Socket Type Constants
;; ============================================================================

(def socket-type
  "Socket type constants."
  {:stream     1   ; SOCK_STREAM (TCP)
   :dgram      2   ; SOCK_DGRAM (UDP)
   :raw        3   ; SOCK_RAW
   :rdm        4   ; SOCK_RDM
   :seqpacket  5   ; SOCK_SEQPACKET
   })

;; ============================================================================
;; IP Protocol Constants
;; ============================================================================

(def ip-protocol
  "IP protocol number constants."
  {:icmp       1   ; IPPROTO_ICMP
   :tcp        6   ; IPPROTO_TCP
   :udp        17  ; IPPROTO_UDP
   :icmpv6     58  ; IPPROTO_ICMPV6
   :sctp       132 ; IPPROTO_SCTP
   })
