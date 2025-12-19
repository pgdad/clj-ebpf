(ns clj-ebpf.tc
  "TC (Traffic Control) support for BPF packet filtering and QoS"
  (:require [clj-ebpf.arch :as arch]
            [clj-ebpf.constants :as const]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.xdp :as xdp]))

;; ============================================================================
;; TC Constants
;; ============================================================================

;; Netlink message types for TC
(def ^:private RTM_NEWQDISC 36)
(def ^:private RTM_DELQDISC 37)
(def ^:private RTM_NEWTFILTER 44)
(def ^:private RTM_DELTFILTER 45)

;; Netlink flags
(def ^:private NLM_F_REQUEST 0x01)
(def ^:private NLM_F_ACK 0x04)
(def ^:private NLM_F_CREATE 0x400)
(def ^:private NLM_F_EXCL 0x200)
(def ^:private NLMSG_ERROR 0x02)

;; Netlink attribute flags
(def ^:private NLA_F_NESTED 0x8000)

;; TC handles and priorities (unsigned 32-bit values)
;; These are defined as longs to avoid signed integer overflow
(def ^:private TC_H_CLSACT 0xFFFF0000)
(def ^:private TC_H_INGRESS 0xFFFFFFF1)  ; Parent for clsact qdisc
(def ^:private TC_H_MIN_INGRESS 0xFFF2)
(def ^:private TC_H_MIN_EGRESS 0xFFF3)

;; TC attributes
(def ^:private TCA_KIND 1)
(def ^:private TCA_OPTIONS 2)

;; TCA_BPF attributes (from linux/pkt_cls.h enum)
;; TCA_BPF_UNSPEC = 0, ACT = 1, POLICE = 2, CLASSID = 3, OPS_LEN = 4, OPS = 5
(def ^:private TCA_BPF_FD 6)
(def ^:private TCA_BPF_NAME 7)
(def ^:private TCA_BPF_FLAGS 8)
(def ^:private TCA_BPF_FLAGS_GEN 9)

;; TC BPF flags
(def ^:private TCA_BPF_FLAG_ACT_DIRECT 1)

;; TC action codes (return values for TC programs)
(def tc-action
  {:unspec -1      ; Continue with next rule
   :ok 0           ; Pass packet (TC_ACT_OK)
   :reclassify 1   ; Reclassify packet
   :shot 2         ; Drop packet (TC_ACT_SHOT)
   :pipe 3         ; Continue with next action
   :stolen 4       ; Consume packet
   :queued 5       ; Packet queued
   :repeat 6       ; Repeat action
   :redirect 7})   ; Redirect packet

(def tc-action->int
  (into {} (map (fn [[k v]] [k v]) tc-action)))

(def int->tc-action
  (into {} (map (fn [[k v]] [v k]) tc-action)))

;; TC attachment direction
(def tc-direction
  {:ingress TC_H_MIN_INGRESS
   :egress TC_H_MIN_EGRESS})

;; ============================================================================
;; Netlink Helpers for TC
;; ============================================================================

(def ^:private NETLINK_ROUTE 0)
(def ^:private AF_NETLINK 16)
(def ^:private SOCK_RAW 3)

(defn- socket
  "Create a socket using architecture-correct syscall number"
  [domain type protocol]
  (let [socket-nr (arch/get-syscall-nr :socket)
        result (syscall/raw-syscall socket-nr domain type protocol)]
    (when (neg? result)
      (throw (ex-info "Failed to create socket" {:errno (- result)})))
    result))

(defn- bind-netlink
  "Bind netlink socket using architecture-correct syscall number"
  [sock-fd]
  (let [bind-nr (arch/get-syscall-nr :bind)
        addr (utils/pack-struct [[:u16 AF_NETLINK]
                                  [:u16 0]
                                  [:u32 0]
                                  [:u32 0]])
        addr-seg (utils/bytes->segment addr)
        result (syscall/raw-syscall bind-nr sock-fd addr-seg 12)]
    (when (neg? result)
      (throw (ex-info "Failed to bind netlink socket" {:errno (- result)})))))

(defn- send-netlink
  "Send netlink message using write syscall.
   For bound netlink sockets, write() works like sendto() with NULL dest."
  [sock-fd msg-bytes]
  (let [write-nr (arch/get-syscall-nr :write)
        msg-seg (utils/bytes->segment msg-bytes)
        result (syscall/raw-syscall write-nr sock-fd msg-seg (count msg-bytes))]
    (when (neg? result)
      (throw (ex-info "Failed to send netlink message" {:errno (- result)})))))

(defn- recv-netlink
  "Receive netlink message using read syscall.
   For bound netlink sockets, read() works like recvfrom() with NULL src."
  [sock-fd buf-size]
  (let [read-nr (arch/get-syscall-nr :read)
        buf-seg (utils/allocate-memory buf-size)
        result (syscall/raw-syscall read-nr sock-fd buf-seg buf-size)]
    (when (neg? result)
      (throw (ex-info "Failed to receive netlink message" {:errno (- result)})))
    (utils/segment->bytes buf-seg result)))

(defn- parse-netlink-ack
  "Parse netlink ACK/error message"
  [response-bytes]
  (when (< (count response-bytes) 20)
    (throw (ex-info "Netlink response too short" {:length (count response-bytes)})))
  (let [nlmsg-type (utils/bytes->short (byte-array (take 2 (drop 4 response-bytes))))
        error-code (utils/bytes->int (byte-array (take 4 (drop 16 response-bytes))))]
    (when (not= nlmsg-type NLMSG_ERROR)
      (throw (ex-info "Unexpected netlink response type" {:type nlmsg-type})))
    (when (neg? error-code)
      (throw (ex-info "Netlink operation failed" {:errno (- error-code)})))))

(defn- nla-align
  "Align length to 4-byte boundary (NLA_ALIGN)"
  [len]
  (bit-and (+ len 3) (bit-not 3)))

(defn- build-nla
  "Build a netlink attribute (struct nlattr).

  Parameters:
  - nla-type: Attribute type (may include flags like NLA_F_NESTED)
  - data: Payload data as byte sequence

  Returns byte sequence with proper padding.
  nla_len includes header (4 bytes) but NOT padding."
  [nla-type data]
  (let [nla-len (+ 4 (count data))           ; Header (4 bytes) + data
        padded-len (nla-align nla-len)
        padding (- padded-len nla-len)]
    (concat (utils/pack-struct [[:u16 nla-len]
                                [:u16 nla-type]])
            data
            (repeat padding 0))))

;; Legacy alias for backward compatibility
(defn- build-rtattr
  "Build rtattr structure (legacy alias for build-nla)"
  [rta-type data]
  (build-nla rta-type data))

(defn- align-4
  "Align data to 4-byte boundary"
  [data]
  (let [len (count data)
        padded-len (nla-align len)
        padding (- padded-len len)]
    (concat data (repeat padding 0))))

;; ============================================================================
;; TC Qdisc Management
;; ============================================================================

(defn- build-qdisc-msg
  "Build netlink message for qdisc operations.

  Structure:
  - nlmsghdr: {len, type, flags, seq, pid}
  - tcmsg: {family, ifindex, handle, parent, info}
  - rtattr for TCA_KIND (\"clsact\")"
  [msg-type ifindex flags]
  (let [;; Build tcmsg structure
        ;; For clsact qdisc: handle=TC_H_CLSACT, parent=TC_H_INGRESS
        tcmsg (utils/pack-struct [[:u8 0]               ; family = AF_UNSPEC
                                  [:u8 0] [:u16 0]      ; padding
                                  [:u32 ifindex]        ; ifindex
                                  [:u32 TC_H_CLSACT]    ; handle
                                  [:u32 TC_H_INGRESS]   ; parent (0xFFFFFFF1)
                                  [:u32 0]])            ; info

        ;; Build TCA_KIND attribute with "clsact"
        kind-data (concat (.getBytes "clsact" "UTF-8") [0]) ; null-terminated
        kind-attr (build-rtattr TCA_KIND (align-4 kind-data))

        ;; Combine tcmsg + attributes
        payload (concat tcmsg kind-attr)

        ;; Build nlmsghdr
        nlmsg-len (+ 16 (count payload))
        nlmsghdr (utils/pack-struct [[:u32 nlmsg-len]
                                     [:u16 msg-type]
                                     [:u16 flags]
                                     [:u32 1]
                                     [:u32 0]])]

    (byte-array (concat nlmsghdr payload))))

(defn add-clsact-qdisc
  "Add clsact qdisc to a network interface.

  The clsact qdisc is required before attaching TC BPF programs.
  It provides ingress and egress attachment points.

  Parameters:
  - ifname: Interface name (e.g., \"eth0\") or interface index (integer)

  Returns the interface index.

  Example:
    (add-clsact-qdisc \"eth0\")"
  [ifname]
  (let [ifindex (if (string? ifname)
                  (xdp/interface-name->index ifname)
                  ifname)
        sock-fd (socket AF_NETLINK SOCK_RAW NETLINK_ROUTE)]

    (try
      (bind-netlink sock-fd)

      (let [msg (build-qdisc-msg RTM_NEWQDISC ifindex
                                 (bit-or NLM_F_REQUEST NLM_F_ACK NLM_F_CREATE NLM_F_EXCL))]
        (send-netlink sock-fd msg)
        (let [response (recv-netlink sock-fd 4096)]
          (parse-netlink-ack response)))

      ifindex

      (finally
        (syscall/close-fd sock-fd)))))

(defn remove-clsact-qdisc
  "Remove clsact qdisc from a network interface.

  This will also remove all attached TC BPF filters.

  Parameters:
  - ifname: Interface name (e.g., \"eth0\") or interface index (integer)

  Example:
    (remove-clsact-qdisc \"eth0\")"
  [ifname]
  (let [ifindex (if (string? ifname)
                  (xdp/interface-name->index ifname)
                  ifname)
        sock-fd (socket AF_NETLINK SOCK_RAW NETLINK_ROUTE)]

    (try
      (bind-netlink sock-fd)

      (let [msg (build-qdisc-msg RTM_DELQDISC ifindex
                                 (bit-or NLM_F_REQUEST NLM_F_ACK))]
        (send-netlink sock-fd msg)
        (let [response (recv-netlink sock-fd 4096)]
          (parse-netlink-ack response)))

      ifindex

      (finally
        (syscall/close-fd sock-fd)))))

;; ============================================================================
;; TC Filter Attachment
;; ============================================================================

(defn- build-filter-msg
  "Build netlink message for TC filter operations.

  Structure:
  - nlmsghdr: {len, type, flags, seq, pid}
  - tcmsg: {family, ifindex, handle, parent, info}
  - rtattr for TCA_KIND (\"bpf\")
  - rtattr for TCA_OPTIONS (nested) containing:
    - rtattr for TCA_BPF_FD
    - rtattr for TCA_BPF_NAME
    - rtattr for TCA_BPF_FLAGS"
  [msg-type ifindex direction prog-fd prog-name priority flags]
  (let [parent (get tc-direction direction TC_H_MIN_INGRESS)

        ;; Build tcmsg structure (20 bytes)
        ;; info field format: lower 16 bits = protocol (0x0003 = ETH_P_ALL), upper 16 bits = priority
        info-field (bit-or (bit-shift-left (long priority) 16) 0x0003)
        tcmsg (utils/pack-struct [[:u8 0]                              ; family = AF_UNSPEC
                                  [:u8 0] [:u16 0]                     ; padding
                                  [:u32 ifindex]                       ; ifindex
                                  [:u32 0]                             ; handle (0 = auto)
                                  [:u32 (bit-or TC_H_CLSACT parent)]   ; parent
                                  [:u32 info-field]])                  ; info (prio << 16 | ETH_P_ALL)

        ;; Build TCA_KIND attribute with "bpf" (null-terminated, aligned)
        kind-data (concat (.getBytes "bpf" "UTF-8") [0])
        kind-attr (build-nla TCA_KIND (align-4 kind-data))

        ;; Build inner BPF option attributes
        bpf-fd-attr (build-nla TCA_BPF_FD (utils/pack-struct [[:u32 prog-fd]]))
        bpf-name-data (concat (.getBytes prog-name "UTF-8") [0])
        bpf-name-attr (build-nla TCA_BPF_NAME (align-4 bpf-name-data))
        bpf-flags-attr (build-nla TCA_BPF_FLAGS (utils/pack-struct [[:u32 TCA_BPF_FLAG_ACT_DIRECT]]))

        ;; Combine BPF options (already individually aligned by build-nla)
        bpf-options (vec (concat bpf-fd-attr bpf-name-attr bpf-flags-attr))

        ;; Build TCA_OPTIONS with NLA_F_NESTED flag
        options-attr (build-nla (bit-or TCA_OPTIONS NLA_F_NESTED) bpf-options)

        ;; Combine tcmsg + attributes
        payload (concat tcmsg kind-attr options-attr)

        ;; Build nlmsghdr (16 bytes)
        nlmsg-len (+ 16 (count payload))
        nlmsghdr (utils/pack-struct [[:u32 nlmsg-len]      ; nlmsg_len
                                     [:u16 msg-type]       ; nlmsg_type
                                     [:u16 flags]          ; nlmsg_flags
                                     [:u32 1]              ; nlmsg_seq
                                     [:u32 0]])]           ; nlmsg_pid

    (byte-array (concat nlmsghdr payload))))

(defn attach-tc-filter
  "Attach TC BPF program as a filter on a network interface.

  Parameters:
  - ifname: Interface name (e.g., \"eth0\") or interface index (integer)
  - prog-fd: BPF program file descriptor
  - direction: :ingress or :egress
  - options: Map of options:
    - :prog-name - Program name for identification (default \"tc_bpf\")
    - :priority - Filter priority (default 1, lower = higher priority)
    - :auto-qdisc - Automatically add clsact qdisc if needed (default true)

  Returns a map with :ifindex and :direction for use with detach-tc-filter.

  Example:
    (attach-tc-filter \"eth0\" prog-fd :ingress {:prog-name \"my_filter\" :priority 1})"
  [ifname prog-fd direction & {:keys [prog-name priority auto-qdisc]
                               :or {prog-name "tc_bpf" priority 1 auto-qdisc true}}]
  (let [ifindex (if (string? ifname)
                  (xdp/interface-name->index ifname)
                  ifname)]

    ;; Ensure clsact qdisc exists
    (when auto-qdisc
      (try
        (add-clsact-qdisc ifindex)
        (catch Exception e
          ;; Ignore EEXIST error (errno 17) if qdisc already exists
          (when-not (= 17 (:errno (ex-data e)))
            (throw e)))))

    (let [sock-fd (socket AF_NETLINK SOCK_RAW NETLINK_ROUTE)]
      (try
        (bind-netlink sock-fd)

        (let [msg (build-filter-msg RTM_NEWTFILTER ifindex direction prog-fd prog-name priority
                                   (bit-or NLM_F_REQUEST NLM_F_ACK NLM_F_CREATE NLM_F_EXCL))]
          (send-netlink sock-fd msg)
          (let [response (recv-netlink sock-fd 4096)]
            (parse-netlink-ack response)))

        {:ifindex ifindex :direction direction :priority priority}

        (finally
          (syscall/close-fd sock-fd))))))

(defn detach-tc-filter
  "Detach TC BPF filter from a network interface.

  Parameters:
  - ifname: Interface name (e.g., \"eth0\") or interface index (integer)
  - direction: :ingress or :egress
  - priority: Filter priority (must match the one used in attach-tc-filter)

  Example:
    (detach-tc-filter \"eth0\" :ingress 1)

  Or using the attachment info:
    (let [info (attach-tc-filter \"eth0\" prog-fd :ingress)]
      (detach-tc-filter (:ifindex info) (:direction info) (:priority info)))"
  [ifname direction priority]
  (let [ifindex (if (string? ifname)
                  (xdp/interface-name->index ifname)
                  ifname)
        sock-fd (socket AF_NETLINK SOCK_RAW NETLINK_ROUTE)]

    (try
      (bind-netlink sock-fd)

      (let [msg (build-filter-msg RTM_DELTFILTER ifindex direction -1 "" priority
                                 (bit-or NLM_F_REQUEST NLM_F_ACK))]
        (send-netlink sock-fd msg)
        (let [response (recv-netlink sock-fd 4096)]
          (parse-netlink-ack response)))

      ifindex

      (finally
        (syscall/close-fd sock-fd)))))

;; ============================================================================
;; TC Program Loading Helpers
;; ============================================================================

(defn load-tc-program
  "Load TC BPF program from bytecode.

  Parameters:
  - bytecode: BPF bytecode (byte array or vector of instruction maps)
  - prog-type: Program type (:sched-cls or :sched-act)
  - options: Map of options:
    - :prog-name - Program name (optional)
    - :license - License string (default \"GPL\")
    - :log-level - Verifier log level (default 0)
    - :log-size - Log buffer size (default 0)

  Returns program file descriptor.

  Example:
    (load-tc-program bytecode :sched-cls {:prog-name \"tc_filter\" :license \"GPL\"})"
  [bytecode prog-type & {:keys [prog-name license log-level log-size]
                         :or {license "GPL" log-level 0 log-size 0}}]
  (when-not (#{:sched-cls :sched-act} prog-type)
    (throw (ex-info "Invalid TC program type, must be :sched-cls or :sched-act"
                   {:prog-type prog-type})))

  (programs/load-program bytecode
                        :prog-type prog-type
                        :prog-name prog-name
                        :license license
                        :log-level log-level
                        :log-size log-size))

;; ============================================================================
;; Convenience Macros
;; ============================================================================

(defmacro with-tc-filter
  "Attach TC filter and ensure detachment after use.

  Example:
    (with-tc-filter [info (attach-tc-filter \"eth0\" prog-fd :ingress {:priority 1})]
      ;; TC filter is active
      (do-packet-processing))"
  [[binding attach-expr] & body]
  `(let [~binding ~attach-expr
         info# ~binding]
     (try
       ~@body
       (finally
         (detach-tc-filter (:ifindex info#) (:direction info#) (:priority info#))))))

(defmacro with-tc-program
  "Load TC program, attach filter, and ensure cleanup.

  Example:
    (with-tc-program [prog-fd bytecode :sched-cls {:prog-name \"tc_filter\"}
                      info \"eth0\" :ingress {:priority 1}]
      ;; TC program is loaded and attached
      (process-packets))"
  [[prog-binding bytecode prog-type options iface-binding ifname direction filter-options] & body]
  `(let [~prog-binding (load-tc-program ~bytecode ~prog-type ~@(apply concat options))]
     (try
       (let [~iface-binding (attach-tc-filter ~ifname ~prog-binding ~direction ~@(apply concat filter-options))]
         (try
           ~@body
           (finally
             (detach-tc-filter (:ifindex ~iface-binding) (:direction ~iface-binding) (:priority ~iface-binding)))))
       (finally
         (syscall/close-fd ~prog-binding)))))

;; ============================================================================
;; High-Level Helper Functions
;; ============================================================================

(defn setup-tc-ingress
  "Setup TC BPF filter on ingress (incoming packets).

  Convenience function that:
  1. Adds clsact qdisc if needed
  2. Loads the BPF program
  3. Attaches it to ingress

  Parameters:
  - ifname: Interface name
  - bytecode: BPF bytecode
  - options: Program and filter options

  Returns a map with :prog-fd and :filter-info for cleanup.

  Example:
    (def setup (setup-tc-ingress \"eth0\" bytecode {:prog-name \"ingress_filter\"}))
    ;; ... later ...
    (teardown-tc-filter setup)"
  [ifname bytecode & {:keys [prog-name priority]
                      :or {prog-name "tc_ingress" priority 1}
                      :as options}]
  (let [prog-fd (load-tc-program bytecode :sched-cls options)
        filter-info (attach-tc-filter ifname prog-fd :ingress
                                     :prog-name prog-name
                                     :priority priority)]
    {:prog-fd prog-fd
     :filter-info filter-info}))

(defn setup-tc-egress
  "Setup TC BPF filter on egress (outgoing packets).

  Similar to setup-tc-ingress but for outgoing traffic.

  Example:
    (def setup (setup-tc-egress \"eth0\" bytecode {:prog-name \"egress_filter\"}))"
  [ifname bytecode & {:keys [prog-name priority]
                      :or {prog-name "tc_egress" priority 1}
                      :as options}]
  (let [prog-fd (load-tc-program bytecode :sched-cls options)
        filter-info (attach-tc-filter ifname prog-fd :egress
                                     :prog-name prog-name
                                     :priority priority)]
    {:prog-fd prog-fd
     :filter-info filter-info}))

(defn teardown-tc-filter
  "Teardown TC filter setup created by setup-tc-ingress or setup-tc-egress.

  Parameters:
  - setup: Map returned by setup-tc-ingress/egress with :prog-fd and :filter-info

  Example:
    (teardown-tc-filter setup)"
  [{:keys [prog-fd filter-info]}]
  (try
    (detach-tc-filter (:ifindex filter-info)
                     (:direction filter-info)
                     (:priority filter-info))
    (finally
      (syscall/close-fd prog-fd))))
