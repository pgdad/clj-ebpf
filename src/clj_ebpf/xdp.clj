(ns clj-ebpf.xdp
  "XDP (eXpress Data Path) support for high-performance packet processing"
  (:require [clj-ebpf.arch :as arch]
            [clj-ebpf.constants :as const]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.programs :as programs])
  (:import [java.lang.foreign Arena MemorySegment FunctionDescriptor Linker ValueLayout SymbolLookup]
           [java.lang.invoke MethodHandle]))

;; ============================================================================
;; Network Interface Utilities
;; ============================================================================

(def ^:private ^Arena default-arena (Arena/ofAuto))
(def ^:private ^Linker linker (Linker/nativeLinker))

;; Libc lookup - try common paths
(def ^:private libc-lookup
  (or
   ;; Try common libc paths on Linux
   (try (SymbolLookup/libraryLookup "/lib/x86_64-linux-gnu/libc.so.6" default-arena) (catch Exception _ nil))
   (try (SymbolLookup/libraryLookup "libc.so.6" default-arena) (catch Exception _ nil))
   (try (SymbolLookup/libraryLookup "c" default-arena) (catch Exception _ nil))
   ;; Fallback to loader lookup
   (SymbolLookup/loaderLookup)))

;; Helper to create FunctionDescriptor
(defn- make-function-descriptor
  "Create a FunctionDescriptor - helper to avoid reflection issues"
  ^java.lang.foreign.FunctionDescriptor
  [^java.lang.foreign.MemoryLayout return-layout & arg-layouts]
  (let [^"[Ljava.lang.foreign.MemoryLayout;" layouts-array (into-array java.lang.foreign.MemoryLayout (or arg-layouts []))]
    (java.lang.foreign.FunctionDescriptor/of return-layout layouts-array)))

;; Bind if_nametoindex - convert interface name to index
(def ^:private if-nametoindex-handle
  (let [symbol (.find libc-lookup "if_nametoindex")]
    (when (.isPresent symbol)
      (let [mem-seg (.get symbol)
            desc (make-function-descriptor ValueLayout/JAVA_INT ValueLayout/ADDRESS)]
        (.downcallHandle linker mem-seg desc (into-array java.lang.foreign.Linker$Option []))))))

;; Bind if_indextoname - convert interface index to name
(def ^:private if-indextoname-handle
  (let [symbol (.find libc-lookup "if_indextoname")]
    (when (.isPresent symbol)
      (let [mem-seg (.get symbol)
            desc (make-function-descriptor ValueLayout/ADDRESS ValueLayout/JAVA_INT ValueLayout/ADDRESS)]
        (.downcallHandle linker mem-seg desc (into-array java.lang.foreign.Linker$Option []))))))

(defn interface-name->index
  "Get network interface index from name.

  Example: (interface-name->index \"eth0\") => 2"
  [^String ifname]
  (when-not if-nametoindex-handle
    (throw (ex-info "if_nametoindex not available" {})))
  (let [name-seg (utils/string->segment ifname)
        result (.invokeWithArguments if-nametoindex-handle [name-seg])]
    (when (zero? result)
      (throw (ex-info "Interface not found" {:interface ifname})))
    result))

(defn interface-index->name
  "Get network interface name from index.

  Example: (interface-index->name 2) => \"eth0\""
  [ifindex]
  (when-not if-indextoname-handle
    (throw (ex-info "if_indextoname not available" {})))
  (let [buf (.allocate default-arena 16 1) ; IF_NAMESIZE = 16
        result (.invokeWithArguments if-indextoname-handle [(int ifindex) buf])]
    (when (= result MemorySegment/NULL)
      (throw (ex-info "Interface index not found" {:ifindex ifindex})))
    (utils/segment->string buf 16)))

;; ============================================================================
;; Netlink Communication for XDP
;; ============================================================================

;; Netlink constants
(def ^:private NETLINK_ROUTE 0)
(def ^:private RTM_SETLINK 19)
(def ^:private RTM_GETLINK 18)
(def ^:private NLM_F_REQUEST 0x01)
(def ^:private NLM_F_ACK 0x04)
(def ^:private NLMSG_ERROR 0x02)
(def ^:private IFLA_XDP 43)
(def ^:private IFLA_XDP_FD 1)
(def ^:private IFLA_XDP_FLAGS 3)

;; Netlink attribute flags
(def ^:private NLA_F_NESTED 0x8000)

;; Netlink socket syscalls
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
  ;; sockaddr_nl: {family=AF_NETLINK, pad=0, pid=0, groups=0}
  (let [bind-nr (arch/get-syscall-nr :bind)
        addr (utils/pack-struct [[:u16 AF_NETLINK]  ; family
                                  [:u16 0]           ; pad
                                  [:u32 0]           ; pid (0 = kernel assigns)
                                  [:u32 0]])         ; groups
        addr-seg (utils/bytes->segment addr)
        result (syscall/raw-syscall bind-nr sock-fd addr-seg 12)]
    (when (neg? result)
      (throw (ex-info "Failed to bind netlink socket" {:errno (- result)})))))

(defn- send-netlink
  "Send netlink message using architecture-correct syscall number"
  [sock-fd msg-bytes]
  (let [sendto-nr (arch/get-syscall-nr :sendto)
        msg-seg (utils/bytes->segment msg-bytes)
        result (syscall/raw-syscall sendto-nr sock-fd msg-seg (count msg-bytes) 0)]
    (when (neg? result)
      (throw (ex-info "Failed to send netlink message" {:errno (- result)})))))

(defn- recv-netlink
  "Receive netlink message using architecture-correct syscall number"
  [sock-fd buf-size]
  (let [recvfrom-nr (arch/get-syscall-nr :recvfrom)
        buf-seg (utils/allocate-memory buf-size)
        result (syscall/raw-syscall recvfrom-nr sock-fd buf-seg buf-size 0)]
    (when (neg? result)
      (throw (ex-info "Failed to receive netlink message" {:errno (- result)})))
    (utils/segment->bytes buf-seg result)))

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

(defn- build-netlink-msg
  "Build netlink RTM_SETLINK message for XDP attachment.

  Structure:
  - nlmsghdr: {len, type, flags, seq, pid}
  - ifinfomsg: {family, type, index, flags, change}
  - rtattr for IFLA_XDP (nested) containing:
    - rtattr for IFLA_XDP_FD
    - rtattr for IFLA_XDP_FLAGS"
  [ifindex prog-fd xdp-flags]
  (let [;; Build inner XDP attributes with proper alignment
        ;; IFLA_XDP_FD: 4-byte header + 4-byte FD value = 8 bytes (already aligned)
        xdp-fd-attr (build-nla IFLA_XDP_FD (utils/pack-struct [[:u32 prog-fd]]))

        ;; IFLA_XDP_FLAGS: 4-byte header + 4-byte flags = 8 bytes (already aligned)
        xdp-flags-attr (build-nla IFLA_XDP_FLAGS (utils/pack-struct [[:u32 xdp-flags]]))

        ;; Combine inner XDP attributes
        xdp-data (vec (concat xdp-fd-attr xdp-flags-attr))

        ;; Build IFLA_XDP rtattr with NLA_F_NESTED flag
        ifla-xdp (build-nla (bit-or IFLA_XDP NLA_F_NESTED) xdp-data)

        ;; Build ifinfomsg (16 bytes)
        ifinfomsg (utils/pack-struct [[:u8 0]        ; ifi_family = AF_UNSPEC
                                      [:u8 0]        ; __ifi_pad (reserved)
                                      [:u16 0]       ; ifi_type
                                      [:u32 ifindex] ; ifi_index
                                      [:u32 0]       ; ifi_flags
                                      [:u32 0]])     ; ifi_change

        ;; Combine ifinfomsg + rtattrs
        payload (concat ifinfomsg ifla-xdp)

        ;; Build nlmsghdr (16 bytes)
        nlmsg-len (+ 16 (count payload))
        nlmsghdr (utils/pack-struct [[:u32 nlmsg-len]                        ; nlmsg_len
                                     [:u16 RTM_SETLINK]                      ; nlmsg_type
                                     [:u16 (bit-or NLM_F_REQUEST NLM_F_ACK)] ; nlmsg_flags
                                     [:u32 1]                                ; nlmsg_seq
                                     [:u32 0]])]                             ; nlmsg_pid

    (byte-array (concat nlmsghdr payload))))

(defn- parse-netlink-ack
  "Parse netlink ACK/error message"
  [response-bytes]
  (let [nlmsg-type (utils/bytes->int (byte-array (take 2 (drop 4 response-bytes))))
        error-code (utils/bytes->int (byte-array (take 4 (drop 16 response-bytes))))]
    (when (not= nlmsg-type NLMSG_ERROR)
      (throw (ex-info "Unexpected netlink response type" {:type nlmsg-type})))
    (when (neg? error-code)
      (throw (ex-info "Netlink operation failed" {:errno (- error-code)})))))

;; ============================================================================
;; XDP Attach/Detach Functions
;; ============================================================================

(defn attach-xdp
  "Attach XDP program to a network interface.

  Parameters:
  - ifname: Interface name (e.g., \"eth0\") or interface index (integer)
  - prog-fd: BPF program file descriptor
  - flags: XDP attachment flags (optional, defaults to :drv-mode)
           :update-if-noexist - Only attach if no XDP program exists
           :skb-mode - Generic XDP (slower, kernel mode)
           :drv-mode - Native XDP (driver mode, fastest)
           :hw-mode - Hardware offload mode
           :replace - Replace existing program

  Returns the interface index.

  Example:
    (attach-xdp \"eth0\" prog-fd [:drv-mode])"
  [ifname prog-fd & flags]
  (let [ifindex (if (string? ifname)
                  (interface-name->index ifname)
                  ifname)
        xdp-flags-val (if (seq flags)
                       (const/flags->bits const/xdp-flags flags)
                       (:drv-mode const/xdp-flags)) ; Default to driver mode

        ;; Create netlink socket
        sock-fd (socket AF_NETLINK SOCK_RAW NETLINK_ROUTE)]

    (try
      ;; Bind socket
      (bind-netlink sock-fd)

      ;; Build and send message
      (let [msg (build-netlink-msg ifindex prog-fd xdp-flags-val)]
        (send-netlink sock-fd msg)

        ;; Receive ACK
        (let [response (recv-netlink sock-fd 4096)]
          (parse-netlink-ack response)))

      ifindex

      (finally
        ;; Close socket
        (syscall/close-fd sock-fd)))))

(defn detach-xdp
  "Detach XDP program from a network interface.

  Parameters:
  - ifname: Interface name (e.g., \"eth0\") or interface index (integer)
  - flags: XDP detachment flags (optional, should match attachment flags)

  Example:
    (detach-xdp \"eth0\")"
  [ifname & flags]
  (let [ifindex (if (string? ifname)
                  (interface-name->index ifname)
                  ifname)
        xdp-flags-val (if (seq flags)
                       (const/flags->bits const/xdp-flags flags)
                       (:drv-mode const/xdp-flags)) ; Default to driver mode

        ;; Use -1 as prog-fd to detach
        prog-fd -1

        ;; Create netlink socket
        sock-fd (socket AF_NETLINK SOCK_RAW NETLINK_ROUTE)]

    (try
      ;; Bind socket
      (bind-netlink sock-fd)

      ;; Build and send message
      (let [msg (build-netlink-msg ifindex prog-fd xdp-flags-val)]
        (send-netlink sock-fd msg)

        ;; Receive ACK
        (let [response (recv-netlink sock-fd 4096)]
          (parse-netlink-ack response)))

      ifindex

      (finally
        ;; Close socket
        (syscall/close-fd sock-fd)))))

;; ============================================================================
;; XDP Program Loading Helpers
;; ============================================================================

(defn load-xdp-program
  "Load XDP program from bytecode.

  Parameters:
  - bytecode: BPF bytecode (byte array or vector of instruction maps)
  - options: Map of options:
    - :prog-name - Program name (optional)
    - :license - License string (default \"GPL\")
    - :log-level - Verifier log level (default 0)
    - :log-size - Log buffer size (default 0)

  Returns program file descriptor.

  Example:
    (load-xdp-program bytecode {:prog-name \"xdp_filter\" :license \"GPL\"})"
  [bytecode & {:keys [prog-name license log-level log-size]
               :or {license "GPL" log-level 0 log-size 0}}]
  ;; For now, delegate to programs namespace
  ;; In a full implementation, this would handle XDP-specific setup
  (programs/load-program bytecode
                        :prog-type :xdp
                        :prog-name prog-name
                        :license license
                        :log-level log-level
                        :log-size log-size))

(defn load-xdp-from-file
  "Load XDP program from ELF file.

  Parameters:
  - path: Path to ELF file containing XDP program
  - section-name: ELF section name (default \"xdp\")
  - options: Additional options passed to load-xdp-program

  Returns program file descriptor.

  Example:
    (load-xdp-from-file \"filter.o\" \"xdp\" {:prog-name \"xdp_filter\"})"
  [path section-name & options]
  ;; This would require ELF parsing - placeholder for now
  (throw (ex-info "ELF loading not yet implemented - use load-xdp-program with bytecode"
                 {:path path :section section-name})))

;; ============================================================================
;; Convenience Macros
;; ============================================================================

(defmacro with-xdp
  "Attach XDP program to interface and ensure detachment after use.

  Example:
    (with-xdp [ifindex (attach-xdp \"eth0\" prog-fd [:drv-mode])]
      ;; XDP program is active
      (do-packet-processing))"
  [[binding attach-expr] & body]
  `(let [~binding ~attach-expr
         ifindex# ~binding]
     (try
       ~@body
       (finally
         (detach-xdp ifindex#)))))

(defmacro with-xdp-program
  "Load XDP program, attach to interface, and ensure cleanup.

  Example:
    (with-xdp-program [prog-fd bytecode {:prog-name \"xdp_filter\"}
                       ifindex \"eth0\" [:drv-mode]]
      ;; XDP program is loaded and attached
      (process-packets))"
  [[prog-binding bytecode options iface-binding ifname flags] & body]
  `(let [~prog-binding (load-xdp-program ~bytecode ~@(apply concat options))]
     (try
       (let [~iface-binding (attach-xdp ~ifname ~prog-binding ~@flags)]
         (try
           ~@body
           (finally
             (detach-xdp ~iface-binding))))
       (finally
         (syscall/close-fd ~prog-binding)))))
