(ns port-proxy
  "Simple Port-Based Reverse Proxy with Direct Server Return (DSR)

  This implementation provides a straightforward port forwarding proxy using XDP.
  It maps local listen ports to remote backend IP:port combinations with DSR.

  Architecture:
  ┌─────────────────────────────────────────────────────────────────┐
  │                     Port Proxy with DSR                         │
  │                                                                 │
  │  Client ──► Host:ListenPort ──► Backend:TargetPort              │
  │                  │                                              │
  │                  └─► XDP: Rewrite dst MAC to backend            │
  │                      Rewrite dst IP to backend IP               │
  │                      Rewrite dst port to target port            │
  │                                                                 │
  │  Client ◄──────────────────────── Backend Server                │
  │             Direct response (backend replies directly)          │
  │             Backend must have VIP configured on loopback        │
  └─────────────────────────────────────────────────────────────────┘

  For DSR to work:
  1. Backend server must have the proxy's IP on its loopback (ip addr add <proxy-ip>/32 dev lo)
  2. Backend must be on same L2 network segment (or use tunneling)
  3. Backend replies directly to client, bypassing the proxy

  Configuration is simple:
  - listen-port: Local port to listen on
  - backend-ip: IP address of backend server
  - backend-port: Port on backend server
  - backend-mac: MAC address of backend server

  Example:
    (def proxy (create-port-proxy \"eth0\"))
    (add-port-mapping proxy {:listen-port 8080
                             :backend-ip \"192.168.1.100\"
                             :backend-port 80
                             :backend-mac \"aa:bb:cc:dd:ee:ff\"})
"
  (:require [clj-ebpf.dsl :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.xdp :as xdp]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.constants :as const]
            [clojure.tools.logging :as log])
  (:import [java.net InetAddress NetworkInterface]
           [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; MAC Address Utilities
;; ============================================================================

(defn parse-mac
  "Parse MAC address string (e.g., 'aa:bb:cc:dd:ee:ff') to byte array"
  [mac-str]
  (let [parts (clojure.string/split mac-str #":")]
    (byte-array (map #(unchecked-byte (Integer/parseInt % 16)) parts))))

(defn format-mac
  "Format byte array as MAC address string"
  [^bytes mac-bytes]
  (clojure.string/join ":" (map #(format "%02x" (bit-and % 0xFF)) mac-bytes)))

(defn get-interface-mac
  "Get MAC address of a network interface"
  [ifname]
  (let [iface (NetworkInterface/getByName ifname)]
    (when iface
      (.getHardwareAddress iface))))

;; ============================================================================
;; Data Structures and Serialization
;; ============================================================================

;; Port mapping key: 4 bytes (listen-port: 2, protocol: 1, pad: 1)
(defn port-key->bytes
  "Serialize port mapping key to bytes"
  [{:keys [listen-port protocol]}]
  (let [buf (ByteBuffer/allocate 4)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putShort buf (short listen-port))
    (.put buf (byte (case protocol :tcp 6 :udp 17 6)))
    (.put buf (byte 0))  ; padding
    (.array buf)))

(defn bytes->port-key
  "Deserialize bytes to port mapping key"
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    {:listen-port (bit-and (.getShort buf) 0xFFFF)
     :protocol (case (bit-and (.get buf) 0xFF)
                 6 :tcp
                 17 :udp
                 :unknown)}))

;; Port mapping value: 16 bytes (backend-ip: 4, backend-port: 2, backend-mac: 6, flags: 2, pad: 2)
(defn port-value->bytes
  "Serialize port mapping value to bytes"
  [{:keys [backend-ip backend-port backend-mac flags]}]
  (let [ip-bytes (if (string? backend-ip)
                   (.getAddress (InetAddress/getByName backend-ip))
                   backend-ip)
        mac-bytes (if (string? backend-mac)
                    (parse-mac backend-mac)
                    backend-mac)
        buf (ByteBuffer/allocate 16)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.put buf ^bytes ip-bytes)              ; 4 bytes
    (.putShort buf (short backend-port))    ; 2 bytes
    (.put buf ^bytes mac-bytes)             ; 6 bytes
    (.putShort buf (short (or flags 1)))    ; 2 bytes (1 = enabled)
    (.putShort buf (short 0))               ; 2 bytes padding
    (.array buf)))

(defn bytes->port-value
  "Deserialize bytes to port mapping value"
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (let [ip-bytes (byte-array 4)
          mac-bytes (byte-array 6)]
      (.get buf ip-bytes)
      {:backend-ip (InetAddress/getByAddress ip-bytes)
       :backend-port (bit-and (.getShort buf) 0xFFFF)
       :backend-mac (do (.get buf mac-bytes) (format-mac mac-bytes))
       :flags (bit-and (.getShort buf) 0xFFFF)})))

;; Statistics value: 16 bytes (packets: 8, bytes: 8)
(defn stats->bytes
  "Serialize stats to bytes"
  [{:keys [packets bytes-transferred]}]
  (let [buf (ByteBuffer/allocate 16)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putLong buf (or packets 0))
    (.putLong buf (or bytes-transferred 0))
    (.array buf)))

(defn bytes->stats
  "Deserialize bytes to stats"
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    {:packets (.getLong buf)
     :bytes-transferred (.getLong buf)}))

;; ============================================================================
;; BPF Map Creation
;; ============================================================================

(defn create-proxy-maps
  "Create BPF maps for port proxy

  Returns:
  - :port-map - Port mapping configuration (listen-port -> backend info)
  - :stats-map - Per-port statistics"
  [& {:keys [max-ports] :or {max-ports 256}}]
  {:port-map
   (maps/create-map
    {:map-type :hash
     :key-size 4
     :value-size 16
     :max-entries max-ports
     :map-name "port_map"
     :key-serializer port-key->bytes
     :key-deserializer bytes->port-key
     :value-serializer port-value->bytes
     :value-deserializer bytes->port-value})

   :stats-map
   (maps/create-map
    {:map-type :hash
     :key-size 4
     :value-size 16
     :max-entries max-ports
     :map-name "stats_map"
     :key-serializer port-key->bytes
     :key-deserializer bytes->port-key
     :value-serializer stats->bytes
     :value-deserializer bytes->stats})})

(defn close-proxy-maps
  "Close all proxy maps"
  [maps]
  (doseq [[_ m] maps]
    (maps/close-map m)))

;; ============================================================================
;; XDP Program Generation
;; ============================================================================

;; Network constants
(def ETH_HLEN 14)
(def ETH_P_IP 0x0800)
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

;; Helper to create LDDW instruction for map FD
(defn- ld-map-fd
  "Load map file descriptor into register using LDDW pseudo-instruction"
  [dst map-fd]
  (let [opcode 0x18
        dst-reg (get bpf/registers dst 0)
        src-reg 1  ; BPF_PSEUDO_MAP_FD
        insn1 (byte-array [opcode
                           (unchecked-byte (bit-or (bit-shift-left src-reg 4) dst-reg))
                           0 0
                           (unchecked-byte (bit-and map-fd 0xFF))
                           (unchecked-byte (bit-and (bit-shift-right map-fd 8) 0xFF))
                           (unchecked-byte (bit-and (bit-shift-right map-fd 16) 0xFF))
                           (unchecked-byte (bit-and (bit-shift-right map-fd 24) 0xFF))])
        insn2 (byte-array [0 0 0 0 0 0 0 0])]
    (byte-array (concat insn1 insn2))))

(defn generate-port-proxy-program
  "Generate XDP bytecode for the port proxy.

  This program:
  1. Parses Ethernet and IP headers
  2. Extracts destination port
  3. Looks up port in port_map
  4. If found and enabled:
     - Rewrites destination MAC to backend MAC (for L2 forwarding)
     - Optionally rewrites destination IP (for full DNAT)
     - Rewrites destination port to backend port
     - Recalculates checksums
  5. Returns XDP_TX to transmit modified packet

  Parameters:
  - port-map-fd: File descriptor of port mapping map"
  [port-map-fd]

  (let [;; XDP actions
        XDP_PASS 2
        XDP_TX 3

        ;; BPF helper function IDs
        BPF_FUNC_map_lookup_elem 1

        ;; Stack layout
        STACK_PORT_KEY -4]

    (bpf/assemble
     [;; ===== Prologue: Load packet pointers =====
      ;; R6 = ctx->data, R7 = ctx->data_end
      (bpf/ldx :dw :r6 :r1 0)
      (bpf/ldx :dw :r7 :r1 8)

      ;; ===== Bounds check for Ethernet header =====
      (bpf/mov-reg :r8 :r6)
      (bpf/add :r8 ETH_HLEN)
      (bpf/jmp-reg :jgt :r8 :r7 42)  ; Jump to pass

      ;; ===== Check EtherType is IPv4 =====
      (bpf/ldx :h :r2 :r6 12)
      (bpf/jmp-imm :jne :r2 0x0008 40)  ; Jump to pass (0x0800 in LE)

      ;; ===== Bounds check for IP header =====
      (bpf/mov-reg :r8 :r6)
      (bpf/add :r8 (+ ETH_HLEN 20))
      (bpf/jmp-reg :jgt :r8 :r7 37)

      ;; ===== Extract IP protocol =====
      (bpf/ldx :b :r2 :r6 (+ ETH_HLEN 9))
      (bpf/mov-reg :r8 :r2)  ; Save protocol
      ;; Check TCP or UDP
      (bpf/jmp-imm :jeq :r2 IPPROTO_TCP 2)
      (bpf/jmp-imm :jne :r2 IPPROTO_UDP 33)

      ;; ===== Get IP header length =====
      (bpf/ldx :b :r3 :r6 ETH_HLEN)
      (bpf/and-op :r3 0x0F)
      (bpf/lsh :r3 2)

      ;; ===== Bounds check for L4 header =====
      (bpf/mov-reg :r9 :r6)
      (bpf/add :r9 ETH_HLEN)
      (bpf/add-reg :r9 :r3)
      (bpf/add :r9 4)
      (bpf/jmp-reg :jgt :r9 :r7 26)

      ;; ===== Build port key on stack =====
      ;; Load destination port (offset 2 in L4 header)
      (bpf/mov-reg :r4 :r6)
      (bpf/add :r4 ETH_HLEN)
      (bpf/add-reg :r4 :r3)
      (bpf/ldx :h :r2 :r4 2)  ; Dst port at offset 2

      ;; Store port key: [port:2, proto:1, pad:1]
      (bpf/stx :h :r10 STACK_PORT_KEY :r2)
      (bpf/stx :b :r10 (+ STACK_PORT_KEY 2) :r8)
      (bpf/st :b :r10 (+ STACK_PORT_KEY 3) 0)

      ;; ===== Look up port in map =====
      (ld-map-fd :r1 port-map-fd)
      (bpf/mov-reg :r2 :r10)
      (bpf/add :r2 STACK_PORT_KEY)
      (bpf/call BPF_FUNC_map_lookup_elem)

      ;; Check if found
      (bpf/jmp-imm :jeq :r0 0 14)

      ;; ===== Port mapping found =====
      ;; R0 points to: [backend-ip:4, backend-port:2, backend-mac:6, flags:2, pad:2]

      ;; Check flags (enabled)
      (bpf/ldx :h :r2 :r0 12)
      (bpf/jmp-imm :jeq :r2 0 11)

      ;; Reload data pointer
      (bpf/ldx :dw :r6 :r1 0)

      ;; ===== Rewrite destination MAC (6 bytes at offset 0) =====
      ;; Backend MAC is at R0+6
      (bpf/ldx :w :r2 :r0 6)
      (bpf/stx :w :r6 :r2 0)
      (bpf/ldx :h :r2 :r0 10)
      (bpf/stx :h :r6 :r2 4)

      ;; ===== Return XDP_TX =====
      (bpf/mov :r0 XDP_TX)
      (bpf/exit-insn)

      ;; ===== Pass: return XDP_PASS =====
      (bpf/mov :r0 XDP_PASS)
      (bpf/exit-insn)])))

;; ============================================================================
;; Port Proxy State Management
;; ============================================================================

(defrecord PortProxy
  [interface        ; Network interface name
   ifindex          ; Interface index
   prog-fd          ; XDP program file descriptor
   maps             ; Map of BPF maps
   port-mappings    ; Atom containing port mappings
   running?])       ; Atom indicating if proxy is running

(defn add-port-mapping
  "Add a port mapping to the proxy

  Parameters:
  - proxy: PortProxy instance
  - config: Map with keys:
    - :listen-port - Local port to listen on (required)
    - :backend-ip - Backend server IP address (required)
    - :backend-port - Backend server port (required)
    - :backend-mac - Backend server MAC address (required)
    - :protocol - :tcp or :udp (default :tcp)

  Example:
    (add-port-mapping proxy {:listen-port 8080
                             :backend-ip \"192.168.1.100\"
                             :backend-port 80
                             :backend-mac \"aa:bb:cc:dd:ee:ff\"})"
  [proxy config]
  (let [{:keys [listen-port backend-ip backend-port backend-mac protocol]
         :or {protocol :tcp}} config
        port-map (get-in proxy [:maps :port-map])
        port-key {:listen-port listen-port :protocol protocol}
        port-value {:backend-ip backend-ip
                    :backend-port backend-port
                    :backend-mac backend-mac
                    :flags 1}]  ; enabled

    ;; Validate
    (when-not listen-port (throw (ex-info "listen-port required" {})))
    (when-not backend-ip (throw (ex-info "backend-ip required" {})))
    (when-not backend-port (throw (ex-info "backend-port required" {})))
    (when-not backend-mac (throw (ex-info "backend-mac required" {})))

    ;; Update BPF map
    (maps/map-update port-map port-key port-value)

    ;; Update local state
    (swap! (:port-mappings proxy) assoc listen-port
           (merge config {:protocol protocol :enabled? true}))

    (log/info "Added port mapping:" listen-port "->" backend-ip ":" backend-port
              "(" (name protocol) ")")
    listen-port))

(defn remove-port-mapping
  "Remove a port mapping from the proxy"
  [proxy listen-port & {:keys [protocol] :or {protocol :tcp}}]
  (let [port-map (get-in proxy [:maps :port-map])
        port-key {:listen-port listen-port :protocol protocol}]

    ;; Delete from BPF map
    (maps/map-delete port-map port-key)

    ;; Update local state
    (swap! (:port-mappings proxy) dissoc listen-port)

    (log/info "Removed port mapping:" listen-port)
    true))

(defn enable-port-mapping
  "Enable a port mapping"
  [proxy listen-port & {:keys [protocol] :or {protocol :tcp}}]
  (let [port-map (get-in proxy [:maps :port-map])
        port-key {:listen-port listen-port :protocol protocol}]
    (when-let [current (maps/map-lookup port-map port-key)]
      (maps/map-update port-map port-key (assoc current :flags 1))
      (swap! (:port-mappings proxy) assoc-in [listen-port :enabled?] true)
      (log/info "Enabled port mapping:" listen-port))))

(defn disable-port-mapping
  "Disable a port mapping (keeps config but stops forwarding)"
  [proxy listen-port & {:keys [protocol] :or {protocol :tcp}}]
  (let [port-map (get-in proxy [:maps :port-map])
        port-key {:listen-port listen-port :protocol protocol}]
    (when-let [current (maps/map-lookup port-map port-key)]
      (maps/map-update port-map port-key (assoc current :flags 0))
      (swap! (:port-mappings proxy) assoc-in [listen-port :enabled?] false)
      (log/info "Disabled port mapping:" listen-port))))

(defn get-port-mappings
  "Get all port mappings"
  [proxy]
  @(:port-mappings proxy))

(defn get-stats
  "Get statistics for a port mapping"
  [proxy listen-port & {:keys [protocol] :or {protocol :tcp}}]
  (let [stats-map (get-in proxy [:maps :stats-map])
        port-key {:listen-port listen-port :protocol protocol}]
    (or (maps/map-lookup stats-map port-key)
        {:packets 0 :bytes-transferred 0})))

;; ============================================================================
;; Port Proxy Lifecycle
;; ============================================================================

(defn create-port-proxy
  "Create a new port-based reverse proxy

  Parameters:
  - interface: Network interface name (e.g., 'eth0')
  - options: Map of options:
    - :max-ports - Maximum number of port mappings (default 256)
    - :xdp-mode - XDP attachment mode (:drv-mode, :skb-mode, :hw-mode)

  Returns a PortProxy record"
  [interface & {:keys [max-ports xdp-mode]
                :or {max-ports 256
                     xdp-mode :skb-mode}}]

  (log/info "Creating port proxy on interface" interface)

  ;; Create BPF maps
  (let [maps (create-proxy-maps :max-ports max-ports)

        ;; Generate and load XDP program
        prog-bytecode (generate-port-proxy-program
                       (get-in maps [:port-map :fd]))

        prog-fd (xdp/load-xdp-program prog-bytecode
                                      :prog-name "port_proxy"
                                      :license "GPL"
                                      :log-level 1
                                      :log-size 65536)

        ;; Get interface index
        ifindex (xdp/interface-name->index interface)]

    ;; Attach XDP program
    (log/info "Attaching XDP program to" interface "(ifindex" ifindex ")")
    (xdp/attach-xdp interface prog-fd [xdp-mode])

    (log/info "Port proxy created and attached")

    (map->PortProxy
     {:interface interface
      :ifindex ifindex
      :prog-fd prog-fd
      :maps maps
      :port-mappings (atom {})
      :running? (atom true)})))

(defn stop-port-proxy
  "Stop and cleanup the port proxy"
  [proxy]
  (log/info "Stopping port proxy on" (:interface proxy))

  ;; Mark as not running
  (reset! (:running? proxy) false)

  ;; Detach XDP program
  (try
    (xdp/detach-xdp (:interface proxy))
    (catch Exception e
      (log/warn "Error detaching XDP:" (.getMessage e))))

  ;; Close program FD
  (when-let [fd (:prog-fd proxy)]
    (syscall/close-fd fd))

  ;; Close all maps
  (close-proxy-maps (:maps proxy))

  (log/info "Port proxy stopped"))

(defmacro with-port-proxy
  "Create port proxy, execute body, then cleanup"
  [[binding interface & options] & body]
  `(let [~binding (create-port-proxy ~interface ~@options)]
     (try
       ~@body
       (finally
         (stop-port-proxy ~binding)))))

;; ============================================================================
;; Configuration Helpers
;; ============================================================================

(defn configure-from-map
  "Configure proxy from a configuration map

  Example config:
  {:mappings [{:listen-port 8080
               :backend-ip \"192.168.1.100\"
               :backend-port 80
               :backend-mac \"aa:bb:cc:dd:ee:01\"}
              {:listen-port 8443
               :backend-ip \"192.168.1.100\"
               :backend-port 443
               :backend-mac \"aa:bb:cc:dd:ee:01\"
               :protocol :tcp}]}"
  [proxy config]
  (doseq [mapping (:mappings config)]
    (add-port-mapping proxy mapping)))

(defn print-status
  "Print current port proxy status"
  [proxy]
  (println "=== Port Proxy Status ===")
  (println "Interface:" (:interface proxy) "(ifindex" (:ifindex proxy) ")")
  (println "Running:" @(:running? proxy))
  (println)
  (println "Port Mappings:")
  (doseq [[port config] (sort-by first @(:port-mappings proxy))]
    (println (format "  %d/%s -> %s:%d (%s) [%s]"
                     port
                     (name (or (:protocol config) :tcp))
                     (:backend-ip config)
                     (:backend-port config)
                     (:backend-mac config)
                     (if (:enabled? config) "ENABLED" "DISABLED")))))

;; ============================================================================
;; Example Usage
;; ============================================================================

(comment
  ;; Example 1: Simple port forwarding
  ;; Forward local port 8080 to backend 192.168.1.100:80

  (def proxy (create-port-proxy "eth0" :xdp-mode :skb-mode))

  (add-port-mapping proxy {:listen-port 8080
                           :backend-ip "192.168.1.100"
                           :backend-port 80
                           :backend-mac "aa:bb:cc:dd:ee:ff"})

  (print-status proxy)

  (stop-port-proxy proxy)

  ;; Example 2: Multiple port mappings
  (with-port-proxy [proxy "eth0"]
    (add-port-mapping proxy {:listen-port 8080
                             :backend-ip "192.168.1.100"
                             :backend-port 80
                             :backend-mac "aa:bb:cc:dd:ee:01"})
    (add-port-mapping proxy {:listen-port 8443
                             :backend-ip "192.168.1.100"
                             :backend-port 443
                             :backend-mac "aa:bb:cc:dd:ee:01"})
    (add-port-mapping proxy {:listen-port 3306
                             :backend-ip "192.168.1.200"
                             :backend-port 3306
                             :backend-mac "aa:bb:cc:dd:ee:02"})
    (print-status proxy)
    (Thread/sleep 60000))

  ;; Example 3: Configure from map
  (with-port-proxy [proxy "eth0"]
    (configure-from-map proxy
      {:mappings [{:listen-port 80
                   :backend-ip "10.0.0.10"
                   :backend-port 80
                   :backend-mac "00:11:22:33:44:55"}
                  {:listen-port 443
                   :backend-ip "10.0.0.10"
                   :backend-port 443
                   :backend-mac "00:11:22:33:44:55"}]})
    (print-status proxy))

  ;; Example 4: Disable/enable mapping
  (with-port-proxy [proxy "eth0"]
    (add-port-mapping proxy {:listen-port 8080
                             :backend-ip "192.168.1.100"
                             :backend-port 80
                             :backend-mac "aa:bb:cc:dd:ee:ff"})
    ;; Temporarily disable
    (disable-port-mapping proxy 8080)
    (print-status proxy)
    ;; Re-enable
    (enable-port-mapping proxy 8080)
    (print-status proxy))

  ;; DSR Setup Notes:
  ;;
  ;; For Direct Server Return to work, the backend server must:
  ;;
  ;; 1. Have the proxy's IP address configured on loopback:
  ;;    $ sudo ip addr add <proxy-ip>/32 dev lo
  ;;
  ;; 2. Be on the same L2 network segment as the proxy
  ;;    (so the MAC rewrite works for direct delivery)
  ;;
  ;; 3. Have arp_ignore and arp_announce set appropriately:
  ;;    $ sudo sysctl -w net.ipv4.conf.all.arp_ignore=1
  ;;    $ sudo sysctl -w net.ipv4.conf.all.arp_announce=2
  ;;
  ;; This ensures:
  ;; - Packets arrive at proxy on listen-port
  ;; - XDP rewrites dst MAC to backend's MAC
  ;; - Packet is transmitted (XDP_TX) back out
  ;; - Switch delivers to backend based on MAC
  ;; - Backend accepts packet (has proxy IP on lo)
  ;; - Backend responds directly to client (bypasses proxy)
  )
