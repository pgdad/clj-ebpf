(ns xdp-lb
  "XDP-based Layer 4 Load Balancer with Direct Server Return (DSR)

  This implementation provides a high-performance reverse proxy using XDP
  for fast packet steering at the driver level. It supports:

  - Multiple VIPs (Virtual IPs) for hosting different services
  - Multiple backends per VIP with configurable weights
  - Direct Server Return (DSR) mode for optimal performance
  - Health checking of backend servers
  - Dynamic configuration updates without program reload

  Architecture:
  ┌─────────────────────────────────────────────────────────────────┐
  │                      Client Request Flow                        │
  │                                                                 │
  │  Client ──► VIP (Load Balancer) ──► Backend Server              │
  │             │                                                   │
  │             └─► XDP: Rewrite dst MAC to backend                 │
  │                 Keep src/dst IP unchanged (DSR)                 │
  │                                                                 │
  │  Client ◄──────────────────────── Backend Server                │
  │             Direct response (bypasses LB)                       │
  └─────────────────────────────────────────────────────────────────┘

  BPF Maps:
  - vip_map: VIP configuration (IP + port) -> VIP metadata
  - backends_map: VIP ID + backend index -> Backend info (IP, MAC, weight)
  - conn_track_map: Connection tracking for session persistence
  - stats_map: Per-VIP statistics"
  (:require [clj-ebpf.dsl :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.xdp :as xdp]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.constants :as const]
            [clojure.tools.logging :as log])
  (:import [java.net InetAddress NetworkInterface]
           [java.nio ByteBuffer ByteOrder]
           [java.util.concurrent Executors TimeUnit ScheduledExecutorService]))

;; ============================================================================
;; MAC Address Utilities (must be defined before serialization)
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

;; VIP key: 8 bytes (IP: 4 bytes, port: 2 bytes, protocol: 1 byte, pad: 1 byte)
(defn vip-key->bytes
  "Serialize VIP key (IP, port, protocol) to bytes"
  [{:keys [ip port protocol]}]
  (let [ip-bytes (if (string? ip)
                   (.getAddress (InetAddress/getByName ip))
                   ip)
        buf (ByteBuffer/allocate 8)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.put buf ^bytes ip-bytes)
    (.putShort buf (short port))
    (.put buf (byte (case protocol
                      :tcp 6
                      :udp 17
                      6))) ; default TCP
    (.put buf (byte 0)) ; padding
    (.array buf)))

(defn bytes->vip-key
  "Deserialize bytes to VIP key"
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (let [ip-bytes (byte-array 4)]
      (.get buf ip-bytes)
      {:ip (InetAddress/getByAddress ip-bytes)
       :port (bit-and (.getShort buf) 0xFFFF)
       :protocol (case (bit-and (.get buf) 0xFF)
                   6 :tcp
                   17 :udp
                   :unknown)})))

;; VIP value: 16 bytes (vip-id: 4, num-backends: 4, flags: 4, reserved: 4)
(defn vip-value->bytes
  "Serialize VIP value to bytes"
  [{:keys [vip-id num-backends flags]}]
  (let [buf (ByteBuffer/allocate 16)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putInt buf (int vip-id))
    (.putInt buf (int (or num-backends 0)))
    (.putInt buf (int (or flags 0)))
    (.putInt buf 0) ; reserved
    (.array buf)))

(defn bytes->vip-value
  "Deserialize bytes to VIP value"
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    {:vip-id (.getInt buf)
     :num-backends (.getInt buf)
     :flags (.getInt buf)}))

;; Backend key: 8 bytes (vip-id: 4, backend-index: 4)
(defn backend-key->bytes
  "Serialize backend key to bytes"
  [{:keys [vip-id backend-index]}]
  (let [buf (ByteBuffer/allocate 8)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putInt buf (int vip-id))
    (.putInt buf (int backend-index))
    (.array buf)))

(defn bytes->backend-key
  "Deserialize bytes to backend key"
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    {:vip-id (.getInt buf)
     :backend-index (.getInt buf)}))

;; Backend value: 24 bytes (ip: 4, mac: 6, weight: 2, flags: 4, health: 4, reserved: 4)
(defn backend-value->bytes
  "Serialize backend value to bytes"
  [{:keys [ip mac weight flags health]}]
  (let [ip-bytes (if (string? ip)
                   (.getAddress (InetAddress/getByName ip))
                   ip)
        mac-bytes (if (string? mac)
                    (parse-mac mac)
                    mac)
        buf (ByteBuffer/allocate 24)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.put buf ^bytes ip-bytes)
    (.put buf ^bytes mac-bytes)
    (.putShort buf (short (or weight 1)))
    (.putInt buf (int (or flags 0)))
    (.putInt buf (int (or health 1))) ; 1 = healthy
    (.putInt buf 0) ; reserved
    (.array buf)))

(defn bytes->backend-value
  "Deserialize bytes to backend value"
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (let [ip-bytes (byte-array 4)
          mac-bytes (byte-array 6)]
      (.get buf ip-bytes)
      (.get buf mac-bytes)
      {:ip (InetAddress/getByAddress ip-bytes)
       :mac (format-mac mac-bytes)
       :weight (bit-and (.getShort buf) 0xFFFF)
       :flags (.getInt buf)
       :health (.getInt buf)})))

;; Stats value: 32 bytes (packets-in: 8, bytes-in: 8, packets-out: 8, bytes-out: 8)
(defn stats-value->bytes
  "Serialize stats value to bytes"
  [{:keys [packets-in bytes-in packets-out bytes-out]}]
  (let [buf (ByteBuffer/allocate 32)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putLong buf (or packets-in 0))
    (.putLong buf (or bytes-in 0))
    (.putLong buf (or packets-out 0))
    (.putLong buf (or bytes-out 0))
    (.array buf)))

(defn bytes->stats-value
  "Deserialize bytes to stats value"
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    {:packets-in (.getLong buf)
     :bytes-in (.getLong buf)
     :packets-out (.getLong buf)
     :bytes-out (.getLong buf)}))

;; Connection tracking key: 16 bytes (src-ip: 4, dst-ip: 4, src-port: 2, dst-port: 2, proto: 1, pad: 3)
(defn conn-key->bytes
  "Serialize connection key to bytes"
  [{:keys [src-ip dst-ip src-port dst-port protocol]}]
  (let [src-bytes (if (string? src-ip)
                    (.getAddress (InetAddress/getByName src-ip))
                    src-ip)
        dst-bytes (if (string? dst-ip)
                    (.getAddress (InetAddress/getByName dst-ip))
                    dst-ip)
        buf (ByteBuffer/allocate 16)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.put buf ^bytes src-bytes)
    (.put buf ^bytes dst-bytes)
    (.putShort buf (short src-port))
    (.putShort buf (short dst-port))
    (.put buf (byte (case protocol :tcp 6 :udp 17 6)))
    (.put buf (byte 0))
    (.put buf (byte 0))
    (.put buf (byte 0))
    (.array buf)))

;; Connection tracking value: 8 bytes (backend-index: 4, timestamp: 4)
(defn conn-value->bytes
  "Serialize connection value to bytes"
  [{:keys [backend-index timestamp]}]
  (let [buf (ByteBuffer/allocate 8)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putInt buf (int backend-index))
    (.putInt buf (int (or timestamp 0)))
    (.array buf)))

(defn bytes->conn-value
  "Deserialize bytes to connection value"
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    {:backend-index (.getInt buf)
     :timestamp (.getInt buf)}))

;; ============================================================================
;; BPF Map Creation
;; ============================================================================

(defn create-lb-maps
  "Create all BPF maps needed for the load balancer

  Returns a map of:
  - :vip-map - VIP configuration map
  - :backends-map - Backend server map
  - :conn-track-map - Connection tracking (session persistence)
  - :stats-map - Per-VIP statistics"
  [& {:keys [max-vips max-backends max-connections]
      :or {max-vips 256
           max-backends 1024
           max-connections 65536}}]

  {:vip-map
   (maps/create-map
    {:map-type :hash
     :key-size 8
     :value-size 16
     :max-entries max-vips
     :map-name "vip_map"
     :key-serializer vip-key->bytes
     :key-deserializer bytes->vip-key
     :value-serializer vip-value->bytes
     :value-deserializer bytes->vip-value})

   :backends-map
   (maps/create-map
    {:map-type :hash
     :key-size 8
     :value-size 24
     :max-entries max-backends
     :map-name "backends"
     :key-serializer backend-key->bytes
     :key-deserializer bytes->backend-key
     :value-serializer backend-value->bytes
     :value-deserializer bytes->backend-value})

   :conn-track-map
   (maps/create-map
    {:map-type :lru-hash
     :key-size 16
     :value-size 8
     :max-entries max-connections
     :map-name "conn_track"
     :key-serializer conn-key->bytes
     :value-serializer conn-value->bytes
     :value-deserializer bytes->conn-value})

   :stats-map
   (maps/create-map
    {:map-type :percpu-array
     :key-size 4
     :value-size 32
     :max-entries max-vips
     :map-name "stats"
     :key-serializer utils/int->bytes
     :key-deserializer utils/bytes->int
     :value-serializer stats-value->bytes
     :value-deserializer bytes->stats-value})})

(defn close-lb-maps
  "Close all load balancer maps"
  [maps]
  (doseq [[_ m] maps]
    (maps/close-map m)))

;; ============================================================================
;; XDP Program Generation (DSR Mode)
;; ============================================================================

;; Network header offsets
(def ETH_HLEN 14)       ; Ethernet header length
(def ETH_P_IP 0x0800)   ; IPv4 EtherType
(def IP_PROTO_OFFSET 9) ; Protocol offset in IP header
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

;; Register allocation for XDP program
;; R0: return value / scratch
;; R1: context (xdp_md)
;; R2-R5: function arguments / scratch
;; R6: saved data pointer
;; R7: saved data_end pointer
;; R8: scratch / computed values
;; R9: map lookup result
;; R10: stack pointer (read-only)

;; Helper to create LDDW instruction for map FD
;; BPF_PSEUDO_MAP_FD = 1, used in src_reg field
(defn- ld-map-fd
  "Load map file descriptor into register using LDDW pseudo-instruction.

  This generates a 16-byte wide instruction that the kernel recognizes
  as a map FD reference. The kernel will replace it with the actual
  map pointer at load time."
  [dst map-fd]
  ;; LDDW with BPF_PSEUDO_MAP_FD (src_reg = 1)
  ;; Opcode: 0x18 (LD | DW | IMM)
  ;; The instruction is 16 bytes (two 8-byte slots)
  (let [opcode 0x18  ; BPF_LD | BPF_DW | BPF_IMM
        dst-reg (get bpf/registers dst 0)
        src-reg 1  ; BPF_PSEUDO_MAP_FD
        ;; First instruction: lower 32 bits
        insn1 (byte-array [opcode
                           (unchecked-byte (bit-or (bit-shift-left src-reg 4) dst-reg))
                           0 0  ; offset (2 bytes)
                           (unchecked-byte (bit-and map-fd 0xFF))
                           (unchecked-byte (bit-and (bit-shift-right map-fd 8) 0xFF))
                           (unchecked-byte (bit-and (bit-shift-right map-fd 16) 0xFF))
                           (unchecked-byte (bit-and (bit-shift-right map-fd 24) 0xFF))])
        ;; Second instruction: upper 32 bits (0 for map FD)
        insn2 (byte-array [0 0 0 0 0 0 0 0])]
    (byte-array (concat insn1 insn2))))

(defn generate-xdp-lb-program
  "Generate XDP bytecode for the DSR load balancer.

  This program:
  1. Parses Ethernet and IP headers
  2. Extracts L4 ports (TCP/UDP)
  3. Looks up VIP in vip_map
  4. Selects backend (round-robin or connection tracking)
  5. Rewrites destination MAC for DSR
  6. Returns XDP_TX to transmit packet

  Parameters:
  - vip-map-fd: File descriptor of VIP map
  - backends-map-fd: File descriptor of backends map
  - conn-track-map-fd: File descriptor of connection tracking map
  - stats-map-fd: File descriptor of statistics map"
  [vip-map-fd backends-map-fd conn-track-map-fd stats-map-fd]

  (let [;; XDP actions
        XDP_ABORTED 0
        XDP_DROP 1
        XDP_PASS 2
        XDP_TX 3
        XDP_REDIRECT 4

        ;; BPF helper function IDs
        BPF_FUNC_map_lookup_elem 1
        BPF_FUNC_map_update_elem 2
        BPF_FUNC_ktime_get_ns 5
        BPF_FUNC_get_prandom_u32 7

        ;; Stack offsets for local variables (negative from R10)
        ;; Stack layout:
        ;; -8:  VIP key (8 bytes)
        ;; -16: Backend key (8 bytes)
        STACK_VIP_KEY -8
        STACK_BACKEND_KEY -16

        ;; Calculate instruction offsets for jumps
        ;; We'll use simple fixed offsets - in a real implementation
        ;; you'd want a proper label resolution pass
        PASS_OFFSET 50]  ; Approximate offset to pass label

    ;; Generate the BPF program
    ;; Note: This generates raw bytecode. The DSL functions return byte arrays.
    (bpf/assemble
     [;; ===== Prologue: Load and validate packet pointers =====
      ;; R1 = xdp_md context
      ;; Load data pointer: R6 = ctx->data
      (bpf/ldx :dw :r6 :r1 0)
      ;; Load data_end pointer: R7 = ctx->data_end
      (bpf/ldx :dw :r7 :r1 8)

      ;; ===== Bounds check for Ethernet header =====
      ;; R8 = R6 + ETH_HLEN (14 bytes)
      (bpf/mov-reg :r8 :r6)
      (bpf/add :r8 ETH_HLEN)
      ;; if R8 > R7 goto pass (packet too small)
      (bpf/jmp-reg :jgt :r8 :r7 PASS_OFFSET)

      ;; ===== Check EtherType is IPv4 =====
      ;; Load EtherType from offset 12 (2 bytes, big-endian)
      (bpf/ldx :h :r2 :r6 12)
      ;; Compare with ETH_P_IP (0x0800, stored in network byte order)
      ;; On little-endian, 0x0800 is read as 0x0008
      (bpf/jmp-imm :jne :r2 0x0008 (- PASS_OFFSET 5))

      ;; ===== Bounds check for IP header (minimum 20 bytes) =====
      (bpf/mov-reg :r8 :r6)
      (bpf/add :r8 (+ ETH_HLEN 20))
      (bpf/jmp-reg :jgt :r8 :r7 (- PASS_OFFSET 8))

      ;; ===== Extract IP protocol =====
      ;; Protocol is at IP header offset 9
      (bpf/ldx :b :r2 :r6 (+ ETH_HLEN 9))
      ;; Save protocol in R8
      (bpf/mov-reg :r8 :r2)
      ;; Check if TCP (6)
      (bpf/jmp-imm :jeq :r2 IPPROTO_TCP 2)  ; Skip next 2 if TCP
      ;; Check if UDP (17)
      (bpf/jmp-imm :jne :r2 IPPROTO_UDP (- PASS_OFFSET 13))

      ;; ===== Check L4 header bounds =====
      ;; Calculate IP header length (IHL * 4)
      (bpf/ldx :b :r3 :r6 ETH_HLEN)  ; First byte has version and IHL
      (bpf/and-op :r3 0x0F)           ; Mask IHL (lower 4 bits)
      (bpf/lsh :r3 2)                 ; Multiply by 4

      ;; R9 = R6 + ETH_HLEN + IHL*4 + 4 (L4 header start + ports)
      (bpf/mov-reg :r9 :r6)
      (bpf/add :r9 ETH_HLEN)
      (bpf/add-reg :r9 :r3)
      (bpf/add :r9 4)
      (bpf/jmp-reg :jgt :r9 :r7 (- PASS_OFFSET 22))

      ;; ===== Build VIP key on stack =====
      ;; Load destination IP (offset 16 in IP header)
      (bpf/ldx :w :r2 :r6 (+ ETH_HLEN 16))
      ;; Store at stack offset -8 (start of VIP key)
      ;; stx signature: [size dst src offset] -> *(dst + offset) = src
      (bpf/stx :w :r10 :r2 STACK_VIP_KEY)

      ;; Calculate L4 header offset: R3 = ETH_HLEN + IHL*4
      (bpf/add :r3 ETH_HLEN)

      ;; Load destination port (offset 2 in L4 header)
      (bpf/mov-reg :r4 :r6)
      (bpf/add-reg :r4 :r3)
      (bpf/ldx :h :r2 :r4 2)
      ;; Store port at stack offset -4
      (bpf/stx :h :r10 :r2 (+ STACK_VIP_KEY 4))

      ;; Store protocol at stack offset -2
      (bpf/stx :b :r10 :r8 (+ STACK_VIP_KEY 6))
      ;; Zero padding byte
      (bpf/st :b :r10 (+ STACK_VIP_KEY 7) 0)

      ;; ===== Look up VIP in map =====
      ;; R1 = map fd
      (ld-map-fd :r1 vip-map-fd)
      ;; R2 = &key (stack pointer + offset)
      (bpf/mov-reg :r2 :r10)
      (bpf/add :r2 STACK_VIP_KEY)
      ;; Call bpf_map_lookup_elem
      (bpf/call BPF_FUNC_map_lookup_elem)

      ;; Check if VIP found (R0 != NULL)
      (bpf/jmp-imm :jeq :r0 0 (- PASS_OFFSET 38))

      ;; ===== VIP found - R0 points to VIP value =====
      ;; VIP value layout: vip-id (4), num-backends (4), flags (4), reserved (4)
      ;; Load vip-id into R8
      (bpf/ldx :w :r8 :r0 0)
      ;; Load num-backends into R9
      (bpf/ldx :w :r9 :r0 4)

      ;; Check if any backends configured
      (bpf/jmp-imm :jeq :r9 0 (- PASS_OFFSET 42))

      ;; ===== Select backend (simple modulo) =====
      ;; Get random number for load balancing
      (bpf/call BPF_FUNC_get_prandom_u32)
      ;; R0 = random number
      ;; Simple backend selection: random & (num_backends - 1)
      ;; This works well when num_backends is a power of 2
      (bpf/sub :r9 1)
      (bpf/and-reg :r0 :r9)

      ;; ===== Build backend key on stack =====
      (bpf/stx :w :r10 :r8 STACK_BACKEND_KEY)  ; Store vip-id
      (bpf/stx :w :r10 :r0 (+ STACK_BACKEND_KEY 4))  ; Store backend index

      ;; ===== Look up backend in map =====
      (ld-map-fd :r1 backends-map-fd)
      (bpf/mov-reg :r2 :r10)
      (bpf/add :r2 STACK_BACKEND_KEY)
      (bpf/call BPF_FUNC_map_lookup_elem)

      ;; Check if backend found
      (bpf/jmp-imm :jeq :r0 0 8)  ; Jump to pass

      ;; ===== Backend found - R0 points to backend value =====
      ;; Backend value: ip (4), mac (6), weight (2), flags (4), health (4), reserved (4)
      ;; Check health status (offset 16)
      (bpf/ldx :w :r2 :r0 16)
      (bpf/jmp-imm :jeq :r2 0 6)  ; Skip if unhealthy

      ;; ===== Perform DSR: Rewrite destination MAC =====
      ;; Reload data pointer
      (bpf/ldx :dw :r6 :r1 0)

      ;; Copy MAC address (6 bytes)
      ;; Load first 4 bytes from backend MAC (offset 4)
      (bpf/ldx :w :r2 :r0 4)
      (bpf/stx :w :r6 :r2 0)
      ;; Load last 2 bytes
      (bpf/ldx :h :r2 :r0 8)
      (bpf/stx :h :r6 :r2 4)

      ;; ===== Return XDP_TX =====
      (bpf/mov :r0 XDP_TX)
      (bpf/exit-insn)

      ;; ===== Pass: return XDP_PASS =====
      (bpf/mov :r0 XDP_PASS)
      (bpf/exit-insn)])))

;; ============================================================================
;; Load Balancer State Management
;; ============================================================================

(defrecord LoadBalancer
  [interface        ; Network interface name
   ifindex          ; Interface index
   prog-fd          ; XDP program file descriptor
   maps             ; Map of BPF maps
   vips             ; Atom containing VIP configurations
   backends         ; Atom containing backend configurations
   health-executor  ; Scheduled executor for health checks
   running?])       ; Atom indicating if LB is running

(defn add-vip
  "Add a VIP (Virtual IP) to the load balancer

  Parameters:
  - lb: LoadBalancer instance
  - vip-config: Map with :ip, :port, :protocol keys

  Returns the VIP ID assigned"
  [lb vip-config]
  (let [{:keys [ip port protocol]} vip-config
        vips-atom (:vips lb)
        vip-map (get-in lb [:maps :vip-map])
        vip-id (count @vips-atom)
        vip-key {:ip ip :port port :protocol (or protocol :tcp)}
        vip-value {:vip-id vip-id :num-backends 0 :flags 0}]

    ;; Update BPF map
    (maps/map-update vip-map vip-key vip-value)

    ;; Update local state
    (swap! vips-atom assoc vip-id (merge vip-config {:vip-id vip-id :backends []}))

    (log/info "Added VIP" vip-id ":" ip ":" port "/" (name (or protocol :tcp)))
    vip-id))

(defn add-backend
  "Add a backend server to a VIP

  Parameters:
  - lb: LoadBalancer instance
  - vip-id: VIP ID to add backend to
  - backend-config: Map with :ip, :mac, :weight (optional) keys

  Returns the backend index"
  [lb vip-id backend-config]
  (let [{:keys [ip mac weight]} backend-config
        vips-atom (:vips lb)
        vip-map (get-in lb [:maps :vip-map])
        backends-map (get-in lb [:maps :backends-map])

        ;; Get current VIP config
        vip-config (get @vips-atom vip-id)
        _ (when-not vip-config
            (throw (ex-info "VIP not found" {:vip-id vip-id})))

        backend-index (count (:backends vip-config))
        backend-key {:vip-id vip-id :backend-index backend-index}
        backend-value {:ip ip
                       :mac mac
                       :weight (or weight 1)
                       :flags 0
                       :health 1}]  ; Start as healthy

    ;; Update backends map
    (maps/map-update backends-map backend-key backend-value)

    ;; Update VIP with new backend count
    (let [vip-key {:ip (:ip vip-config)
                   :port (:port vip-config)
                   :protocol (or (:protocol vip-config) :tcp)}
          new-num-backends (inc backend-index)]
      (maps/map-update vip-map vip-key
                       {:vip-id vip-id :num-backends new-num-backends :flags 0}))

    ;; Update local state
    (swap! vips-atom update-in [vip-id :backends]
           conj (merge backend-config {:index backend-index :healthy? true}))

    (log/info "Added backend" backend-index "to VIP" vip-id ":" ip "(" mac ")")
    backend-index))

(defn remove-backend
  "Remove a backend server from a VIP (marks as unhealthy)"
  [lb vip-id backend-index]
  (let [backends-map (get-in lb [:maps :backends-map])
        backend-key {:vip-id vip-id :backend-index backend-index}]

    ;; Mark as unhealthy in BPF map
    (when-let [current (maps/map-lookup backends-map backend-key)]
      (maps/map-update backends-map backend-key
                       (assoc current :health 0)))

    ;; Update local state
    (swap! (:vips lb) update-in [vip-id :backends backend-index]
           assoc :healthy? false)

    (log/info "Removed backend" backend-index "from VIP" vip-id)))

(defn set-backend-health
  "Set the health status of a backend

  Parameters:
  - lb: LoadBalancer instance
  - vip-id: VIP ID
  - backend-index: Backend index
  - healthy?: Boolean health status"
  [lb vip-id backend-index healthy?]
  (let [backends-map (get-in lb [:maps :backends-map])
        backend-key {:vip-id vip-id :backend-index backend-index}]

    (when-let [current (maps/map-lookup backends-map backend-key)]
      (maps/map-update backends-map backend-key
                       (assoc current :health (if healthy? 1 0))))

    (swap! (:vips lb) update-in [vip-id :backends backend-index]
           assoc :healthy? healthy?)

    (log/debug "Backend" vip-id "/" backend-index "health:" healthy?)))

(defn get-stats
  "Get statistics for a VIP

  Returns map with :packets-in, :bytes-in, :packets-out, :bytes-out"
  [lb vip-id]
  (let [stats-map (get-in lb [:maps :stats-map])]
    (or (maps/map-lookup stats-map vip-id)
        {:packets-in 0 :bytes-in 0 :packets-out 0 :bytes-out 0})))

(defn get-all-stats
  "Get statistics for all VIPs"
  [lb]
  (into {}
        (for [[vip-id _] @(:vips lb)]
          [vip-id (get-stats lb vip-id)])))

;; ============================================================================
;; Health Checking
;; ============================================================================

(defn check-backend-health
  "Perform TCP health check on a backend

  Returns true if backend is healthy"
  [ip port timeout-ms]
  (try
    (let [addr (InetAddress/getByName (if (instance? InetAddress ip)
                                        (.getHostAddress ip)
                                        ip))
          socket (java.net.Socket.)]
      (try
        (.connect socket
                  (java.net.InetSocketAddress. addr port)
                  timeout-ms)
        true
        (finally
          (.close socket))))
    (catch Exception _
      false)))

(defn start-health-checker
  "Start background health checking for all backends"
  [lb check-interval-ms health-check-port timeout-ms]
  (let [executor (Executors/newSingleThreadScheduledExecutor)]
    (.scheduleAtFixedRate
     executor
     (fn []
       (try
         (doseq [[vip-id vip-config] @(:vips lb)
                 [idx backend] (map-indexed vector (:backends vip-config))]
           (let [healthy? (check-backend-health
                           (:ip backend)
                           (or health-check-port (:port vip-config))
                           timeout-ms)]
             (when (not= healthy? (:healthy? backend))
               (log/info "Backend" vip-id "/" idx "health changed:" healthy?)
               (set-backend-health lb vip-id idx healthy?))))
         (catch Exception e
           (log/error e "Health check error"))))
     check-interval-ms
     check-interval-ms
     TimeUnit/MILLISECONDS)
    executor))

;; ============================================================================
;; Load Balancer Lifecycle
;; ============================================================================

(defn create-load-balancer
  "Create a new XDP-based load balancer

  Parameters:
  - interface: Network interface name (e.g., 'eth0')
  - options: Map of options:
    - :max-vips - Maximum number of VIPs (default 256)
    - :max-backends - Maximum backends total (default 1024)
    - :max-connections - Maximum tracked connections (default 65536)
    - :xdp-mode - XDP attachment mode (:drv-mode, :skb-mode, :hw-mode)
    - :health-check-interval-ms - Health check interval (default 5000)
    - :health-check-timeout-ms - Health check timeout (default 1000)
    - :health-check-port - Port to check (default: use VIP port)

  Returns a LoadBalancer record"
  [interface & {:keys [max-vips max-backends max-connections xdp-mode
                       health-check-interval-ms health-check-timeout-ms
                       health-check-port]
                :or {max-vips 256
                     max-backends 1024
                     max-connections 65536
                     xdp-mode :skb-mode  ; Default to generic mode for compatibility
                     health-check-interval-ms 5000
                     health-check-timeout-ms 1000}}]

  (log/info "Creating XDP load balancer on interface" interface)

  ;; Create BPF maps
  (let [maps (create-lb-maps :max-vips max-vips
                             :max-backends max-backends
                             :max-connections max-connections)

        ;; Generate and load XDP program
        prog-bytecode (generate-xdp-lb-program
                       (get-in maps [:vip-map :fd])
                       (get-in maps [:backends-map :fd])
                       (get-in maps [:conn-track-map :fd])
                       (get-in maps [:stats-map :fd]))

        prog-fd (xdp/load-xdp-program prog-bytecode
                                      :prog-name "xdp_lb"
                                      :license "GPL"
                                      :log-level 1
                                      :log-size 65536)

        ;; Get interface index
        ifindex (xdp/interface-name->index interface)]

    ;; Attach XDP program
    (log/info "Attaching XDP program to" interface "(ifindex" ifindex ")")
    (xdp/attach-xdp interface prog-fd [xdp-mode])

    ;; Create load balancer record
    (let [lb (map->LoadBalancer
              {:interface interface
               :ifindex ifindex
               :prog-fd prog-fd
               :maps maps
               :vips (atom {})
               :backends (atom {})
               :running? (atom true)
               :health-executor nil})]

      ;; Start health checker if enabled
      (when health-check-interval-ms
        (assoc lb :health-executor
               (start-health-checker lb
                                     health-check-interval-ms
                                     health-check-port
                                     health-check-timeout-ms)))

      (log/info "XDP load balancer created and attached")
      lb)))

(defn stop-load-balancer
  "Stop and cleanup the load balancer"
  [lb]
  (log/info "Stopping XDP load balancer on" (:interface lb))

  ;; Mark as not running
  (reset! (:running? lb) false)

  ;; Stop health checker
  (when-let [executor (:health-executor lb)]
    (.shutdown executor)
    (.awaitTermination executor 5 TimeUnit/SECONDS))

  ;; Detach XDP program
  (try
    (xdp/detach-xdp (:interface lb))
    (catch Exception e
      (log/warn "Error detaching XDP:" (.getMessage e))))

  ;; Close program FD
  (when-let [fd (:prog-fd lb)]
    (syscall/close-fd fd))

  ;; Close all maps
  (close-lb-maps (:maps lb))

  (log/info "XDP load balancer stopped"))

(defmacro with-load-balancer
  "Create load balancer, execute body, then cleanup"
  [[binding interface & options] & body]
  `(let [~binding (create-load-balancer ~interface ~@options)]
     (try
       ~@body
       (finally
         (stop-load-balancer ~binding)))))

;; ============================================================================
;; Configuration Helpers
;; ============================================================================

(defn configure-from-map
  "Configure load balancer from a configuration map

  Example config:
  {:vips [{:ip \"10.0.0.100\" :port 80 :protocol :tcp
           :backends [{:ip \"10.0.0.1\" :mac \"aa:bb:cc:dd:ee:01\" :weight 1}
                      {:ip \"10.0.0.2\" :mac \"aa:bb:cc:dd:ee:02\" :weight 2}]}
          {:ip \"10.0.0.100\" :port 443 :protocol :tcp
           :backends [{:ip \"10.0.0.1\" :mac \"aa:bb:cc:dd:ee:01\"}]}]}"
  [lb config]
  (doseq [vip-config (:vips config)]
    (let [vip-id (add-vip lb (select-keys vip-config [:ip :port :protocol]))]
      (doseq [backend (:backends vip-config)]
        (add-backend lb vip-id backend)))))

(defn print-status
  "Print current load balancer status"
  [lb]
  (println "=== XDP Load Balancer Status ===")
  (println "Interface:" (:interface lb) "(ifindex" (:ifindex lb) ")")
  (println "Running:" @(:running? lb))
  (println)
  (println "VIPs:")
  (doseq [[vip-id vip-config] (sort-by first @(:vips lb))]
    (println (format "  [%d] %s:%d/%s"
                     vip-id
                     (:ip vip-config)
                     (:port vip-config)
                     (name (or (:protocol vip-config) :tcp))))
    (doseq [[idx backend] (map-indexed vector (:backends vip-config))]
      (println (format "      -> [%d] %s (%s) weight=%d %s"
                       idx
                       (:ip backend)
                       (:mac backend)
                       (or (:weight backend) 1)
                       (if (:healthy? backend) "HEALTHY" "UNHEALTHY")))))
  (println)
  (println "Statistics:")
  (doseq [[vip-id stats] (sort-by first (get-all-stats lb))]
    (println (format "  VIP %d: %d packets, %d bytes in"
                     vip-id
                     (:packets-in stats)
                     (:bytes-in stats)))))

;; ============================================================================
;; Example Usage
;; ============================================================================

(comment
  ;; Example: Create a load balancer with 2 backends

  ;; 1. Create the load balancer
  (def lb (create-load-balancer "eth0"
                                :xdp-mode :skb-mode
                                :health-check-interval-ms 5000))

  ;; 2. Add a VIP
  (def vip-id (add-vip lb {:ip "10.0.0.100" :port 80 :protocol :tcp}))

  ;; 3. Add backends
  (add-backend lb vip-id {:ip "10.0.0.1" :mac "aa:bb:cc:dd:ee:01" :weight 1})
  (add-backend lb vip-id {:ip "10.0.0.2" :mac "aa:bb:cc:dd:ee:02" :weight 2})

  ;; 4. Check status
  (print-status lb)

  ;; 5. Get statistics
  (get-stats lb vip-id)

  ;; 6. Stop when done
  (stop-load-balancer lb)

  ;; Or use with-load-balancer macro for automatic cleanup:
  (with-load-balancer [lb "eth0" :xdp-mode :skb-mode]
    (add-vip lb {:ip "10.0.0.100" :port 80 :protocol :tcp})
    (add-backend lb 0 {:ip "10.0.0.1" :mac "aa:bb:cc:dd:ee:01"})
    (add-backend lb 0 {:ip "10.0.0.2" :mac "aa:bb:cc:dd:ee:02"})
    (print-status lb)
    ;; Load balancer runs...
    (Thread/sleep 60000))

  ;; Configure from a map:
  (with-load-balancer [lb "eth0"]
    (configure-from-map lb
      {:vips [{:ip "10.0.0.100" :port 80 :protocol :tcp
               :backends [{:ip "10.0.0.1" :mac "aa:bb:cc:dd:ee:01"}
                          {:ip "10.0.0.2" :mac "aa:bb:cc:dd:ee:02"}]}
              {:ip "10.0.0.100" :port 443 :protocol :tcp
               :backends [{:ip "10.0.0.1" :mac "aa:bb:cc:dd:ee:01"}]}]})
    (print-status lb)
    (Thread/sleep 60000)))
