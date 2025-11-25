(ns clj-ebpf.generators
  "Property-based testing generators for BPF operations.

   Provides test.check generators for:
   - BPF map configurations
   - Key/value data
   - BPF instructions
   - Network packets
   - Event structures"
  (:require [clojure.test.check.generators :as gen]))

;; ============================================================================
;; Primitive Generators
;; ============================================================================

(def gen-u8
  "Generate unsigned 8-bit integers"
  (gen/choose 0 255))

(def gen-u16
  "Generate unsigned 16-bit integers"
  (gen/choose 0 65535))

(def gen-u32
  "Generate unsigned 32-bit integers"
  (gen/choose 0 0xFFFFFFFF))

(def gen-u64
  "Generate unsigned 64-bit integers"
  gen/large-integer)

(def gen-i32
  "Generate signed 32-bit integers"
  (gen/choose Integer/MIN_VALUE Integer/MAX_VALUE))

(def gen-i64
  "Generate signed 64-bit integers"
  gen/large-integer)

(defn gen-byte-array
  "Generate a byte array of the given size"
  [size]
  (gen/fmap byte-array (gen/vector gen-u8 size)))

(defn gen-byte-array-range
  "Generate a byte array with size in [min-size, max-size]"
  [min-size max-size]
  (gen/bind (gen/choose min-size max-size)
            gen-byte-array))

;; ============================================================================
;; BPF Map Generators
;; ============================================================================

(def gen-map-type
  "Generate valid BPF map types"
  (gen/elements [:hash :array :percpu-hash :percpu-array
                 :lru-hash :lru-percpu-hash
                 :lpm-trie :hash-of-maps :array-of-maps
                 :stack :queue :ringbuf :bloom-filter]))

(def gen-hash-map-type
  "Generate hash-based map types"
  (gen/elements [:hash :percpu-hash :lru-hash :lru-percpu-hash]))

(def gen-array-map-type
  "Generate array-based map types"
  (gen/elements [:array :percpu-array]))

(def gen-key-size
  "Generate valid key sizes (4-256 bytes, aligned)"
  (gen/fmap #(* 4 %) (gen/choose 1 64)))

(def gen-value-size
  "Generate valid value sizes (1-4096 bytes)"
  (gen/choose 1 4096))

(def gen-max-entries
  "Generate reasonable max_entries values"
  (gen/one-of
   [(gen/choose 1 100)        ; Small maps
    (gen/choose 100 1000)     ; Medium maps
    (gen/choose 1000 10000)])) ; Large maps

;; Map flag constants (duplicated here to avoid circular deps)
(def ^:private BPF_F_NO_PREALLOC 1)
(def ^:private BPF_F_RDONLY_PROG 128)
(def ^:private BPF_F_WRONLY_PROG 256)

(def gen-map-flags
  "Generate map flags combinations"
  (gen/one-of
   [(gen/return 0)
    (gen/return BPF_F_NO_PREALLOC)
    (gen/return BPF_F_RDONLY_PROG)
    (gen/return BPF_F_WRONLY_PROG)]))

(def gen-map-config
  "Generate complete map configuration"
  (gen/let [map-type gen-map-type
            key-size (if (#{:array :percpu-array :stack :queue} map-type)
                       (gen/return 4)
                       gen-key-size)
            value-size gen-value-size
            max-entries gen-max-entries]
    {:type map-type
     :key-size key-size
     :value-size value-size
     :max-entries max-entries}))

(def gen-hash-map-config
  "Generate hash map configuration"
  (gen/let [map-type gen-hash-map-type
            key-size gen-key-size
            value-size gen-value-size
            max-entries gen-max-entries]
    {:type map-type
     :key-size key-size
     :value-size value-size
     :max-entries max-entries}))

;; ============================================================================
;; Key/Value Generators
;; ============================================================================

(defn gen-key
  "Generate a key for the given key size"
  [key-size]
  (gen-byte-array key-size))

(defn gen-value
  "Generate a value for the given value size"
  [value-size]
  (gen-byte-array value-size))

(defn gen-kv-pair
  "Generate a key-value pair"
  [key-size value-size]
  (gen/tuple (gen-key key-size) (gen-value value-size)))

(defn gen-kv-batch
  "Generate a batch of key-value pairs"
  [key-size value-size batch-size]
  (gen/vector (gen-kv-pair key-size value-size) batch-size))

(defn gen-unique-keys
  "Generate n unique keys of the given size"
  [n key-size]
  (gen/fmap (fn [keys]
              (->> keys
                   (map #(vec %))
                   distinct
                   (take n)
                   (mapv byte-array)))
            (gen/vector (gen-byte-array key-size) (* n 2))))

;; ============================================================================
;; BPF Instruction Generators
;; ============================================================================

(def gen-register
  "Generate a BPF register (r0-r10)"
  (gen/elements [:r0 :r1 :r2 :r3 :r4 :r5 :r6 :r7 :r8 :r9 :r10]))

(def gen-writable-register
  "Generate a writable register (r0-r9, excluding r10/fp)"
  (gen/elements [:r0 :r1 :r2 :r3 :r4 :r5 :r6 :r7 :r8 :r9]))

(def gen-arg-register
  "Generate argument registers (r1-r5)"
  (gen/elements [:r1 :r2 :r3 :r4 :r5]))

(def gen-callee-saved-register
  "Generate callee-saved registers (r6-r9)"
  (gen/elements [:r6 :r7 :r8 :r9]))

(def gen-imm32
  "Generate 32-bit immediate value"
  gen-i32)

(def gen-offset
  "Generate memory offset (-32768 to 32767)"
  (gen/choose -32768 32767))

(def gen-alu-op
  "Generate ALU operation"
  (gen/elements [:add :sub :mul :div :mod :or :and :xor :lsh :rsh :arsh :neg]))

(def gen-jmp-op
  "Generate jump operation"
  (gen/elements [:jeq :jne :jgt :jge :jlt :jle :jset :jsgt :jsge :jslt :jsle]))

(def gen-size
  "Generate memory access size"
  (gen/elements [:b :h :w :dw]))

;; ============================================================================
;; Network Packet Generators
;; ============================================================================

(def gen-mac-address
  "Generate a MAC address as 6 bytes"
  (gen-byte-array 6))

(def gen-ipv4-address
  "Generate an IPv4 address as 4 bytes"
  (gen-byte-array 4))

(def gen-ipv6-address
  "Generate an IPv6 address as 16 bytes"
  (gen-byte-array 16))

(def gen-port
  "Generate a TCP/UDP port number"
  (gen/choose 1 65535))

(def gen-well-known-port
  "Generate a well-known port"
  (gen/elements [80 443 22 21 25 53 110 143 993 995 3306 5432 6379 27017]))

(def gen-protocol
  "Generate IP protocol number"
  (gen/elements [1 6 17]))  ; ICMP, TCP, UDP

(def gen-ethernet-type
  "Generate Ethernet type"
  (gen/elements [0x0800 0x0806 0x86DD]))  ; IPv4, ARP, IPv6

(def gen-ethernet-header
  "Generate Ethernet header (14 bytes)"
  (gen/let [dst-mac gen-mac-address
            src-mac gen-mac-address
            eth-type gen-ethernet-type]
    {:dst-mac dst-mac
     :src-mac src-mac
     :eth-type eth-type}))

(def gen-ipv4-header
  "Generate IPv4 header fields"
  (gen/let [src-ip gen-ipv4-address
            dst-ip gen-ipv4-address
            protocol gen-protocol
            ttl (gen/choose 1 255)
            id gen-u16]
    {:version 4
     :ihl 5
     :tos 0
     :total-length 40  ; Will be adjusted
     :id id
     :flags 0
     :frag-offset 0
     :ttl ttl
     :protocol protocol
     :checksum 0  ; Will be computed
     :src-ip src-ip
     :dst-ip dst-ip}))

(def gen-tcp-header
  "Generate TCP header fields"
  (gen/let [src-port gen-port
            dst-port gen-port
            seq-num gen-u32
            ack-num gen-u32
            flags (gen/elements [0x02 0x10 0x12 0x18])]  ; SYN, ACK, SYN-ACK, PSH-ACK
    {:src-port src-port
     :dst-port dst-port
     :seq-num seq-num
     :ack-num ack-num
     :data-offset 5
     :flags flags
     :window 65535
     :checksum 0
     :urgent 0}))

(def gen-udp-header
  "Generate UDP header fields"
  (gen/let [src-port gen-port
            dst-port gen-port
            length (gen/choose 8 1500)]
    {:src-port src-port
     :dst-port dst-port
     :length length
     :checksum 0}))

;; ============================================================================
;; Event Structure Generators
;; ============================================================================

(def gen-timestamp
  "Generate a nanosecond timestamp"
  (gen/fmap (fn [_] (System/nanoTime)) (gen/return nil)))

(def gen-pid
  "Generate a process ID"
  (gen/choose 1 65535))

(def gen-tid
  "Generate a thread ID"
  (gen/choose 1 65535))

(def gen-uid
  "Generate a user ID"
  (gen/choose 0 65535))

(def gen-comm
  "Generate a process comm (max 16 chars)"
  (gen/fmap (fn [s] (subs s 0 (min 15 (count s))))
            (gen/not-empty gen/string-alphanumeric)))

(def gen-event-type
  "Generate an event type"
  (gen/choose 0 255))

(def gen-syscall-event
  "Generate a syscall event structure"
  (gen/let [event-type gen-event-type
            timestamp gen-timestamp
            pid gen-pid
            tid gen-tid
            uid gen-uid
            syscall-nr (gen/choose 0 500)
            retval gen-i64]
    {:type event-type
     :timestamp timestamp
     :pid pid
     :tid tid
     :uid uid
     :syscall-nr syscall-nr
     :retval retval}))

(def gen-network-event
  "Generate a network event structure"
  (gen/let [event-type gen-event-type
            timestamp gen-timestamp
            pid gen-pid
            src-ip gen-ipv4-address
            dst-ip gen-ipv4-address
            src-port gen-port
            dst-port gen-port
            protocol gen-protocol
            bytes-sent gen-u32
            bytes-recv gen-u32]
    {:type event-type
     :timestamp timestamp
     :pid pid
     :src-ip src-ip
     :dst-ip dst-ip
     :src-port src-port
     :dst-port dst-port
     :protocol protocol
     :bytes-sent bytes-sent
     :bytes-recv bytes-recv}))

;; ============================================================================
;; Composite Generators
;; ============================================================================

(defn gen-map-operations
  "Generate a sequence of map operations"
  [key-size value-size]
  (gen/vector
   (gen/one-of
    [(gen/fmap (fn [k] {:op :lookup :key k})
               (gen-key key-size))
     (gen/let [k (gen-key key-size)
               v (gen-value value-size)]
       {:op :update :key k :value v})
     (gen/fmap (fn [k] {:op :delete :key k})
               (gen-key key-size))])
   1 100))

(defn gen-batch-operation
  "Generate a batch operation"
  [key-size value-size]
  (gen/let [op-type (gen/elements [:lookup-batch :update-batch :delete-batch])
            batch-size (gen/choose 1 100)
            keys (gen-unique-keys batch-size key-size)
            values (gen/vector (gen-value value-size) batch-size)]
    (case op-type
      :lookup-batch {:op op-type :keys keys}
      :update-batch {:op op-type :keys keys :values values}
      :delete-batch {:op op-type :keys keys})))
