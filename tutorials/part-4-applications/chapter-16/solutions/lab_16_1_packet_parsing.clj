(ns lab-16-1-packet-parsing
  "Lab 16.1: Packet Parsing

   This solution demonstrates:
   - Ethernet header parsing
   - IPv4 header parsing
   - TCP/UDP header parsing
   - Safe bounds checking
   - Protocol identification

   Run with: clojure -M -m lab-16-1-packet-parsing test"
  (:require [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Byte Buffer Utilities
;;; ============================================================================

(defn bytes->buffer
  "Create a ByteBuffer from byte array"
  [^bytes arr]
  (doto (ByteBuffer/wrap arr)
    (.order ByteOrder/BIG_ENDIAN)))

(defn read-u8
  "Read unsigned byte at offset"
  [^ByteBuffer buf offset]
  (bit-and 0xFF (.get buf offset)))

(defn read-u16
  "Read unsigned 16-bit value at offset (big endian)"
  [^ByteBuffer buf offset]
  (bit-and 0xFFFF (.getShort buf offset)))

(defn read-u32
  "Read unsigned 32-bit value at offset (big endian)"
  [^ByteBuffer buf offset]
  (bit-and 0xFFFFFFFF (.getInt buf offset)))

(defn read-bytes
  "Read bytes at offset"
  [^ByteBuffer buf offset length]
  (let [arr (byte-array length)]
    (doto (.duplicate buf)
      (.position offset)
      (.get arr))
    arr))

;;; ============================================================================
;;; Part 2: MAC Address Handling
;;; ============================================================================

(defn parse-mac
  "Parse 6-byte MAC address"
  [^ByteBuffer buf offset]
  (vec (for [i (range 6)] (read-u8 buf (+ offset i)))))

(defn mac->string
  "Format MAC address as string"
  [mac]
  (str/join ":" (map #(format "%02x" %) mac)))

(defn string->mac
  "Parse MAC address from string"
  [s]
  (vec (map #(Integer/parseInt % 16) (str/split s #":"))))

;;; ============================================================================
;;; Part 3: IP Address Handling
;;; ============================================================================

(defn parse-ipv4
  "Parse 4-byte IPv4 address"
  [^ByteBuffer buf offset]
  (vec (for [i (range 4)] (read-u8 buf (+ offset i)))))

(defn ipv4->string
  "Format IPv4 address as string"
  [ip]
  (str/join "." ip))

(defn ipv4->int
  "Convert IPv4 address to integer"
  [ip]
  (reduce (fn [acc b] (+ (bit-shift-left acc 8) b)) 0 ip))

(defn int->ipv4
  "Convert integer to IPv4 address"
  [n]
  [(bit-and 0xFF (bit-shift-right n 24))
   (bit-and 0xFF (bit-shift-right n 16))
   (bit-and 0xFF (bit-shift-right n 8))
   (bit-and 0xFF n)])

(defn string->ipv4
  "Parse IPv4 address from string"
  [s]
  (vec (map #(Integer/parseInt %) (str/split s #"\."))))

;;; ============================================================================
;;; Part 4: Ethernet Header Parsing
;;; ============================================================================

(def ETH_HEADER_LEN 14)
(def ETH_P_IP 0x0800)
(def ETH_P_ARP 0x0806)
(def ETH_P_IPV6 0x86DD)
(def ETH_P_8021Q 0x8100)

(defrecord EthernetHeader
  [dst-mac src-mac ethertype])

(defn parse-ethernet
  "Parse Ethernet header from buffer"
  [^ByteBuffer buf]
  (when (>= (.remaining buf) ETH_HEADER_LEN)
    (->EthernetHeader
      (parse-mac buf 0)
      (parse-mac buf 6)
      (read-u16 buf 12))))

(defn ethertype-name
  "Get human-readable EtherType name"
  [ethertype]
  (case ethertype
    0x0800 "IPv4"
    0x0806 "ARP"
    0x86DD "IPv6"
    0x8100 "802.1Q VLAN"
    (format "0x%04X" ethertype)))

;;; ============================================================================
;;; Part 5: IPv4 Header Parsing
;;; ============================================================================

(def IP_HEADER_MIN_LEN 20)
(def IPPROTO_ICMP 1)
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

(defrecord IPv4Header
  [version ihl tos total-length
   identification flags fragment-offset
   ttl protocol checksum
   src-ip dst-ip
   header-length])

(defn parse-ipv4-header
  "Parse IPv4 header from buffer at offset"
  [^ByteBuffer buf offset]
  (when (>= (- (.remaining buf) offset) IP_HEADER_MIN_LEN)
    (let [version-ihl (read-u8 buf offset)
          version (bit-shift-right version-ihl 4)
          ihl (bit-and version-ihl 0x0F)
          header-length (* ihl 4)]
      (when (and (= version 4)
                 (>= ihl 5)
                 (>= (- (.remaining buf) offset) header-length))
        (let [flags-frag (read-u16 buf (+ offset 6))]
          (->IPv4Header
            version
            ihl
            (read-u8 buf (+ offset 1))
            (read-u16 buf (+ offset 2))
            (read-u16 buf (+ offset 4))
            (bit-shift-right flags-frag 13)
            (bit-and flags-frag 0x1FFF)
            (read-u8 buf (+ offset 8))
            (read-u8 buf (+ offset 9))
            (read-u16 buf (+ offset 10))
            (parse-ipv4 buf (+ offset 12))
            (parse-ipv4 buf (+ offset 16))
            header-length))))))

(defn protocol-name
  "Get human-readable protocol name"
  [protocol]
  (case protocol
    1 "ICMP"
    6 "TCP"
    17 "UDP"
    (format "Protocol %d" protocol)))

;;; ============================================================================
;;; Part 6: TCP Header Parsing
;;; ============================================================================

(def TCP_HEADER_MIN_LEN 20)

(def TCP_FLAG_FIN 0x01)
(def TCP_FLAG_SYN 0x02)
(def TCP_FLAG_RST 0x04)
(def TCP_FLAG_PSH 0x08)
(def TCP_FLAG_ACK 0x10)
(def TCP_FLAG_URG 0x20)

(defrecord TCPHeader
  [src-port dst-port
   seq-num ack-num
   data-offset flags
   window checksum urgent-ptr])

(defn parse-tcp-header
  "Parse TCP header from buffer at offset"
  [^ByteBuffer buf offset]
  (when (>= (- (.remaining buf) offset) TCP_HEADER_MIN_LEN)
    (let [data-offset-flags (read-u8 buf (+ offset 12))
          data-offset (bit-shift-right data-offset-flags 4)
          header-length (* data-offset 4)]
      (when (>= (- (.remaining buf) offset) header-length)
        (->TCPHeader
          (read-u16 buf offset)
          (read-u16 buf (+ offset 2))
          (read-u32 buf (+ offset 4))
          (read-u32 buf (+ offset 8))
          data-offset
          (read-u8 buf (+ offset 13))
          (read-u16 buf (+ offset 14))
          (read-u16 buf (+ offset 16))
          (read-u16 buf (+ offset 18)))))))

(defn tcp-flags->string
  "Format TCP flags as string"
  [flags]
  (str
    (if (pos? (bit-and flags TCP_FLAG_SYN)) "S" ".")
    (if (pos? (bit-and flags TCP_FLAG_ACK)) "A" ".")
    (if (pos? (bit-and flags TCP_FLAG_FIN)) "F" ".")
    (if (pos? (bit-and flags TCP_FLAG_RST)) "R" ".")
    (if (pos? (bit-and flags TCP_FLAG_PSH)) "P" ".")
    (if (pos? (bit-and flags TCP_FLAG_URG)) "U" ".")))

;;; ============================================================================
;;; Part 7: UDP Header Parsing
;;; ============================================================================

(def UDP_HEADER_LEN 8)

(defrecord UDPHeader
  [src-port dst-port length checksum])

(defn parse-udp-header
  "Parse UDP header from buffer at offset"
  [^ByteBuffer buf offset]
  (when (>= (- (.remaining buf) offset) UDP_HEADER_LEN)
    (->UDPHeader
      (read-u16 buf offset)
      (read-u16 buf (+ offset 2))
      (read-u16 buf (+ offset 4))
      (read-u16 buf (+ offset 6)))))

;;; ============================================================================
;;; Part 8: ICMP Header Parsing
;;; ============================================================================

(def ICMP_HEADER_LEN 8)

(defrecord ICMPHeader
  [type code checksum identifier sequence])

(defn parse-icmp-header
  "Parse ICMP header from buffer at offset"
  [^ByteBuffer buf offset]
  (when (>= (- (.remaining buf) offset) ICMP_HEADER_LEN)
    (->ICMPHeader
      (read-u8 buf offset)
      (read-u8 buf (+ offset 1))
      (read-u16 buf (+ offset 2))
      (read-u16 buf (+ offset 4))
      (read-u16 buf (+ offset 6)))))

(defn icmp-type-name
  "Get ICMP type name"
  [type]
  (case type
    0 "Echo Reply"
    3 "Destination Unreachable"
    8 "Echo Request"
    11 "Time Exceeded"
    (format "Type %d" type)))

;;; ============================================================================
;;; Part 9: Complete Packet Parsing
;;; ============================================================================

(defrecord ParsedPacket
  [ethernet ipv4 transport transport-type payload-offset])

(defn parse-packet
  "Parse complete packet"
  [^bytes packet-bytes]
  (let [buf (bytes->buffer packet-bytes)
        eth (parse-ethernet buf)]
    (when eth
      (if (= (:ethertype eth) ETH_P_IP)
        (let [ip (parse-ipv4-header buf ETH_HEADER_LEN)]
          (when ip
            (let [transport-offset (+ ETH_HEADER_LEN (:header-length ip))
                  [transport transport-type]
                  (case (:protocol ip)
                    6  [(parse-tcp-header buf transport-offset) :tcp]
                    17 [(parse-udp-header buf transport-offset) :udp]
                    1  [(parse-icmp-header buf transport-offset) :icmp]
                    [nil :unknown])]
              (->ParsedPacket eth ip transport transport-type
                              (+ transport-offset
                                 (case transport-type
                                   :tcp (* 4 (or (:data-offset transport) 5))
                                   :udp UDP_HEADER_LEN
                                   :icmp ICMP_HEADER_LEN
                                   0))))))
        (->ParsedPacket eth nil nil :non-ip ETH_HEADER_LEN)))))

(defn packet-summary
  "Generate human-readable packet summary"
  [parsed]
  (if-let [ip (:ipv4 parsed)]
    (let [proto (:transport-type parsed)
          transport (:transport parsed)]
      (case proto
        :tcp (format "%s:%d -> %s:%d TCP [%s]"
                     (ipv4->string (:src-ip ip))
                     (:src-port transport)
                     (ipv4->string (:dst-ip ip))
                     (:dst-port transport)
                     (tcp-flags->string (:flags transport)))
        :udp (format "%s:%d -> %s:%d UDP"
                     (ipv4->string (:src-ip ip))
                     (:src-port transport)
                     (ipv4->string (:dst-ip ip))
                     (:dst-port transport))
        :icmp (format "%s -> %s ICMP %s"
                      (ipv4->string (:src-ip ip))
                      (ipv4->string (:dst-ip ip))
                      (icmp-type-name (:type transport)))
        (format "%s -> %s %s"
                (ipv4->string (:src-ip ip))
                (ipv4->string (:dst-ip ip))
                (protocol-name (:protocol ip)))))
    (format "%s -> %s %s"
            (mac->string (:src-mac (:ethernet parsed)))
            (mac->string (:dst-mac (:ethernet parsed)))
            (ethertype-name (:ethertype (:ethernet parsed))))))

;;; ============================================================================
;;; Part 10: Test Packet Generation
;;; ============================================================================

(defn create-ethernet-header
  "Create Ethernet header bytes"
  [dst-mac src-mac ethertype]
  (let [buf (ByteBuffer/allocate 14)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (doseq [b dst-mac] (.put buf (unchecked-byte b)))
    (doseq [b src-mac] (.put buf (unchecked-byte b)))
    (.putShort buf (unchecked-short ethertype))
    (.array buf)))

(defn create-ipv4-header
  "Create IPv4 header bytes"
  [src-ip dst-ip protocol total-length]
  (let [buf (ByteBuffer/allocate 20)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (.put buf (unchecked-byte 0x45))  ; Version 4, IHL 5
    (.put buf (unchecked-byte 0))     ; TOS
    (.putShort buf (unchecked-short total-length))
    (.putShort buf (unchecked-short 0))  ; ID
    (.putShort buf (unchecked-short 0))  ; Flags/Fragment
    (.put buf (unchecked-byte 64))    ; TTL
    (.put buf (unchecked-byte protocol))
    (.putShort buf (unchecked-short 0))  ; Checksum
    (doseq [b src-ip] (.put buf (unchecked-byte b)))
    (doseq [b dst-ip] (.put buf (unchecked-byte b)))
    (.array buf)))

(defn create-tcp-header
  "Create TCP header bytes"
  [src-port dst-port flags]
  (let [buf (ByteBuffer/allocate 20)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putShort buf (unchecked-short src-port))
    (.putShort buf (unchecked-short dst-port))
    (.putInt buf 0)                   ; Seq
    (.putInt buf 0)                   ; Ack
    (.put buf (unchecked-byte 0x50))  ; Data offset 5
    (.put buf (unchecked-byte flags))
    (.putShort buf (unchecked-short 65535)) ; Window
    (.putShort buf (unchecked-short 0))     ; Checksum
    (.putShort buf (unchecked-short 0))     ; Urgent
    (.array buf)))

(defn create-udp-header
  "Create UDP header bytes"
  [src-port dst-port length]
  (let [buf (ByteBuffer/allocate 8)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putShort buf (unchecked-short src-port))
    (.putShort buf (unchecked-short dst-port))
    (.putShort buf (unchecked-short length))
    (.putShort buf (unchecked-short 0))  ; Checksum
    (.array buf)))

(defn create-test-tcp-packet
  "Create a test TCP packet"
  [src-ip dst-ip src-port dst-port flags]
  (let [eth (create-ethernet-header
              [0x00 0x11 0x22 0x33 0x44 0x55]
              [0xAA 0xBB 0xCC 0xDD 0xEE 0xFF]
              ETH_P_IP)
        ip (create-ipv4-header src-ip dst-ip IPPROTO_TCP 40)
        tcp (create-tcp-header src-port dst-port flags)]
    (byte-array (concat eth ip tcp))))

(defn create-test-udp-packet
  "Create a test UDP packet"
  [src-ip dst-ip src-port dst-port]
  (let [eth (create-ethernet-header
              [0x00 0x11 0x22 0x33 0x44 0x55]
              [0xAA 0xBB 0xCC 0xDD 0xEE 0xFF]
              ETH_P_IP)
        ip (create-ipv4-header src-ip dst-ip IPPROTO_UDP 28)
        udp (create-udp-header src-port dst-port 8)]
    (byte-array (concat eth ip udp))))

;;; ============================================================================
;;; Part 11: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 16.1 Tests ===\n")

  ;; Test 1: MAC address parsing
  (println "Test 1: MAC Address Parsing")
  (let [mac [0x00 0x11 0x22 0x33 0x44 0x55]]
    (assert (= "00:11:22:33:44:55" (mac->string mac)) "mac to string")
    (assert (= mac (string->mac "00:11:22:33:44:55")) "string to mac"))
  (println "  MAC address parsing works correctly")
  (println "  PASSED\n")

  ;; Test 2: IPv4 address parsing
  (println "Test 2: IPv4 Address Parsing")
  (let [ip [192 168 1 1]]
    (assert (= "192.168.1.1" (ipv4->string ip)) "ip to string")
    (assert (= ip (string->ipv4 "192.168.1.1")) "string to ip")
    (assert (= ip (int->ipv4 (ipv4->int ip))) "roundtrip"))
  (println "  IPv4 address parsing works correctly")
  (println "  PASSED\n")

  ;; Test 3: Ethernet header parsing
  (println "Test 3: Ethernet Header Parsing")
  (let [packet (create-test-tcp-packet [192 168 1 1] [192 168 1 2] 12345 80 TCP_FLAG_SYN)
        eth (parse-ethernet (bytes->buffer packet))]
    (assert (some? eth) "ethernet parsed")
    (assert (= ETH_P_IP (:ethertype eth)) "ethertype is IP")
    (assert (= [0x00 0x11 0x22 0x33 0x44 0x55] (:dst-mac eth)) "dst mac"))
  (println "  Ethernet header parsing works correctly")
  (println "  PASSED\n")

  ;; Test 4: IPv4 header parsing
  (println "Test 4: IPv4 Header Parsing")
  (let [packet (create-test-tcp-packet [10 0 0 1] [10 0 0 2] 12345 443 TCP_FLAG_SYN)
        buf (bytes->buffer packet)
        ip (parse-ipv4-header buf ETH_HEADER_LEN)]
    (assert (some? ip) "ip parsed")
    (assert (= 4 (:version ip)) "version 4")
    (assert (= 5 (:ihl ip)) "ihl 5")
    (assert (= IPPROTO_TCP (:protocol ip)) "protocol TCP")
    (assert (= [10 0 0 1] (:src-ip ip)) "src ip")
    (assert (= [10 0 0 2] (:dst-ip ip)) "dst ip"))
  (println "  IPv4 header parsing works correctly")
  (println "  PASSED\n")

  ;; Test 5: TCP header parsing
  (println "Test 5: TCP Header Parsing")
  (let [packet (create-test-tcp-packet [1 2 3 4] [5 6 7 8] 54321 22 (bit-or TCP_FLAG_SYN TCP_FLAG_ACK))
        buf (bytes->buffer packet)
        tcp (parse-tcp-header buf (+ ETH_HEADER_LEN IP_HEADER_MIN_LEN))]
    (assert (some? tcp) "tcp parsed")
    (assert (= 54321 (:src-port tcp)) "src port")
    (assert (= 22 (:dst-port tcp)) "dst port")
    (assert (= (bit-or TCP_FLAG_SYN TCP_FLAG_ACK) (:flags tcp)) "flags")
    (assert (= "SA...." (tcp-flags->string (:flags tcp))) "flag string"))
  (println "  TCP header parsing works correctly")
  (println "  PASSED\n")

  ;; Test 6: UDP header parsing
  (println "Test 6: UDP Header Parsing")
  (let [packet (create-test-udp-packet [8 8 8 8] [1 1 1 1] 53 53)
        buf (bytes->buffer packet)
        udp (parse-udp-header buf (+ ETH_HEADER_LEN IP_HEADER_MIN_LEN))]
    (assert (some? udp) "udp parsed")
    (assert (= 53 (:src-port udp)) "src port")
    (assert (= 53 (:dst-port udp)) "dst port"))
  (println "  UDP header parsing works correctly")
  (println "  PASSED\n")

  ;; Test 7: Complete packet parsing
  (println "Test 7: Complete Packet Parsing")
  (let [tcp-packet (create-test-tcp-packet [192 168 1 100] [10 0 0 1] 45678 80 TCP_FLAG_SYN)
        parsed (parse-packet tcp-packet)]
    (assert (some? parsed) "packet parsed")
    (assert (= :tcp (:transport-type parsed)) "transport type")
    (assert (= 80 (:dst-port (:transport parsed))) "dst port from transport"))
  (println "  Complete packet parsing works correctly")
  (println "  PASSED\n")

  ;; Test 8: Packet summary
  (println "Test 8: Packet Summary")
  (let [packet (create-test-tcp-packet [192 168 1 100] [93 184 216 34] 45678 443 TCP_FLAG_SYN)
        parsed (parse-packet packet)
        summary (packet-summary parsed)]
    (assert (str/includes? summary "192.168.1.100") "src ip in summary")
    (assert (str/includes? summary "93.184.216.34") "dst ip in summary")
    (assert (str/includes? summary "443") "port in summary")
    (assert (str/includes? summary "TCP") "protocol in summary"))
  (println "  Packet summary works correctly")
  (println "  PASSED\n")

  ;; Test 9: Bounds checking
  (println "Test 9: Bounds Checking")
  (assert (nil? (parse-ethernet (bytes->buffer (byte-array 10)))) "short ethernet")
  (assert (nil? (parse-ipv4-header (bytes->buffer (byte-array 30)) 14)) "short ip")
  (assert (nil? (parse-tcp-header (bytes->buffer (byte-array 40)) 34)) "short tcp")
  (println "  Bounds checking prevents buffer overread")
  (println "  PASSED\n")

  ;; Test 10: Protocol names
  (println "Test 10: Protocol and Type Names")
  (assert (= "IPv4" (ethertype-name ETH_P_IP)) "ipv4 ethertype")
  (assert (= "TCP" (protocol-name IPPROTO_TCP)) "tcp protocol")
  (assert (= "Echo Request" (icmp-type-name 8)) "icmp type")
  (println "  Protocol names resolved correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 12: Demo
;;; ============================================================================

(defn run-demo
  "Run demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 16.1: Packet Parsing")
  (println (str/join "" (repeat 60 "=")) "\n")

  (println "=== Parsing Sample Packets ===\n")

  (let [packets
        [(create-test-tcp-packet [192 168 1 100] [93 184 216 34] 45678 80 TCP_FLAG_SYN)
         (create-test-tcp-packet [93 184 216 34] [192 168 1 100] 80 45678 (bit-or TCP_FLAG_SYN TCP_FLAG_ACK))
         (create-test-tcp-packet [192 168 1 100] [93 184 216 34] 45678 80 TCP_FLAG_ACK)
         (create-test-udp-packet [192 168 1 100] [8 8 8 8] 54321 53)
         (create-test-tcp-packet [10 0 0 5] [10 0 0 1] 22222 22 TCP_FLAG_SYN)]]

    (doseq [packet packets]
      (let [parsed (parse-packet packet)]
        (println (format "Packet (%d bytes): %s" (count packet) (packet-summary parsed)))
        (when (= :tcp (:transport-type parsed))
          (println (format "  TCP Flags: %s" (tcp-flags->string (:flags (:transport parsed))))))
        (println))))

  (println "=== Header Details ===\n")

  (let [packet (create-test-tcp-packet [192 168 1 100] [93 184 216 34] 45678 443
                                       (bit-or TCP_FLAG_SYN TCP_FLAG_ACK))
        parsed (parse-packet packet)]
    (println "Ethernet Header:")
    (println (format "  Dst MAC: %s" (mac->string (:dst-mac (:ethernet parsed)))))
    (println (format "  Src MAC: %s" (mac->string (:src-mac (:ethernet parsed)))))
    (println (format "  Type: %s" (ethertype-name (:ethertype (:ethernet parsed)))))
    (println)

    (println "IPv4 Header:")
    (println (format "  Version: %d" (:version (:ipv4 parsed))))
    (println (format "  IHL: %d (%d bytes)" (:ihl (:ipv4 parsed)) (:header-length (:ipv4 parsed))))
    (println (format "  TTL: %d" (:ttl (:ipv4 parsed))))
    (println (format "  Protocol: %s" (protocol-name (:protocol (:ipv4 parsed)))))
    (println (format "  Src: %s" (ipv4->string (:src-ip (:ipv4 parsed)))))
    (println (format "  Dst: %s" (ipv4->string (:dst-ip (:ipv4 parsed)))))
    (println)

    (println "TCP Header:")
    (println (format "  Src Port: %d" (:src-port (:transport parsed))))
    (println (format "  Dst Port: %d" (:dst-port (:transport parsed))))
    (println (format "  Flags: %s" (tcp-flags->string (:flags (:transport parsed)))))
    (println (format "  Window: %d" (:window (:transport parsed))))))

;;; ============================================================================
;;; Part 13: Main
;;; ============================================================================

(defn -main [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      (do
        (println "Usage: clojure -M -m lab-16-1-packet-parsing <command>")
        (println "Commands:")
        (println "  test  - Run tests")
        (println "  demo  - Run demonstration")))))
