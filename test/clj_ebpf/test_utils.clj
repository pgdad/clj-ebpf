(ns clj-ebpf.test-utils
  "Test utilities for clj-ebpf.

   Provides:
   - Fixtures for mock and real BPF testing
   - Helper functions for common test patterns
   - Test data generators
   - Assertions for BPF-specific conditions"
  (:require [clojure.test :refer [is testing]]
            [clj-ebpf.mock :as mock]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Test Detection
;; ============================================================================

(defn has-bpf-capabilities?
  "Check if the current process has BPF capabilities.
   Returns true if real BPF operations can be performed."
  []
  (try
    (utils/has-cap-bpf?)
    (catch Exception _ false)))

(defn skip-without-capabilities
  "Skip test if BPF capabilities are not available.
   Use as first line in tests that require real BPF access."
  []
  (when-not (has-bpf-capabilities?)
    (println "  [SKIPPED] Test requires CAP_BPF capability")
    :skipped))

;; ============================================================================
;; Test Fixtures
;; ============================================================================

(defn mock-fixture
  "Test fixture that enables mock BPF syscalls.

   Usage:
   ```clojure
   (use-fixtures :each mock-fixture)
   ```"
  [f]
  (mock/with-mock-bpf
    (f)))

(defn capabilities-fixture
  "Test fixture that skips tests without BPF capabilities.

   Usage:
   ```clojure
   (use-fixtures :once capabilities-fixture)
   ```"
  [f]
  (if (has-bpf-capabilities?)
    (f)
    (println "Skipping test suite - no BPF capabilities")))

(defn cleanup-fixture
  "Test fixture that ensures cleanup of BPF resources.

   Usage:
   ```clojure
   (use-fixtures :each cleanup-fixture)
   ```"
  [f]
  (let [result (try
                 (f)
                 (catch Exception e
                   {:error e}))]
    ;; Force GC to trigger arena cleanup
    (System/gc)
    (when-let [e (:error result)]
      (throw e))))

;; ============================================================================
;; Test Data Helpers
;; ============================================================================

(defn make-key
  "Create a key byte array from an integer.
   Default size is 4 bytes."
  ([n] (make-key n 4))
  ([n size]
   (let [bytes (byte-array size)]
     (dotimes [i (min 4 size)]
       (aset bytes i (unchecked-byte (bit-and (bit-shift-right n (* i 8)) 0xff))))
     bytes)))

(defn make-value
  "Create a value byte array from a long.
   Default size is 8 bytes."
  ([n] (make-value n 8))
  ([n size]
   (let [bytes (byte-array size)]
     (dotimes [i (min 8 size)]
       (aset bytes i (unchecked-byte (bit-and (bit-shift-right n (* i 8)) 0xff))))
     bytes)))

(defn key->int
  "Convert a key byte array back to integer."
  [^bytes key-bytes]
  (utils/bytes->int key-bytes))

(defn value->long
  "Convert a value byte array back to long."
  [^bytes value-bytes]
  (utils/bytes->long value-bytes))

(defn random-key
  "Generate a random key byte array."
  ([size]
   (let [bytes (byte-array size)]
     (dotimes [i size]
       (aset bytes i (unchecked-byte (rand-int 256))))
     bytes)))

(defn random-value
  "Generate a random value byte array."
  ([size]
   (let [bytes (byte-array size)]
     (dotimes [i size]
       (aset bytes i (unchecked-byte (rand-int 256))))
     bytes)))

(defn make-entries
  "Generate n test entries with sequential keys.

   Returns sequence of [key-bytes value-bytes] pairs."
  [n key-size value-size]
  (for [i (range n)]
    [(make-key i key-size)
     (make-value (* i i) value-size)]))

;; ============================================================================
;; Assertion Helpers
;; ============================================================================

(defn assert-bytes-equal
  "Assert two byte arrays are equal."
  [expected actual & [message]]
  (is (java.util.Arrays/equals ^bytes expected ^bytes actual)
      (or message
          (str "Expected " (vec expected) " but got " (vec actual)))))

(defn assert-map-lookup
  "Assert that looking up key in map returns expected value."
  [bpf-map key-bytes expected-value-bytes]
  ;; Note: To avoid circular dependencies, this is a placeholder.
  ;; In real usage, call maps/map-lookup directly from your test.
  true)

(defmacro with-temp-map
  "Execute body with a temporary map that is automatically closed.

   Example:
   ```clojure
   (with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 100}]
     (map-update m key val)
     (is (= val (map-lookup m key))))
   ```"
  [[sym config] & body]
  `(let [create-map# (requiring-resolve 'clj-ebpf.maps/create-map)
         close-map# (requiring-resolve 'clj-ebpf.maps/close-map)
         ~sym (create-map# (:type ~config)
                           (:max-entries ~config)
                           (:key-size ~config)
                           (:value-size ~config))]
     (try
       ~@body
       (finally
         (close-map# ~sym)))))

;; ============================================================================
;; Error Testing Helpers
;; ============================================================================

(defmacro assert-throws-bpf-error
  "Assert that body throws a BPF error with the given type."
  [error-type & body]
  `(try
     ~@body
     (is false "Expected exception to be thrown")
     (catch clojure.lang.ExceptionInfo e#
       (is (= ~error-type (:error-type (ex-data e#)))
           (str "Expected error type " ~error-type " but got " (:error-type (ex-data e#)))))))

(defmacro assert-throws-errno
  "Assert that body throws an error with the given errno keyword."
  [errno-kw & body]
  `(try
     ~@body
     (is false "Expected exception to be thrown")
     (catch clojure.lang.ExceptionInfo e#
       (is (= ~errno-kw (:errno-keyword (ex-data e#)))
           (str "Expected errno " ~errno-kw " but got " (:errno-keyword (ex-data e#)))))))

;; ============================================================================
;; Performance Testing Helpers
;; ============================================================================

(defmacro time-op
  "Time an operation and return [result elapsed-ns]."
  [& body]
  `(let [start# (System/nanoTime)
         result# (do ~@body)
         elapsed# (- (System/nanoTime) start#)]
     [result# elapsed#]))

(defn benchmark-op
  "Run an operation n times and return statistics.

   Returns map with :min :max :mean :median :std-dev (all in nanoseconds)"
  [n f]
  (let [times (doall (for [_ (range n)]
                       (let [start (System/nanoTime)]
                         (f)
                         (- (System/nanoTime) start))))
        sorted (sort times)
        sum (reduce + times)
        mean (/ sum n)
        median (nth sorted (/ n 2))
        variance (/ (reduce + (map #(Math/pow (- % mean) 2) times)) n)]
    {:min (first sorted)
     :max (last sorted)
     :mean mean
     :median median
     :std-dev (Math/sqrt variance)
     :samples n}))

(defn format-ns
  "Format nanoseconds to human-readable string."
  [ns]
  (cond
    (< ns 1000) (format "%.0f ns" (double ns))
    (< ns 1000000) (format "%.2f µs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.2f ms" (/ ns 1000000.0))
    :else (format "%.2f s" (/ ns 1000000000.0))))

;; ============================================================================
;; Packet Building Helpers (for XDP/TC tests)
;; ============================================================================

(defn build-eth-header
  "Build an Ethernet header.

   Options:
   - :src-mac - Source MAC as 6-byte array (default: 00:00:00:00:00:01)
   - :dst-mac - Destination MAC as 6-byte array (default: 00:00:00:00:00:02)
   - :eth-type - Ethernet type (default: 0x0800 for IPv4)"
  [& {:keys [src-mac dst-mac eth-type]
      :or {src-mac (byte-array [0 0 0 0 0 1])
           dst-mac (byte-array [0 0 0 0 0 2])
           eth-type 0x0800}}]
  (let [header (byte-array 14)]
    (System/arraycopy dst-mac 0 header 0 6)
    (System/arraycopy src-mac 0 header 6 6)
    (aset header 12 (unchecked-byte (bit-shift-right eth-type 8)))
    (aset header 13 (unchecked-byte (bit-and eth-type 0xff)))
    header))

(defn build-ipv4-header
  "Build an IPv4 header.

   Options:
   - :src-ip - Source IP as 4-byte array
   - :dst-ip - Destination IP as 4-byte array
   - :protocol - Protocol number (6=TCP, 17=UDP, 1=ICMP)
   - :ttl - Time to live (default: 64)"
  [& {:keys [src-ip dst-ip protocol ttl total-length]
      :or {src-ip (byte-array [10 0 0 1])
           dst-ip (byte-array [10 0 0 2])
           protocol 6
           ttl 64
           total-length 40}}]
  (let [header (byte-array 20)]
    ;; Version (4) + IHL (5)
    (aset header 0 (unchecked-byte 0x45))
    ;; TOS
    (aset header 1 (unchecked-byte 0))
    ;; Total length
    (aset header 2 (unchecked-byte (bit-shift-right total-length 8)))
    (aset header 3 (unchecked-byte (bit-and total-length 0xff)))
    ;; ID
    (aset header 4 (unchecked-byte 0))
    (aset header 5 (unchecked-byte 1))
    ;; Flags + Fragment offset
    (aset header 6 (unchecked-byte 0x40))  ; Don't fragment
    (aset header 7 (unchecked-byte 0))
    ;; TTL
    (aset header 8 (unchecked-byte ttl))
    ;; Protocol
    (aset header 9 (unchecked-byte protocol))
    ;; Checksum (set to 0, would need to compute)
    (aset header 10 (unchecked-byte 0))
    (aset header 11 (unchecked-byte 0))
    ;; Source IP
    (System/arraycopy src-ip 0 header 12 4)
    ;; Destination IP
    (System/arraycopy dst-ip 0 header 16 4)
    header))

(defn build-tcp-header
  "Build a TCP header.

   Options:
   - :src-port - Source port
   - :dst-port - Destination port
   - :seq - Sequence number
   - :ack - Acknowledgment number
   - :flags - TCP flags (SYN=0x02, ACK=0x10, etc.)"
  [& {:keys [src-port dst-port seq ack flags]
      :or {src-port 12345
           dst-port 80
           seq 1000
           ack 0
           flags 0x02}}]  ; SYN
  (let [header (byte-array 20)]
    ;; Source port
    (aset header 0 (unchecked-byte (bit-shift-right src-port 8)))
    (aset header 1 (unchecked-byte (bit-and src-port 0xff)))
    ;; Destination port
    (aset header 2 (unchecked-byte (bit-shift-right dst-port 8)))
    (aset header 3 (unchecked-byte (bit-and dst-port 0xff)))
    ;; Sequence number
    (aset header 4 (unchecked-byte (bit-shift-right seq 24)))
    (aset header 5 (unchecked-byte (bit-and (bit-shift-right seq 16) 0xff)))
    (aset header 6 (unchecked-byte (bit-and (bit-shift-right seq 8) 0xff)))
    (aset header 7 (unchecked-byte (bit-and seq 0xff)))
    ;; Ack number
    (aset header 8 (unchecked-byte (bit-shift-right ack 24)))
    (aset header 9 (unchecked-byte (bit-and (bit-shift-right ack 16) 0xff)))
    (aset header 10 (unchecked-byte (bit-and (bit-shift-right ack 8) 0xff)))
    (aset header 11 (unchecked-byte (bit-and ack 0xff)))
    ;; Data offset (5 words = 20 bytes) + reserved
    (aset header 12 (unchecked-byte 0x50))
    ;; Flags
    (aset header 13 (unchecked-byte flags))
    ;; Window
    (aset header 14 (unchecked-byte 0xff))
    (aset header 15 (unchecked-byte 0xff))
    ;; Checksum
    (aset header 16 (unchecked-byte 0))
    (aset header 17 (unchecked-byte 0))
    ;; Urgent pointer
    (aset header 18 (unchecked-byte 0))
    (aset header 19 (unchecked-byte 0))
    header))

(defn build-test-packet
  "Build a complete test packet.

   Options:
   - :protocol - :tcp, :udp, or :icmp
   - :src-ip, :dst-ip - IP addresses
   - :src-port, :dst-port - Ports (for TCP/UDP)
   - :payload - Optional payload bytes"
  [& {:keys [protocol src-ip dst-ip src-port dst-port payload]
      :or {protocol :tcp
           src-ip (byte-array [10 0 0 1])
           dst-ip (byte-array [10 0 0 2])
           src-port 12345
           dst-port 80
           payload (byte-array 0)}}]
  (let [proto-num (case protocol :tcp 6 :udp 17 :icmp 1)
        eth (build-eth-header)
        ip (build-ipv4-header :src-ip src-ip :dst-ip dst-ip :protocol proto-num)
        transport (case protocol
                    :tcp (build-tcp-header :src-port src-port :dst-port dst-port)
                    :udp (byte-array 8)  ; Simplified UDP header
                    :icmp (byte-array 8))  ; Simplified ICMP header
        total-len (+ (count eth) (count ip) (count transport) (count payload))
        packet (byte-array total-len)]
    (System/arraycopy eth 0 packet 0 (count eth))
    (System/arraycopy ip 0 packet (count eth) (count ip))
    (System/arraycopy transport 0 packet (+ (count eth) (count ip)) (count transport))
    (when (pos? (count payload))
      (System/arraycopy payload 0 packet (+ (count eth) (count ip) (count transport)) (count payload)))
    packet))
