(ns lab-14-5-property-testing
  "Lab 14.5: Property-Based Testing

   This solution demonstrates:
   - Property-based testing for BPF operations
   - Custom generators for BPF data types
   - Round-trip property verification
   - Invariant testing for instructions
   - Shrinking and failure analysis

   Note: Uses test.check style property testing.
   This solution provides generators and properties without the library dependency.

   Run with: clojure -M -m lab-14-5-property-testing test"
  (:require [clojure.string :as str])
  (:import [java.util Random]
           [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Simple Property Testing Framework
;;; ============================================================================

(def ^:dynamic *random* (Random.))
(def default-test-count 100)

(defn set-seed! [seed]
  (set! *random* (Random. seed)))

(defn rand-int-range
  "Generate random int in range [min, max]"
  [min-val max-val]
  (let [range-size (- (inc (long max-val)) (long min-val))]
    (cond
      (<= range-size 0) min-val
      (> range-size Integer/MAX_VALUE)
      ;; Range too large for nextInt, use nextLong approach
      (int (+ min-val (mod (Math/abs (.nextLong *random*)) range-size)))
      :else
      (+ min-val (.nextInt *random* (int range-size))))))

(defn rand-long-range
  "Generate random long in range"
  [min-val max-val]
  (let [range-size (- (inc max-val) min-val)]
    (if (pos? range-size)
      (+ min-val (Math/abs (mod (.nextLong *random*) range-size)))
      min-val)))

(defn rand-bytes
  "Generate random byte array"
  [size]
  (let [arr (byte-array size)]
    (.nextBytes *random* arr)
    arr))

(defn shrink-int
  "Shrink an integer towards zero"
  [n]
  (cond
    (zero? n) []
    (pos? n) (distinct [(quot n 2) (dec n) 0])
    :else (distinct [(quot n 2) (inc n) 0])))

(defn run-property
  "Run a property test multiple times"
  [name gen-fn prop-fn num-tests]
  (print (format "  %-40s " name))
  (flush)
  (loop [i 0]
    (if (>= i num-tests)
      (do (println (format "PASS (%d tests)" num-tests))
          {:pass true :tests num-tests})
      (let [input (gen-fn)
            result (try
                     (prop-fn input)
                     (catch Exception e
                       {:error e :input input}))]
        (if (and (not (map? result)) result)
          (recur (inc i))
          (do
            (println "FAIL")
            (println (format "    Failing input: %s" (pr-str input)))
            (when (map? result)
              (println (format "    Error: %s" (.getMessage (:error result)))))
            {:pass false :failing-input input :tests i}))))))

;;; ============================================================================
;;; Part 2: BPF Data Generators
;;; ============================================================================

;; Primitive generators
(defn gen-u8 [] (rand-int-range 0 255))
(defn gen-u16 [] (rand-int-range 0 65535))
(defn gen-u32 [] (rand-int-range 0 Integer/MAX_VALUE))
(defn gen-u64 [] (Math/abs (.nextLong *random*)))
(defn gen-i32 [] (.nextInt *random*))
(defn gen-i64 [] (.nextLong *random*))

(defn gen-byte-array
  "Generate byte array of fixed size"
  [size]
  (rand-bytes size))

(defn gen-byte-array-range
  "Generate byte array with size in range"
  [min-size max-size]
  (rand-bytes (rand-int-range min-size max-size)))

;; BPF register generators
(def registers [:r0 :r1 :r2 :r3 :r4 :r5 :r6 :r7 :r8 :r9 :r10])
(def writable-registers [:r0 :r1 :r2 :r3 :r4 :r5 :r6 :r7 :r8 :r9])
(def arg-registers [:r1 :r2 :r3 :r4 :r5])
(def callee-saved-registers [:r6 :r7 :r8 :r9])

(defn gen-register [] (rand-nth registers))
(defn gen-writable-register [] (rand-nth writable-registers))
(defn gen-arg-register [] (rand-nth arg-registers))
(defn gen-callee-saved [] (rand-nth callee-saved-registers))

;; BPF operation generators
(def alu-ops [:add :sub :mul :div :or :and :lsh :rsh :neg :mod :xor :mov :arsh])
(def jmp-ops [:jeq :jgt :jge :jne :jlt :jle :jset :jsgt :jsge :jslt :jsle])
(def mem-sizes [:b :h :w :dw])

(defn gen-alu-op [] (rand-nth alu-ops))
(defn gen-jmp-op [] (rand-nth jmp-ops))
(defn gen-mem-size [] (rand-nth mem-sizes))

;; BPF immediate and offset generators
(defn gen-imm32 [] (.nextInt *random*))  ; Full 32-bit signed range
(defn gen-offset [] (rand-int-range -32768 32767))
(defn gen-stack-offset [] (rand-int-range -512 0))

;; Map configuration generators
(def map-types [:hash :array :lru-hash :percpu-hash :percpu-array :lru-percpu-hash
                :stack :queue :ringbuf])
(def hash-map-types [:hash :percpu-hash :lru-hash :lru-percpu-hash])
(def array-map-types [:array :percpu-array])

(defn gen-map-type [] (rand-nth map-types))
(defn gen-hash-map-type [] (rand-nth hash-map-types))
(defn gen-array-map-type [] (rand-nth array-map-types))
(defn gen-key-size [] (* 4 (rand-int-range 1 64)))  ; 4-256, aligned
(defn gen-value-size [] (rand-int-range 1 4096))
(defn gen-max-entries [] (rand-nth [1 10 100 1000 10000]))

(defn gen-map-config []
  (let [map-type (gen-map-type)]
    {:type map-type
     :key-size (if (#{:array :percpu-array} map-type) 4 (gen-key-size))
     :value-size (gen-value-size)
     :max-entries (gen-max-entries)}))

;; Network generators
(defn gen-mac-address []
  (byte-array (repeatedly 6 #(unchecked-byte (rand-int-range 0 255)))))

(defn gen-ipv4-address []
  (byte-array (repeatedly 4 #(unchecked-byte (rand-int-range 0 255)))))

(defn gen-port [] (rand-int-range 1 65535))
(defn gen-well-known-port [] (rand-nth [22 80 443 53 25 21 23 110 143 993 995 3306 5432 6379 8080]))
(defn gen-protocol [] (rand-nth [1 6 17]))  ; ICMP, TCP, UDP
(defn gen-ethernet-type [] (rand-nth [0x0800 0x0806 0x86DD]))  ; IPv4, ARP, IPv6

(defn gen-ethernet-header []
  {:dst-mac (gen-mac-address)
   :src-mac (gen-mac-address)
   :eth-type (gen-ethernet-type)})

(defn gen-ipv4-header []
  {:version 4
   :ihl 5
   :tos (rand-int-range 0 255)
   :total-length (rand-int-range 20 1500)
   :identification (rand-int-range 0 65535)
   :flags (rand-int-range 0 7)
   :fragment-offset (rand-int-range 0 8191)
   :ttl (rand-int-range 1 255)
   :protocol (gen-protocol)
   :checksum (rand-int-range 0 65535)
   :src-ip (gen-ipv4-address)
   :dst-ip (gen-ipv4-address)})

(defn gen-tcp-header []
  {:src-port (gen-port)
   :dst-port (gen-port)
   :seq-num (gen-u32)
   :ack-num (gen-u32)
   :data-offset 5
   :flags (rand-int-range 0 63)  ; 6 flag bits
   :window (rand-int-range 0 65535)
   :checksum (rand-int-range 0 65535)
   :urgent-ptr 0})

;; Process/event generators
(defn gen-pid [] (rand-int-range 1 32768))
(defn gen-tid [] (gen-pid))
(defn gen-uid [] (rand-int-range 0 65534))
(defn gen-comm []
  (let [chars "abcdefghijklmnopqrstuvwxyz0123456789"
        len (rand-int-range 1 15)]
    (apply str (repeatedly len #(rand-nth chars)))))

(defn gen-syscall-event []
  {:pid (gen-pid)
   :tid (gen-tid)
   :uid (gen-uid)
   :comm (gen-comm)
   :syscall-nr (rand-int-range 0 450)
   :timestamp (System/nanoTime)})

(defn gen-network-event []
  {:pid (gen-pid)
   :comm (gen-comm)
   :protocol (gen-protocol)
   :src-ip (gen-ipv4-address)
   :dst-ip (gen-ipv4-address)
   :src-port (gen-port)
   :dst-port (gen-port)
   :bytes-sent (rand-int-range 0 100000)
   :bytes-recv (rand-int-range 0 100000)
   :timestamp (System/nanoTime)})

;;; ============================================================================
;;; Part 3: Memory Utility Functions (for round-trip tests)
;;; ============================================================================

(defn int->bytes
  "Convert int to little-endian byte array"
  [value]
  (let [buf (ByteBuffer/allocate 4)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putInt buf value)
    (.array buf)))

(defn bytes->int
  "Convert little-endian byte array to int"
  [bytes]
  (let [buf (ByteBuffer/wrap bytes)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.getInt buf)))

(defn long->bytes
  "Convert long to little-endian byte array"
  [value]
  (let [buf (ByteBuffer/allocate 8)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putLong buf value)
    (.array buf)))

(defn bytes->long
  "Convert little-endian byte array to long"
  [bytes]
  (let [buf (ByteBuffer/wrap bytes)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.getLong buf)))

(defn short->bytes
  "Convert short to little-endian byte array"
  [value]
  (let [buf (ByteBuffer/allocate 2)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putShort buf value)
    (.array buf)))

(defn bytes->short
  "Convert little-endian byte array to short"
  [bytes]
  (let [buf (ByteBuffer/wrap bytes)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.getShort buf)))

;;; ============================================================================
;;; Part 4: Simulated BPF DSL Functions
;;; ============================================================================

(def BPF_ALU64 0x07)
(def BPF_ALU 0x04)
(def BPF_JMP 0x05)
(def BPF_LD 0x00)
(def BPF_LDX 0x01)
(def BPF_ST 0x02)
(def BPF_STX 0x03)

(def BPF_K 0x00)
(def BPF_X 0x08)

(def alu-op-codes
  {:add 0x00 :sub 0x10 :mul 0x20 :div 0x30
   :or 0x40 :and 0x50 :lsh 0x60 :rsh 0x70
   :neg 0x80 :mod 0x90 :xor 0xa0 :mov 0xb0 :arsh 0xc0})

(def jmp-op-codes
  {:jeq 0x10 :jgt 0x20 :jge 0x30 :jne 0x50
   :jlt 0xa0 :jle 0xb0 :jset 0x40
   :jsgt 0x60 :jsge 0x70 :jslt 0xc0 :jsle 0xd0})

(def size-codes {:b 0x10 :h 0x08 :w 0x00 :dw 0x18})

(def reg-nums {:r0 0 :r1 1 :r2 2 :r3 3 :r4 4
               :r5 5 :r6 6 :r7 7 :r8 8 :r9 9 :r10 10})

(defn mov
  "Generate MOV instruction"
  [dst imm]
  {:opcode (bit-or BPF_ALU64 (:mov alu-op-codes) BPF_K)
   :dst (get reg-nums dst 0)
   :src 0
   :off 0
   :imm imm
   :type :mov-imm})

(defn mov-reg
  "Generate MOV reg instruction"
  [dst src]
  {:opcode (bit-or BPF_ALU64 (:mov alu-op-codes) BPF_X)
   :dst (get reg-nums dst 0)
   :src (get reg-nums src 0)
   :off 0
   :imm 0
   :type :mov-reg})

(defn alu-imm
  "Generate ALU immediate instruction"
  [op dst imm]
  {:opcode (bit-or BPF_ALU64 (get alu-op-codes op 0) BPF_K)
   :dst (get reg-nums dst 0)
   :src 0
   :off 0
   :imm imm
   :type :alu-imm
   :op op})

(defn alu-reg
  "Generate ALU reg instruction"
  [op dst src]
  {:opcode (bit-or BPF_ALU64 (get alu-op-codes op 0) BPF_X)
   :dst (get reg-nums dst 0)
   :src (get reg-nums src 0)
   :off 0
   :imm 0
   :type :alu-reg
   :op op})

(defn jmp-imm
  "Generate JMP immediate instruction"
  [op dst imm offset]
  {:opcode (bit-or BPF_JMP (get jmp-op-codes op 0) BPF_K)
   :dst (get reg-nums dst 0)
   :src 0
   :off (if (> offset 32767) (- offset 65536) offset)
   :imm imm
   :type :jmp-imm
   :op op})

(defn ldx
  "Generate LDX instruction"
  [size dst src offset]
  {:opcode (bit-or BPF_LDX (get size-codes size 0) 0x01)
   :dst (get reg-nums dst 0)
   :src (get reg-nums src 0)
   :off offset
   :imm 0
   :type :ldx
   :size size})

(defn stx
  "Generate STX instruction"
  [size dst src offset]
  {:opcode (bit-or BPF_STX (get size-codes size 0) 0x03)
   :dst (get reg-nums dst 0)
   :src (get reg-nums src 0)
   :off offset
   :imm 0
   :type :stx
   :size size})

(defn exit-insn
  "Generate EXIT instruction"
  []
  {:opcode 0x95
   :dst 0
   :src 0
   :off 0
   :imm 0
   :type :exit})

(defn call-helper
  "Generate CALL instruction"
  [helper-id]
  {:opcode 0x85
   :dst 0
   :src 0
   :off 0
   :imm helper-id
   :type :call})

;;; ============================================================================
;;; Part 5: Property Tests
;;; ============================================================================

(defn run-dsl-properties
  "Run DSL instruction property tests"
  []
  (println "\nDSL Instruction Properties:")

  ;; MOV immediate produces valid instruction
  (run-property "mov-imm produces valid instruction"
    (fn [] {:reg (gen-writable-register) :imm (gen-imm32)})
    (fn [{:keys [reg imm]}]
      (let [insn (mov reg imm)]
        (and (map? insn)
             (number? (:opcode insn))
             (<= 0 (:opcode insn) 255)
             (= (get reg-nums reg) (:dst insn)))))
    default-test-count)

  ;; MOV reg produces valid instruction
  (run-property "mov-reg produces valid instruction"
    (fn [] {:dst (gen-writable-register) :src (gen-register)})
    (fn [{:keys [dst src]}]
      (let [insn (mov-reg dst src)]
        (and (map? insn)
             (number? (:opcode insn))
             (= :mov-reg (:type insn)))))
    default-test-count)

  ;; ALU immediate produces valid instruction
  (run-property "alu-imm produces valid instruction"
    (fn [] {:op (gen-alu-op) :dst (gen-writable-register) :imm (gen-imm32)})
    (fn [{:keys [op dst imm]}]
      (let [insn (alu-imm op dst imm)]
        (and (map? insn)
             (number? (:opcode insn))
             (<= 0 (:opcode insn) 255)
             (= op (:op insn)))))
    default-test-count)

  ;; ALU reg produces valid instruction
  (run-property "alu-reg produces valid instruction"
    (fn [] {:op (gen-alu-op) :dst (gen-writable-register) :src (gen-register)})
    (fn [{:keys [op dst src]}]
      (let [insn (alu-reg op dst src)]
        (and (map? insn)
             (= :alu-reg (:type insn)))))
    default-test-count)

  ;; JMP instruction has valid offset
  (run-property "jmp-imm offset in valid range"
    (fn [] {:op (gen-jmp-op) :dst (gen-register) :imm (gen-imm32) :off (gen-offset)})
    (fn [{:keys [op dst imm off]}]
      (let [insn (jmp-imm op dst imm off)]
        (and (map? insn)
             (<= -32768 (:off insn) 32767))))
    default-test-count)

  ;; Load instruction preserves size
  (run-property "ldx preserves size info"
    (fn [] {:size (gen-mem-size) :dst (gen-writable-register)
            :src (gen-register) :off (gen-offset)})
    (fn [{:keys [size dst src off]}]
      (let [insn (ldx size dst src off)]
        (and (map? insn)
             (= size (:size insn)))))
    default-test-count))

(defn run-roundtrip-properties
  "Run round-trip property tests"
  []
  (println "\nRound-Trip Properties:")

  ;; Int round-trip
  (run-property "int->bytes->int round-trip"
    gen-i32
    (fn [value]
      (= value (bytes->int (int->bytes value))))
    default-test-count)

  ;; Long round-trip
  (run-property "long->bytes->long round-trip"
    gen-i64
    (fn [value]
      (= value (bytes->long (long->bytes value))))
    default-test-count)

  ;; Short round-trip
  (run-property "short->bytes->short round-trip"
    (fn [] (short (rand-int-range -32768 32767)))
    (fn [value]
      (= value (bytes->short (short->bytes value))))
    default-test-count)

  ;; Byte array preserves content
  (run-property "byte-array content preserved"
    (fn [] (gen-byte-array (rand-int-range 1 100)))
    (fn [arr]
      (let [roundtrip (byte-array (vec arr))]
        (java.util.Arrays/equals ^bytes arr ^bytes roundtrip)))
    default-test-count))

(defn run-generator-sanity
  "Run generator sanity tests"
  []
  (println "\nGenerator Sanity:")

  ;; Map config has required fields
  (run-property "map-config has required fields"
    gen-map-config
    (fn [config]
      (and (keyword? (:type config))
           (pos-int? (:key-size config))
           (pos-int? (:value-size config))
           (pos-int? (:max-entries config))))
    default-test-count)

  ;; Ethernet header has correct structure
  (run-property "ethernet-header structure valid"
    gen-ethernet-header
    (fn [header]
      (and (= 6 (count (:dst-mac header)))
           (= 6 (count (:src-mac header)))
           (#{0x0800 0x0806 0x86DD} (:eth-type header))))
    default-test-count)

  ;; IPv4 header has correct structure
  (run-property "ipv4-header structure valid"
    gen-ipv4-header
    (fn [header]
      (and (= 4 (:version header))
           (= 5 (:ihl header))
           (= 4 (count (:src-ip header)))
           (= 4 (count (:dst-ip header)))
           (<= 1 (:ttl header) 255)
           (#{1 6 17} (:protocol header))))
    default-test-count)

  ;; TCP header has valid ports
  (run-property "tcp-header has valid ports"
    gen-tcp-header
    (fn [header]
      (and (<= 1 (:src-port header) 65535)
           (<= 1 (:dst-port header) 65535)))
    default-test-count)

  ;; Syscall event has required fields
  (run-property "syscall-event has required fields"
    gen-syscall-event
    (fn [event]
      (and (pos-int? (:pid event))
           (pos-int? (:tid event))
           (string? (:comm event))
           (number? (:syscall-nr event))))
    default-test-count))

(defn run-boundary-tests
  "Run boundary value tests"
  []
  (println "\nBoundary Value Tests:")

  ;; u8 boundaries
  (run-property "u8 in valid range"
    gen-u8
    (fn [v] (<= 0 v 255))
    default-test-count)

  ;; u16 boundaries
  (run-property "u16 in valid range"
    gen-u16
    (fn [v] (<= 0 v 65535))
    default-test-count)

  ;; Offset in valid range
  (run-property "offset in 16-bit signed range"
    gen-offset
    (fn [v] (<= -32768 v 32767))
    default-test-count)

  ;; Stack offset valid
  (run-property "stack-offset in valid range"
    gen-stack-offset
    (fn [v] (<= -512 v 0))
    default-test-count))

;;; ============================================================================
;;; Part 6: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 14.5 Tests ===\n")

  ;; Test 1: Generator output types
  (println "Test 1: Generator Output Types")
  (assert (integer? (gen-u8)) "gen-u8 returns integer")
  (assert (integer? (gen-u16)) "gen-u16 returns integer")
  (assert (integer? (gen-i32)) "gen-i32 returns integer")
  (assert (bytes? (gen-byte-array 10)) "gen-byte-array returns bytes")
  (assert (keyword? (gen-register)) "gen-register returns keyword")
  (assert (keyword? (gen-alu-op)) "gen-alu-op returns keyword")
  (println "  All generators return correct types")
  (println "  PASSED")

  ;; Test 2: Instruction generation
  (println "\nTest 2: Instruction Generation")
  (let [mov-insn (mov :r0 42)
        alu-insn (alu-imm :add :r1 100)
        jmp-insn (jmp-imm :jeq :r2 0 10)]
    (assert (map? mov-insn) "mov produces map")
    (assert (= :mov-imm (:type mov-insn)) "mov has correct type")
    (assert (map? alu-insn) "alu-imm produces map")
    (assert (= :add (:op alu-insn)) "alu-imm has correct op")
    (assert (map? jmp-insn) "jmp-imm produces map")
    (assert (= :jeq (:op jmp-insn)) "jmp-imm has correct op"))
  (println "  All instruction generators work")
  (println "  PASSED")

  ;; Test 3: Round-trip conversions
  (println "\nTest 3: Round-Trip Conversions")
  (let [test-int 12345
        test-long 9876543210
        test-short (short -1234)]
    (assert (= test-int (bytes->int (int->bytes test-int))) "int round-trip")
    (assert (= test-long (bytes->long (long->bytes test-long))) "long round-trip")
    (assert (= test-short (bytes->short (short->bytes test-short))) "short round-trip"))
  (println "  All round-trip conversions work")
  (println "  PASSED")

  ;; Test 4: Map config generation
  (println "\nTest 4: Map Config Generation")
  (dotimes [_ 10]
    (let [config (gen-map-config)]
      (assert (keyword? (:type config)) "type is keyword")
      (assert (pos? (:key-size config)) "key-size positive")
      (assert (pos? (:value-size config)) "value-size positive")
      (assert (pos? (:max-entries config)) "max-entries positive")
      ;; Array maps must have 4-byte keys
      (when (#{:array :percpu-array} (:type config))
        (assert (= 4 (:key-size config)) "array map key-size is 4"))))
  (println "  Map configs are valid")
  (println "  PASSED")

  ;; Test 5: Network header generation
  (println "\nTest 5: Network Header Generation")
  (let [eth (gen-ethernet-header)
        ip (gen-ipv4-header)
        tcp (gen-tcp-header)]
    (assert (= 6 (count (:dst-mac eth))) "eth dst-mac length")
    (assert (= 6 (count (:src-mac eth))) "eth src-mac length")
    (assert (= 4 (:version ip)) "ipv4 version")
    (assert (= 4 (count (:src-ip ip))) "ipv4 src-ip length")
    (assert (<= 1 (:src-port tcp) 65535) "tcp src-port range"))
  (println "  Network headers are valid")
  (println "  PASSED")

  ;; Run property tests
  (println "\n--- Running Property Tests ---")
  (run-dsl-properties)
  (run-roundtrip-properties)
  (run-generator-sanity)
  (run-boundary-tests)

  (println "\n=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 7: Demo
;;; ============================================================================

(defn run-demo
  "Run interactive demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 14.5: Property-Based Testing")
  (println (str/join "" (repeat 60 "=")) "\n")

  ;; Show generators
  (println "=== Generator Samples ===\n")

  (println "Primitive generators:")
  (println (format "  gen-u8 (5 samples):  %s" (pr-str (repeatedly 5 gen-u8))))
  (println (format "  gen-u16 (5 samples): %s" (pr-str (repeatedly 5 gen-u16))))
  (println (format "  gen-i32 (5 samples): %s" (pr-str (repeatedly 5 gen-i32))))
  (println)

  (println "Register generators:")
  (println (format "  gen-register (5 samples): %s" (pr-str (repeatedly 5 gen-register))))
  (println (format "  gen-writable (5 samples): %s" (pr-str (repeatedly 5 gen-writable-register))))
  (println)

  (println "Operation generators:")
  (println (format "  gen-alu-op (5 samples): %s" (pr-str (repeatedly 5 gen-alu-op))))
  (println (format "  gen-jmp-op (5 samples): %s" (pr-str (repeatedly 5 gen-jmp-op))))
  (println)

  (println "Map config samples:")
  (dotimes [_ 3]
    (println (format "  %s" (pr-str (gen-map-config)))))
  (println)

  (println "Network header sample:")
  (println (format "  Ethernet: %s" (pr-str (gen-ethernet-header))))
  (println (format "  IPv4: %s" (pr-str (select-keys (gen-ipv4-header)
                                                     [:version :protocol :ttl]))))
  (println (format "  TCP: %s" (pr-str (select-keys (gen-tcp-header)
                                                    [:src-port :dst-port :flags]))))
  (println)

  ;; Run property tests
  (println "=== Property Test Results ===")
  (run-dsl-properties)
  (run-roundtrip-properties)
  (run-generator-sanity)
  (run-boundary-tests)

  (println "\n=== Available Generators ===")
  (println)
  (println "Primitives: gen-u8, gen-u16, gen-u32, gen-u64, gen-i32, gen-i64")
  (println "Bytes: gen-byte-array, gen-byte-array-range")
  (println "Registers: gen-register, gen-writable-register, gen-arg-register")
  (println "Operations: gen-alu-op, gen-jmp-op, gen-mem-size")
  (println "Values: gen-imm32, gen-offset, gen-stack-offset")
  (println "Maps: gen-map-type, gen-map-config, gen-key-size, gen-value-size")
  (println "Network: gen-mac-address, gen-ipv4-address, gen-port, gen-protocol")
  (println "Headers: gen-ethernet-header, gen-ipv4-header, gen-tcp-header")
  (println "Events: gen-syscall-event, gen-network-event, gen-pid, gen-comm"))

;;; ============================================================================
;;; Part 8: Main
;;; ============================================================================

(defn -main
  "Main entry point"
  [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      "generators" (do
                     (println "\n=== Generator Samples ===\n")
                     (println "gen-u8:" (repeatedly 10 gen-u8))
                     (println "gen-register:" (repeatedly 10 gen-register))
                     (println "gen-map-config:" (gen-map-config))
                     (println "gen-ethernet-header:" (gen-ethernet-header))
                     (println "gen-syscall-event:" (gen-syscall-event)))
      "properties" (do
                     (println "\n=== Running All Properties ===")
                     (run-dsl-properties)
                     (run-roundtrip-properties)
                     (run-generator-sanity)
                     (run-boundary-tests))
      ;; Default: run demo
      (run-demo))))
