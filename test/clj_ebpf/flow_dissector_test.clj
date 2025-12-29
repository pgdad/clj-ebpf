(ns clj-ebpf.flow-dissector-test
  "Tests for FLOW_DISSECTOR program support.

   These tests verify:
   - FLOW_DISSECTOR constants are defined correctly
   - DSL helpers generate valid bytecode
   - Flow keys field access works correctly
   - Parsing helper patterns
   - Program building and assembly functions

   Note: Actual FLOW_DISSECTOR program loading and attachment requires
   root privileges and kernel 4.2+. These tests focus on the
   code generation aspects that can run without privileges."
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.constants :as const]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.flow-dissector :as fd]))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-flow-dissector-program-type
  (testing "FLOW_DISSECTOR program type is defined"
    (is (= 22 (const/prog-type->num :flow-dissector)))
    (is (= :flow-dissector (const/int->prog-type 22)))))

(deftest test-flow-dissector-attach-type
  (testing "FLOW_DISSECTOR attach type is defined"
    (is (= 17 (const/attach-type->num :flow-dissector)))
    (is (= :flow-dissector (const/int->attach-type 17)))))

;; ============================================================================
;; Verdict Constants Tests
;; ============================================================================

(deftest test-flow-dissector-verdict-values
  (testing "FLOW_DISSECTOR verdict values"
    (is (= 0 (fd/flow-dissector-action :ok)))
    (is (= -1 (fd/flow-dissector-action :drop)))))

(deftest test-flow-dissector-verdict-map
  (testing "FLOW_DISSECTOR verdict map contents"
    (is (= {:ok 0 :drop -1} fd/flow-dissector-verdict))))

(deftest test-flow-dissector-invalid-action
  (testing "Invalid FLOW_DISSECTOR action throws"
    (is (thrown? clojure.lang.ExceptionInfo
                 (fd/flow-dissector-action :invalid)))))

;; ============================================================================
;; Flow Keys Offset Tests
;; ============================================================================

(deftest test-flow-keys-offsets
  (testing "bpf_flow_keys field offsets"
    (are [field expected] (= expected (fd/flow-keys-offset field))
      :nhoff          0
      :thoff          2
      :addr-proto     4
      :is-frag        6
      :is-first-frag  7
      :is-encap       8
      :ip-proto       9
      :n-proto        10
      :sport          12
      :dport          14
      :ipv4-src       16
      :ipv4-dst       20
      :ipv6-src       16
      :ipv6-dst       32
      :flags          48
      :flow-label     52)))

(deftest test-flow-keys-invalid-field
  (testing "Invalid flow_keys field throws"
    (is (thrown? clojure.lang.ExceptionInfo
                 (fd/flow-keys-offset :invalid-field)))))

;; ============================================================================
;; Protocol Constants Tests
;; ============================================================================

(deftest test-ethernet-protocols
  (testing "Ethernet protocol constants"
    (is (= 0x0800 (:ipv4 fd/ethernet-protocols)))
    (is (= 0x86DD (:ipv6 fd/ethernet-protocols)))
    (is (= 0x0806 (:arp fd/ethernet-protocols)))
    (is (= 0x8100 (:vlan fd/ethernet-protocols)))))

(deftest test-ip-protocols
  (testing "IP protocol constants"
    (is (= 1 (:icmp fd/ip-protocols)))
    (is (= 6 (:tcp fd/ip-protocols)))
    (is (= 17 (:udp fd/ip-protocols)))
    (is (= 47 (:gre fd/ip-protocols)))
    (is (= 132 (:sctp fd/ip-protocols)))))

;; ============================================================================
;; SKB Context Offset Tests (reused from TC)
;; ============================================================================

(deftest test-skb-offsets-available
  (testing "__sk_buff offsets are available from TC"
    (is (map? fd/skb-offsets))
    (is (contains? fd/skb-offsets :data))
    (is (contains? fd/skb-offsets :data-end))
    (is (contains? fd/skb-offsets :flow-keys))))

(deftest test-skb-offset-function
  (testing "skb-offset function works"
    (is (number? (fd/skb-offset :data)))
    (is (number? (fd/skb-offset :data-end)))
    (is (number? (fd/skb-offset :flow-keys)))))

;; ============================================================================
;; Flow Keys Flags Tests
;; ============================================================================

(deftest test-flow-keys-flags
  (testing "flow_keys flags are defined"
    (is (= 0x0001 (:frag fd/flow-keys-flags)))
    (is (= 0x0002 (:first-frag fd/flow-keys-flags)))
    (is (= 0x0004 (:encap fd/flow-keys-flags)))))

;; ============================================================================
;; Header Size Constants Tests
;; ============================================================================

(deftest test-header-size-constants
  (testing "Header size constants are defined"
    (is (= 14 fd/ethernet-header-size))
    (is (= 20 fd/ipv4-header-min-size))
    (is (= 40 fd/ipv6-header-size))
    (is (= 20 fd/tcp-header-min-size))
    (is (= 8 fd/udp-header-size))))

;; ============================================================================
;; DSL Helper Tests - Prologue
;; ============================================================================

(deftest test-flow-dissector-prologue
  (testing "flow-dissector-prologue generates bytecode"
    (let [insns (fd/flow-dissector-prologue :r6 :r2 :r3)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-flow-dissector-prologue-different-registers
  (testing "flow-dissector-prologue with different registers"
    (let [insns (fd/flow-dissector-prologue :r7 :r8 :r9)]
      (is (vector? insns))
      (is (every? bytes? insns)))))

;; ============================================================================
;; DSL Helper Tests - Context Field Access
;; ============================================================================

(deftest test-flow-dissector-load-ctx-field
  (testing "flow-dissector-load-ctx-field generates bytecode"
    (let [insn (fd/flow-dissector-load-ctx-field :r6 :r0 :data)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-dissector-get-flow-keys-ptr
  (testing "flow-dissector-get-flow-keys-ptr generates bytecode"
    (let [insn (fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

;; ============================================================================
;; DSL Helper Tests - Flow Keys Store Operations
;; ============================================================================

(deftest test-flow-keys-store-u8
  (testing "flow-keys-store-u8 generates bytecode"
    (let [insn (fd/flow-keys-store-u8 :r7 :is-frag :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-store-u16
  (testing "flow-keys-store-u16 generates bytecode"
    (let [insn (fd/flow-keys-store-u16 :r7 :nhoff :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-store-u32
  (testing "flow-keys-store-u32 generates bytecode"
    (let [insn (fd/flow-keys-store-u32 :r7 :ipv4-src :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-set-nhoff
  (testing "flow-keys-set-nhoff generates bytecode"
    (let [insn (fd/flow-keys-set-nhoff :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-set-thoff
  (testing "flow-keys-set-thoff generates bytecode"
    (let [insn (fd/flow-keys-set-thoff :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-set-addr-proto
  (testing "flow-keys-set-addr-proto generates bytecode"
    (let [insn (fd/flow-keys-set-addr-proto :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-set-ip-proto
  (testing "flow-keys-set-ip-proto generates bytecode"
    (let [insn (fd/flow-keys-set-ip-proto :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-set-n-proto
  (testing "flow-keys-set-n-proto generates bytecode"
    (let [insn (fd/flow-keys-set-n-proto :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-set-ports
  (testing "flow-keys-set-ports generates bytecode"
    (let [insns (fd/flow-keys-set-ports :r7 :r0 :r1)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-flow-keys-set-ipv4-addrs
  (testing "flow-keys-set-ipv4-addrs generates bytecode"
    (let [insns (fd/flow-keys-set-ipv4-addrs :r7 :r0 :r1)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-flow-keys-set-is-frag
  (testing "flow-keys-set-is-frag generates bytecode"
    (let [insn (fd/flow-keys-set-is-frag :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-set-is-first-frag
  (testing "flow-keys-set-is-first-frag generates bytecode"
    (let [insn (fd/flow-keys-set-is-first-frag :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-set-is-encap
  (testing "flow-keys-set-is-encap generates bytecode"
    (let [insn (fd/flow-keys-set-is-encap :r7 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

;; ============================================================================
;; DSL Helper Tests - Flow Keys Load Operations
;; ============================================================================

(deftest test-flow-keys-load-u8
  (testing "flow-keys-load-u8 generates bytecode"
    (let [insn (fd/flow-keys-load-u8 :r7 :r0 :ip-proto)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-load-u16
  (testing "flow-keys-load-u16 generates bytecode"
    (let [insn (fd/flow-keys-load-u16 :r7 :r0 :nhoff)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-flow-keys-load-u32
  (testing "flow-keys-load-u32 generates bytecode"
    (let [insn (fd/flow-keys-load-u32 :r7 :r0 :ipv4-src)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

;; ============================================================================
;; DSL Helper Tests - Return Patterns
;; ============================================================================

(deftest test-flow-dissector-ok
  (testing "flow-dissector-ok generates bytecode"
    (let [insns (fd/flow-dissector-ok)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-flow-dissector-drop
  (testing "flow-dissector-drop generates bytecode"
    (let [insns (fd/flow-dissector-drop)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; DSL Helper Tests - Bounds Check
;; ============================================================================

(deftest test-flow-dissector-bounds-check
  (testing "flow-dissector-bounds-check generates bytecode"
    (let [insns (fd/flow-dissector-bounds-check :r2 :r3 14 3)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-flow-dissector-bounds-check-different-offsets
  (testing "Bounds check with various offsets"
    (doseq [offset [0 14 34 54 128]]
      (let [insns (fd/flow-dissector-bounds-check :r2 :r3 offset 1)]
        (is (vector? insns))
        (is (every? bytes? insns))))))

;; ============================================================================
;; DSL Helper Tests - Parsing Patterns
;; ============================================================================

(deftest test-flow-dissector-parse-ethernet
  (testing "flow-dissector-parse-ethernet generates bytecode"
    (let [insns (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-flow-dissector-parse-ipv4
  (testing "flow-dissector-parse-ipv4 generates bytecode"
    (let [insns (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-flow-dissector-parse-tcp-ports
  (testing "flow-dissector-parse-tcp-ports generates bytecode"
    (let [insns (fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-flow-dissector-parse-udp-ports
  (testing "flow-dissector-parse-udp-ports generates bytecode"
    (let [insns (fd/flow-dissector-parse-udp-ports :r2 :r3 :r7 34 :r0)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Program Builder Tests
;; ============================================================================

(deftest test-build-flow-dissector-program
  (testing "build-flow-dissector-program with minimal body"
    (let [bytecode (fd/build-flow-dissector-program {:body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "build-flow-dissector-program with custom registers"
    (let [bytecode (fd/build-flow-dissector-program
                     {:ctx-reg :r7
                      :data-reg :r8
                      :data-end-reg :r9
                      :body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "build-flow-dissector-program with default ok"
    (let [bytecode (fd/build-flow-dissector-program
                     {:body []
                      :default-action :ok})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "build-flow-dissector-program with default drop"
    (let [bytecode (fd/build-flow-dissector-program
                     {:body []
                      :default-action :drop})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Section Names Tests
;; ============================================================================

(deftest test-flow-dissector-section-name
  (testing "flow-dissector-section-name without name"
    (is (= "flow_dissector" (fd/flow-dissector-section-name))))

  (testing "flow-dissector-section-name with name"
    (is (= "flow_dissector/my_prog" (fd/flow-dissector-section-name "my_prog")))))

(deftest test-make-flow-dissector-info
  (testing "make-flow-dissector-info creates correct metadata"
    (let [info (fd/make-flow-dissector-info "test_prog" [])]
      (is (= "test_prog" (:name info)))
      (is (= "flow_dissector/test_prog" (:section info)))
      (is (= :flow-dissector (:type info)))
      (is (= [] (:instructions info))))))

;; ============================================================================
;; Byte Order Utility Tests
;; ============================================================================

(deftest test-htons
  (testing "htons converts correctly"
    (is (= 0x0050 (fd/htons 0x5000)))  ; Port 80 -> network order
    (is (= 0x901F (fd/htons 0x1F90)))  ; Port 8080 -> network order
    (is (= 0x0100 (fd/htons 0x0001)))))

(deftest test-ntohs
  (testing "ntohs converts correctly"
    (is (= 0x5000 (fd/ntohs 0x0050)))
    (is (= 0x1F90 (fd/ntohs 0x901F)))))

(deftest test-htonl
  (testing "htonl converts correctly"
    ;; 192.168.1.1 = 0xC0A80101 -> network order = 0x0101A8C0
    (is (= 0x0101A8C0 (fd/htonl 0xC0A80101)))
    ;; 127.0.0.1 = 0x7F000001 -> network order = 0x0100007F
    (is (= 0x0100007F (fd/htonl 0x7F000001)))))

(deftest test-ntohl
  (testing "ntohl converts correctly"
    (is (= 0xC0A80101 (fd/ntohl 0x0101A8C0)))
    (is (= 0x7F000001 (fd/ntohl 0x0100007F)))))

;; ============================================================================
;; Complete Program Assembly Tests
;; ============================================================================

(deftest test-complete-flow-dissector-program-assembly
  (testing "Complete FLOW_DISSECTOR program assembles correctly"
    (let [;; Build a simple program that parses Ethernet and returns OK
          bytecode (dsl/assemble
                    (vec (concat
                          (fd/flow-dissector-prologue :r6 :r2 :r3)
                          ;; Get flow_keys pointer
                          [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
                          ;; Parse Ethernet header
                          (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)
                          ;; Return OK
                          (fd/flow-dissector-ok))))]
      (is (bytes? bytecode))
      ;; Should have multiple instructions
      (is (>= (count bytecode) 48)))))  ; At least 6 instructions

(deftest test-flow-dissector-program-with-ipv4-parsing
  (testing "FLOW_DISSECTOR program with IPv4 parsing"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          (fd/flow-dissector-prologue :r6 :r2 :r3)
                          [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
                          ;; Parse Ethernet
                          (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)
                          ;; Parse IPv4
                          (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)
                          ;; Return OK
                          (fd/flow-dissector-ok))))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-flow-dissector-program-with-tcp-ports
  (testing "FLOW_DISSECTOR program parsing TCP ports"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          (fd/flow-dissector-prologue :r6 :r2 :r3)
                          [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
                          ;; Parse TCP ports at offset 34 (14 + 20)
                          (fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)
                          ;; Return OK
                          (fd/flow-dissector-ok))))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Instruction Size Tests
;; ============================================================================

(deftest test-instruction-sizes
  (testing "All single instructions are 8 bytes"
    (let [single-insns [(fd/flow-keys-set-nhoff :r7 :r0)
                        (fd/flow-keys-set-thoff :r7 :r0)
                        (fd/flow-keys-set-addr-proto :r7 :r0)
                        (fd/flow-keys-set-ip-proto :r7 :r0)
                        (fd/flow-keys-store-u8 :r7 :is-frag :r0)
                        (fd/flow-keys-store-u16 :r7 :nhoff :r0)
                        (fd/flow-keys-store-u32 :r7 :ipv4-src :r0)
                        (fd/flow-keys-load-u8 :r7 :r0 :ip-proto)
                        (fd/flow-keys-load-u16 :r7 :r0 :nhoff)
                        (fd/flow-keys-load-u32 :r7 :r0 :ipv4-src)]]
      (doseq [insn single-insns]
        (is (bytes? insn))
        (is (= 8 (count insn)))))))

(deftest test-vector-instruction-sizes
  (testing "All instructions in vectors are 8 bytes"
    (let [test-cases [[(fd/flow-dissector-ok) 2]
                      [(fd/flow-dissector-drop) 2]
                      [(fd/flow-keys-set-ports :r7 :r0 :r1) 2]
                      [(fd/flow-keys-set-ipv4-addrs :r7 :r0 :r1) 2]
                      [(fd/flow-dissector-bounds-check :r2 :r3 14 1) 3]]]
      (doseq [[insns expected-count] test-cases]
        (is (= expected-count (count insns)))
        (doseq [insn insns]
          (is (= 8 (count insn))))))))

;; ============================================================================
;; Edge Case Tests
;; ============================================================================

(deftest test-zero-offset-bounds-check
  (testing "Zero offset bounds check works"
    (let [insns (fd/flow-dissector-bounds-check :r2 :r3 0 1)]
      (is (vector? insns))
      (is (every? bytes? insns)))))

(deftest test-large-offset-bounds-check
  (testing "Large offset bounds check works"
    (let [insns (fd/flow-dissector-bounds-check :r2 :r3 1500 1)]
      (is (vector? insns))
      (is (every? bytes? insns)))))

(deftest test-various-skip-counts
  (testing "Various skip counts in bounds check"
    (doseq [skip [0 1 5 10 127]]
      (let [insns (fd/flow-dissector-bounds-check :r2 :r3 14 skip)]
        (is (vector? insns))
        (is (every? bytes? insns))))))

(deftest test-all-flow-keys-fields-can-be-stored
  (testing "All flow_keys fields can be stored"
    (let [u8-fields [:is-frag :is-first-frag :is-encap :ip-proto]
          u16-fields [:nhoff :thoff :addr-proto :n-proto :sport :dport]
          u32-fields [:ipv4-src :ipv4-dst :flags :flow-label]]
      (doseq [field u8-fields]
        (is (bytes? (fd/flow-keys-store-u8 :r7 field :r0))))
      (doseq [field u16-fields]
        (is (bytes? (fd/flow-keys-store-u16 :r7 field :r0))))
      (doseq [field u32-fields]
        (is (bytes? (fd/flow-keys-store-u32 :r7 field :r0)))))))

(deftest test-all-flow-keys-fields-can-be-loaded
  (testing "All flow_keys fields can be loaded"
    (let [u8-fields [:is-frag :is-first-frag :is-encap :ip-proto]
          u16-fields [:nhoff :thoff :addr-proto :n-proto :sport :dport]
          u32-fields [:ipv4-src :ipv4-dst :flags :flow-label]]
      (doseq [field u8-fields]
        (is (bytes? (fd/flow-keys-load-u8 :r7 :r0 field))))
      (doseq [field u16-fields]
        (is (bytes? (fd/flow-keys-load-u16 :r7 :r0 field))))
      (doseq [field u32-fields]
        (is (bytes? (fd/flow-keys-load-u32 :r7 :r0 field)))))))

;; ============================================================================
;; Register Combinations Tests
;; ============================================================================

(deftest test-prologue-register-combinations
  (testing "Prologue works with various register combinations"
    (let [regs [:r6 :r7 :r8 :r9]]
      (doseq [ctx regs
              data regs
              data-end regs
              :when (and (not= ctx data) (not= ctx data-end) (not= data data-end))]
        (let [insns (fd/flow-dissector-prologue ctx data data-end)]
          (is (vector? insns))
          (is (every? bytes? insns)))))))

(deftest test-store-register-combinations
  (testing "Store operations work with various registers"
    (doseq [keys-reg [:r6 :r7 :r8]
            value-reg [:r0 :r1 :r2 :r3]
            :when (not= keys-reg value-reg)]
      (is (bytes? (fd/flow-keys-set-nhoff keys-reg value-reg)))
      (is (bytes? (fd/flow-keys-set-ip-proto keys-reg value-reg))))))

;; ============================================================================
;; Complex Program Tests
;; ============================================================================

(deftest test-complete-ipv4-tcp-dissector
  (testing "Complete IPv4/TCP flow dissector assembles"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          ;; Prologue
                          (fd/flow-dissector-prologue :r6 :r2 :r3)
                          ;; Get flow_keys pointer
                          [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
                          ;; Parse Ethernet
                          (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)
                          ;; Parse IPv4
                          (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)
                          ;; Parse TCP ports
                          (fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)
                          ;; Return OK
                          (fd/flow-dissector-ok))))]
      (is (bytes? bytecode))
      ;; Complex program should have substantial size
      (is (>= (count bytecode) 200)))))

(deftest test-minimal-passthrough-dissector
  (testing "Minimal passthrough dissector assembles"
    (let [bytecode (fd/build-flow-dissector-program
                     {:body []
                      :default-action :ok})]
      (is (bytes? bytecode))
      ;; Minimal program: prologue (3 insns) + return (2 insns) = 5 insns = 40 bytes
      (is (>= (count bytecode) 40)))))

;; ============================================================================
;; Field Overlap Tests (IPv4 vs IPv6 addresses share space)
;; ============================================================================

(deftest test-ipv4-ipv6-address-overlap
  (testing "IPv4 and IPv6 source addresses share offset"
    (is (= (fd/flow-keys-offset :ipv4-src)
           (fd/flow-keys-offset :ipv6-src)))))

(deftest test-ipv6-dst-after-ipv4
  (testing "IPv6 dst is after IPv4 addresses"
    (is (> (fd/flow-keys-offset :ipv6-dst)
           (fd/flow-keys-offset :ipv4-dst)))))
