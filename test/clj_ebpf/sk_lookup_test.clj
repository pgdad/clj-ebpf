(ns clj-ebpf.sk-lookup-test
  "Tests for SK_LOOKUP program support.

   These tests verify:
   - SK_LOOKUP constants are defined correctly
   - DSL helpers generate valid bytecode
   - Context field access works correctly
   - Program building and assembly functions

   Note: Actual SK_LOOKUP program loading and attachment requires
   root privileges and kernel 5.9+. These tests focus on the
   code generation aspects that can run without privileges."
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.constants :as const]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.sk-lookup :as sk-lookup]))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-sk-lookup-program-type
  (testing "SK_LOOKUP program type is defined"
    (is (= 30 (const/prog-type->num :sk-lookup)))
    (is (= :sk-lookup (const/int->prog-type 30)))))

(deftest test-sk-lookup-attach-type
  (testing "SK_LOOKUP attach type is defined"
    (is (= 36 (const/attach-type->num :sk-lookup)))
    (is (= :sk-lookup (const/int->attach-type 36)))))

;; ============================================================================
;; Verdict Constants Tests
;; ============================================================================

(deftest test-sk-lookup-verdict-values
  (testing "SK_LOOKUP verdict values"
    (is (= 0 (sk-lookup/sk-lookup-action :drop)))
    (is (= 1 (sk-lookup/sk-lookup-action :pass)))))

(deftest test-sk-lookup-verdict-map
  (testing "SK_LOOKUP verdict map contents"
    (is (= {:drop 0 :pass 1} sk-lookup/sk-lookup-verdict))))

(deftest test-sk-lookup-invalid-action
  (testing "Invalid SK_LOOKUP action throws"
    (is (thrown? clojure.lang.ExceptionInfo
                 (sk-lookup/sk-lookup-action :invalid)))))

;; ============================================================================
;; Context Offset Tests
;; ============================================================================

(deftest test-sk-lookup-context-offsets
  (testing "bpf_sk_lookup context field offsets"
    (are [field expected] (= expected (sk-lookup/sk-lookup-offset field))
      :sk              0
      :family          8
      :protocol        12
      :remote-ip4      16
      :remote-ip6      20
      :remote-port     36
      :local-ip4       40
      :local-ip6       44
      :local-port      60
      :ingress-ifindex 64)))

(deftest test-sk-lookup-invalid-field
  (testing "Invalid context field throws"
    (is (thrown? clojure.lang.ExceptionInfo
                 (sk-lookup/sk-lookup-offset :invalid-field)))))

;; ============================================================================
;; Protocol Constants Tests
;; ============================================================================

(deftest test-address-families
  (testing "Address family constants"
    (is (= 2 (:af-inet sk-lookup/address-families)))
    (is (= 10 (:af-inet6 sk-lookup/address-families)))))

(deftest test-ip-protocols
  (testing "IP protocol constants"
    (is (= 6 (:tcp sk-lookup/ip-protocols)))
    (is (= 17 (:udp sk-lookup/ip-protocols)))))

;; ============================================================================
;; DSL Helper Tests - Prologue
;; ============================================================================

(deftest test-sk-lookup-prologue
  (testing "sk-lookup-prologue generates bytecode"
    (let [insns (sk-lookup/sk-lookup-prologue :r6)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

(deftest test-sk-lookup-prologue-different-registers
  (testing "sk-lookup-prologue with different registers"
    (doseq [reg [:r6 :r7 :r8 :r9]]
      (let [insns (sk-lookup/sk-lookup-prologue reg)]
        (is (vector? insns))
        (is (bytes? (first insns)))))))

;; ============================================================================
;; DSL Helper Tests - Context Field Access
;; ============================================================================

(deftest test-sk-lookup-load-field
  (testing "sk-lookup-load-field generates bytecode"
    (doseq [field [:family :protocol :local-port :remote-port :local-ip4 :remote-ip4]]
      (let [insn (sk-lookup/sk-lookup-load-field :r6 :r0 field)]
        (is (bytes? insn))
        (is (= 8 (count insn)))))))

(deftest test-sk-lookup-get-family
  (testing "sk-lookup-get-family generates bytecode"
    (let [insn (sk-lookup/sk-lookup-get-family :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-sk-lookup-get-protocol
  (testing "sk-lookup-get-protocol generates bytecode"
    (let [insn (sk-lookup/sk-lookup-get-protocol :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-sk-lookup-get-local-port
  (testing "sk-lookup-get-local-port generates bytecode"
    (let [insn (sk-lookup/sk-lookup-get-local-port :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-sk-lookup-get-remote-port
  (testing "sk-lookup-get-remote-port generates bytecode"
    (let [insn (sk-lookup/sk-lookup-get-remote-port :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-sk-lookup-get-local-ip4
  (testing "sk-lookup-get-local-ip4 generates bytecode"
    (let [insn (sk-lookup/sk-lookup-get-local-ip4 :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-sk-lookup-get-remote-ip4
  (testing "sk-lookup-get-remote-ip4 generates bytecode"
    (let [insn (sk-lookup/sk-lookup-get-remote-ip4 :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-sk-lookup-get-ifindex
  (testing "sk-lookup-get-ifindex generates bytecode"
    (let [insn (sk-lookup/sk-lookup-get-ifindex :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

;; ============================================================================
;; DSL Helper Tests - Helper Functions
;; ============================================================================

(deftest test-sk-assign
  (testing "sk-assign generates bytecode"
    (let [insns (sk-lookup/sk-assign :r6 :r7 0)]
      (is (vector? insns))
      (is (= 4 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-lookup-tcp
  (testing "sk-lookup-tcp generates bytecode"
    (let [insns (sk-lookup/sk-lookup-tcp :r6 :r7 12 0 0)]
      (is (vector? insns))
      (is (= 6 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-lookup-udp
  (testing "sk-lookup-udp generates bytecode"
    (let [insns (sk-lookup/sk-lookup-udp :r6 :r7 12 0 0)]
      (is (vector? insns))
      (is (= 6 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-release
  (testing "sk-release generates bytecode"
    (let [insns (sk-lookup/sk-release :r7)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; DSL Helper Tests - Return Patterns
;; ============================================================================

(deftest test-sk-lookup-pass
  (testing "sk-lookup-pass generates bytecode"
    (let [insns (sk-lookup/sk-lookup-pass)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-lookup-drop
  (testing "sk-lookup-drop generates bytecode"
    (let [insns (sk-lookup/sk-lookup-drop)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; DSL Helper Tests - Common Patterns
;; ============================================================================

(deftest test-sk-lookup-check-port
  (testing "sk-lookup-check-port generates bytecode"
    (let [insns (sk-lookup/sk-lookup-check-port :r6 :r7 8080 3)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-lookup-check-protocol
  (testing "sk-lookup-check-protocol with keyword protocol"
    (let [insns (sk-lookup/sk-lookup-check-protocol :r6 :r7 :tcp 3)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "sk-lookup-check-protocol with numeric protocol"
    (let [insns (sk-lookup/sk-lookup-check-protocol :r6 :r7 17 3)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-lookup-assign-and-pass
  (testing "sk-lookup-assign-and-pass generates bytecode"
    (let [insns (sk-lookup/sk-lookup-assign-and-pass :r6 :r7)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Program Builder Tests
;; ============================================================================

(deftest test-build-sk-lookup-program
  (testing "build-sk-lookup-program with minimal body"
    (let [bytecode (sk-lookup/build-sk-lookup-program
                    {:body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "build-sk-lookup-program with custom ctx-reg"
    (let [bytecode (sk-lookup/build-sk-lookup-program
                    {:ctx-reg :r7
                     :body []})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "build-sk-lookup-program with body and default pass"
    (let [bytecode (sk-lookup/build-sk-lookup-program
                    {:ctx-reg :r6
                     :body [(sk-lookup/sk-lookup-get-local-port :r6 :r0)]
                     :default-action :pass})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "build-sk-lookup-program with default drop"
    (let [bytecode (sk-lookup/build-sk-lookup-program
                    {:body []
                     :default-action :drop})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Section Names Tests
;; ============================================================================

(deftest test-sk-lookup-section-name
  (testing "sk-lookup-section-name without name"
    (is (= "sk_lookup" (sk-lookup/sk-lookup-section-name))))

  (testing "sk-lookup-section-name with name"
    (is (= "sk_lookup/my_prog" (sk-lookup/sk-lookup-section-name "my_prog")))))

(deftest test-make-sk-lookup-info
  (testing "make-sk-lookup-info creates correct metadata"
    (let [info (sk-lookup/make-sk-lookup-info "test_prog" [])]
      (is (= "test_prog" (:name info)))
      (is (= "sk_lookup/test_prog" (:section info)))
      (is (= :sk-lookup (:type info)))
      (is (= [] (:instructions info))))))

;; ============================================================================
;; Byte Order Utility Tests
;; ============================================================================

(deftest test-htons
  (testing "htons converts correctly"
    (is (= 0x0050 (sk-lookup/htons 0x5000)))  ; Port 80 -> network order
    (is (= 0x901F (sk-lookup/htons 0x1F90)))  ; Port 8080 -> network order
    (is (= 0x0100 (sk-lookup/htons 0x0001)))))

(deftest test-ntohs
  (testing "ntohs converts correctly"
    (is (= 0x5000 (sk-lookup/ntohs 0x0050)))
    (is (= 0x1F90 (sk-lookup/ntohs 0x901F)))))

(deftest test-htonl
  (testing "htonl converts correctly"
    ;; 192.168.1.1 = 0xC0A80101 -> network order = 0x0101A8C0
    (is (= 0x0101A8C0 (sk-lookup/htonl 0xC0A80101)))
    ;; 127.0.0.1 = 0x7F000001 -> network order = 0x0100007F
    (is (= 0x0100007F (sk-lookup/htonl 0x7F000001)))))

(deftest test-ntohl
  (testing "ntohl converts correctly"
    (is (= 0xC0A80101 (sk-lookup/ntohl 0x0101A8C0)))
    (is (= 0x7F000001 (sk-lookup/ntohl 0x0100007F)))))

(deftest test-ipv4-to-int
  (testing "ipv4-to-int converts correctly"
    (is (= 0x7F000001 (sk-lookup/ipv4-to-int "127.0.0.1")))
    (is (= 0xC0A80101 (sk-lookup/ipv4-to-int "192.168.1.1")))
    (is (= 0x0A000001 (sk-lookup/ipv4-to-int "10.0.0.1")))))

;; ============================================================================
;; Complete Program Assembly Tests
;; ============================================================================

(deftest test-complete-sk-lookup-program-assembly
  (testing "Complete SK_LOOKUP program assembles correctly"
    (let [;; Build a simple program that checks local port
          bytecode (dsl/assemble
                    (vec (concat
                          (sk-lookup/sk-lookup-prologue :r6)
                          ;; Load local port
                          [(sk-lookup/sk-lookup-get-local-port :r6 :r7)]
                          ;; Check if port 8080
                          [(dsl/jmp-imm :jne :r7 8080 2)]
                          ;; Port matches - return SK_PASS
                          (sk-lookup/sk-lookup-pass)
                          ;; Default - return SK_DROP
                          (sk-lookup/sk-lookup-drop))))]
      (is (bytes? bytecode))
      ;; Should have multiple instructions
      (is (>= (count bytecode) 48)))))  ; At least 6 instructions

(deftest test-sk-lookup-program-with-protocol-check
  (testing "SK_LOOKUP program with protocol check"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          (sk-lookup/sk-lookup-prologue :r6)
                          ;; Check if TCP
                          (sk-lookup/sk-lookup-check-protocol :r6 :r7 :tcp 2)
                          ;; Not TCP - drop
                          (sk-lookup/sk-lookup-drop)
                          ;; TCP - pass
                          (sk-lookup/sk-lookup-pass))))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Instruction Size Tests
;; ============================================================================

(deftest test-instruction-sizes
  (testing "All instructions are 8 bytes"
    (let [test-cases [[(sk-lookup/sk-lookup-prologue :r6) 1]
                      [(sk-lookup/sk-lookup-pass) 2]
                      [(sk-lookup/sk-lookup-drop) 2]
                      [(sk-lookup/sk-assign :r6 :r7 0) 4]
                      [(sk-lookup/sk-release :r7) 2]]]
      (doseq [[insns expected-count] test-cases]
        (is (= expected-count (count insns)))
        (doseq [insn insns]
          (is (= 8 (count insn))))))))

;; ============================================================================
;; Edge Case Tests
;; ============================================================================

(deftest test-max-port-value
  (testing "Port 65535 works correctly"
    (let [insns (sk-lookup/sk-lookup-check-port :r6 :r7 65535 1)]
      (is (vector? insns))
      (is (every? bytes? insns)))))

(deftest test-zero-port
  (testing "Port 0 works correctly"
    (let [insns (sk-lookup/sk-lookup-check-port :r6 :r7 0 1)]
      (is (vector? insns))
      (is (every? bytes? insns)))))

(deftest test-various-skip-counts
  (testing "Various skip counts in check-port"
    (doseq [skip [0 1 5 10 127]]
      (let [insns (sk-lookup/sk-lookup-check-port :r6 :r7 80 skip)]
        (is (vector? insns))
        (is (every? bytes? insns))))))
