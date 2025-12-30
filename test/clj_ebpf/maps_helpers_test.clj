(ns clj-ebpf.maps-helpers-test
  "Tests for BPF map helper instruction generators - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.maps.helpers :as helpers]))

;; Note: DSL functions return byte arrays representing BPF instructions
;; Each BPF instruction is 8 bytes

(def ^:const BPF-INSN-SIZE 8)

(defn instruction-count
  "Count the number of BPF instructions (each is 8 bytes)"
  [instrs]
  (reduce + (map #(quot (count %) BPF-INSN-SIZE) instrs)))

;; ============================================================================
;; Basic Map Operation Helpers Tests
;; ============================================================================

(deftest test-build-map-lookup
  (testing "build-map-lookup generates correct instruction sequence"
    (let [instrs (helpers/build-map-lookup 42 -16)]
      ;; Should generate: ld-map-fd (2 insn slots = 16 bytes), mov-reg, add, call
      ;; Total = 5 instruction slots
      (is (vector? instrs))
      (is (= 4 (count instrs)))  ; 4 instruction vectors
      (is (every? bytes? instrs))
      ;; ld-map-fd takes 16 bytes (2 insn slots)
      (is (= 16 (count (first instrs))))
      ;; Total instruction count: 2 + 1 + 1 + 1 = 5
      (is (= 5 (instruction-count instrs))))))

(deftest test-build-map-update
  (testing "build-map-update generates correct instruction sequence"
    (let [instrs (helpers/build-map-update 42 -16 -32 helpers/BPF-ANY)]
      ;; Should generate: ld-map-fd (2), mov-reg, add, mov-reg, add, mov, call
      ;; Total = 8 instruction slots
      (is (vector? instrs))
      (is (= 7 (count instrs)))
      (is (every? bytes? instrs))
      (is (= 8 (instruction-count instrs))))))

(deftest test-build-map-delete
  (testing "build-map-delete generates correct instruction sequence"
    (let [instrs (helpers/build-map-delete 42 -16)]
      ;; Should generate: ld-map-fd (2), mov-reg, add, call
      ;; Total = 5 instruction slots
      (is (vector? instrs))
      (is (= 4 (count instrs)))
      (is (every? bytes? instrs))
      (is (= 5 (instruction-count instrs))))))

;; ============================================================================
;; Convenience Helpers Tests
;; ============================================================================

(deftest test-build-map-lookup-or-init
  (testing "build-map-lookup-or-init generates correct instruction sequence"
    (let [instrs (helpers/build-map-lookup-or-init 42 -16 -32)]
      ;; Should be: lookup (5), jne (1), update (8), lookup (5) = 19
      (is (seq? instrs))
      (is (every? bytes? instrs))
      ;; At least lookup + conditional + update + lookup
      (is (> (instruction-count instrs) 15)))))

(deftest test-build-map-increment
  (testing "build-map-increment generates instruction sequence"
    (let [instrs (helpers/build-map-increment 42 -8 -16)]
      (is (seq? instrs))
      (is (every? bytes? instrs))
      ;; Should have lookup, conditional, increment logic, update
      (is (> (instruction-count instrs) 10))))

  (testing "build-map-increment with custom increment value"
    (let [instrs (helpers/build-map-increment 42 -8 -16 5)]
      (is (seq? instrs))
      (is (every? bytes? instrs)))))

;; ============================================================================
;; Pointer-based Variants Tests
;; ============================================================================

(deftest test-build-map-lookup-ptr
  (testing "build-map-lookup-ptr generates correct sequence"
    (let [instrs (helpers/build-map-lookup-ptr 42 :r6)]
      ;; ld-map-fd (2), mov-reg, call = 4 instruction slots
      (is (vector? instrs))
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs))
      (is (= 4 (instruction-count instrs))))))

(deftest test-build-map-update-ptr
  (testing "build-map-update-ptr generates correct sequence"
    (let [instrs (helpers/build-map-update-ptr 42 :r6 :r7 helpers/BPF-NOEXIST)]
      ;; ld-map-fd (2), mov-reg, mov-reg, mov, call = 6 instruction slots
      (is (vector? instrs))
      (is (= 5 (count instrs)))
      (is (every? bytes? instrs))
      (is (= 6 (instruction-count instrs))))))

(deftest test-build-map-delete-ptr
  (testing "build-map-delete-ptr generates correct sequence"
    (let [instrs (helpers/build-map-delete-ptr 42 :r6)]
      ;; ld-map-fd (2), mov-reg, call = 4 instruction slots
      (is (vector? instrs))
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs))
      (is (= 4 (instruction-count instrs))))))

;; ============================================================================
;; Socket Key Building Tests
;; ============================================================================

(deftest test-context-key-offsets
  (testing "Context key offsets are defined for all supported types"
    (is (contains? helpers/context-key-offsets :sock-ops))
    (is (contains? helpers/context-key-offsets :sk-msg))
    (is (contains? helpers/context-key-offsets :sk-skb))
    (is (contains? helpers/context-key-offsets :tc)))

  (testing "sock-ops offsets match bpf_sock_ops structure"
    (let [offsets (get helpers/context-key-offsets :sock-ops)]
      (is (= 24 (:remote-ip4 offsets)))
      (is (= 28 (:local-ip4 offsets)))
      (is (= 64 (:remote-port offsets)))
      (is (= 68 (:local-port offsets)))))

  (testing "sk-msg offsets match sk_msg_md structure"
    (let [offsets (get helpers/context-key-offsets :sk-msg)]
      (is (= 20 (:remote-ip4 offsets)))
      (is (= 24 (:local-ip4 offsets)))
      (is (= 60 (:remote-port offsets)))
      (is (= 64 (:local-port offsets)))))

  (testing "__sk_buff offsets for sk-skb and tc"
    (let [offsets (get helpers/context-key-offsets :sk-skb)]
      (is (= 124 (:remote-ip4 offsets)))
      (is (= 128 (:local-ip4 offsets)))
      (is (= 132 (:remote-port offsets)))
      (is (= 136 (:local-port offsets))))
    ;; tc should have same offsets as sk-skb
    (is (= (get helpers/context-key-offsets :sk-skb)
           (get helpers/context-key-offsets :tc)))))

(deftest test-build-sock-key
  (testing "build-sock-key generates 8 instructions for 4-tuple key"
    ;; 4 loads + 4 stores = 8 instructions = 64 bytes
    (let [instrs (helpers/build-sock-key :r6 -16 :sock-ops)]
      (is (vector? instrs))
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs))
      (is (= 8 (instruction-count instrs)))))

  (testing "build-sock-key works with all supported context types"
    (doseq [ctx-type [:sock-ops :sk-msg :sk-skb :tc]]
      (let [instrs (helpers/build-sock-key :r6 -16 ctx-type)]
        (is (= 8 (instruction-count instrs))
            (str "Context type " ctx-type " should generate 8 instructions")))))

  (testing "build-sock-key works with different context registers"
    (let [instrs-r6 (helpers/build-sock-key :r6 -16 :sock-ops)
          instrs-r7 (helpers/build-sock-key :r7 -16 :sock-ops)]
      (is (= 8 (instruction-count instrs-r6)))
      (is (= 8 (instruction-count instrs-r7)))
      ;; They should be different (different source register encoded)
      (is (not= instrs-r6 instrs-r7))))

  (testing "build-sock-key works with different stack offsets"
    (let [instrs-16 (helpers/build-sock-key :r6 -16 :sock-ops)
          instrs-32 (helpers/build-sock-key :r6 -32 :sock-ops)]
      (is (= 8 (instruction-count instrs-16)))
      (is (= 8 (instruction-count instrs-32)))
      ;; They should be different (different stack offset encoded)
      (is (not= instrs-16 instrs-32))))

  (testing "build-sock-key throws on unknown context type"
    (is (thrown? clojure.lang.ExceptionInfo
                 (helpers/build-sock-key :r6 -16 :unknown)))))

(deftest test-build-sock-key-ipv6
  (testing "build-sock-key-ipv6 generates correct instruction count"
    ;; IPv6: 8 loads + 8 stores for IP addresses (16 bytes each)
    ;;       2 loads + 2 stores for ports
    ;; Total: 20 instructions = 160 bytes
    (let [instrs (helpers/build-sock-key-ipv6 :r6 -48 :sock-ops)]
      (is (seq? instrs))
      (is (every? bytes? instrs))
      (is (= 20 (instruction-count instrs)))))

  (testing "build-sock-key-ipv6 only supports sock-ops context"
    (is (thrown? clojure.lang.ExceptionInfo
                 (helpers/build-sock-key-ipv6 :r6 -48 :sk-msg)))))

(deftest test-sock-key-produces-valid-instructions
  (testing "Each instruction in build-sock-key is exactly 8 bytes"
    (let [instrs (helpers/build-sock-key :r6 -16 :sock-ops)]
      (is (every? #(= 8 (count %)) instrs))))

  (testing "Each instruction in build-sock-key-ipv6 is exactly 8 bytes"
    (let [instrs (helpers/build-sock-key-ipv6 :r6 -48 :sock-ops)]
      (is (every? #(= 8 (count %)) instrs)))))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-helper-constants
  (testing "BPF helper function IDs"
    (is (= 1 helpers/BPF-FUNC-map-lookup-elem))
    (is (= 2 helpers/BPF-FUNC-map-update-elem))
    (is (= 3 helpers/BPF-FUNC-map-delete-elem)))

  (testing "Map update flags"
    (is (= 0 helpers/BPF-ANY))
    (is (= 1 helpers/BPF-NOEXIST))
    (is (= 2 helpers/BPF-EXIST))))

;; ============================================================================
;; Integration Tests
;; ============================================================================

(deftest test-sock-key-with-map-lookup
  (testing "build-sock-key output can be combined with build-map-lookup"
    ;; This simulates a typical usage pattern
    (let [sock-key-instrs (helpers/build-sock-key :r6 -16 :sock-ops)
          ;; Use a placeholder fd (0) for testing
          map-lookup-instrs (helpers/build-map-lookup 0 -16)
          combined (concat sock-key-instrs map-lookup-instrs)]
      ;; sock-key: 8 instrs, map-lookup: 5 instrs = 13 total
      (is (= 13 (instruction-count combined)))
      (is (every? bytes? combined)))))
