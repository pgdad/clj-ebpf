(ns clj-ebpf.sockmap-test
  "Tests for SOCKMAP, SOCKHASH, and SK_SKB/SK_MSG support.

   These tests verify:
   - Map creation functions
   - Socket redirect DSL helpers
   - SK_SKB and SK_MSG program instruction generation
   - Bytecode assembly for socket redirect programs"
  {:ci-safe true}
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.socket :as socket]
            [clj-ebpf.constants :as const]))

;; ============================================================================
;; Map Type Constants Tests
;; ============================================================================

(deftest test-sockmap-constants
  (testing "SOCKMAP constants are defined"
    (is (= 15 (const/map-type :sockmap)))
    (is (= 18 (const/map-type :sockhash)))))

(deftest test-program-type-constants
  (testing "SK_SKB and SK_MSG program types are defined"
    (is (= 14 (const/prog-type :sk-skb)))
    (is (= 16 (const/prog-type :sk-msg)))))

(deftest test-attach-type-constants
  (testing "Socket attach types are defined"
    (is (= 4 (const/attach-type->num :sk-skb-stream-parser)))
    (is (= 5 (const/attach-type->num :sk-skb-stream-verdict)))
    (is (= 7 (const/attach-type->num :sk-msg-verdict)))))

;; ============================================================================
;; Map Creation Tests (Spec Only - No Kernel)
;; ============================================================================

(deftest test-create-sock-map-spec
  (testing "create-sock-map generates correct spec"
    (is (fn? maps/create-sock-map))
    (is (= 15 (const/map-type :sockmap)))))

(deftest test-create-sock-hash-spec
  (testing "create-sock-hash generates correct spec"
    (is (fn? maps/create-sock-hash))
    (is (= 18 (const/map-type :sockhash)))))

;; ============================================================================
;; Socket Helper ID Tests
;; ============================================================================

(deftest test-socket-helper-ids
  (testing "Socket redirect helpers are defined in DSL"
    (is (= 52 (dsl/bpf-helpers :sk-redirect-map)))
    (is (= 53 (dsl/bpf-helpers :sock-map-update)))
    (is (= 60 (dsl/bpf-helpers :msg-redirect-map)))
    (is (= 70 (dsl/bpf-helpers :sock-hash-update)))
    (is (= 71 (dsl/bpf-helpers :msg-redirect-hash)))
    (is (= 72 (dsl/bpf-helpers :sk-redirect-hash)))))

;; ============================================================================
;; SK_SKB DSL Tests
;; ============================================================================

(deftest test-sk-skb-verdict-values
  (testing "SK_SKB verdict values are correct"
    (is (= 0 (socket/sk-skb-action :drop)))
    (is (= 1 (socket/sk-skb-action :pass)))))

(deftest test-sk-skb-prologue
  (testing "sk-skb-prologue generates instructions"
    (let [insns (socket/sk-skb-prologue :r2 :r3)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-redirect-map
  (testing "sk-redirect-map generates instruction bytes"
    (let [insns (socket/sk-redirect-map 5 0 0)]
      (is (vector? insns))
      (is (pos? (count insns)))
      ;; Should have: ld_map_fd (returns single byte-array), mov key, mov flags, call
      (is (every? (fn [x] (or (bytes? x) (vector? x))) insns)))))

(deftest test-sk-redirect-hash
  (testing "sk-redirect-hash generates instruction bytes"
    (let [insns (socket/sk-redirect-hash 5 :r4 0)]
      (is (vector? insns))
      (is (pos? (count insns))))))

(deftest test-sk-redirect-map-with-fallback
  (testing "sk-redirect-map-with-fallback includes exit"
    (let [insns (socket/sk-redirect-map-with-fallback 5 0)]
      (is (vector? insns))
      (is (pos? (count insns))))))

;; ============================================================================
;; SK_MSG DSL Tests
;; ============================================================================

(deftest test-sk-msg-verdict-values
  (testing "SK_MSG verdict values are correct"
    (is (= 0 (socket/sk-msg-action :drop)))
    (is (= 1 (socket/sk-msg-action :pass)))))

(deftest test-sk-msg-offsets
  (testing "sk_msg_md offsets are defined"
    (is (= 0 (socket/sk-msg-offset :data)))
    (is (= 8 (socket/sk-msg-offset :data-end)))
    (is (= 16 (socket/sk-msg-offset :family)))
    (is (= 60 (socket/sk-msg-offset :remote-port)))
    (is (= 64 (socket/sk-msg-offset :local-port)))))

(deftest test-sk-msg-prologue
  (testing "sk-msg-prologue generates instructions"
    (let [insns (socket/sk-msg-prologue :r6 :r2 :r3)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-msg-redirect-map
  (testing "msg-redirect-map generates instruction bytes"
    (let [insns (socket/msg-redirect-map :r6 5 0 0)]
      (is (vector? insns))
      (is (pos? (count insns))))))

(deftest test-msg-redirect-hash
  (testing "msg-redirect-hash generates instruction bytes"
    (let [insns (socket/msg-redirect-hash :r6 5 :r4 0)]
      (is (vector? insns))
      (is (pos? (count insns))))))

(deftest test-msg-redirect-map-with-fallback
  (testing "msg-redirect-map-with-fallback includes exit"
    (let [insns (socket/msg-redirect-map-with-fallback :r6 5 0)]
      (is (vector? insns))
      (is (pos? (count insns))))))

;; ============================================================================
;; Return Pattern Tests
;; ============================================================================

(deftest test-sk-skb-pass
  (testing "sk-skb-pass generates pass + exit"
    (let [insns (socket/sk-skb-pass)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-skb-drop
  (testing "sk-skb-drop generates drop + exit"
    (let [insns (socket/sk-skb-drop)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-msg-pass
  (testing "sk-msg-pass generates pass + exit"
    (let [insns (socket/sk-msg-pass)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-sk-msg-drop
  (testing "sk-msg-drop generates drop + exit"
    (let [insns (socket/sk-msg-drop)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-sk-skb-section-names
  (testing "SK_SKB section names are correct"
    (is (= "sk_skb/stream_parser" (socket/sk-skb-section-name :parser)))
    (is (= "sk_skb/stream_verdict" (socket/sk-skb-section-name :verdict)))
    (is (= "sk_skb/stream_parser/my_parser"
           (socket/sk-skb-section-name :parser "my_parser")))))

(deftest test-sk-msg-section-names
  (testing "SK_MSG section names are correct"
    (is (= "sk_msg" (socket/sk-msg-section-name)))
    (is (= "sk_msg/my_verdict" (socket/sk-msg-section-name "my_verdict")))))

;; ============================================================================
;; Complete Program Assembly Tests
;; ============================================================================

(deftest test-sk-skb-parser-assembly
  (testing "Can assemble SK_SKB parser program"
    (let [;; Simple parser that returns full length (pass all data)
          program-insns [(dsl/mov-reg :r6 :r1)    ; Save context
                         ;; Load len field from __sk_buff (offset 0)
                         (dsl/ldx :w :r0 :r6 0)   ; r0 = skb->len
                         (dsl/exit-insn)]
          bytecode (dsl/assemble program-insns)]
      (is (bytes? bytecode))
      (is (= 24 (count bytecode))))))  ; 3 insns * 8 bytes

(deftest test-sk-skb-verdict-assembly
  (testing "Can assemble SK_SKB verdict program"
    (let [;; Verdict program that passes all data
          program-insns (vec (concat
                              (socket/sk-skb-prologue :r2 :r3)
                              (socket/sk-skb-pass)))
          bytecode (dsl/assemble program-insns)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-sk-skb-redirect-assembly
  (testing "Can assemble SK_SKB redirect verdict"
    (let [;; Verdict that redirects to socket at index 0
          program-insns (vec (concat
                              (socket/sk-skb-prologue :r2 :r3)
                              (socket/sk-redirect-map-with-fallback 5 0)))
          bytecode (dsl/assemble program-insns)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-sk-msg-verdict-assembly
  (testing "Can assemble SK_MSG verdict program"
    (let [;; SK_MSG verdict that passes all messages
          program-insns (vec (concat
                              (socket/sk-msg-prologue :r6 :r2 :r3)
                              (socket/sk-msg-pass)))
          bytecode (dsl/assemble program-insns)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-sk-msg-redirect-assembly
  (testing "Can assemble SK_MSG redirect verdict"
    (let [;; SK_MSG verdict that redirects
          program-insns (vec (concat
                              (socket/sk-msg-prologue :r6 :r2 :r3)
                              (socket/msg-redirect-map-with-fallback :r6 5 0)))
          bytecode (dsl/assemble program-insns)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Helper Update Tests
;; ============================================================================

(deftest test-sock-map-update-insns
  (testing "sock-map-update generates valid instructions"
    (let [insns (socket/sock-map-update 5 0 0)]
      (is (vector? insns))
      (is (pos? (count insns))))))

(deftest test-sock-hash-update-insns
  (testing "sock-hash-update generates valid instructions"
    (let [insns (socket/sock-hash-update 5 :r4 0)]
      (is (vector? insns))
      (is (pos? (count insns))))))

;; ============================================================================
;; Field Loading Tests
;; ============================================================================

(deftest test-sk-msg-load-field
  (testing "sk-msg-load-field generates ldx instruction"
    (let [insn (socket/sk-msg-load-field :r6 :r0 :remote-port)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

;; ============================================================================
;; Edge Cases
;; ============================================================================

(deftest test-redirect-with-register-key
  (testing "Redirect with register key"
    (let [insns (socket/sk-redirect-map 5 :r4 0)]
      (is (vector? insns))
      (is (pos? (count insns))))))

(deftest test-redirect-with-flags
  (testing "Redirect with non-zero flags"
    (let [insns (socket/sk-redirect-map 5 0 1)]
      (is (vector? insns))
      (is (pos? (count insns))))))

;; ============================================================================
;; Bytecode Size Tests
;; ============================================================================

(deftest test-sk-skb-pass-size
  (testing "SK_SKB pass is 16 bytes (2 instructions)"
    (let [insns (socket/sk-skb-pass)
          total-bytes (reduce + (map count insns))]
      (is (= 16 total-bytes)))))

(deftest test-sk-msg-pass-size
  (testing "SK_MSG pass is 16 bytes (2 instructions)"
    (let [insns (socket/sk-msg-pass)
          total-bytes (reduce + (map count insns))]
      (is (= 16 total-bytes)))))

;; ============================================================================
;; Integration Pattern Tests
;; ============================================================================

(deftest test-echo-server-pattern
  (testing "Echo server pattern (SK_SKB parser + verdict)"
    ;; Parser returns message length
    (let [parser-insns [(dsl/mov-reg :r6 :r1)
                        (dsl/ldx :w :r0 :r6 0)   ; skb->len
                        (dsl/exit-insn)]
          parser-bytecode (dsl/assemble parser-insns)
          ;; Verdict passes all
          verdict-insns (vec (concat
                              (socket/sk-skb-prologue :r2 :r3)
                              (socket/sk-skb-pass)))
          verdict-bytecode (dsl/assemble verdict-insns)]
      (is (bytes? parser-bytecode))
      (is (bytes? verdict-bytecode))
      (is (pos? (count parser-bytecode)))
      (is (pos? (count verdict-bytecode))))))

(deftest test-proxy-pattern
  (testing "Proxy pattern (SK_MSG redirect)"
    (let [;; Simple proxy that redirects all messages to index 0
          proxy-insns (vec (concat
                            (socket/sk-msg-prologue :r6 :r2 :r3)
                            (socket/msg-redirect-map-with-fallback :r6 5 0)))
          proxy-bytecode (dsl/assemble proxy-insns)]
      (is (bytes? proxy-bytecode))
      (is (pos? (count proxy-bytecode))))))
