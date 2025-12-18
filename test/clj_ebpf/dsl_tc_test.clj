(ns clj-ebpf.dsl-tc-test
  "Tests for TC DSL features
   CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.dsl.tc :as tc]
            [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; TC Actions Tests
;; ============================================================================

(deftest test-tc-actions
  (testing "TC actions map contains all actions"
    (is (map? tc/tc-actions))
    (is (contains? tc/tc-actions :ok))
    (is (contains? tc/tc-actions :shot))
    (is (contains? tc/tc-actions :redirect))
    (is (contains? tc/tc-actions :pipe))
    (is (contains? tc/tc-actions :unspec)))

  (testing "TC action values are correct"
    (is (= -1 (:unspec tc/tc-actions)))
    (is (= 0 (:ok tc/tc-actions)))
    (is (= 1 (:reclassify tc/tc-actions)))
    (is (= 2 (:shot tc/tc-actions)))
    (is (= 3 (:pipe tc/tc-actions)))
    (is (= 7 (:redirect tc/tc-actions))))

  (testing "tc-action returns correct values"
    (is (= -1 (tc/tc-action :unspec)))
    (is (= 0 (tc/tc-action :ok)))
    (is (= 2 (tc/tc-action :shot)))
    (is (= 7 (tc/tc-action :redirect))))

  (testing "tc-action throws for unknown actions"
    (is (thrown? clojure.lang.ExceptionInfo
                 (tc/tc-action :invalid)))))

;; ============================================================================
;; __sk_buff Offsets Tests
;; ============================================================================

(deftest test-skb-offsets
  (testing "skb-offsets contains all common fields"
    (is (map? tc/skb-offsets))
    (is (contains? tc/skb-offsets :len))
    (is (contains? tc/skb-offsets :mark))
    (is (contains? tc/skb-offsets :priority))
    (is (contains? tc/skb-offsets :data))
    (is (contains? tc/skb-offsets :data-end))
    (is (contains? tc/skb-offsets :protocol))
    (is (contains? tc/skb-offsets :tc-classid)))

  (testing "skb offsets are correct"
    (is (= 0 (:len tc/skb-offsets)))
    (is (= 8 (:mark tc/skb-offsets)))
    (is (= 32 (:priority tc/skb-offsets)))
    (is (= 76 (:data tc/skb-offsets)))
    (is (= 80 (:data-end tc/skb-offsets)))
    (is (= 72 (:tc-classid tc/skb-offsets))))

  (testing "skb-offset function works"
    (is (= 0 (tc/skb-offset :len)))
    (is (= 8 (tc/skb-offset :mark)))
    (is (= 76 (tc/skb-offset :data))))

  (testing "skb-offset throws for unknown fields"
    (is (thrown? clojure.lang.ExceptionInfo
                 (tc/skb-offset :invalid)))))

;; ============================================================================
;; Context Access Tests
;; ============================================================================

(deftest test-tc-load-ctx-field
  (testing "tc-load-ctx-field generates ldx instruction"
    (let [insn (tc/tc-load-ctx-field :r1 :data :r2)]
      (is (bytes? insn))
      (is (= 8 (count insn)))))

  (testing "tc-load-ctx-field works with different fields"
    (is (some? (tc/tc-load-ctx-field :r1 :mark :r4)))
    (is (some? (tc/tc-load-ctx-field :r1 :priority :r5)))))

(deftest test-tc-load-data-pointers
  (testing "tc-load-data-pointers generates two instructions"
    (let [insns (tc/tc-load-data-pointers :r1 :r2 :r3)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-prologue
  (testing "tc-prologue without context save"
    (let [prologue (tc/tc-prologue :r2 :r3)]
      (is (vector? prologue))
      (is (= 2 (count prologue)))
      (is (every? bytes? prologue))))

  (testing "tc-prologue with context save"
    (let [prologue (tc/tc-prologue :r9 :r2 :r3)]
      (is (vector? prologue))
      (is (= 3 (count prologue)))
      (is (every? bytes? prologue)))))

;; ============================================================================
;; TC-Specific Field Access Tests
;; ============================================================================

(deftest test-tc-get-mark
  (testing "tc-get-mark generates ldx instruction"
    (let [insn (tc/tc-get-mark :r1 :r4)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tc-set-mark
  (testing "tc-set-mark generates stx instruction"
    (let [insn (tc/tc-set-mark :r1 :r4)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tc-get-priority
  (testing "tc-get-priority generates ldx instruction"
    (let [insn (tc/tc-get-priority :r1 :r4)]
      (is (bytes? insn)))))

(deftest test-tc-set-priority
  (testing "tc-set-priority generates stx instruction"
    (let [insn (tc/tc-set-priority :r1 :r4)]
      (is (bytes? insn)))))

(deftest test-tc-get-tc-classid
  (testing "tc-get-tc-classid generates ldx instruction"
    (let [insn (tc/tc-get-tc-classid :r1 :r4)]
      (is (bytes? insn)))))

(deftest test-tc-set-tc-classid
  (testing "tc-set-tc-classid generates stx instruction"
    (let [insn (tc/tc-set-tc-classid :r1 :r4)]
      (is (bytes? insn)))))

(deftest test-tc-get-protocol
  (testing "tc-get-protocol generates ldx instruction"
    (let [insn (tc/tc-get-protocol :r1 :r4)]
      (is (bytes? insn)))))

(deftest test-tc-get-ifindex
  (testing "tc-get-ifindex generates ldx instruction"
    (let [insn (tc/tc-get-ifindex :r1 :r4)]
      (is (bytes? insn)))))

(deftest test-tc-get-len
  (testing "tc-get-len generates ldx instruction"
    (let [insn (tc/tc-get-len :r1 :r4)]
      (is (bytes? insn)))))

(deftest test-tc-get-hash
  (testing "tc-get-hash generates ldx instruction"
    (let [insn (tc/tc-get-hash :r1 :r4)]
      (is (bytes? insn)))))

;; ============================================================================
;; Bounds Checking Tests
;; ============================================================================

(deftest test-tc-bounds-check
  (testing "tc-bounds-check is available (reused from XDP)"
    (is (fn? tc/tc-bounds-check)))

  (testing "tc-bounds-check generates correct instructions"
    (let [insns (tc/tc-bounds-check :r2 :r3 14)]
      (is (vector? insns))
      (is (= 5 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Packet Data Access Tests
;; ============================================================================

(deftest test-tc-load-functions
  (testing "tc-load-byte is available"
    (is (fn? tc/tc-load-byte))
    (is (bytes? (tc/tc-load-byte :r2 0 :r4))))

  (testing "tc-load-half is available"
    (is (fn? tc/tc-load-half))
    (is (bytes? (tc/tc-load-half :r2 12 :r4))))

  (testing "tc-load-word is available"
    (is (fn? tc/tc-load-word))
    (is (bytes? (tc/tc-load-word :r2 16 :r4)))))

;; ============================================================================
;; Protocol Parsing Tests (reused from XDP)
;; ============================================================================

(deftest test-tc-parse-functions
  (testing "tc-parse-ethernet is available"
    (is (fn? tc/tc-parse-ethernet))
    (let [insns (tc/tc-parse-ethernet :r2 :r3 :r4)]
      (is (vector? insns))
      (is (pos? (count insns)))))

  (testing "tc-parse-ipv4 is available"
    (is (fn? tc/tc-parse-ipv4))
    (let [insns (tc/tc-parse-ipv4 :r2 :r3 14 :r4)]
      (is (vector? insns))))

  (testing "tc-parse-tcp is available"
    (is (fn? tc/tc-parse-tcp))
    (let [insns (tc/tc-parse-tcp :r2 :r3 34 :src-port :r4)]
      (is (vector? insns))))

  (testing "tc-parse-udp is available"
    (is (fn? tc/tc-parse-udp))
    (let [insns (tc/tc-parse-udp :r2 :r3 34 :dst-port :r5)]
      (is (vector? insns)))))

;; ============================================================================
;; Protocol Constants Tests
;; ============================================================================

(deftest test-protocol-constants
  (testing "Header sizes are defined"
    (is (= 14 tc/ethernet-header-size))
    (is (= 20 tc/ipv4-header-min-size))
    (is (= 40 tc/ipv6-header-size))
    (is (= 20 tc/tcp-header-min-size))
    (is (= 8 tc/udp-header-size)))

  (testing "Header offset maps are defined"
    (is (map? tc/ethernet-offsets))
    (is (map? tc/ipv4-offsets))
    (is (map? tc/tcp-offsets))
    (is (map? tc/udp-offsets)))

  (testing "Protocol value maps are defined"
    (is (map? tc/ethertypes))
    (is (map? tc/ip-protocols))
    (is (map? tc/tcp-flags))))

;; ============================================================================
;; TC Helper Tests
;; ============================================================================

(deftest test-tc-redirect
  (testing "tc-redirect generates call instructions"
    (let [insns (tc/tc-redirect 2 0)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-clone-redirect
  (testing "tc-clone-redirect generates call instructions"
    (let [insns (tc/tc-clone-redirect :r9 2 0)]
      (is (vector? insns))
      (is (= 4 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-skb-store-bytes
  (testing "tc-skb-store-bytes generates call instructions"
    (let [insns (tc/tc-skb-store-bytes :r9 0 :r4 14 0)]
      (is (vector? insns))
      (is (= 6 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-skb-load-bytes
  (testing "tc-skb-load-bytes generates call instructions"
    (let [insns (tc/tc-skb-load-bytes :r9 0 :r4 14)]
      (is (vector? insns))
      (is (= 5 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-skb-change-head
  (testing "tc-skb-change-head generates call instructions"
    (let [insns (tc/tc-skb-change-head :r9 14 0)]
      (is (vector? insns))
      (is (= 4 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-skb-change-tail
  (testing "tc-skb-change-tail generates call instructions"
    (let [insns (tc/tc-skb-change-tail :r9 100 0)]
      (is (vector? insns))
      (is (= 4 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-l3-csum-replace
  (testing "tc-l3-csum-replace generates call instructions"
    (let [insns (tc/tc-l3-csum-replace :r9 24 0 0 4)]
      (is (vector? insns))
      (is (= 6 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-l4-csum-replace
  (testing "tc-l4-csum-replace generates call instructions"
    (let [insns (tc/tc-l4-csum-replace :r9 50 0 0 4)]
      (is (vector? insns))
      (is (= 6 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Program Building Tests
;; ============================================================================

(deftest test-build-tc-program
  (testing "build-tc-program creates valid bytecode"
    (let [prog (tc/build-tc-program
                {:body []
                 :default-action :ok})]
      (is (bytes? prog))
      (is (> (count prog) 0))
      (is (zero? (mod (count prog) 8)))))

  (testing "build-tc-program with body instructions"
    (let [prog (tc/build-tc-program
                {:ctx-reg :r9
                 :body [(dsl/mov :r4 42)]
                 :default-action :shot})]
      (is (bytes? prog))
      (is (> (count prog) 0))))

  (testing "build-tc-program uses default action"
    (let [prog1 (tc/build-tc-program {:body []})
          prog2 (tc/build-tc-program {:body [] :default-action :shot})]
      (is (bytes? prog1))
      (is (bytes? prog2)))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(tc/deftc-instructions test-drop-all
  {:default-action :shot}
  [])

(tc/deftc-instructions test-pass-all
  {:default-action :ok
   :ctx-reg :r9}
  [(dsl/mov :r4 123)])

(deftest test-deftc-instructions-macro
  (testing "deftc-instructions creates a function"
    (is (fn? test-drop-all))
    (is (fn? test-pass-all)))

  (testing "deftc-instructions returns instructions"
    (let [insns (test-drop-all)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "deftc-instructions includes prologue"
    (let [insns (test-pass-all)]
      ;; ctx save (1) + data pointers (2) + body (1) + return (2) = 6
      (is (= 6 (count insns))))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-tc-section-name
  (testing "tc-section-name without args"
    (is (= "tc" (tc/tc-section-name))))

  (testing "tc-section-name with direction"
    (is (= "tc/ingress" (tc/tc-section-name :ingress)))
    (is (= "tc/egress" (tc/tc-section-name :egress))))

  (testing "tc-section-name with direction and interface"
    (is (= "tc/ingress/eth0" (tc/tc-section-name :ingress "eth0")))
    (is (= "tc/egress/ens192" (tc/tc-section-name :egress "ens192")))))

;; ============================================================================
;; Program Info Tests
;; ============================================================================

(deftest test-make-tc-program-info
  (testing "make-tc-program-info returns correct structure"
    (let [info (tc/make-tc-program-info "my_tc" [])]
      (is (map? info))
      (is (= "my_tc" (:name info)))
      (is (= "tc" (:section info)))
      (is (= :tc (:type info)))
      (is (vector? (:instructions info)))))

  (testing "make-tc-program-info with direction"
    (let [info (tc/make-tc-program-info "my_tc" [] :ingress)]
      (is (= "tc/ingress" (:section info)))
      (is (= :ingress (:direction info)))))

  (testing "make-tc-program-info with direction and interface"
    (let [info (tc/make-tc-program-info "my_tc" [] :egress "eth0")]
      (is (= "tc/egress/eth0" (:section info)))
      (is (= :egress (:direction info)))
      (is (= "eth0" (:interface info))))))

;; ============================================================================
;; Common Patterns Tests
;; ============================================================================

(deftest test-tc-return-action
  (testing "tc-return-action generates mov and exit"
    (let [insns (tc/tc-return-action :shot)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "tc-return-action works with all actions"
    (doseq [action [:ok :shot :pipe :redirect]]
      (is (= 2 (count (tc/tc-return-action action)))))))

(deftest test-tc-mark-packet
  (testing "tc-mark-packet generates instructions"
    (let [insns (tc/tc-mark-packet :r9 0x1234)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-classify-packet
  (testing "tc-classify-packet generates instructions"
    (let [insns (tc/tc-classify-packet :r9 1 10)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-tc-match-mark
  (testing "tc-match-mark generates instructions"
    (let [insns (tc/tc-match-mark :r9 0x100 :shot)]
      (is (vector? insns))
      (is (= 4 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; IP Helper Tests
;; ============================================================================

(deftest test-ipv4-to-int
  (testing "ipv4-to-int is available from TC"
    (is (fn? tc/ipv4-to-int))
    (is (= 0x0A000001 (tc/ipv4-to-int "10.0.0.1")))))

;; ============================================================================
;; Integration Tests
;; ============================================================================

(deftest test-complete-tc-program-assembly
  (testing "Complete TC drop program assembles correctly"
    (let [bytecode (dsl/assemble (test-drop-all))]
      (is (bytes? bytecode))
      (is (> (count bytecode) 0))
      (is (zero? (mod (count bytecode) 8)))))

  (testing "Complete TC pass program assembles correctly"
    (let [bytecode (dsl/assemble (test-pass-all))]
      (is (bytes? bytecode))
      (is (> (count bytecode) 0))
      (is (zero? (mod (count bytecode) 8))))))

(deftest test-tc-program-with-mark
  (testing "TC program with mark manipulation assembles"
    (let [insns (vec (concat
                      (tc/tc-prologue :r9 :r2 :r3)
                      [(tc/tc-get-mark :r9 :r4)]
                      (tc/tc-return-action :ok)))
          bytecode (dsl/assemble insns)]
      (is (bytes? bytecode))
      (is (> (count bytecode) 0)))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-api-completeness
  (testing "All TC action functions are defined"
    (is (fn? tc/tc-action)))

  (testing "All context access functions are defined"
    (is (fn? tc/tc-load-ctx-field))
    (is (fn? tc/tc-load-data-pointers))
    (is (fn? tc/tc-prologue)))

  (testing "All sk_buff field functions are defined"
    (is (fn? tc/tc-get-mark))
    (is (fn? tc/tc-set-mark))
    (is (fn? tc/tc-get-priority))
    (is (fn? tc/tc-set-priority))
    (is (fn? tc/tc-get-tc-classid))
    (is (fn? tc/tc-set-tc-classid))
    (is (fn? tc/tc-get-protocol))
    (is (fn? tc/tc-get-ifindex))
    (is (fn? tc/tc-get-len))
    (is (fn? tc/tc-get-hash)))

  (testing "All helper functions are defined"
    (is (fn? tc/tc-redirect))
    (is (fn? tc/tc-clone-redirect))
    (is (fn? tc/tc-skb-store-bytes))
    (is (fn? tc/tc-skb-load-bytes))
    (is (fn? tc/tc-skb-change-head))
    (is (fn? tc/tc-skb-change-tail))
    (is (fn? tc/tc-l3-csum-replace))
    (is (fn? tc/tc-l4-csum-replace)))

  (testing "All builder functions are defined"
    (is (fn? tc/build-tc-program))
    (is (fn? tc/tc-section-name))
    (is (fn? tc/make-tc-program-info))))

(deftest test-documentation
  (testing "Core functions have docstrings"
    (is (string? (:doc (meta #'tc/tc-action))))
    (is (string? (:doc (meta #'tc/tc-prologue))))
    (is (string? (:doc (meta #'tc/tc-get-mark))))
    (is (string? (:doc (meta #'tc/build-tc-program))))))
