(ns clj-ebpf.struct-ops-test
  "Tests for BPF STRUCT_OPS support.

   These tests verify:
   - STRUCT_OPS constants are defined correctly
   - DSL helpers generate valid bytecode
   - TCP socket field access works correctly
   - Callback prologue and return patterns
   - Program templates and metadata

   Note: Actual STRUCT_OPS program loading and registration requires
   root privileges, kernel 5.6+, and BTF support. These tests focus on
   the code generation aspects that can run without privileges."
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.constants :as const]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.struct-ops :as struct-ops]))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-struct-ops-program-type
  (testing "STRUCT_OPS program type is defined"
    (is (= 27 (const/prog-type->num :struct-ops)))
    (is (= :struct-ops (const/int->prog-type 27)))))

(deftest test-struct-ops-map-type
  (testing "STRUCT_OPS map type is defined"
    (is (= 26 (const/map-type->num :struct-ops)))
    (is (= :struct-ops (const/int->map-type 26)))))

(deftest test-struct-ops-attach-type
  (testing "STRUCT_OPS attach type is defined"
    (is (= 44 (const/attach-type->num :struct-ops)))
    (is (= :struct-ops (const/int->attach-type 44)))))

;; ============================================================================
;; TCP Congestion Control Constants Tests
;; ============================================================================

(deftest test-tcp-ca-states
  (testing "TCP CA states are defined"
    (is (map? struct-ops/tcp-ca-states))
    (are [state expected] (= expected (get struct-ops/tcp-ca-states state))
      :open      0
      :disorder  1
      :cwr       2
      :recovery  3
      :loss      4)))

(deftest test-tcp-ca-events
  (testing "TCP CA events are defined"
    (is (map? struct-ops/tcp-ca-events))
    (are [event expected] (= expected (get struct-ops/tcp-ca-events event))
      :tx-start      0
      :cwnd-restart  1
      :complete-cwr  2
      :loss          3)))

(deftest test-tcp-ca-ack-flags
  (testing "TCP CA ACK flags are defined"
    (is (map? struct-ops/tcp-ca-ack-flags))
    (is (= 1 (:slow struct-ops/tcp-ca-ack-flags)))
    (is (= 2 (:ecn struct-ops/tcp-ca-ack-flags)))
    (is (= 4 (:ece struct-ops/tcp-ca-ack-flags)))
    (is (= 8 (:delay-ack struct-ops/tcp-ca-ack-flags)))))

;; ============================================================================
;; TCP Socket Field Offset Tests
;; ============================================================================

(deftest test-tcp-sock-offsets
  (testing "TCP socket offsets are defined"
    (is (map? struct-ops/tcp-sock-offsets))
    (is (number? (:snd-cwnd struct-ops/tcp-sock-offsets)))
    (is (number? (:snd-ssthresh struct-ops/tcp-sock-offsets)))
    (is (number? (:srtt-us struct-ops/tcp-sock-offsets)))
    (is (number? (:mdev-us struct-ops/tcp-sock-offsets)))
    (is (number? (:packets-out struct-ops/tcp-sock-offsets)))
    (is (number? (:ca-state struct-ops/tcp-sock-offsets)))))

(deftest test-tcp-sock-offset-function
  (testing "tcp-sock-offset returns correct values"
    (is (= 256 (struct-ops/tcp-sock-offset :snd-cwnd)))
    (is (= 260 (struct-ops/tcp-sock-offset :snd-ssthresh)))
    (is (= 268 (struct-ops/tcp-sock-offset :srtt-us)))))

(deftest test-tcp-sock-offset-invalid
  (testing "tcp-sock-offset throws on invalid field"
    (is (thrown? clojure.lang.ExceptionInfo
                 (struct-ops/tcp-sock-offset :invalid-field)))))

;; ============================================================================
;; Prologue Tests
;; ============================================================================

(deftest test-struct-ops-prologue
  (testing "struct-ops-prologue generates bytecode"
    (let [insns (struct-ops/struct-ops-prologue :r6)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

(deftest test-struct-ops-prologue-different-registers
  (testing "struct-ops-prologue works with different registers"
    (doseq [reg [:r6 :r7 :r8 :r9]]
      (let [insns (struct-ops/struct-ops-prologue reg)]
        (is (vector? insns))
        (is (bytes? (first insns)))))))

(deftest test-struct-ops-prologue-2arg
  (testing "struct-ops-prologue-2arg generates bytecode"
    (let [insns (struct-ops/struct-ops-prologue-2arg :r6 :r7)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-struct-ops-prologue-3arg
  (testing "struct-ops-prologue-3arg generates bytecode"
    (let [insns (struct-ops/struct-ops-prologue-3arg :r6 :r7 :r8)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; TCP Socket Field Access Tests
;; ============================================================================

(deftest test-tcp-sock-load-u32
  (testing "tcp-sock-load-u32 generates bytecode"
    (let [insn (struct-ops/tcp-sock-load-u32 :r6 :r0 :snd-cwnd)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tcp-sock-load-u16
  (testing "tcp-sock-load-u16 generates bytecode"
    (let [insn (struct-ops/tcp-sock-load-u16 :r6 :r0 :mss-cache)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tcp-sock-load-u8
  (testing "tcp-sock-load-u8 generates bytecode"
    (let [insn (struct-ops/tcp-sock-load-u8 :r6 :r0 :ca-state)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tcp-sock-store-u32
  (testing "tcp-sock-store-u32 generates bytecode"
    (let [insn (struct-ops/tcp-sock-store-u32 :r6 :snd-cwnd :r7)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

;; Convenience function tests
(deftest test-tcp-sock-load-cwnd
  (testing "tcp-sock-load-cwnd generates bytecode"
    (let [insn (struct-ops/tcp-sock-load-cwnd :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tcp-sock-load-ssthresh
  (testing "tcp-sock-load-ssthresh generates bytecode"
    (let [insn (struct-ops/tcp-sock-load-ssthresh :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tcp-sock-load-srtt
  (testing "tcp-sock-load-srtt generates bytecode"
    (let [insn (struct-ops/tcp-sock-load-srtt :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tcp-sock-load-packets-out
  (testing "tcp-sock-load-packets-out generates bytecode"
    (let [insn (struct-ops/tcp-sock-load-packets-out :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tcp-sock-load-ca-state
  (testing "tcp-sock-load-ca-state generates bytecode"
    (let [insn (struct-ops/tcp-sock-load-ca-state :r6 :r0)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tcp-sock-store-cwnd
  (testing "tcp-sock-store-cwnd generates bytecode"
    (let [insn (struct-ops/tcp-sock-store-cwnd :r6 :r7)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-tcp-sock-store-ssthresh
  (testing "tcp-sock-store-ssthresh generates bytecode"
    (let [insn (struct-ops/tcp-sock-store-ssthresh :r6 :r7)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

;; ============================================================================
;; Return Pattern Tests
;; ============================================================================

(deftest test-struct-ops-return
  (testing "struct-ops-return generates bytecode"
    (let [insns (struct-ops/struct-ops-return)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

(deftest test-struct-ops-return-imm
  (testing "struct-ops-return-imm generates bytecode"
    (let [insns (struct-ops/struct-ops-return-imm 42)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-struct-ops-return-reg
  (testing "struct-ops-return-reg generates bytecode"
    (let [insns (struct-ops/struct-ops-return-reg :r7)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-struct-ops-return-void
  (testing "struct-ops-return-void generates bytecode"
    (let [insns (struct-ops/struct-ops-return-void)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Callback Prologue Tests
;; ============================================================================

(deftest test-ssthresh-prologue
  (testing "ssthresh-prologue generates bytecode"
    (let [insns (struct-ops/ssthresh-prologue :r6)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-cong-avoid-prologue
  (testing "cong-avoid-prologue generates bytecode"
    (let [insns (struct-ops/cong-avoid-prologue :r6 :r7 :r8)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-set-state-prologue
  (testing "set-state-prologue generates bytecode"
    (let [insns (struct-ops/set-state-prologue :r6 :r7)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-cwnd-event-prologue
  (testing "cwnd-event-prologue generates bytecode"
    (let [insns (struct-ops/cwnd-event-prologue :r6 :r7)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-pkts-acked-prologue
  (testing "pkts-acked-prologue generates bytecode"
    (let [insns (struct-ops/pkts-acked-prologue :r6 :r7)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-undo-cwnd-prologue
  (testing "undo-cwnd-prologue generates bytecode"
    (let [insns (struct-ops/undo-cwnd-prologue :r6)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-cong-control-prologue
  (testing "cong-control-prologue generates bytecode"
    (let [insns (struct-ops/cong-control-prologue :r6 :r7)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-init-prologue
  (testing "init-prologue generates bytecode"
    (let [insns (struct-ops/init-prologue :r6)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-release-prologue
  (testing "release-prologue generates bytecode"
    (let [insns (struct-ops/release-prologue :r6)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Algorithm Pattern Tests
;; ============================================================================

(deftest test-aimd-ssthresh
  (testing "aimd-ssthresh generates bytecode"
    (let [insns (struct-ops/aimd-ssthresh :r6 :r7)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-slow-start-check
  (testing "slow-start-check generates bytecode"
    (let [insns (struct-ops/slow-start-check :r6 :r7 :r8 3)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-increment-cwnd
  (testing "increment-cwnd generates bytecode"
    (let [insns (struct-ops/increment-cwnd :r6 :r7)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Program Template Tests
;; ============================================================================

(deftest test-minimal-ssthresh-program
  (testing "minimal-ssthresh-program generates bytecode"
    (let [insns (struct-ops/minimal-ssthresh-program)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-passthrough-ssthresh-program
  (testing "passthrough-ssthresh-program generates bytecode"
    (let [insns (struct-ops/passthrough-ssthresh-program)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-minimal-cong-avoid-program
  (testing "minimal-cong-avoid-program generates bytecode"
    (let [insns (struct-ops/minimal-cong-avoid-program)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-minimal-init-program
  (testing "minimal-init-program generates bytecode"
    (let [insns (struct-ops/minimal-init-program)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-minimal-release-program
  (testing "minimal-release-program generates bytecode"
    (let [insns (struct-ops/minimal-release-program)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-minimal-undo-cwnd-program
  (testing "minimal-undo-cwnd-program generates bytecode"
    (let [insns (struct-ops/minimal-undo-cwnd-program)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Callback Metadata Tests
;; ============================================================================

(deftest test-tcp-congestion-ops-callbacks
  (testing "TCP congestion ops callbacks are defined"
    (is (map? struct-ops/tcp-congestion-ops-callbacks))
    (is (contains? struct-ops/tcp-congestion-ops-callbacks :ssthresh))
    (is (contains? struct-ops/tcp-congestion-ops-callbacks :cong-avoid))
    (is (contains? struct-ops/tcp-congestion-ops-callbacks :init))
    (is (contains? struct-ops/tcp-congestion-ops-callbacks :release))))

(deftest test-get-callback-info
  (testing "get-callback-info returns correct metadata"
    (let [ssthresh-info (struct-ops/get-callback-info :ssthresh)]
      (is (= 1 (:args ssthresh-info)))
      (is (= :u32 (:return ssthresh-info)))
      (is (false? (:required ssthresh-info))))
    (let [cong-avoid-info (struct-ops/get-callback-info :cong-avoid)]
      (is (= 3 (:args cong-avoid-info)))
      (is (= :void (:return cong-avoid-info))))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-struct-ops-section-name
  (testing "struct-ops-section-name generates correct names"
    (is (= "struct_ops/tcp_congestion_ops/ssthresh"
           (struct-ops/struct-ops-section-name "tcp_congestion_ops" "ssthresh")))
    (is (= "struct_ops/tcp_congestion_ops/cong_avoid"
           (struct-ops/struct-ops-section-name "tcp_congestion_ops" "cong_avoid")))))

(deftest test-tcp-cong-ops-section-name
  (testing "tcp-cong-ops-section-name generates correct names"
    (is (= "struct_ops/tcp_congestion_ops/ssthresh"
           (struct-ops/tcp-cong-ops-section-name "ssthresh")))
    (is (= "struct_ops/tcp_congestion_ops/init"
           (struct-ops/tcp-cong-ops-section-name "init")))))

;; ============================================================================
;; Program Info Tests
;; ============================================================================

(deftest test-make-struct-ops-info
  (testing "make-struct-ops-info creates correct metadata"
    (let [info (struct-ops/make-struct-ops-info
                 "my_ssthresh"
                 "tcp_congestion_ops"
                 "ssthresh"
                 [])]
      (is (= "my_ssthresh" (:name info)))
      (is (= "struct_ops/tcp_congestion_ops/ssthresh" (:section info)))
      (is (= :struct-ops (:type info)))
      (is (= "tcp_congestion_ops" (:struct-name info)))
      (is (= "ssthresh" (:callback info)))
      (is (= [] (:instructions info))))))

(deftest test-make-tcp-cong-ops-info
  (testing "make-tcp-cong-ops-info creates correct metadata"
    (let [info (struct-ops/make-tcp-cong-ops-info "my_init" "init" [])]
      (is (= "my_init" (:name info)))
      (is (= "struct_ops/tcp_congestion_ops/init" (:section info)))
      (is (= :struct-ops (:type info)))
      (is (= "tcp_congestion_ops" (:struct-name info)))
      (is (= "init" (:callback info))))))

;; ============================================================================
;; Complete Program Assembly Tests
;; ============================================================================

(deftest test-ssthresh-program-assembly
  (testing "Complete ssthresh program assembles correctly"
    (let [bytecode (dsl/assemble (struct-ops/minimal-ssthresh-program))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-cong-avoid-program-assembly
  (testing "Complete cong_avoid program assembles correctly"
    (let [bytecode (dsl/assemble (struct-ops/minimal-cong-avoid-program))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-init-program-assembly
  (testing "Complete init program assembles correctly"
    (let [bytecode (dsl/assemble (struct-ops/minimal-init-program))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-custom-ssthresh-assembly
  (testing "Custom ssthresh program assembles"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          (struct-ops/ssthresh-prologue :r6)
                          ;; Load current cwnd
                          [(struct-ops/tcp-sock-load-cwnd :r6 :r7)]
                          ;; Divide by 2 (shift right)
                          [(dsl/rsh :r7 1)]
                          ;; Ensure at least 2
                          [(dsl/jmp-imm :jge :r7 2 1)
                           (dsl/mov :r7 2)]
                          ;; Return result
                          (struct-ops/struct-ops-return-reg :r7))))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Instruction Size Tests
;; ============================================================================

(deftest test-instruction-sizes
  (testing "All instructions are 8 bytes"
    (let [test-cases [[(struct-ops/struct-ops-prologue :r6) 1]
                      [(struct-ops/struct-ops-prologue-2arg :r6 :r7) 2]
                      [(struct-ops/struct-ops-prologue-3arg :r6 :r7 :r8) 3]
                      [(struct-ops/struct-ops-return) 1]
                      [(struct-ops/struct-ops-return-void) 2]
                      [(struct-ops/struct-ops-return-imm 0) 2]
                      [(struct-ops/struct-ops-return-reg :r7) 2]]]
      (doseq [[insns expected-count] test-cases]
        (is (= expected-count (count insns)))
        (doseq [insn insns]
          (is (= 8 (count insn))))))))

;; ============================================================================
;; Register Combination Tests
;; ============================================================================

(deftest test-prologue-register-combinations
  (testing "Prologues work with various registers"
    (doseq [sk [:r6 :r7 :r8 :r9]]
      (let [insns (struct-ops/struct-ops-prologue sk)]
        (is (vector? insns))
        (is (every? bytes? insns))))))

(deftest test-2arg-prologue-combinations
  (testing "2-arg prologues work with various register pairs"
    (doseq [sk [:r6 :r7]
            arg2 [:r8 :r9]
            :when (not= sk arg2)]
      (let [insns (struct-ops/struct-ops-prologue-2arg sk arg2)]
        (is (vector? insns))
        (is (every? bytes? insns))))))

(deftest test-field-load-register-combinations
  (testing "Field loads work with various registers"
    (doseq [sk [:r6 :r7]
            dst [:r0 :r8 :r9]]
      (let [insn (struct-ops/tcp-sock-load-cwnd sk dst)]
        (is (bytes? insn))
        (is (= 8 (count insn)))))))

;; ============================================================================
;; Edge Case Tests
;; ============================================================================

(deftest test-all-tcp-sock-fields-loadable
  (testing "All TCP socket fields can be loaded"
    (doseq [field (keys struct-ops/tcp-sock-offsets)]
      (let [size (cond
                   (#{:mss-cache} field) :h  ; 16-bit
                   (#{:ecn-flags :ca-state} field) :b  ; 8-bit
                   :else :w)]  ; 32-bit
        (case size
          :w (is (bytes? (struct-ops/tcp-sock-load-u32 :r6 :r0 field)))
          :h (is (bytes? (struct-ops/tcp-sock-load-u16 :r6 :r0 field)))
          :b (is (bytes? (struct-ops/tcp-sock-load-u8 :r6 :r0 field))))))))

(deftest test-various-return-values
  (testing "Various return values work"
    (doseq [val [0 1 2 10 100 255]]
      (let [insns (struct-ops/struct-ops-return-imm val)]
        (is (vector? insns))
        (is (= 2 (count insns)))
        (is (every? bytes? insns))))))

;; ============================================================================
;; Complex Program Tests
;; ============================================================================

(deftest test-full-cong-avoid-pattern
  (testing "Full cong_avoid pattern assembles"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          ;; Save args
                          (struct-ops/cong-avoid-prologue :r6 :r7 :r8)
                          ;; Check slow start
                          (struct-ops/slow-start-check :r6 :r9 :r1 3)
                          ;; In slow start: increment cwnd
                          (struct-ops/increment-cwnd :r6 :r2)
                          [(dsl/jmp-imm :ja :r0 0 0)]  ; skip congestion avoidance
                          ;; In congestion avoidance: just return
                          (struct-ops/struct-ops-return-void))))]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-callback-info-completeness
  (testing "All callback infos have required fields"
    (doseq [[callback info] struct-ops/tcp-congestion-ops-callbacks]
      (is (contains? info :args) (str callback " should have :args"))
      (is (contains? info :return) (str callback " should have :return"))
      (is (contains? info :required) (str callback " should have :required"))
      (is (number? (:args info)) (str callback " :args should be a number"))
      (is (keyword? (:return info)) (str callback " :return should be a keyword"))
      (is (boolean? (:required info)) (str callback " :required should be boolean")))))
