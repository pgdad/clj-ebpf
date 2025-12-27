(ns clj-ebpf.net.checksum-test
  "Tests for checksum calculation helpers - CI-safe"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.net.checksum :as csum]
            [clj-ebpf.dsl :as dsl]))

(deftest test-constants
  (testing "BPF helper function IDs are correct"
    (is (= 28 csum/BPF-FUNC-csum-diff))
    (is (= 10 csum/BPF-FUNC-l3-csum-replace))
    (is (= 11 csum/BPF-FUNC-l4-csum-replace))
    (is (= 40 csum/BPF-FUNC-csum-update)))

  (testing "Checksum flags are correct"
    (is (= 0x01 csum/BPF-F-RECOMPUTE-CSUM))
    (is (= 0x10 csum/BPF-F-PSEUDO-HDR))
    (is (= 0x20 csum/BPF-F-MARK-MANGLED-0))
    (is (= 0x40 csum/BPF-F-MARK-ENFORCE))))

(deftest test-l3-csum-replace-4
  (testing "l3-csum-replace-4 generates 6 instructions"
    (let [instrs (csum/l3-csum-replace-4 :r6 24 :r8 :r9)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "l3-csum-replace-4 with different registers"
    (let [instrs (csum/l3-csum-replace-4 :r7 10 :r1 :r2)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-l3-csum-replace-2
  (testing "l3-csum-replace-2 generates 6 instructions"
    (let [instrs (csum/l3-csum-replace-2 :r6 24 :r8 :r9)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-l4-csum-replace-4
  (testing "l4-csum-replace-4 generates 6 instructions without pseudo-header"
    (let [instrs (csum/l4-csum-replace-4 :r6 50 :r8 :r9 false)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "l4-csum-replace-4 generates 6 instructions with pseudo-header"
    (let [instrs (csum/l4-csum-replace-4 :r6 50 :r8 :r9 true)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-l4-csum-replace-2
  (testing "l4-csum-replace-2 generates 6 instructions"
    (let [instrs (csum/l4-csum-replace-2 :r6 50 :r8 :r9 false)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-convenience-wrappers
  (testing "update-ip-checksum generates correct instructions"
    (let [instrs (csum/update-ip-checksum :r6 14 :r8 :r9)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "update-tcp-checksum-for-ip generates correct instructions"
    (let [instrs (csum/update-tcp-checksum-for-ip :r6 34 :r8 :r9)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "update-udp-checksum-for-ip generates correct instructions"
    (let [instrs (csum/update-udp-checksum-for-ip :r6 34 :r8 :r9)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "update-tcp-checksum-for-port generates correct instructions"
    (let [instrs (csum/update-tcp-checksum-for-port :r6 34 :r8 :r9)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "update-udp-checksum-for-port generates correct instructions"
    (let [instrs (csum/update-udp-checksum-for-port :r6 34 :r8 :r9)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-csum-diff
  (testing "csum-diff generates 6 instructions"
    (let [instrs (csum/csum-diff :r6 4 :r7 4 :r8)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-fold-csum-32
  (testing "fold-csum-32 generates 8 instructions"
    (let [instrs (csum/fold-csum-32 :r0 :r1)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-negate-csum
  (testing "negate-csum generates 2 instructions"
    (let [instrs (csum/negate-csum :r0)]
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-build-api
  (testing "build-l3-csum-replace is alias for l3-csum-replace-4"
    (let [instrs1 (csum/build-l3-csum-replace :r6 24 :r8 :r9)
          instrs2 (csum/l3-csum-replace-4 :r6 24 :r8 :r9)]
      (is (= (count instrs1) (count instrs2)))
      ;; Compare actual byte contents
      (is (= (mapv vec instrs1) (mapv vec instrs2)))))

  (testing "build-l4-csum-replace generates 6 instructions"
    (let [instrs (csum/build-l4-csum-replace :r6 50 :r8 :r9 0)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-l4-csum-replace with pseudo-header flag"
    (let [instrs (csum/build-l4-csum-replace :r6 50 :r8 :r9 csum/BPF-F-PSEUDO-HDR)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-csum-diff generates 6 instructions"
    (let [instrs (csum/build-csum-diff :r6 4 :r7 4 0)]
      (is (= 6 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-complete-nat-example
  (testing "Complete DNAT checksum update sequence assembles"
    (let [ip-hdr-off 14
          tcp-csum-off 50
          ;; DNAT sequence: Update IP checksum, then TCP checksum
          program (concat
                    ;; Update IP header checksum (old dst in r8, new dst in r9)
                    (csum/update-ip-checksum :r6 ip-hdr-off :r8 :r9)
                    ;; Update TCP checksum for IP change
                    (csum/update-tcp-checksum-for-ip :r6 tcp-csum-off :r8 :r9)
                    ;; Return TC_ACT_OK
                    [(dsl/mov :r0 0)
                     (dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 6 + 6 + 2 = 14 instructions = 112 bytes
      (is (= 112 (count bytecode))))))

(deftest test-xdp-checksum-calculation
  (testing "XDP manual checksum calculation sequence"
    ;; XDP doesn't have l3/l4_csum_replace, must use csum_diff
    (let [program (concat
                    ;; Compute checksum diff between old and new data on stack
                    (csum/csum-diff :r6 4 :r7 4 :r8)
                    ;; Fold the result
                    (csum/fold-csum-32 :r0 :r1)
                    ;; XDP_PASS
                    [(dsl/mov :r0 2)
                     (dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 6 + 8 + 2 = 16 instructions = 128 bytes
      (is (= 128 (count bytecode))))))
