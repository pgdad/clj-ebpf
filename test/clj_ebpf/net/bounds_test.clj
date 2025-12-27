(ns clj-ebpf.net.bounds-test
  "Tests for packet bounds checking helpers - CI-safe"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.net.bounds :as bounds]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.asm :as asm]))

(deftest test-build-bounds-check
  (testing "build-bounds-check returns 3 instructions"
    (let [instrs (bounds/build-bounds-check :r6 :r7 0 14 10)]
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-bounds-check with different offsets"
    (let [instrs (bounds/build-bounds-check :r6 :r7 14 20 5)]
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-bounds-check uses correct offset calculation"
    ;; offset=14, size=20 -> should add 34 to data pointer
    (let [instrs (bounds/build-bounds-check :r6 :r7 14 20 5)]
      ;; First instruction: mov r8, r6
      ;; Second instruction: add r8, 34 (14 + 20)
      ;; Third instruction: jgt r8, r7, +5
      (is (= 3 (count instrs))))))

(deftest test-build-bounds-check-label
  (testing "build-bounds-check-label returns 3 instructions/pseudo-instructions"
    (let [instrs (bounds/build-bounds-check-label :r6 :r7 0 14 :drop)]
      (is (= 3 (count instrs)))
      ;; First two are bytecode, third is a symbolic jump
      (is (bytes? (first instrs)))
      (is (bytes? (second instrs)))
      (is (map? (nth instrs 2)))
      (is (= :jmp-reg (:type (nth instrs 2))))
      (is (= :drop (:target (nth instrs 2))))))

  (testing "build-bounds-check-label assembles correctly with labels"
    (let [program (concat
                    (bounds/build-bounds-check-label :r6 :r7 0 14 :drop)
                    [(dsl/mov :r0 2)]  ; XDP_PASS
                    [(dsl/exit-insn)]
                    [(asm/label :drop)]
                    [(dsl/mov :r0 1)]  ; XDP_DROP
                    [(dsl/exit-insn)])
          bytecode (asm/assemble-with-labels program)]
      ;; Should assemble without errors
      (is (bytes? bytecode))
      ;; 3 (bounds check) + 2 (pass path) + 2 (drop path) = 7 instructions = 56 bytes
      (is (= 56 (count bytecode))))))

(deftest test-build-bounds-check-with-scratch
  (testing "build-bounds-check-with-scratch uses custom scratch register"
    (let [instrs (bounds/build-bounds-check-with-scratch :r6 :r7 0 14 10 :r9)]
      (is (= 3 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-bounds-check-label-with-scratch uses custom scratch register"
    (let [instrs (bounds/build-bounds-check-label-with-scratch :r6 :r7 0 14 :drop :r9)]
      (is (= 3 (count instrs)))
      (is (bytes? (first instrs)))
      (is (bytes? (second instrs)))
      (is (map? (nth instrs 2))))))

(deftest test-protocol-constants
  (testing "Protocol header size constants are correct"
    (is (= 14 bounds/ETH-HLEN))
    (is (= 20 bounds/IPV4-MIN-HLEN))
    (is (= 40 bounds/IPV6-HLEN))
    (is (= 20 bounds/TCP-MIN-HLEN))
    (is (= 8 bounds/UDP-HLEN))
    (is (= 8 bounds/ICMP-HLEN))))

(deftest test-convenience-functions
  (testing "check-eth-header generates correct bounds check"
    (let [instrs (bounds/check-eth-header :r6 :r7 :drop)]
      (is (= 3 (count instrs)))))

  (testing "check-ipv4-header generates correct bounds check"
    (let [instrs (bounds/check-ipv4-header :r6 :r7 :drop)]
      (is (= 3 (count instrs)))))

  (testing "check-ipv6-header generates correct bounds check"
    (let [instrs (bounds/check-ipv6-header :r6 :r7 :drop)]
      (is (= 3 (count instrs)))))

  (testing "check-l4-ports generates correct bounds check"
    (let [instrs (bounds/check-l4-ports :r6 :r7 34 :drop)]
      (is (= 3 (count instrs)))))

  (testing "check-tcp-header generates correct bounds check"
    (let [instrs (bounds/check-tcp-header :r6 :r7 34 :drop)]
      (is (= 3 (count instrs)))))

  (testing "check-udp-header generates correct bounds check"
    (let [instrs (bounds/check-udp-header :r6 :r7 34 :drop)]
      (is (= 3 (count instrs))))))

(deftest test-complete-xdp-example
  (testing "Complete XDP program with bounds checking assembles"
    (let [program (concat
                    ;; Load data and data_end
                    [(dsl/ldx :dw :r6 :r1 0)    ; r6 = data
                     (dsl/ldx :dw :r7 :r1 8)]   ; r7 = data_end

                    ;; Check Ethernet header bounds
                    (bounds/check-eth-header :r6 :r7 :drop)

                    ;; Check IPv4 header bounds
                    (bounds/check-ipv4-header :r6 :r7 :drop)

                    ;; Return XDP_PASS
                    [(dsl/mov :r0 2)
                     (dsl/exit-insn)]

                    ;; Drop label
                    [(asm/label :drop)
                     (dsl/mov :r0 1)
                     (dsl/exit-insn)])
          bytecode (asm/assemble-with-labels program)]
      (is (bytes? bytecode))
      ;; 2 (loads) + 3 (eth check) + 3 (ipv4 check) + 2 (pass) + 2 (drop) = 12 instructions
      (is (= 96 (count bytecode))))))

(deftest test-multiple-checks-sequence
  (testing "Multiple bounds checks in sequence"
    (let [l4-offset 34  ; ETH (14) + IPv4 (20)
          program (concat
                    ;; Ethernet header check
                    (bounds/check-eth-header :r6 :r7 :drop)

                    ;; IPv4 header check
                    (bounds/check-ipv4-header :r6 :r7 :drop)

                    ;; L4 ports check
                    (bounds/check-l4-ports :r6 :r7 l4-offset :drop)

                    ;; All checks passed
                    [(dsl/mov :r0 2)
                     (dsl/exit-insn)]

                    [(asm/label :drop)
                     (dsl/mov :r0 1)
                     (dsl/exit-insn)])
          bytecode (asm/assemble-with-labels program)]
      (is (bytes? bytecode))
      ;; 3 + 3 + 3 + 2 + 2 = 13 instructions = 104 bytes
      (is (= 104 (count bytecode))))))
