(ns clj-ebpf.net.ipv6-test
  "Tests for IPv6 address loading helpers - CI-safe"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.net.ipv6 :as ipv6]
            [clj-ebpf.dsl :as dsl]))

(deftest test-ipv6-constants
  (testing "IPv6 header field offsets are correct"
    (is (= 0 ipv6/IPV6-OFF-VERSION))
    (is (= 4 ipv6/IPV6-OFF-PAYLOAD-LEN))
    (is (= 6 ipv6/IPV6-OFF-NEXT-HEADER))
    (is (= 7 ipv6/IPV6-OFF-HOP-LIMIT))
    (is (= 8 ipv6/IPV6-OFF-SRC))
    (is (= 24 ipv6/IPV6-OFF-DST))
    (is (= 40 ipv6/IPV6-HLEN))
    (is (= 16 ipv6/IPV6-ADDR-LEN)))

  (testing "IPv4 constants are correct"
    (is (= 12 ipv6/IPV4-OFF-SRC))
    (is (= 16 ipv6/IPV4-OFF-DST))
    (is (= 4 ipv6/IPV4-ADDR-LEN))))

(deftest test-build-load-ipv6-address
  (testing "build-load-ipv6-address generates 8 instructions"
    (let [instrs (ipv6/build-load-ipv6-address :r9 ipv6/IPV6-OFF-SRC -84)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-load-ipv6-address with destination offset"
    (let [instrs (ipv6/build-load-ipv6-address :r9 ipv6/IPV6-OFF-DST -68)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-load-ipv6-address with different registers"
    (let [instrs (ipv6/build-load-ipv6-address :r6 0 -100)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-build-load-ipv6-address-adjusted
  (testing "build-load-ipv6-address-adjusted generates 8 instructions"
    (let [instrs (ipv6/build-load-ipv6-address-adjusted :r9 -44 ipv6/IPV6-OFF-SRC -56)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-load-ipv6-address-adjusted with positive offset"
    (let [instrs (ipv6/build-load-ipv6-address-adjusted :r6 14 ipv6/IPV6-OFF-SRC -84)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-build-load-ipv4-unified
  (testing "build-load-ipv4-unified generates 5 instructions"
    (let [instrs (ipv6/build-load-ipv4-unified :r9 12 -84)]
      (is (= 5 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-load-ipv4-unified for destination"
    (let [instrs (ipv6/build-load-ipv4-unified :r9 16 -68)]
      (is (= 5 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-convenience-functions
  (testing "build-load-ipv4-src-unified generates correct instructions"
    (let [instrs1 (ipv6/build-load-ipv4-src-unified :r9 -84)
          instrs2 (ipv6/build-load-ipv4-unified :r9 ipv6/IPV4-OFF-SRC -84)]
      (is (= (count instrs1) (count instrs2)))
      (is (= (mapv vec instrs1) (mapv vec instrs2)))))

  (testing "build-load-ipv4-dst-unified generates correct instructions"
    (let [instrs1 (ipv6/build-load-ipv4-dst-unified :r9 -68)
          instrs2 (ipv6/build-load-ipv4-unified :r9 ipv6/IPV4-OFF-DST -68)]
      (is (= (count instrs1) (count instrs2)))
      (is (= (mapv vec instrs1) (mapv vec instrs2)))))

  (testing "build-load-ipv6-src generates correct instructions"
    (let [instrs1 (ipv6/build-load-ipv6-src :r9 -84)
          instrs2 (ipv6/build-load-ipv6-address :r9 ipv6/IPV6-OFF-SRC -84)]
      (is (= (count instrs1) (count instrs2)))
      (is (= (mapv vec instrs1) (mapv vec instrs2)))))

  (testing "build-load-ipv6-dst generates correct instructions"
    (let [instrs1 (ipv6/build-load-ipv6-dst :r9 -68)
          instrs2 (ipv6/build-load-ipv6-address :r9 ipv6/IPV6-OFF-DST -68)]
      (is (= (count instrs1) (count instrs2)))
      (is (= (mapv vec instrs1) (mapv vec instrs2))))))

(deftest test-build-copy-ipv6-address
  (testing "build-copy-ipv6-address generates 8 instructions"
    (let [instrs (ipv6/build-copy-ipv6-address -84 -100)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-copy-ipv6-address with different offsets"
    (let [instrs (ipv6/build-copy-ipv6-address -32 -64)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-build-store-ipv6-address
  (testing "build-store-ipv6-address generates 8 instructions"
    (let [instrs (ipv6/build-store-ipv6-address -84 :r9 ipv6/IPV6-OFF-DST)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-store-ipv6-address with source offset"
    (let [instrs (ipv6/build-store-ipv6-address -68 :r9 ipv6/IPV6-OFF-SRC)]
      (is (= 8 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-dual-stack-pattern
  (testing "Dual-stack address loading assembles correctly"
    (let [;; Simulating loading addresses into unified format
          ;; For IPv4 path
          ipv4-program (concat
                         (ipv6/build-load-ipv4-src-unified :r9 -84)
                         (ipv6/build-load-ipv4-dst-unified :r9 -68)
                         [(dsl/exit-insn)])
          ipv4-bytecode (dsl/assemble ipv4-program)

          ;; For IPv6 path
          ipv6-program (concat
                         (ipv6/build-load-ipv6-src :r9 -84)
                         (ipv6/build-load-ipv6-dst :r9 -68)
                         [(dsl/exit-insn)])
          ipv6-bytecode (dsl/assemble ipv6-program)]
      (is (bytes? ipv4-bytecode))
      (is (bytes? ipv6-bytecode))
      ;; IPv4: 5 + 5 + 1 = 11 instructions = 88 bytes
      (is (= 88 (count ipv4-bytecode)))
      ;; IPv6: 8 + 8 + 1 = 17 instructions = 136 bytes
      (is (= 136 (count ipv6-bytecode))))))

(deftest test-address-copy-and-restore
  (testing "Copy and restore pattern assembles"
    (let [program (concat
                    ;; Load original destination
                    (ipv6/build-load-ipv6-dst :r9 -84)
                    ;; Copy to backup location
                    (ipv6/build-copy-ipv6-address -84 -100)
                    ;; ... modify address at -84 ...
                    ;; Restore from backup
                    (ipv6/build-store-ipv6-address -100 :r9 ipv6/IPV6-OFF-DST)
                    [(dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 8 + 8 + 8 + 1 = 25 instructions = 200 bytes
      (is (= 200 (count bytecode))))))

(deftest test-conntrack-key-building
  (testing "Building conntrack key with unified addresses"
    (let [program (concat
                    ;; Load source address to key offset 0-15
                    (ipv6/build-load-ipv6-src :r9 -64)
                    ;; Load dest address to key offset 16-31
                    (ipv6/build-load-ipv6-dst :r9 -48)
                    ;; Key is now at stack[-64] to stack[-33]
                    [(dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 8 + 8 + 1 = 17 instructions = 136 bytes
      (is (= 136 (count bytecode))))))
