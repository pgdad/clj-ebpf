(ns clj-ebpf.net-test
  "Tests for networking helpers - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]
            [clj-ebpf.net.ethernet :as eth]
            [clj-ebpf.net.ipv4 :as ipv4]
            [clj-ebpf.net.tcp :as tcp]
            [clj-ebpf.net.udp :as udp]
            [clj-ebpf.net.checksum :as csum]
            [clj-ebpf.net.nat :as nat]))

;; ============================================================================
;; Protocol Constants Tests
;; ============================================================================

(deftest test-ethernet-constants
  (testing "Ethernet type constants"
    (is (= 0x0800 net/ETH-P-IP))
    (is (= 0x86DD net/ETH-P-IPV6))
    (is (= 0x0806 net/ETH-P-ARP))
    (is (= 14 net/ETH-HLEN))
    (is (= 6 net/ETH-ALEN))))

(deftest test-ip-protocol-constants
  (testing "IP protocol numbers"
    (is (= 1 net/IPPROTO-ICMP))
    (is (= 6 net/IPPROTO-TCP))
    (is (= 17 net/IPPROTO-UDP))
    (is (= 58 net/IPPROTO-ICMPV6))))

(deftest test-header-size-constants
  (testing "Header size constants"
    (is (= 20 net/IPV4-MIN-HLEN))
    (is (= 40 net/IPV6-HLEN))
    (is (= 20 net/TCP-MIN-HLEN))
    (is (= 8 net/UDP-HLEN))))

(deftest test-tcp-flag-constants
  (testing "TCP flag constants"
    (is (= 0x01 net/TCP-FIN))
    (is (= 0x02 net/TCP-SYN))
    (is (= 0x04 net/TCP-RST))
    (is (= 0x08 net/TCP-PSH))
    (is (= 0x10 net/TCP-ACK))
    (is (= 0x20 net/TCP-URG))))

(deftest test-xdp-action-constants
  (testing "XDP action codes"
    (is (= 0 net/XDP-ABORTED))
    (is (= 1 net/XDP-DROP))
    (is (= 2 net/XDP-PASS))
    (is (= 3 net/XDP-TX))
    (is (= 4 net/XDP-REDIRECT))))

(deftest test-tc-action-constants
  (testing "TC action codes"
    (is (= 0 net/TC-ACT-OK))
    (is (= 2 net/TC-ACT-SHOT))
    (is (= 7 net/TC-ACT-REDIRECT))))

;; ============================================================================
;; Offset Helper Tests
;; ============================================================================

(deftest test-eth-offsets
  (testing "Ethernet header offsets"
    (is (= 0 (net/eth-offset :dst-mac)))
    (is (= 6 (net/eth-offset :src-mac)))
    (is (= 12 (net/eth-offset :ethertype)))))

(deftest test-ipv4-offsets
  (testing "IPv4 header offsets"
    (is (= 0 (net/ipv4-offset :version-ihl)))
    (is (= 1 (net/ipv4-offset :tos)))
    (is (= 2 (net/ipv4-offset :tot-len)))
    (is (= 8 (net/ipv4-offset :ttl)))
    (is (= 9 (net/ipv4-offset :protocol)))
    (is (= 10 (net/ipv4-offset :check)))
    (is (= 12 (net/ipv4-offset :saddr)))
    (is (= 16 (net/ipv4-offset :daddr)))))

(deftest test-ipv6-offsets
  (testing "IPv6 header offsets"
    (is (= 0 (net/ipv6-offset :version-tc-flow)))
    (is (= 4 (net/ipv6-offset :payload-len)))
    (is (= 6 (net/ipv6-offset :next-header)))
    (is (= 7 (net/ipv6-offset :hop-limit)))
    (is (= 8 (net/ipv6-offset :saddr)))
    (is (= 24 (net/ipv6-offset :daddr)))))

(deftest test-tcp-offsets
  (testing "TCP header offsets"
    (is (= 0 (net/tcp-offset :sport)))
    (is (= 2 (net/tcp-offset :dport)))
    (is (= 4 (net/tcp-offset :seq)))
    (is (= 8 (net/tcp-offset :ack-seq)))
    (is (= 12 (net/tcp-offset :data-off)))
    (is (= 13 (net/tcp-offset :flags)))
    (is (= 14 (net/tcp-offset :window)))
    (is (= 16 (net/tcp-offset :check)))
    (is (= 18 (net/tcp-offset :urg-ptr)))))

(deftest test-udp-offsets
  (testing "UDP header offsets"
    (is (= 0 (net/udp-offset :sport)))
    (is (= 2 (net/udp-offset :dport)))
    (is (= 4 (net/udp-offset :len)))
    (is (= 6 (net/udp-offset :check)))))

;; ============================================================================
;; Bounds Check Tests
;; ============================================================================

(deftest test-bounds-check-generation
  (testing "Static bounds check generates correct instructions"
    (let [insns (net/check-bounds :r6 :r7 14 5 :r8)]
      (is (= 3 (count insns)))
      ;; Each instruction should be a byte array of 8 bytes
      (is (every? #(= 8 (count %)) insns)))))

(deftest test-bounds-check-dynamic-generation
  (testing "Dynamic bounds check generates correct instructions"
    (let [insns (net/check-bounds-dynamic :r6 :r7 :r8 5 :r9)]
      (is (= 3 (count insns)))
      (is (every? #(= 8 (count %)) insns)))))

;; ============================================================================
;; XDP/TC Context Helper Tests
;; ============================================================================

(deftest test-xdp-load-data-ptrs
  (testing "XDP data pointer loading"
    (let [insns (net/xdp-load-data-ptrs :r6 :r7 :r1)]
      (is (= 2 (count insns)))
      (is (every? #(= 8 (count %)) insns)))))

(deftest test-tc-load-data-ptrs
  (testing "TC data pointer loading"
    (let [insns (net/tc-load-data-ptrs :r6 :r7 :r1)]
      (is (= 2 (count insns)))
      (is (every? #(= 8 (count %)) insns)))))

;; ============================================================================
;; Ethernet Helper Tests
;; ============================================================================

(deftest test-eth-load-ethertype
  (testing "Ethertype loading"
    (let [insns (eth/load-ethertype :r8 :r6)]
      (is (= 1 (count insns)))
      (is (= 8 (count (first insns)))))))

(deftest test-eth-is-ipv4
  (testing "IPv4 check instruction"
    (let [insns (eth/is-ipv4 :r8 5)]
      (is (= 1 (count insns)))
      (is (= 8 (count (first insns)))))))

(deftest test-eth-parse-ethernet
  (testing "Full Ethernet parsing"
    (let [insns (eth/parse-ethernet :r6 :r7 :r8 10 :r9)]
      ;; Should have bounds check (3) + load ethertype (1)
      (is (= 4 (count insns)))
      (is (every? #(= 8 (count %)) insns)))))

(deftest test-eth-get-ip-header-ptr
  (testing "IP header pointer calculation"
    (let [insns (eth/get-ip-header-ptr :r8 :r6)]
      (is (= 2 (count insns))))))

;; ============================================================================
;; IPv4 Helper Tests
;; ============================================================================

(deftest test-ipv4-load-protocol
  (testing "Protocol loading"
    (let [insns (ipv4/load-protocol :r8 :r6)]
      (is (= 1 (count insns))))))

(deftest test-ipv4-load-addrs
  (testing "Source and dest IP loading"
    (let [insns (ipv4/parse-addrs :r8 :r9 :r6)]
      (is (= 2 (count insns))))))

(deftest test-ipv4-load-ihl
  (testing "IHL loading and multiplication"
    (let [insns (ipv4/load-ihl :r8 :r6)]
      (is (= 3 (count insns))))))

(deftest test-ipv4-is-tcp
  (testing "TCP protocol check"
    (let [insns (ipv4/is-tcp :r8 5)]
      (is (= 1 (count insns))))))

(deftest test-ipv4-parse-header
  (testing "Full IPv4 parsing"
    (let [insns (ipv4/parse-ipv4-header :r6 :r7 :r8 :r9 10 :r5)]
      ;; bounds check (3) + load protocol (1) + l4 ptr (2)
      (is (= 6 (count insns))))))

;; ============================================================================
;; TCP Helper Tests
;; ============================================================================

(deftest test-tcp-load-ports
  (testing "TCP port loading"
    (let [insns (tcp/load-ports :r8 :r9 :r6)]
      (is (= 2 (count insns))))))

(deftest test-tcp-load-ports-host
  (testing "TCP port loading with byte order conversion"
    (let [insns (tcp/load-ports-host :r8 :r9 :r6)]
      (is (= 4 (count insns))))))

(deftest test-tcp-load-flags
  (testing "TCP flags loading"
    (let [insns (tcp/load-flags :r8 :r6)]
      (is (= 1 (count insns))))))

(deftest test-tcp-is-syn
  (testing "SYN flag check"
    (let [insns (tcp/is-syn :r8 5)]
      (is (= 1 (count insns))))))

(deftest test-tcp-parse-header
  (testing "Full TCP parsing"
    (let [insns (tcp/parse-tcp-header :r6 :r7 :r8 :r9 10 :r5)]
      ;; bounds check (3) + load ports (2)
      (is (= 5 (count insns))))))

;; ============================================================================
;; UDP Helper Tests
;; ============================================================================

(deftest test-udp-load-ports
  (testing "UDP port loading"
    (let [insns (udp/load-ports :r8 :r9 :r6)]
      (is (= 2 (count insns))))))

(deftest test-udp-parse-header
  (testing "Full UDP parsing"
    (let [insns (udp/parse-udp-header :r6 :r7 :r8 :r9 10 :r5)]
      ;; bounds check (3) + load ports (2)
      (is (= 5 (count insns))))))

(deftest test-udp-get-payload-ptr
  (testing "UDP payload pointer"
    (let [insns (udp/get-payload-ptr :r8 :r6)]
      (is (= 2 (count insns))))))

;; ============================================================================
;; Checksum Helper Tests
;; ============================================================================

(deftest test-l3-csum-replace
  (testing "L3 checksum replace generates helper call"
    (let [insns (csum/l3-csum-replace-4 :r6 24 :r3 :r4)]
      (is (= 6 (count insns)))
      ;; Last instruction should be a call
      (is (= 8 (count (last insns)))))))

(deftest test-l4-csum-replace
  (testing "L4 checksum replace generates helper call"
    (let [insns (csum/l4-csum-replace-4 :r6 36 :r3 :r4 true)]
      (is (= 6 (count insns))))))

(deftest test-update-ip-checksum
  (testing "IP checksum update wrapper"
    (let [insns (csum/update-ip-checksum :r6 14 :r3 :r4)]
      (is (= 6 (count insns))))))

(deftest test-update-tcp-checksum-for-ip
  (testing "TCP checksum update for IP change"
    (let [insns (csum/update-tcp-checksum-for-ip :r6 34 :r3 :r4)]
      (is (= 6 (count insns))))))

;; ============================================================================
;; NAT Helper Tests
;; ============================================================================

(deftest test-dnat-ip
  (testing "DNAT IP generates instruction sequence"
    (let [insns (nat/dnat-ip :r6 :r7 14 34 :tcp :r3 :r4 :r8)]
      (is (seq insns))
      ;; Should include store and helper calls
      (is (every? #(= 8 (count %)) insns)))))

(deftest test-dnat-port
  (testing "DNAT port generates instruction sequence"
    (let [insns (nat/dnat-port :r6 :r7 34 :tcp :r3 :r4 :r8)]
      (is (seq insns)))))

(deftest test-full-dnat
  (testing "Full DNAT generates combined sequence"
    (let [insns (nat/full-dnat :r6 :r7 14 34 :tcp
                               :r2 :r3 :r4 :r5 :r8)]
      (is (seq insns)))))

(deftest test-snat-ip
  (testing "SNAT IP generates instruction sequence"
    (let [insns (nat/snat-ip :r6 :r7 14 34 :tcp :r3 :r4 :r8)]
      (is (seq insns)))))

(deftest test-full-snat
  (testing "Full SNAT generates combined sequence"
    (let [insns (nat/full-snat :r6 :r7 14 34 :tcp
                               :r2 :r3 :r4 :r5 :r8)]
      (is (seq insns)))))

(deftest test-xdp-rewrite-helpers
  (testing "XDP rewrite helpers generate instructions"
    (is (= 3 (count (nat/xdp-rewrite-daddr :r6 14 :r3 :r8))))
    (is (= 3 (count (nat/xdp-rewrite-saddr :r6 14 :r3 :r8))))
    (is (= 3 (count (nat/xdp-rewrite-dport :r6 34 :tcp :r3 :r8))))
    (is (= 3 (count (nat/xdp-rewrite-sport :r6 34 :tcp :r3 :r8))))))

;; ============================================================================
;; Integration Tests - Assembling Complete Programs
;; ============================================================================

(deftest test-simple-xdp-program-assembly
  (testing "Simple XDP IPv4 filter program can be assembled"
    (let [;; fail-label is 6 instructions from bounds check
          prog-insns (concat
                      ;; Load data pointers (2 insns)
                      (net/xdp-load-data-ptrs :r6 :r7 :r1)
                      ;; Check ethernet bounds (3 insns) - fail jumps 4 forward
                      (net/check-bounds :r6 :r7 net/ETH-HLEN 4 :r8)
                      ;; Load ethertype (1 insn)
                      (eth/load-ethertype :r8 :r6)
                      ;; Check IPv4 - skip 2 to pass (1 insn)
                      (eth/is-ipv4 :r8 2)
                      ;; Not IPv4 - drop (2 insns)
                      (net/return-action net/XDP-DROP)
                      ;; IPv4 - pass (2 insns)
                      (net/return-action net/XDP-PASS))
          bytecode (dsl/assemble prog-insns)]
      ;; Should produce valid bytecode
      (is (pos? (count bytecode)))
      ;; Bytecode should be multiple of 8 (BPF instruction size)
      (is (zero? (mod (count bytecode) 8)))
      ;; Check expected size: 11 instructions * 8 bytes = 88
      (is (= 88 (count bytecode))))))

(deftest test-tcp-port-filter-assembly
  (testing "TCP port filter program structure"
    (let [;; Build just the TCP parsing part
          tcp-parse (concat
                     (tcp/load-ports :r8 :r9 :r6)
                     (tcp/is-dport :r9 8080 2)  ; Jump 2 if port matches
                     (net/return-action net/XDP-PASS)
                     (net/return-action net/XDP-DROP))
          bytecode (dsl/assemble tcp-parse)]
      (is (pos? (count bytecode)))
      (is (zero? (mod (count bytecode) 8))))))

(deftest test-return-action
  (testing "Return action generates mov and exit"
    (let [insns (net/return-action net/XDP-PASS)]
      (is (= 2 (count insns)))
      (is (every? #(= 8 (count %)) insns)))))
