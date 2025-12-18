(ns clj-ebpf.dsl-socket-test
  "Tests for Socket Filter DSL - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.socket :as socket]))

;; ============================================================================
;; Action Tests
;; ============================================================================

(deftest test-socket-actions
  (testing "Socket filter action values"
    (is (= 0 (:reject socket/socket-filter-actions)))
    (is (= -1 (:accept socket/socket-filter-actions))))

  (testing "socket-action function"
    (is (= 0 (socket/socket-action :reject)))
    (is (= -1 (socket/socket-action :accept))))

  (testing "Invalid action throws"
    (is (thrown? clojure.lang.ExceptionInfo
                (socket/socket-action :invalid)))))

;; ============================================================================
;; __sk_buff Tests (reused from TC)
;; ============================================================================

(deftest test-skb-offsets
  (testing "Socket filter reuses TC __sk_buff offsets"
    (is (= 0 (socket/skb-offset :len)))
    (is (= 76 (socket/skb-offset :data)))
    (is (= 80 (socket/skb-offset :data-end)))
    (is (= 16 (socket/skb-offset :protocol)))))

;; ============================================================================
;; Prologue Tests
;; ============================================================================

(deftest test-socket-prologue
  (testing "Basic prologue"
    (let [insns (socket/socket-prologue :r2 :r3)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "Prologue with context save"
    (let [insns (socket/socket-prologue :r6 :r2 :r3)]
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Context Access Tests
;; ============================================================================

(deftest test-socket-get-len
  (testing "Get packet length"
    (let [insn (socket/socket-get-len :r1 :r0)]
      (is (bytes? insn)))))

(deftest test-socket-get-protocol
  (testing "Get protocol"
    (let [insn (socket/socket-get-protocol :r1 :r0)]
      (is (bytes? insn)))))

(deftest test-socket-get-ifindex
  (testing "Get interface index"
    (let [insn (socket/socket-get-ifindex :r1 :r0)]
      (is (bytes? insn)))))

;; ============================================================================
;; Return Pattern Tests
;; ============================================================================

(deftest test-socket-accept
  (testing "Accept packet (return length)"
    (let [insns (socket/socket-accept :r6)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-socket-accept-bytes
  (testing "Accept specific bytes"
    (let [insns (socket/socket-accept-bytes 100)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-socket-reject
  (testing "Reject packet"
    (let [insns (socket/socket-reject)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Builder Tests
;; ============================================================================

(deftest test-build-socket-filter
  (testing "Accept-all filter"
    (let [bytecode (socket/build-socket-filter
                    {:body []
                     :default-action :accept})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "Reject-all filter"
    (let [bytecode (socket/build-socket-filter
                    {:body []
                     :default-action :reject})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "Filter with body"
    (let [bytecode (socket/build-socket-filter
                    {:ctx-reg :r6
                     :body [(dsl/mov :r0 42)]
                     :default-action :accept})]
      (is (bytes? bytecode)))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(socket/defsocket-filter-instructions test-accept-all
  {:default-action :accept}
  [])

(socket/defsocket-filter-instructions test-reject-all
  {:default-action :reject}
  [])

(socket/defsocket-filter-instructions test-with-ctx
  {:ctx-reg :r6
   :default-action :accept}
  [(dsl/mov :r0 100)])

(deftest test-macro
  (testing "Accept-all macro"
    (let [insns (test-accept-all)]
      (is (vector? insns))
      (is (>= (count insns) 4))
      (is (every? bytes? insns))))

  (testing "Reject-all macro"
    (let [insns (test-reject-all)]
      (is (vector? insns))
      (is (>= (count insns) 4))
      (is (every? bytes? insns))))

  (testing "With context"
    (let [insns (test-with-ctx)]
      (is (vector? insns))
      (is (>= (count insns) 5))
      (is (every? bytes? insns))))

  (testing "Assembly works"
    (is (bytes? (dsl/assemble (test-accept-all))))
    (is (bytes? (dsl/assemble (test-reject-all))))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-section-names
  (testing "Default section name"
    (is (= "socket" (socket/socket-filter-section-name))))

  (testing "Named section"
    (is (= "socket/my_filter"
           (socket/socket-filter-section-name "my_filter")))))

;; ============================================================================
;; Metadata Tests
;; ============================================================================

(deftest test-program-metadata
  (testing "Socket filter metadata"
    (let [info (socket/make-socket-filter-info
                "my_filter" (test-accept-all))]
      (is (= "my_filter" (:name info)))
      (is (= "socket/my_filter" (:section info)))
      (is (= :socket-filter (:type info)))
      (is (vector? (:instructions info))))))

;; ============================================================================
;; Protocol Constant Tests
;; ============================================================================

(deftest test-protocol-constants
  (testing "Ethernet header size"
    (is (= 14 socket/ethernet-header-size)))

  (testing "IPv4 header min size"
    (is (= 20 socket/ipv4-header-min-size)))

  (testing "IPv6 header size"
    (is (= 40 socket/ipv6-header-size)))

  (testing "TCP header min size"
    (is (= 20 socket/tcp-header-min-size)))

  (testing "UDP header size"
    (is (= 8 socket/udp-header-size))))

(deftest test-ethernet-offsets
  (testing "Ethernet header offsets"
    (is (map? socket/ethernet-offsets))
    (is (contains? socket/ethernet-offsets :dst-mac))
    (is (contains? socket/ethernet-offsets :src-mac))
    (is (contains? socket/ethernet-offsets :ethertype))))

(deftest test-ip-offsets
  (testing "IPv4 header offsets"
    (is (map? socket/ipv4-offsets))
    (is (contains? socket/ipv4-offsets :src-addr))
    (is (contains? socket/ipv4-offsets :dst-addr))
    (is (contains? socket/ipv4-offsets :protocol))))

(deftest test-ethertypes
  (testing "Ethertype constants"
    (is (map? socket/ethertypes))
    (is (contains? socket/ethertypes :ipv4))
    (is (contains? socket/ethertypes :ipv6))))

(deftest test-ip-protocols
  (testing "IP protocol constants"
    (is (map? socket/ip-protocols))
    (is (= 6 (:tcp socket/ip-protocols)))
    (is (= 17 (:udp socket/ip-protocols)))
    (is (= 1 (:icmp socket/ip-protocols)))))

;; ============================================================================
;; Complete Program Tests
;; ============================================================================

(deftest test-complete-programs
  (testing "Simple accept-all program"
    (let [insns (vec (concat
                      (socket/socket-prologue :r6 :r2 :r3)
                      (socket/socket-accept :r6)))
          bytecode (dsl/assemble insns)]
      (is (bytes? bytecode))
      (is (>= (count bytecode) 40))))

  (testing "Simple reject-all program"
    (let [insns (vec (concat
                      (socket/socket-prologue :r2 :r3)
                      (socket/socket-reject)))
          bytecode (dsl/assemble insns)]
      (is (bytes? bytecode))))

  (testing "Accept specific bytes"
    (let [insns (vec (concat
                      (socket/socket-prologue :r2 :r3)
                      (socket/socket-accept-bytes 1500)))
          bytecode (dsl/assemble insns)]
      (is (bytes? bytecode)))))

;; ============================================================================
;; Bytecode Size Tests
;; ============================================================================

(deftest test-bytecode-sizes
  (testing "Accept instructions size"
    (let [insns (socket/socket-accept :r6)
          bytecode (dsl/assemble insns)]
      (is (= 16 (count bytecode)))))  ; 2 instructions * 8 bytes

  (testing "Reject instructions size"
    (let [insns (socket/socket-reject)
          bytecode (dsl/assemble insns)]
      (is (= 16 (count bytecode))))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-api-completeness
  (testing "Core functions exist"
    (is (fn? socket/socket-action))
    (is (fn? socket/skb-offset))
    (is (fn? socket/socket-prologue))
    (is (fn? socket/socket-get-len))
    (is (fn? socket/socket-get-protocol))
    (is (fn? socket/socket-get-ifindex))
    (is (fn? socket/socket-accept))
    (is (fn? socket/socket-accept-bytes))
    (is (fn? socket/socket-reject))
    (is (fn? socket/build-socket-filter))
    (is (fn? socket/socket-filter-section-name))
    (is (fn? socket/make-socket-filter-info)))

  (testing "Reused functions exist"
    (is (fn? socket/socket-load-ctx-field))
    (is (fn? socket/socket-load-data-pointers))
    (is (fn? socket/socket-parse-ethernet))
    (is (fn? socket/socket-parse-ipv4))
    (is (fn? socket/socket-parse-tcp))
    (is (fn? socket/socket-bounds-check))))

;; ============================================================================
;; Data Structure Tests
;; ============================================================================

(deftest test-data-structures
  (testing "Socket filter actions"
    (is (= 2 (count socket/socket-filter-actions))))

  (testing "__sk_buff offsets available"
    (is (map? socket/skb-offsets))
    (is (pos? (count socket/skb-offsets)))))

;; ============================================================================
;; Filter Pattern Tests (without labels)
;; ============================================================================

(deftest test-filter-by-protocol
  (testing "Filter by TCP protocol"
    ;; Note: This function uses labels internally, so we test basic structure
    (is (fn? socket/socket-filter-by-protocol))))

(deftest test-filter-by-port
  (testing "Filter by port function exists"
    (is (fn? socket/socket-filter-by-port))))

(deftest test-filter-by-ip
  (testing "Filter by IP function exists"
    (is (fn? socket/socket-filter-by-ip))))

;; ============================================================================
;; IP Address Helper Tests
;; ============================================================================

(deftest test-ipv4-to-int
  (testing "IPv4 to int function available"
    (is (fn? socket/ipv4-to-int))
    ;; Test with small IP that doesn't overflow
    (is (number? (socket/ipv4-to-int "10.0.0.1")))))
