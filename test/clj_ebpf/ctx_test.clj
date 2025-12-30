(ns clj-ebpf.ctx-test
  "Tests for BPF context structure offsets - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.ctx :as ctx]))

;; ============================================================================
;; bpf_sock_ops Tests
;; ============================================================================

(deftest test-bpf-sock-ops-offsets
  (testing "bpf_sock_ops field offsets"
    ;; Core fields
    (is (= 0 (:op ctx/bpf-sock-ops)))
    (is (= 4 (:args ctx/bpf-sock-ops)))
    (is (= 4 (:reply ctx/bpf-sock-ops)))  ; Union with args
    (is (= 20 (:family ctx/bpf-sock-ops)))

    ;; IP address fields
    (is (= 24 (:remote-ip4 ctx/bpf-sock-ops)))
    (is (= 28 (:local-ip4 ctx/bpf-sock-ops)))
    (is (= 32 (:remote-ip6 ctx/bpf-sock-ops)))
    (is (= 48 (:local-ip6 ctx/bpf-sock-ops)))

    ;; Port fields (important byte order notes)
    (is (= 64 (:remote-port ctx/bpf-sock-ops)))  ; network byte order
    (is (= 68 (:local-port ctx/bpf-sock-ops)))   ; HOST byte order!

    ;; TCP state fields
    (is (= 72 (:is-fullsock ctx/bpf-sock-ops)))
    (is (= 76 (:snd-cwnd ctx/bpf-sock-ops)))
    (is (= 80 (:srtt-us ctx/bpf-sock-ops)))
    (is (= 88 (:state ctx/bpf-sock-ops)))

    ;; Stats fields
    (is (= 168 (:bytes-received ctx/bpf-sock-ops)))
    (is (= 176 (:bytes-acked ctx/bpf-sock-ops)))
    (is (= 184 (:sk ctx/bpf-sock-ops))))

  (testing "sock-ops-offset helper"
    (is (= 0 (ctx/sock-ops-offset :op)))
    (is (= 68 (ctx/sock-ops-offset :local-port)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (ctx/sock-ops-offset :invalid-field)))))

(deftest test-sock-ops-op-codes
  (testing "SOCK_OPS operation codes"
    (is (= 0 (:void ctx/sock-ops-op)))
    (is (= 4 (:active-established-cb ctx/sock-ops-op)))
    (is (= 5 (:passive-established-cb ctx/sock-ops-op)))
    (is (= 10 (:state-cb ctx/sock-ops-op)))))

;; ============================================================================
;; bpf_sock Tests
;; ============================================================================

(deftest test-bpf-sock-offsets
  (testing "bpf_sock field offsets"
    (is (= 0 (:bound-dev-if ctx/bpf-sock)))
    (is (= 4 (:family ctx/bpf-sock)))
    (is (= 8 (:type ctx/bpf-sock)))
    (is (= 12 (:protocol ctx/bpf-sock)))
    (is (= 16 (:mark ctx/bpf-sock)))
    (is (= 20 (:priority ctx/bpf-sock)))

    ;; Source fields
    (is (= 24 (:src-ip4 ctx/bpf-sock)))   ; network byte order
    (is (= 28 (:src-ip6 ctx/bpf-sock)))   ; network byte order
    (is (= 44 (:src-port ctx/bpf-sock)))  ; HOST byte order!

    ;; Destination fields
    (is (= 48 (:dst-port ctx/bpf-sock)))  ; network byte order
    (is (= 52 (:dst-ip4 ctx/bpf-sock)))   ; network byte order
    (is (= 56 (:dst-ip6 ctx/bpf-sock)))   ; network byte order

    (is (= 72 (:state ctx/bpf-sock)))
    (is (= 76 (:rx-queue-mapping ctx/bpf-sock))))

  (testing "sock-offset helper"
    (is (= 4 (ctx/sock-offset :family)))
    (is (= 44 (ctx/sock-offset :src-port)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (ctx/sock-offset :invalid-field)))))

;; ============================================================================
;; Re-exported Structure Tests
;; ============================================================================

(deftest test-sk-buff-offsets
  (testing "__sk_buff field offsets (re-exported from tc)"
    (is (= 0 (:len ctx/sk-buff)))
    (is (= 8 (:mark ctx/sk-buff)))
    (is (= 76 (:data ctx/sk-buff)))
    (is (= 80 (:data-end ctx/sk-buff)))
    (is (= 132 (:remote-port ctx/sk-buff)))
    (is (= 136 (:local-port ctx/sk-buff)))))

(deftest test-xdp-md-offsets
  (testing "xdp_md field offsets (re-exported from xdp)"
    (is (= 0 (:data ctx/xdp-md)))
    (is (= 4 (:data-end ctx/xdp-md)))
    (is (= 8 (:data-meta ctx/xdp-md)))
    (is (= 12 (:ingress-ifindex ctx/xdp-md)))
    (is (= 16 (:rx-queue-index ctx/xdp-md)))))

(deftest test-sk-msg-offsets
  (testing "sk_msg_md field offsets (re-exported from socket)"
    (is (= 0 (:data ctx/sk-msg)))
    (is (= 8 (:data-end ctx/sk-msg)))
    (is (= 16 (:family ctx/sk-msg)))
    (is (= 60 (:remote-port ctx/sk-msg)))
    (is (= 64 (:local-port ctx/sk-msg)))))

(deftest test-bpf-sk-lookup-offsets
  (testing "bpf_sk_lookup field offsets (re-exported from sk-lookup)"
    (is (= 0 (:sk ctx/bpf-sk-lookup)))
    (is (= 8 (:family ctx/bpf-sk-lookup)))
    (is (= 12 (:protocol ctx/bpf-sk-lookup)))
    (is (= 60 (:local-port ctx/bpf-sk-lookup)))))

;; ============================================================================
;; Protocol Header Offset Tests
;; ============================================================================

(deftest test-protocol-header-offsets
  (testing "Ethernet header offsets"
    (is (= 0 (:dst-mac ctx/ethernet-offsets)))
    (is (= 6 (:src-mac ctx/ethernet-offsets)))
    (is (= 12 (:ethertype ctx/ethernet-offsets))))

  (testing "IPv4 header offsets"
    (is (= 0 (:version-ihl ctx/ipv4-offsets)))
    (is (= 9 (:protocol ctx/ipv4-offsets)))
    (is (= 12 (:src-addr ctx/ipv4-offsets)))
    (is (= 16 (:dst-addr ctx/ipv4-offsets))))

  (testing "TCP header offsets"
    (is (= 0 (:src-port ctx/tcp-offsets)))
    (is (= 2 (:dst-port ctx/tcp-offsets)))
    (is (= 13 (:flags ctx/tcp-offsets))))

  (testing "UDP header offsets"
    (is (= 0 (:src-port ctx/udp-offsets)))
    (is (= 2 (:dst-port ctx/udp-offsets)))
    (is (= 4 (:length ctx/udp-offsets)))))

;; ============================================================================
;; Header Size Constants Tests
;; ============================================================================

(deftest test-header-sizes
  (testing "Header size constants"
    (is (= 14 ctx/ethernet-header-size))
    (is (= 20 ctx/ipv4-header-min-size))
    (is (= 40 ctx/ipv6-header-size))
    (is (= 20 ctx/tcp-header-min-size))
    (is (= 8 ctx/udp-header-size))))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-address-family-constants
  (testing "Address family constants"
    (is (= 2 (:inet ctx/address-family)))
    (is (= 10 (:inet6 ctx/address-family)))
    (is (= 1 (:unix ctx/address-family)))))

(deftest test-socket-type-constants
  (testing "Socket type constants"
    (is (= 1 (:stream ctx/socket-type)))
    (is (= 2 (:dgram ctx/socket-type)))
    (is (= 3 (:raw ctx/socket-type)))))

(deftest test-ip-protocol-constants
  (testing "IP protocol constants"
    (is (= 6 (:tcp ctx/ip-protocol)))
    (is (= 17 (:udp ctx/ip-protocol)))
    (is (= 1 (:icmp ctx/ip-protocol)))))

;; ============================================================================
;; Structure Completeness Tests
;; ============================================================================

(deftest test-structure-completeness
  (testing "bpf-sock-ops has expected field count"
    (is (>= (count ctx/bpf-sock-ops) 30)))

  (testing "bpf-sock has expected field count"
    (is (>= (count ctx/bpf-sock) 12)))

  (testing "All offset values are non-negative integers"
    (is (every? #(and (integer? %) (>= % 0))
                (vals ctx/bpf-sock-ops)))
    (is (every? #(and (integer? %) (>= % 0))
                (vals ctx/bpf-sock)))
    (is (every? #(and (integer? %) (>= % 0))
                (vals ctx/sk-buff)))
    (is (every? #(and (integer? %) (>= % 0))
                (vals ctx/xdp-md)))))
