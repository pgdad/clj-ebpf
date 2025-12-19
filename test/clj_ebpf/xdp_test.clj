(ns clj-ebpf.xdp-test
  "Tests for XDP (eXpress Data Path) support"
  (:require [clojure.test :refer :all]
            [clj-ebpf.xdp :as xdp]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.constants :as const]))

(defn linux?
  "Check if we're on Linux"
  []
  (= "Linux" (System/getProperty "os.name")))

;; ============================================================================
;; Network Interface Tests
;; ============================================================================

(deftest test-interface-operations
  (when (linux?)
    (testing "Interface name to index conversion"
      ;; The loopback interface (lo) should always exist on Linux
      (let [ifindex (xdp/interface-name->index "lo")]
        (is (pos? ifindex))
        (is (integer? ifindex))
        (println "Loopback interface index:" ifindex)

        ;; Test reverse conversion
        (let [ifname (xdp/interface-index->name ifindex)]
          (is (= "lo" ifname)))))

    (testing "Non-existent interface should throw"
      (is (thrown? Exception
                  (xdp/interface-name->index "nonexistent_interface_xyz"))))))

;; ============================================================================
;; XDP Constants Tests
;; ============================================================================

(deftest test-xdp-action-constants
  (testing "XDP action codes exist"
    (is (= 0 (:aborted const/xdp-action)))
    (is (= 1 (:drop const/xdp-action)))
    (is (= 2 (:pass const/xdp-action)))
    (is (= 3 (:tx const/xdp-action)))
    (is (= 4 (:redirect const/xdp-action)))))

(deftest test-xdp-flags-constants
  (testing "XDP flags exist"
    (is (= 1 (:update-if-noexist const/xdp-flags)))
    (is (= 2 (:skb-mode const/xdp-flags)))
    (is (= 4 (:drv-mode const/xdp-flags)))
    (is (= 8 (:hw-mode const/xdp-flags)))
    (is (= 16 (:replace const/xdp-flags)))))

;; ============================================================================
;; XDP Attachment Tests (require root privileges)
;; ============================================================================

(defn has-cap-net-admin?
  "Check if process has CAP_NET_ADMIN capability (needed for XDP)"
  []
  (try
    (let [status (slurp "/proc/self/status")
          cap-eff-line (first (filter #(clojure.string/starts-with? % "CapEff:")
                                    (clojure.string/split-lines status)))
          cap-hex (clojure.string/trim (subs cap-eff-line 7))
          cap-val (Long/parseLong cap-hex 16)
          ;; CAP_NET_ADMIN is bit 12
          cap-net-admin-bit 12]
      (not= 0 (bit-and cap-val (bit-shift-left 1 cap-net-admin-bit))))
    (catch Exception _ false)))

(deftest test-simple-xdp-program
  (when (and (linux?)
             (has-cap-net-admin?)
             (try (utils/check-bpf-available) true (catch Exception _ false)))
    (testing "Create simple XDP program that passes all packets"
      ;; Simple XDP program: return XDP_PASS (2)
      ;; BPF instructions:
      ;;   mov r0, 2    ; XDP_PASS
      ;;   exit
      (let [bytecode [[(bit-or 0xb7 0) 2 0 0]  ; mov r0, 2
                      [(bit-or 0x95 0) 0 0 0]]] ; exit
        ;; Note: Full test would require actual XDP attachment
        ;; For now, just verify the program can be constructed
        (is (seq bytecode))))))

;; ============================================================================
;; Netlink Message Construction Tests (CI-safe, no privileges needed)
;; ============================================================================

(deftest test-nla-align
  (testing "NLA alignment to 4-byte boundary"
    (is (= 0 (#'xdp/nla-align 0)))
    (is (= 4 (#'xdp/nla-align 1)))
    (is (= 4 (#'xdp/nla-align 2)))
    (is (= 4 (#'xdp/nla-align 3)))
    (is (= 4 (#'xdp/nla-align 4)))
    (is (= 8 (#'xdp/nla-align 5)))
    (is (= 8 (#'xdp/nla-align 8)))
    (is (= 12 (#'xdp/nla-align 9)))))

(deftest test-build-nla
  (testing "Build NLA with 4-byte payload (already aligned)"
    (let [data [0x01 0x02 0x03 0x04]
          result (vec (#'xdp/build-nla 1 data))]
      ;; Header (4 bytes) + data (4 bytes) = 8 bytes
      (is (= 8 (count result)))
      ;; nla_len should be 8 (includes header)
      (is (= 8 (bit-or (bit-and (nth result 0) 0xFF)
                       (bit-shift-left (bit-and (nth result 1) 0xFF) 8))))
      ;; nla_type should be 1
      (is (= 1 (bit-or (bit-and (nth result 2) 0xFF)
                       (bit-shift-left (bit-and (nth result 3) 0xFF) 8))))))

  (testing "Build NLA with padding"
    (let [data [0x01 0x02 0x03]
          result (vec (#'xdp/build-nla 2 data))]
      ;; Header (4) + data (3) + padding (1) = 8 bytes
      (is (= 8 (count result)))
      ;; nla_len should be 7 (header + data, NOT padding)
      (is (= 7 (bit-or (bit-and (nth result 0) 0xFF)
                       (bit-shift-left (bit-and (nth result 1) 0xFF) 8))))))

  (testing "Build NLA with NLA_F_NESTED flag"
    (let [nla-f-nested 0x8000
          nla-type (bit-or 43 nla-f-nested)  ; IFLA_XDP with nested flag
          data [0x01 0x02 0x03 0x04]
          result (vec (#'xdp/build-nla nla-type data))]
      ;; nla_type should have nested flag set
      (let [type-val (bit-or (bit-and (nth result 2) 0xFF)
                             (bit-shift-left (bit-and (nth result 3) 0xFF) 8))]
        (is (not= 0 (bit-and type-val nla-f-nested)))
        (is (= 43 (bit-and type-val 0x7FFF)))))))

(deftest test-build-netlink-msg
  (testing "Build XDP netlink message structure"
    (let [msg (#'xdp/build-netlink-msg 1 5 4)]  ; ifindex=1, prog-fd=5, flags=4 (drv-mode)
      (is (instance? (Class/forName "[B") msg))
      ;; Message structure:
      ;; - nlmsghdr: 16 bytes
      ;; - ifinfomsg: 16 bytes
      ;; - IFLA_XDP (nested): 4 + (IFLA_XDP_FD: 8) + (IFLA_XDP_FLAGS: 8) = 20 bytes
      ;; Total: at least 52 bytes
      (is (>= (count msg) 52))))

  (testing "XDP message includes NLA_F_NESTED flag for IFLA_XDP"
    (let [msg (#'xdp/build-netlink-msg 1 5 4)
          ;; Skip nlmsghdr (16) + ifinfomsg (16) = 32 bytes to find IFLA_XDP
          ifla-xdp-start 32
          nla-type-lo (aget msg (+ ifla-xdp-start 2))
          nla-type-hi (aget msg (+ ifla-xdp-start 3))
          nla-type (bit-or (bit-and nla-type-lo 0xFF)
                          (bit-shift-left (bit-and nla-type-hi 0xFF) 8))
          nla-f-nested 0x8000
          ifla-xdp 43]
      ;; Verify IFLA_XDP with NLA_F_NESTED flag
      (is (not= 0 (bit-and nla-type nla-f-nested)) "NLA_F_NESTED flag should be set")
      (is (= ifla-xdp (bit-and nla-type 0x7FFF)) "IFLA_XDP type should be 43")))

  (testing "XDP message handles detachment (prog-fd = -1)"
    (let [msg (#'xdp/build-netlink-msg 1 -1 4)]  ; -1 for detach
      (is (instance? (Class/forName "[B") msg))
      (is (> (count msg) 0)))))

;; Note: Actual XDP attachment/detachment tests require:
;; 1. Root privileges (CAP_NET_ADMIN)
;; 2. A test network interface (can't use lo for XDP)
;; 3. Driver support for XDP
;;
;; These tests would be:
;; - Load XDP program
;; - Attach to test interface
;; - Verify attachment
;; - Detach program
;; - Verify detachment
;;
;; Example test (commented out - requires root):
#_
(deftest test-xdp-attach-detach
  (when (and (linux?)
             (has-cap-net-admin?))
    (testing "Attach and detach XDP program"
      ;; Create simple XDP program
      (let [bytecode ...
            prog-fd (xdp/load-xdp-program bytecode :prog-name "test_xdp")]
        (try
          ;; Attach to test interface in SKB mode (works without driver support)
          (xdp/attach-xdp "eth0" prog-fd :skb-mode)

          ;; Verify program is attached
          ;; ...

          ;; Detach program
          (xdp/detach-xdp "eth0" :skb-mode)

          (finally
            (syscall/close-fd prog-fd)))))))
