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
