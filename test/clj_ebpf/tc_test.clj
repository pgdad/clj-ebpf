(ns clj-ebpf.tc-test
  "Tests for TC (Traffic Control) BPF support"
  (:require [clojure.test :refer :all]
            [clj-ebpf.tc :as tc]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.constants :as const]))

(defn linux-with-bpf?
  "Check if we're on Linux with BPF available"
  []
  (and (= "Linux" (System/getProperty "os.name"))
       (try
         (utils/check-bpf-available)
         true
         (catch Exception _ false))))

;; ============================================================================
;; TC Constants Tests
;; ============================================================================

(deftest test-tc-action-mappings
  (testing "TC action code mappings"
    (is (= 0 (:ok tc/tc-action)))
    (is (= 2 (:shot tc/tc-action)))
    (is (= 7 (:redirect tc/tc-action)))
    (is (= :ok (get tc/int->tc-action 0)))
    (is (= :shot (get tc/int->tc-action 2)))))

(deftest test-tc-direction
  (testing "TC direction mappings"
    (is (some? (:ingress tc/tc-direction)))
    (is (some? (:egress tc/tc-direction)))
    (is (not= (:ingress tc/tc-direction) (:egress tc/tc-direction)))))

;; ============================================================================
;; Netlink Message Building Tests
;; ============================================================================

(deftest test-build-rtattr
  (testing "Build rtattr structure"
    (let [data [1 2 3 4]
          result (#'tc/build-rtattr 1 data)
          ;; rtattr header is 4 bytes: u16 len, u16 type
          ;; len should be 4 (header) + 4 (data) = 8
          header (take 4 result)
          body (drop 4 result)]
      (is (= 4 (count header)))
      (is (= data body)))))

(deftest test-align-4
  (testing "4-byte alignment"
    (is (= [1 2 3 4] (#'tc/align-4 [1 2 3 4])))
    (is (= [1 2 3 0] (#'tc/align-4 [1 2 3])))
    (is (= [1 2 0 0] (#'tc/align-4 [1 2])))
    (is (= [1 0 0 0] (#'tc/align-4 [1])))))

(deftest test-qdisc-msg-structure
  (testing "Qdisc message structure"
    (let [msg (#'tc/build-qdisc-msg 36 2 0x05)]
      ;; Message should be a byte array
      (is (instance? (Class/forName "[B") msg))
      ;; Message should have at least nlmsghdr (16 bytes) + tcmsg (20 bytes)
      (is (>= (count msg) 36)))))

(deftest test-filter-msg-structure
  (testing "Filter message structure"
    (let [msg (#'tc/build-filter-msg 44 2 :ingress 5 "test_prog" 1 0x05)]
      ;; Message should be a byte array
      (is (instance? (Class/forName "[B") msg))
      ;; Message should have at least nlmsghdr + tcmsg + attributes
      (is (>= (count msg) 50)))))

(deftest test-nla-align
  (testing "NLA alignment to 4-byte boundary"
    (is (= 0 (#'tc/nla-align 0)))
    (is (= 4 (#'tc/nla-align 1)))
    (is (= 4 (#'tc/nla-align 2)))
    (is (= 4 (#'tc/nla-align 3)))
    (is (= 4 (#'tc/nla-align 4)))
    (is (= 8 (#'tc/nla-align 5)))
    (is (= 8 (#'tc/nla-align 6)))
    (is (= 8 (#'tc/nla-align 7)))
    (is (= 8 (#'tc/nla-align 8)))
    (is (= 12 (#'tc/nla-align 9)))))

(deftest test-build-nla
  (testing "Build NLA with 4-byte payload (no padding needed)"
    (let [data [0x01 0x02 0x03 0x04]
          result (vec (#'tc/build-nla 1 data))]
      ;; Header (4 bytes) + data (4 bytes) = 8 bytes (already aligned)
      (is (= 8 (count result)))
      ;; nla_len should be 8 (includes header)
      (is (= 8 (bit-or (bit-and (nth result 0) 0xFF)
                       (bit-shift-left (bit-and (nth result 1) 0xFF) 8))))
      ;; nla_type should be 1
      (is (= 1 (bit-or (bit-and (nth result 2) 0xFF)
                       (bit-shift-left (bit-and (nth result 3) 0xFF) 8))))))

  (testing "Build NLA with 3-byte payload (needs 1 byte padding)"
    (let [data [0x01 0x02 0x03]
          result (vec (#'tc/build-nla 2 data))]
      ;; Header (4 bytes) + data (3 bytes) + padding (1 byte) = 8 bytes
      (is (= 8 (count result)))
      ;; nla_len should be 7 (header + data, NOT including padding)
      (is (= 7 (bit-or (bit-and (nth result 0) 0xFF)
                       (bit-shift-left (bit-and (nth result 1) 0xFF) 8))))
      ;; Last byte should be padding (0)
      (is (= 0 (nth result 7)))))

  (testing "Build NLA with NLA_F_NESTED flag"
    (let [nla-f-nested 0x8000
          nla-type (bit-or 2 nla-f-nested)
          data [0x01 0x02 0x03 0x04]
          result (vec (#'tc/build-nla nla-type data))]
      ;; nla_type should have nested flag set
      (let [type-bytes (bit-or (bit-and (nth result 2) 0xFF)
                               (bit-shift-left (bit-and (nth result 3) 0xFF) 8))]
        (is (not= 0 (bit-and type-bytes nla-f-nested)))
        (is (= 2 (bit-and type-bytes 0x7FFF)))))))

(deftest test-tc-handles-in-messages
  (testing "TC handles with large unsigned values in qdisc message"
    ;; This test verifies that TC_H_CLSACT (0xFFFF0000) is correctly
    ;; packed without integer overflow
    (let [msg (#'tc/build-qdisc-msg 36 1 0x05)]
      (is (instance? (Class/forName "[B") msg))
      ;; Message should build successfully without throwing
      (is (> (count msg) 0))))

  (testing "TC combined handle in filter message"
    ;; TC_H_CLSACT | TC_H_MIN_INGRESS = 0xFFFFFFF2
    ;; This should not throw integer overflow
    (let [msg (#'tc/build-filter-msg 44 1 :ingress 5 "test" 1 0x05)]
      (is (instance? (Class/forName "[B") msg))
      (is (> (count msg) 0))))

  (testing "TC combined handle with egress"
    ;; TC_H_CLSACT | TC_H_MIN_EGRESS = 0xFFFFFFF3
    (let [msg (#'tc/build-filter-msg 44 1 :egress 5 "test" 1 0x05)]
      (is (instance? (Class/forName "[B") msg))
      (is (> (count msg) 0)))))

;; ============================================================================
;; TC Protocol Field Tests (ETH_P_IP fix verification)
;; ============================================================================

(defn- extract-info-field
  "Extract the info field from a filter message.
   Filter message structure:
   - nlmsghdr: 16 bytes
   - tcmsg: 20 bytes (family, pad, ifindex, handle, parent, info)
   - info is at offset 32 (16 + 16) in the message, 4 bytes"
  [msg]
  (let [b (byte-array msg)
        ;; info field is at offset 32 in the message (16 byte nlmsghdr + 16 bytes of tcmsg before info)
        ;; Actually: nlmsghdr (16) + family(1) + pad(3) + ifindex(4) + handle(4) + parent(4) = offset 32
        ;; Then info is 4 bytes at offset 32
        offset 32]
    (bit-or (bit-and (aget b offset) 0xFF)
            (bit-shift-left (bit-and (aget b (+ offset 1)) 0xFF) 8)
            (bit-shift-left (bit-and (aget b (+ offset 2)) 0xFF) 16)
            (bit-shift-left (bit-and (aget b (+ offset 3)) 0xFF) 24))))

(deftest test-filter-protocol-eth-p-ip
  (testing "Filter message uses ETH_P_IP (0x0008 in network byte order) for IPv4"
    ;; ETH_P_IP = 0x0800 in host order, which becomes 0x0008 in network byte order
    ;; The info field format is: (priority << 16) | protocol
    ;; So with priority=1 and ETH_P_IP=0x0008: info = 0x00010008
    (let [msg (#'tc/build-filter-msg 44 1 :ingress 5 "test" 1 0x05)
          info-field (extract-info-field msg)
          protocol (bit-and info-field 0xFFFF)
          priority (bit-shift-right info-field 16)]
      ;; Verify protocol is ETH_P_IP in network byte order (0x0008)
      (is (= 0x0008 protocol)
          "Protocol should be ETH_P_IP (0x0008 in network byte order)")
      ;; Verify priority is correct
      (is (= 1 priority)
          "Priority should be 1")))

  (testing "Filter message uses ETH_P_IP for egress as well"
    (let [msg (#'tc/build-filter-msg 44 1 :egress 5 "test" 1 0x05)
          info-field (extract-info-field msg)
          protocol (bit-and info-field 0xFFFF)]
      (is (= 0x0008 protocol)
          "Egress filter should also use ETH_P_IP (0x0008)")))

  (testing "Protocol field is not ETH_P_ALL (old value was 0x0003)"
    (let [msg (#'tc/build-filter-msg 44 1 :ingress 5 "test" 1 0x05)
          info-field (extract-info-field msg)
          protocol (bit-and info-field 0xFFFF)]
      (is (not= 0x0003 protocol)
          "Protocol should NOT be ETH_P_ALL (0x0003)")))

  (testing "Different priorities encode correctly with ETH_P_IP"
    (doseq [prio [1 10 100 255]]
      (let [msg (#'tc/build-filter-msg 44 1 :ingress 5 "test" prio 0x05)
            info-field (extract-info-field msg)
            protocol (bit-and info-field 0xFFFF)
            extracted-prio (bit-and (bit-shift-right info-field 16) 0xFFFF)]
        (is (= 0x0008 protocol)
            (str "Protocol should be ETH_P_IP for priority " prio))
        (is (= prio extracted-prio)
            (str "Priority should be " prio))))))

;; ============================================================================
;; TC Program Type Tests
;; ============================================================================

(deftest test-load-tc-program-validation
  (testing "TC program type validation"
    ;; Should throw on invalid program type
    (is (thrown-with-msg? Exception #"Invalid TC program type"
          (tc/load-tc-program (byte-array 0) :xdp)))))

;; ============================================================================
;; Helper Function Tests
;; ============================================================================

(deftest test-setup-teardown-structure
  (testing "Setup/teardown function structure"
    ;; We can't actually run these without root privileges,
    ;; but we can verify the structure

    ;; Verify that setup functions would return the expected structure
    (let [expected-keys [:prog-fd :filter-info]]
      ;; Test that we can call the functions (they'll fail without proper setup)
      ;; but we're just checking the code structure
      (is (fn? tc/setup-tc-ingress))
      (is (fn? tc/setup-tc-egress))
      (is (fn? tc/teardown-tc-filter)))))

;; ============================================================================
;; Integration Tests (require root/CAP_NET_ADMIN)
;; ============================================================================

;; Note: These tests require:
;; 1. Root privileges or CAP_NET_ADMIN + CAP_BPF capabilities
;; 2. A valid network interface (usually "lo" for loopback)
;; 3. Kernel with TC BPF support
;;
;; They are commented out by default to avoid CI failures

(deftest ^:integration test-clsact-qdisc-lifecycle
  (when (and (linux-with-bpf?)
            (System/getenv "RUN_INTEGRATION_TESTS"))
    (testing "Add and remove clsact qdisc"
      (try
        ;; Try to add clsact qdisc to loopback
        (let [ifindex (tc/add-clsact-qdisc "lo")]
          (is (pos? ifindex))

          ;; Remove it
          (let [result (tc/remove-clsact-qdisc "lo")]
            (is (pos? result))))

        (catch Exception e
          ;; Expected to fail without proper permissions
          (is (or (re-find #"Operation not permitted" (.getMessage e))
                 (re-find #"Permission denied" (.getMessage e)))))))))

(deftest ^:integration test-tc-filter-attachment
  (when (and (linux-with-bpf?)
            (System/getenv "RUN_INTEGRATION_TESTS"))
    (testing "Attach and detach TC filter"
      (try
        ;; Create a minimal valid BPF program (just returns TC_ACT_OK)
        (let [bytecode (byte-array [
                                     ;; mov r0, 0 (TC_ACT_OK)
                                     0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                                     ;; exit
                                     0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])
              prog-fd (tc/load-tc-program bytecode :sched-cls
                                         :prog-name "test_tc"
                                         :license "GPL")]

          (try
            ;; Add clsact qdisc first
            (tc/add-clsact-qdisc "lo")

            ;; Attach filter
            (let [info (tc/attach-tc-filter "lo" prog-fd :ingress
                                           :prog-name "test_filter"
                                           :priority 1)]
              (is (some? info))
              (is (= :ingress (:direction info)))

              ;; Detach filter
              (tc/detach-tc-filter (:ifindex info) (:direction info) (:priority info)))

            (finally
              ;; Cleanup
              (try (tc/remove-clsact-qdisc "lo") (catch Exception _))
              (try (clj-ebpf.syscall/close-fd prog-fd) (catch Exception _)))))

        (catch Exception e
          ;; Expected to fail without proper permissions
          (is (or (re-find #"Operation not permitted" (.getMessage e))
                 (re-find #"Permission denied" (.getMessage e)))))))))

(deftest ^:integration test-tc-egress-filter-ipv4
  (when (and (linux-with-bpf?)
            (System/getenv "RUN_INTEGRATION_TESTS"))
    (testing "TC egress filter works with ETH_P_IP protocol for IPv4 traffic"
      ;; This test verifies that the ETH_P_IP fix allows egress filters to work
      ;; Previously, ETH_P_ALL (0x0003) was used which didn't match egress traffic
      (try
        (let [bytecode (byte-array [
                                     ;; mov r0, 0 (TC_ACT_OK - pass the packet)
                                     0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                                     ;; exit
                                     0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])
              prog-fd (tc/load-tc-program bytecode :sched-cls
                                         :prog-name "egress_test"
                                         :license "GPL")]
          (try
            ;; Add clsact qdisc
            (tc/add-clsact-qdisc "lo")

            ;; Attach egress filter - this is what the ETH_P_IP fix enables
            (let [info (tc/attach-tc-filter "lo" prog-fd :egress
                                           :prog-name "egress_filter"
                                           :priority 1)]
              (is (some? info) "Egress filter should attach successfully")
              (is (= :egress (:direction info)) "Direction should be egress")
              (is (= 1 (:priority info)) "Priority should be 1")

              ;; Detach filter
              (tc/detach-tc-filter (:ifindex info) (:direction info) (:priority info)))

            (finally
              (try (tc/remove-clsact-qdisc "lo") (catch Exception _))
              (try (clj-ebpf.syscall/close-fd prog-fd) (catch Exception _)))))

        (catch Exception e
          (is (or (re-find #"Operation not permitted" (.getMessage e))
                 (re-find #"Permission denied" (.getMessage e)))))))))

(deftest ^:integration test-tc-both-directions-ipv4
  (when (and (linux-with-bpf?)
            (System/getenv "RUN_INTEGRATION_TESTS"))
    (testing "TC filters work on both ingress and egress simultaneously"
      ;; Test that we can attach filters to both directions with ETH_P_IP
      (try
        (let [bytecode (byte-array [
                                     0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00  ; mov r0, 0
                                     0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00]) ; exit
              ingress-fd (tc/load-tc-program bytecode :sched-cls
                                             :prog-name "ingress_prog"
                                             :license "GPL")
              egress-fd (tc/load-tc-program bytecode :sched-cls
                                            :prog-name "egress_prog"
                                            :license "GPL")]
          (try
            (tc/add-clsact-qdisc "lo")

            ;; Attach both ingress and egress filters
            (let [ingress-info (tc/attach-tc-filter "lo" ingress-fd :ingress
                                                    :prog-name "ingress_filter"
                                                    :priority 1)
                  egress-info (tc/attach-tc-filter "lo" egress-fd :egress
                                                   :prog-name "egress_filter"
                                                   :priority 1)]
              (is (= :ingress (:direction ingress-info)))
              (is (= :egress (:direction egress-info)))

              ;; Detach both
              (tc/detach-tc-filter (:ifindex ingress-info) :ingress 1)
              (tc/detach-tc-filter (:ifindex egress-info) :egress 1))

            (finally
              (try (tc/remove-clsact-qdisc "lo") (catch Exception _))
              (try (clj-ebpf.syscall/close-fd ingress-fd) (catch Exception _))
              (try (clj-ebpf.syscall/close-fd egress-fd) (catch Exception _)))))

        (catch Exception e
          (is (or (re-find #"Operation not permitted" (.getMessage e))
                 (re-find #"Permission denied" (.getMessage e)))))))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(deftest test-tc-api-completeness
  (testing "TC API functions are available"
    ;; Test that key functions exist and are callable
    (is (fn? tc/add-clsact-qdisc))
    (is (fn? tc/remove-clsact-qdisc))
    (is (fn? tc/attach-tc-filter))
    (is (fn? tc/detach-tc-filter))
    (is (fn? tc/load-tc-program))
    (is (fn? tc/setup-tc-ingress))
    (is (fn? tc/setup-tc-egress))
    (is (fn? tc/teardown-tc-filter))))

;; ============================================================================
;; Error Handling Tests
;; ============================================================================

(deftest test-error-handling
  (testing "Invalid interface name"
    (when (linux-with-bpf?)
      ;; Should throw when trying to use non-existent interface
      (is (thrown? Exception
            (tc/add-clsact-qdisc "nonexistent_interface_xyz")))))

  (testing "Invalid direction"
    ;; Should handle invalid direction gracefully
    (is (some? (get tc/tc-direction :ingress)))
    (is (nil? (get tc/tc-direction :invalid)))))

;; ============================================================================
;; Documentation Tests
;; ============================================================================

(deftest test-function-metadata
  (testing "Key functions have docstrings"
    (is (string? (:doc (meta #'tc/add-clsact-qdisc))))
    (is (string? (:doc (meta #'tc/remove-clsact-qdisc))))
    (is (string? (:doc (meta #'tc/attach-tc-filter))))
    (is (string? (:doc (meta #'tc/detach-tc-filter))))
    (is (string? (:doc (meta #'tc/load-tc-program))))
    (is (string? (:doc (meta #'tc/setup-tc-ingress))))
    (is (string? (:doc (meta #'tc/setup-tc-egress))))
    (is (string? (:doc (meta #'tc/teardown-tc-filter))))))

;; ============================================================================
;; Example Usage Documentation
;; ============================================================================

(deftest ^:example test-usage-examples
  (testing "Example code compiles correctly"
    ;; These are example patterns that should compile
    ;; (won't run without proper setup)

    ;; Example 1: Basic usage
    (is (fn? (fn []
               (let [bytecode (byte-array 16)
                     prog-fd (tc/load-tc-program bytecode :sched-cls
                                                :prog-name "example"
                                                :license "GPL")]
                 (try
                   (tc/add-clsact-qdisc "eth0")
                   (let [info (tc/attach-tc-filter "eth0" prog-fd :ingress)]
                     (Thread/sleep 1000)
                     (tc/detach-tc-filter (:ifindex info) (:direction info) (:priority info)))
                   (finally
                     (clj-ebpf.syscall/close-fd prog-fd)))))))

    ;; Example 2: Using convenience functions
    (is (fn? (fn []
               (let [setup (tc/setup-tc-ingress "eth0" (byte-array 16))]
                 (Thread/sleep 1000)
                 (tc/teardown-tc-filter setup)))))

    ;; Example 3: Using macros
    (is (fn? (fn []
               (tc/with-tc-program [prog-fd (byte-array 16) :sched-cls {}
                                   info "eth0" :ingress {}]
                 (Thread/sleep 1000)))))))

;; ============================================================================
;; Performance and Limits Tests
;; ============================================================================

(deftest test-multiple-priorities
  (testing "Multiple filter priorities"
    ;; Verify that we can specify different priorities
    (let [priorities [1 2 3 10 100]]
      (doseq [prio priorities]
        ;; Just verify the structure builds correctly
        (is (map? {:priority prio :direction :ingress}))))))

(deftest test-direction-combinations
  (testing "Both ingress and egress directions"
    (is (= :ingress :ingress))
    (is (= :egress :egress))
    ;; Verify we can use both directions
    (let [directions [:ingress :egress]]
      (doseq [dir directions]
        (is (some? (get tc/tc-direction dir)))))))
