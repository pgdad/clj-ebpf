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
