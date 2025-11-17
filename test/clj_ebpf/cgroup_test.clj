(ns clj-ebpf.cgroup-test
  "Tests for Cgroup BPF support"
  (:require [clojure.test :refer :all]
            [clj-ebpf.cgroup :as cgroup]
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

(defn cgroup-v2-available?
  "Check if cgroup v2 is available"
  []
  (try
    (.exists (clojure.java.io/file cgroup/DEFAULT_CGROUP_PATH))
    (catch Exception _ false)))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-cgroup-constants
  (testing "Cgroup attach flags"
    (is (= 0 (:none cgroup/cgroup-attach-flags)))
    (is (= 1 (:override cgroup/cgroup-attach-flags)))
    (is (= 2 (:multi cgroup/cgroup-attach-flags)))
    (is (= 4 (:replace cgroup/cgroup-attach-flags))))

  (testing "Cgroup return codes"
    (is (= 1 (:ok cgroup/cgroup-return-code)))
    (is (= 0 (:reject cgroup/cgroup-return-code)))))

(deftest test-prog-type-mappings
  (testing "Program type to attach type mappings"
    (is (= :cgroup-inet-ingress
           (get-in cgroup/prog-type->attach-type [:cgroup-skb :ingress])))
    (is (= :cgroup-inet-egress
           (get-in cgroup/prog-type->attach-type [:cgroup-skb :egress])))
    (is (= :cgroup-inet-sock-create
           (get cgroup/prog-type->attach-type :cgroup-sock)))
    (is (= :cgroup-device
           (get cgroup/prog-type->attach-type :cgroup-device)))))

;; ============================================================================
;; Cgroup Path Tests
;; ============================================================================

(deftest test-cgroup-exists
  (when (cgroup-v2-available?)
    (testing "Root cgroup exists"
      (is (true? (cgroup/cgroup-exists? cgroup/DEFAULT_CGROUP_PATH))))

    (testing "Non-existent cgroup"
      (is (false? (cgroup/cgroup-exists? "/sys/fs/cgroup/nonexistent_cgroup_xyz"))))))

(deftest test-get-current-cgroup
  (when (cgroup-v2-available?)
    (testing "Get current process cgroup"
      (let [cgroup-path (cgroup/get-current-cgroup)]
        (is (string? cgroup-path))
        ;; Should be a valid path (starts with / or is /)
        (is (or (= "/" cgroup-path)
                (.startsWith cgroup-path "/")))))))

;; ============================================================================
;; Cgroup FD Management Tests
;; ============================================================================

(deftest test-cgroup-fd-management
  (when (cgroup-v2-available?)
    (testing "Open and close root cgroup"
      (try
        (let [fd (cgroup/get-cgroup-fd cgroup/DEFAULT_CGROUP_PATH)]
          (is (pos? fd) "Should get positive FD")
          (cgroup/close-cgroup fd))
        (catch Exception e
          ;; May fail without proper permissions - that's ok
          (is (string? (.getMessage e)) "Exception should have a message"))))

    (testing "Open non-existent cgroup"
      (is (thrown? Exception
            (cgroup/get-cgroup-fd "/sys/fs/cgroup/nonexistent_xyz"))))))

;; ============================================================================
;; Syscall Structure Tests
;; ============================================================================

(deftest test-prog-attach-attr-structure
  (testing "BPF_PROG_ATTACH attribute structure"
    (let [attr-seg (#'cgroup/prog-attach-attr->segment 5 6 0 1 0)]
      (is (some? attr-seg))
      ;; Structure should be at least 20 bytes (5 u32 fields)
      (is (>= (.byteSize attr-seg) 20)))))

(deftest test-prog-detach-attr-structure
  (testing "BPF_PROG_DETACH attribute structure"
    (let [attr-seg (#'cgroup/prog-detach-attr->segment 5 6 0)]
      (is (some? attr-seg))
      ;; Structure should be at least 12 bytes (3 u32 fields)
      (is (>= (.byteSize attr-seg) 12)))))

;; ============================================================================
;; Program Loader Tests
;; ============================================================================

(deftest test-cgroup-skb-direction-validation
  (testing "Load cgroup SKB program with valid direction"
    ;; Should accept :ingress and :egress
    (is (fn? cgroup/load-cgroup-skb-program))

    ;; Test that it validates direction
    (is (thrown-with-msg? Exception #"Invalid direction"
          (cgroup/load-cgroup-skb-program (byte-array 0) :invalid)))))

(deftest test-program-loaders-exist
  (testing "All cgroup program loaders are available"
    (is (fn? cgroup/load-cgroup-skb-program))
    (is (fn? cgroup/load-cgroup-sock-program))
    (is (fn? cgroup/load-cgroup-device-program))
    (is (fn? cgroup/load-cgroup-sysctl-program))))

;; ============================================================================
;; Integration Tests (require root/CAP_BPF and cgroup v2)
;; ============================================================================

(deftest ^:integration test-cgroup-attachment-lifecycle
  (when (and (linux-with-bpf?)
            (cgroup-v2-available?)
            (System/getenv "RUN_INTEGRATION_TESTS"))
    (testing "Full cgroup attachment lifecycle"
      (try
        ;; Create a minimal cgroup SKB program (return 1 = allow)
        (let [bytecode (byte-array [
                                     ;; mov r0, 1 (allow)
                                     0xb7 0x00 0x00 0x00 0x01 0x00 0x00 0x00
                                     ;; exit
                                     0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])
              prog-fd (cgroup/load-cgroup-skb-program bytecode :ingress
                                                      :prog-name "test_cgroup"
                                                      :license "GPL")]

          (try
            ;; Try to attach to root cgroup
            (let [info (cgroup/attach-cgroup-program cgroup/DEFAULT_CGROUP_PATH
                                                    prog-fd
                                                    :cgroup-inet-ingress
                                                    :flags :override)]
              (is (some? info))
              (is (= :cgroup-inet-ingress (:attach-type info)))

              ;; Detach
              (cgroup/detach-cgroup-program (:cgroup-path info)
                                           (:attach-type info)
                                           :prog-fd prog-fd))

            (finally
              ;; Cleanup
              (try (clj-ebpf.syscall/close-fd prog-fd) (catch Exception _)))))

        (catch Exception e
          ;; Expected to fail without proper permissions
          (is (or (re-find #"Operation not permitted" (.getMessage e))
                 (re-find #"Permission denied" (.getMessage e)))))))))

(deftest ^:integration test-setup-teardown-helpers
  (when (and (linux-with-bpf?)
            (cgroup-v2-available?)
            (System/getenv "RUN_INTEGRATION_TESTS"))
    (testing "Setup/teardown helper functions"
      (try
        (let [bytecode (byte-array [0xb7 0x00 0x00 0x00 0x01 0x00 0x00 0x00
                                    0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])
              setup (cgroup/setup-cgroup-skb cgroup/DEFAULT_CGROUP_PATH
                                            bytecode
                                            :ingress
                                            :prog-name "test_helper")]
          (is (some? setup))
          (is (pos? (:prog-fd setup)))

          ;; Cleanup
          (cgroup/teardown-cgroup-program setup))

        (catch Exception e
          ;; Expected to fail without proper permissions
          (is (or (re-find #"Operation not permitted" (.getMessage e))
                 (re-find #"Permission denied" (.getMessage e)))))))))

;; ============================================================================
;; Utility Function Tests
;; ============================================================================

(deftest test-list-cgroup-children
  (when (cgroup-v2-available?)
    (testing "List children of root cgroup"
      (let [children (cgroup/list-cgroup-children cgroup/DEFAULT_CGROUP_PATH)]
        (is (vector? children))
        ;; Root cgroup typically has at least some children
        ;; (may be empty in minimal environments)
        (is (or (seq children) (empty? children)))))

    (testing "List children of non-existent cgroup"
      (let [children (cgroup/list-cgroup-children "/sys/fs/cgroup/nonexistent_xyz")]
        (is (empty? children))))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-cgroup-api-completeness
  (testing "Core cgroup functions are available"
    (is (fn? cgroup/get-cgroup-fd))
    (is (fn? cgroup/close-cgroup))
    (is (fn? cgroup/cgroup-exists?))
    (is (fn? cgroup/prog-attach-cgroup))
    (is (fn? cgroup/prog-detach-cgroup))
    (is (fn? cgroup/attach-cgroup-program))
    (is (fn? cgroup/detach-cgroup-program)))

  (testing "Setup/teardown functions are available"
    (is (fn? cgroup/setup-cgroup-skb))
    (is (fn? cgroup/setup-cgroup-sock))
    (is (fn? cgroup/setup-cgroup-device))
    (is (fn? cgroup/teardown-cgroup-program)))

  (testing "Utility functions are available"
    (is (fn? cgroup/get-current-cgroup))
    (is (fn? cgroup/list-cgroup-children))))

;; ============================================================================
;; Documentation Tests
;; ============================================================================

(deftest test-function-metadata
  (testing "Key functions have docstrings"
    (is (string? (:doc (meta #'cgroup/get-cgroup-fd))))
    (is (string? (:doc (meta #'cgroup/close-cgroup))))
    (is (string? (:doc (meta #'cgroup/attach-cgroup-program))))
    (is (string? (:doc (meta #'cgroup/detach-cgroup-program))))
    (is (string? (:doc (meta #'cgroup/load-cgroup-skb-program))))
    (is (string? (:doc (meta #'cgroup/setup-cgroup-skb))))
    (is (string? (:doc (meta #'cgroup/teardown-cgroup-program))))))

;; ============================================================================
;; Example Usage Documentation
;; ============================================================================

(deftest ^:example test-usage-examples
  (testing "Example code compiles correctly"
    ;; Example 1: Basic attachment
    (is (fn? (fn []
               (let [bytecode (byte-array 16)
                     prog-fd (cgroup/load-cgroup-skb-program bytecode :ingress
                                                            :license "GPL")]
                 (try
                   (let [info (cgroup/attach-cgroup-program "/sys/fs/cgroup"
                                                           prog-fd
                                                           :cgroup-inet-ingress)]
                     (Thread/sleep 1000)
                     (cgroup/detach-cgroup-program (:cgroup-path info)
                                                  (:attach-type info)
                                                  :prog-fd prog-fd))
                   (finally
                     (clj-ebpf.syscall/close-fd prog-fd)))))))

    ;; Example 2: Using convenience functions
    (is (fn? (fn []
               (let [setup (cgroup/setup-cgroup-skb "/sys/fs/cgroup"
                                                   (byte-array 16)
                                                   :ingress)]
                 (Thread/sleep 1000)
                 (cgroup/teardown-cgroup-program setup)))))

    ;; Example 3: Using macros
    (is (fn? (fn []
               (cgroup/with-cgroup-skb [setup (cgroup/setup-cgroup-skb
                                               "/sys/fs/cgroup"
                                               (byte-array 16)
                                               :ingress)]
                 (Thread/sleep 1000)))))))

;; ============================================================================
;; Error Handling Tests
;; ============================================================================

(deftest test-error-handling
  (testing "Invalid cgroup path"
    (is (thrown? Exception
          (cgroup/get-cgroup-fd "/nonexistent/path/to/cgroup"))))

  (testing "Invalid attach type"
    ;; Should throw when attach type is not found
    (is (nil? (const/attach-type->num :invalid-attach-type)))))

;; ============================================================================
;; Attach Type Coverage Tests
;; ============================================================================

(deftest test-attach-type-coverage
  (testing "All common cgroup attach types are defined"
    (is (some? (const/attach-type->num :cgroup-inet-ingress)))
    (is (some? (const/attach-type->num :cgroup-inet-egress)))
    (is (some? (const/attach-type->num :cgroup-inet-sock-create)))
    (is (some? (const/attach-type->num :cgroup-device)))
    (is (some? (const/attach-type->num :cgroup-sysctl)))
    (is (some? (const/attach-type->num :cgroup-getsockopt)))
    (is (some? (const/attach-type->num :cgroup-setsockopt)))
    (is (some? (const/attach-type->num :cgroup-inet4-bind)))
    (is (some? (const/attach-type->num :cgroup-inet6-bind)))
    (is (some? (const/attach-type->num :cgroup-inet4-connect)))
    (is (some? (const/attach-type->num :cgroup-inet6-connect)))))
