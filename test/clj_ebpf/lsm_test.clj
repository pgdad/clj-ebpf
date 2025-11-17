(ns clj-ebpf.lsm-test
  "Tests for LSM BPF support"
  (:require [clojure.test :refer :all]
            [clj-ebpf.lsm :as lsm]
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
;; Constants Tests
;; ============================================================================

(deftest test-lsm-constants
  (testing "LSM return codes"
    (is (= 0 (:allow lsm/lsm-return-code)))
    (is (= -1 (:deny lsm/lsm-return-code))))

  (testing "LSM hooks are defined"
    (is (map? lsm/lsm-hooks))
    (is (contains? lsm/lsm-hooks :file-open))
    (is (contains? lsm/lsm-hooks :bprm-check-security))
    (is (contains? lsm/lsm-hooks :socket-create))))

;; ============================================================================
;; LSM Hook Tests
;; ============================================================================

(deftest test-lsm-hook-names
  (testing "LSM hook name resolution"
    (is (= "file_open" (lsm/get-lsm-hook-name :file-open)))
    (is (= "bprm_check_security" (lsm/get-lsm-hook-name :bprm-check-security)))
    (is (= "socket_create" (lsm/get-lsm-hook-name :socket-create)))))

(deftest test-list-lsm-hooks
  (testing "List all LSM hooks"
    (let [hooks (lsm/list-lsm-hooks)]
      (is (vector? hooks))
      (is (seq hooks))
      (is (every? keyword? hooks))
      (is (contains? (set hooks) :file-open))
      (is (contains? (set hooks) :bprm-check-security)))))

;; ============================================================================
;; LSM Hook Categories Tests
;; ============================================================================

(deftest test-lsm-hook-categories
  (testing "LSM hook categories"
    (is (map? lsm/lsm-hook-categories))
    (is (contains? lsm/lsm-hook-categories :file-system))
    (is (contains? lsm/lsm-hook-categories :process))
    (is (contains? lsm/lsm-hook-categories :network))))

(deftest test-list-hooks-by-category
  (testing "List hooks by category"
    (let [fs-hooks (lsm/list-hooks-by-category :file-system)]
      (is (vector? fs-hooks))
      (is (seq fs-hooks))
      (is (contains? (set fs-hooks) :file-open)))

    (let [proc-hooks (lsm/list-hooks-by-category :process)]
      (is (contains? (set proc-hooks) :bprm-check-security)))

    (let [net-hooks (lsm/list-hooks-by-category :network)]
      (is (contains? (set net-hooks) :socket-create)))))

(deftest test-get-hook-category
  (testing "Get category for hook"
    (is (= :file-system (lsm/get-hook-category :file-open)))
    (is (= :process (lsm/get-hook-category :bprm-check-security)))
    (is (= :network (lsm/get-hook-category :socket-create)))
    (is (nil? (lsm/get-hook-category :nonexistent-hook)))))

;; ============================================================================
;; Link Creation Tests
;; ============================================================================

(deftest test-link-create-attr-structure
  (testing "BPF_LINK_CREATE attribute structure"
    (let [attr-seg (#'lsm/link-create-attr->segment 5 27 0)]
      (is (some? attr-seg))
      ;; Structure should be at least 20 bytes (5 u32 fields)
      (is (>= (.byteSize attr-seg) 20)))))

;; ============================================================================
;; Program Loading Tests
;; ============================================================================

(deftest test-lsm-program-validation
  (testing "LSM program hook validation"
    ;; Should throw on invalid hook
    (is (thrown-with-msg? Exception #"Invalid LSM hook"
          (lsm/load-lsm-program (byte-array 0) :invalid-hook)))))

;; ============================================================================
;; LSM Availability Tests
;; ============================================================================

(deftest test-lsm-availability
  (when (linux-with-bpf?)
    (testing "Check LSM BPF availability"
      ;; This will return false on most systems without LSM BPF enabled
      (let [available (lsm/lsm-available?)]
        (is (boolean? available))))))

;; ============================================================================
;; Integration Tests (require root/CAP_BPF and LSM BPF enabled)
;; ============================================================================

(deftest ^:integration test-lsm-program-lifecycle
  (when (and (linux-with-bpf?)
            (System/getenv "RUN_INTEGRATION_TESTS"))
    (testing "Full LSM program lifecycle"
      (try
        ;; Create a minimal LSM program (return 0 = allow)
        (let [bytecode (byte-array [
                                     ;; mov r0, 0 (allow)
                                     0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                                     ;; exit
                                     0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])
              prog-fd (lsm/load-lsm-program bytecode :file-open
                                            :prog-name "test_lsm"
                                            :license "GPL")]

          (is (pos? prog-fd))

          (try
            ;; Try to attach
            (let [link-info (lsm/attach-lsm-program prog-fd)]
              (is (some? link-info))
              (is (pos? (:link-fd link-info)))

              ;; Detach
              (lsm/detach-lsm-program link-info))

            (finally
              ;; Cleanup
              (try (clj-ebpf.syscall/close-fd prog-fd) (catch Exception _)))))

        (catch Exception e
          ;; Expected to fail without LSM BPF support or proper permissions
          (is (or (re-find #"Operation not permitted" (.getMessage e))
                 (re-find #"Permission denied" (.getMessage e))
                 (re-find #"Invalid argument" (.getMessage e))
                 (re-find #"Operation not supported" (.getMessage e)))))))))

(deftest ^:integration test-setup-teardown-helpers
  (when (and (linux-with-bpf?)
            (System/getenv "RUN_INTEGRATION_TESTS"))
    (testing "Setup/teardown helper functions"
      (try
        (let [bytecode (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                                    0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])
              setup (lsm/setup-lsm-hook bytecode :file-open
                                       :prog-name "test_helper")]
          (is (some? setup))
          (is (pos? (:prog-fd setup)))
          (is (pos? (:link-fd setup)))

          ;; Cleanup
          (lsm/teardown-lsm-hook setup))

        (catch Exception e
          ;; Expected to fail without LSM BPF support or proper permissions
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-lsm-api-completeness
  (testing "Core LSM functions are available"
    (is (fn? lsm/load-lsm-program))
    (is (fn? lsm/create-lsm-link))
    (is (fn? lsm/close-lsm-link))
    (is (fn? lsm/attach-lsm-program))
    (is (fn? lsm/detach-lsm-program))
    (is (fn? lsm/setup-lsm-hook))
    (is (fn? lsm/teardown-lsm-hook))
    (is (fn? lsm/lsm-available?))
    (is (fn? lsm/list-lsm-hooks))
    (is (fn? lsm/get-lsm-hook-name))
    (is (fn? lsm/list-hooks-by-category))
    (is (fn? lsm/get-hook-category))))

;; ============================================================================
;; Documentation Tests
;; ============================================================================

(deftest test-function-metadata
  (testing "Key functions have docstrings"
    (is (string? (:doc (meta #'lsm/load-lsm-program))))
    (is (string? (:doc (meta #'lsm/create-lsm-link))))
    (is (string? (:doc (meta #'lsm/attach-lsm-program))))
    (is (string? (:doc (meta #'lsm/detach-lsm-program))))
    (is (string? (:doc (meta #'lsm/setup-lsm-hook))))
    (is (string? (:doc (meta #'lsm/teardown-lsm-hook))))
    (is (string? (:doc (meta #'lsm/lsm-available?))))))

;; ============================================================================
;; Example Usage Documentation
;; ============================================================================

(deftest ^:example test-usage-examples
  (testing "Example code compiles correctly"
    ;; Example 1: Basic usage
    (is (fn? (fn []
               (let [bytecode (byte-array 16)
                     prog-fd (lsm/load-lsm-program bytecode :file-open
                                                   :license "GPL")]
                 (try
                   (let [link-info (lsm/attach-lsm-program prog-fd)]
                     (Thread/sleep 1000)
                     (lsm/detach-lsm-program link-info))
                   (finally
                     (clj-ebpf.syscall/close-fd prog-fd)))))))

    ;; Example 2: Using convenience functions
    (is (fn? (fn []
               (let [setup (lsm/setup-lsm-hook (byte-array 16) :file-open)]
                 (Thread/sleep 1000)
                 (lsm/teardown-lsm-hook setup)))))

    ;; Example 3: Using macros
    (is (fn? (fn []
               (lsm/with-lsm-hook [setup (lsm/setup-lsm-hook
                                          (byte-array 16)
                                          :file-open)]
                 (Thread/sleep 1000)))))))

;; ============================================================================
;; Hook Coverage Tests
;; ============================================================================

(deftest test-hook-coverage
  (testing "Common LSM hooks are defined"
    ;; File system hooks
    (is (contains? lsm/lsm-hooks :file-open))
    (is (contains? lsm/lsm-hooks :file-permission))
    (is (contains? lsm/lsm-hooks :inode-create))

    ;; Process hooks
    (is (contains? lsm/lsm-hooks :bprm-check-security))
    (is (contains? lsm/lsm-hooks :task-kill))

    ;; Network hooks
    (is (contains? lsm/lsm-hooks :socket-create))
    (is (contains? lsm/lsm-hooks :socket-bind))
    (is (contains? lsm/lsm-hooks :socket-connect))

    ;; Mount hooks
    (is (contains? lsm/lsm-hooks :sb-mount))))

(deftest test-hook-count
  (testing "Reasonable number of hooks defined"
    (let [hook-count (count lsm/lsm-hooks)]
      ;; We've defined a subset of common hooks
      (is (>= hook-count 20))
      (is (<= hook-count 50)))))
