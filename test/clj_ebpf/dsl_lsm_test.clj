(ns clj-ebpf.dsl-lsm-test
  "Tests for LSM DSL - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.lsm :as lsm]))

;; ============================================================================
;; Action Tests
;; ============================================================================

(deftest test-lsm-actions
  (testing "LSM action values"
    (is (= 0 (:allow lsm/lsm-actions)))
    (is (= -1 (:eperm lsm/lsm-actions)))
    (is (= -13 (:eacces lsm/lsm-actions)))
    (is (= -2 (:enoent lsm/lsm-actions)))
    (is (= -22 (:einval lsm/lsm-actions))))

  (testing "lsm-action function"
    (is (= 0 (lsm/lsm-action :allow)))
    (is (= -1 (lsm/lsm-action :eperm)))
    (is (= -13 (lsm/lsm-action :eacces))))

  (testing "Invalid action throws"
    (is (thrown? clojure.lang.ExceptionInfo
                (lsm/lsm-action :invalid)))))

;; ============================================================================
;; Common Hooks Tests
;; ============================================================================

(deftest test-common-hooks
  (testing "Common LSM hooks defined"
    (is (map? lsm/common-lsm-hooks))
    (is (pos? (count lsm/common-lsm-hooks)))
    (is (contains? lsm/common-lsm-hooks :bprm-check-security))
    (is (contains? lsm/common-lsm-hooks :file-open))
    (is (contains? lsm/common-lsm-hooks :socket-create))
    (is (contains? lsm/common-lsm-hooks :path-unlink))))

;; ============================================================================
;; Prologue Tests
;; ============================================================================

(deftest test-lsm-prologue
  (testing "Empty prologue"
    (let [insns (lsm/lsm-prologue [])]
      (is (= 0 (count insns)))))

  (testing "Single arg prologue"
    (let [insns (lsm/lsm-prologue [[0 :r6]])]
      (is (= 1 (count insns)))
      (is (bytes? (first insns)))))

  (testing "Multiple args prologue"
    (let [insns (lsm/lsm-prologue [[0 :r6] [1 :r7] [2 :r8]])]
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-lsm-save-args
  (testing "Save 2 args"
    (let [insns (lsm/lsm-save-args 2)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "Save 5 args"
    (let [insns (lsm/lsm-save-args 5)]
      (is (= 5 (count insns))))))

;; ============================================================================
;; Return Pattern Tests
;; ============================================================================

(deftest test-lsm-allow
  (testing "Allow instructions"
    (let [insns (lsm/lsm-allow)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-lsm-deny
  (testing "Deny with default errno"
    (let [insns (lsm/lsm-deny)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "Deny with specific errno"
    (let [insns (lsm/lsm-deny :eacces)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "Deny with numeric errno"
    (let [insns (lsm/lsm-deny -13)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-lsm-return
  (testing "Return specific value"
    (let [insns (lsm/lsm-return 0)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Helper Tests
;; ============================================================================

(deftest test-lsm-get-current-pid
  (testing "Get PID instructions"
    (let [insns (lsm/lsm-get-current-pid)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-lsm-get-current-uid
  (testing "Get UID instructions"
    (let [insns (lsm/lsm-get-current-uid)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-lsm-get-current-gid
  (testing "Get GID instructions"
    (let [insns (lsm/lsm-get-current-gid)]
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-lsm-get-current-comm
  (testing "Get comm instructions"
    (let [insns (lsm/lsm-get-current-comm :r1)]
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Builder Tests
;; ============================================================================

(deftest test-build-lsm-program
  (testing "Allow-all program"
    (let [bytecode (lsm/build-lsm-program
                    {:body []
                     :default-action :allow})]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "Deny-all program"
    (let [bytecode (lsm/build-lsm-program
                    {:body []
                     :default-action :eperm})]
      (is (bytes? bytecode))))

  (testing "Program with args"
    (let [bytecode (lsm/build-lsm-program
                    {:arg-saves [[0 :r6]]
                     :body []
                     :default-action :allow})]
      (is (bytes? bytecode)))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(lsm/deflsm-instructions test-allow-all
  {:hook "bprm_check_security"
   :default-action :allow}
  [])

(lsm/deflsm-instructions test-deny-all
  {:hook "file_open"
   :default-action :eperm}
  [])

(lsm/deflsm-instructions test-with-args
  {:hook "socket_connect"
   :args [:sock :addr :addrlen]
   :arg-saves [[0 :r6] [1 :r7]]
   :default-action :allow}
  [])

(deftest test-deflsm-macro
  (testing "Allow-all macro"
    (let [insns (test-allow-all)]
      (is (vector? insns))
      (is (>= (count insns) 2))
      (is (every? bytes? insns))))

  (testing "Deny-all macro"
    (let [insns (test-deny-all)]
      (is (vector? insns))
      (is (>= (count insns) 2))))

  (testing "With args macro"
    (let [insns (test-with-args)]
      (is (vector? insns))
      (is (>= (count insns) 4))))

  (testing "Assembly works"
    (is (bytes? (dsl/assemble (test-allow-all))))
    (is (bytes? (dsl/assemble (test-deny-all))))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-section-names
  (testing "LSM section names"
    (is (= "lsm/bprm_check_security"
           (lsm/lsm-section-name "bprm_check_security")))
    (is (= "lsm/file_open"
           (lsm/lsm-section-name "file_open")))
    (is (= "lsm/socket_connect"
           (lsm/lsm-section-name "socket_connect")))))

;; ============================================================================
;; Metadata Tests
;; ============================================================================

(deftest test-program-metadata
  (testing "LSM program info"
    (let [info (lsm/make-lsm-program-info
                "my_lsm" "bprm_check_security" (test-allow-all))]
      (is (= "my_lsm" (:name info)))
      (is (= "lsm/bprm_check_security" (:section info)))
      (is (= :lsm (:type info)))
      (is (= "bprm_check_security" (:hook info)))
      (is (vector? (:instructions info))))))

;; ============================================================================
;; Filter Pattern Tests
;; ============================================================================

(deftest test-lsm-filter-by-uid
  (testing "Filter by UID"
    (let [insns (lsm/lsm-filter-by-uid 1000 2)]
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-lsm-filter-by-pid
  (testing "Filter by PID"
    (let [insns (lsm/lsm-filter-by-pid 1234 2)]
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Hook Information Tests
;; ============================================================================

(deftest test-describe-hook
  (testing "Known hook description"
    (let [info (lsm/describe-lsm-hook :bprm-check-security)]
      (is (= "bprm-check-security" (:hook info)))
      (is (string? (:description info)))
      (is (= :lsm (:prog-type info)))
      (is (vector? (:notes info)))))

  (testing "Custom hook description"
    (let [info (lsm/describe-lsm-hook "custom_hook")]
      (is (= "custom_hook" (:hook info)))
      (is (= "Custom hook" (:description info))))))

;; ============================================================================
;; Complete Program Tests
;; ============================================================================

(deftest test-complete-programs
  (testing "UID-based policy"
    (let [insns (vec (concat
                      (lsm/lsm-prologue [[0 :r6]])
                      (lsm/lsm-get-current-uid)
                      ;; Allow if UID == 0 (root)
                      [(dsl/jmp-imm :jeq :r0 0 2)]
                      (lsm/lsm-deny :eperm)
                      (lsm/lsm-allow)))
          bytecode (dsl/assemble insns)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))))

  (testing "PID-based policy"
    (let [insns (vec (concat
                      (lsm/lsm-prologue [])
                      (lsm/lsm-filter-by-pid 1 2)  ; Allow PID 1
                      (lsm/lsm-deny :eperm)
                      (lsm/lsm-allow)))
          bytecode (dsl/assemble insns)]
      (is (bytes? bytecode)))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-api-completeness
  (testing "Core functions exist"
    (is (fn? lsm/lsm-action))
    (is (fn? lsm/lsm-prologue))
    (is (fn? lsm/lsm-save-args))
    (is (fn? lsm/lsm-allow))
    (is (fn? lsm/lsm-deny))
    (is (fn? lsm/lsm-return))
    (is (fn? lsm/build-lsm-program))
    (is (fn? lsm/lsm-section-name))
    (is (fn? lsm/make-lsm-program-info)))

  (testing "Helper functions exist"
    (is (fn? lsm/lsm-get-current-pid))
    (is (fn? lsm/lsm-get-current-uid))
    (is (fn? lsm/lsm-get-current-gid))
    (is (fn? lsm/lsm-get-current-comm)))

  (testing "Filter functions exist"
    (is (fn? lsm/lsm-filter-by-uid))
    (is (fn? lsm/lsm-filter-by-pid)))

  (testing "Info function exists"
    (is (fn? lsm/describe-lsm-hook))))

;; ============================================================================
;; Data Structure Tests
;; ============================================================================

(deftest test-data-structures
  (testing "LSM actions count"
    (is (= 5 (count lsm/lsm-actions))))

  (testing "Common hooks count"
    (is (>= (count lsm/common-lsm-hooks) 10))))
