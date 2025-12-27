(ns clj-ebpf.constants-test
  "Tests for BPF constants - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.constants :as const]
            [clj-ebpf.arch :as arch]))

(deftest test-cmd-conversions
  (testing "BPF command keyword to number conversion"
    (is (= 0 (const/cmd->num :map-create)))
    (is (= 5 (const/cmd->num :prog-load)))
    (is (= 1 (const/cmd->num :map-lookup-elem))))

  (testing "BPF command number to keyword conversion"
    (is (= :map-create (get const/int->cmd 0)))
    (is (= :prog-load (get const/int->cmd 5)))))

(deftest test-map-type-conversions
  (testing "Map type keyword to number conversion"
    (is (= 1 (const/map-type->num :hash)))
    (is (= 2 (const/map-type->num :array)))
    (is (= 27 (const/map-type->num :ringbuf))))

  (testing "Map type number to keyword conversion"
    (is (= :hash (get const/int->map-type 1)))
    (is (= :array (get const/int->map-type 2)))
    (is (= :ringbuf (get const/int->map-type 27)))))

(deftest test-prog-type-conversions
  (testing "Program type keyword to number conversion"
    (is (= 2 (const/prog-type->num :kprobe)))
    (is (= 5 (const/prog-type->num :tracepoint)))
    (is (= 6 (const/prog-type->num :xdp))))

  (testing "Program type number to keyword conversion"
    (is (= :kprobe (get const/int->prog-type 2)))
    (is (= :tracepoint (get const/int->prog-type 5)))))

(deftest test-attach-type-conversions
  (testing "Attach type keyword to number conversion"
    (is (= 23 (const/attach-type->num :trace-raw-tp)))
    (is (= 41 (const/attach-type->num :perf-event))))

  (testing "Attach type number to keyword conversion"
    (is (= :trace-raw-tp (get const/int->attach-type 23)))
    (is (= :perf-event (get const/int->attach-type 41)))))

(deftest test-flags-conversion
  (testing "Map flags to bits conversion"
    (is (= 0x01 (const/flags->bits const/map-flags [:no-prealloc])))
    (is (= 0x09 (const/flags->bits const/map-flags [:no-prealloc :rdonly])))
    (is (= 0 (const/flags->bits const/map-flags []))))

  (testing "Map update flags"
    (is (= 0 (get const/map-update-flags :any)))
    (is (= 1 (get const/map-update-flags :noexist)))
    (is (= 2 (get const/map-update-flags :exist)))))

(deftest test-constants-defined
  (testing "Important constants are defined"
    ;; BPF_SYSCALL_NR is architecture-specific - verify it matches arch module
    (is (= (arch/get-syscall-nr :bpf) const/BPF_SYSCALL_NR))
    (is (= 16 const/BPF_OBJ_NAME_LEN))
    (is (= 8 const/BPF_TAG_SIZE))
    (is (= (* 16 1024 1024) const/BPF_LOG_BUF_SIZE))))

(deftest test-architecture-detection
  (testing "Architecture is detected and supported"
    (is (arch/supported-arch?))
    (is (keyword? arch/current-arch))
    (is (contains? #{:x86_64 :arm64 :s390x :ppc64le :riscv64} arch/current-arch)))

  (testing "Syscall numbers are valid for current architecture"
    (is (pos-int? const/BPF_SYSCALL_NR))
    (is (pos-int? const/PERF_EVENT_OPEN_SYSCALL_NR))
    ;; Architecture-specific value ranges (all known values are between 200-400)
    (is (<= 200 const/BPF_SYSCALL_NR 400))))

(deftest test-errno-values
  (testing "Common errno values"
    (is (= 1 (:eperm const/errno)))
    (is (= 2 (:enoent const/errno)))
    (is (= 13 (:eacces const/errno)))
    (is (= 22 (:einval const/errno)))))
