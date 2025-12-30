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

(deftest test-helper-func-ids
  (testing "Common BPF helper function IDs"
    ;; Map helpers (1-3)
    (is (= 1 (:map-lookup-elem const/helper-func)))
    (is (= 2 (:map-update-elem const/helper-func)))
    (is (= 3 (:map-delete-elem const/helper-func)))

    ;; Time/info helpers
    (is (= 5 (:ktime-get-ns const/helper-func)))
    (is (= 14 (:get-current-pid-tgid const/helper-func)))
    (is (= 16 (:get-current-comm const/helper-func)))

    ;; Network helpers
    (is (= 23 (:redirect const/helper-func)))
    (is (= 28 (:csum-diff const/helper-func)))
    (is (= 44 (:xdp-adjust-head const/helper-func)))
    (is (= 51 (:redirect-map const/helper-func)))
    (is (= 69 (:fib-lookup const/helper-func)))

    ;; Socket helpers
    (is (= 53 (:sock-map-update const/helper-func)))
    (is (= 70 (:sock-hash-update const/helper-func)))
    (is (= 71 (:msg-redirect-hash const/helper-func)))
    (is (= 72 (:sk-redirect-hash const/helper-func)))

    ;; Ring buffer helpers
    (is (= 130 (:ringbuf-output const/helper-func)))
    (is (= 131 (:ringbuf-reserve const/helper-func)))
    (is (= 132 (:ringbuf-submit const/helper-func)))
    (is (= 133 (:ringbuf-discard const/helper-func)))

    ;; Newer helpers (kernel 5.x+)
    (is (= 112 (:probe-read-user const/helper-func)))
    (is (= 113 (:probe-read-kernel const/helper-func)))
    (is (= 125 (:ktime-get-boot-ns const/helper-func)))

    ;; Timer helpers
    (is (= 156 (:timer-init const/helper-func)))
    (is (= 157 (:timer-set-callback const/helper-func)))

    ;; Kernel 6.x helpers
    (is (= 208 (:ktime-get-tai-ns const/helper-func)))
    (is (= 211 (:cgrp-storage-delete const/helper-func))))

  (testing "Helper func map has expected count"
    ;; 209 helpers (1-191, 194-211; IDs 192-193 are reserved) + 1 unspec = 210 entries
    (is (= 210 (count const/helper-func))))

  (testing "Helper func IDs are unique"
    (let [ids (vals const/helper-func)]
      (is (= (count ids) (count (set ids))))))

  (testing "Helper func IDs are in valid range"
    (let [ids (vals const/helper-func)]
      (is (every? #(and (>= % 0) (<= % 300)) ids)))))
