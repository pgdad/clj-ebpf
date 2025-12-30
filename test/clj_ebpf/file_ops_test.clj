(ns clj-ebpf.file-ops-test
  "Tests for file operations (openat syscall) - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.arch :as arch])
  (:import [java.io File]))

;; ============================================================================
;; Test Constants
;; ============================================================================

(deftest test-file-open-constants
  (testing "AT_FDCWD constant"
    (is (= -100 syscall/AT_FDCWD)))

  (testing "O_RDONLY constant"
    (is (= 0 syscall/O_RDONLY)))

  (testing "O_WRONLY constant"
    (is (= 1 syscall/O_WRONLY)))

  (testing "O_RDWR constant"
    (is (= 2 syscall/O_RDWR)))

  (testing "O_CREAT constant"
    (is (= 0x40 syscall/O_CREAT)))

  (testing "O_EXCL constant"
    (is (= 0x80 syscall/O_EXCL)))

  (testing "O_TRUNC constant"
    (is (= 0x200 syscall/O_TRUNC)))

  (testing "O_APPEND constant"
    (is (= 0x400 syscall/O_APPEND)))

  (testing "O_NONBLOCK constant"
    (is (= 0x800 syscall/O_NONBLOCK)))

  (testing "O_CLOEXEC constant"
    (is (= 0x80000 syscall/O_CLOEXEC))))

;; ============================================================================
;; Test Syscall Numbers
;; ============================================================================

(deftest test-openat-syscall-numbers
  (testing "openat syscall number is available"
    (is (number? (arch/get-syscall-nr :openat))))

  (testing "openat syscall number is positive"
    (is (pos? (arch/get-syscall-nr :openat))))

  (testing "openat syscall number matches architecture"
    (case arch/current-arch
      :x86_64  (is (= 257 (arch/get-syscall-nr :openat)))
      :arm64   (is (= 56 (arch/get-syscall-nr :openat)))
      :riscv64 (is (= 56 (arch/get-syscall-nr :openat)))
      :s390x   (is (= 288 (arch/get-syscall-nr :openat)))
      :ppc64le (is (= 286 (arch/get-syscall-nr :openat)))
      ;; Skip for unknown architectures
      nil)))

;; ============================================================================
;; Test file-open Function
;; ============================================================================

(deftest test-file-open-read-existing
  (testing "Open existing file for reading"
    (let [fd (syscall/file-open "/etc/passwd" syscall/O_RDONLY)]
      (is (number? fd))
      (is (pos? fd))
      (syscall/close-fd fd)))

  (testing "Open /dev/null for reading"
    (let [fd (syscall/file-open "/dev/null" syscall/O_RDONLY)]
      (is (number? fd))
      (is (pos? fd))
      (syscall/close-fd fd)))

  (testing "Open /proc/self/status for reading"
    (let [fd (syscall/file-open "/proc/self/status" syscall/O_RDONLY)]
      (is (number? fd))
      (is (pos? fd))
      (syscall/close-fd fd))))

(deftest test-file-open-nonexistent
  (testing "Open non-existent file throws exception"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"Failed to open file"
                          (syscall/file-open "/nonexistent/path/file.txt"
                                             syscall/O_RDONLY))))

  (testing "Exception contains error info"
    (try
      (syscall/file-open "/nonexistent/path/file.txt" syscall/O_RDONLY)
      (is false "Should have thrown")
      (catch clojure.lang.ExceptionInfo e
        (let [data (ex-data e)]
          (is (= "/nonexistent/path/file.txt" (:path data)))
          (is (= syscall/O_RDONLY (:flags data)))
          (is (keyword? (:error data)))
          (is (= :enoent (:error data))))))))

(deftest test-file-open-create
  (testing "Create new file"
    (let [test-file (str "/tmp/clj-ebpf-test-" (System/currentTimeMillis) ".txt")
          fd (syscall/file-open test-file
                                (bit-or syscall/O_CREAT syscall/O_WRONLY)
                                0644)]
      (try
        (is (number? fd))
        (is (pos? fd))
        (is (.exists (File. test-file)))
        (syscall/close-fd fd)
        (finally
          (.delete (File. test-file))))))

  (testing "Create file with O_EXCL fails if exists"
    (let [test-file (str "/tmp/clj-ebpf-test-excl-" (System/currentTimeMillis) ".txt")]
      ;; First create the file
      (let [fd (syscall/file-open test-file
                                  (bit-or syscall/O_CREAT syscall/O_WRONLY)
                                  0644)]
        (syscall/close-fd fd))
      (try
        ;; Now try to create with O_EXCL - should fail
        (is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #"Failed to open file"
                              (syscall/file-open test-file
                                                 (bit-or syscall/O_CREAT
                                                         syscall/O_EXCL
                                                         syscall/O_WRONLY)
                                                 0644)))
        (finally
          (.delete (File. test-file)))))))

(deftest test-file-open-modes
  (testing "Open with O_RDWR"
    (let [test-file (str "/tmp/clj-ebpf-test-rdwr-" (System/currentTimeMillis) ".txt")
          fd (syscall/file-open test-file
                                (bit-or syscall/O_CREAT syscall/O_RDWR)
                                0644)]
      (try
        (is (number? fd))
        (is (pos? fd))
        (syscall/close-fd fd)
        (finally
          (.delete (File. test-file))))))

  (testing "Open with O_APPEND"
    (let [test-file (str "/tmp/clj-ebpf-test-append-" (System/currentTimeMillis) ".txt")
          fd (syscall/file-open test-file
                                (bit-or syscall/O_CREAT syscall/O_WRONLY syscall/O_APPEND)
                                0644)]
      (try
        (is (number? fd))
        (is (pos? fd))
        (syscall/close-fd fd)
        (finally
          (.delete (File. test-file))))))

  (testing "Open with O_TRUNC"
    (let [test-file (str "/tmp/clj-ebpf-test-trunc-" (System/currentTimeMillis) ".txt")]
      ;; Create file with content using Java (to have content to truncate)
      (spit test-file "Some content to truncate")
      (try
        (let [fd (syscall/file-open test-file
                                    (bit-or syscall/O_WRONLY syscall/O_TRUNC)
                                    0644)]
          (is (number? fd))
          (is (pos? fd))
          (syscall/close-fd fd)
          ;; File should be empty after O_TRUNC
          (is (= 0 (.length (File. test-file)))))
        (finally
          (.delete (File. test-file)))))))

(deftest test-file-open-permissions
  (testing "Create file with mode 0600"
    (let [test-file (str "/tmp/clj-ebpf-test-perm-" (System/currentTimeMillis) ".txt")
          fd (syscall/file-open test-file
                                (bit-or syscall/O_CREAT syscall/O_WRONLY)
                                0600)]
      (try
        (is (number? fd))
        (syscall/close-fd fd)
        (finally
          (.delete (File. test-file))))))

  (testing "Create file with mode 0755"
    (let [test-file (str "/tmp/clj-ebpf-test-perm2-" (System/currentTimeMillis) ".txt")
          fd (syscall/file-open test-file
                                (bit-or syscall/O_CREAT syscall/O_WRONLY)
                                0755)]
      (try
        (is (number? fd))
        (syscall/close-fd fd)
        (finally
          (.delete (File. test-file)))))))

(deftest test-file-open-default-mode
  (testing "file-open without mode uses 0644"
    (let [test-file (str "/tmp/clj-ebpf-test-default-" (System/currentTimeMillis) ".txt")
          fd (syscall/file-open test-file
                                (bit-or syscall/O_CREAT syscall/O_WRONLY))]
      (try
        (is (number? fd))
        (is (pos? fd))
        (syscall/close-fd fd)
        (finally
          (.delete (File. test-file)))))))

(deftest test-file-open-special-files
  (testing "Open /dev/zero"
    (let [fd (syscall/file-open "/dev/zero" syscall/O_RDONLY)]
      (is (number? fd))
      (is (pos? fd))
      (syscall/close-fd fd)))

  (testing "Open /dev/urandom"
    (let [fd (syscall/file-open "/dev/urandom" syscall/O_RDONLY)]
      (is (number? fd))
      (is (pos? fd))
      (syscall/close-fd fd))))

;; ============================================================================
;; Test Flag Combinations
;; ============================================================================

(deftest test-flag-combinations
  (testing "Multiple flags can be combined with bit-or"
    (let [flags (bit-or syscall/O_CREAT syscall/O_WRONLY syscall/O_TRUNC)]
      (is (= (bit-or 0x40 0x01 0x200) flags))))

  (testing "O_CLOEXEC can be combined with other flags"
    (let [test-file (str "/tmp/clj-ebpf-test-cloexec-" (System/currentTimeMillis) ".txt")
          fd (syscall/file-open test-file
                                (bit-or syscall/O_CREAT
                                        syscall/O_WRONLY
                                        syscall/O_CLOEXEC)
                                0644)]
      (try
        (is (number? fd))
        (is (pos? fd))
        (syscall/close-fd fd)
        (finally
          (.delete (File. test-file)))))))

;; ============================================================================
;; Integration Tests
;; ============================================================================

(deftest test-file-open-close-cycle
  (testing "Multiple open/close cycles on same file"
    (let [test-file (str "/tmp/clj-ebpf-test-cycle-" (System/currentTimeMillis) ".txt")]
      ;; Create file
      (let [fd (syscall/file-open test-file
                                  (bit-or syscall/O_CREAT syscall/O_WRONLY)
                                  0644)]
        (syscall/close-fd fd))
      (try
        ;; Open and close multiple times
        (dotimes [_ 10]
          (let [fd (syscall/file-open test-file syscall/O_RDONLY)]
            (is (number? fd))
            (is (pos? fd))
            (syscall/close-fd fd)))
        (finally
          (.delete (File. test-file)))))))

(deftest test-multiple-files-open
  (testing "Can have multiple files open simultaneously"
    (let [files (for [i (range 5)]
                  (str "/tmp/clj-ebpf-test-multi-" i "-" (System/currentTimeMillis) ".txt"))
          fds (doall
               (for [f files]
                 (syscall/file-open f
                                    (bit-or syscall/O_CREAT syscall/O_WRONLY)
                                    0644)))]
      (try
        (is (= 5 (count fds)))
        (is (every? number? fds))
        (is (every? pos? fds))
        ;; All FDs should be unique
        (is (= 5 (count (set fds))))
        ;; Close all
        (doseq [fd fds]
          (syscall/close-fd fd))
        (finally
          (doseq [f files]
            (.delete (File. f))))))))
