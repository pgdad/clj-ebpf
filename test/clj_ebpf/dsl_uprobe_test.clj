(ns clj-ebpf.dsl-uprobe-test
  "Tests for Uprobe DSL features
   CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.dsl.uprobe :as up]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.arch :as arch]))

;; ============================================================================
;; Argument Reading Tests
;; ============================================================================

(deftest test-uprobe-read-args
  (testing "uprobe-read-args generates instructions for single argument"
    (let [insns (up/uprobe-read-args :r1 [[0 :r6]])]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (bytes? (first insns)))
      (is (= 8 (count (first insns))))))

  (testing "uprobe-read-args generates instructions for multiple arguments"
    (let [insns (up/uprobe-read-args :r1 [[0 :r6] [1 :r7] [2 :r8]])]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns))))

  (testing "uprobe-read-args handles empty bindings"
    (let [insns (up/uprobe-read-args :r1 [])]
      (is (vector? insns))
      (is (empty? insns))))

  (testing "uprobe-read-args works with different context registers"
    (let [insns (up/uprobe-read-args :r9 [[0 :r6]])]
      (is (vector? insns))
      (is (= 1 (count insns))))))

;; ============================================================================
;; Prologue Generation Tests
;; ============================================================================

(deftest test-uprobe-prologue
  (testing "uprobe-prologue with context save and args"
    (let [prologue (up/uprobe-prologue :r9 [:r6 :r7])]
      (is (vector? prologue))
      ;; 1 mov (context save) + 2 ldx (args) = 3 instructions
      (is (= 3 (count prologue)))
      (is (every? bytes? prologue))))

  (testing "uprobe-prologue without context save"
    (let [prologue (up/uprobe-prologue [:r6 :r7 :r8])]
      (is (vector? prologue))
      ;; 3 ldx instructions only
      (is (= 3 (count prologue)))
      (is (every? bytes? prologue))))

  (testing "uprobe-prologue with empty args"
    (let [prologue (up/uprobe-prologue :r9 [])]
      (is (vector? prologue))
      ;; Only context save
      (is (= 1 (count prologue)))))

  (testing "uprobe-prologue with nil context and empty args"
    (let [prologue (up/uprobe-prologue nil [])]
      (is (vector? prologue))
      (is (empty? prologue))))

  (testing "uprobe-prologue single-arity version"
    (let [prologue (up/uprobe-prologue [:r6])]
      (is (vector? prologue))
      (is (= 1 (count prologue))))))

;; ============================================================================
;; Return Value Extraction Tests
;; ============================================================================

(deftest test-uretprobe-get-return-value
  (testing "uretprobe-get-return-value generates ldx instruction"
    (let [insn (up/uretprobe-get-return-value :r1 :r6)]
      (is (some? insn))
      (is (bytes? insn))
      (is (= 8 (count insn)))))

  (testing "uretprobe-get-return-value works with different registers"
    (let [insn (up/uretprobe-get-return-value :r9 :r7)]
      (is (bytes? insn))
      (is (= 8 (count insn)))))

  (testing "uretprobe-get-return-value uses architecture-specific offset"
    ;; Just verify it doesn't throw on current architecture
    (is (some? (up/uretprobe-get-return-value :r1 :r6)))))

;; ============================================================================
;; Program Building Tests
;; ============================================================================

(deftest test-build-uprobe-program
  (testing "build-uprobe-program creates valid bytecode with args"
    (let [prog (up/build-uprobe-program
                {:args [:r6 :r7]
                 :body []
                 :return-value 0})]
      (is (bytes? prog))
      (is (> (count prog) 0))
      (is (zero? (mod (count prog) 8)))))

  (testing "build-uprobe-program with context save"
    (let [prog (up/build-uprobe-program
                {:args [:r6]
                 :ctx-reg :r9
                 :body [(dsl/mov-reg :r8 :r6)]
                 :return-value 0})]
      (is (bytes? prog))
      ;; Prologue (2) + body (1) + epilogue (2) = 5 instructions
      (is (>= (count prog) 40))))

  (testing "build-uprobe-program with empty options"
    (let [prog (up/build-uprobe-program {})]
      (is (bytes? prog))
      ;; Just epilogue: mov r0, 0 + exit = 2 instructions
      (is (= 16 (count prog)))))

  (testing "build-uprobe-program with custom return value"
    (let [prog (up/build-uprobe-program
                {:return-value 42})]
      (is (bytes? prog)))))

(deftest test-build-uretprobe-program
  (testing "build-uretprobe-program creates valid bytecode"
    (let [prog (up/build-uretprobe-program
                {:ret-reg :r6
                 :body []
                 :return-value 0})]
      (is (bytes? prog))
      (is (> (count prog) 0))
      (is (zero? (mod (count prog) 8)))))

  (testing "build-uretprobe-program with context save"
    (let [prog (up/build-uretprobe-program
                {:ret-reg :r6
                 :ctx-reg :r9
                 :body [(dsl/mov-reg :r7 :r6)]
                 :return-value 0})]
      (is (bytes? prog))
      ;; ctx save (1) + ret load (1) + body (1) + epilogue (2) = 5 insns
      (is (>= (count prog) 40))))

  (testing "build-uretprobe-program without ret-reg"
    (let [prog (up/build-uretprobe-program
                {:body [(dsl/mov :r6 123)]
                 :return-value 0})]
      (is (bytes? prog)))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(up/defuprobe-instructions test-malloc-probe
  {:binary "/lib/x86_64-linux-gnu/libc.so.6"
   :function "malloc"
   :args [:r6]
   :ctx-reg :r9}
  [(dsl/mov :r0 0)
   (dsl/exit-insn)])

(up/defuretprobe-instructions test-malloc-ret-probe
  {:binary "/lib/x86_64-linux-gnu/libc.so.6"
   :function "malloc"
   :ret-reg :r6
   :ctx-reg :r9}
  [(dsl/mov :r0 0)
   (dsl/exit-insn)])

(deftest test-defuprobe-instructions-macro
  (testing "defuprobe-instructions creates a function"
    (is (fn? test-malloc-probe)))

  (testing "defuprobe-instructions returns instructions"
    (let [insns (test-malloc-probe)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "defuprobe-instructions includes prologue"
    (let [insns (test-malloc-probe)]
      ;; ctx save (1) + arg load (1) + body (2) = 4 instructions
      (is (= 4 (count insns))))))

(deftest test-defuretprobe-instructions-macro
  (testing "defuretprobe-instructions creates a function"
    (is (fn? test-malloc-ret-probe)))

  (testing "defuretprobe-instructions returns instructions"
    (let [insns (test-malloc-ret-probe)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "defuretprobe-instructions includes ret value load"
    (let [insns (test-malloc-ret-probe)]
      ;; ctx save (1) + ret load (1) + body (2) = 4 instructions
      (is (= 4 (count insns))))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-section-names
  (testing "uprobe-section-name generates correct format"
    (is (= "uprobe/libc.so.6:malloc"
           (up/uprobe-section-name "/lib/x86_64-linux-gnu/libc.so.6" "malloc")))
    (is (= "uprobe/myapp:main"
           (up/uprobe-section-name "/usr/bin/myapp" "main"))))

  (testing "uprobe-section-name with numeric offset"
    (is (= "uprobe/libc.so.6:0x1234"
           (up/uprobe-section-name "/lib/libc.so.6" "0x1234"))))

  (testing "uretprobe-section-name generates correct format"
    (is (= "uretprobe/libc.so.6:malloc"
           (up/uretprobe-section-name "/lib/x86_64-linux-gnu/libc.so.6" "malloc")))
    (is (= "uretprobe/myapp:main"
           (up/uretprobe-section-name "/usr/bin/myapp" "main")))))

;; ============================================================================
;; Program Info Tests
;; ============================================================================

(deftest test-program-info
  (testing "make-uprobe-program-info returns correct structure"
    (let [info (up/make-uprobe-program-info
                "/lib/libc.so.6" "malloc" 0x1234 "my_probe" [])]
      (is (map? info))
      (is (= "my_probe" (:name info)))
      (is (= "uprobe/libc.so.6:malloc" (:section info)))
      (is (= :uprobe (:type info)))
      (is (= "/lib/libc.so.6" (:binary info)))
      (is (= "malloc" (:function info)))
      (is (= 0x1234 (:offset info)))
      (is (vector? (:instructions info)))))

  (testing "make-uretprobe-program-info returns correct structure"
    (let [info (up/make-uretprobe-program-info
                "/lib/libc.so.6" "malloc" 0x5678 "my_ret_probe" [])]
      (is (map? info))
      (is (= "my_ret_probe" (:name info)))
      (is (= "uretprobe/libc.so.6:malloc" (:section info)))
      (is (= :uretprobe (:type info)))
      (is (= "malloc" (:function info)))
      (is (= 0x5678 (:offset info))))))

;; ============================================================================
;; Library Path Tests
;; ============================================================================

(deftest test-common-library-paths
  (testing "common-library-paths is defined"
    (is (vector? up/common-library-paths))
    (is (pos? (count up/common-library-paths))))

  (testing "common-library-paths contains expected paths"
    (let [paths (set up/common-library-paths)]
      (is (or (contains? paths "/lib/x86_64-linux-gnu")
              (contains? paths "/lib64")
              (contains? paths "/lib/aarch64-linux-gnu"))))))

(deftest test-find-library
  (testing "find-library returns nil for nonexistent library"
    (is (nil? (up/find-library "nonexistent-library-xyz.so.1"))))

  (testing "find-library accepts .so suffix"
    ;; This may or may not find libc depending on system
    (let [result (up/find-library "libc.so.6")]
      (is (or (nil? result) (string? result))))))

(deftest test-find-libc
  (testing "find-libc returns path or nil"
    (let [result (up/find-libc)]
      (is (or (nil? result)
              (and (string? result)
                   (clojure.string/includes? result "libc")))))))

;; ============================================================================
;; Common Functions Tests
;; ============================================================================

(deftest test-common-libc-functions
  (testing "common-libc-functions is defined"
    (is (map? up/common-libc-functions)))

  (testing "common-libc-functions has expected categories"
    (is (contains? up/common-libc-functions :memory))
    (is (contains? up/common-libc-functions :file-io))
    (is (contains? up/common-libc-functions :process))
    (is (contains? up/common-libc-functions :network)))

  (testing "memory functions include malloc and free"
    (let [memory-funcs (set (:memory up/common-libc-functions))]
      (is (contains? memory-funcs "malloc"))
      (is (contains? memory-funcs "free"))
      (is (contains? memory-funcs "calloc")))))

(deftest test-common-crypto-functions
  (testing "common-crypto-functions is defined"
    (is (map? up/common-crypto-functions)))

  (testing "common-crypto-functions has OpenSSL functions"
    (is (contains? up/common-crypto-functions :openssl))
    (let [ssl-funcs (set (:openssl up/common-crypto-functions))]
      (is (contains? ssl-funcs "SSL_connect"))
      (is (contains? ssl-funcs "SSL_read")))))

;; ============================================================================
;; Attachment Info Tests
;; ============================================================================

(deftest test-uprobe-attach-info
  (testing "uprobe-attach-info with numeric offset"
    (let [info (up/uprobe-attach-info "/lib/libc.so.6" 0x1234)]
      (is (map? info))
      (is (= "/lib/libc.so.6" (:binary info)))
      (is (= 0x1234 (:offset info)))
      (is (= :uprobe (:type info)))
      (is (nil? (:function info)))))

  (testing "uprobe-attach-info with PID filter"
    (let [info (up/uprobe-attach-info "/lib/libc.so.6" 0x1234 :pid 1234)]
      (is (= 1234 (:pid info))))))

(deftest test-uretprobe-attach-info
  (testing "uretprobe-attach-info with numeric offset"
    (let [info (up/uretprobe-attach-info "/lib/libc.so.6" 0x5678)]
      (is (map? info))
      (is (= "/lib/libc.so.6" (:binary info)))
      (is (= 0x5678 (:offset info)))
      (is (= :uretprobe (:type info)))))

  (testing "uretprobe-attach-info with PID filter"
    (let [info (up/uretprobe-attach-info "/lib/libc.so.6" 0x5678 :pid 5678)]
      (is (= 5678 (:pid info))))))

;; ============================================================================
;; Symbol Resolution Tests (may require system access)
;; ============================================================================

(deftest test-get-symbol-info
  (testing "get-symbol-info returns nil for nonexistent binary"
    (is (nil? (up/get-symbol-info "/nonexistent/binary" "malloc")))))

(deftest test-list-symbols
  (testing "list-symbols returns empty vector for nonexistent binary"
    (is (= [] (up/list-symbols "/nonexistent/binary")))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-api-completeness
  (testing "All core functions are defined"
    (is (fn? up/uprobe-read-args))
    (is (fn? up/uprobe-prologue))
    (is (fn? up/uretprobe-get-return-value))
    (is (fn? up/build-uprobe-program))
    (is (fn? up/build-uretprobe-program))
    (is (fn? up/uprobe-section-name))
    (is (fn? up/uretprobe-section-name))
    (is (fn? up/make-uprobe-program-info))
    (is (fn? up/make-uretprobe-program-info)))

  (testing "Symbol resolution functions are defined"
    (is (fn? up/resolve-symbol-offset))
    (is (fn? up/get-symbol-info))
    (is (fn? up/list-symbols)))

  (testing "Library path functions are defined"
    (is (fn? up/find-library))
    (is (fn? up/find-libc)))

  (testing "Attachment info functions are defined"
    (is (fn? up/uprobe-attach-info))
    (is (fn? up/uretprobe-attach-info))))

(deftest test-documentation
  (testing "Core functions have docstrings"
    (is (string? (:doc (meta #'up/uprobe-prologue))))
    (is (string? (:doc (meta #'up/uretprobe-get-return-value))))
    (is (string? (:doc (meta #'up/build-uprobe-program))))
    (is (string? (:doc (meta #'up/resolve-symbol-offset))))))

;; ============================================================================
;; Integration Tests
;; ============================================================================

(deftest test-complete-program-assembly
  (testing "Complete uprobe program assembles correctly"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          (up/uprobe-prologue :r9 [:r6 :r7])
                          ;; Get PID
                          (dsl/helper-get-current-pid-tgid)
                          [(dsl/mov-reg :r8 :r0)]
                          ;; Exit
                          [(dsl/mov :r0 0)
                           (dsl/exit-insn)])))]
      (is (bytes? bytecode))
      (is (> (count bytecode) 0))
      (is (zero? (mod (count bytecode) 8))))))

(deftest test-complete-uretprobe-assembly
  (testing "Complete uretprobe program assembles correctly"
    (let [bytecode (dsl/assemble
                    (vec (concat
                          ;; Save context and get return value
                          [(dsl/mov-reg :r9 :r1)]
                          [(up/uretprobe-get-return-value :r1 :r6)]
                          ;; Check if return is NULL
                          [(dsl/jmp-imm :jeq :r6 0 2)]
                          ;; Non-NULL path
                          (dsl/helper-get-current-pid-tgid)
                          [(dsl/mov-reg :r7 :r0)]
                          ;; Exit
                          [(dsl/mov :r0 0)
                           (dsl/exit-insn)])))]
      (is (bytes? bytecode))
      (is (> (count bytecode) 0))
      (is (zero? (mod (count bytecode) 8))))))

;; ============================================================================
;; Architecture-Specific Tests
;; ============================================================================

(deftest test-architecture-awareness
  (testing "Current architecture is detected"
    (is (keyword? arch/current-arch)))

  (testing "Uprobe uses correct pt_regs offsets for architecture"
    ;; Verify that argument reading works for current architecture
    (let [insns (up/uprobe-prologue [:r6 :r7])]
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "Return value offset is valid for current architecture"
    (let [insn (up/uretprobe-get-return-value :r1 :r6)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))
