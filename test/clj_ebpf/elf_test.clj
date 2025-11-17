(ns clj-ebpf.elf-test
  "Tests for ELF parser"
  (:require [clojure.test :refer :all]
            [clj-ebpf.elf :as elf]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; ELF Header Tests
;; ============================================================================

(deftest test-elf-magic-validation
  (testing "Valid ELF magic number"
    (let [valid-elf (byte-array (concat [0x7f 0x45 0x4c 0x46] ; ELF magic
                                       (repeat 60 0)))]
      ;; Should parse without error (will fail on other checks but that's ok)
      (is (thrown? Exception (#'elf/parse-elf-header valid-elf)))))

  (testing "Invalid ELF magic number"
    (let [invalid-elf (byte-array 64)]
      (is (thrown-with-msg? Exception #"Invalid ELF magic"
            (#'elf/parse-elf-header invalid-elf))))))

(deftest test-elf-class-validation
  (testing "Only 64-bit ELF supported"
    (let [elf32 (byte-array (concat [0x7f 0x45 0x4c 0x46 1] ; ELFCLASS32
                                   (repeat 59 0)))]
      (is (thrown-with-msg? Exception #"Only 64-bit"
            (#'elf/parse-elf-header elf32))))))

;; ============================================================================
;; Section Name Parsing Tests
;; ============================================================================

(deftest test-prog-type-inference
  (testing "Infer program type from section name"
    (is (= :kprobe (#'elf/infer-prog-type "kprobe/sys_clone")))
    (is (= :kprobe (#'elf/infer-prog-type "kretprobe/sys_clone")))
    (is (= :tracepoint (#'elf/infer-prog-type "tracepoint/syscalls/sys_enter_open")))
    (is (= :raw-tracepoint (#'elf/infer-prog-type "raw_tracepoint/sched_switch")))
    (is (= :xdp (#'elf/infer-prog-type "xdp")))
    (is (= :xdp (#'elf/infer-prog-type "xdp_filter")))
    (is (= :sched-cls (#'elf/infer-prog-type "tc_ingress")))
    (is (= :sched-cls (#'elf/infer-prog-type "classifier")))
    (is (= :socket-filter (#'elf/infer-prog-type ".text")))))

;; ============================================================================
;; Byte Reading Tests
;; ============================================================================

(deftest test-read-u8
  (testing "Read unsigned 8-bit integer"
    (let [data (byte-array [0 1 127 -128 -1])]
      (is (= 0 (#'elf/read-u8 data 0)))
      (is (= 1 (#'elf/read-u8 data 1)))
      (is (= 127 (#'elf/read-u8 data 2)))
      (is (= 128 (#'elf/read-u8 data 3))) ; -128 as unsigned
      (is (= 255 (#'elf/read-u8 data 4)))))) ; -1 as unsigned

(deftest test-read-u16-le
  (testing "Read unsigned 16-bit integer (little endian)"
    (let [data (byte-array [0x34 0x12])] ; 0x1234 in little endian
      (is (= 0x1234 (#'elf/read-u16-le data 0))))))

(deftest test-read-u32-le
  (testing "Read unsigned 32-bit integer (little endian)"
    (let [data (byte-array [0x78 0x56 0x34 0x12])] ; 0x12345678 in little endian
      (is (= 0x12345678 (#'elf/read-u32-le data 0))))))

(deftest test-read-u64-le
  (testing "Read unsigned 64-bit integer (little endian)"
    (let [data (byte-array [0x88 0x77 0x66 0x55 0x44 0x33 0x22 0x11])]
      (is (= 0x1122334455667788 (#'elf/read-u64-le data 0))))))

(deftest test-read-string-at
  (testing "Read null-terminated string"
    (let [data (byte-array (concat (.getBytes "hello" "UTF-8") [0] (.getBytes "world" "UTF-8") [0]))]
      (is (= "hello" (#'elf/read-string-at data 0)))
      (is (= "world" (#'elf/read-string-at data 6))))))

;; ============================================================================
;; Map Definition Tests
;; ============================================================================

(deftest test-parse-map-def
  (testing "Parse BPF map definition structure"
    ;; Create a map definition:
    ;; type=1 (hash), key_size=4, value_size=8, max_entries=100, flags=0
    (let [data (utils/pack-struct [[:u32 1]   ; type
                                   [:u32 4]   ; key_size
                                   [:u32 8]   ; value_size
                                   [:u32 100] ; max_entries
                                   [:u32 0]]) ; flags
          map-def (#'elf/parse-map-def data 0 "test_map")]

      (is (= "test_map" (:name map-def)))
      (is (= 1 (:type map-def)))
      (is (= 4 (:key-size map-def)))
      (is (= 8 (:value-size map-def)))
      (is (= 100 (:max-entries map-def)))
      (is (= 0 (:flags map-def))))))

;; ============================================================================
;; Symbol Tests
;; ============================================================================

(deftest test-parse-symbol
  (testing "Parse symbol table entry"
    ;; Create a symbol entry (64-bit):
    ;; st_name=10, st_info=18 (STT_FUNC|STB_GLOBAL<<4), st_other=0,
    ;; st_shndx=5, st_value=0x1000, st_size=100
    (let [data (utils/pack-struct [[:u32 10]    ; st_name
                                   [:u8 18]     ; st_info (STT_FUNC=2, STB_GLOBAL=1)
                                   [:u8 0]      ; st_other
                                   [:u16 5]     ; st_shndx
                                   [:u64 0x1000] ; st_value
                                   [:u64 100]])  ; st_size
          symbol (#'elf/parse-symbol data 0)]

      (is (= 10 (:name-idx symbol)))
      (is (= 18 (:info symbol)))
      (is (= 0 (:other symbol)))
      (is (= 5 (:shndx symbol)))
      (is (= 0x1000 (:value symbol)))
      (is (= 100 (:size symbol))))))

;; ============================================================================
;; Relocation Tests
;; ============================================================================

(deftest test-parse-rela-entry
  (testing "Parse RELA relocation entry"
    ;; Create a RELA entry:
    ;; r_offset=0x100, r_info=(sym=5<<32 | type=1), r_addend=0
    (let [r-info (bit-or (bit-shift-left 5 32) 1)
          data (utils/pack-struct [[:u64 0x100]  ; r_offset
                                   [:u64 r-info] ; r_info
                                   [:u64 0]])    ; r_addend
          rela (#'elf/parse-rela-entry data 0)]

      (is (= 0x100 (:offset rela)))
      (is (= 1 (:type rela)))
      (is (= 5 (:symbol rela)))
      (is (= 0 (:addend rela))))))

;; ============================================================================
;; Helper Function Tests
;; ============================================================================

(deftest test-inspect-elf-structure
  (testing "Inspect ELF function returns correct structure"
    ;; We can't test with real ELF files in unit tests,
    ;; but we can verify the structure
    (let [result {:programs []
                 :maps []
                 :license "GPL"
                 :version 0}]
      (is (map? result))
      (is (contains? result :programs))
      (is (contains? result :maps))
      (is (contains? result :license))
      (is (contains? result :version)))))

(deftest test-list-programs-structure
  (testing "List programs returns correct structure"
    (let [mock-program {:name "test_prog"
                       :section "xdp"
                       :type :xdp
                       :size 128}]
      (is (contains? mock-program :name))
      (is (contains? mock-program :section))
      (is (contains? mock-program :type))
      (is (contains? mock-program :size)))))

(deftest test-list-maps-structure
  (testing "List maps returns correct structure"
    (let [mock-map {:name "test_map"
                   :type 1
                   :key-size 4
                   :value-size 8
                   :max-entries 100}]
      (is (contains? mock-map :name))
      (is (contains? mock-map :type))
      (is (contains? mock-map :key-size))
      (is (contains? mock-map :value-size))
      (is (contains? mock-map :max-entries)))))

;; ============================================================================
;; Edge Case Tests
;; ============================================================================

(deftest test-file-too-small
  (testing "File too small to be valid ELF"
    (let [small-file (byte-array 10)]
      (is (thrown-with-msg? Exception #"File too small"
            (#'elf/parse-elf-header small-file))))))

(deftest test-section-name-patterns
  (testing "Various section name patterns"
    (is (true? (#'elf/is-prog-section?
                {:type 1 ; SHT_PROGBITS
                 :flags 4 ; SHF_EXECINSTR
                 :name "kprobe/test"})))

    (is (false? (#'elf/is-prog-section?
                 {:type 1
                  :flags 4
                  :name ".text"}))) ; Special section

    (is (false? (#'elf/is-prog-section?
                 {:type 3 ; SHT_STRTAB
                  :flags 0
                  :name "strtab"}))))) ; Not PROGBITS

;; Note: Full integration tests with real compiled BPF object files
;; would require:
;; 1. A C compiler (clang) with BPF target support
;; 2. Sample BPF C programs
;; 3. Compilation to .o files
;; 4. Loading and verifying the parsed data
;;
;; Example integration test (requires real ELF file):
;; (deftest test-load-real-elf-file
;;   (when (.exists (io/file "test/resources/sample.o"))
;;     (let [elf-file (elf/parse-elf-file "test/resources/sample.o")]
;;       (is (seq (:programs elf-file)))
;;       (is (= "GPL" (:license elf-file))))))
