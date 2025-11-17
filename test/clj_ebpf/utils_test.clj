(ns clj-ebpf.utils-test
  (:require [clojure.test :refer :all]
            [clj-ebpf.utils :as utils])
  (:import [com.sun.jna Pointer Memory]))

(deftest test-integer-encoding
  (testing "32-bit integer encoding/decoding"
    (let [value 12345
          bytes (utils/int->bytes value)
          decoded (utils/bytes->int bytes)]
      (is (= 4 (count bytes)))
      (is (= value decoded))))

  (testing "64-bit long encoding/decoding"
    (let [value 9876543210
          bytes (utils/long->bytes value)
          decoded (utils/bytes->long bytes)]
      (is (= 8 (count bytes)))
      (is (= value decoded))))

  (testing "16-bit short encoding/decoding"
    (let [value 1234
          bytes (utils/short->bytes value)
          decoded (utils/bytes->short bytes)]
      (is (= 2 (count bytes)))
      (is (= value decoded)))))

(deftest test-pointer-operations
  (testing "Integer to/from pointer"
    (let [value 42
          ptr (utils/int->pointer value)
          decoded (utils/pointer->int ptr)]
      (is (instance? Memory ptr))
      (is (= value decoded))))

  (testing "Long to/from pointer"
    (let [value 123456789
          ptr (utils/long->pointer value)
          decoded (utils/pointer->long ptr)]
      (is (instance? Memory ptr))
      (is (= value decoded))))

  (testing "Bytes to/from pointer"
    (let [bytes (byte-array [1 2 3 4 5])
          ptr (utils/bytes->pointer bytes)
          decoded (utils/pointer->bytes ptr 5)]
      (is (instance? Memory ptr))
      (is (= (seq bytes) (seq decoded))))))

(deftest test-string-operations
  (testing "String to/from pointer"
    (let [s "Hello, BPF!"
          ptr (utils/string->pointer s)
          decoded (utils/pointer->string ptr 100)]
      (is (instance? Memory ptr))
      (is (= s decoded)))))

(deftest test-memory-allocation
  (testing "Allocate memory"
    (let [mem (utils/allocate-memory 128)]
      (is (instance? Memory mem))))

  (testing "Zero memory"
    (let [mem (utils/allocate-memory 16)
          _ (doseq [i (range 16)] (.setByte mem i (byte 0xff)))
          _ (utils/zero-memory mem 16)]
      (is (every? zero? (seq (utils/pointer->bytes mem 16)))))))

(deftest test-struct-packing
  (testing "Pack struct"
    (let [packed (utils/pack-struct [[:u8 5]
                                     [:u16 1000]
                                     [:u32 100000]
                                     [:u64 10000000000]])]
      (is (= (+ 1 2 4 8) (count packed)))))

  (testing "Unpack struct"
    (let [packed (utils/pack-struct [[:u8 5]
                                     [:u16 1000]
                                     [:u32 100000]
                                     [:u64 10000000000]])
          unpacked (utils/unpack-struct packed [:u8 :u16 :u32 :u64])]
      (is (= [5 1000 100000 10000000000] unpacked))))

  (testing "Round-trip struct packing"
    (let [values [[:u32 123] [:u32 456] [:u64 789]]
          packed (utils/pack-struct values)
          unpacked (utils/unpack-struct packed [:u32 :u32 :u64])]
      (is (= [123 456 789] unpacked)))))

(deftest test-kernel-version
  (testing "Parse kernel version"
    (is (= 0x050f00 (utils/parse-kernel-version "5.15.0")))
    (is (= 0x041200 (utils/parse-kernel-version "4.18.0")))
    (is (= 0x060102 (utils/parse-kernel-version "6.1.2"))))

  (testing "Get kernel version (if on Linux)"
    (when (= "Linux" (System/getProperty "os.name"))
      (let [version (utils/get-kernel-version)]
        (is (number? version))
        (is (pos? version))))))

(deftest test-hex-dump
  (testing "Hex dump of bytes"
    (let [bytes (byte-array (range 32))
          dump (utils/hex-dump bytes)]
      (is (string? dump))
      (is (not (empty? dump))))))

(deftest test-endianness
  (testing "Host endianness check"
    (is (boolean? (utils/host-endian?)))))
