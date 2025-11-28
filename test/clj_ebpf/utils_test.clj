(ns clj-ebpf.utils-test
  "Tests for utility functions - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.utils :as utils])
  (:import [java.lang.foreign MemorySegment]))

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

(deftest test-segment-operations
  (testing "Integer to/from segment"
    (let [value 42
          seg (utils/int->segment value)
          decoded (utils/segment->int seg)]
      (is (instance? MemorySegment seg))
      (is (= value decoded))))

  (testing "Long to/from segment"
    (let [value 123456789
          seg (utils/long->segment value)
          decoded (utils/segment->long seg)]
      (is (instance? MemorySegment seg))
      (is (= value decoded))))

  (testing "Bytes to/from segment"
    (let [bytes (byte-array [1 2 3 4 5])
          seg (utils/bytes->segment bytes)
          decoded (utils/segment->bytes seg 5)]
      (is (instance? MemorySegment seg))
      (is (= (seq bytes) (seq decoded))))))

(deftest test-string-operations
  (testing "String to/from segment"
    (let [s "Hello, BPF!"
          seg (utils/string->segment s)
          decoded (utils/segment->string seg 100)]
      (is (instance? MemorySegment seg))
      (is (= s decoded)))))

(deftest test-memory-allocation
  (testing "Allocate memory"
    (let [mem (utils/allocate-memory 128)]
      (is (instance? MemorySegment mem))))

  (testing "Zero memory"
    (let [mem (utils/allocate-memory 16)
          ;; Fill with 0xff using MemorySegment API
          _ (.fill mem (unchecked-byte 0xff))
          _ (utils/zero-memory mem 16)]
      (is (every? zero? (seq (utils/segment->bytes mem 16)))))))

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
