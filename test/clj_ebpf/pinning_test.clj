(ns clj-ebpf.pinning-test
  "Tests for BPF object pinning to filesystem"
  (:require [clojure.test :refer :all]
            [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils])
  (:import [java.io File]))

(def test-pin-path "/sys/fs/bpf/clj-ebpf-test")

(defn linux-with-bpf?
  "Check if we're on Linux with BPF available"
  []
  (and (= "Linux" (System/getProperty "os.name"))
       (try
         (utils/check-bpf-available)
         true
         (catch Exception _ false))))

(defn bpf-fs-available?
  "Check if BPF filesystem is mounted and writable"
  []
  (and (.exists (File. "/sys/fs/bpf"))
       (.canWrite (File. "/sys/fs/bpf"))))

(defn cleanup-test-pins
  "Clean up any test pin files"
  []
  (try
    (.delete (File. (str test-pin-path "_map")))
    (.delete (File. (str test-pin-path "_prog")))
    (catch Exception _ nil)))

(use-fixtures :each
  (fn [f]
    (cleanup-test-pins)
    (f)
    (cleanup-test-pins)))

;; ============================================================================
;; Map Pinning Tests
;; ============================================================================

(deftest test-map-pinning
  (when (and (linux-with-bpf?) (bpf-fs-available?))
    (testing "Pin and retrieve BPF map"
      (let [pin-path (str test-pin-path "_map")]
        ;; Create a map and pin it
        (maps/with-map [m {:map-type :hash
                          :key-size 4
                          :value-size 4
                          :max-entries 10
                          :map-name "pinned_map"
                          :key-serializer utils/int->bytes
                          :key-deserializer utils/bytes->int
                          :value-serializer utils/int->bytes
                          :value-deserializer utils/bytes->int}]
          ;; Add some data
          (maps/map-update m 1 100)
          (maps/map-update m 2 200)

          ;; Pin the map
          (syscall/obj-pin pin-path (:fd m))
          (is (.exists (File. pin-path)) "Pin file should exist"))

        ;; Map is now closed, but we can retrieve it from the pin
        (let [fd (syscall/obj-get pin-path)
              m (maps/map-from-fd fd
                                  :key-size 4
                                  :value-size 4
                                  :key-serializer utils/int->bytes
                                  :key-deserializer utils/bytes->int
                                  :value-serializer utils/int->bytes
                                  :value-deserializer utils/bytes->int)]
          (is (pos? fd) "Retrieved FD should be valid")

          ;; Verify data persisted
          (is (= 100 (maps/map-lookup m 1)) "Data should persist in pinned map")
          (is (= 200 (maps/map-lookup m 2)) "Data should persist in pinned map")

          (maps/close-map m))

        ;; Cleanup
        (.delete (File. pin-path))))))

;; ============================================================================
;; Program Pinning Tests
;; ============================================================================

(def simple-bpf-bytecode
  (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00   ; r0 = 0
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

(deftest test-program-pinning
  (when (and (linux-with-bpf?) (bpf-fs-available?))
    (testing "Pin and retrieve BPF program"
      (let [pin-path (str test-pin-path "_prog")]
        ;; Create a program and pin it
        (bpf/with-program [prog {:prog-type :raw-tracepoint
                                 :insns simple-bpf-bytecode
                                 :license "GPL"
                                 :prog-name "pinned_prog"}]
          ;; Pin the program
          (syscall/obj-pin pin-path (:fd prog))
          (is (.exists (File. pin-path)) "Pin file should exist"))

        ;; Program is now closed, but we can retrieve it from the pin
        (let [fd (syscall/obj-get pin-path)]
          (is (pos? fd) "Retrieved FD should be valid")
          (syscall/close-fd fd))

        ;; Cleanup
        (.delete (File. pin-path))))))

(deftest test-pin-path-validation
  (when (and (linux-with-bpf?) (bpf-fs-available?))
    (testing "Invalid pin paths should fail"
      (maps/with-map [m {:map-type :hash
                        :key-size 4
                        :value-size 4
                        :max-entries 10
                        :map-name "test_invalid_pin"}]
        ;; Try to pin to invalid path
        (is (thrown? Exception
                    (syscall/obj-pin "/tmp/invalid_bpf_pin" (:fd m)))
            "Should fail when pinning outside /sys/fs/bpf")))))

(deftest test-double-pin-fails
  (when (and (linux-with-bpf?) (bpf-fs-available?))
    (testing "Pinning to existing path should fail"
      (let [pin-path (str test-pin-path "_double")]
        (maps/with-map [m1 {:map-type :hash
                           :key-size 4
                           :value-size 4
                           :max-entries 10
                           :map-name "test_pin1"}]
          ;; First pin succeeds
          (syscall/obj-pin pin-path (:fd m1))
          (is (.exists (File. pin-path)))

          (maps/with-map [m2 {:map-type :hash
                             :key-size 4
                             :value-size 4
                             :max-entries 10
                             :map-name "test_pin2"}]
            ;; Second pin to same path should fail
            (is (thrown? Exception
                        (syscall/obj-pin pin-path (:fd m2)))
                "Should fail when pin path already exists")))

        ;; Cleanup
        (.delete (File. pin-path))))))
