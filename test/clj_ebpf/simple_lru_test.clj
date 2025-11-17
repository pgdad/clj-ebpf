(ns clj-ebpf.simple-lru-test
  (:require [clojure.test :refer :all]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.constants :as const]
            [clj-ebpf.utils :as utils]))

(defn linux-with-bpf?
  []
  (and (= "Linux" (System/getProperty "os.name"))
       (try (utils/check-bpf-available) true
            (catch Exception _ false))))

(deftest test-lru-direct-create
  (when (linux-with-bpf?)
    (testing "Create LRU map directly via syscall"
      (let [fd (syscall/map-create
                 {:map-type :lru-hash
                  :key-size 4
                  :value-size 4
                  :max-entries 10
                  :map-flags 0
                  :map-name "direct_lru"})]
        (is (pos? fd) "FD should be positive")
        (syscall/close-fd fd)))))

(deftest test-lru-via-helper
  (when (linux-with-bpf?)
    (testing "Create LRU map via helper function"
      (let [m (maps/create-lru-hash-map 10 :map-name "helper_lru")]
        (is (some? m))
        (is (pos? (:fd m)))
        (maps/close-map m)))))

(deftest test-lru-with-map-macro
  (when (linux-with-bpf?)
    (testing "Create LRU map with with-map macro"
      (maps/with-map [m {:map-type :lru-hash
                        :key-size 4
                        :value-size 4
                        :max-entries 10
                        :map-name "macro_lru"
                        :key-serializer utils/int->bytes
                        :key-deserializer utils/bytes->int
                        :value-serializer utils/int->bytes
                        :value-deserializer utils/bytes->int}]
        (is (some? m))
        (is (pos? (:fd m)))
        (is (= :lru-hash (:type m)))))))

(deftest test-lru-basic-operations
  (when (linux-with-bpf?)
    (testing "Basic operations on LRU map"
      (let [m (maps/create-lru-hash-map 10 :map-name "ops_lru")]
        (try
          (maps/map-update m 1 100)
          (is (= 100 (maps/map-lookup m 1)))
          (finally
            (maps/close-map m)))))))
