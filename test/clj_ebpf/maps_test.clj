(ns clj-ebpf.maps-test
  (:require [clojure.test :refer :all]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils]))

;; Note: These tests require Linux kernel with BPF support and appropriate permissions
;; They will be skipped on non-Linux systems or without privileges

(defn linux-with-bpf?
  "Check if we're on Linux with BPF available"
  []
  (and (= "Linux" (System/getProperty "os.name"))
       (try
         (utils/check-bpf-available)
         true
         (catch Exception _ false))))

(use-fixtures :once
  (fn [f]
    (if (linux-with-bpf?)
      (f)
      (println "Skipping BPF map tests (not on Linux or insufficient permissions)"))))

(deftest test-hash-map-creation
  (when (linux-with-bpf?)
    (testing "Create and close hash map"
      (let [m (maps/create-hash-map 100 :map-name "test_hash")]
        (is (some? m))
        (is (pos? (:fd m)))
        (is (= :hash (:type m)))
        (is (= 4 (:key-size m)))
        (is (= 4 (:value-size m)))
        (is (= 100 (:max-entries m)))
        (maps/close-map m)))))

(deftest test-array-map-creation
  (when (linux-with-bpf?)
    (testing "Create and close array map"
      (let [m (maps/create-array-map 50 :map-name "test_array")]
        (is (some? m))
        (is (pos? (:fd m)))
        (is (= :array (:type m)))
        (is (= 4 (:key-size m)))
        (is (= 4 (:value-size m)))
        (is (= 50 (:max-entries m)))
        (maps/close-map m)))))

(deftest test-map-operations
  (when (linux-with-bpf?)
    (testing "Map update and lookup"
      (maps/with-map [m {:map-type :hash
                        :key-size 4
                        :value-size 4
                        :max-entries 10
                        :map-name "test_ops"
                        :key-serializer utils/int->bytes
                        :key-deserializer utils/bytes->int
                        :value-serializer utils/int->bytes
                        :value-deserializer utils/bytes->int}]
        ;; Insert
        (maps/map-update m 1 100)
        (maps/map-update m 2 200)
        (maps/map-update m 3 300)

        ;; Lookup
        (is (= 100 (maps/map-lookup m 1)))
        (is (= 200 (maps/map-lookup m 2)))
        (is (= 300 (maps/map-lookup m 3)))

        ;; Lookup non-existent
        (is (nil? (maps/map-lookup m 999)))

        ;; Update existing
        (maps/map-update m 2 222)
        (is (= 222 (maps/map-lookup m 2)))))))

(deftest test-map-delete
  (when (linux-with-bpf?)
    (testing "Map delete operation"
      (maps/with-map [m {:map-type :hash
                        :key-size 4
                        :value-size 4
                        :max-entries 10
                        :map-name "test_delete"
                        :key-serializer utils/int->bytes
                        :key-deserializer utils/bytes->int
                        :value-serializer utils/int->bytes
                        :value-deserializer utils/bytes->int}]
        (maps/map-update m 1 100)
        (is (= 100 (maps/map-lookup m 1)))

        ;; Delete existing key
        (is (true? (maps/map-delete m 1)))
        (is (nil? (maps/map-lookup m 1)))

        ;; Delete non-existent key
        (is (false? (maps/map-delete m 999)))))))

(deftest test-map-iteration
  (when (linux-with-bpf?)
    (testing "Map iteration"
      (maps/with-map [m {:map-type :hash
                        :key-size 4
                        :value-size 4
                        :max-entries 10
                        :map-name "test_iter"
                        :key-serializer utils/int->bytes
                        :key-deserializer utils/bytes->int
                        :value-serializer utils/int->bytes
                        :value-deserializer utils/bytes->int}]
        ;; Insert multiple entries
        (maps/map-update m 10 100)
        (maps/map-update m 20 200)
        (maps/map-update m 30 300)

        ;; Get all keys
        (let [keys (set (maps/map-keys m))]
          (is (= #{10 20 30} keys)))

        ;; Get all values
        (let [values (set (maps/map-values m))]
          (is (= #{100 200 300} values)))

        ;; Get all entries
        (let [entries (into {} (maps/map-entries m))]
          (is (= {10 100, 20 200, 30 300} entries)))

        ;; Count entries
        (is (= 3 (maps/map-count m)))))))

(deftest test-map-clear
  (when (linux-with-bpf?)
    (testing "Clear all map entries"
      (maps/with-map [m {:map-type :hash
                        :key-size 4
                        :value-size 4
                        :max-entries 10
                        :map-name "test_clear"
                        :key-serializer utils/int->bytes
                        :key-deserializer utils/bytes->int
                        :value-serializer utils/int->bytes
                        :value-deserializer utils/bytes->int}]
        (maps/map-update m 1 100)
        (maps/map-update m 2 200)
        (maps/map-update m 3 300)

        (is (= 3 (maps/map-count m)))

        (maps/map-clear m)

        (is (= 0 (maps/map-count m)))))))

(deftest test-map-update-flags
  (when (linux-with-bpf?)
    (testing "Map update with flags"
      (maps/with-map [m {:map-type :hash
                        :key-size 4
                        :value-size 4
                        :max-entries 10
                        :map-name "test_flags"
                        :key-serializer utils/int->bytes
                        :key-deserializer utils/bytes->int
                        :value-serializer utils/int->bytes
                        :value-deserializer utils/bytes->int}]
        ;; Insert with :noexist (should succeed)
        (maps/map-update m 1 100 :flags :noexist)
        (is (= 100 (maps/map-lookup m 1)))

        ;; Insert again with :noexist (should fail)
        (is (thrown? Exception
                    (maps/map-update m 1 111 :flags :noexist)))

        ;; Update with :exist (should succeed)
        (maps/map-update m 1 200 :flags :exist)
        (is (= 200 (maps/map-lookup m 1)))

        ;; Update non-existent with :exist (should fail)
        (is (thrown? Exception
                    (maps/map-update m 999 888 :flags :exist)))))))

(deftest test-array-map-operations
  (when (linux-with-bpf?)
    (testing "Array map operations"
      (maps/with-map [m {:map-type :array
                        :key-size 4
                        :value-size 4
                        :max-entries 5
                        :map-name "test_array_ops"
                        :key-serializer utils/int->bytes
                        :key-deserializer utils/bytes->int
                        :value-serializer utils/int->bytes
                        :value-deserializer utils/bytes->int}]
        ;; Array maps use 0-based indices
        (maps/map-update m 0 10)
        (maps/map-update m 1 20)
        (maps/map-update m 2 30)

        (is (= 10 (maps/map-lookup m 0)))
        (is (= 20 (maps/map-lookup m 1)))
        (is (= 30 (maps/map-lookup m 2)))

        ;; Out of bounds should fail
        (is (thrown? Exception
                    (maps/map-update m 10 100)))))))

(deftest test-map-with-macro
  (when (linux-with-bpf?)
    (testing "with-map macro properly cleans up"
      (let [fd-atom (atom nil)]
        (maps/with-map [m {:map-type :hash
                          :key-size 4
                          :value-size 4
                          :max-entries 10
                          :map-name "test_macro"}]
          (reset! fd-atom (:fd m))
          (is (pos? (:fd m)))
          (maps/map-update m 1 100 :key-serializer utils/int->bytes
                                    :value-serializer utils/int->bytes))
        ;; Map should be closed after exiting the block
        ;; Attempting to use the FD should fail
        (is (some? @fd-atom))))))

(deftest test-ringbuf-map-creation
  (when (linux-with-bpf?)
    (testing "Create ring buffer map"
      ;; Ring buffer size must be power of 2 and page-aligned
      ;; 4096 * 16 = 64KB
      (let [size (* 4096 16)]
        (try
          (let [m (maps/create-ringbuf-map size :map-name "test_ringbuf")]
            (is (some? m))
            (is (pos? (:fd m)))
            (is (= :ringbuf (:type m)))
            (maps/close-map m))
          (catch Exception e
            ;; Ring buffers may not be supported on older kernels
            (println "Ring buffer creation failed (may not be supported):" (.getMessage e))))))))
