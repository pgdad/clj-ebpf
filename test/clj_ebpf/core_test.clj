(ns clj-ebpf.core-test
  (:require [clojure.test :refer :all]
            [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]))

(defn linux-with-bpf?
  "Check if we're on Linux with BPF available"
  []
  (and (= "Linux" (System/getProperty "os.name"))
       (try
         (utils/check-bpf-available)
         true
         (catch Exception _ false))))

(deftest test-version
  (testing "Version string"
    (is (string? (bpf/version)))
    (is (not (empty? (bpf/version))))))

(deftest test-init
  (when (linux-with-bpf?)
    (testing "Initialize clj-ebpf"
      (let [checks (bpf/init!)]
        (is (map? checks))
        (is (contains? checks :kernel-version))
        (is (contains? checks :bpf-fs-mounted))
        (is (number? (:kernel-version checks)))
        (is (boolean? (:bpf-fs-mounted checks)))))))

(deftest test-constants-exported
  (testing "Constants are exported"
    (is (map? bpf/bpf-cmd))
    (is (map? bpf/map-type))
    (is (map? bpf/prog-type))
    (is (map? bpf/attach-type))))

(deftest test-map-api-exported
  (testing "Map API is exported"
    (is (fn? bpf/create-map))
    (is (fn? bpf/close-map))
    (is (fn? bpf/map-lookup))
    (is (fn? bpf/map-update))
    (is (fn? bpf/map-delete))
    (is (fn? bpf/create-hash-map))
    (is (fn? bpf/create-array-map))))

(deftest test-program-api-exported
  (testing "Program API is exported"
    (is (fn? bpf/load-program))
    (is (fn? bpf/close-program))
    (is (fn? bpf/attach-kprobe))
    (is (fn? bpf/attach-kretprobe))
    (is (fn? bpf/attach-tracepoint))))

(deftest test-events-api-exported
  (testing "Events API is exported"
    (is (fn? bpf/create-ringbuf-consumer))
    (is (fn? bpf/start-ringbuf-consumer))
    (is (fn? bpf/stop-ringbuf-consumer))))

(deftest test-utils-api-exported
  (testing "Utils API is exported"
    (is (fn? bpf/check-bpf-available))
    (is (fn? bpf/get-kernel-version))
    (is (fn? bpf/bpf-fs-mounted?))))

(deftest test-run-example
  (when (linux-with-bpf?)
    (testing "Run example successfully"
      ;; This should not throw
      (is (nil? (bpf/run-example))))))
