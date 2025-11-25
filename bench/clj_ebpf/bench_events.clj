(ns clj-ebpf.bench-events
  "Benchmarks for BPF ring buffer and event handling.

   Tests performance of:
   - Ring buffer creation and configuration
   - Event throughput
   - Backpressure handling
   - Consumer patterns"
  (:require [clj-ebpf.bench-core :as bench]
            [clj-ebpf.events :as events]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils]
            [criterium.core :as crit])
  (:import [java.util.concurrent CountDownLatch TimeUnit]))

;; ============================================================================
;; Ring Buffer Creation Benchmarks
;; ============================================================================

(defn bench-ringbuf-creation
  "Benchmark ring buffer creation overhead"
  []
  (println "\n=== Ring Buffer Creation Benchmarks ===")
  (println "Testing ring buffer creation for different sizes\n")

  (let [sizes [[64 "64 KB"]
               [256 "256 KB"]
               [1024 "1 MB"]
               [4096 "4 MB"]]]

    (doseq [[size-kb desc] sizes]
      (let [results (crit/quick-benchmark
                     (let [rb (maps/create-map :ringbuf 0 0 (* size-kb 1024))]
                       (maps/close-map rb))
                     {})
            mean-time (first (:mean results))]
        (println (format "Ring buffer %-8s %s"
                         desc
                         (bench/format-time mean-time)))))))

;; ============================================================================
;; Consumer Setup Benchmarks
;; ============================================================================

(defn bench-consumer-setup
  "Benchmark consumer creation overhead"
  []
  (println "\n=== Consumer Setup Benchmarks ===")
  (println "Testing consumer creation and teardown\n")

  (let [rb (maps/create-map :ringbuf 0 0 (* 256 1024))
        callback (fn [_] nil)]
    (try
      ;; Simple consumer
      (let [results (crit/quick-benchmark
                     (let [consumer (events/create-ringbuf-consumer
                                     {:map rb
                                      :callback callback})]
                       (events/stop-ringbuf-consumer consumer))
                     {})
            mean-time (first (:mean results))]
        (println (format "Simple consumer setup/teardown:     %s"
                         (bench/format-time mean-time))))

      ;; Backpressure consumer
      (let [results (crit/quick-benchmark
                     (let [consumer (events/create-backpressure-consumer
                                     {:map rb
                                      :callback callback
                                      :max-pending 1000})]
                       (events/stop-backpressure-consumer consumer))
                     {})
            mean-time (first (:mean results))]
        (println (format "Backpressure consumer setup/teardown: %s"
                         (bench/format-time mean-time))))
      (finally
        (maps/close-map rb)))))

;; ============================================================================
;; Callback Overhead Benchmarks
;; ============================================================================

(defn bench-callback-overhead
  "Benchmark the overhead of different callback patterns"
  []
  (println "\n=== Callback Pattern Benchmarks ===")
  (println "Testing overhead of different callback implementations\n")

  ;; Simulate callback invocation patterns
  (let [data (byte-array 64)
        counter (atom 0)]

    ;; Simple callback
    (let [results (crit/quick-benchmark
                   ((fn [_] nil) data)
                   {})
          mean-time (first (:mean results))]
      (println (format "No-op callback:           %s"
                       (bench/format-time mean-time))))

    ;; Callback with atom update
    (let [results (crit/quick-benchmark
                   ((fn [_] (swap! counter inc)) data)
                   {})
          mean-time (first (:mean results))]
      (println (format "Atom increment callback:  %s"
                       (bench/format-time mean-time))))

    ;; Callback with parsing
    (let [results (crit/quick-benchmark
                   ((fn [d]
                      (let [seg (utils/bytes->segment d)]
                        {:field1 (utils/segment->int seg)
                         :field2 (utils/segment->long seg)}))
                    data)
                   {})
          mean-time (first (:mean results))]
      (println (format "Parse fields callback:    %s"
                       (bench/format-time mean-time))))

    ;; Callback with event parser
    (let [parser (events/make-event-parser
                  {:event-type [:u32 0]
                   :timestamp [:u64 4]
                   :pid [:u32 12]})
          results (crit/quick-benchmark
                   ((fn [d] (parser d)) data)
                   {})
          mean-time (first (:mean results))]
      (println (format "Event parser callback:    %s"
                       (bench/format-time mean-time))))))

;; ============================================================================
;; Deserialization Benchmarks
;; ============================================================================

(defn bench-deserialization
  "Benchmark event deserialization patterns"
  []
  (println "\n=== Deserialization Benchmarks ===")
  (println "Testing event parsing for different layouts\n")

  (let [data (byte-array 256)]

    ;; Small event (16 bytes)
    (let [parser (events/make-event-parser {:type [:u32 0]
                                            :value [:u64 8]})
          results (crit/quick-benchmark
                   (parser data)
                   {})
          mean-time (first (:mean results))]
      (println (format "Small event (16B, 2 fields):   %s"
                       (bench/format-time mean-time))))

    ;; Medium event (64 bytes)
    (let [parser (events/make-event-parser {:type [:u32 0]
                                            :timestamp [:u64 4]
                                            :pid [:u32 12]
                                            :tid [:u32 16]
                                            :uid [:u32 20]
                                            :comm [:bytes 24 16]
                                            :args [:bytes 40 24]})
          results (crit/quick-benchmark
                   (parser data)
                   {})
          mean-time (first (:mean results))]
      (println (format "Medium event (64B, 7 fields):  %s"
                       (bench/format-time mean-time))))

    ;; Large event (256 bytes)
    (let [parser (events/make-event-parser {:type [:u32 0]
                                            :timestamp [:u64 4]
                                            :pid [:u32 12]
                                            :tid [:u32 16]
                                            :uid [:u32 20]
                                            :gid [:u32 24]
                                            :comm [:bytes 28 16]
                                            :filename [:bytes 44 128]
                                            :args [:bytes 172 64]
                                            :retval [:i32 236]
                                            :flags [:u64 240]})
          results (crit/quick-benchmark
                   (parser data)
                   {})
          mean-time (first (:mean results))]
      (println (format "Large event (256B, 11 fields): %s"
                       (bench/format-time mean-time))))))

;; ============================================================================
;; Queue Throughput Benchmarks
;; ============================================================================

(defn bench-queue-throughput
  "Benchmark internal queue throughput for backpressure consumer"
  []
  (println "\n=== Queue Throughput Benchmarks ===")
  (println "Testing bounded queue performance\n")

  (let [queue (java.util.concurrent.LinkedBlockingQueue. 10000)
        data (byte-array 64)]

    ;; Queue offer throughput
    (let [results (crit/quick-benchmark
                   (.offer queue data)
                   {})
          _ (.clear queue)
          mean-time (first (:mean results))]
      (println (format "Queue offer (unbounded):  %s  (%s)"
                       (bench/format-time mean-time)
                       (bench/format-throughput (/ 1.0 mean-time)))))

    ;; Queue poll throughput
    (.offer queue data)
    (let [results (crit/quick-benchmark
                   (do (.offer queue data)
                       (.poll queue))
                   {})
          mean-time (first (:mean results))]
      (println (format "Queue offer+poll pair:    %s  (%s)"
                       (bench/format-time mean-time)
                       (bench/format-throughput (/ 1.0 mean-time)))))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn run-all-benchmarks
  "Run all event handling benchmarks"
  []
  (println)
  (println "=========================================")
  (println "    BPF Events Performance Benchmarks    ")
  (println "=========================================")
  (println)
  (println "Note: Some benchmarks require root/CAP_BPF capabilities")
  (println)

  ;; These don't require BPF capabilities
  (bench-callback-overhead)
  (bench-deserialization)
  (bench-queue-throughput)

  ;; These require capabilities - wrapped in try/catch
  (try
    (bench-ringbuf-creation)
    (bench-consumer-setup)
    (catch Exception e
      (println "\nSkipping BPF-dependent benchmarks (requires capabilities)")
      (println (str "  Error: " (.getMessage e)))))

  (println)
  (println "Benchmarks complete."))

(defn -main [& args]
  (run-all-benchmarks))
