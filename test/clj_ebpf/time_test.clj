(ns clj-ebpf.time-test
  "Tests for time and random number helpers - CI-safe"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.time :as t]
            [clj-ebpf.dsl :as dsl]))

(deftest test-constants
  (testing "BPF helper function IDs are correct"
    (is (= 5 t/BPF-FUNC-ktime-get-ns))
    (is (= 7 t/BPF-FUNC-get-prandom-u32))
    (is (= 125 t/BPF-FUNC-ktime-get-boot-ns))
    (is (= 190 t/BPF-FUNC-ktime-get-coarse-ns))
    (is (= 208 t/BPF-FUNC-ktime-get-tai-ns))
    (is (= 118 t/BPF-FUNC-jiffies64))))

(deftest test-time-helpers
  (testing "build-ktime-get-ns generates 1 instruction"
    (let [instrs (t/build-ktime-get-ns)]
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs)))))

  (testing "build-ktime-get-boot-ns generates 1 instruction"
    (let [instrs (t/build-ktime-get-boot-ns)]
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs)))))

  (testing "build-ktime-get-coarse-ns generates 1 instruction"
    (let [instrs (t/build-ktime-get-coarse-ns)]
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs)))))

  (testing "build-ktime-get-tai-ns generates 1 instruction"
    (let [instrs (t/build-ktime-get-tai-ns)]
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs)))))

  (testing "build-jiffies64 generates 1 instruction"
    (let [instrs (t/build-jiffies64)]
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs))))))

(deftest test-random-helpers
  (testing "build-get-prandom-u32 generates 1 instruction"
    (let [instrs (t/build-get-prandom-u32)]
      (is (= 1 (count instrs)))
      (is (bytes? (first instrs)))))

  (testing "build-random-mod generates 2 instructions"
    (let [instrs (t/build-random-mod 100)]
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-random-mod with different moduli"
    (doseq [n [2 4 10 100 1000]]
      (let [instrs (t/build-random-mod n)]
        (is (= 2 (count instrs))))))

  (testing "build-random-weighted-select generates 2 instructions"
    (let [instrs (t/build-random-weighted-select)]
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-convenience-patterns
  (testing "build-store-timestamp generates 2 instructions"
    (let [instrs (t/build-store-timestamp -16)]
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-load-elapsed-ns generates 4 instructions"
    (let [instrs (t/build-load-elapsed-ns -16 :r1)]
      (is (= 4 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-update-timestamp generates 2 instructions"
    (let [instrs (t/build-update-timestamp :r9 8)]
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-random-percentage generates 2 instructions"
    (let [instrs (t/build-random-percentage)]
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs))))

  (testing "build-random-bool generates 2 instructions"
    (let [instrs (t/build-random-bool)]
      (is (= 2 (count instrs)))
      (is (every? bytes? instrs)))))

(deftest test-connection-tracking-pattern
  (testing "Connection tracking timestamp pattern assembles"
    (let [program (concat
                    ;; On new connection: store both created_ns and last_seen_ns
                    (t/build-store-timestamp -24)  ; created_ns at stack[-24]
                    (t/build-store-timestamp -32)  ; last_seen_ns at stack[-32]
                    [(dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 2 + 2 + 1 = 5 instructions = 40 bytes
      (is (= 40 (count bytecode))))))

(deftest test-elapsed-time-pattern
  (testing "Elapsed time calculation assembles"
    (let [program (concat
                    ;; Calculate elapsed time since stored timestamp
                    (t/build-load-elapsed-ns -16 :r1)
                    ;; r1 now contains elapsed nanoseconds
                    ;; Check if more than 1 second (1e9 ns)
                    ;; For testing, just exit with the result
                    [(dsl/mov-reg :r0 :r1)
                     (dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 4 + 1 + 1 = 6 instructions = 48 bytes
      (is (= 48 (count bytecode))))))

(deftest test-weighted-load-balancing-pattern
  (testing "Weighted load balancing pattern assembles"
    (let [program (concat
                    ;; Get random percentage
                    (t/build-random-weighted-select)
                    ;; r0 now in [0, 99]
                    ;; Simulate checking against cumulative weights
                    ;; Backend 0: 30%, Backend 1: 50%, Backend 2: 20%
                    ;; Cumulative: 30, 80, 100
                    [(dsl/jmp-imm :jlt :r0 30 2)   ; if r0 < 30, select backend 0
                     (dsl/jmp-imm :jlt :r0 80 1)   ; if r0 < 80, select backend 1
                     ;; else select backend 2
                     (dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 2 + 1 + 1 + 1 = 5 instructions = 40 bytes
      (is (= 40 (count bytecode))))))

(deftest test-rate-limiting-time-delta
  (testing "Rate limiting time delta pattern assembles"
    (let [program (concat
                    ;; Get current time
                    (t/build-ktime-get-ns)
                    ;; Save as 'now'
                    [(dsl/mov-reg :r1 :r0)]
                    ;; Load last_update from bucket (assume r9 points to bucket)
                    [(dsl/ldx :dw :r2 :r9 8)]
                    ;; Calculate elapsed = now - last_update
                    [(dsl/sub-reg :r1 :r2)]
                    ;; r1 now contains elapsed_ns
                    [(dsl/exit-insn)])
          bytecode (dsl/assemble program)]
      (is (bytes? bytecode))
      ;; 1 + 1 + 1 + 1 + 1 = 5 instructions = 40 bytes
      (is (= 40 (count bytecode))))))
