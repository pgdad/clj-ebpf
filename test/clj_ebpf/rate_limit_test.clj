(ns clj-ebpf.rate-limit-test
  "Tests for token bucket rate limiting helpers - CI-safe"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.rate-limit :as rl]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.asm :as asm]))

(deftest test-constants
  (testing "Token scale constant is correct"
    (is (= 1000 rl/TOKEN-SCALE)))

  (testing "Time constants are correct"
    (is (= 1000000000 rl/NS-PER-SEC))
    (is (= 1000 rl/NS-PER-US))
    (is (= 1000000 rl/US-PER-SEC))
    (is (= 10000000 rl/MAX-ELAPSED-US)))

  (testing "Config structure offsets are correct"
    (is (= 0 rl/CONFIG-OFF-RATE))
    (is (= 8 rl/CONFIG-OFF-BURST)))

  (testing "Bucket structure offsets are correct"
    (is (= 0 rl/BUCKET-OFF-TOKENS))
    (is (= 8 rl/BUCKET-OFF-LAST-UPDATE))))

(deftest test-build-rate-limit-check
  (testing "build-rate-limit-check generates instruction sequence"
    (let [instrs (vec (rl/build-rate-limit-check 10 0 20 -16 -48 :pass :drop))]
      (is (vector? instrs))
      (is (pos? (count instrs)))
      ;; Should contain a mix of instructions and pseudo-instructions
      (is (some #(or (bytes? %) (map? %)) instrs))))

  (testing "build-rate-limit-check with different config indices"
    (doseq [idx [0 1 2]]
      (let [instrs (rl/build-rate-limit-check 10 idx 20 -16 -48 :pass :drop)]
        (is (pos? (count instrs))))))

  (testing "build-rate-limit-check assembles with labels"
    (let [program (concat
                    ;; Assume key is already set up at stack[-16]
                    (rl/build-rate-limit-check 10 0 20 -16 -48 :pass :drop)
                    [(asm/label :pass)
                     (dsl/mov :r0 2)    ; XDP_PASS
                     (dsl/exit-insn)]
                    [(asm/label :drop)
                     (dsl/mov :r0 1)    ; XDP_DROP
                     (dsl/exit-insn)])
          bytecode (asm/assemble-with-labels program)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-build-simple-rate-limit
  (testing "build-simple-rate-limit generates instruction sequence"
    (let [instrs (vec (rl/build-simple-rate-limit 20 -16 -32 100 200 :pass :drop))]
      (is (vector? instrs))
      (is (pos? (count instrs)))))

  (testing "build-simple-rate-limit with different rates"
    (doseq [[rate burst] [[10 20] [100 200] [1000 2000]]]
      (let [instrs (rl/build-simple-rate-limit 20 -16 -32 rate burst :pass :drop)]
        (is (pos? (count instrs))))))

  (testing "build-simple-rate-limit assembles with labels"
    (let [program (concat
                    ;; Assume key is already set up at stack[-16]
                    (rl/build-simple-rate-limit 20 -16 -32 100 200 :pass :drop)
                    [(asm/label :pass)
                     (dsl/mov :r0 2)    ; XDP_PASS
                     (dsl/exit-insn)]
                    [(asm/label :drop)
                     (dsl/mov :r0 1)    ; XDP_DROP
                     (dsl/exit-insn)])
          bytecode (asm/assemble-with-labels program)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-encode-rate-limit-config
  (testing "encode-rate-limit-config returns 16-byte array"
    (let [buf (rl/encode-rate-limit-config 100 200)]
      (is (bytes? buf))
      (is (= 16 (count buf)))))

  (testing "encode-rate-limit-config scales values correctly"
    (let [buf (rl/encode-rate-limit-config 1 1)
          ;; Read back the values (little-endian 64-bit)
          rate (reduce (fn [acc i]
                         (+ acc (bit-shift-left (bit-and (aget buf i) 0xFF) (* i 8))))
                       0 (range 8))
          burst (reduce (fn [acc i]
                          (+ acc (bit-shift-left (bit-and (aget buf (+ 8 i)) 0xFF) (* i 8))))
                        0 (range 8))]
      (is (= 1000 rate))    ; 1 * TOKEN-SCALE
      (is (= 1000 burst)))) ; 1 * TOKEN-SCALE

  (testing "encode-rate-limit-config with larger values"
    (let [buf (rl/encode-rate-limit-config 100 200)
          rate (reduce (fn [acc i]
                         (+ acc (bit-shift-left (bit-and (aget buf i) 0xFF) (* i 8))))
                       0 (range 8))
          burst (reduce (fn [acc i]
                          (+ acc (bit-shift-left (bit-and (aget buf (+ 8 i)) 0xFF) (* i 8))))
                        0 (range 8))]
      (is (= 100000 rate))   ; 100 * TOKEN-SCALE
      (is (= 200000 burst)))) ; 200 * TOKEN-SCALE
  )

(deftest test-rate-disabled-config
  (testing "rate-disabled-config returns 16-byte array of zeros"
    (let [buf (rl/rate-disabled-config)]
      (is (bytes? buf))
      (is (= 16 (count buf)))
      (is (every? zero? (seq buf))))))

(deftest test-xdp-rate-limit-program
  (testing "Complete XDP program with rate limiting assembles"
    (let [bucket-map-fd 20
          program (concat
                    ;; Load XDP context
                    [(dsl/mov-reg :r6 :r1)]

                    ;; Extract source IP (simplified - assume already done)
                    ;; Store as key at stack[-16]
                    [(dsl/mov :r0 0x0A000001)  ; 10.0.0.1
                     (dsl/stx :w :r10 :r0 -16)]

                    ;; Apply rate limiting: 100 req/s, burst 200
                    (rl/build-simple-rate-limit bucket-map-fd -16 -32 100 200 :pass :drop)

                    ;; Pass label
                    [(asm/label :pass)
                     (dsl/mov :r0 2)    ; XDP_PASS
                     (dsl/exit-insn)]

                    ;; Drop label
                    [(asm/label :drop)
                     (dsl/mov :r0 1)    ; XDP_DROP
                     (dsl/exit-insn)])
          bytecode (asm/assemble-with-labels program)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-tc-rate-limit-with-config
  (testing "TC program with configurable rate limiting assembles"
    (let [config-map-fd 10
          bucket-map-fd 20
          program (concat
                    ;; Save SKB pointer
                    [(dsl/mov-reg :r6 :r1)]

                    ;; Extract source IP (simplified)
                    [(dsl/mov :r0 0x0A000001)
                     (dsl/stx :w :r10 :r0 -16)]

                    ;; Apply configurable rate limiting
                    (rl/build-rate-limit-check config-map-fd 0 bucket-map-fd -16 -48 :pass :drop)

                    ;; Pass
                    [(asm/label :pass)
                     (dsl/mov :r0 0)    ; TC_ACT_OK
                     (dsl/exit-insn)]

                    ;; Drop
                    [(asm/label :drop)
                     (dsl/mov :r0 2)    ; TC_ACT_SHOT
                     (dsl/exit-insn)])
          bytecode (asm/assemble-with-labels program)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))
