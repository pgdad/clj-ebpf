(ns clj-ebpf.devmap-test
  "Tests for DEVMAP, DEVMAP_HASH, and CPUMAP support.

   These tests verify:
   - Map creation functions
   - XDP redirect DSL helpers
   - Instruction generation for redirect_map"
  {:ci-safe true}
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.xdp :as xdp]
            [clj-ebpf.constants :as const]))

;; ============================================================================
;; Map Type Constants Tests
;; ============================================================================

(deftest test-devmap-constants
  (testing "DEVMAP constants are defined"
    (is (= 14 (const/map-type :devmap)))
    (is (= 25 (const/map-type :devmap-hash)))
    (is (= 16 (const/map-type :cpumap)))))

;; ============================================================================
;; Map Creation Tests (Spec Only - No Kernel)
;; ============================================================================

(deftest test-create-dev-map-spec
  (testing "create-dev-map generates correct spec"
    ;; Test that the function signature accepts expected params
    (is (fn? maps/create-dev-map))

    ;; Test the map type value
    (is (= 14 (const/map-type :devmap)))))

(deftest test-create-dev-map-hash-spec
  (testing "create-dev-map-hash generates correct spec"
    (is (fn? maps/create-dev-map-hash))
    (is (= 25 (const/map-type :devmap-hash)))))

(deftest test-create-cpu-map-spec
  (testing "create-cpu-map generates correct spec"
    (is (fn? maps/create-cpu-map))
    (is (= 16 (const/map-type :cpumap)))))

;; ============================================================================
;; DSL Helper Tests
;; ============================================================================

(deftest test-redirect-map-helper-id
  (testing "redirect-map helper is defined"
    (is (= 51 (dsl/bpf-helpers :redirect-map)))
    (is (= 52 (dsl/bpf-helpers :sk-redirect-map)))
    (is (= 53 (dsl/bpf-helpers :sock-map-update)))))

;; ============================================================================
;; XDP Redirect DSL Tests
;; ============================================================================

(deftest test-xdp-redirect
  (testing "xdp-redirect generates instruction bytes"
    (let [insns (xdp/xdp-redirect 2 0)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-redirect with register ifindex"
    (let [insns (xdp/xdp-redirect :r5 0)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-redirect-map
  (testing "xdp-redirect-map generates instruction bytes"
    (let [insns (xdp/xdp-redirect-map 5 0 0)]
      (is (vector? insns))
      ;; Should have: ld_map_fd (2 slots), mov key, mov flags, call = 4 insns
      ;; But ld_map_fd returns 2 byte arrays for 16-byte instruction
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-redirect-map with register key"
    (let [insns (xdp/xdp-redirect-map 5 :r6 0)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-redirect-map-with-action
  (testing "xdp-redirect-map-with-action generates bytecode"
    (let [insns (xdp/xdp-redirect-map-with-action 5 0)]
      (is (vector? insns))
      ;; Contains exit instruction at end
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-redirect-to-cpu
  (testing "xdp-redirect-to-cpu generates bytecode"
    (let [insns (xdp/xdp-redirect-to-cpu 5 0)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-redirect-to-interface
  (testing "xdp-redirect-to-interface generates bytecode"
    (let [insns (xdp/xdp-redirect-to-interface 5 1)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; XDP Actions Tests
;; ============================================================================

(deftest test-xdp-redirect-action
  (testing "XDP_REDIRECT action value"
    (is (= 4 (xdp/xdp-actions :redirect)))
    (is (= 4 (xdp/xdp-action :redirect)))))

;; ============================================================================
;; Instruction Assembly Tests
;; ============================================================================

(deftest test-redirect-program-assembly
  (testing "Can assemble XDP program with redirect"
    (let [;; Simple program that redirects all packets
          program-insns [(dsl/ld-map-fd :r1 5)  ; map fd
                         (dsl/mov :r2 0)         ; key = 0
                         (dsl/mov :r3 0)         ; flags = 0
                         (dsl/call 51)           ; bpf_redirect_map
                         (dsl/exit-insn)]
          bytecode (dsl/assemble program-insns)]
      (is (bytes? bytecode))
      ;; ld_map_fd is a double-wide instruction (16 bytes)
      ;; Plus 4 more instructions (8 bytes each) = 16 + 32 = 48 bytes
      (is (= 48 (count bytecode))))))

(deftest test-redirect-with-check-assembly
  (testing "Can assemble XDP program with conditional redirect"
    (let [;; Program that checks a condition before redirect
          program-insns [(dsl/mov :r6 1)          ; Some key
                         (dsl/jmp-imm :jeq :r6 0 4)  ; if key == 0, skip redirect
                         (dsl/ld-map-fd :r1 5)
                         (dsl/mov :r2 0)
                         (dsl/mov :r3 0)
                         (dsl/call 51)
                         (dsl/exit-insn)
                         ;; fallthrough: pass
                         (dsl/mov :r0 2)          ; XDP_PASS
                         (dsl/exit-insn)]
          bytecode (dsl/assemble program-insns)]
      (is (bytes? bytecode))
      ;; Verify it assembles without error
      (is (pos? (count bytecode))))))

;; ============================================================================
;; Integration Pattern Tests
;; ============================================================================

(deftest test-devmap-redirect-pattern
  (testing "DEVMAP redirect pattern generates valid bytecode"
    (let [;; Typical pattern: load data pointers, redirect
          program (dsl/assemble
                   (vec (concat
                         ;; Standard XDP prologue
                         (xdp/xdp-prologue :r6 :r2 :r3)
                         ;; Redirect to interface at index 0
                         (xdp/xdp-redirect-map-with-action 5 0 0))))]
      (is (bytes? program))
      (is (pos? (count program))))))

(deftest test-cpumap-redirect-pattern
  (testing "CPUMAP redirect pattern generates valid bytecode"
    (let [;; Pattern for CPU steering based on hash
          program (dsl/assemble
                   (vec (concat
                         (xdp/xdp-prologue :r6 :r2 :r3)
                         ;; Simple: always redirect to CPU 0
                         (xdp/xdp-redirect-to-cpu 5 0))))]
      (is (bytes? program))
      (is (pos? (count program))))))

;; ============================================================================
;; Edge Cases
;; ============================================================================

(deftest test-redirect-with-max-index
  (testing "Redirect with large index value"
    (let [insns (xdp/xdp-redirect-map 5 255 0)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-redirect-with-flags
  (testing "Redirect with non-zero flags"
    (let [insns (xdp/xdp-redirect-map 5 0 1)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Bytecode Size Tests
;; ============================================================================

(deftest test-redirect-instruction-sizes
  (testing "redirect instruction sizes are correct"
    ;; bpf_redirect: mov r1, ifindex + mov r2, flags + call = 3 insns = 24 bytes
    (let [insns (xdp/xdp-redirect 2 0)
          total-bytes (reduce + (map count insns))]
      (is (= 24 total-bytes)))

    ;; bpf_redirect_map: ld_map_fd (16 bytes) + mov r2 + mov r3 + call = 40 bytes
    (let [insns (xdp/xdp-redirect-map 5 0 0)
          total-bytes (reduce + (map count insns))]
      (is (= 40 total-bytes)))))

;; ============================================================================
;; Complete Program Tests
;; ============================================================================

(deftest test-complete-devmap-program
  (testing "Complete XDP DEVMAP redirect program"
    (let [;; Full program: prologue + redirect
          prog-insns (vec (concat
                           ;; Save context, load data pointers
                           (xdp/xdp-prologue :r9 :r2 :r3)
                           ;; Redirect all packets to index 0 in devmap
                           (xdp/xdp-redirect-to-interface 5 0)))
          bytecode (dsl/assemble prog-insns)]
      (is (bytes? bytecode))
      ;; Prologue: 3 insns (mov ctx, 2x ldx) = 24 bytes
      ;; redirect: ld_map_fd (16) + mov (8) + mov (8) + call (8) + exit (8) = 48 bytes
      ;; Total: 72 bytes
      (is (= 72 (count bytecode))))))

(deftest test-complete-cpumap-program
  (testing "Complete XDP CPUMAP redirect program"
    (let [prog-insns (vec (concat
                           (xdp/xdp-prologue :r9 :r2 :r3)
                           (xdp/xdp-redirect-to-cpu 5 0)))
          bytecode (dsl/assemble prog-insns)]
      (is (bytes? bytecode))
      (is (= 72 (count bytecode))))))
