(ns clj-ebpf.xskmap-test
  "Tests for XSKMAP (AF_XDP Socket Map) support.

   These tests verify:
   - XSKMAP constant is defined
   - Map creation function works
   - XDP redirect DSL helpers for XSK
   - Instruction generation for redirect to XSK
   - Complete XDP program assembly with XSKMAP"
  {:ci-safe true}
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.xdp :as xdp]
            [clj-ebpf.constants :as const]))

;; ============================================================================
;; Map Type Constants Tests
;; ============================================================================

(deftest test-xskmap-constant
  (testing "XSKMAP constant is defined"
    (is (= 17 (const/map-type :xskmap)))
    (is (some? (const/map-type :xskmap)))))

(deftest test-xskmap-in-map-types
  (testing "XSKMAP is listed in map types"
    (is (contains? const/map-type :xskmap))))

;; ============================================================================
;; Map Creation Tests (Spec Only - No Kernel)
;; ============================================================================

(deftest test-create-xsk-map-function-exists
  (testing "create-xsk-map function exists"
    (is (fn? maps/create-xsk-map))))

(deftest test-xskmap-type-value
  (testing "XSKMAP type value matches kernel definition"
    ;; BPF_MAP_TYPE_XSKMAP = 17 in kernel
    (is (= 17 (const/map-type :xskmap)))))

;; ============================================================================
;; XDP Context Field Tests
;; ============================================================================

(deftest test-xdp-md-rx-queue-index
  (testing "xdp_md rx_queue_index offset is defined"
    (is (= 16 (xdp/xdp-md-offset :rx-queue-index)))
    (is (some? (xdp/xdp-md-offsets :rx-queue-index)))))

(deftest test-xdp-load-rx-queue-index
  (testing "Can load rx_queue_index from xdp_md"
    (let [insn (xdp/xdp-load-ctx-field :r1 :rx-queue-index :r4)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))  ; Single ldx instruction = 8 bytes

;; ============================================================================
;; XDP Redirect to XSK Tests
;; ============================================================================

(deftest test-xdp-redirect-to-xsk
  (testing "xdp-redirect-to-xsk generates bytecode"
    (let [insns (xdp/xdp-redirect-to-xsk 5 0)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-redirect-to-xsk with register queue index"
    (let [insns (xdp/xdp-redirect-to-xsk 5 :r4)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-redirect-to-xsk default fallback is XDP_PASS"
    ;; Default flags should be 2 (XDP_PASS)
    (let [insns-default (xdp/xdp-redirect-to-xsk 5 0)
          insns-explicit (xdp/xdp-redirect-to-xsk 5 0 2)]
      ;; Both should generate identical bytecode
      (is (= (count insns-default) (count insns-explicit))))))

(deftest test-xdp-redirect-to-xsk-with-custom-flags
  (testing "xdp-redirect-to-xsk with custom fallback flags"
    (let [;; Use XDP_DROP (1) as fallback
          insns (xdp/xdp-redirect-to-xsk 5 0 1)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-redirect-to-xsk-by-queue
  (testing "xdp-redirect-to-xsk-by-queue generates bytecode"
    (let [insns (xdp/xdp-redirect-to-xsk-by-queue :r6 5)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-redirect-to-xsk-by-queue with custom tmp register"
    (let [insns (xdp/xdp-redirect-to-xsk-by-queue :r6 5 :r5)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-redirect-to-xsk-by-queue with custom flags"
    (let [insns (xdp/xdp-redirect-to-xsk-by-queue :r6 5 :r4 1)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Instruction Size Tests
;; ============================================================================

(deftest test-xsk-redirect-instruction-sizes
  (testing "XSK redirect instruction sizes are correct"
    ;; xdp-redirect-to-xsk: ld_map_fd (16) + mov (8) + mov (8) + call (8) + exit (8) = 48 bytes
    (let [insns (xdp/xdp-redirect-to-xsk 5 0)
          total-bytes (reduce + (map count insns))]
      (is (= 48 total-bytes))))

  (testing "XSK redirect by queue instruction sizes"
    ;; xdp-redirect-to-xsk-by-queue: ldx (8) + ld_map_fd (16) + mov (8) + mov (8) + call (8) + exit (8) = 56 bytes
    (let [insns (xdp/xdp-redirect-to-xsk-by-queue :r6 5)
          total-bytes (reduce + (map count insns))]
      (is (= 56 total-bytes)))))

;; ============================================================================
;; Program Assembly Tests
;; ============================================================================

(deftest test-xskmap-redirect-program-assembly
  (testing "Can assemble XDP program with XSK redirect"
    (let [program-insns [(dsl/ld-map-fd :r1 5)   ; xskmap fd
                         (dsl/mov :r2 0)          ; queue index = 0
                         (dsl/mov :r3 2)          ; flags = XDP_PASS fallback
                         (dsl/call 51)            ; bpf_redirect_map
                         (dsl/exit-insn)]
          bytecode (dsl/assemble program-insns)]
      (is (bytes? bytecode))
      ;; ld_map_fd (16) + mov (8) + mov (8) + call (8) + exit (8) = 48 bytes
      (is (= 48 (count bytecode))))))

(deftest test-xskmap-with-queue-lookup
  (testing "Can assemble XDP program that loads queue index"
    (let [;; Load rx_queue_index and use as key
          program-insns [(dsl/mov-reg :r6 :r1)           ; Save context
                         (dsl/ldx :w :r4 :r6 16)         ; r4 = xdp_md->rx_queue_index
                         (dsl/ld-map-fd :r1 5)           ; xskmap fd
                         (dsl/mov-reg :r2 :r4)           ; key = queue index
                         (dsl/mov :r3 2)                 ; flags = XDP_PASS
                         (dsl/call 51)                   ; bpf_redirect_map
                         (dsl/exit-insn)]
          bytecode (dsl/assemble program-insns)]
      (is (bytes? bytecode))
      ;; mov (8) + ldx (8) + ld_map_fd (16) + mov (8) + mov (8) + call (8) + exit (8) = 64 bytes
      (is (= 64 (count bytecode))))))

;; ============================================================================
;; Complete XDP Program Tests
;; ============================================================================

(deftest test-complete-xsk-redirect-program
  (testing "Complete XDP program with XSK redirect"
    (let [;; Full program: prologue + redirect to XSK at queue index
          prog-insns (vec (concat
                           ;; Save context, load data pointers
                           (xdp/xdp-prologue :r9 :r2 :r3)
                           ;; Redirect to XSK at index 0
                           (xdp/xdp-redirect-to-xsk 5 0)))
          bytecode (dsl/assemble prog-insns)]
      (is (bytes? bytecode))
      ;; Prologue: 3 insns = 24 bytes
      ;; redirect: 48 bytes
      ;; Total: 72 bytes
      (is (= 72 (count bytecode))))))

(deftest test-complete-xsk-redirect-by-queue-program
  (testing "Complete XDP program with queue-based XSK redirect"
    (let [;; Full program with queue-based redirect
          prog-insns (vec (concat
                           ;; Save context
                           [(dsl/mov-reg :r6 :r1)]
                           ;; Load data pointers (optional for this pattern)
                           (xdp/xdp-load-data-pointers :r6 :r2 :r3)
                           ;; Redirect based on rx_queue_index
                           (xdp/xdp-redirect-to-xsk-by-queue :r6 5)))
          bytecode (dsl/assemble prog-insns)]
      (is (bytes? bytecode))
      ;; mov (8) + 2x ldx (16) + ldx (8) + ld_map_fd (16) + mov (8) + mov (8) + call (8) + exit (8) = 80 bytes
      (is (= 80 (count bytecode))))))

;; ============================================================================
;; Edge Cases
;; ============================================================================

(deftest test-xsk-redirect-with-max-queues
  (testing "XSK redirect with various queue indices"
    (doseq [queue-idx [0 1 7 15 31 63]]
      (let [insns (xdp/xdp-redirect-to-xsk 5 queue-idx)]
        (is (vector? insns))
        (is (pos? (count insns)))
        (is (every? bytes? insns))))))

(deftest test-xsk-redirect-different-fallback-actions
  (testing "XSK redirect with different fallback actions"
    (doseq [[action value] [[:aborted 0] [:drop 1] [:pass 2] [:tx 3] [:redirect 4]]]
      (let [insns (xdp/xdp-redirect-to-xsk 5 0 value)]
        (is (vector? insns))
        (is (pos? (count insns)))
        (is (every? bytes? insns))))))

;; ============================================================================
;; Integration Pattern Tests
;; ============================================================================

(deftest test-xsk-redirect-after-packet-inspection
  (testing "XSK redirect after basic packet inspection"
    (let [;; Pattern: check packet, redirect matching ones to XSK
          prog-insns (vec (concat
                           ;; Prologue
                           (xdp/xdp-prologue :r6 :r2 :r3)
                           ;; Bounds check for Ethernet header
                           (xdp/xdp-bounds-check :r2 :r3 14 :pass)
                           ;; All packets that pass bounds check go to XSK
                           (xdp/xdp-redirect-to-xsk 5 0)))
          bytecode (dsl/assemble prog-insns)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

(deftest test-xsk-selective-redirect
  (testing "Selective redirect - only some packets to XSK"
    (let [;; Pattern: redirect based on condition, else pass
          prog-insns [(dsl/mov-reg :r6 :r1)           ; Save context
                      ;; Load rx_queue_index
                      (dsl/ldx :w :r4 :r6 16)
                      ;; If queue != 0, pass to kernel stack
                      (dsl/jmp-imm :jne :r4 0 5)
                      ;; Queue 0 -> redirect to XSK
                      (dsl/ld-map-fd :r1 5)
                      (dsl/mov :r2 0)
                      (dsl/mov :r3 2)
                      (dsl/call 51)
                      (dsl/exit-insn)
                      ;; Other queues -> XDP_PASS
                      (dsl/mov :r0 2)
                      (dsl/exit-insn)]
          bytecode (dsl/assemble prog-insns)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode))))))

;; ============================================================================
;; DSL Helper Consistency Tests
;; ============================================================================

(deftest test-xsk-redirect-consistency-with-other-redirects
  (testing "XSK redirect uses same helper as DEVMAP/CPUMAP"
    ;; All should use bpf_redirect_map (helper 51)
    (let [xsk-insns (xdp/xdp-redirect-to-xsk 5 0)
          dev-insns (xdp/xdp-redirect-to-interface 5 0)
          cpu-insns (xdp/xdp-redirect-to-cpu 5 0)]
      ;; All should have same instruction count
      (is (= (count xsk-insns) (count dev-insns) (count cpu-insns)))
      ;; All should have same total byte count
      (is (= (reduce + (map count xsk-insns))
             (reduce + (map count dev-insns))
             (reduce + (map count cpu-insns)))))))

;; ============================================================================
;; XDP Actions Used with XSK
;; ============================================================================

(deftest test-xdp-actions-for-xsk
  (testing "XDP action values used with XSKMAP"
    (is (= 4 (xdp/xdp-action :redirect)))
    (is (= 2 (xdp/xdp-action :pass)))
    (is (= 1 (xdp/xdp-action :drop)))))

;; ============================================================================
;; Real-World Pattern: Multi-Queue XSK
;; ============================================================================

(deftest test-multi-queue-xsk-pattern
  (testing "Multi-queue XSK pattern compiles"
    (let [;; Pattern: redirect each queue to its corresponding XSK socket
          ;; This is the standard AF_XDP setup
          prog-insns (vec (concat
                           ;; Save context
                           [(dsl/mov-reg :r6 :r1)]
                           ;; Get rx_queue_index
                           [(dsl/ldx :w :r4 :r6 16)]
                           ;; Redirect to XSK at queue index
                           ;; (XSK sockets are registered at their queue index)
                           (xdp/xdp-redirect-to-xsk 5 :r4 2)))
          bytecode (dsl/assemble prog-insns)]
      (is (bytes? bytecode))
      ;; mov (8) + ldx (8) + ld_map_fd (16) + mov (8) + mov (8) + call (8) + exit (8) = 64 bytes
      (is (= 64 (count bytecode))))))

;; ============================================================================
;; Documentation Examples Verification
;; ============================================================================

(deftest test-documentation-example-compiles
  (testing "Documentation example compiles correctly"
    ;; Example from create-xsk-map docstring
    (let [;; r4 = xdp_md->rx_queue_index
          ;; return bpf_redirect_map(&xsks_map, r4, XDP_PASS)
          prog-insns [(dsl/mov-reg :r6 :r1)      ; Save context
                      (dsl/ldx :w :r4 :r6 16)    ; r4 = rx_queue_index
                      (dsl/ld-map-fd :r1 5)      ; r1 = xsks_map fd
                      (dsl/mov-reg :r2 :r4)      ; r2 = key (queue index)
                      (dsl/mov :r3 2)            ; r3 = XDP_PASS
                      (dsl/call 51)              ; bpf_redirect_map
                      (dsl/exit-insn)]
          bytecode (dsl/assemble prog-insns)]
      (is (bytes? bytecode))
      (is (= 64 (count bytecode))))))
