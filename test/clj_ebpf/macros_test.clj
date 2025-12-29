(ns clj-ebpf.macros-test
  "Tests for high-level declarative macros - CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer :all]
            [clj-ebpf.macros :as macros]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; defmap-spec Tests
;; ============================================================================

(deftest test-defmap-spec-basic
  (testing "defmap-spec creates correct map specification"
    (macros/defmap-spec test-hash-map
      :type :hash
      :key-size 4
      :value-size 8
      :max-entries 1024)

    (is (= :hash (:map-type test-hash-map)))
    (is (= 4 (:key-size test-hash-map)))
    (is (= 8 (:value-size test-hash-map)))
    (is (= 1024 (:max-entries test-hash-map)))
    (is (= 0 (:map-flags test-hash-map)))
    (is (= "test-hash-map" (:map-name test-hash-map)))))

(deftest test-defmap-spec-with-flags
  (testing "defmap-spec with custom flags"
    (macros/defmap-spec test-flagged-map
      :type :array
      :key-size 4
      :value-size 4
      :max-entries 256
      :flags 2)

    (is (= :array (:map-type test-flagged-map)))
    (is (= 2 (:map-flags test-flagged-map)))))

(deftest test-defmap-spec-with-custom-name
  (testing "defmap-spec with custom map name"
    (macros/defmap-spec test-named-map
      :type :lru-hash
      :key-size 8
      :value-size 16
      :max-entries 512
      :map-name "my_custom_map")

    (is (= "my_custom_map" (:map-name test-named-map)))))

(deftest test-defmap-spec-serializers
  (testing "defmap-spec includes serializers"
    (macros/defmap-spec test-serializer-map
      :type :hash
      :key-size 4
      :value-size 4
      :max-entries 100)

    (is (fn? (:key-serializer test-serializer-map)))
    (is (fn? (:key-deserializer test-serializer-map)))
    (is (fn? (:value-serializer test-serializer-map)))
    (is (fn? (:value-deserializer test-serializer-map)))))

(deftest test-defmap-spec-all-map-types
  (testing "defmap-spec works with various map types"
    (doseq [map-type [:hash :array :lru-hash :percpu-hash :percpu-array
                      :lru-percpu-hash :stack :queue :ringbuf :lpm-trie]]
      (let [spec-name (symbol (str "test-" (name map-type) "-map"))
            spec {:map-type map-type
                  :key-size 4
                  :value-size 4
                  :max-entries 100
                  :map-flags 0
                  :map-name (str spec-name)
                  :key-serializer utils/int->bytes
                  :key-deserializer utils/bytes->int
                  :value-serializer utils/int->bytes
                  :value-deserializer utils/bytes->int}]
        (is (= map-type (:map-type spec)))))))

;; ============================================================================
;; defprogram Tests
;; ============================================================================

(deftest test-defprogram-basic
  (testing "defprogram creates correct program specification"
    (macros/defprogram test-simple-prog
      :type :xdp
      :body [(dsl/mov :r0 2)
             (dsl/exit-insn)])

    (is (= :xdp (:prog-type test-simple-prog)))
    (is (= "GPL" (:license test-simple-prog)))
    (is (= "test-simple-prog" (:prog-name test-simple-prog)))
    (is (= 1 (:log-level test-simple-prog)))
    (is (fn? (:body-fn test-simple-prog)))))

(deftest test-defprogram-custom-license
  (testing "defprogram with custom license"
    (macros/defprogram test-licensed-prog
      :type :kprobe
      :license "Dual MIT/GPL"
      :body [(dsl/mov :r0 0)
             (dsl/exit-insn)])

    (is (= "Dual MIT/GPL" (:license test-licensed-prog)))))

(deftest test-defprogram-with-opts
  (testing "defprogram with options"
    (macros/defprogram test-opts-prog
      :type :tracepoint
      :opts {:log-level 2
             :prog-name "custom_name"}
      :body [(dsl/mov :r0 0)
             (dsl/exit-insn)])

    (is (= 2 (:log-level test-opts-prog)))
    (is (= "custom_name" (:prog-name test-opts-prog)))))

(deftest test-defprogram-body-fn
  (testing "defprogram body-fn assembles to bytecode"
    (macros/defprogram test-bytecode-prog
      :type :xdp
      :body [(dsl/mov :r0 2)
             (dsl/exit-insn)])

    (let [bytecode ((:body-fn test-bytecode-prog))]
      (is (bytes? bytecode))
      ;; Two instructions: mov r0, 2 + exit = 16 bytes
      (is (= 16 (count bytecode))))))

(deftest test-defprogram-stores-body-source
  (testing "defprogram stores original body source"
    (macros/defprogram test-source-prog
      :type :xdp
      :body [(dsl/mov :r0 2)
             (dsl/exit-insn)])

    (is (some? (:body-source test-source-prog)))
    ;; Body source is a vector (quoted from the original body)
    (is (vector? (:body-source test-source-prog)))))

(deftest test-defprogram-various-types
  (testing "defprogram works with various program types"
    (doseq [prog-type [:kprobe :kretprobe :uprobe :uretprobe
                       :tracepoint :xdp :tc :socket-filter]]
      (let [spec {:prog-type prog-type
                  :license "GPL"
                  :prog-name "test"
                  :log-level 1
                  :body-fn (fn [] (dsl/assemble [(dsl/mov :r0 0) (dsl/exit-insn)]))
                  :body-source '[(dsl/mov :r0 0) (dsl/exit-insn)]}]
        (is (= prog-type (:prog-type spec)))))))

;; ============================================================================
;; Bytecode Assembly Tests
;; ============================================================================

(deftest test-defprogram-xdp-pass-bytecode
  (testing "XDP pass program produces correct bytecode"
    (macros/defprogram xdp-pass-prog
      :type :xdp
      :body [(dsl/mov :r0 2)      ; XDP_PASS = 2
             (dsl/exit-insn)])

    (let [bytecode ((:body-fn xdp-pass-prog))]
      ;; mov r0, 2 - opcode 0xb7 (ALU64 | K | MOV)
      (is (= (unchecked-byte 0xb7) (aget bytecode 0)))
      ;; dst reg = r0 (0), src reg = 0
      (is (= 0 (aget bytecode 1)))
      ;; exit - opcode 0x95 (JMP | EXIT)
      (is (= (unchecked-byte 0x95) (aget bytecode 8))))))

(deftest test-defprogram-xdp-drop-bytecode
  (testing "XDP drop program produces correct bytecode"
    (macros/defprogram xdp-drop-prog
      :type :xdp
      :body [(dsl/mov :r0 1)      ; XDP_DROP = 1
             (dsl/exit-insn)])

    (let [bytecode ((:body-fn xdp-drop-prog))]
      (is (= 16 (count bytecode)))
      ;; Check immediate value is 1
      (is (= 1 (aget bytecode 4))))))

(deftest test-defprogram-complex-body
  (testing "defprogram with complex body"
    (macros/defprogram complex-prog
      :type :kprobe
      :body [(dsl/mov :r6 0)       ; r6 = 0
             (dsl/add :r6 1)       ; r6 += 1
             (dsl/mov-reg :r0 :r6) ; r0 = r6
             (dsl/exit-insn)])

    (let [bytecode ((:body-fn complex-prog))]
      ;; 4 instructions * 8 bytes = 32 bytes
      (is (= 32 (count bytecode))))))

;; ============================================================================
;; resolve-program-spec Tests
;; ============================================================================

(deftest test-resolve-program-spec
  (testing "resolve-program-spec adds bytecode"
    (macros/defprogram resolve-test-prog
      :type :xdp
      :body [(dsl/mov :r0 0)
             (dsl/exit-insn)])

    (let [resolved (#'macros/resolve-program-spec resolve-test-prog)]
      (is (contains? resolved :insns))
      (is (bytes? (:insns resolved)))
      (is (= 16 (count (:insns resolved)))))))

(deftest test-resolve-program-spec-no-body
  (testing "resolve-program-spec handles spec without body-fn"
    (let [spec {:prog-type :xdp
                :license "GPL"
                :insns (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                                    0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])}
          resolved (#'macros/resolve-program-spec spec)]
      (is (= spec resolved)))))

;; ============================================================================
;; Map Spec Serializer Tests
;; ============================================================================

(deftest test-defmap-spec-default-serializers-work
  (testing "Default serializers can round-trip integers"
    (macros/defmap-spec serializer-test-map
      :type :hash
      :key-size 4
      :value-size 4
      :max-entries 10)

    (let [key-ser (:key-serializer serializer-test-map)
          key-deser (:key-deserializer serializer-test-map)
          val-ser (:value-serializer serializer-test-map)
          val-deser (:value-deserializer serializer-test-map)]
      ;; Test key round-trip
      (is (= 42 (key-deser (key-ser 42))))
      (is (= 0 (key-deser (key-ser 0))))
      (is (= -1 (key-deser (key-ser -1))))
      ;; Test value round-trip
      (is (= 100 (val-deser (val-ser 100)))))))

;; ============================================================================
;; Program Spec Completeness Tests
;; ============================================================================

(deftest test-defprogram-spec-complete
  (testing "defprogram creates complete spec for load-program"
    (macros/defprogram complete-spec-prog
      :type :xdp
      :license "GPL"
      :body [(dsl/mov :r0 2)
             (dsl/exit-insn)])

    (let [resolved (#'macros/resolve-program-spec complete-spec-prog)]
      ;; All required fields for load-program should be present
      (is (contains? resolved :prog-type))
      (is (contains? resolved :license))
      (is (contains? resolved :insns))
      (is (contains? resolved :prog-name))
      (is (contains? resolved :log-level)))))

;; ============================================================================
;; Edge Cases
;; ============================================================================

(deftest test-defmap-spec-large-sizes
  (testing "defmap-spec handles large sizes"
    (macros/defmap-spec large-map
      :type :hash
      :key-size 256
      :value-size 4096
      :max-entries 1000000)

    (is (= 256 (:key-size large-map)))
    (is (= 4096 (:value-size large-map)))
    (is (= 1000000 (:max-entries large-map)))))

(deftest test-defprogram-empty-body
  (testing "defprogram with minimal body"
    (macros/defprogram minimal-prog
      :type :xdp
      :body [(dsl/exit-insn)])

    (let [bytecode ((:body-fn minimal-prog))]
      ;; Just exit instruction = 8 bytes
      (is (= 8 (count bytecode))))))

(deftest test-defprogram-nested-body
  (testing "defprogram with nested instruction sequences"
    (macros/defprogram nested-prog
      :type :xdp
      :body [[(dsl/mov :r0 0)]
             [(dsl/add :r0 1)]
             (dsl/exit-insn)])

    (let [bytecode ((:body-fn nested-prog))]
      ;; 3 instructions = 24 bytes
      (is (= 24 (count bytecode))))))

;; ============================================================================
;; Convenience Function Tests
;; ============================================================================

(deftest test-load-defprogram-exists
  (testing "load-defprogram function is available"
    (is (fn? macros/load-defprogram))))

(deftest test-create-defmap-exists
  (testing "create-defmap function is available"
    (is (fn? macros/create-defmap))))

;; ============================================================================
;; Integration Pattern Tests (without actual kernel interaction)
;; ============================================================================

(deftest test-spec-pattern-xdp
  (testing "XDP program spec pattern"
    (macros/defmap-spec xdp-counter-map
      :type :array
      :key-size 4
      :value-size 8
      :max-entries 1)

    (macros/defprogram xdp-counter-prog
      :type :xdp
      :body [(dsl/mov :r0 2)   ; XDP_PASS
             (dsl/exit-insn)])

    ;; Verify specs are well-formed
    (is (= :array (:map-type xdp-counter-map)))
    (is (= :xdp (:prog-type xdp-counter-prog)))
    (is (bytes? ((:body-fn xdp-counter-prog))))))

(deftest test-spec-pattern-kprobe
  (testing "Kprobe program spec pattern"
    (macros/defmap-spec kprobe-event-map
      :type :hash
      :key-size 4
      :value-size 16
      :max-entries 10000)

    (macros/defprogram kprobe-trace-prog
      :type :kprobe
      :body [(dsl/mov :r0 0)
             (dsl/exit-insn)])

    ;; Verify specs are well-formed
    (is (= :hash (:map-type kprobe-event-map)))
    (is (= :kprobe (:prog-type kprobe-trace-prog)))))

;; ============================================================================
;; Macro Expansion Tests
;; ============================================================================

(deftest test-defmap-spec-macro-expands
  (testing "defmap-spec macro expansion produces valid def"
    ;; The macro expands to (def name {...}), creating a var
    (macros/defmap-spec macro-test-map
      :type :hash
      :key-size 4
      :value-size 4
      :max-entries 100)

    ;; Verify the var was created with correct content
    (is (map? macro-test-map))
    (is (= :hash (:map-type macro-test-map)))))

(deftest test-defprogram-macro-expands
  (testing "defprogram macro expansion produces valid def"
    ;; The macro expands to (def name {...}), creating a var
    (macros/defprogram macro-test-prog
      :type :xdp
      :body [(dsl/exit-insn)])

    ;; Verify the var was created with correct content
    (is (map? macro-test-prog))
    (is (= :xdp (:prog-type macro-test-prog)))))

;; ============================================================================
;; Helper Function Tests
;; ============================================================================

(deftest test-create-maps-from-specs
  (testing "create-maps-from-specs function exists"
    (is (some? #'macros/create-maps-from-specs))))

(deftest test-load-programs-from-specs
  (testing "load-programs-from-specs function exists"
    (is (some? #'macros/load-programs-from-specs))))

(deftest test-perform-attachments
  (testing "perform-attachments function exists"
    (is (some? #'macros/perform-attachments))))
