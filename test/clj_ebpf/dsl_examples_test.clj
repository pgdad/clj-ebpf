(ns clj-ebpf.dsl-examples-test
  "Tests for DSL examples to ensure they compile correctly."
  (:require [clojure.test :refer [deftest testing is]]
            [clj-ebpf.examples :as examples]))

(deftest test-basic-xdp-examples
  (testing "Basic XDP examples compile without errors"
    (testing "XDP pass all"
      (let [bytecode (examples/xdp-pass-all)]
        (is (bytes? bytecode))
        (is (pos? (count bytecode)))
        (is (zero? (mod (count bytecode) 8)) "Bytecode should be multiple of 8 bytes")))

    (testing "XDP drop all"
      (let [bytecode (examples/xdp-drop-all)]
        (is (bytes? bytecode))
        (is (pos? (count bytecode)))))

    (testing "XDP packet size filter"
      (let [bytecode (examples/xdp-packet-size-filter)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 16) "Should have multiple instructions")))

    (testing "XDP aborted on error"
      (let [bytecode (examples/xdp-aborted-on-error)]
        (is (bytes? bytecode))
        (is (pos? (count bytecode)))))))

(deftest test-ethernet-parsing-examples
  (testing "Ethernet header parsing examples compile correctly"
    (testing "Ethernet parser"
      (let [bytecode (examples/xdp-ethernet-parser)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 16) "Should parse and validate header")))

    (testing "EtherType filter"
      (let [bytecode (examples/xdp-ethertype-filter)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 32) "Should have parsing and filtering logic")))))

(deftest test-ip-parsing-examples
  (testing "IP header parsing examples compile correctly"
    (testing "IPv4 parser"
      (let [bytecode (examples/xdp-ipv4-parser)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 32))))

    (testing "IP protocol filter"
      (let [bytecode (examples/xdp-ip-protocol-filter)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 32))))))

(deftest test-port-filtering-examples
  (testing "TCP/UDP port filtering examples compile correctly"
    (testing "TCP port filter"
      (let [bytecode (examples/xdp-tcp-port-filter)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 40) "Should parse headers and check port")))

    (testing "UDP port range filter"
      (let [bytecode (examples/xdp-udp-port-range-filter)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 40) "Should check port range")))))

(deftest test-map-operation-examples
  (testing "BPF map operation examples compile correctly"
    (testing "Map lookup example"
      (let [bytecode (examples/xdp-map-lookup-example)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 40) "Should set up key, call helper, check result")))

    (testing "Map update counter"
      (let [bytecode (examples/xdp-map-update-counter)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 80) "Should have lookup, increment, update logic")))))

(deftest test-tc-examples
  (testing "Traffic Control examples compile correctly"
    (testing "TC ok all"
      (let [bytecode (examples/tc-ok-all)]
        (is (bytes? bytecode))
        (is (= 16 (count bytecode))) ; 2 instructions
        ;; Check for TC_ACT_OK opcode
        (is (= (unchecked-byte 0xb7) (aget bytecode 0)))))

    (testing "TC shot all"
      (let [bytecode (examples/tc-shot-all)]
        (is (bytes? bytecode))
        (is (= 16 (count bytecode)))))

    (testing "TC packet classifier"
      (let [bytecode (examples/tc-packet-classifier)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 40) "Should have size checks and branching")))))

(deftest test-tracing-examples
  (testing "Tracing and debugging examples compile correctly"
    (testing "Kprobe with trace printk"
      (let [bytecode (examples/kprobe-with-trace-printk)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 16) "Should set up args and call helper")))

    (testing "Kprobe timestamp logger"
      (let [bytecode (examples/kprobe-timestamp-logger)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 16))))))

(deftest test-arithmetic-examples
  (testing "Arithmetic operation examples compile correctly"
    (testing "Arithmetic demo"
      (let [bytecode (examples/arithmetic-operations-demo)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 40) "Should have multiple arithmetic ops")))

    (testing "Bitwise demo"
      (let [bytecode (examples/bitwise-operations-demo)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 40) "Should have multiple bitwise ops")))

    (testing "Conditional logic demo"
      (let [bytecode (examples/conditional-logic-demo)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 24) "Should have conditional jump")))))

(deftest test-complex-examples
  (testing "Complex real-world examples compile correctly"
    (testing "SYN flood protection"
      (let [bytecode (examples/xdp-syn-flood-protection)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 32))))

    (testing "ICMP rate limiter"
      (let [bytecode (examples/xdp-icmp-rate-limiter)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 40))))

    (testing "IP allowlist filter"
      (let [bytecode (examples/xdp-allowlist-filter)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 64) "Should parse IP, lookup in map")))))

(deftest test-helper-function-examples
  (testing "Helper function examples compile correctly"
    (testing "Perf event output demo"
      (let [bytecode (examples/perf-event-output-demo)]
        (is (bytes? bytecode))
        (is (> (count bytecode) 40) "Should set up args and call helper")))

    (testing "Get SMP processor ID demo"
      (let [bytecode (examples/get-smp-processor-id-demo)]
        (is (bytes? bytecode))
        (is (>= (count bytecode) 16))))))

(deftest test-examples-lookup
  (testing "Examples lookup table"
    (testing "All examples in lookup table are valid"
      (is (map? examples/examples))
      (is (> (count examples/examples) 20) "Should have many examples")

      ;; Test each example can be retrieved and executed
      (doseq [[name {:keys [fn description]}] examples/examples]
        (is (keyword? name) (str "Example name should be keyword: " name))
        (is (fn? fn) (str "Example should have function: " name))
        (is (string? description) (str "Example should have description: " name))

        ;; Test that the function produces valid bytecode
        (let [bytecode (fn)]
          (is (bytes? bytecode) (str "Example should produce bytecode: " name))
          (is (pos? (count bytecode)) (str "Bytecode should not be empty: " name))
          (is (zero? (mod (count bytecode) 8))
              (str "Bytecode should be multiple of 8 bytes: " name)))))))

(deftest test-get-example-function
  (testing "get-example function"
    (testing "Returns bytecode for valid example"
      (let [bytecode (examples/get-example :xdp-pass-all)]
        (is (bytes? bytecode))
        (is (pos? (count bytecode)))))

    (testing "Throws exception for invalid example"
      (is (thrown? Exception (examples/get-example :nonexistent-example))))))

(deftest test-bytecode-structure
  (testing "Generated bytecode has correct structure"
    (testing "All examples produce 8-byte aligned bytecode"
      (doseq [[name {:keys [fn]}] examples/examples]
        (let [bytecode (fn)
              insn-count (/ (count bytecode) 8)]
          (is (pos? insn-count)
              (str "Example should have at least one instruction: " name))
          (is (integer? insn-count)
              (str "Instruction count should be integer: " name)))))

    (testing "Examples with jumps have valid instruction counts"
      ;; These examples have conditional logic and should have multiple instructions
      (let [conditional-examples [:xdp-packet-size-filter
                                   :xdp-ethernet-parser
                                   :xdp-ethertype-filter
                                   :xdp-ipv4-parser
                                   :conditional-demo]]
        (doseq [name conditional-examples]
          (let [bytecode (examples/get-example name)
                insn-count (/ (count bytecode) 8)]
            (is (>= insn-count 3)
                (str "Conditional example should have >= 3 instructions: " name))))))))

(deftest test-instruction-opcodes
  (testing "First instruction opcodes are valid"
    (testing "XDP pass all starts with MOV instruction"
      (let [bytecode (examples/xdp-pass-all)]
        ;; MOV immediate has opcode 0xb7
        (is (= (unchecked-byte 0xb7) (aget bytecode 0)))))

    (testing "XDP drop all starts with MOV instruction"
      (let [bytecode (examples/xdp-drop-all)]
        (is (= (unchecked-byte 0xb7) (aget bytecode 0)))))

    (testing "Programs end with EXIT instruction"
      (let [bytecode (examples/xdp-pass-all)
            last-insn-offset (- (count bytecode) 8)]
        ;; EXIT has opcode 0x95
        (is (= (unchecked-byte 0x95) (aget bytecode last-insn-offset)))))))

(deftest test-examples-documentation
  (testing "All examples have proper documentation"
    (doseq [[name {:keys [description]}] examples/examples]
      (is (string? description)
          (str "Example should have description: " name))
      (is (> (count description) 10)
          (str "Description should be meaningful: " name))
      (is (not (.endsWith description "."))
          (str "Description should not end with period: " name)))))

(deftest test-examples-categories
  (testing "Examples are properly categorized"
    (let [example-names (set (keys examples/examples))]
      (testing "Has basic XDP examples"
        (is (contains? example-names :xdp-pass-all))
        (is (contains? example-names :xdp-drop-all)))

      (testing "Has packet parsing examples"
        (is (contains? example-names :xdp-ethernet-parser))
        (is (contains? example-names :xdp-ipv4-parser)))

      (testing "Has filtering examples"
        (is (contains? example-names :xdp-tcp-port-filter))
        (is (contains? example-names :xdp-ethertype-filter)))

      (testing "Has map operation examples"
        (is (contains? example-names :xdp-map-lookup))
        (is (contains? example-names :xdp-map-counter)))

      (testing "Has TC examples"
        (is (contains? example-names :tc-ok-all))
        (is (contains? example-names :tc-classifier)))

      (testing "Has tracing examples"
        (is (contains? example-names :kprobe-trace-printk))
        (is (contains? example-names :kprobe-timestamp)))

      (testing "Has complex examples"
        (is (contains? example-names :syn-flood-protection))
        (is (contains? example-names :ip-allowlist))))))

(deftest test-example-sizes
  (testing "Example bytecode sizes are reasonable"
    (testing "Simple examples are small"
      (let [simple-examples [:xdp-pass-all :xdp-drop-all :tc-ok-all]]
        (doseq [name simple-examples]
          (let [bytecode (examples/get-example name)]
            (is (<= (count bytecode) 32)
                (str "Simple example should be <= 32 bytes: " name))))))

    (testing "Complex examples are larger"
      (let [complex-examples [:ip-allowlist :xdp-map-counter :syn-flood-protection]]
        (doseq [name complex-examples]
          (let [bytecode (examples/get-example name)]
            (is (> (count bytecode) 32)
                (str "Complex example should be > 32 bytes: " name))))))))

(deftest test-examples-use-valid-actions
  (testing "XDP examples use valid XDP actions"
    (let [xdp-examples [:xdp-pass-all :xdp-drop-all :xdp-packet-size-filter
                        :xdp-aborted-on-error]]
      ;; These should all compile without errors
      ;; The actual action values are tested in the DSL tests
      (doseq [name xdp-examples]
        (is (bytes? (examples/get-example name))
            (str "XDP example should compile: " name)))))

  (testing "TC examples use valid TC actions"
    (let [tc-examples [:tc-ok-all :tc-shot-all :tc-classifier]]
      (doseq [name tc-examples]
        (is (bytes? (examples/get-example name))
            (str "TC example should compile: " name))))))
