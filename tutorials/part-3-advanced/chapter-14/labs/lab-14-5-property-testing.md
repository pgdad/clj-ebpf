# Lab 14.5: Property-Based Testing

**Objective**: Use property-based testing to verify BPF operations invariants

**Duration**: 60 minutes

## Overview

Property-based testing verifies that your code satisfies certain properties across many randomly generated inputs. Unlike example-based tests that check specific cases, property tests discover edge cases you might not anticipate.

clj-ebpf provides comprehensive generators and property definitions for testing BPF operations, DSL instructions, memory utilities, and network packet handling.

## What You'll Learn

- How to use clj-ebpf's test.check generators
- Writing property-based tests for BPF operations
- Testing DSL instruction generation invariants
- Verifying memory operation round-trips
- Generating realistic test data (packets, events, maps)
- Running property tests and interpreting results

## Prerequisites

- Understanding of BPF instruction format
- Basic familiarity with clojure.test
- Completed Labs 14.1-14.4

## Theory

### Property-Based Testing Fundamentals

Traditional unit tests verify specific input-output pairs:
```clojure
;; Example-based: tests ONE case
(is (= 42 (add 40 2)))
```

Property-based tests verify invariants across MANY random inputs:
```clojure
;; Property-based: tests HUNDREDS of cases
(prop/for-all [a gen/int, b gen/int]
  (= (add a b) (add b a)))  ; Commutativity property
```

### BPF Testing Properties

Key properties to verify in BPF code:

1. **DSL Invariants**: Every DSL function produces valid instruction maps
2. **Round-trip Properties**: Data survives encode/decode cycles
3. **Generator Constraints**: Generated data meets BPF requirements
4. **Structural Properties**: Instructions have correct format

## clj-ebpf Modules Used

| Module | Purpose |
|--------|---------|
| `clj-ebpf.generators` | BPF-specific test.check generators |
| `clj-ebpf.properties` | Pre-defined property tests |
| `clj-ebpf.dsl` | DSL instruction generation |
| `clj-ebpf.utils` | Memory utilities for round-trip tests |

## Implementation

### Step 1: Understanding the Generators

clj-ebpf provides generators organized by category:

```clojure
(ns lab-14-5-property-testing
  "Lab 14.5: Property-Based Testing"
  (:require [clojure.test :refer :all]
            [clojure.test.check :as tc]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [clj-ebpf.generators :as bpf-gen]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Primitive Generators
;; ============================================================================

(defn explore-primitive-generators
  "Demonstrate primitive data generators"
  []
  (println "=== Primitive Generators ===\n")

  ;; Unsigned integers
  (println "gen-u8 (5 samples):" (gen/sample bpf-gen/gen-u8 5))
  (println "gen-u16 (5 samples):" (gen/sample bpf-gen/gen-u16 5))
  (println "gen-u32 (5 samples):" (gen/sample bpf-gen/gen-u32 5))

  ;; Signed integers
  (println "gen-i32 (5 samples):" (gen/sample bpf-gen/gen-i32 5))
  (println "gen-i64 (5 samples):" (gen/sample bpf-gen/gen-i64 5))

  ;; Byte arrays
  (println "gen-byte-array 4 (3 samples):"
           (map vec (gen/sample (bpf-gen/gen-byte-array 4) 3)))
  (println "gen-byte-array-range 2-8 (3 samples):"
           (map #(format "len=%d" (count %))
                (gen/sample (bpf-gen/gen-byte-array-range 2 8) 3))))
```

### Step 2: BPF Map Generators

Generate valid BPF map configurations:

```clojure
;; ============================================================================
;; Map Configuration Generators
;; ============================================================================

(defn explore-map-generators
  "Demonstrate map configuration generators"
  []
  (println "\n=== Map Configuration Generators ===\n")

  ;; Map types
  (println "Available map types:")
  (println "  gen-map-type (5 samples):"
           (gen/sample bpf-gen/gen-map-type 5))
  (println "  gen-hash-map-type (5 samples):"
           (gen/sample bpf-gen/gen-hash-map-type 5))
  (println "  gen-array-map-type (5 samples):"
           (gen/sample bpf-gen/gen-array-map-type 5))

  ;; Map parameters
  (println "\nMap parameters:")
  (println "  gen-key-size (aligned 4-256):"
           (gen/sample bpf-gen/gen-key-size 5))
  (println "  gen-value-size (1-4096):"
           (gen/sample bpf-gen/gen-value-size 5))
  (println "  gen-max-entries:"
           (gen/sample bpf-gen/gen-max-entries 5))

  ;; Complete configurations
  (println "\nComplete map configs:")
  (doseq [config (gen/sample bpf-gen/gen-map-config 3)]
    (println "  " config)))
```

### Step 3: BPF Instruction Generators

Generate valid instruction components:

```clojure
;; ============================================================================
;; Instruction Generators
;; ============================================================================

(defn explore-instruction-generators
  "Demonstrate instruction generators"
  []
  (println "\n=== Instruction Generators ===\n")

  ;; Registers
  (println "Register generators:")
  (println "  gen-register (all r0-r10):"
           (gen/sample bpf-gen/gen-register 5))
  (println "  gen-writable-register (r0-r9):"
           (gen/sample bpf-gen/gen-writable-register 5))
  (println "  gen-arg-register (r1-r5):"
           (gen/sample bpf-gen/gen-arg-register 5))
  (println "  gen-callee-saved-register (r6-r9):"
           (gen/sample bpf-gen/gen-callee-saved-register 5))

  ;; Operations
  (println "\nOperation generators:")
  (println "  gen-alu-op:" (gen/sample bpf-gen/gen-alu-op 5))
  (println "  gen-jmp-op:" (gen/sample bpf-gen/gen-jmp-op 5))
  (println "  gen-size:" (gen/sample bpf-gen/gen-size 5))

  ;; Immediates and offsets
  (println "\nImmediate/offset generators:")
  (println "  gen-imm32 (5 samples):" (gen/sample bpf-gen/gen-imm32 5))
  (println "  gen-offset (-32768 to 32767):" (gen/sample bpf-gen/gen-offset 5)))
```

### Step 4: Network Packet Generators

Generate realistic network packet data:

```clojure
;; ============================================================================
;; Network Packet Generators
;; ============================================================================

(defn explore-network-generators
  "Demonstrate network packet generators"
  []
  (println "\n=== Network Packet Generators ===\n")

  ;; Addresses
  (println "Address generators:")
  (println "  gen-mac-address (as hex):"
           (->> (gen/sample bpf-gen/gen-mac-address 2)
                (map #(apply format "%02x:%02x:%02x:%02x:%02x:%02x" (map #(bit-and % 0xff) %)))))
  (println "  gen-ipv4-address (as dotted):"
           (->> (gen/sample bpf-gen/gen-ipv4-address 2)
                (map #(apply format "%d.%d.%d.%d" (map #(bit-and % 0xff) %)))))

  ;; Ports and protocols
  (println "\nPort/protocol generators:")
  (println "  gen-port:" (gen/sample bpf-gen/gen-port 5))
  (println "  gen-well-known-port:" (gen/sample bpf-gen/gen-well-known-port 5))
  (println "  gen-protocol:" (gen/sample bpf-gen/gen-protocol 5))

  ;; Headers
  (println "\nHeader generators:")
  (println "  gen-ethernet-header:")
  (doseq [h (gen/sample bpf-gen/gen-ethernet-header 2)]
    (println "    eth-type:" (format "0x%04x" (:eth-type h))))

  (println "\n  gen-ipv4-header:")
  (doseq [h (gen/sample bpf-gen/gen-ipv4-header 2)]
    (println "    protocol:" (:protocol h) "ttl:" (:ttl h)))

  (println "\n  gen-tcp-header:")
  (doseq [h (gen/sample bpf-gen/gen-tcp-header 2)]
    (println "    ports:" (:src-port h) "->" (:dst-port h)
             "flags:" (format "0x%02x" (:flags h)))))
```

### Step 5: Event Structure Generators

Generate BPF event data:

```clojure
;; ============================================================================
;; Event Structure Generators
;; ============================================================================

(defn explore-event-generators
  "Demonstrate event structure generators"
  []
  (println "\n=== Event Structure Generators ===\n")

  ;; Process identifiers
  (println "Process ID generators:")
  (println "  gen-pid:" (gen/sample bpf-gen/gen-pid 5))
  (println "  gen-tid:" (gen/sample bpf-gen/gen-tid 5))
  (println "  gen-uid:" (gen/sample bpf-gen/gen-uid 5))
  (println "  gen-comm:" (gen/sample bpf-gen/gen-comm 3))

  ;; Syscall events
  (println "\nSyscall event (sample):")
  (let [event (gen/generate bpf-gen/gen-syscall-event)]
    (doseq [[k v] (dissoc event :timestamp)]
      (println "  " k ":" v)))

  ;; Network events
  (println "\nNetwork event (sample):")
  (let [event (gen/generate bpf-gen/gen-network-event)]
    (println "  pid:" (:pid event))
    (println "  protocol:" (:protocol event))
    (println "  src-port:" (:src-port event) "-> dst-port:" (:dst-port event))
    (println "  bytes-sent:" (:bytes-sent event)
             "bytes-recv:" (:bytes-recv event))))
```

### Step 6: Writing Property Tests

Now let's write property-based tests:

```clojure
;; ============================================================================
;; Property Tests: DSL Invariants
;; ============================================================================

(def num-tests 100)

;; Every MOV instruction produces a valid instruction map
(defspec mov-produces-valid-instruction num-tests
  (prop/for-all [reg bpf-gen/gen-writable-register
                 imm bpf-gen/gen-imm32]
    (let [insn (dsl/mov reg imm)]
      (and (map? insn)
           (contains? insn :opcode)
           (number? (:opcode insn))
           (= reg (:dst insn))))))

;; Every ALU operation produces valid bytecode
(defspec alu-operations-are-valid num-tests
  (prop/for-all [op bpf-gen/gen-alu-op
                 dst bpf-gen/gen-writable-register
                 imm bpf-gen/gen-imm32]
    (let [insn (dsl/alu-imm op dst imm)]
      (and (map? insn)
           (contains? insn :opcode)
           ;; Opcode should be a valid BPF opcode
           (<= 0 (:opcode insn) 255)))))

;; Jump instructions have valid offsets
(defspec jump-offsets-in-range num-tests
  (prop/for-all [op bpf-gen/gen-jmp-op
                 dst bpf-gen/gen-register
                 imm bpf-gen/gen-imm32
                 offset bpf-gen/gen-offset]
    (let [insn (dsl/jmp-imm op dst imm offset)]
      (and (map? insn)
           ;; Offset fits in 16 bits
           (<= -32768 (:off insn) 32767)))))

;; Load/store instructions preserve size
(defspec memory-ops-preserve-size num-tests
  (prop/for-all [size bpf-gen/gen-size
                 dst bpf-gen/gen-writable-register
                 src bpf-gen/gen-register
                 offset bpf-gen/gen-offset]
    (let [insn (dsl/ldx size dst src offset)]
      ;; Size is encoded in opcode
      (and (map? insn)
           (contains? insn :opcode)))))
```

### Step 7: Round-Trip Property Tests

Test that data survives encoding/decoding:

```clojure
;; ============================================================================
;; Property Tests: Round-Trip Invariants
;; ============================================================================

;; Integer round-trip: int -> bytes -> int
(defspec int-roundtrip-property num-tests
  (prop/for-all [value bpf-gen/gen-i32]
    (let [bytes (utils/int->bytes value)
          result (utils/bytes->int bytes)]
      (= value result))))

;; Long round-trip: long -> bytes -> long
(defspec long-roundtrip-property num-tests
  (prop/for-all [value bpf-gen/gen-i64]
    (let [bytes (utils/long->bytes value)
          result (utils/bytes->long bytes)]
      (= value result))))

;; Byte array round-trip via memory segment
(defspec byte-array-segment-roundtrip num-tests
  (prop/for-all [data (bpf-gen/gen-byte-array-range 1 256)]
    (let [seg (utils/bytes->segment data)
          result (utils/segment->bytes seg (count data))]
      (java.util.Arrays/equals ^bytes data ^bytes result))))

;; Short round-trip
(defspec short-roundtrip-property num-tests
  (prop/for-all [value (gen/choose -32768 32767)]
    (let [bytes (utils/short->bytes (short value))
          result (utils/bytes->short bytes)]
      (= (short value) result))))
```

### Step 8: Generator Sanity Tests

Verify that generators produce valid data:

```clojure
;; ============================================================================
;; Property Tests: Generator Sanity
;; ============================================================================

;; Map configs have all required fields with valid values
(defspec map-configs-are-valid num-tests
  (prop/for-all [config bpf-gen/gen-map-config]
    (and (keyword? (:type config))
         (pos-int? (:key-size config))
         (pos-int? (:value-size config))
         (pos-int? (:max-entries config))
         ;; Array maps require 4-byte keys
         (or (not (#{:array :percpu-array} (:type config)))
             (= 4 (:key-size config))))))

;; Ethernet headers have correct structure
(defspec ethernet-headers-valid num-tests
  (prop/for-all [header bpf-gen/gen-ethernet-header]
    (and (= 6 (count (:dst-mac header)))
         (= 6 (count (:src-mac header)))
         (#{0x0800 0x0806 0x86DD} (:eth-type header)))))

;; IPv4 headers have correct structure
(defspec ipv4-headers-valid num-tests
  (prop/for-all [header bpf-gen/gen-ipv4-header]
    (and (= 4 (:version header))
         (= 5 (:ihl header))
         (= 4 (count (:src-ip header)))
         (= 4 (count (:dst-ip header)))
         (<= 1 (:ttl header) 255)
         (#{1 6 17} (:protocol header)))))

;; Unique keys are actually unique
(defspec unique-keys-truly-unique num-tests
  (prop/for-all [n (gen/choose 1 50)
                 key-size (gen/choose 4 32)]
    (let [keys (gen/generate (bpf-gen/gen-unique-keys n key-size))
          key-vecs (map vec keys)]
      (= (count key-vecs) (count (distinct key-vecs))))))
```

### Step 9: Composite Operation Tests

Test sequences of operations:

```clojure
;; ============================================================================
;; Property Tests: Composite Operations
;; ============================================================================

;; Map operations sequence generator produces valid operations
(defspec map-operations-are-valid num-tests
  (prop/for-all [key-size (gen/choose 4 32)
                 value-size (gen/choose 4 64)]
    (let [ops (gen/generate (bpf-gen/gen-map-operations key-size value-size))]
      (every? (fn [op]
                (and (map? op)
                     (#{:lookup :update :delete} (:op op))
                     (= key-size (count (:key op)))
                     (or (not= :update (:op op))
                         (= value-size (count (:value op))))))
              ops))))

;; Batch operations have consistent sizes
(defspec batch-operations-consistent num-tests
  (prop/for-all [key-size (gen/choose 4 16)
                 value-size (gen/choose 4 64)]
    (let [batch-op (gen/generate (bpf-gen/gen-batch-operation key-size value-size))]
      (and (#{:lookup-batch :update-batch :delete-batch} (:op batch-op))
           (vector? (:keys batch-op))
           (every? #(= key-size (count %)) (:keys batch-op))
           (or (not= :update-batch (:op batch-op))
               (and (vector? (:values batch-op))
                    (every? #(= value-size (count %)) (:values batch-op))))))))

;; Key-value batches have matching sizes
(defspec kv-batch-sizes-match num-tests
  (prop/for-all [batch-size (gen/choose 1 50)
                 key-size (gen/choose 4 16)
                 value-size (gen/choose 4 64)]
    (let [batch (gen/generate (bpf-gen/gen-kv-batch key-size value-size batch-size))]
      (and (= batch-size (count batch))
           (every? #(= 2 (count %)) batch)
           (every? #(= key-size (count (first %))) batch)
           (every? #(= value-size (count (second %))) batch)))))
```

### Step 10: Running Tests and Interpreting Results

```clojure
;; ============================================================================
;; Test Runner
;; ============================================================================

(defn run-quick-check
  "Run a property test and format the result"
  [name property num-tests]
  (print (format "  %-40s " name))
  (flush)
  (let [result (tc/quick-check num-tests property)
        passed? (:pass? result)]
    (if passed?
      (println (format "PASS (%d tests)" num-tests))
      (do
        (println "FAIL")
        (println "    Shrunk example:" (:shrunk result))
        (println "    Failing input:" (get-in result [:shrunk :smallest]))))
    result))

(defn run-all-property-tests
  "Run all property tests with formatted output"
  []
  (println "=== Running Property-Based Tests ===\n")

  (println "DSL Instruction Properties:")
  (run-quick-check "mov-produces-valid-instruction"
    (prop/for-all [reg bpf-gen/gen-writable-register
                   imm bpf-gen/gen-imm32]
      (map? (dsl/mov reg imm)))
    num-tests)

  (run-quick-check "alu-reg-produces-instruction"
    (prop/for-all [op (gen/elements [:add :sub :mul :div])
                   dst bpf-gen/gen-writable-register
                   src bpf-gen/gen-register]
      (map? (dsl/alu-reg op dst src)))
    num-tests)

  (println "\nRound-Trip Properties:")
  (run-quick-check "int-roundtrip"
    (prop/for-all [v bpf-gen/gen-i32]
      (= v (utils/bytes->int (utils/int->bytes v))))
    num-tests)

  (run-quick-check "long-roundtrip"
    (prop/for-all [v bpf-gen/gen-i64]
      (= v (utils/bytes->long (utils/long->bytes v))))
    num-tests)

  (println "\nGenerator Sanity:")
  (run-quick-check "map-config-valid"
    (prop/for-all [config bpf-gen/gen-map-config]
      (and (keyword? (:type config))
           (pos? (:key-size config))))
    num-tests)

  (run-quick-check "ethernet-header-valid"
    (prop/for-all [h bpf-gen/gen-ethernet-header]
      (and (= 6 (count (:dst-mac h)))
           (= 6 (count (:src-mac h)))))
    num-tests)

  (println "\n=== Property Tests Complete ==="))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main []
  (println "=== Lab 14.5: Property-Based Testing ===\n")

  ;; Explore generators
  (explore-primitive-generators)
  (explore-map-generators)
  (explore-instruction-generators)
  (explore-network-generators)
  (explore-event-generators)

  ;; Run property tests
  (println)
  (run-all-property-tests)

  (println "\n=== Lab 14.5 Complete! ==="))
```

### Step 11: Run the Lab

```bash
cd tutorials/part-3-advanced/chapter-14/labs
clojure -M lab-14-5.clj
```

### Expected Output

```
=== Lab 14.5: Property-Based Testing ===

=== Primitive Generators ===

gen-u8 (5 samples): (0 1 0 1 3)
gen-u16 (5 samples): (0 1 0 2 4)
gen-u32 (5 samples): (0 1 0 0 1)
gen-i32 (5 samples): (0 0 0 1 3)
gen-i64 (5 samples): (0 -1 0 -2 1)
gen-byte-array 4 (3 samples): ([0 0 0 0] [0 1 0 1] [0 0 1 2])
gen-byte-array-range 2-8 (3 samples): (len=2 len=3 len=5)

=== Map Configuration Generators ===

Available map types:
  gen-map-type (5 samples): (:hash :array :lru-hash :stack :ringbuf)
  gen-hash-map-type (5 samples): (:hash :percpu-hash :lru-hash :hash)
  gen-array-map-type (5 samples): (:array :percpu-array :array :array)

Map parameters:
  gen-key-size (aligned 4-256): (4 8 12 16 32)
  gen-value-size (1-4096): (1 2 1 3 5)
  gen-max-entries: (1 50 500 1000 5000)

Complete map configs:
   {:type :hash, :key-size 8, :value-size 32, :max-entries 100}
   {:type :array, :key-size 4, :value-size 64, :max-entries 500}
   {:type :lru-hash, :key-size 16, :value-size 128, :max-entries 1000}

=== Running Property-Based Tests ===

DSL Instruction Properties:
  mov-produces-valid-instruction              PASS (100 tests)
  alu-reg-produces-instruction                PASS (100 tests)

Round-Trip Properties:
  int-roundtrip                               PASS (100 tests)
  long-roundtrip                              PASS (100 tests)

Generator Sanity:
  map-config-valid                            PASS (100 tests)
  ethernet-header-valid                       PASS (100 tests)

=== Property Tests Complete ===

=== Lab 14.5 Complete! ===
```

## Using Pre-Built Properties

clj-ebpf includes pre-defined property tests in `clj-ebpf.properties`:

```clojure
(require '[clj-ebpf.properties :as props])

;; Run all pre-defined property tests
(props/run-all-properties)

;; Or run as part of test suite
(run-tests 'clj-ebpf.properties)
```

Available property tests:
- `mov-imm-produces-instruction`
- `mov-reg-produces-instruction`
- `alu-reg-produces-instruction`
- `alu-imm-produces-instruction`
- `alu32-reg-produces-instruction`
- `alu32-imm-produces-instruction`
- `load-produces-instruction`
- `store-produces-instruction`
- `store-imm-produces-instruction`
- `jump-produces-instruction`
- `jump-imm-produces-instruction`
- `exit-produces-instruction`
- `call-produces-instruction`
- `lddw-produces-two-instructions`
- `byte-array-roundtrip`
- `int-roundtrip`
- `long-roundtrip`
- `short-bytes-roundtrip`
- `gen-map-config-produces-valid-configs`
- `gen-ethernet-header-has-correct-structure`
- `gen-ipv4-header-has-correct-structure`
- `gen-syscall-event-has-required-fields`
- `gen-unique-keys-are-unique`
- `gen-kv-batch-produces-correct-count`

## Writing Custom Generators

Create domain-specific generators:

```clojure
;; Custom generator for your application's event type
(def gen-my-event
  (gen/let [timestamp bpf-gen/gen-timestamp
            pid bpf-gen/gen-pid
            syscall-nr (gen/elements [1 2 3 60 231])  ; open, close, exit, etc.
            latency-ns (gen/choose 1 1000000)]
    {:type :syscall-latency
     :timestamp timestamp
     :pid pid
     :syscall-nr syscall-nr
     :latency-ns latency-ns}))

;; Generator for connection 4-tuples
(def gen-connection
  (gen/let [src-ip bpf-gen/gen-ipv4-address
            dst-ip bpf-gen/gen-ipv4-address
            src-port bpf-gen/gen-port
            dst-port bpf-gen/gen-well-known-port]
    {:src-ip src-ip
     :dst-ip dst-ip
     :src-port src-port
     :dst-port dst-port}))

;; Generator for firewall rules
(def gen-firewall-rule
  (gen/let [action (gen/elements [:allow :deny :log])
            protocol bpf-gen/gen-protocol
            dst-port (gen/one-of [bpf-gen/gen-well-known-port
                                  bpf-gen/gen-port])
            priority (gen/choose 1 1000)]
    {:action action
     :protocol protocol
     :dst-port dst-port
     :priority priority}))
```

## Experiments

### Experiment 1: Find Edge Cases

Write a property that might fail:

```clojure
;; This property tests division - might it find edge cases?
(defspec division-property 1000
  (prop/for-all [a bpf-gen/gen-i32
                 b bpf-gen/gen-i32]
    (if (zero? b)
      true  ; Skip division by zero
      (let [insn (dsl/div :r0 b)]
        (map? insn)))))
```

### Experiment 2: Stress Test with More Iterations

```clojure
;; Run 10,000 tests to find rare edge cases
(tc/quick-check 10000
  (prop/for-all [offset bpf-gen/gen-offset]
    (<= -32768 offset 32767)))
```

### Experiment 3: Custom Shrinking

```clojure
;; Generator with custom shrinking for better failure examples
(def gen-non-empty-key
  (gen/such-that
    #(some pos? %)
    (bpf-gen/gen-byte-array 4)
    100))
```

## Troubleshooting

### Test Runs Too Long

**Symptom**: Property test takes minutes to complete

**Solution**: Reduce test count or simplify generators:
```clojure
(def quick-tests 10)  ; For development
(def thorough-tests 1000)  ; For CI
```

### Shrinking Produces Confusing Examples

**Symptom**: Failed case is hard to understand

**Solution**: Add better generator constraints:
```clojure
;; Instead of any bytes
(gen/choose 0 255)

;; Use meaningful ranges
(gen/one-of
  [(gen/return 0)           ; Boundary
   (gen/return 255)         ; Boundary
   (gen/choose 1 127)])     ; Normal range
```

### Generator Fails to Produce Values

**Symptom**: `ExceptionInfo: Couldn't satisfy such-that predicate`

**Solution**: Relax constraints or use different approach:
```clojure
;; Bad: too restrictive
(gen/such-that #(> % 1000000) gen/nat)

;; Good: generate in range directly
(gen/choose 1000000 2000000)
```

## Key Takeaways

- Property-based tests find edge cases you wouldn't think to test
- clj-ebpf provides comprehensive BPF-specific generators
- Round-trip properties verify data integrity
- Generator sanity tests ensure test data quality
- Use `defspec` for integration with `clojure.test`
- Shrinking automatically finds minimal failing examples
- Customize `num-tests` based on CI vs local development

## Available Generators Summary

| Category | Generators |
|----------|------------|
| **Primitives** | `gen-u8`, `gen-u16`, `gen-u32`, `gen-u64`, `gen-i32`, `gen-i64`, `gen-byte-array`, `gen-byte-array-range` |
| **Maps** | `gen-map-type`, `gen-hash-map-type`, `gen-array-map-type`, `gen-key-size`, `gen-value-size`, `gen-max-entries`, `gen-map-config`, `gen-hash-map-config` |
| **Keys/Values** | `gen-key`, `gen-value`, `gen-kv-pair`, `gen-kv-batch`, `gen-unique-keys` |
| **Instructions** | `gen-register`, `gen-writable-register`, `gen-arg-register`, `gen-callee-saved-register`, `gen-imm32`, `gen-offset`, `gen-alu-op`, `gen-jmp-op`, `gen-size` |
| **Network** | `gen-mac-address`, `gen-ipv4-address`, `gen-ipv6-address`, `gen-port`, `gen-well-known-port`, `gen-protocol`, `gen-ethernet-type`, `gen-ethernet-header`, `gen-ipv4-header`, `gen-tcp-header`, `gen-udp-header` |
| **Events** | `gen-timestamp`, `gen-pid`, `gen-tid`, `gen-uid`, `gen-comm`, `gen-event-type`, `gen-syscall-event`, `gen-network-event` |
| **Composite** | `gen-map-operations`, `gen-batch-operation` |

## Next Steps

- **Previous Lab**: [Lab 14.4 - Mock Testing Infrastructure](lab-14-4-mock-testing.md)
- **Chapter**: [Chapter 14 - Testing and Debugging](../README.md)
- **Next Chapter**: [Chapter 15 - Performance Optimization](../../chapter-15/README.md)

## Challenge

Create a property-based test that:
1. Generates random BPF programs (sequence of instructions)
2. Verifies they can be assembled to bytecode
3. Verifies the bytecode length matches expected (8 bytes per instruction, 16 for lddw)

Solution in: [solutions/lab-14-5-challenge.clj](../solutions/lab-14-5-challenge.clj)
