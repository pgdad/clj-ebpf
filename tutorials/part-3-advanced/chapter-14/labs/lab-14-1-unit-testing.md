# Lab 14.1: Unit Testing Framework

## Objective

Build a comprehensive unit testing framework for BPF programs that provides test fixtures, assertions, mock data generation, and automated test execution. Learn to use clj-ebpf's built-in testing infrastructure.

## Learning Goals

- Use the built-in mock syscall layer for unprivileged testing
- Leverage test utilities for common patterns
- Design testable BPF programs
- Create reusable test fixtures
- Implement BPF-specific assertions
- Generate mock packet/event data
- Automate test execution

## Architecture

```
┌─────────────────────────────────────────────┐
│         Test Framework                      │
│                                             │
│  ┌────────────────┐  ┌─────────────────┐   │
│  │ clj-ebpf.mock  │  │ clj-ebpf.test-  │   │
│  │  (syscalls)    │  │    utils        │   │
│  └────────────────┘  └─────────────────┘   │
│         ↓                    ↓              │
│  ┌──────────────────────────────────────┐  │
│  │     Test Runner (clojure.test)       │  │
│  └──────────────────────────────────────┘  │
│         ↓                                   │
│  ┌──────────────────────────────────────┐  │
│  │     BPF Program (mock or real)       │  │
│  └──────────────────────────────────────┘  │
│         ↓                                   │
│  ┌──────────────────────────────────────┐  │
│  │     Results + Coverage               │  │
│  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## Built-in Testing Infrastructure

clj-ebpf provides two key namespaces for testing:

### 1. `clj-ebpf.mock` - Mock Syscall Layer

Enables testing BPF logic **without CAP_BPF capabilities**:

```clojure
(require '[clj-ebpf.mock :as mock])

;; Enable mock mode for testing
(mock/with-mock-bpf
  ;; All BPF operations use in-memory simulation
  (let [m (maps/create-map :hash 100 4 8)]
    (maps/map-update m key val)
    (maps/map-lookup m key)))
```

### 2. `clj-ebpf.test-utils` - Test Utilities

Provides fixtures, data generators, and assertions:

```clojure
(require '[clj-ebpf.test-utils :as tu])

;; Check if real BPF is available
(tu/has-bpf-capabilities?)  ; => true/false

;; Use fixtures
(use-fixtures :each tu/mock-fixture)

;; Generate test data
(tu/make-key 42)       ; => byte array key
(tu/make-value 100)    ; => byte array value
(tu/make-entries 10 4 8)  ; => 10 [key value] pairs

;; Build test packets
(tu/build-test-packet :protocol :tcp :src-port 8080)
```

## Implementation

```clojure
(ns testing.unit-framework
  "Unit testing framework using clj-ebpf's built-in testing infrastructure"
  (:require [clojure.test :refer :all]
            [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.mock :as mock]
            [clj-ebpf.test-utils :as tu]
            [clj-ebpf.errors :as errors]))

;; ============================================================================
;; Test Fixtures (Using Built-in Infrastructure)
;; ============================================================================

;; Use the built-in mock fixture for all tests
(use-fixtures :each tu/mock-fixture)

;; For tests that require real BPF, use capabilities fixture
;; (use-fixtures :once tu/capabilities-fixture)

;; Custom fixture combining mock + cleanup
(defn comprehensive-fixture
  "Fixture that uses mock BPF and ensures cleanup"
  [f]
  (tu/mock-fixture
    (fn []
      (tu/cleanup-fixture f))))

;; ============================================================================
;; Testing Maps with Mock Infrastructure
;; ============================================================================

(deftest test-hash-map-operations
  (testing "Hash map basic operations in mock mode"
    ;; mock-fixture already enabled mock mode
    (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (let [key (tu/make-key 42)
            val (tu/make-value 12345)]

        ;; Insert
        (maps/map-update m key val)

        ;; Lookup
        (let [result (maps/map-lookup m key)]
          (tu/assert-bytes-equal val result "Value should match"))

        ;; Delete
        (maps/map-delete m key)
        (is (nil? (maps/map-lookup m key)) "Key should be deleted")))))

(deftest test-array-map-operations
  (testing "Array map operations"
    (tu/with-temp-map [m {:type :array :key-size 4 :value-size 8 :max-entries 10}]
      (doseq [[key-bytes val-bytes] (tu/make-entries 10 4 8)]
        (maps/map-update m key-bytes val-bytes))

      ;; Verify all entries
      (doseq [i (range 10)]
        (let [key (tu/make-key i)
              expected (tu/make-value (* i i))
              actual (maps/map-lookup m key)]
          (tu/assert-bytes-equal expected actual))))))

(deftest test-map-overflow
  (testing "Map overflow behavior"
    (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 5}]
      ;; Fill the map
      (doseq [i (range 5)]
        (maps/map-update m (tu/make-key i) (tu/make-value i)))

      ;; Attempting to add 6th entry should fail
      (tu/assert-throws-errno :enospc
        (maps/map-update m (tu/make-key 99) (tu/make-value 99))))))

;; ============================================================================
;; Mock Packet Generation (Using Built-in Helpers)
;; ============================================================================

(deftest test-packet-generation
  (testing "Packet building utilities"
    (let [tcp-packet (tu/build-test-packet
                       :protocol :tcp
                       :src-ip (byte-array [192 168 1 1])
                       :dst-ip (byte-array [10 0 0 1])
                       :src-port 12345
                       :dst-port 80)]

      ;; Verify packet structure
      (is (= 54 (count tcp-packet)) "TCP packet should be 54 bytes (eth+ip+tcp)")

      ;; Check EtherType (IPv4 = 0x0800)
      (is (= 0x08 (bit-and (aget tcp-packet 12) 0xFF)))
      (is (= 0x00 (bit-and (aget tcp-packet 13) 0xFF))))))

(deftest test-ethernet-header
  (testing "Ethernet header building"
    (let [eth (tu/build-eth-header
                :src-mac (byte-array [0x00 0x11 0x22 0x33 0x44 0x55])
                :dst-mac (byte-array [0xFF 0xFF 0xFF 0xFF 0xFF 0xFF])
                :eth-type 0x0800)]

      (is (= 14 (count eth)) "Ethernet header is 14 bytes"))))

(deftest test-ipv4-header
  (testing "IPv4 header building"
    (let [ip (tu/build-ipv4-header
               :src-ip (byte-array [10 0 0 1])
               :dst-ip (byte-array [10 0 0 2])
               :protocol 6  ; TCP
               :ttl 64)]

      (is (= 20 (count ip)) "IPv4 header is 20 bytes")
      (is (= 0x45 (bit-and (aget ip 0) 0xFF)) "Version 4, IHL 5"))))

;; ============================================================================
;; Testing with Failure Injection
;; ============================================================================

(deftest test-transient-failures
  (testing "Handling transient BPF errors"
    ;; Inject failures for testing retry logic
    (mock/with-mock-failure :map-lookup {:errno :eagain :count 2}
      (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 100}]
        (let [key (tu/make-key 1)
              val (tu/make-value 100)]

          ;; First lookup will fail twice, then succeed
          (maps/map-update m key val)

          ;; With retry wrapper from errors.clj
          (let [result (errors/with-retry {:max-attempts 3}
                         (maps/map-lookup m key))]
            (tu/assert-bytes-equal val result)))))))

(deftest test-permission-errors
  (testing "Permission error handling"
    (mock/with-mock-failure :program-load {:errno :eperm :permanent true}
      (tu/assert-throws-errno :eperm
        (bpf/load-program some-program)))))

;; ============================================================================
;; BPF-Specific Assertions (Using Built-in + Custom)
;; ============================================================================

(defn assert-map-value
  "Assert map contains expected value at key"
  [bpf-map key-bytes expected-bytes]
  (let [actual (maps/map-lookup bpf-map key-bytes)]
    (tu/assert-bytes-equal expected-bytes actual
      (format "Map value mismatch for key %s" (vec key-bytes)))))

(defn assert-map-contains
  "Assert map contains key"
  [bpf-map key-bytes]
  (is (some? (maps/map-lookup bpf-map key-bytes))
      (format "Map should contain key %s" (vec key-bytes))))

(defn assert-map-empty
  "Assert map is empty (for hash maps)"
  [bpf-map]
  (let [first-key (maps/map-get-next-key bpf-map nil)]
    (is (nil? first-key) "Map should be empty")))

(defn assert-counter-incremented
  "Assert counter was incremented"
  [bpf-map key-bytes initial-value]
  (let [actual-bytes (maps/map-lookup bpf-map key-bytes)
        actual (tu/value->long actual-bytes)]
    (is (> actual initial-value)
        (format "Counter should increase: was %d, now %d" initial-value actual))))

(defn assert-xdp-action
  "Assert XDP program returned expected action"
  [result expected-action]
  (let [action-map {:aborted 0 :drop 1 :pass 2 :tx 3 :redirect 4}
        expected-code (get action-map expected-action)]
    (is (= expected-code (:return-value result))
        (format "Expected XDP action %s (%d), got %d"
                expected-action expected-code (:return-value result)))))

;; ============================================================================
;; Example Tests Using Full Infrastructure
;; ============================================================================

(deftest test-packet-counter-mock
  (testing "Packet counter logic in mock mode"
    (tu/with-temp-map [stats {:type :array :key-size 4 :value-size 8 :max-entries 256}]
      ;; Simulate packet processing
      (let [tcp-key (tu/make-key 6)    ; TCP protocol
            udp-key (tu/make-key 17)]  ; UDP protocol

        ;; Initialize counters
        (maps/map-update stats tcp-key (tu/make-value 0))
        (maps/map-update stats udp-key (tu/make-value 0))

        ;; Simulate 10 TCP packets
        (dotimes [_ 10]
          (let [current (tu/value->long (maps/map-lookup stats tcp-key))]
            (maps/map-update stats tcp-key (tu/make-value (inc current)))))

        ;; Simulate 5 UDP packets
        (dotimes [_ 5]
          (let [current (tu/value->long (maps/map-lookup stats udp-key))]
            (maps/map-update stats udp-key (tu/make-value (inc current)))))

        ;; Verify counters
        (is (= 10 (tu/value->long (maps/map-lookup stats tcp-key))))
        (is (= 5 (tu/value->long (maps/map-lookup stats udp-key))))))))

(deftest test-firewall-blacklist-mock
  (testing "Firewall blacklist logic"
    (tu/with-temp-map [blacklist {:type :hash :key-size 4 :value-size 4 :max-entries 1000}]
      (let [blocked-ip (byte-array [192 168 1 100])
            allowed-ip (byte-array [192 168 1 1])
            block-marker (tu/make-value 1 4)]

        ;; Add IP to blacklist
        (maps/map-update blacklist blocked-ip block-marker)

        ;; Check lookups
        (is (some? (maps/map-lookup blacklist blocked-ip))
            "Blocked IP should be in blacklist")
        (is (nil? (maps/map-lookup blacklist allowed-ip))
            "Allowed IP should not be in blacklist")))))

;; ============================================================================
;; Performance Testing Helpers (Using Built-in)
;; ============================================================================

(deftest test-map-performance
  (testing "Map operation performance"
    (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 10000}]

      ;; Benchmark insertions
      (let [stats (tu/benchmark-op 1000
                    (fn []
                      (let [key (tu/random-key 4)
                            val (tu/random-value 8)]
                        (maps/map-update m key val))))]

        (println "\n=== Insert Performance ===")
        (println (format "Min: %s" (tu/format-ns (:min stats))))
        (println (format "Max: %s" (tu/format-ns (:max stats))))
        (println (format "Mean: %s" (tu/format-ns (:mean stats))))
        (println (format "Median: %s" (tu/format-ns (:median stats))))

        ;; Assert reasonable performance
        (is (< (:mean stats) 1000000)  ; Less than 1ms average
            "Insert should be sub-millisecond")))))

;; ============================================================================
;; Testing Without Mock (Real BPF - Requires Capabilities)
;; ============================================================================

(deftest ^:integration test-real-bpf-map
  (testing "Real BPF map operations"
    (when-not (tu/has-bpf-capabilities?)
      (println "  [SKIPPED] Requires CAP_BPF")
      (is true)  ; Don't fail, just skip
      (return))

    ;; Real BPF test - runs only with capabilities
    (let [m (maps/create-map :hash 100 4 8)]
      (try
        (let [key (tu/make-key 42)
              val (tu/make-value 12345)]
          (maps/map-update m key val)
          (tu/assert-bytes-equal val (maps/map-lookup m key)))
        (finally
          (maps/close-map m))))))

;; ============================================================================
;; Test Coverage Analysis
;; ============================================================================

(defn analyze-test-results
  "Analyze test results and print summary"
  [results]
  (let [total (+ (:pass results 0) (:fail results 0) (:error results 0))
        pass-rate (if (pos? total)
                    (* 100.0 (/ (:pass results 0) total))
                    0.0)]

    (println "\n=== Test Summary ===")
    (println (format "Total tests: %d" total))
    (println (format "Passed: %d (%.1f%%)" (:pass results 0) pass-rate))
    (println (format "Failed: %d" (:fail results 0)))
    (println (format "Errors: %d" (:error results 0)))

    (when (< pass-rate 100)
      (println "\n⚠️  Some tests did not pass"))

    (zero? (+ (:fail results 0) (:error results 0)))))

;; ============================================================================
;; Test Suite Runner
;; ============================================================================

(defn run-test-suite
  "Run comprehensive test suite"
  []
  (println "=== BPF Unit Test Suite ===")
  (println "Using clj-ebpf.mock for unprivileged testing\n")

  (let [start-time (System/currentTimeMillis)
        results (run-tests 'testing.unit-framework)
        duration (- (System/currentTimeMillis) start-time)]

    (analyze-test-results results)
    (println (format "Duration: %dms" duration))

    (if (and (zero? (:fail results))
             (zero? (:error results)))
      (do
        (println "\n✓ All tests passed!")
        0)
      (do
        (println "\n✗ Some tests failed")
        1))))

(defn -main [& args]
  (System/exit (run-test-suite)))
```

## Test Organization

```
test/
├── clj_ebpf/
│   ├── mock.clj              ; Built-in mock syscall layer
│   ├── test_utils.clj        ; Built-in test utilities
│   ├── generators.clj        ; Property-based test generators
│   └── properties.clj        ; Property-based test properties
├── unit/
│   ├── maps_test.clj         ; Map unit tests
│   ├── programs_test.clj     ; Program tests
│   └── dsl_test.clj          ; DSL tests
└── integration/
    └── ...                   ; Integration tests (require CAP_BPF)
```

## Running Tests

```bash
# Run all unit tests (uses mock, no CAP_BPF needed)
clojure -M:test

# Run specific test namespace
clojure -M:test -n testing.unit-framework

# Run only mock-based tests
clojure -M:test -i :unit

# Run integration tests (requires CAP_BPF)
sudo clojure -M:test -i :integration

# Run with test.check for property-based tests
clojure -M:test:test-check
```

## Key Testing Patterns

### Pattern 1: Mock-Based Unit Tests

```clojure
(use-fixtures :each tu/mock-fixture)

(deftest test-map-logic
  (tu/with-temp-map [m config]
    ;; Test your logic here - no real BPF needed
    ))
```

### Pattern 2: Conditional Real BPF Tests

```clojure
(deftest ^:integration test-real-bpf
  (when-not (tu/has-bpf-capabilities?)
    (tu/skip-without-capabilities)
    (return))
  ;; Real BPF test here
  )
```

### Pattern 3: Failure Injection

```clojure
(deftest test-error-handling
  (mock/with-mock-failure :map-lookup {:errno :eagain}
    ;; Test that your code handles EAGAIN correctly
    ))
```

### Pattern 4: Performance Benchmarking

```clojure
(deftest test-performance
  (let [stats (tu/benchmark-op 1000 my-operation)]
    (is (< (:mean stats) threshold))))
```

## Expected Output

```
=== BPF Unit Test Suite ===
Using clj-ebpf.mock for unprivileged testing

Testing testing.unit-framework

Ran 12 tests containing 28 assertions.
0 failures, 0 errors.

=== Insert Performance ===
Min: 1.23 µs
Max: 45.67 µs
Mean: 3.45 µs
Median: 2.89 µs

=== Test Summary ===
Total tests: 12
Passed: 12 (100.0%)
Failed: 0
Errors: 0
Duration: 234ms

✓ All tests passed!
```

## Best Practices

1. **Use Mock Mode**: Always use `tu/mock-fixture` for unit tests
2. **Test Without Privileges**: Most tests should run without CAP_BPF
3. **Use Built-in Utilities**: Leverage `tu/make-key`, `tu/make-value`, etc.
4. **Assert Explicitly**: Use `tu/assert-bytes-equal` for byte comparisons
5. **Test Edge Cases**: Empty maps, full maps, invalid inputs
6. **Inject Failures**: Use `mock/with-mock-failure` for error path testing
7. **Benchmark Performance**: Use `tu/benchmark-op` for performance tests
8. **Tag Integration Tests**: Mark tests requiring CAP_BPF with `^:integration`

## Challenges

1. **Concurrent Testing**: Test per-CPU map behavior with multiple threads
2. **Property-Based Tests**: Use test.check with `generators.clj`
3. **Error Path Coverage**: Inject all errno values
4. **Performance Regression**: Track performance across commits
5. **Integration Suite**: Build comprehensive real-BPF tests

## Key Takeaways

- clj-ebpf provides `mock.clj` and `test-utils.clj` for testing
- Mock mode enables testing without CAP_BPF privileges
- Use fixtures for consistent test setup/teardown
- Failure injection helps test error handling
- Built-in utilities simplify common test patterns
- Separate unit tests (mock) from integration tests (real BPF)

## References

- [clj-ebpf.mock Documentation](../../api/mock.md)
- [clj-ebpf.test-utils Documentation](../../api/test-utils.md)
- [Clojure Testing](https://clojure.org/guides/deps_and_cli#testing)
- [Property-Based Testing](https://github.com/clojure/test.check)
