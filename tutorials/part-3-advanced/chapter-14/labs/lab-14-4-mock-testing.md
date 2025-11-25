# Lab 14.4: Mock Testing Infrastructure

## Objective

Learn to use clj-ebpf's built-in mock syscall layer to test BPF logic without requiring CAP_BPF privileges or root access. This enables fast, isolated unit testing in any environment.

## Learning Goals

- Understand the mock syscall architecture
- Use `clj-ebpf.mock` for unprivileged testing
- Leverage test fixtures and utilities
- Inject failures for error path testing
- Build comprehensive test suites without real BPF

## Why Mock Testing?

**Problem**: Real BPF testing requires:
- Root privileges or CAP_BPF capability
- Linux kernel 5.8+
- Cannot run in CI/CD pipelines easily
- Slow due to kernel interactions

**Solution**: Mock syscall layer enables:
- Testing without any privileges
- Running on any OS (for logic testing)
- Fast execution (no kernel round-trips)
- Deterministic failure injection
- CI/CD integration

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Your Test Code                       │
│                                                      │
│  (maps/create-map :hash 100 4 8)                    │
│                    ↓                                 │
├─────────────────────────────────────────────────────┤
│              clj-ebpf.maps API                       │
│                    ↓                                 │
├─────────────────────────────────────────────────────┤
│         *mock-enabled* = true?                       │
│              ↙           ↘                           │
│           Yes              No                        │
│            ↓               ↓                         │
│  ┌─────────────────┐  ┌─────────────────┐           │
│  │  Mock Layer     │  │  Real Syscall   │           │
│  │  (In-memory)    │  │  (Kernel BPF)   │           │
│  └─────────────────┘  └─────────────────┘           │
└─────────────────────────────────────────────────────┘
```

## Implementation

```clojure
(ns testing.mock-infrastructure
  "Comprehensive mock testing using clj-ebpf.mock"
  (:require [clojure.test :refer :all]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.mock :as mock]
            [clj-ebpf.test-utils :as tu]
            [clj-ebpf.errors :as errors]))

;; ============================================================================
;; Basic Mock Usage
;; ============================================================================

(deftest test-basic-mock-mode
  (testing "Mock mode enables unprivileged testing"
    ;; Enable mock mode
    (mock/with-mock-bpf

      ;; Create a map - no real BPF syscall!
      (let [m (mock/mock-map-create
                {:map-type :hash
                 :key-size 4
                 :value-size 8
                 :max-entries 100})]

        ;; Perform operations
        (mock/mock-map-update m (tu/make-key 1) (tu/make-value 100))
        (mock/mock-map-update m (tu/make-key 2) (tu/make-value 200))

        ;; Verify
        (let [result (mock/mock-map-lookup m (tu/make-key 1))]
          (is (= 100 (tu/value->long result))))

        ;; Delete
        (mock/mock-map-delete m (tu/make-key 1))
        (is (nil? (mock/mock-map-lookup m (tu/make-key 1))))))))

;; ============================================================================
;; Using Test Fixtures
;; ============================================================================

;; Apply mock fixture to all tests in namespace
(use-fixtures :each tu/mock-fixture)

(deftest test-with-fixture
  (testing "Fixture automatically enables mock mode"
    ;; mock-fixture already enabled mock mode
    (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (let [key (tu/make-key 42)
            val (tu/make-value 12345)]

        ;; Operations work without CAP_BPF
        (maps/map-update m key val)

        (let [result (maps/map-lookup m key)]
          (tu/assert-bytes-equal val result))))))

(deftest test-multiple-maps
  (testing "Multiple maps in mock mode"
    (tu/with-temp-map [hash-map {:type :hash :key-size 4 :value-size 8 :max-entries 50}]
      (tu/with-temp-map [array-map {:type :array :key-size 4 :value-size 8 :max-entries 10}]

        ;; Use both maps
        (maps/map-update hash-map (tu/make-key 1) (tu/make-value 100))
        (maps/map-update array-map (tu/make-key 0) (tu/make-value 200))

        ;; Verify independently
        (is (= 100 (tu/value->long (maps/map-lookup hash-map (tu/make-key 1)))))
        (is (= 200 (tu/value->long (maps/map-lookup array-map (tu/make-key 0)))))))))

;; ============================================================================
;; Testing Map Types
;; ============================================================================

(deftest test-hash-map-semantics
  (testing "Hash map mock follows real semantics"
    (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 3}]

      ;; Test insert
      (maps/map-update m (tu/make-key 1) (tu/make-value 10))
      (maps/map-update m (tu/make-key 2) (tu/make-value 20))
      (maps/map-update m (tu/make-key 3) (tu/make-value 30))

      ;; Test lookup
      (is (= 20 (tu/value->long (maps/map-lookup m (tu/make-key 2)))))

      ;; Test update existing key
      (maps/map-update m (tu/make-key 2) (tu/make-value 25))
      (is (= 25 (tu/value->long (maps/map-lookup m (tu/make-key 2)))))

      ;; Test overflow (max-entries = 3)
      (tu/assert-throws-errno :enospc
        (maps/map-update m (tu/make-key 4) (tu/make-value 40))))))

(deftest test-array-map-semantics
  (testing "Array map mock follows real semantics"
    (tu/with-temp-map [m {:type :array :key-size 4 :value-size 8 :max-entries 5}]

      ;; Array maps have implicit zero-initialization
      (is (= 0 (tu/value->long (maps/map-lookup m (tu/make-key 0)))))

      ;; Update specific indices
      (maps/map-update m (tu/make-key 2) (tu/make-value 200))
      (is (= 200 (tu/value->long (maps/map-lookup m (tu/make-key 2)))))

      ;; Out of bounds access
      (tu/assert-throws-errno :enoent
        (maps/map-lookup m (tu/make-key 10))))))

(deftest test-lru-hash-map-semantics
  (testing "LRU hash map eviction behavior"
    (tu/with-temp-map [m {:type :lru-hash :key-size 4 :value-size 8 :max-entries 3}]

      ;; Fill the map
      (maps/map-update m (tu/make-key 1) (tu/make-value 10))
      (maps/map-update m (tu/make-key 2) (tu/make-value 20))
      (maps/map-update m (tu/make-key 3) (tu/make-value 30))

      ;; Access key 1 to make it recently used
      (maps/map-lookup m (tu/make-key 1))

      ;; Add new entry - should evict LRU (key 2)
      (maps/map-update m (tu/make-key 4) (tu/make-value 40))

      ;; Key 1 should still exist (was accessed)
      (is (some? (maps/map-lookup m (tu/make-key 1))))

      ;; Key 2 should be evicted
      (is (nil? (maps/map-lookup m (tu/make-key 2)))))))

;; ============================================================================
;; Failure Injection
;; ============================================================================

(deftest test-transient-failure-injection
  (testing "Inject transient EAGAIN errors"
    (mock/with-mock-failure :map-lookup {:errno :eagain :count 2}
      (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 100}]
        (let [key (tu/make-key 1)
              val (tu/make-value 100)]

          (maps/map-update m key val)

          ;; First two lookups will fail with EAGAIN
          (is (thrown-with-msg? Exception #"EAGAIN"
                (maps/map-lookup m key)))

          (is (thrown-with-msg? Exception #"EAGAIN"
                (maps/map-lookup m key)))

          ;; Third lookup succeeds
          (tu/assert-bytes-equal val (maps/map-lookup m key)))))))

(deftest test-permanent-failure-injection
  (testing "Inject permanent EPERM errors"
    (mock/with-mock-failure :map-create {:errno :eperm :permanent true}
      (tu/assert-throws-errno :eperm
        (maps/create-map :hash 100 4 8)))))

(deftest test-retry-with-transient-failures
  (testing "Retry logic handles transient failures"
    (mock/with-mock-failure :map-lookup {:errno :eagain :count 2}
      (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 100}]
        (let [key (tu/make-key 1)
              val (tu/make-value 100)]

          (maps/map-update m key val)

          ;; Use errors/with-retry to handle transient failures
          (let [result (errors/with-retry {:max-retries 5}
                         (maps/map-lookup m key))]
            (tu/assert-bytes-equal val result)))))))

(deftest test-selective-failure-injection
  (testing "Failures only affect specified operations"
    (mock/with-mock-failure :map-delete {:errno :enoent :permanent true}
      (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 100}]
        (let [key (tu/make-key 1)
              val (tu/make-value 100)]

          ;; These work fine
          (maps/map-update m key val)
          (tu/assert-bytes-equal val (maps/map-lookup m key))

          ;; Only delete fails
          (tu/assert-throws-errno :enoent
            (maps/map-delete m key)))))))

;; ============================================================================
;; Testing Business Logic
;; ============================================================================

;; Example: Rate limiter logic
(defn rate-limiter-check
  "Check if request should be rate limited"
  [rate-map client-ip max-requests window-ms]
  (let [now (System/currentTimeMillis)
        key (tu/make-key (hash client-ip))
        current (maps/map-lookup rate-map key)]

    (if (nil? current)
      ;; First request
      (do
        (maps/map-update rate-map key (tu/make-value 1))
        :allow)

      ;; Check count
      (let [count (tu/value->long current)]
        (if (>= count max-requests)
          :deny
          (do
            (maps/map-update rate-map key (tu/make-value (inc count)))
            :allow))))))

(deftest test-rate-limiter-logic
  (testing "Rate limiter allows up to max requests"
    (tu/with-temp-map [rate-map {:type :hash :key-size 4 :value-size 8 :max-entries 1000}]
      (let [client "192.168.1.100"
            max-requests 5]

        ;; First 5 requests allowed
        (dotimes [_ 5]
          (is (= :allow (rate-limiter-check rate-map client max-requests 60000))))

        ;; 6th request denied
        (is (= :deny (rate-limiter-check rate-map client max-requests 60000)))))))

;; Example: Firewall logic
(defn firewall-check
  "Check if IP should be blocked"
  [blacklist-map src-ip]
  (let [key (byte-array (map unchecked-byte src-ip))]
    (if (maps/map-lookup blacklist-map key)
      :block
      :allow)))

(deftest test-firewall-logic
  (testing "Firewall blocks blacklisted IPs"
    (tu/with-temp-map [blacklist {:type :hash :key-size 4 :value-size 1 :max-entries 1000}]
      ;; Add blocked IP
      (let [blocked-ip [192 168 1 100]
            allowed-ip [192 168 1 1]]

        (maps/map-update blacklist
                        (byte-array (map unchecked-byte blocked-ip))
                        (byte-array [1]))

        ;; Test blocking
        (is (= :block (firewall-check blacklist blocked-ip)))
        (is (= :allow (firewall-check blacklist allowed-ip)))))))

;; ============================================================================
;; Testing Concurrent Access
;; ============================================================================

(deftest test-concurrent-map-access
  (testing "Concurrent access to mock maps"
    (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 1000}]
      (let [num-threads 10
            ops-per-thread 100
            results (atom [])]

        ;; Run concurrent operations
        (let [futures (doall
                        (for [t (range num-threads)]
                          (future
                            (dotimes [i ops-per-thread]
                              (let [key (tu/make-key (+ (* t ops-per-thread) i))
                                    val (tu/make-value i)]
                                (maps/map-update m key val)
                                (swap! results conj [:insert key]))))))]

          ;; Wait for completion
          (doseq [f futures] @f))

        ;; Verify some entries
        (is (= 0 (tu/value->long (maps/map-lookup m (tu/make-key 0)))))
        (is (= 50 (tu/value->long (maps/map-lookup m (tu/make-key 50)))))))))

;; ============================================================================
;; Mock Program Loading
;; ============================================================================

(deftest test-mock-program-load
  (testing "Mock program loading"
    (mock/with-mock-bpf
      (let [prog (mock/mock-program-load
                   {:type :xdp
                    :insns [(tu/make-value 0x95 8)]  ; exit instruction
                    :name "test-prog"})]

        (is (some? prog))
        (is (pos? (:fd prog)))

        ;; Unload
        (mock/mock-program-unload prog)))))

;; ============================================================================
;; Integration with Real Code
;; ============================================================================

(deftest test-real-application-logic
  (testing "Test real application logic in mock mode"
    ;; This tests the actual application logic without needing real BPF

    (tu/with-temp-map [counters {:type :array :key-size 4 :value-size 8 :max-entries 256}]
      ;; Simulate packet processing
      (let [process-packet (fn [protocol]
                            (let [key (tu/make-key protocol)
                                  current (or (some-> (maps/map-lookup counters key)
                                                     tu/value->long)
                                             0)]
                              (maps/map-update counters key (tu/make-value (inc current)))))]

        ;; Process mixed traffic
        (dotimes [_ 100] (process-packet 6))   ; TCP
        (dotimes [_ 50] (process-packet 17))   ; UDP
        (dotimes [_ 25] (process-packet 1))    ; ICMP

        ;; Verify counters
        (is (= 100 (tu/value->long (maps/map-lookup counters (tu/make-key 6)))))
        (is (= 50 (tu/value->long (maps/map-lookup counters (tu/make-key 17)))))
        (is (= 25 (tu/value->long (maps/map-lookup counters (tu/make-key 1)))))))))

;; ============================================================================
;; Test Utilities Demo
;; ============================================================================

(deftest test-packet-building
  (testing "Packet building utilities"
    (let [packet (tu/build-test-packet
                   :protocol :tcp
                   :src-ip (byte-array [10 0 0 1])
                   :dst-ip (byte-array [10 0 0 2])
                   :src-port 8080
                   :dst-port 80)]

      (is (= 54 (count packet)) "TCP packet is 54 bytes")

      ;; Check structure
      (is (= 0x45 (bit-and (aget packet 14) 0xFF)) "IPv4 version + IHL"))))

(deftest test-performance-benchmarking
  (testing "Built-in performance benchmarking"
    (tu/with-temp-map [m {:type :hash :key-size 4 :value-size 8 :max-entries 10000}]

      (let [stats (tu/benchmark-op 1000
                    (fn []
                      (let [key (tu/random-key 4)
                            val (tu/random-value 8)]
                        (maps/map-update m key val))))]

        (println "\n=== Mock Map Performance ===")
        (println (format "Min: %s" (tu/format-ns (:min stats))))
        (println (format "Max: %s" (tu/format-ns (:max stats))))
        (println (format "Mean: %s" (tu/format-ns (:mean stats))))
        (println (format "Samples: %d" (:samples stats)))

        ;; Mock operations should be fast
        (is (< (:mean stats) 100000) "Mock operations < 100µs")))))

;; ============================================================================
;; Running Tests
;; ============================================================================

(defn run-mock-tests
  "Run all mock infrastructure tests"
  []
  (println "=== Mock Testing Infrastructure ===")
  (println "No CAP_BPF required!\n")

  (run-tests 'testing.mock-infrastructure))

(defn -main [& args]
  (let [results (run-mock-tests)]
    (System/exit (if (and (zero? (:fail results 0))
                          (zero? (:error results 0)))
                   0 1))))
```

## Key Concepts

### 1. Mock Mode Activation

```clojure
;; Option 1: with-mock-bpf macro
(mock/with-mock-bpf
  ;; All BPF ops are mocked here
  )

;; Option 2: Test fixture
(use-fixtures :each tu/mock-fixture)

;; Option 3: Manual toggle (for debugging)
(binding [mock/*mock-enabled* true]
  ;; Mocked
  )
```

### 2. Failure Injection

```clojure
;; Transient failure (N times)
(mock/with-mock-failure :map-lookup {:errno :eagain :count 2}
  ...)

;; Permanent failure
(mock/with-mock-failure :map-create {:errno :eperm :permanent true}
  ...)

;; Multiple operations
(mock/with-mock-failures
  {:map-lookup {:errno :eagain :count 1}
   :map-update {:errno :enospc :permanent true}}
  ...)
```

### 3. Supported Operations

| Operation | Mock Function | Notes |
|-----------|---------------|-------|
| Map create | `mock-map-create` | All map types supported |
| Map lookup | `mock-map-lookup` | Returns nil if not found |
| Map update | `mock-map-update` | Respects max-entries |
| Map delete | `mock-map-delete` | Returns success/failure |
| Program load | `mock-program-load` | Returns mock FD |

### 4. Map Type Behaviors

| Map Type | Mock Behavior |
|----------|---------------|
| Hash | Standard hash map, ENOSPC on overflow |
| Array | Zero-initialized, fixed size |
| LRU Hash | Evicts least-recently-used on overflow |
| Per-CPU | Simulated per-CPU with thread ID |

## Expected Output

```
=== Mock Testing Infrastructure ===
No CAP_BPF required!

Testing testing.mock-infrastructure

=== Mock Map Performance ===
Min: 0.89 µs
Max: 12.34 µs
Mean: 1.45 µs
Samples: 1000

Ran 15 tests containing 32 assertions.
0 failures, 0 errors.
```

## Best Practices

1. **Always use mock for unit tests** - Save real BPF for integration tests
2. **Test edge cases** - Use failure injection liberally
3. **Verify semantics** - Mock should behave like real BPF
4. **Combine with test-utils** - Use fixtures and assertions together
5. **Run in CI/CD** - Mock tests can run anywhere
6. **Performance test separately** - Mock is faster but not representative

## Challenges

1. **Simulate per-CPU maps**: Use thread ID as CPU proxy
2. **Test atomic operations**: Implement lock-based simulation
3. **Ring buffer mocking**: Implement producer/consumer simulation
4. **BTF type validation**: Mock type checking

## Key Takeaways

- Mock syscall layer enables testing without privileges
- `mock/with-mock-bpf` is the primary entry point
- Failure injection tests error handling paths
- Combine with `test-utils` for complete testing
- Mock is fast but use real BPF for final validation
- All map types have mock implementations

## clj-ebpf Modules Used

| Module | Purpose |
|--------|---------|
| `clj-ebpf.mock` | Mock syscall layer, failure injection |
| `clj-ebpf.test-utils` | Fixtures, data generators, assertions |
| `clj-ebpf.errors` | Retry logic, error classification |
| `clj-ebpf.maps` | Map operations (work with mock transparently) |

## References

- [clj-ebpf.mock Source](../../../test/clj_ebpf/mock.clj)
- [clj-ebpf.test-utils Source](../../../test/clj_ebpf/test_utils.clj)
- [Clojure Testing Guide](https://clojure.org/guides/deps_and_cli#testing)
