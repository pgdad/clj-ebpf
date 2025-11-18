# Lab 14.1: Unit Testing Framework

## Objective

Build a comprehensive unit testing framework for BPF programs that provides test fixtures, assertions, mock data generation, and automated test execution.

## Learning Goals

- Design testable BPF programs
- Create reusable test fixtures
- Implement BPF-specific assertions
- Generate mock packet/event data
- Automate test execution
- Measure test coverage

## Architecture

```
┌─────────────────────────────────────────────┐
│         Test Framework                      │
│                                             │
│  ┌────────────┐  ┌──────────────┐          │
│  │  Fixtures  │  │  Assertions  │          │
│  └────────────┘  └──────────────┘          │
│         ↓              ↓                    │
│  ┌──────────────────────────────┐          │
│  │     Test Runner              │          │
│  └──────────────────────────────┘          │
│         ↓                                   │
│  ┌──────────────────────────────┐          │
│  │     BPF Program              │          │
│  └──────────────────────────────┘          │
│         ↓                                   │
│  ┌──────────────────────────────┐          │
│  │     Results + Coverage       │          │
│  └──────────────────────────────┘          │
└─────────────────────────────────────────────┘
```

## Implementation

```clojure
(ns testing.unit-framework
  (:require [clj-ebpf.core :as bpf]
            [clojure.test :refer :all]))

;; ============================================================================
;; Test Fixtures
;; ============================================================================

(defn create-test-fixture
  "Create a test fixture with setup and teardown"
  [setup-fn teardown-fn]
  (fn [test-fn]
    (let [context (setup-fn)]
      (try
        (test-fn context)
        (finally
          (teardown-fn context))))))

(defn bpf-program-fixture
  "Standard fixture for testing BPF programs"
  [program-def]
  (create-test-fixture
    ;; Setup
    (fn []
      (let [prog (bpf/load-program program-def)]
        {:program prog
         :maps (:maps prog)
         :start-time (System/currentTimeMillis)}))

    ;; Teardown
    (fn [context]
      (bpf/unload-program (:program context))
      (println (format "Test duration: %dms"
                      (- (System/currentTimeMillis) (:start-time context)))))))

;; Example usage
(def packet-counter-fixture
  (bpf-program-fixture packet-counter-program))

(use-fixtures :each packet-counter-fixture)

;; ============================================================================
;; Mock Data Generation
;; ============================================================================

(defn generate-ipv4-packet
  "Generate mock IPv4 packet"
  [& {:keys [src-ip dst-ip protocol src-port dst-port payload-size]
      :or {src-ip "192.168.1.1"
           dst-ip "10.0.0.1"
           protocol 6  ; TCP
           src-port 12345
           dst-port 80
           payload-size 64}}]

  (let [packet (byte-array (+ 54 payload-size))]  ; Eth + IP + TCP + payload

    ;; Ethernet header (14 bytes)
    ;; Destination MAC
    (aset-byte packet 0 (byte 0xFF))
    (aset-byte packet 1 (byte 0xFF))
    (aset-byte packet 2 (byte 0xFF))
    (aset-byte packet 3 (byte 0xFF))
    (aset-byte packet 4 (byte 0xFF))
    (aset-byte packet 5 (byte 0xFF))

    ;; Source MAC
    (aset-byte packet 6 (byte 0x00))
    (aset-byte packet 7 (byte 0x11))
    (aset-byte packet 8 (byte 0x22))
    (aset-byte packet 9 (byte 0x33))
    (aset-byte packet 10 (byte 0x44))
    (aset-byte packet 11 (byte 0x55))

    ;; EtherType (0x0800 = IPv4)
    (aset-byte packet 12 (byte 0x08))
    (aset-byte packet 13 (byte 0x00))

    ;; IPv4 header (20 bytes, simplified)
    ;; Version + IHL
    (aset-byte packet 14 (byte 0x45))

    ;; Protocol
    (aset-byte packet 23 (byte protocol))

    ;; Source IP
    (let [src-parts (map #(Integer/parseInt %) (clojure.string/split src-ip #"\."))]
      (aset-byte packet 26 (byte (nth src-parts 0)))
      (aset-byte packet 27 (byte (nth src-parts 1)))
      (aset-byte packet 28 (byte (nth src-parts 2)))
      (aset-byte packet 29 (byte (nth src-parts 3))))

    ;; Destination IP
    (let [dst-parts (map #(Integer/parseInt %) (clojure.string/split dst-ip #"\."))]
      (aset-byte packet 30 (byte (nth dst-parts 0)))
      (aset-byte packet 31 (byte (nth dst-parts 1)))
      (aset-byte packet 32 (byte (nth dst-parts 2)))
      (aset-byte packet 33 (byte (nth dst-parts 3))))

    ;; TCP/UDP header (20 bytes, simplified)
    ;; Source port (big-endian)
    (aset-byte packet 34 (byte (bit-shift-right src-port 8)))
    (aset-byte packet 35 (byte (bit-and src-port 0xFF)))

    ;; Destination port
    (aset-byte packet 36 (byte (bit-shift-right dst-port 8)))
    (aset-byte packet 37 (byte (bit-and dst-port 0xFF)))

    packet))

(defn generate-process-event
  "Generate mock process event"
  [& {:keys [pid uid comm timestamp]
      :or {pid 1234
           uid 1000
           comm "test-process"
           timestamp (System/nanoTime)}}]

  {:pid pid
   :uid uid
   :comm comm
   :timestamp timestamp})

(defn generate-syscall-event
  "Generate mock syscall event"
  [& {:keys [syscall-nr args ret]
      :or {syscall-nr 1  ; write
           args [1 0x7fff 100]
           ret 100}}]

  {:syscall-nr syscall-nr
   :args args
   :ret ret})

;; ============================================================================
;; Packet Injection
;; ============================================================================

(defn inject-xdp-packet
  "Inject packet into XDP program for testing"
  [program packet]
  ;; This would use BPF_PROG_TEST_RUN ioctl
  ;; Simplified here for demonstration
  (let [ctx {:data packet
             :data-end (+ (alength packet))
             :data-meta 0}
        result (bpf/test-run program ctx)]
    result))

(defn inject-tracepoint-event
  "Inject event into tracepoint program"
  [program event-data]
  (let [ctx (event-to-ctx event-data)
        result (bpf/test-run program ctx)]
    result))

;; ============================================================================
;; BPF-Specific Assertions
;; ============================================================================

(defn assert-map-value
  "Assert map contains expected value"
  [map-ref key expected]
  (let [actual (bpf/map-lookup map-ref key)]
    (is (= expected actual)
        (format "Map value mismatch: expected %s, got %s" expected actual))))

(defn assert-map-contains
  "Assert map contains key"
  [map-ref key]
  (let [value (bpf/map-lookup map-ref key)]
    (is (not (nil? value))
        (format "Map should contain key %s" key))))

(defn assert-map-empty
  "Assert map is empty"
  [map-ref]
  (let [entries (bpf/map-get-all map-ref)]
    (is (empty? entries)
        "Map should be empty")))

(defn assert-counter-incremented
  "Assert counter was incremented"
  [map-ref key initial-value]
  (let [new-value (bpf/map-lookup map-ref key)]
    (is (> new-value initial-value)
        (format "Counter should increase: was %d, now %d" initial-value new-value))))

(defn assert-xdp-action
  "Assert XDP program returned expected action"
  [result expected-action]
  (let [action-map {:pass 2 :drop 1 :aborted 0 :tx 3 :redirect 4}
        expected-code (get action-map expected-action)]
    (is (= expected-code (:return-value result))
        (format "Expected XDP action %s (%d), got %d"
                expected-action expected-code (:return-value result)))))

(defn assert-event-captured
  "Assert event was captured in ring buffer"
  [ring-buffer predicate]
  (let [events (atom [])
        _ (bpf/consume-ring-buffer ring-buffer
                                   (fn [e] (swap! events conj e))
                                   {:poll-timeout-ms 100})]
    (is (some predicate @events)
        "Expected event not found in ring buffer")))

;; ============================================================================
;; Example Tests
;; ============================================================================

(deftest test-packet-counter-tcp
  (testing "TCP packet increments TCP counter"
    (let [prog (bpf/load-program packet-counter-program)
          stats-map (get-in prog [:maps :stats])]

      ;; Initial state
      (assert-map-value stats-map 6 0)  ; TCP counter = 0

      ;; Inject TCP packet
      (let [packet (generate-ipv4-packet :protocol 6)
            result (inject-xdp-packet prog packet)]

        ;; Should pass packet
        (assert-xdp-action result :pass)

        ;; Should increment TCP counter
        (assert-map-value stats-map 6 1))

      (bpf/unload-program prog))))

(deftest test-packet-counter-udp
  (testing "UDP packet increments UDP counter"
    (let [prog (bpf/load-program packet-counter-program)
          stats-map (get-in prog [:maps :stats])]

      ;; Inject UDP packet
      (let [packet (generate-ipv4-packet :protocol 17)
            result (inject-xdp-packet prog packet)]

        (assert-xdp-action result :pass)
        (assert-map-value stats-map 17 1))

      (bpf/unload-program prog))))

(deftest test-packet-counter-multiple-protocols
  (testing "Multiple protocols tracked independently"
    (let [prog (bpf/load-program packet-counter-program)
          stats-map (get-in prog [:maps :stats])]

      ;; Inject mixed traffic
      (doseq [_ (range 10)]
        (inject-xdp-packet prog (generate-ipv4-packet :protocol 6)))   ; TCP

      (doseq [_ (range 5)]
        (inject-xdp-packet prog (generate-ipv4-packet :protocol 17)))  ; UDP

      ;; Verify counters
      (assert-map-value stats-map 6 10)   ; TCP
      (assert-map-value stats-map 17 5)   ; UDP

      (bpf/unload-program prog))))

(deftest test-process-monitor-captures-exec
  (testing "Process exec events captured"
    (let [prog (bpf/load-program process-monitor-program)
          events-buf (get-in prog [:maps :events])]

      ;; Inject exec event
      (let [event (generate-process-event :comm "bash" :uid 0)]
        (inject-tracepoint-event prog event))

      ;; Verify event captured
      (assert-event-captured
        events-buf
        (fn [e] (= "bash" (:comm e))))

      (bpf/unload-program prog))))

(deftest test-firewall-blocks-blacklisted-ip
  (testing "Blacklisted IP addresses are dropped"
    (let [prog (bpf/load-program firewall-program)
          blacklist-map (get-in prog [:maps :blacklist])]

      ;; Add IP to blacklist
      (bpf/map-update! blacklist-map (ip->u32 "192.168.1.100") 1)

      ;; Packet from blacklisted IP should be dropped
      (let [packet (generate-ipv4-packet :src-ip "192.168.1.100")
            result (inject-xdp-packet prog packet)]
        (assert-xdp-action result :drop))

      ;; Packet from allowed IP should pass
      (let [packet (generate-ipv4-packet :src-ip "192.168.1.1")
            result (inject-xdp-packet prog packet)]
        (assert-xdp-action result :pass))

      (bpf/unload-program prog))))

;; ============================================================================
;; Property-Based Testing
;; ============================================================================

(deftest test-packet-counter-properties
  (testing "Packet counter maintains invariants"
    (let [prog (bpf/load-program packet-counter-program)
          stats-map (get-in prog [:maps :stats])]

      ;; Property: Counter only increases
      (dotimes [i 100]
        (let [before (or (bpf/map-lookup stats-map 6) 0)
              packet (generate-ipv4-packet :protocol 6)
              _ (inject-xdp-packet prog packet)
              after (bpf/map-lookup stats-map 6)]

          (is (>= after before)
              (format "Counter should not decrease: %d -> %d" before after))))

      ;; Property: Total events = sum of protocol counters
      (let [total-injected 100
            protocol-counts (map #(or (bpf/map-lookup stats-map %) 0)
                                (range 0 256))
            total-counted (reduce + protocol-counts)]

        (is (= total-injected total-counted)
            "Sum of protocol counters should equal total events"))

      (bpf/unload-program prog))))

;; ============================================================================
;; Edge Case Tests
;; ============================================================================

(deftest test-malformed-packets
  (testing "Handles malformed packets gracefully"
    (let [prog (bpf/load-program packet-parser-program)]

      ;; Too short
      (let [packet (byte-array 10)
            result (inject-xdp-packet prog packet)]
        (is (#{:pass :drop} (xdp-action-from-code (:return-value result)))
            "Should handle short packets"))

      ;; Invalid EtherType
      (let [packet (generate-ipv4-packet)
            _ (aset-byte packet 12 (byte 0x99))  ; Invalid EtherType
            result (inject-xdp-packet prog packet)]
        (is (some? result) "Should handle invalid EtherType"))

      ;; Zero-length payload
      (let [packet (generate-ipv4-packet :payload-size 0)
            result (inject-xdp-packet prog packet)]
        (is (some? result) "Should handle zero-length payload"))

      (bpf/unload-program prog))))

(deftest test-boundary-conditions
  (testing "Handles boundary conditions"
    (let [prog (bpf/load-program rate-limiter-program)]

      ;; Exactly at limit
      (dotimes [_ 1000]  ; Assume limit is 1000/sec
        (inject-xdp-packet prog (generate-ipv4-packet)))

      ;; Next packet should be rate-limited
      (let [result (inject-xdp-packet prog (generate-ipv4-packet))]
        (assert-xdp-action result :drop))

      (bpf/unload-program prog))))

;; ============================================================================
;; Test Coverage Analysis
;; ============================================================================

(defn analyze-coverage
  "Analyze which program paths were tested"
  [program test-results]
  (let [total-paths (count-program-paths program)
        executed-paths (count-executed-paths test-results)
        coverage (/ executed-paths (double total-paths))]

    (println "\n=== Test Coverage ===")
    (println (format "Total paths: %d" total-paths))
    (println (format "Executed paths: %d" executed-paths))
    (println (format "Coverage: %.1f%%" (* coverage 100)))

    (when (< coverage 0.8)
      (println "\n⚠️  WARNING: Low test coverage (<80%)"))

    coverage))

;; ============================================================================
;; Test Suite Runner
;; ============================================================================

(defn run-test-suite
  "Run comprehensive test suite"
  []
  (println "=== BPF Unit Test Suite ===\n")

  (let [start-time (System/currentTimeMillis)
        results (run-tests 'testing.unit-framework)
        duration (- (System/currentTimeMillis) start-time)]

    (println "\n=== Summary ===")
    (println (format "Tests run: %d" (+ (:pass results) (:fail results) (:error results))))
    (println (format "Passed: %d" (:pass results)))
    (println (format "Failed: %d" (:fail results)))
    (println (format "Errors: %d" (:error results)))
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
tests/
├── unit/
│   ├── packet_counter_test.clj
│   ├── flow_tracker_test.clj
│   ├── process_monitor_test.clj
│   └── firewall_test.clj
├── fixtures/
│   ├── packets.clj          ; Packet generators
│   ├── events.clj           ; Event generators
│   └── assertions.clj       ; Custom assertions
├── helpers/
│   ├── bpf_runner.clj       ; BPF test runner
│   └── coverage.clj         ; Coverage analysis
└── integration/
    └── ...
```

## Running Tests

```bash
# Run all unit tests
lein test :unit

# Run specific test
lein test :only testing.unit-framework/test-packet-counter-tcp

# Run with coverage
lein test-coverage

# Run in watch mode
lein test-refresh
```

## Expected Output

```
=== BPF Unit Test Suite ===

Testing testing.unit-framework

Ran 8 tests containing 15 assertions.
0 failures, 0 errors.

=== Test Coverage ===
Total paths: 45
Executed paths: 38
Coverage: 84.4%

=== Summary ===
Tests run: 8
Passed: 8
Failed: 0
Errors: 0
Duration: 1234ms

✓ All tests passed!
```

## Best Practices

1. **Test Small Units**: Test individual programs, not entire systems
2. **Use Fixtures**: Setup/teardown for consistent state
3. **Mock External Data**: Generate deterministic test data
4. **Assert Explicitly**: Check exact values, not just "something happened"
5. **Test Edge Cases**: Empty, max, invalid inputs
6. **Measure Coverage**: Aim for 80%+ path coverage
7. **Fast Tests**: Unit tests should run in milliseconds
8. **Isolated Tests**: No dependencies between tests

## Challenges

1. **Concurrent Testing**: Test per-CPU map behavior
2. **Performance Tests**: Assert execution time constraints
3. **Verifier Tests**: Verify programs pass verifier
4. **Negative Tests**: Ensure invalid programs are rejected
5. **Regression Suite**: Build comprehensive regression tests

## Key Takeaways

- Unit tests catch bugs early
- Mock data enables deterministic testing
- BPF-specific assertions simplify tests
- Test coverage reveals untested paths
- Fast, isolated tests enable rapid development
- Fixtures ensure consistent test environment

## References

- [Clojure Testing](https://clojure.org/guides/deps_and_cli#testing)
- [BPF Program Testing](https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html)
- [Property-Based Testing](https://github.com/clojure/test.check)
