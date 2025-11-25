# ADR 0005: Testing Strategy

## Status

Accepted

## Context

BPF programs run in the kernel, which creates testing challenges:
- Requires root/CAP_BPF to load programs
- Side effects are kernel-level
- Hard to run in CI environments
- Difficult to test edge cases

We needed a testing strategy that:
- Allows testing without root privileges
- Supports CI/CD integration
- Tests all code paths including error handling
- Is fast enough for rapid development

## Decision

### Three-Tier Testing Strategy

#### Tier 1: Mock Testing (No Privileges)

A mock syscall layer in `clj-ebpf.mock` simulates BPF operations:

```clojure
(mock/with-mock-bpf {:mode :recording}
  (let [m (maps/create {:type :hash ...})]
    (maps/update! m key val)
    (is (= val (maps/lookup m key)))))
```

Mock modes:
- `:passthrough` - Real syscalls (needs root)
- `:recording` - Record and replay
- `:simulation` - Full simulation, no syscalls

#### Tier 2: BPF_PROG_TEST_RUN (Limited Privileges)

Use `BPF_PROG_TEST_RUN` to test programs without attaching:

```clojure
(let [prog (load-program xdp-prog :xdp)
      result (test-run-program prog {:data-in packet})]
  (is (= 2 (:retval result))))  ; XDP_PASS
```

Benefits:
- Tests actual program execution
- No network attachment needed
- Can test with synthetic packets

#### Tier 3: Integration Testing (Full Privileges)

Full integration tests with real BPF operations:

```clojure
(deftest ^:integration xdp-attach-test
  (with-xdp-program [prog "eth0" ...]
    (is (some? (:fd prog)))))
```

Run separately: `clojure -X:test :includes [:integration]`

### Test Utilities

`clj-ebpf.test-utils` provides helpers:

```clojure
(tu/with-bpf-test-context []
  ;; Maps and programs auto-cleaned up
  (let [m (maps/create ...)]
    ...))

(tu/with-temp-map [m {:type :hash ...}]
  ...)
```

### Property-Based Testing

`clj-ebpf.generators` and `clj-ebpf.properties` for generative testing:

```clojure
(defspec dsl-roundtrip 100
  (prop/for-all [op gen-alu-op
                 dst gen-register
                 imm gen-imm32]
    (valid-instruction? (dsl/alu-imm op dst imm))))
```

## Consequences

### Positive

- **CI-friendly**: Mock tests run without privileges
- **Fast development**: Quick feedback loop
- **Comprehensive**: Tests at multiple levels
- **Deterministic**: Mock tests are reproducible

### Negative

- **Mock accuracy**: Mock may not match kernel behavior exactly
- **Maintenance**: Need to update mocks for new features
- **Test duplication**: Similar tests at different tiers

### Test Organization

```
test/
  clj_ebpf/
    mock.clj           ; Mock syscall layer
    test_utils.clj     ; Test fixtures and helpers
    generators.clj     ; test.check generators
    properties.clj     ; Property-based tests
    *_test.clj         ; Unit tests (mock)
    integration/       ; Integration tests (real syscalls)
```

## Running Tests

```bash
# Unit tests (no privileges needed)
clojure -X:test

# Integration tests (needs root/CAP_BPF)
sudo clojure -X:test :includes '[:integration]'

# All tests
sudo clojure -X:test :includes '[:unit :integration]'
```

## References

- [BPF_PROG_TEST_RUN](https://lwn.net/Articles/760294/)
- [test.check](https://github.com/clojure/test.check)
