# Chapter 14: Testing and Debugging

## Overview

BPF programs run in kernel space with strict safety constraints. A single bug can crash the kernel or create security vulnerabilities. Rigorous testing and effective debugging are essential for production deployments.

This chapter covers:
- Testing strategies (unit, integration, stress testing)
- Debugging techniques and tools
- Verifier error analysis and resolution
- Performance profiling
- CI/CD integration
- Common pitfalls and solutions

## Why BPF Testing Is Different

### Unique Challenges

1. **Kernel Context**: Programs run in kernel space, limited debugging
2. **Verifier Constraints**: Must pass static analysis before loading
3. **No Standard Library**: Can't use printf, malloc, etc.
4. **Limited Stack**: 512 bytes maximum
5. **Instruction Limit**: 1M instructions (complexity limit)
6. **No Floating Point**: Integer arithmetic only
7. **Safety Requirements**: Bugs can crash kernel

### Testing Pyramid for BPF

```
        ┌─────────────────┐
        │  E2E Tests      │  ← Few (expensive)
        │  (10%)          │
        ├─────────────────┤
        │ Integration     │  ← Some (moderate cost)
        │ Tests (30%)     │
        ├─────────────────┤
        │  Unit Tests     │  ← Many (cheap)
        │  (60%)          │
        └─────────────────┘
```

## Testing Strategies

### 1. Unit Testing

**Goal**: Test individual BPF programs in isolation.

**Approach**: Load program with test data, verify map contents.

```clojure
(ns testing.unit-test
  (:require [clj-ebpf.core :as bpf]
            [clojure.test :refer :all]))

(deftest test-packet-counter
  (let [prog (bpf/load-program packet-counter-prog)
        stats-map (:maps prog)]

    ;; Inject test packet
    (simulate-packet prog {:protocol 6  ; TCP
                          :src-ip "192.168.1.1"
                          :dst-ip "10.0.0.1"})

    ;; Verify counter incremented
    (let [tcp-count (bpf/map-lookup stats-map 6)]
      (is (= 1 tcp-count) "TCP counter should be 1"))

    ;; Cleanup
    (bpf/unload-program prog)))
```

**Benefits**:
- Fast execution
- Isolated failures
- Easy to write many tests
- Run in CI/CD

**Limitations**:
- Can't test kernel interactions
- May miss integration issues

### 2. Integration Testing

**Goal**: Test BPF program with real kernel events.

**Approach**: Attach to tracepoint/kprobe, trigger real event, verify result.

```clojure
(deftest test-process-monitor-integration
  (let [prog (bpf/load-program process-monitor)
        events (atom [])]

    ;; Attach to real tracepoint
    (bpf/attach-tracepoint prog "sched" "sched_process_exec")

    ;; Start event consumer
    (future
      (bpf/consume-ring-buffer
        (:event-buffer prog)
        (fn [event] (swap! events conj event))))

    ;; Trigger real event
    (sh/sh "ls" "/tmp")

    ;; Wait for event
    (Thread/sleep 100)

    ;; Verify event captured
    (is (some #(= "ls" (:comm %)) @events)
        "Should capture 'ls' process exec")

    ;; Cleanup
    (bpf/detach-tracepoint prog)))
```

**Benefits**:
- Tests real kernel integration
- Catches timing issues
- Validates end-to-end flow

**Limitations**:
- Slower than unit tests
- Requires root/capabilities
- May have side effects

### 3. Stress Testing

**Goal**: Verify behavior under extreme load.

**Approach**: Generate high event rate, monitor for drops/errors.

```clojure
(deftest test-high-event-rate
  (let [prog (bpf/load-program event-processor)
        duration-sec 10
        target-rate 1000000]  ; 1M events/sec

    ;; Generate load
    (generate-synthetic-load target-rate duration-sec)

    ;; Check stats
    (let [stats (get-buffer-stats prog)
          drop-rate (/ (:drops stats) (:events stats))]

      (is (< drop-rate 0.01)
          "Drop rate should be < 1%")

      (is (zero? (:errors stats))
          "Should have no errors"))))
```

### 4. Fuzzing

**Goal**: Discover edge cases and crashes.

**Approach**: Feed random/malformed data to program.

```clojure
(deftest test-packet-parser-fuzzing
  (let [prog (bpf/load-program packet-parser)]

    (dotimes [_ 10000]
      (let [random-packet (generate-random-packet)]
        (try
          ;; Should not crash on any input
          (process-packet prog random-packet)
          (catch Exception e
            (is false (str "Crashed on packet: " random-packet
                          " Error: " (.getMessage e)))))))))
```

## Debugging Techniques

### 1. BPF Print Statements

**Using bpf_trace_printk** (limited, but useful):

```clojure
(def debug-program
  {:type :kprobe
   :name "tcp_connect"
   :program
   [;; Print PID
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r10 -4 :r0)]

    ;; Print to trace pipe (simplified)
    ;; Actual implementation varies
    ;; Output visible in /sys/kernel/debug/tracing/trace_pipe

    ...]})
```

**Read trace output**:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**Limitations**:
- Limited format string support
- Shared buffer (can interfere with other tools)
- Performance overhead

### 2. Map-Based Debugging

**Strategy**: Use maps to export debug information.

```clojure
(def debug-map
  "Export debug values"
  {:type :array
   :key-type :u32
   :value-type :struct  ; {checkpoint:u32, value:u64, timestamp:u64}
   :max-entries 100})

;; In BPF program
[(bpf/mov :r1 CHECKPOINT_1)]
[(bpf/store-mem :w :r10 -4 :r1)]
[(bpf/mov :r1 :r7)]  ; Value to debug
[(bpf/store-mem :dw :r10 -12 :r1)]
;; Store to debug map
```

**Read debug data**:
```clojure
(defn read-debug-map []
  (doseq [[idx debug-entry] (bpf/map-get-all debug-map)]
    (printf "Checkpoint %d: value=%d timestamp=%d\n"
            (:checkpoint debug-entry)
            (:value debug-entry)
            (:timestamp debug-entry))))
```

### 3. Ring Buffer Event Logging

**Strategy**: Log detailed events for post-mortem analysis.

```clojure
(def debug-events
  {:type :ring_buffer
   :max-entries (* 256 1024)})

;; Log decision points
[(bpf/mov-reg :r1 (bpf/map-ref debug-events))]
[(bpf/mov :r2 32)]
[(bpf/mov :r3 0)]
[(bpf/call (bpf/helper :ringbuf_reserve))]
;; Fill with debug info
```

### 4. Instruction Counting

**Strategy**: Count instructions executed to find hotspots.

```clojure
(defn count-instructions [program]
  ;; Use bpftool to analyze program
  (let [output (sh/sh "bpftool" "prog" "show" (str (:id program)))
        insn-count (parse-instruction-count output)]
    (println "Program instructions:" insn-count)
    (when (> insn-count 500)
      (println "WARNING: High instruction count, consider optimization"))))
```

## Verifier Errors and Solutions

### Common Verifier Errors

#### 1. "Unbounded Loop Detected"

**Error**:
```
back-edge from insn 45 to 20
```

**Cause**: Loop without bounded iteration count.

**Bad Code**:
```clojure
;; Infinite loop potential
[(bpf/jmp :loop)]
[:loop]
;; ... code ...
[(bpf/jmp-imm :jne :r1 0 :loop)]  ; Unbounded!
```

**Solution**: Use bounded loop with verifiable limit.

```clojure
;; Bounded loop
[(bpf/mov :r6 0)]  ; Iterator
[:loop]
[(bpf/jmp-imm :jge :r6 10 :exit)]  ; Max 10 iterations
;; ... code ...
[(bpf/add :r6 1)]
[(bpf/jmp :loop)]

[:exit]
```

#### 2. "Invalid Memory Access"

**Error**:
```
R1 invalid mem access 'scalar'
```

**Cause**: Accessing memory without bounds check.

**Bad Code**:
```clojure
[(bpf/load-ctx :dw :r2 0)]       ; data
[(bpf/load-mem :w :r1 :r2 0)]    ; NO BOUNDS CHECK!
```

**Solution**: Always bounds check before access.

```clojure
[(bpf/load-ctx :dw :r2 0)]       ; data
[(bpf/load-ctx :dw :r3 8)]       ; data_end
[(bpf/mov-reg :r4 :r2)]
[(bpf/add :r4 4)]
[(bpf/jmp-reg :jgt :r4 :r3 :exit)]  ; Bounds check
[(bpf/load-mem :w :r1 :r2 0)]       ; Safe!
```

#### 3. "Stack Access Out of Bounds"

**Error**:
```
invalid stack off=-516 size=4
```

**Cause**: Stack offset exceeds 512-byte limit.

**Bad Code**:
```clojure
[(bpf/store-mem :w :r10 -520 :r1)]  ; -520 > -512!
```

**Solution**: Use map instead of large stack allocations.

```clojure
;; Use map for large data
(def temp-storage
  {:type :array
   :key-type :u32
   :value-type [128 :u8]  ; 128 bytes
   :max-entries 1})
```

#### 4. "Register Spill/Fill Mismatch"

**Error**:
```
R6 !read_ok
```

**Cause**: Reading register before writing to it.

**Bad Code**:
```clojure
[(bpf/jmp-imm :jeq :r1 0 :branch)]
;; r6 not initialized on this path
[:branch]
[(bpf/mov-reg :r1 :r6)]  ; Reading uninitialized r6!
```

**Solution**: Initialize on all paths.

```clojure
[(bpf/mov :r6 0)]  ; Initialize
[(bpf/jmp-imm :jeq :r1 0 :branch)]
[:branch]
[(bpf/mov-reg :r1 :r6)]  ; Safe!
```

#### 5. "Path Not Explored"

**Error**:
```
path unexplored from insn 45
```

**Cause**: Verifier couldn't prove all paths terminate.

**Solution**: Add explicit exit or simplify logic.

```clojure
;; Ensure all paths reach exit
[(bpf/jmp-imm :jeq :r1 0 :path-a)]
[(bpf/jmp :path-b)]

[:path-a]
;; ... code ...
[(bpf/jmp :exit)]  ; Explicit jump to exit

[:path-b]
;; ... code ...
;; Falls through to exit

[:exit]
[(bpf/mov :r0 0)]
[(bpf/exit)]
```

### Verifier Debugging Strategy

1. **Simplify**: Comment out code until it loads
2. **Add Bounds Checks**: Ensure all memory access is checked
3. **Limit Loops**: Make iteration count explicit and small
4. **Check Initialization**: Initialize all registers on all paths
5. **Use bpftool**: Get detailed verifier log

```bash
# Get full verifier log
sudo bpftool prog load program.o /sys/fs/bpf/myprog \
  type xdp \
  verbose 2>&1 | less
```

## Debugging Tools

### 1. bpftool

**Capabilities**:
- List loaded programs
- Dump program instructions
- Show map contents
- Get program metadata

**Common Commands**:
```bash
# List all BPF programs
sudo bpftool prog show

# Show program details
sudo bpftool prog show id 123

# Dump program instructions
sudo bpftool prog dump xlated id 123

# Show maps
sudo bpftool map show

# Dump map contents
sudo bpftool map dump id 456

# Get verifier log
sudo bpftool prog load prog.o /sys/fs/bpf/test type xdp verbose
```

### 2. bpftrace

**Use Case**: Quick one-liners for debugging.

```bash
# Trace all system calls
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# Show TCP connect latency
sudo bpftrace -e 'kprobe:tcp_connect { @start[tid] = nsecs; }
                   kretprobe:tcp_connect /@start[tid]/ {
                     printf("Latency: %d us\n", (nsecs - @start[tid]) / 1000);
                     delete(@start[tid]);
                   }'
```

### 3. perf

**Use Case**: Profile BPF program performance.

```bash
# Profile BPF program execution
sudo perf record -e cpu-clock -a -g -- sleep 10
sudo perf report

# Count BPF events
sudo perf stat -e bpf:bpf_prog_load -a sleep 60
```

### 4. Custom Debugging Harness

```clojure
(ns testing.debug-harness
  (:require [clj-ebpf.core :as bpf]))

(defn debug-program
  "Run program with comprehensive debugging"
  [program test-data]
  (println "=== Debugging BPF Program ===\n")

  ;; 1. Load program
  (println "Loading program...")
  (let [prog (try
               (bpf/load-program program)
               (catch Exception e
                 (println "LOAD FAILED:")
                 (println (.getMessage e))
                 (System/exit 1)))]

    (println "✓ Program loaded successfully")
    (println "  Program ID:" (:id prog))
    (println "  Instructions:" (count-instructions prog))

    ;; 2. Check maps
    (println "\nMaps:")
    (doseq [[name map-def] (:maps prog)]
      (println (format "  %s: type=%s entries=%d"
                      name (:type map-def) (:max-entries map-def))))

    ;; 3. Run test
    (println "\nRunning test...")
    (let [result (run-test prog test-data)]
      (println "✓ Test completed")
      (println "  Return value:" (:return result))

      ;; 4. Check map contents
      (println "\nMap contents after test:")
      (doseq [[name map-ref] (:maps prog)]
        (println (format "  %s:" name))
        (doseq [[k v] (bpf/map-get-all map-ref)]
          (println (format "    %s -> %s" k v))))

      ;; 5. Check for errors
      (when-let [errors (:errors result)]
        (println "\n⚠ Errors detected:")
        (doseq [err errors]
          (println "  -" err)))

      result)))
```

## Performance Profiling

### 1. Instruction Profiling

**Goal**: Find expensive code paths.

```clojure
(defn profile-instructions [program]
  (let [insns (get-program-instructions program)
        expensive (filter #(>= (:cycles %) 10) insns)]

    (println "=== Expensive Instructions ===")
    (doseq [insn expensive]
      (printf "Offset %d: %s (%d cycles)\n"
              (:offset insn)
              (:opcode insn)
              (:cycles insn)))))
```

### 2. Map Access Profiling

**Goal**: Find map access hotspots.

```clojure
(def map-access-counter
  {:type :array
   :key-type :u32
   :value-type :u64
   :max-entries 10})  ; Track top 10 maps

;; In BPF program, increment counter on map access
;; Then analyze:
(defn show-map-access-stats []
  (println "=== Map Access Statistics ===")
  (doseq [[map-id count] (bpf/map-get-all map-access-counter)]
    (println (format "Map %d: %d accesses" map-id count))))
```

### 3. Event Rate Measurement

```clojure
(defn measure-event-rate [program duration-sec]
  (let [start-count (get-event-count program)
        start-time (System/currentTimeMillis)]

    (Thread/sleep (* duration-sec 1000))

    (let [end-count (get-event-count program)
          end-time (System/currentTimeMillis)
          events (- end-count start-count)
          duration-ms (- end-time start-time)
          rate (/ (* events 1000.0) duration-ms)]

      {:events events
       :duration-ms duration-ms
       :events-per-sec rate})))
```

## CI/CD Integration

### Test Structure

```
tests/
├── unit/
│   ├── test_packet_counter.clj
│   ├── test_flow_tracker.clj
│   └── test_process_monitor.clj
├── integration/
│   ├── test_xdp_integration.clj
│   └── test_tracepoint_integration.clj
├── stress/
│   └── test_high_load.clj
└── fixtures/
    ├── sample_packets.edn
    └── test_data.edn
```

### GitHub Actions Workflow

```yaml
name: BPF Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: ubuntu:22.04
      options: --privileged  # Required for BPF

    steps:
      - uses: actions/checkout@v2

      - name: Install dependencies
        run: |
          apt-get update
          apt-get install -y clojure leiningen linux-tools-generic

      - name: Run unit tests
        run: lein test :unit

      - name: Run integration tests
        run: lein test :integration

      - name: Check for verifier errors
        run: lein run -m testing.verifier-check
```

## Common Pitfalls and Solutions

### Pitfall 1: Not Testing Edge Cases

**Problem**: Program works for normal data, crashes on edge cases.

**Solution**: Test boundary conditions explicitly.

```clojure
(deftest test-edge-cases
  (are [input expected] (= expected (process input))
    nil         :error
    []          :empty
    [0]         :single
    (repeat 1000 1)  :max-size))
```

### Pitfall 2: Race Conditions

**Problem**: Per-CPU maps have race conditions between CPUs.

**Solution**: Use per-CPU maps or atomic operations.

```clojure
;; Bad: Regular map (lock contention)
(def counter {:type :hash ...})

;; Good: Per-CPU map (lock-free)
(def counter {:type :percpu_hash ...})
```

### Pitfall 3: Memory Leaks

**Problem**: Maps grow without bounds.

**Solution**: Implement cleanup/eviction.

```clojure
(defn cleanup-old-entries [map-ref max-age-sec]
  (let [cutoff (- (System/currentTimeMillis) (* max-age-sec 1000))]
    (doseq [[k v] (bpf/map-get-all map-ref)]
      (when (< (:timestamp v) cutoff)
        (bpf/map-delete! map-ref k)))))
```

### Pitfall 4: Silent Failures

**Problem**: Errors not logged or monitored.

**Solution**: Always track and alert on errors.

```clojure
(def error-counter
  {:type :array
   :key-type :u32
   :value-type :u64
   :max-entries 1})

;; Monitor in userspace
(defn monitor-errors []
  (loop []
    (Thread/sleep 60000)
    (when-let [errors (bpf/map-lookup error-counter 0)]
      (when (pos? errors)
        (log/error "BPF program errors detected:" errors)))
    (recur)))
```

## Labs

### Lab 14.1: Unit Testing Framework

Build a comprehensive unit testing framework for BPF programs with test fixtures and assertions.

**Skills**: Test design, mock data, assertions

### Lab 14.2: Debugging Toolkit

Implement debugging tools including instruction tracing, map inspection, and event replay.

**Skills**: Debugging, introspection, tooling

### Lab 14.3: Verifier Error Fixer

Analyze and automatically fix common verifier errors.

**Skills**: Verifier understanding, error analysis, code transformation

## Key Takeaways

1. **Test Early, Test Often** - BPF bugs are hard to debug
2. **Unit Tests First** - Fast, isolated, easy to write
3. **Verifier Is Your Friend** - Catches bugs before runtime
4. **Use Maps for Debugging** - Export internal state
5. **Bounds Check Everything** - Memory safety is critical
6. **Profile Before Optimizing** - Measure actual performance
7. **CI/CD Is Essential** - Automate testing to catch regressions
8. **Monitor Production** - Track errors and performance metrics

## References

- [BPF Testing Guide](https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html)
- [bpftool Documentation](https://github.com/libbpf/bpftool)
- [BPF Verifier](https://www.kernel.org/doc/html/latest/bpf/verifier.html)
- [libbpf Testing](https://github.com/libbpf/libbpf#testing)

---

**Next**: [Part IV: Real-World Applications](../../part-4-applications/README.md) - Build complete production systems
