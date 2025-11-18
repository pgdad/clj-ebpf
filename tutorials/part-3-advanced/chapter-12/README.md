# Chapter 12: Performance Optimization

## Introduction

BPF programs run in the kernel's hot paths, processing millions of events per second. Poor performance can degrade entire system performance. This chapter teaches you to write fast, scalable BPF programs through measurement, optimization techniques, and architectural patterns.

## Why Performance Matters

BPF programs execute in critical kernel paths:
- **XDP**: Processes every incoming packet (10-30M packets/sec)
- **Tracepoints**: Fires on every syscall (100K-1M/sec)
- **Kprobes**: Instruments frequently-called kernel functions

**1% overhead** in a BPF program can translate to:
- 10% CPU increase in packet processing
- Significant latency impact on applications
- Reduced system capacity

**Performance is not optional—it's essential.**

## BPF Performance Characteristics

### Execution Model

```
Event Trigger → BPF Program → Helper Calls → Map Operations → Return
   ↓              ↓              ↓              ↓               ↓
  0ns          10-500ns       50-200ns       50-100ns        0ns
```

### Typical Performance Budget

| Operation | Time | Frequency | Total Impact |
|-----------|------|-----------|--------------|
| Packet arrival (XDP) | 0ns | 10M/sec | - |
| BPF instructions | 100-500ns | per packet | 1-5% CPU |
| Map lookup | 50-100ns | per packet | 0.5-1% CPU |
| Helper call | 50-200ns | per packet | 0.5-2% CPU |
| **Total** | **200-800ns** | **per packet** | **2-8% CPU** |

**Budget**: Keep BPF program execution under 1 microsecond.

## Verifier Constraints

The BPF verifier enforces limits for safety and termination:

### Hard Limits (Kernel 5.15+)

| Limit | Value | Impact |
|-------|-------|--------|
| **Max Instructions** | 1,000,000 | Program complexity |
| **Max Stack Size** | 512 bytes | Local variables |
| **Max Tail Calls** | 33 | Program chaining depth |
| **Max Map Entries** | 2^32 | Memory usage |
| **Max BPF Program Size** | 16 KB | JIT code size |

### Verifier Complexity Limits

The verifier analyzes all possible execution paths. Complex control flow increases verification time exponentially:

**Simple Program** (linear):
```clojure
[(bpf/load-ctx :w :r6 0)]
[(bpf/add :r6 1)]
[(bpf/exit)]
```
Verification time: < 1ms

**Complex Program** (many branches):
```clojure
[(bpf/jmp-imm :jgt :r6 100 :label1)]
[(bpf/jmp-imm :jgt :r6 50 :label2)]
;; ... 20 more branches ...
```
Verification time: 100ms - several seconds

**Key Insight**: Simplify control flow to reduce verification time.

## Optimization Fundamentals

### Rule #1: Measure First

**Never optimize without measuring.** Premature optimization wastes time.

Measurement approaches:
1. **bpftool prog profile** - Built-in profiling
2. **Instruction counting** - Track critical path instructions
3. **Benchmarking** - End-to-end performance tests
4. **Production metrics** - Real-world impact

### Rule #2: Optimize Hot Paths

Use the **80/20 rule**: 80% of time is spent in 20% of code.

Example hot paths:
- **XDP**: Packet parsing (Ethernet → IP → TCP)
- **Tracepoints**: Map lookups and updates
- **Kprobes**: Argument extraction and validation

Focus optimization efforts on these critical sections.

### Rule #3: Trade-Offs

Every optimization involves trade-offs:
- **Memory vs Speed**: Caching vs recalculation
- **Accuracy vs Performance**: Sampling vs full instrumentation
- **Complexity vs Maintainability**: Micro-optimizations vs readable code

## Optimization Techniques

### 1. Loop Unrolling

BPF supports bounded loops (kernel 5.3+), but unrolling is often faster.

**Before** (loop):
```clojure
[(bpf/mov :r9 0)]
[:loop]
[(bpf/jmp-imm :jge :r9 8 :done)]
[(bpf/load-mem :b :r1 :r6 :r9)]
;; ... process byte ...
[(bpf/add :r9 1)]
[(bpf/jmp :loop)]
[:done]
```

**After** (unrolled):
```clojure
[(bpf/load-mem :b :r1 :r6 0)]
;; ... process byte ...
[(bpf/load-mem :b :r1 :r6 1)]
;; ... process byte ...
;; ... repeat 6 more times ...
[(bpf/load-mem :b :r1 :r6 7)]
;; ... process byte ...
```

**Speedup**: 20-30% for small loops (< 16 iterations)
**Trade-off**: Larger program size, more instructions to verify

### 2. Efficient Map Access

Map lookups are expensive (50-100ns). Minimize them.

**Bad** (multiple lookups):
```clojure
;; Lookup 1
[(bpf/call (bpf/helper :map_lookup_elem))]
[(bpf/load-mem :dw :r1 :r0 0)]        ; Read field 1

;; Lookup 2 (SAME KEY!)
[(bpf/call (bpf/helper :map_lookup_elem))]
[(bpf/load-mem :dw :r2 :r0 8)]        ; Read field 2
```

**Good** (single lookup, cache pointer):
```clojure
;; Lookup once
[(bpf/call (bpf/helper :map_lookup_elem))]
[(bpf/mov-reg :r7 :r0)]               ; Cache pointer
[(bpf/load-mem :dw :r1 :r7 0)]        ; Read field 1
[(bpf/load-mem :dw :r2 :r7 8)]        ; Read field 2
```

**Speedup**: 50% reduction in map operation overhead

### 3. Per-CPU Data Structures

Per-CPU maps eliminate lock contention in SMP systems.

**Regular Hash Map** (contended):
```clojure
(def counter-map
  {:type :hash
   :key-type :u32
   :value-type :u64
   :max-entries 1000})

;; Every CPU contends for locks on updates
```
Performance: ~100ns per update (with contention)

**Per-CPU Hash Map** (lock-free):
```clojure
(def counter-map
  {:type :percpu_hash
   :key-type :u32
   :value-type :u64
   :max-entries 1000})

;; Each CPU has its own copy, no locks
```
Performance: ~50ns per update (no contention)

**Trade-off**: More memory usage (entries × CPUs)

### 4. Array Maps for Hot Keys

Array maps are faster than hash maps for known, small key spaces.

**Hash Map**:
```clojure
(def stats {:type :hash
            :key-type :u32
            :value-type :u64
            :max-entries 256})
```
Lookup: ~100ns

**Array Map**:
```clojure
(def stats {:type :array
            :key-type :u32
            :value-type :u64
            :max-entries 256})
```
Lookup: ~50ns (direct index, no hashing)

**When to use**: Key space is small (< 1000) and dense.

### 5. Early Exit

Exit as soon as possible to avoid unnecessary work.

**Bad** (does work before checking):
```clojure
;; Parse entire packet
[(bpf/load-mem :h :r6 :r1 12)]        ; EtherType
[(bpf/load-mem :b :r7 :r1 23)]        ; IP protocol
[(bpf/load-mem :h :r8 :r1 36)]        ; Dst port

;; Then check if we care
[(bpf/jmp-imm :jne :r8 80 :drop)]
```

**Good** (check first, then parse):
```clojure
;; Quick check: is it TCP port 80?
[(bpf/load-mem :h :r8 :r1 36)]        ; Dst port
[(bpf/jmp-imm :jne :r8 80 :drop)]

;; Only parse if we care
[(bpf/load-mem :h :r6 :r1 12)]        ; EtherType
[(bpf/load-mem :b :r7 :r1 23)]        ; IP protocol
```

**Speedup**: 90% of packets exit early, saving parsing overhead

### 6. Inline Small Functions

Helper functions have call overhead. Inline small, frequently-called functions.

**Before** (function call):
```clojure
(defn add-to-counter [counter-reg value]
  [(bpf/load-mem :dw :r1 counter-reg 0)]
  [(bpf/add :r1 value)]
  [(bpf/store-mem :dw counter-reg 0 :r1)])

;; Call site
(add-to-counter :r6 1)
```

**After** (inlined):
```clojure
;; Inline directly
[(bpf/load-mem :dw :r1 :r6 0)]
[(bpf/add :r1 1)]
[(bpf/store-mem :dw :r6 0 :r1)]
```

**Speedup**: Eliminates function call overhead (~5-10ns per call)

### 7. Batch Operations

Process multiple items together when possible.

**Bad** (one at a time):
```clojure
;; Update counter for each packet
[(bpf/call (bpf/helper :map_update_elem))]
```

**Good** (batch updates):
```clojure
;; Accumulate locally, update periodically
[(bpf/load-mem :dw :r1 :r10 -8)]      ; Local counter
[(bpf/add :r1 1)]
[(bpf/store-mem :dw :r10 -8 :r1)]

;; Flush every 1000 packets
[(bpf/jmp-imm :jlt :r1 1000 :skip-flush)]
[(bpf/call (bpf/helper :map_update_elem))]
[(bpf/mov :r1 0)]
[(bpf/store-mem :dw :r10 -8 :r1)]
[:skip-flush]
```

**Speedup**: 10x reduction in map operations

### 8. Avoid Expensive Helpers

Not all helpers are created equal.

| Helper | Cost | When to Use |
|--------|------|-------------|
| `ktime_get_ns` | ~20ns | Sparingly |
| `get_current_pid_tgid` | ~10ns | Common |
| `map_lookup_elem` | ~50-100ns | Cached |
| `probe_read_kernel` | ~50-200ns | Validated |
| `ringbuf_output` | ~200-500ns | Batched |
| `trace_printk` | ~1000ns | **Debug only!** |

**Key**: Use `trace_printk` only in development. Never in production.

## Profiling BPF Programs

### Method 1: bpftool prog profile

```bash
# Profile program ID 42 for 5 seconds
sudo bpftool prog profile id 42 duration 5 cycles instructions

# Output:
#   47201 cycles                          (64.2%)
#   23801 instructions                    (32.4%)
#   ...
```

### Method 2: Instruction Counting

Manually count instructions in critical path:

```clojure
;; Critical path: 15 instructions
[(bpf/load-ctx :w :r6 0)]              ; 1
[(bpf/endian-be :w :r6)]               ; 2
[(bpf/jmp-imm :jne :r6 0x0800 :drop)]  ; 3
[(bpf/load-mem :b :r7 :r1 23)]         ; 4
[(bpf/jmp-imm :jne :r7 6 :drop)]       ; 5
;; ... 10 more ...
```

**Target**: < 100 instructions for hot path

### Method 3: End-to-End Benchmarking

Measure actual system impact:

```bash
# Baseline (no BPF)
sudo iperf3 -c server -t 30
# Result: 9.5 Gbps

# With BPF program
sudo iperf3 -c server -t 30
# Result: 9.0 Gbps

# Overhead: (9.5 - 9.0) / 9.5 = 5.3%
```

### Method 4: perf Integration

```bash
# Record BPF program events
sudo perf record -e bpf_prog:* -a sleep 10

# Analyze
sudo perf report
```

## Scalability Patterns

### Pattern 1: Sampling

Don't process every event—sample intelligently.

```clojure
;; Process 1 in 100 packets
[(bpf/call (bpf/helper :get_prandom_u32))]
[(bpf/mod :r0 100)]
[(bpf/jmp-imm :jne :r0 0 :drop)]

;; Process this packet
;; ...
```

**Overhead reduction**: 99%
**Accuracy**: Statistical approximation

### Pattern 2: Aggregation

Aggregate in kernel, export to userspace periodically.

**Bad** (export every event):
```clojure
;; Ring buffer output for EVERY packet
[(bpf/call (bpf/helper :ringbuf_output))]
```
Overhead: ~500ns per packet

**Good** (aggregate, export summary):
```clojure
;; Update counter in map
[(bpf/call (bpf/helper :map_update_elem))]

;; Userspace polls map every 1 second
```
Overhead: ~50ns per packet

**Overhead reduction**: 10x

### Pattern 3: Hierarchical Filtering

Filter early, process late.

```clojure
;; Level 1: Quick filter (1-2 instructions)
[(bpf/load-mem :h :r6 :r1 12)]
[(bpf/jmp-imm :jne :r6 0x0800 :drop)]  ; Not IPv4 → drop

;; Level 2: Medium filter (10 instructions)
[(bpf/load-mem :b :r7 :r1 23)]
[(bpf/jmp-imm :jne :r7 6 :drop)]       ; Not TCP → drop

;; Level 3: Expensive processing (100+ instructions)
;; ... full packet analysis ...
```

**Key**: Most packets exit at level 1 or 2.

### Pattern 4: Adaptive Behavior

Adjust behavior based on load.

```clojure
;; Check current load
[(bpf/call (bpf/helper :map_lookup_elem))]
[(bpf/load-mem :dw :r1 :r0 0)]         ; Load counter

;; If high load, increase sampling
[(bpf/jmp-imm :jgt :r1 10000 :high-load)]

;; Normal load: process fully
;; ...
[(bpf/jmp :done)]

[:high-load]
;; High load: sample only
[(bpf/call (bpf/helper :get_prandom_u32))]
[(bpf/mod :r0 10)]
[(bpf/jmp-imm :jne :r0 0 :drop)]

[:done]
```

## Common Performance Pitfalls

### Pitfall 1: Unbounded Loops

**Problem**: Verifier rejects or programs hang
**Solution**: Unroll or use bounded loops

### Pitfall 2: Stack Overflow

**Problem**: > 512 bytes stack usage
**Solution**: Use maps for large data structures

### Pitfall 3: Map Lookup Spam

**Problem**: Looking up same key multiple times
**Solution**: Cache pointer in register

### Pitfall 4: Unnecessary String Operations

**Problem**: Copying/comparing strings repeatedly
**Solution**: Use hashes or fixed-width comparisons

### Pitfall 5: Excessive Logging

**Problem**: Logging every event to ring buffer
**Solution**: Log only errors or sample

### Pitfall 6: Global Map Contention

**Problem**: All CPUs updating same map entry
**Solution**: Use per-CPU maps

### Pitfall 7: Complex Branching

**Problem**: Too many conditional branches
**Solution**: Simplify logic, use lookup tables

## Performance Checklist

Before deploying to production:

- [ ] Profiled program under load
- [ ] Measured overhead < 5%
- [ ] Verified no verifier warnings
- [ ] Tested on multiple kernel versions
- [ ] Benchmarked map operations
- [ ] Validated under peak load
- [ ] Checked for lock contention
- [ ] Reviewed instruction count
- [ ] Tested scaling to 32+ CPUs
- [ ] Monitored memory usage
- [ ] Verified tail call depth
- [ ] Tested with full packet rate
- [ ] Confirmed BTF compatibility
- [ ] Audited helper function usage
- [ ] Validated error handling overhead

## Real-World Performance Examples

### Example 1: XDP Packet Filter

**Before optimization**:
```
Throughput: 5 Mpps (million packets/sec)
CPU usage: 80%
Instructions: 250
```

**After optimization**:
- Early exit on non-IPv4
- Per-CPU maps
- Loop unrolling
- Cached map lookups

```
Throughput: 15 Mpps
CPU usage: 40%
Instructions: 80
```

**Improvement**: 3x throughput, 50% CPU reduction

### Example 2: Tracepoint Monitor

**Before**:
```
Events/sec: 100K
Overhead: 15%
Ring buffer outputs: 100K/sec
```

**After**:
- Aggregation in maps
- 1% sampling for details
- Batched updates

```
Events/sec: 100K (same)
Overhead: 2%
Ring buffer outputs: 1K/sec
```

**Improvement**: 7.5x overhead reduction

## Summary

Performance optimization for BPF requires:

✅ **Measurement** - Profile before optimizing
✅ **Understanding** - Know the hot paths
✅ **Techniques** - Apply appropriate optimizations
✅ **Trade-offs** - Balance performance, memory, complexity
✅ **Validation** - Test under realistic load

**Key Insight**: The fastest code is code that doesn't run. Filter early, process late, aggregate in kernel, export minimally.

## Next Steps

The following labs demonstrate practical optimization:

1. **Lab 12.1: High-Performance Packet Counter** - Optimize for millions of packets/sec
2. **Lab 12.2: Zero-Copy Event Collection** - Efficient event streaming
3. **Lab 12.3: Adaptive Sampling System** - Dynamic overhead control

These labs will teach you to build production-grade, high-performance BPF programs.

## References

- [BPF Performance Guide](https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html)
- [XDP Performance Tuning](https://github.com/xdp-project/xdp-tutorial/tree/master/packet03-redirecting)
- [BPF Verifier Documentation](https://www.kernel.org/doc/html/latest/bpf/verifier.html)
