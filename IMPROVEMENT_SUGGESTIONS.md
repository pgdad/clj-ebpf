# clj-ebpf Improvement Suggestions

This document outlines beneficial changes to the clj-ebpf project based on a comprehensive code review. Each suggestion includes proposed implementation details and expected benefits.

---

## Table of Contents

1. [High Priority Changes](#high-priority-changes)
2. [Medium Priority Changes](#medium-priority-changes)
3. [Lower Priority Changes](#lower-priority-changes)
4. [Code Organization](#code-organization)
5. [API Improvements](#api-improvements)
6. [Testing Enhancements](#testing-enhancements)
7. [Documentation](#documentation)

---

## High Priority Changes

### 1. Multi-Architecture Support

**Current State:**
- Hardcoded syscall numbers for x86_64 only (321 for bpf, 298 for perf_event_open)
- Hardcoded libc path: `/lib/x86_64-linux-gnu/libc.so.6`
- No runtime architecture detection

**Proposed Implementation:**
```clojure
;; In syscall.clj or new arch.clj module

(def ^:private arch
  (let [arch-str (System/getProperty "os.arch")]
    (case arch-str
      "amd64" :x86_64
      "x86_64" :x86_64
      "aarch64" :arm64
      "arm64" :arm64
      "s390x" :s390x
      :unknown)))

(def ^:private syscall-nrs
  {:x86_64  {:bpf 321 :perf-event-open 298 :mmap 9 :munmap 11}
   :arm64   {:bpf 280 :perf-event-open 241 :mmap 222 :munmap 215}
   :s390x   {:bpf 351 :perf-event-open 331 :mmap 90 :munmap 91}})

(def ^:private libc-paths
  {:x86_64  ["/lib/x86_64-linux-gnu/libc.so.6" "/lib64/libc.so.6"]
   :arm64   ["/lib/aarch64-linux-gnu/libc.so.6" "/lib64/libc.so.6"]
   :s390x   ["/lib/s390x-linux-gnu/libc.so.6" "/lib64/libc.so.6"]})

(defn- find-libc []
  (let [paths (get libc-paths arch)]
    (or (first (filter #(.exists (java.io.File. %)) paths))
        (throw (ex-info "Could not find libc" {:arch arch :tried paths})))))
```

**Expected Benefits:**
- Enables clj-ebpf on ARM64 servers (AWS Graviton, Apple Silicon via Linux VMs)
- Supports s390x mainframes for enterprise users
- More robust libc discovery with fallback paths
- Single codebase for all platforms

---

### 2. DSL Module Refactoring

**Current State:**
- `dsl.clj` is 2,075 lines - monolithic and hard to navigate
- Mixes instruction encoding, helper definitions, and high-level constructs

**Proposed Implementation:**

Split into focused modules:
```
src/clj_ebpf/dsl/
├── core.clj           ;; Public API, re-exports
├── instructions.clj   ;; Low-level instruction encoding
├── alu.clj            ;; ALU operations (add, sub, mul, div, etc.)
├── memory.clj         ;; Load/store operations (ldx, stx, ld, st)
├── jump.clj           ;; Jump/branch operations
├── helpers.clj        ;; BPF helper call wrappers
└── assembler.clj      ;; Instruction assembly, byte encoding
```

**Example structure for `dsl/instructions.clj`:**
```clojure
(ns clj-ebpf.dsl.instructions
  "Low-level BPF instruction encoding.")

(def ^:const BPF_LD    0x00)
(def ^:const BPF_LDX   0x01)
(def ^:const BPF_ST    0x02)
(def ^:const BPF_STX   0x03)
(def ^:const BPF_ALU   0x04)
(def ^:const BPF_JMP   0x05)
(def ^:const BPF_ALU64 0x07)

(defn encode-instruction
  "Encode a single BPF instruction into 8 bytes."
  [opcode dst src offset imm]
  ...)
```

**Expected Benefits:**
- Improved maintainability - each module has single responsibility
- Easier testing - can test instruction encoding independently
- Better discoverability - users can find relevant functions faster
- Cleaner namespace imports - load only what you need

---

### 3. Externalize Helper Metadata

**Current State:**
- `helpers.clj` is ~2,000 lines of hardcoded Clojure data
- Adding new helpers requires code changes
- No easy way to extend with custom helpers

**Proposed Implementation:**

Move metadata to EDN resource:
```clojure
;; resources/bpf-helpers.edn
{:bpf-map-lookup-elem
 {:id 1
  :name "bpf_map_lookup_elem"
  :return :ptr
  :args [{:name "map" :type :map-fd}
         {:name "key" :type :ptr}]
  :since "3.19"
  :categories #{:map}
  :description "Look up an element in a map."}

 :bpf-get-prandom-u32
 {:id 7
  :name "bpf_get_prandom_u32"
  :return :u32
  :args []
  :since "4.1"
  :categories #{:utility}
  :description "Get a pseudo-random 32-bit number."}}
```

New loader in `helpers.clj`:
```clojure
(ns clj-ebpf.helpers
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]))

(def helpers
  (delay
    (with-open [r (io/reader (io/resource "bpf-helpers.edn"))]
      (edn/read (java.io.PushbackReader. r)))))

(defn helper-by-id [id]
  (first (filter #(= id (:id %)) (vals @helpers))))

(defn helper-by-name [name]
  (get @helpers (keyword name)))
```

**Expected Benefits:**
- Easier to add new helpers (just edit EDN)
- Enables user-defined custom helpers
- Reduces code size
- Better separation of data and logic
- Easier documentation generation from metadata

---

### 4. Improved Error Handling

**Current State:**
- Incomplete errno mapping (falls back to `:unknown`)
- No retry logic for transient failures
- Mix of exception types

**Proposed Implementation:**

Create dedicated exception hierarchy:
```clojure
;; In new errors.clj module

(defn bpf-error [type message data]
  (ex-info message (assoc data :error-type type)))

(defn map-error [message data]
  (bpf-error :map-error message data))

(defn program-error [message data]
  (bpf-error :program-error message data))

(defn syscall-error [message data]
  (bpf-error :syscall-error message data))

;; Complete errno mapping
(def errno->keyword
  {1  :eperm
   2  :enoent
   3  :esrch
   4  :eintr
   5  :eio
   ;; ... complete POSIX set
   524 :enotsupp})

;; Retry wrapper for transient errors
(defn with-retry
  "Retry operation on transient errors like EAGAIN or EINTR."
  ([f] (with-retry f 3 100))
  ([f max-retries delay-ms]
   (loop [attempt 1]
     (let [result (try (f) (catch Exception e {:error e}))]
       (if-let [e (:error result)]
         (if (and (< attempt max-retries)
                  (transient-error? e))
           (do (Thread/sleep delay-ms)
               (recur (inc attempt)))
           (throw e))
         result)))))
```

**Expected Benefits:**
- Clearer error messages with context
- Automatic recovery from transient failures
- Programmatic error handling based on type
- Complete errno coverage for debugging

---

## Medium Priority Changes

### 5. Lazy Map Iteration

**Current State:**
- `map-keys` and `map-entries` eagerly load all entries into memory
- Can cause OOM for large maps

**Proposed Implementation:**
```clojure
(defn map-entries-seq
  "Returns a lazy sequence of [key value] pairs from a BPF map.
   Keys and values are deserialized on demand."
  [bpf-map]
  (let [{:keys [fd key-size value-size key-deserializer value-deserializer]} bpf-map]
    (letfn [(next-entry [prev-key]
              (lazy-seq
                (when-let [[k v] (map-get-next-key-value fd prev-key key-size value-size)]
                  (cons [(key-deserializer k) (value-deserializer v)]
                        (next-entry k)))))]
      (next-entry nil))))

;; Usage
(doseq [[k v] (take 100 (map-entries-seq my-large-map))]
  (process k v))
```

**Expected Benefits:**
- Memory efficient for large maps
- Can process maps larger than JVM heap
- Compatible with Clojure's sequence abstraction
- Enables streaming processing patterns

---

### 6. Ring Buffer Backpressure Support

**Current State:**
- Ring buffer consumer processes events as fast as possible
- No mechanism to slow down producers when consumer is overwhelmed

**Proposed Implementation:**
```clojure
(defn create-ringbuf-consumer-with-backpressure
  "Create a ring buffer consumer that supports backpressure.
   When the pending queue exceeds max-pending, new events are dropped
   and a metric is incremented."
  [ringbuf-map handler {:keys [max-pending drop-handler]
                        :or {max-pending 10000
                             drop-handler (fn [_] nil)}}]
  (let [pending (java.util.concurrent.atomic.AtomicLong. 0)
        dropped (java.util.concurrent.atomic.AtomicLong. 0)
        wrapped-handler (fn [event]
                          (if (< (.get pending) max-pending)
                            (do (.incrementAndGet pending)
                                (try
                                  (handler event)
                                  (finally
                                    (.decrementAndGet pending))))
                            (do (.incrementAndGet dropped)
                                (drop-handler event))))]
    {:consumer (create-ringbuf-consumer ringbuf-map wrapped-handler)
     :pending pending
     :dropped dropped}))
```

**Expected Benefits:**
- Prevents unbounded memory growth under load
- Observable metrics for monitoring
- Graceful degradation instead of crashes
- Custom drop handling (logging, sampling)

---

### 7. Tail Call Chaining Helper

**Current State:**
- BPF supports tail calls for program chaining
- Helper exists (`bpf_tail_call`) but no high-level pattern

**Proposed Implementation:**
```clojure
(defn create-prog-array
  "Create a program array for tail calls."
  [max-entries]
  (create-map {:map-type :prog-array
               :key-size 4
               :value-size 4
               :max-entries max-entries}))

(defn register-tail-call
  "Register a program at index for tail calls."
  [prog-array index program]
  (map-update prog-array
              (utils/int->bytes index)
              (utils/int->bytes (:fd program))))

(defn tail-call-instructions
  "Generate instructions for a tail call.
   r1 = ctx (preserved from entry)
   r2 = prog-array fd
   r3 = index"
  [prog-array-fd index]
  [(ld-map-fd :r2 prog-array-fd)
   (mov :r3 index)
   (call :bpf-tail-call)])

;; High-level chain macro
(defmacro defchain
  "Define a chain of BPF programs with tail calls."
  [name prog-array & stages]
  `(do
     ~@(for [[idx stage-name stage-body] (map-indexed vector stages)]
         `(def ~stage-name
            (load-program
              {:prog-type :xdp
               :insns (concat ~stage-body
                              (tail-call-instructions (:fd ~prog-array) ~(inc idx)))})))
     (def ~name {:stages [~@(map second stages)]
                 :prog-array ~prog-array})))
```

**Expected Benefits:**
- Enables complex multi-stage packet processing
- Better code organization for large BPF programs
- Works around BPF instruction limits
- Familiar pattern for libbpf users

---

### 8. Atomic Operations in DSL

**Current State:**
- DSL lacks atomic operation helpers
- Manual instruction encoding required for atomics

**Proposed Implementation:**
```clojure
;; In dsl/atomic.clj

(defn atomic-add
  "Atomic add to memory location.
   *dst += src"
  [size dst src offset]
  (let [op (case size :w 0x00 :dw 0x01)]
    (encode-instruction
      (bit-or BPF_STX BPF_ATOMIC op)
      dst src offset BPF_ADD)))

(defn atomic-xchg
  "Atomic exchange.
   src = xchg(*dst, src)"
  [size dst src offset]
  ...)

(defn atomic-cmpxchg
  "Atomic compare and exchange.
   r0 = cmpxchg(*dst, r0, src)"
  [size dst src offset]
  ...)

(defn atomic-fetch-add
  "Atomic fetch and add.
   src = fetch_add(*dst, src)"
  [size dst src offset]
  ...)
```

**Expected Benefits:**
- Thread-safe counters and statistics
- Lock-free data structure support
- Essential for per-CPU map aggregation
- Matches libbpf atomic support

---

## Lower Priority Changes

### 9. Map-in-Map Support

**Current State:**
- Basic map types supported
- No explicit support for nested maps (map-in-map)

**Proposed Implementation:**
```clojure
(defn create-map-in-map
  "Create an outer map that holds references to inner maps."
  [{:keys [outer-type inner-template max-entries]
    :or {outer-type :array-of-maps}}]
  (let [inner-map (create-map inner-template)
        outer-map (create-map
                    {:map-type outer-type
                     :key-size 4
                     :value-size 4
                     :max-entries max-entries
                     :inner-map-fd (:fd inner-map)})]
    {:outer outer-map
     :inner-template inner-template
     :inner-maps (atom {0 inner-map})}))

(defn add-inner-map
  "Add a new inner map at the specified index."
  [{:keys [outer inner-template inner-maps]} index]
  (let [new-inner (create-map inner-template)]
    (map-update outer (utils/int->bytes index) (utils/int->bytes (:fd new-inner)))
    (swap! inner-maps assoc index new-inner)
    new-inner))
```

**Expected Benefits:**
- Per-CPU hash tables
- Dynamic map allocation
- Complex nested data structures
- Better memory isolation

---

### 10. BPF_PROG_TEST_RUN Support

**Current State:**
- Programs can only be tested by attaching to real hooks
- No offline/unit testing capability

**Proposed Implementation:**
```clojure
(defn test-run-program
  "Run a BPF program in test mode with synthetic input.
   Returns {:retval N :duration-ns N :data-out bytes}."
  [program {:keys [data-in ctx-in repeat]
            :or {repeat 1}}]
  (let [data-out-size (or (count data-in) 256)
        data-out (byte-array data-out-size)
        attr (build-test-run-attr
               (:fd program)
               data-in
               ctx-in
               data-out
               repeat)]
    (syscall/bpf-syscall :prog-test-run attr)
    {:retval (get-attr-field attr :retval)
     :duration-ns (get-attr-field attr :duration)
     :data-out data-out}))

;; Usage for XDP testing
(let [result (test-run-program xdp-prog
               {:data-in (build-test-packet :tcp {:src-ip "10.0.0.1"
                                                   :dst-ip "10.0.0.2"
                                                   :dst-port 80})})]
  (assert (= 2 (:retval result))) ; XDP_PASS
  )
```

**Expected Benefits:**
- Unit test BPF programs without root/network access
- Faster development iteration
- CI/CD integration for BPF code
- Regression testing for packet processing logic

---

### 11. Performance Benchmarks

**Current State:**
- No benchmark suite
- Performance characteristics unknown

**Proposed Implementation:**

Create `bench/` directory with Criterium benchmarks:
```clojure
;; bench/clj_ebpf/bench/maps.clj
(ns clj-ebpf.bench.maps
  (:require [criterium.core :as bench]
            [clj-ebpf.maps :as maps]))

(defn bench-map-lookup []
  (let [m (maps/create-map {:map-type :hash
                            :key-size 4
                            :value-size 8
                            :max-entries 10000})]
    ;; Populate
    (doseq [i (range 10000)]
      (maps/map-update m (utils/int->bytes i) (utils/long->bytes (* i i))))

    ;; Benchmark
    (bench/bench
      (maps/map-lookup m (utils/int->bytes (rand-int 10000))))))

(defn bench-batch-operations []
  ...)

(defn -main []
  (println "=== Map Lookup Benchmark ===")
  (bench-map-lookup)
  (println "\n=== Batch Operations Benchmark ===")
  (bench-batch-operations))
```

**Expected Benefits:**
- Identify performance bottlenecks
- Track performance across versions
- Compare with libbpf baseline
- Guide optimization efforts

---

## Code Organization

### 12. Consistent Namespace Structure

**Current Issues:**
- Some modules in root `clj_ebpf/` are feature-specific
- Mixed abstraction levels in same directory

**Proposed Structure:**
```
src/clj_ebpf/
├── core.clj              ;; Public API re-exports
├── constants.clj         ;; BPF constants
├── utils.clj             ;; Common utilities
│
├── internal/             ;; Low-level implementation
│   ├── syscall.clj       ;; FFI syscalls
│   ├── memory.clj        ;; Memory management
│   └── arch.clj          ;; Architecture detection
│
├── data/                 ;; Data structures
│   ├── maps.clj          ;; BPF maps
│   ├── programs.clj      ;; BPF programs
│   └── events.clj        ;; Event buffers
│
├── dsl/                  ;; Code generation
│   ├── core.clj          ;; DSL API
│   ├── instructions.clj  ;; Instruction encoding
│   └── assembler.clj     ;; Assembly
│
├── attach/               ;; Attachment points
│   ├── xdp.clj
│   ├── tc.clj
│   ├── kprobe.clj
│   ├── cgroup.clj
│   └── lsm.clj
│
└── tools/                ;; Development tools
    ├── btf.clj           ;; BTF parsing
    ├── elf.clj           ;; ELF parsing
    └── relocate.clj      ;; CO-RE relocations
```

**Expected Benefits:**
- Clearer mental model of library structure
- Easier navigation for new contributors
- Better separation of stable vs internal APIs
- Logical grouping by functionality

---

## API Improvements

### 13. Consistent Function Signatures

**Current Issues:**
- Mix of positional and keyword arguments
- Inconsistent option names (`:flags` vs embedded in options)

**Proposed Standard:**
```clojure
;; All public functions follow this pattern:
;; (fn required-arg {:keys [optional-args] :as opts})

;; Before (inconsistent)
(defn create-map [map-type key-size value-size max-entries & opts])
(defn load-program [prog-type insns flags log-level])

;; After (consistent)
(defn create-map
  "Create a BPF map.

   Required:
   - map-type: One of :hash, :array, :lru-hash, etc.
   - key-size: Size of key in bytes
   - value-size: Size of value in bytes

   Options:
   - :max-entries (default 1024)
   - :flags (default 0)
   - :name (optional, for debugging)
   - :key-serializer (fn [clj-val] -> bytes)
   - :key-deserializer (fn [bytes] -> clj-val)"
  [{:keys [map-type key-size value-size max-entries flags name
           key-serializer key-deserializer value-serializer value-deserializer]
    :or {max-entries 1024 flags 0}
    :as opts}]
  ...)
```

**Expected Benefits:**
- Predictable API for users
- Easier to add new options without breaking changes
- Self-documenting function calls
- Better IDE support

---

### 14. Predicate Functions

**Current State:**
- No easy way to check if a map/program exists or is valid

**Proposed Implementation:**
```clojure
(defn map-exists?
  "Check if a BPF map is still valid."
  [bpf-map]
  (try
    (syscall/bpf-obj-get-info-by-fd (:fd bpf-map) :map)
    true
    (catch Exception _ false)))

(defn program-exists?
  "Check if a BPF program is still valid."
  [bpf-prog]
  (try
    (syscall/bpf-obj-get-info-by-fd (:fd bpf-prog) :prog)
    true
    (catch Exception _ false)))

(defn map-pinned?
  "Check if a map is pinned to the BPF filesystem."
  [bpf-map]
  (boolean (:pin-path bpf-map)))

(defn program-attached?
  "Check if a program has any active attachments."
  [bpf-prog]
  (not (empty? (:attachments bpf-prog))))
```

**Expected Benefits:**
- Defensive programming patterns
- Better error messages
- State introspection for debugging
- Resource cleanup validation

---

## Testing Enhancements

### 15. Mock Syscall Layer

**Current State:**
- All tests require real BPF syscalls
- Tests fail without CAP_BPF capability

**Proposed Implementation:**
```clojure
;; test/clj_ebpf/test_utils.clj
(ns clj-ebpf.test-utils)

(def ^:dynamic *mock-syscalls* false)
(def ^:dynamic *syscall-results* {})

(defmacro with-mock-syscalls
  "Run tests with mocked syscall layer."
  [mock-results & body]
  `(binding [*mock-syscalls* true
             *syscall-results* ~mock-results]
     ~@body))

;; In syscall.clj
(defn bpf-syscall [cmd attr]
  (if *mock-syscalls*
    (get *syscall-results* cmd {:fd 42})  ; Return mock fd
    (real-bpf-syscall cmd attr)))

;; Usage in tests
(deftest test-map-creation
  (with-mock-syscalls {:map-create {:fd 100}}
    (let [m (create-map {:map-type :hash :key-size 4 :value-size 4})]
      (is (= 100 (:fd m))))))
```

**Expected Benefits:**
- Tests run without root privileges
- Faster test execution
- CI/CD compatibility
- Isolated unit testing

---

### 16. Property-Based Testing

**Current State:**
- Only example-based tests
- Edge cases may be missed

**Proposed Implementation:**
```clojure
(ns clj-ebpf.maps-property-test
  (:require [clojure.test.check :as tc]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def gen-key (gen/vector gen/byte 4))
(def gen-value (gen/vector gen/byte 8))

(def map-roundtrip-property
  (prop/for-all [k gen-key
                 v gen-value]
    (with-map [m {:map-type :hash :key-size 4 :value-size 8}]
      (map-update m k v)
      (= v (map-lookup m k)))))

(deftest property-tests
  (is (:pass? (tc/quick-check 100 map-roundtrip-property))))
```

**Expected Benefits:**
- Better edge case coverage
- Discovers unexpected invariant violations
- More confidence in serialization code
- Reproducible failure cases

---

## Documentation

### 17. API Documentation Generation

**Current State:**
- Some functions lack docstrings
- No generated API documentation

**Proposed Implementation:**

Add comprehensive docstrings and use codox for generation:
```clojure
;; deps.edn
{:aliases
 {:docs {:extra-deps {codox/codox {:mvn/version "0.10.8"}}
         :exec-fn codox.main/generate-docs
         :exec-args {:source-paths ["src"]
                     :output-path "docs/api"
                     :metadata {:doc/format :markdown}}}}}

;; Example improved docstring
(defn create-map
  "Create a new BPF map.

   ## Arguments

   | Key | Type | Required | Default | Description |
   |-----|------|----------|---------|-------------|
   | `:map-type` | keyword | yes | - | Map type (`:hash`, `:array`, etc.) |
   | `:key-size` | int | yes | - | Key size in bytes |
   | `:value-size` | int | yes | - | Value size in bytes |
   | `:max-entries` | int | no | 1024 | Maximum number of entries |

   ## Returns

   A map record with `:fd`, `:type`, `:key-size`, `:value-size` keys.

   ## Example

   ```clojure
   (def my-map (create-map {:map-type :hash
                            :key-size 4
                            :value-size 8
                            :max-entries 10000}))
   ```

   ## See Also

   - `map-lookup` - Read values from the map
   - `map-update` - Write values to the map
   - `with-map` - Automatic resource management"
  [{:keys [map-type key-size value-size max-entries] :as opts}]
  ...)
```

**Expected Benefits:**
- Searchable API documentation
- Consistent documentation style
- Easier onboarding for new users
- IDE tooltip support

---

### 18. Architecture Decision Records (ADRs)

**Current State:**
- Design decisions not documented
- Hard for contributors to understand "why"

**Proposed Implementation:**

Create `docs/adr/` directory:
```markdown
# ADR-001: Use Panama FFI instead of JNI

## Status
Accepted

## Context
clj-ebpf needs to make BPF syscalls to interact with the kernel.
Options considered:
1. JNI with native C library
2. JNA (Java Native Access)
3. Panama FFI (Foreign Function & Memory API)

## Decision
Use Panama FFI (Java 21+) for all native interactions.

## Consequences
### Positive
- No native compilation required
- Pure Java distribution
- Automatic memory management via Arena
- Type-safe foreign function calls

### Negative
- Requires Java 21+
- Panama API still evolving
- Less community examples compared to JNI

## References
- JEP 454: Foreign Function & Memory API
```

**Expected Benefits:**
- Preserves institutional knowledge
- Easier onboarding for contributors
- Transparent design process
- Reference for future decisions

---

## Summary of Priorities

| Priority | Change | Impact | Effort |
|----------|--------|--------|--------|
| High | Multi-architecture support | Enables ARM64/s390x | Medium |
| High | DSL module refactoring | Maintainability | High |
| High | Externalize helper metadata | Extensibility | Low |
| High | Improved error handling | Reliability | Medium |
| Medium | Lazy map iteration | Memory efficiency | Medium |
| Medium | Ring buffer backpressure | Stability under load | Medium |
| Medium | Tail call chaining | Feature completeness | Medium |
| Medium | Atomic operations in DSL | Concurrency support | Low |
| Low | Map-in-map support | Advanced use cases | Medium |
| Low | BPF_PROG_TEST_RUN | Testing | Medium |
| Low | Performance benchmarks | Optimization | Low |

---

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)
- Multi-architecture support
- Improved error handling
- Externalize helper metadata

### Phase 2: Code Quality (Weeks 3-4)
- DSL module refactoring
- Consistent namespace structure
- API documentation generation

### Phase 3: Features (Weeks 5-6)
- Lazy map iteration
- Atomic operations in DSL
- Tail call chaining helper

### Phase 4: Advanced (Weeks 7-8)
- Ring buffer backpressure
- BPF_PROG_TEST_RUN support
- Map-in-map support

### Ongoing
- Performance benchmarks
- Property-based testing
- Architecture decision records

---

*Document generated: 2025-11-24*
*Based on review of clj-ebpf v1.0*
