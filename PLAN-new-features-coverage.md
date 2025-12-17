# Plan: New Features Coverage - Tutorials, Examples, and Tests

## Executive Summary

This plan covers the new features added to clj-ebpf that need documentation, examples, and test coverage verification. The key new additions are:

1. **Kprobe DSL Module** (`src/clj_ebpf/dsl/kprobe.clj`)
2. **Event Struct DSL Module** (`src/clj_ebpf/dsl/structs.clj`)
3. **Ring Buffer DSL Enhancements** (`src/clj_ebpf/dsl.clj`)
4. **Architecture-specific Kprobe Support** (`src/clj_ebpf/arch.clj`)
5. **Enhanced BTF Capabilities** (`src/clj_ebpf/btf.clj`)
6. **Bug Fixes** (ring buffer parsing, pinned maps, kprobe_multi syscalls)

---

## Part 1: New Features Analysis

### 1.1 Kprobe DSL Module (`clj-ebpf.dsl.kprobe`)

**New Functions:**
- `kprobe-read-args` - Generate instructions to read kprobe arguments from pt_regs
- `kprobe-prologue` - Standard kprobe prologue with optional context saving
- `kretprobe-get-return-value` - Read return value in kretprobe handlers
- `build-kprobe-program` - Complete kprobe program builder
- `build-kretprobe-program` - Complete kretprobe program builder
- `defkprobe-instructions` - Macro for defining kprobe handlers
- `defkretprobe-instructions` - Macro for defining kretprobe handlers
- `kprobe-section-name` / `kretprobe-section-name` - ELF section name generators
- `make-kprobe-program-info` / `make-kretprobe-program-info` - Program metadata builders

**Test Coverage:** ✅ Covered in `dsl_kprobe_test.clj`

### 1.2 Event Struct DSL Module (`clj-ebpf.dsl.structs`)

**New Functions:**
- `defevent` - Macro for defining event structures
- `make-event-def` - Programmatic event definition
- `event-size` - Get total structure size
- `event-field-offset` - Get field byte offset
- `event-field-size` - Get field size
- `event-field-type` - Get field type
- `event-fields` - List all field names
- `store-event-field` - Generate stx instruction for field
- `store-event-imm` - Generate st instruction for immediate value
- `zero-event-field` - Zero a field
- `store-event-fields` - Batch store multiple fields

**Test Coverage:** ✅ Covered in `dsl_kprobe_test.clj`

### 1.3 Ring Buffer DSL Enhancements (`clj-ebpf.dsl`)

**New Functions:**
- `ringbuf-reserve` - Reserve space in ring buffer
- `ringbuf-submit` - Submit reserved data
- `ringbuf-discard` - Discard reserved data
- `read-kprobe-arg` - Read kprobe argument by index

**Test Coverage:** ✅ Covered in `dsl_kprobe_test.clj`

### 1.4 Architecture Support (`clj-ebpf.arch`)

**New Functions:**
- `get-kprobe-arg-offset` - Get pt_regs offset for function argument
- Per-architecture pt_regs layouts for x86_64, ARM64, s390x, PPC64LE, RISC-V

**Test Coverage:** ✅ Covered in `dsl_kprobe_test.clj`

### 1.5 Call Helper Enhancement (`clj-ebpf.dsl.jump`)

**New Function:**
- `call-helper` - Generate BPF helper call by name

**Test Coverage:** ✅ Covered in `dsl_kprobe_test.clj`

---

## Part 2: Required Tutorials

### 2.1 NEW: Kprobe DSL Tutorial (Part 2, Chapter 5 Enhancement)

**Location:** `tutorials/part-2-program-types/chapter-05-kprobes/`

**Content to Add:**
```markdown
## Using the Kprobe DSL

### High-Level Kprobe Program Building

The `clj-ebpf.dsl.kprobe` namespace provides high-level macros and functions
for building kprobe programs without manually managing pt_regs offsets.

#### Reading Function Arguments

```clojure
(require '[clj-ebpf.dsl.kprobe :as kprobe])

;; Read first two arguments into r6 and r7
(kprobe/kprobe-prologue [:r6 :r7])

;; Or with context register saved
(kprobe/kprobe-prologue :r9 [:r6 :r7])
```

#### Building Complete Programs

```clojure
(kprobe/build-kprobe-program
  {:args [:r6 :r7]        ;; Function arguments
   :ctx-reg :r9           ;; Save pt_regs pointer
   :body [...]            ;; Your program logic
   :return-value 0})
```

#### Defining Kprobe Handlers

```clojure
(kprobe/defkprobe-instructions tcp-connect-probe
  {:function "tcp_v4_connect"
   :args [:r6]}  ;; sk pointer in r6
  (concat
    (helper-get-current-pid-tgid)
    [(mov-reg :r7 :r0)]
    ;; ... rest of program
    [(mov :r0 0)
     (exit-insn)]))
```
```

### 2.2 NEW: Event Structures Tutorial (Part 3, New Chapter)

**Location:** `tutorials/part-3-advanced/chapter-XX-event-structures/`

**Suggested Title:** "Defining Event Structures with the Struct DSL"

**Content:**
```markdown
# Chapter: Defining Event Structures with the Struct DSL

## Overview

When sending data from BPF programs to userspace via ring buffers or perf
events, you need well-defined structures. The `clj-ebpf.dsl.structs` namespace
provides a DSL for defining these structures with automatic offset calculation.

## Defining Events

```clojure
(require '[clj-ebpf.dsl.structs :as structs])

(structs/defevent ConnectionEvent
  [:timestamp :u64]
  [:pid :u32]
  [:saddr :u32]
  [:daddr :u32]
  [:sport :u16]
  [:dport :u16]
  [:protocol :u8]
  [:direction :u8]
  [:padding :u8 2]    ;; Array of 2 bytes
  [:comm :char 16])   ;; Fixed-size string
```

## Querying Structure Information

```clojure
(structs/event-size ConnectionEvent)        ;; => 44
(structs/event-field-offset ConnectionEvent :pid)  ;; => 8
(structs/event-fields ConnectionEvent)      ;; => [:timestamp :pid ...]
```

## Storing Fields in BPF Programs

```clojure
;; Store register value to field
(structs/store-event-field :r6 ConnectionEvent :pid :r7)

;; Store immediate value
(structs/store-event-imm :r6 ConnectionEvent :protocol 6)

;; Store multiple fields at once
(structs/store-event-fields :r6 ConnectionEvent
  {:pid {:reg :r7}
   :protocol {:imm 6}
   :direction {:imm 0}})
```
```

### 2.3 NEW: Ring Buffer DSL Tutorial (Part 3, Event Processing Enhancement)

**Location:** `tutorials/part-3-advanced/chapter-13-event-processing/`

**Content to Add:**
```markdown
## Ring Buffer DSL Operations

### Reserving Space

```clojure
(require '[clj-ebpf.dsl :as dsl])

;; Reserve 48 bytes in ring buffer (map fd = 5)
(dsl/ringbuf-reserve :r6 5 48)
;; r6 now contains pointer to reserved space, or NULL on failure
```

### Submitting Data

```clojure
;; After filling the reserved space, submit it
(dsl/ringbuf-submit :r6)
```

### Discarding Data

```clojure
;; If you need to abort, discard the reservation
(dsl/ringbuf-discard :r6)
```

### Complete Ring Buffer Pattern

```clojure
(def connection-tracer
  (dsl/assemble
    (vec (concat
      ;; Prologue: get first argument (sk pointer)
      (kprobe/kprobe-prologue [:r7])

      ;; Reserve space in ring buffer
      (dsl/ringbuf-reserve :r6 ringbuf-map-fd event-size)

      ;; Check if reservation succeeded
      [(dsl/jmp-imm :jeq :r6 0 :skip-store)]

      ;; Store event data
      [(structs/store-event-field :r6 ConnectionEvent :timestamp :r8)
       (structs/store-event-field :r6 ConnectionEvent :pid :r7)]

      ;; Submit to ring buffer
      (dsl/ringbuf-submit :r6)

      ;; Exit
      [(dsl/mov :r0 0)
       (dsl/exit-insn)]))))
```
```

---

## Part 3: Required Examples

### 3.1 NEW: Pure Clojure Kprobe Example

**Location:** `examples/pure_clojure_kprobe.clj`

**Description:** Complete example showing how to build a kprobe entirely in Clojure
without external C/LLVM compilation.

```clojure
(ns clj-ebpf.examples.pure-clojure-kprobe
  "Example: Building a complete kprobe program in pure Clojure.

   This example demonstrates the new kprobe DSL for building BPF programs
   without needing external compilers."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.kprobe :as kprobe]
            [clj-ebpf.dsl.structs :as structs]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as progs]))

;; Define the event structure
(structs/defevent TcpConnectEvent
  [:timestamp :u64]
  [:pid :u32]
  [:tgid :u32]
  [:comm :char 16]
  [:daddr :u32]
  [:dport :u16]
  [:padding :u16])

;; Build the kprobe program
(defn make-tcp-connect-probe [ringbuf-fd]
  (dsl/assemble
    (vec (concat
      ;; Read sk pointer (first arg) into r7
      (kprobe/kprobe-prologue :r9 [:r7])

      ;; Get current PID/TGID
      (dsl/helper-get-current-pid-tgid)
      [(dsl/mov-reg :r8 :r0)]  ;; Save in r8

      ;; Get timestamp
      (dsl/helper-ktime-get-ns)
      [(dsl/mov-reg :r6 :r0)]  ;; Save timestamp in r6

      ;; Reserve ring buffer space
      (dsl/ringbuf-reserve :r1 ringbuf-fd (structs/event-size TcpConnectEvent))

      ;; Check reservation success
      [(dsl/jmp-imm :jeq :r1 0 :exit)]

      ;; Store timestamp
      [(structs/store-event-field :r1 TcpConnectEvent :timestamp :r6)]

      ;; Store PID (lower 32 bits of r8)
      [(dsl/mov-reg :r2 :r8)
       (dsl/and-imm :r2 0xffffffff)
       (structs/store-event-field :r1 TcpConnectEvent :pid :r2)]

      ;; Store TGID (upper 32 bits of r8)
      [(dsl/rsh :r8 32)
       (structs/store-event-field :r1 TcpConnectEvent :tgid :r8)]

      ;; Submit event
      (dsl/ringbuf-submit :r1)

      ;; Exit with success
      [[:label :exit]
       (dsl/mov :r0 0)
       (dsl/exit-insn)]))))

;; Main function to run the tracer
(defn run-tcp-connect-tracer []
  (let [;; Create ring buffer map
        ringbuf (maps/create-ringbuf-map 4096 :map-name "events")

        ;; Build and load program
        prog-bytes (make-tcp-connect-probe (:fd ringbuf))
        prog (progs/load-program prog-bytes :kprobe "tcp_connect_trace")]

    ;; Attach to tcp_v4_connect
    (progs/attach-kprobe prog "tcp_v4_connect")

    {:program prog
     :ringbuf ringbuf}))
```

### 3.2 NEW: Event Structure Definition Example

**Location:** `examples/event_structs.clj`

**Description:** Shows various event structure patterns.

### 3.3 NEW: Multi-Architecture Kprobe Example

**Location:** `examples/multiarch_kprobe.clj`

**Description:** Shows how the kprobe DSL handles different architectures.

---

## Part 4: Lab Exercises

### 4.1 NEW: Kprobe DSL Lab (Part 2, Chapter 5)

**Location:** `tutorials/part-2-program-types/chapter-05-kprobes/labs/`

**Lab 5.3: Pure Clojure Kprobe**

**Objectives:**
1. Define an event structure using `defevent`
2. Build a kprobe using `build-kprobe-program`
3. Use ring buffer DSL for event output
4. Handle multiple function arguments

**Starter Code:**
```clojure
(ns lab-5-3-pure-clojure-kprobe
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.kprobe :as kprobe]
            [clj-ebpf.dsl.structs :as structs]))

;; TODO: Define SyscallEvent structure with:
;; - timestamp (u64)
;; - pid (u32)
;; - syscall_nr (u32)
;; - arg0, arg1, arg2 (u64 each)

;; TODO: Build kprobe for sys_enter tracepoint
;; that captures syscall info and outputs to ring buffer
```

### 4.2 NEW: Event Structures Lab (Part 3)

**Location:** `tutorials/part-3-advanced/chapter-XX-event-structures/labs/`

**Lab: Network Event Structure**

**Objectives:**
1. Define complex nested-style event structure
2. Handle arrays and padding
3. Use batch store operations

---

## Part 5: Test Coverage Verification

### Current Test Status

| Feature | Test File | Tests | Status |
|---------|-----------|-------|--------|
| Kprobe DSL | `dsl_kprobe_test.clj` | 16 | ✅ Complete |
| Event Structs | `dsl_kprobe_test.clj` | 5 | ✅ Complete |
| Ring Buffer DSL | `dsl_kprobe_test.clj` | 3 | ✅ Complete |
| call-helper | `dsl_kprobe_test.clj` | 2 | ✅ Complete |
| pt_regs offsets | `dsl_kprobe_test.clj` | 2 | ✅ Complete |
| DSL Core | `dsl_test.clj` | 40 | ✅ Complete |
| DSL Examples | `dsl_examples_test.clj` | 30 | ✅ Complete |

### CI-Safe Test Suite

**Total:** 164 tests, 928 assertions
**Status:** All passing

### Missing Test Coverage (Low Priority)

1. **Edge cases for large event structures** - Consider adding property-based tests
2. **Multi-architecture pt_regs offsets** - Currently only tests current arch
3. **Ring buffer reservation failure paths** - Mocked tests needed

---

## Part 6: Implementation Plan

### Phase 1: Immediate (Test & CI)
- [x] Add `dsl_kprobe_test.clj` to CI-safe tests
- [x] Verify all tests pass
- [ ] Commit and push test updates

### Phase 2: Examples (1-2 days)
- [ ] Create `examples/pure_clojure_kprobe.clj`
- [ ] Create `examples/event_structs.clj`
- [ ] Create `examples/multiarch_kprobe.clj`
- [ ] Update `examples/README.md`

### Phase 3: Tutorials (2-3 days)
- [ ] Add kprobe DSL section to Chapter 5
- [ ] Create new Event Structures chapter
- [ ] Add ring buffer DSL content to Chapter 13
- [ ] Create corresponding lab exercises

### Phase 4: Documentation (1 day)
- [ ] Update API documentation
- [ ] Add docstrings to new functions
- [ ] Update main README with new features

---

## Part 7: Files to Create/Modify

### New Files
1. `examples/pure_clojure_kprobe.clj`
2. `examples/event_structs.clj`
3. `examples/multiarch_kprobe.clj`
4. `tutorials/part-3-advanced/chapter-XX-event-structures/README.md`
5. `tutorials/part-3-advanced/chapter-XX-event-structures/labs/README.md`
6. `tutorials/part-2-program-types/chapter-05-kprobes/labs/lab_5_3_pure_clojure.clj`

### Files to Modify
1. `tutorials/part-2-program-types/chapter-05-kprobes/README.md` - Add DSL section
2. `tutorials/part-3-advanced/chapter-13-event-processing/README.md` - Add ring buffer DSL
3. `examples/README.md` - Document new examples
4. `README.md` - Highlight new features

---

## Conclusion

The new kprobe DSL, event structures, and ring buffer DSL features are **well-tested**
(16+ dedicated tests) but need **tutorial documentation** and **runnable examples**
to help users adopt them effectively.

Priority order:
1. ✅ Test coverage is complete
2. **HIGH**: Create working examples
3. **MEDIUM**: Add tutorial content
4. **LOW**: Edge case tests for property-based testing
