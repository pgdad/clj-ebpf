# Chapter 21: Event Structures with the Struct DSL

**Duration**: 2-3 hours | **Difficulty**: Intermediate

## Learning Objectives

By the end of this chapter, you will:
- Define BPF event structures using the `defevent` macro
- Calculate field offsets and sizes automatically
- Generate store instructions for filling structures
- Design efficient, aligned event layouts
- Parse events in userspace Clojure code
- Use common patterns for different event types

## Prerequisites

- Completed [Chapter 13 - Event Processing](../chapter-13/README.md)
- Understanding of BPF maps and ring buffers
- Familiarity with C struct layouts
- Basic knowledge of memory alignment

## 21.1 Why Event Structures Matter

### The Problem

When sending data from BPF programs to userspace, you need well-defined structures:

```
BPF Program (Kernel)              Userspace (Clojure)
┌─────────────────┐               ┌─────────────────┐
│ Collect data    │               │ Parse data      │
│ ├── timestamp   │ ──────────────│ ├── timestamp?  │
│ ├── pid         │   Ring Buffer │ ├── pid?        │
│ └── comm[16]    │               │ └── comm?       │
└─────────────────┘               └─────────────────┘

Without structure definitions:
- Manual offset calculations
- Easy to make mistakes
- Hard to maintain
- Not portable
```

### The Solution

The `clj-ebpf.dsl.structs` namespace provides:
- Type-safe structure definitions
- Automatic offset calculation
- Store instruction generation
- Field type metadata

```clojure
(require '[clj-ebpf.dsl.structs :as structs])

;; Define once, use everywhere
(structs/defevent ProcessEvent
  [:timestamp :u64]
  [:pid :u32]
  [:comm :char 16])

;; Query structure
(structs/event-size ProcessEvent)        ;; => 28
(structs/event-field-offset ProcessEvent :pid)  ;; => 8

;; Generate instructions
(structs/store-event-field :r6 ProcessEvent :pid :r7)
```

## 21.2 The defevent Macro

### Basic Syntax

```clojure
(structs/defevent EventName
  [:field1 :type]
  [:field2 :type]
  [:array-field :type count]
  ...)
```

### Supported Types

| Type | Size | Description |
|------|------|-------------|
| `:u8` | 1 byte | Unsigned 8-bit integer |
| `:i8` | 1 byte | Signed 8-bit integer |
| `:u16` | 2 bytes | Unsigned 16-bit integer |
| `:i16` | 2 bytes | Signed 16-bit integer |
| `:u32` | 4 bytes | Unsigned 32-bit integer |
| `:i32` | 4 bytes | Signed 32-bit integer |
| `:u64` | 8 bytes | Unsigned 64-bit integer |
| `:i64` | 8 bytes | Signed 64-bit integer |
| `:ptr` | 8 bytes | Pointer (64-bit) |
| `:char` | 1 byte | Character (for arrays) |

### Array Fields

Use a third element for array count:

```clojure
(structs/defevent NetworkEvent
  [:timestamp :u64]
  [:comm :char 16]        ;; 16-byte character array
  [:padding :u8 3]        ;; 3-byte padding array
  [:ports :u16 4])        ;; 4 element u16 array
```

## 21.3 Structure Queries

### Basic Queries

```clojure
;; Total size in bytes
(structs/event-size MyEvent)

;; Field byte offset
(structs/event-field-offset MyEvent :fieldname)

;; Field size in bytes
(structs/event-field-size MyEvent :fieldname)

;; Field type
(structs/event-field-type MyEvent :fieldname)

;; List of all field names
(structs/event-fields MyEvent)
```

### Example

```clojure
(structs/defevent ConnectionEvent
  [:timestamp :u64]    ; offset 0, size 8
  [:pid :u32]          ; offset 8, size 4
  [:uid :u32]          ; offset 12, size 4
  [:saddr :u32]        ; offset 16, size 4
  [:daddr :u32]        ; offset 20, size 4
  [:sport :u16]        ; offset 24, size 2
  [:dport :u16]        ; offset 26, size 2
  [:protocol :u8]      ; offset 28, size 1
  [:flags :u8]         ; offset 29, size 1
  [:padding :u8 2])    ; offset 30, size 2
;; Total: 32 bytes

(structs/event-size ConnectionEvent)            ;; => 32
(structs/event-field-offset ConnectionEvent :sport)  ;; => 24
(structs/event-fields ConnectionEvent)
;; => [:timestamp :pid :uid :saddr :daddr :sport :dport :protocol :flags :padding]
```

## 21.4 Generating Store Instructions

### Store from Register

```clojure
;; Store register value to field
(structs/store-event-field event-reg event-def field-name value-reg)

;; Example: Store r7 to pid field at event pointer r6
(structs/store-event-field :r6 ConnectionEvent :pid :r7)
;; Generates: stxw [r6 + 8], r7
```

### Store Immediate Value

```clojure
;; Store immediate value to field
(structs/store-event-imm event-reg event-def field-name imm-value)

;; Example: Store protocol = 6 (TCP)
(structs/store-event-imm :r6 ConnectionEvent :protocol 6)
;; Generates: stb [r6 + 28], 6
```

### Zero a Field

```clojure
;; Zero a field (store 0)
(structs/zero-event-field :r6 ConnectionEvent :flags)
```

### Batch Store Multiple Fields

```clojure
;; Store multiple fields at once
(structs/store-event-fields :r6 ConnectionEvent
  {:timestamp {:reg :r8}       ; From register
   :pid {:reg :r7}             ; From register
   :protocol {:imm 6}          ; Immediate value
   :flags {:imm 0}})           ; Immediate value
;; Returns vector of store instructions
```

## 21.5 Memory Alignment

### Why Alignment Matters

Unaligned memory access can cause:
- Performance degradation
- BPF verifier rejection
- Architecture-specific issues

### Natural Alignment Rules

| Type Size | Alignment |
|-----------|-----------|
| 1 byte | 1-byte aligned |
| 2 bytes | 2-byte aligned |
| 4 bytes | 4-byte aligned |
| 8 bytes | 8-byte aligned |

### Designing Aligned Structures

**Bad Layout** (unaligned):
```clojure
(structs/defevent BadEvent
  [:flag :u8]          ; offset 0
  [:timestamp :u64]    ; offset 1 - MISALIGNED! Should be 8-byte aligned
  [:pid :u32])         ; offset 9 - MISALIGNED!
```

**Good Layout** (aligned):
```clojure
(structs/defevent GoodEvent
  [:timestamp :u64]    ; offset 0 - 8-byte aligned ✓
  [:pid :u32]          ; offset 8 - 4-byte aligned ✓
  [:flag :u8]          ; offset 12 - 1-byte aligned ✓
  [:padding :u8 3])    ; offset 13 - Explicit padding
;; Total: 16 bytes, all fields aligned
```

### Layout Guidelines

1. **Start with largest types**: Put 8-byte fields first
2. **Group by size**: Keep similar sizes together
3. **Add explicit padding**: Make alignment visible
4. **End with padding**: Round up to power of 2 if needed

## 21.6 Common Event Patterns

### Process Event

```clojure
(structs/defevent ProcessEvent
  [:timestamp :u64]
  [:pid :u32]
  [:tgid :u32]
  [:uid :u32]
  [:gid :u32]
  [:ppid :u32]
  [:exit_code :i32]
  [:comm :char 16]
  [:filename :char 64])
;; 112 bytes, all aligned
```

### Network Event

```clojure
(structs/defevent NetworkEvent
  [:timestamp :u64]
  [:pid :u32]
  [:protocol :u8]
  [:direction :u8]
  [:family :u8]
  [:padding :u8]
  [:saddr_v4 :u32]
  [:daddr_v4 :u32]
  [:saddr_v6 :u8 16]
  [:daddr_v6 :u8 16]
  [:sport :u16]
  [:dport :u16]
  [:bytes :u64])
;; 72 bytes
```

### File System Event

```clojure
(structs/defevent FileEvent
  [:timestamp :u64]
  [:pid :u32]
  [:uid :u32]
  [:inode :u64]
  [:dev :u64]
  [:size :u64]
  [:operation :u32]   ; 0=open, 1=read, 2=write, 3=close
  [:flags :u32]
  [:mode :u32]
  [:ret :i32]
  [:filename :char 128])
;; 192 bytes
```

### Syscall Event

```clojure
(structs/defevent SyscallEvent
  [:timestamp :u64]
  [:duration_ns :u64]
  [:pid :u32]
  [:tgid :u32]
  [:syscall_nr :u32]
  [:ret :i32]
  [:arg0 :u64]
  [:arg1 :u64]
  [:arg2 :u64]
  [:arg3 :u64]
  [:arg4 :u64]
  [:arg5 :u64]
  [:comm :char 16])
;; 104 bytes
```

## 21.7 Parsing Events in Userspace

### Helper Functions

```clojure
(defn extract-u64 [data offset]
  (utils/bytes->long (byte-array (take 8 (drop offset data)))))

(defn extract-u32 [data offset]
  (utils/bytes->int (byte-array (take 4 (drop offset data)))))

(defn extract-u16 [data offset]
  (utils/bytes->short (byte-array (take 2 (drop offset data)))))

(defn extract-string [data offset max-len]
  (let [bytes (take max-len (drop offset data))
        end (or (first (keep-indexed
                        (fn [i b] (when (zero? b) i))
                        bytes))
                max-len)]
    (String. (byte-array (take end bytes)) "UTF-8")))
```

### Generic Parser Generator

```clojure
(defn make-event-parser [event-def]
  (fn [data]
    (when (>= (count data) (structs/event-size event-def))
      (into {}
        (for [field (structs/event-fields event-def)]
          (let [offset (structs/event-field-offset event-def field)
                type (structs/event-field-type event-def field)
                size (structs/event-field-size event-def field)]
            [field
             (case type
               :u64 (extract-u64 data offset)
               :i64 (extract-u64 data offset)
               :u32 (extract-u32 data offset)
               :i32 (extract-u32 data offset)
               :u16 (extract-u16 data offset)
               :u8 (aget data offset)
               :char (extract-string data offset size)
               :ptr (extract-u64 data offset)
               nil)]))))))

;; Usage:
(def parse-connection-event (make-event-parser ConnectionEvent))
(parse-connection-event raw-bytes)
```

## 21.8 Integration with Ring Buffers

### Complete Pattern

```clojure
(defn build-tracer-program [ringbuf-fd]
  (let [event-size (structs/event-size MyEvent)]
    (dsl/assemble
      (vec (concat
        ;; Reserve ring buffer space
        (dsl/ringbuf-reserve :r6 ringbuf-fd event-size)

        ;; Check for NULL
        [(dsl/jmp-imm :jeq :r6 0 :exit)]

        ;; Fill structure using store helpers
        (dsl/helper-ktime-get-ns)
        [(structs/store-event-field :r6 MyEvent :timestamp :r0)]

        (dsl/helper-get-current-pid-tgid)
        [(dsl/and-imm :r0 0xffffffff)
         (structs/store-event-field :r6 MyEvent :pid :r0)]

        ;; Submit event
        (dsl/ringbuf-submit :r6)

        ;; Exit
        [[:label :exit]
         (dsl/mov :r0 0)
         (dsl/exit-insn)])))))
```

## Labs

### Lab 21.1: Define and Query Structures

Define event structures for various use cases and query their properties.

### Lab 21.2: Building a Structured Tracer

Build a complete tracer using event structures and ring buffers.

## Navigation

- **Next**: [Lab 21.1 - Event Structure Definition](labs/lab-21-1-event-structures.md)
- **Previous**: [Chapter 20](../chapter-20/README.md)
- **Up**: [Part III - Advanced Topics](../)
- **Home**: [Tutorial Home](../../README.md)

## Additional Resources

- [BPF Ring Buffer](https://nakryiko.com/posts/bpf-ringbuf/)
- [Memory Alignment in C](https://en.wikipedia.org/wiki/Data_structure_alignment)
- [clj-ebpf API Documentation](../../api/clj-ebpf.dsl.structs.html)
