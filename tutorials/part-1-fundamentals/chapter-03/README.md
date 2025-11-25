# Chapter 3: BPF Instruction Set

**Duration**: 3-4 hours | **Difficulty**: Intermediate

## Learning Objectives

By the end of this chapter, you will:
- Understand BPF architecture (registers, stack, calling conventions)
- Master BPF instruction classes (ALU, load/store, jumps, calls)
- Write complex BPF programs using the instruction set
- Understand verifier requirements and constraints
- Build practical packet filters and parsers

## Prerequisites

- Completed [Chapter 2: BPF Maps](../chapter-02/README.md)
- Understanding of assembly language concepts
- Basic knowledge of computer architecture
- Familiarity with registers and memory

## 3.1 BPF Architecture

### Registers

BPF has 11 64-bit registers (r0-r10):

```
┌────────┬──────────────────────────────────┐
│Register│ Purpose                          │
├────────┼──────────────────────────────────┤
│  r0    │ Return value (from functions)    │
│        │ Also used for temporary values   │
├────────┼──────────────────────────────────┤
│  r1-r5 │ Function arguments               │
│        │ Caller-saved (clobbered by calls)│
├────────┼──────────────────────────────────┤
│  r6-r9 │ Callee-saved registers           │
│        │ Preserved across function calls  │
├────────┼──────────────────────────────────┤
│  r10   │ Read-only frame pointer          │
│        │ Points to 512-byte stack         │
└────────┴──────────────────────────────────┘
```

### Calling Convention

```
Function Call:
┌────────────────┐
│ Caller         │
│  r1 = arg1     │  Setup arguments
│  r2 = arg2     │
│  r3 = arg3     │
│  r4 = arg4     │
│  r5 = arg5     │
│  call func     │  Call function
│  r0 = result   │  Get return value
│  (r1-r5 trash) │  r1-r5 may be modified
│  (r6-r9 safe)  │  r6-r9 preserved
└────────────────┘
```

### Stack

Each BPF program has a 512-byte stack:

```
Stack Layout:
r10 → ┌──────────────┐ ← Top (address 0)
      │              │
      │   512 bytes  │   Grows downward
      │   available  │   Addresses: -1 to -512
      │              │
      └──────────────┘ ← Bottom (address -512)

Usage:
  Stack[- 8] → First  64-bit value
  Stack[-16] → Second 64-bit value
  Stack[-24] → Third  64-bit value
  ...
```

### Instruction Format

BPF instructions are 64 bits (8 bytes):

```
Standard Instruction (64 bits):
┌────────┬────┬────┬────────┬────────────────────┐
│ opcode │dst │src │ offset │     immediate      │
│ 8 bits │4bit│4bit│16 bits │     32 bits        │
└────────┴────┴────┴────────┴────────────────────┘

Wide Instruction (128 bits, for 64-bit immediates):
┌────────┬────┬────┬────────┬────────────────────┐
│ opcode │dst │src │   0    │     imm (low)      │
│        │    │    │        │     32 bits        │
├────────┴────┴────┴────────┼────────────────────┤
│         0x00               │     imm (high)     │
│                            │     32 bits        │
└────────────────────────────┴────────────────────┘
```

## 3.2 Instruction Classes

### ALU Operations (Arithmetic and Logic)

#### 64-bit ALU (BPF_ALU64)

```clojure
;; Arithmetic
(bpf/add :r0 :r1)      ; r0 += r1
(bpf/add :r0 42)       ; r0 += 42
(bpf/sub :r0 :r1)      ; r0 -= r1
(bpf/mul :r0 :r1)      ; r0 *= r1
(bpf/div :r0 :r1)      ; r0 /= r1 (unsigned)
(bpf/mod :r0 :r1)      ; r0 %= r1 (modulo)

;; Bitwise
(bpf/or :r0 :r1)       ; r0 |= r1
(bpf/and :r0 :r1)      ; r0 &= r1
(bpf/xor :r0 :r1)      ; r0 ^= r1
(bpf/lsh :r0 8)        ; r0 <<= 8 (left shift)
(bpf/rsh :r0 8)        ; r0 >>= 8 (logical right shift)
(bpf/arsh :r0 8)       ; r0 >>= 8 (arithmetic right shift)

;; Unary
(bpf/neg :r0)          ; r0 = -r0
(bpf/mov :r0 :r1)      ; r0 = r1
(bpf/mov :r0 42)       ; r0 = 42
```

#### 32-bit ALU (BPF_ALU)

```clojure
;; Same operations, but 32-bit
;; Upper 32 bits are zeroed
(bpf/add32 :r0 :r1)    ; r0 = (u32)(r0 + r1)
(bpf/sub32 :r0 :r1)    ; r0 = (u32)(r0 - r1)
;; ... etc for all ALU ops
```

### Load/Store Operations

#### Direct Loads/Stores

```clojure
;; Store immediate to memory
(bpf/store-mem :dw :r10 -8 42)
;; Sizes: :b (byte), :h (halfword), :w (word), :dw (doubleword)
;; [r10 - 8] = 42 (8 bytes)

;; Store register to memory
(bpf/store-mem :dw :r10 -8 :r1)
;; [r10 - 8] = r1 (8 bytes)

;; Load from memory
(bpf/load-mem :dw :r0 :r10 -8)
;; r0 = [r10 - 8] (8 bytes)
```

#### Atomic Operations (kernel 5.12+)

The `clj-ebpf.dsl.atomic` module provides comprehensive atomic memory operations:

```clojure
(require '[clj-ebpf.dsl.atomic :as atomic])

;; Basic atomic operations
(atomic/atomic-add :dw :r10 :r1 -8)    ; [r10 - 8] += r1
(atomic/atomic-or  :dw :r10 :r1 -8)    ; [r10 - 8] |= r1
(atomic/atomic-and :dw :r10 :r1 -8)    ; [r10 - 8] &= r1
(atomic/atomic-xor :dw :r10 :r1 -8)    ; [r10 - 8] ^= r1

;; Atomic exchange
(atomic/atomic-xchg :dw :r10 :r1 -8)
;; Atomically: tmp = [r10 - 8]; [r10 - 8] = r1; r1 = tmp

;; Compare and exchange
(atomic/atomic-cmpxchg :dw :r10 :r1 -8)
;; Atomically: if ([r10 - 8] == r0) [r10 - 8] = r1

;; Fetch variants (return old value in src register)
(atomic/atomic-fetch-add :dw :r10 :r1 -8)  ; r1 = old value; [r10-8] += r1
(atomic/atomic-fetch-or  :dw :r10 :r1 -8)
(atomic/atomic-fetch-and :dw :r10 :r1 -8)
(atomic/atomic-fetch-xor :dw :r10 :r1 -8)
```

High-level atomic patterns:

```clojure
;; Increment/decrement
(atomic/atomic-inc :dw :r10 :r1 -8)    ; [r10 - 8]++
(atomic/atomic-dec :dw :r10 :r1 -8)    ; [r10 - 8]--

;; Bit operations
(atomic/atomic-set-bit :dw :r10 :r1 3 -8)    ; Set bit 3
(atomic/atomic-clear-bit :dw :r10 :r1 3 -8)  ; Clear bit 3
(atomic/atomic-toggle-bit :dw :r10 :r1 3 -8) ; Toggle bit 3

;; Check kernel version support
(atomic/atomic-available? :fetch-add "5.12")  ; => true
```

### Jump Operations

#### Conditional Jumps

```clojure
;; Jump if equal
(bpf/jmp-imm :jeq :r0 42 :label)   ; if (r0 == 42) goto label
(bpf/jmp-reg :jeq :r0 :r1 :label)  ; if (r0 == r1) goto label

;; Jump conditions:
;; :jeq  - equal
;; :jne  - not equal
;; :jgt  - greater than (unsigned)
;; :jge  - greater or equal (unsigned)
;; :jlt  - less than (unsigned)
;; :jle  - less or equal (unsigned)
;; :jsgt - greater than (signed)
;; :jsge - greater or equal (signed)
;; :jslt - less than (signed)
;; :jsle - less or equal (signed)
;; :jset - test bits set

;; Unconditional jump
(bpf/jmp :label)                   ; goto label
```

#### Jump Offsets

```clojure
;; Jumps use instruction offsets
;; Offset 0 = next instruction
;; Offset 1 = skip 1 instruction
;; Offset -1 = back 1 instruction

;; Example: skip 2 instructions if r0 == 0
[(bpf/jmp-imm :jeq :r0 0 2)]
[(bpf/mov :r0 1)]           ; Skipped if r0 == 0
[(bpf/add :r0 10)]          ; Skipped if r0 == 0
[(bpf/exit-insn)]           ; Execution continues here
```

### Function Calls

#### Helper Function Calls

```clojure
;; Call BPF helper by ID
(bpf/call 1)  ; bpf_map_lookup_elem

;; Using helper wrappers (from Chapter 1)
(bpf/helper-map-lookup-elem :r1 :r2)
;; Automatically sets up r1, r2 and calls helper

;; After call:
;; - r0 contains return value
;; - r1-r5 may be modified
;; - r6-r9 preserved
```

#### Tail Calls

```clojure
;; Jump to another BPF program
(bpf/tail-call :r1 :r2 :r3)
;; r1 = context
;; r2 = prog_array map
;; r3 = index

;; Note: tail call does NOT return
;; Limited to 33 tail calls per execution
```

### Exit

```clojure
;; Return from BPF program
(bpf/exit-insn)
;; Return value in r0
```

## 3.3 Verifier Constraints

### Safety Requirements

The BPF verifier ensures programs are safe by checking:

1. **Bounded Execution**
   - No infinite loops
   - All paths must reach exit
   - Maximum complexity limit (1 million instructions)

2. **Memory Safety**
   - All memory accesses validated
   - Pointer arithmetic checked
   - No NULL pointer dereferences
   - Stack bounds enforced

3. **Type Safety**
   - Register types tracked
   - Invalid operations rejected
   - Pointer types distinguished

4. **Control Flow**
   - All paths analyzed
   - Unreachable code detected
   - Forward jumps only (mostly)

### Common Verifier Errors

#### Unbounded Loop

```clojure
;; WRONG - verifier rejects
(loop []
  (bpf/add :r0 1)
  (recur))  ; Infinite loop

;; RIGHT - bounded loop
(dotimes [i 10]
  (bpf/add :r0 1))  ; Max 10 iterations
```

#### Invalid Memory Access

```clojure
;; WRONG - no bounds check
[(bpf/load-mem :dw :r0 :r1 0)]  ; r1 could be invalid

;; RIGHT - bounds checked
[(bpf/jmp-imm :jeq :r1 0 :error)]  ; Check not NULL
[(bpf/load-mem :dw :r0 :r1 0)]     ; Safe to load
```

#### Register State

```clojure
;; WRONG - undefined register
[(bpf/add :r0 :r1)]  ; r1 not initialized

;; RIGHT - initialize first
[(bpf/mov :r1 0)]
[(bpf/add :r0 :r1)]
```

## 3.4 Common Patterns

### Bounds Checking

```clojure
;; Check pointer bounds before access
(defn safe-load [ptr-reg offset size data-end-reg]
  (vec (concat
    ;; Calculate access end: ptr + offset + size
    [(bpf/mov-reg :r9 ptr-reg)]
    [(bpf/add :r9 (+ offset size))]
    ;; Check: if (ptr + offset + size > data_end) goto error
    [(bpf/jmp-reg :jgt :r9 data-end-reg :error)]
    ;; Safe to access
    [(bpf/load-mem size :r0 ptr-reg offset)]
    )))
```

### Extract Bit Fields

```clojure
;; Extract bits [high:low] from register
(defn extract-bits [reg high low]
  (let [shift (- 63 high)
        mask (bit-shift-left (dec (bit-shift-left 1 (- high low -1))) low)]
    (vec (concat
      [(bpf/lsh reg shift)]        ; Shift left to position
      [(bpf/rsh reg (+ shift low))] ; Shift right to extract
      ))))
```

### Endianness Conversion

```clojure
;; Network byte order (big-endian) to host (little-endian)
(bpf/be16 :r0)  ; Convert 16-bit big-endian to host
(bpf/be32 :r0)  ; Convert 32-bit big-endian to host
(bpf/be64 :r0)  ; Convert 64-bit big-endian to host

;; Host to network
(bpf/le16 :r0)  ; Convert 16-bit host to little-endian
(bpf/le32 :r0)  ; Convert 32-bit host to little-endian
(bpf/le64 :r0)  ; Convert 64-bit host to little-endian
```

### Switch Statement

```clojure
(defn switch-case [value-reg cases default]
  "Generate switch/case structure"
  (loop [remaining cases
         offset 0
         insns []]
    (if (empty? remaining)
      (vec (concat insns default))
      (let [[case-val case-code] (first remaining)
            case-len (count case-code)
            rest-len (+ offset case-len 1)]  ; +1 for jump
        (recur (rest remaining)
               rest-len
               (vec (concat insns
                           [(bpf/jmp-imm :jne value-reg case-val (inc case-len))]
                           case-code
                           [(bpf/jmp (- rest-len offset))])))))))
```

## 3.5 clj-ebpf DSL for Instructions

### Basic Instructions

```clojure
(require '[clj-ebpf.core :as bpf])

;; ALU operations
(bpf/mov :r0 42)
(bpf/add :r0 :r1)
(bpf/sub :r0 10)

;; Memory operations
(bpf/store-mem :dw :r10 -8 :r0)
(bpf/load-mem :dw :r0 :r10 -8)

;; Jumps
(bpf/jmp-imm :jeq :r0 0 5)  ; Offset 5
(bpf/jmp :label)             ; Named label

;; Calls
(bpf/call 14)  ; bpf_get_current_pid_tgid

;; Exit
(bpf/exit-insn)
```

### Labels

```clojure
(defn program-with-labels []
  (bpf/assemble-with-labels
    {:start
     [(bpf/mov :r0 0)
      (bpf/jmp :check)]

     :check
     [(bpf/jmp-imm :jeq :r0 0 :zero)
      (bpf/jmp :nonzero)]

     :zero
     [(bpf/mov :r0 1)
      (bpf/exit-insn)]

     :nonzero
     [(bpf/mov :r0 2)
      (bpf/exit-insn)]}
    :start))  ; Entry point
```

### Helper Wrappers

```clojure
;; High-level helper wrappers (from Chapter 1)
(bpf/helper-get-current-pid-tgid)
(bpf/helper-map-lookup-elem :r1 :r2)
(bpf/helper-probe-read-kernel :r1 :r2 :r3)

;; Expand to proper register setup + call
```

## Labs

This chapter includes three hands-on labs:

### Lab 3.1: Packet Filter
Build a network packet filter using BPF instructions

### Lab 3.2: System Call Argument Capture
Capture and parse system call arguments

### Lab 3.3: Custom Protocol Parser
Parse a custom network protocol

## Navigation

- **Next**: [Lab 3.1 - Packet Filter](labs/lab-3-1-packet-filter.md)
- **Previous**: [Chapter 2 - BPF Maps](../chapter-02/README.md)
- **Up**: [Part I - Fundamentals](../../part-1-fundamentals/)
- **Home**: [Tutorial Home](../../README.md)

## Additional Resources

- [eBPF Instruction Set](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html)
- [BPF Design Q&A](https://www.kernel.org/doc/Documentation/bpf/bpf_design_QA.txt)
- [eBPF Verifier](https://www.kernel.org/doc/html/latest/bpf/verifier.html)
- [Linux BPF Documentation](https://docs.kernel.org/bpf/index.html)
