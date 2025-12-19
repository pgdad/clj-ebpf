# Lab 3.4: Label-Based Assembly

**Duration**: 45-60 minutes | **Difficulty**: Intermediate

## Objective

Learn to use the `clj-ebpf.asm` namespace to build BPF programs with symbolic
labels, eliminating error-prone manual jump offset calculations.

## Prerequisites

- Completed Chapter 3 sections on Jump Operations
- Understanding of BPF control flow
- Familiarity with XDP and TC program types

## Why Labels Matter

### The Problem

Manual jump offset calculation is:
1. **Error-prone**: Easy to miscalculate offsets
2. **Fragile**: Adding/removing code breaks all offsets
3. **Unreadable**: Numbers don't convey intent
4. **Unmaintainable**: Changes require recalculating every jump

```clojure
;; This is painful and error-prone:
[(dsl/jmp-imm :jeq :r0 0 14)  ; What does 14 mean? Where does it go?
 (dsl/mov :r0 1)
 (dsl/jmp 7)                   ; And 7?
 ;; ... 10 more instructions ...
 (dsl/exit-insn)]
```

### The Solution

Symbolic labels make code readable and maintainable:

```clojure
;; This is clear and maintainable:
[(asm/jmp-imm :jeq :r0 0 :is-zero)  ; Jump to :is-zero label
 (dsl/mov :r0 1)
 (asm/jmp :done)                     ; Jump to :done label
 ;; ... any number of instructions ...
 (asm/label :is-zero)                ; Target of first jump
 (dsl/mov :r0 0)
 (asm/label :done)                   ; Target of second jump
 (dsl/exit-insn)]
```

## Part 1: Basic Label Usage

### Step 1: Setup

Create a new file `label_demo.clj`:

```clojure
(ns label-demo
  (:require [clj-ebpf.asm :as asm]
            [clj-ebpf.dsl :as dsl]))
```

### Step 2: Create a Simple Branching Program

Build a program that returns different values based on input:

```clojure
(defn build-branching-program
  "Return 1 if r1 > 10, 0 if r1 == 0, -1 otherwise."
  []
  (asm/assemble-with-labels
    [;; Check if r1 > 10
     (asm/jmp-imm :jgt :r1 10 :greater-than-ten)

     ;; Check if r1 == 0
     (asm/jmp-imm :jeq :r1 0 :is-zero)

     ;; Default case: return -1
     (dsl/mov :r0 -1)
     (asm/jmp :exit)

     ;; r1 > 10: return 1
     (asm/label :greater-than-ten)
     (dsl/mov :r0 1)
     (asm/jmp :exit)

     ;; r1 == 0: return 0
     (asm/label :is-zero)
     (dsl/mov :r0 0)

     ;; Common exit point
     (asm/label :exit)
     (dsl/exit-insn)]))
```

### Step 3: Examine the Bytecode

```clojure
(let [bytecode (build-branching-program)]
  (println "Bytecode size:" (count bytecode) "bytes")
  (println "Instructions:" (/ (count bytecode) 8)))
;; Output:
;; Bytecode size: 72 bytes
;; Instructions: 9
```

**Key insight**: Labels don't generate bytecode - they're only used for offset calculation.

## Part 2: Loop Patterns with Backward Jumps

### Step 4: Build a Counting Loop

```clojure
(defn build-counter-loop
  "Count from 0 to n (in r1), return count in r0."
  []
  (asm/assemble-with-labels
    [;; Initialize counter
     (dsl/mov :r0 0)

     ;; Loop start
     (asm/label :loop)

     ;; Check termination: if r1 == 0, exit
     (asm/jmp-imm :jeq :r1 0 :done)

     ;; Decrement r1, increment r0
     (dsl/sub :r1 1)
     (dsl/add :r0 1)

     ;; Loop back (backward jump!)
     (asm/jmp :loop)

     ;; Exit
     (asm/label :done)
     (dsl/exit-insn)]))
```

**Note**: The `:loop` label enables a backward jump. The label resolver
automatically calculates the negative offset.

## Part 3: XDP Packet Filter with Labels

### Step 5: Build a Complete XDP Program

```clojure
(ns xdp-filter
  (:require [clj-ebpf.asm :as asm]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]
            [clj-ebpf.programs :as prog]
            [clj-ebpf.xdp :as xdp]))

(defn build-ipv4-tcp-filter
  "XDP program that parses IPv4/TCP packets.
   Demonstrates multiple labels for complex control flow."
  []
  (asm/assemble-with-labels
    [;; Prologue: Save context, load data pointers
     (dsl/mov-reg :r6 :r1)           ; Save xdp_md context
     (dsl/ldx :w :r7 :r6 0)          ; r7 = data
     (dsl/ldx :w :r8 :r6 4)          ; r8 = data_end

     ;; Check Ethernet header bounds (14 bytes)
     (asm/check-bounds :r7 :r8 14 :pass :r9)

     ;; Load EtherType
     (dsl/ldx :h :r9 :r7 12)

     ;; Check for IPv4 (0x0008 = 0x0800 in network byte order)
     (asm/jmp-imm :jne :r9 0x0008 :not-ipv4)

     ;; IPv4 path: check IP+TCP bounds (54 bytes total)
     (asm/check-bounds :r7 :r8 54 :pass :r9)

     ;; Load IP header pointer
     (dsl/mov-reg :r2 :r7)
     (dsl/add :r2 14)

     ;; Check protocol (offset 9 in IP header)
     (dsl/ldx :b :r3 :r2 9)
     (asm/jmp-imm :jne :r3 6 :not-tcp)  ; 6 = TCP

     ;; TCP packet found!
     ;; Load TCP header pointer
     (dsl/mov-reg :r3 :r2)
     (dsl/add :r3 20)

     ;; Load source and dest ports (for demonstration)
     (dsl/ldx :h :r4 :r3 0)          ; Source port
     (dsl/ldx :h :r5 :r3 2)          ; Dest port

     ;; Pass TCP packets
     (dsl/mov :r0 net/XDP-PASS)
     (asm/jmp :exit)

     ;; Not TCP - pass anyway
     (asm/label :not-tcp)
     (dsl/mov :r0 net/XDP-PASS)
     (asm/jmp :exit)

     ;; Not IPv4 - pass
     (asm/label :not-ipv4)
     (dsl/mov :r0 net/XDP-PASS)
     (asm/jmp :exit)

     ;; Bounds check failed - pass (safe default)
     (asm/label :pass)
     (dsl/mov :r0 net/XDP-PASS)

     ;; Common exit
     (asm/label :exit)
     (dsl/exit-insn)]))
```

### Step 6: Load and Test the Program

```clojure
(defn test-xdp-filter []
  (let [bytecode (build-ipv4-tcp-filter)]
    (println "Program size:" (/ (count bytecode) 8) "instructions")

    ;; Load the program
    (let [prog-record (prog/load-program
                        {:insns bytecode
                         :prog-type :xdp
                         :prog-name "label_demo"
                         :license "GPL"})]
      (println "Loaded successfully, fd:" (:fd prog-record))

      ;; Attach to loopback
      (xdp/attach-xdp "lo" (:fd prog-record) :skb-mode)
      (println "Attached to lo")

      ;; Run briefly
      (Thread/sleep 2000)

      ;; Cleanup
      (xdp/detach-xdp "lo")
      (prog/close-program prog-record)
      (println "Cleaned up"))))

;; Run with: sudo clojure -M -m xdp-filter
```

## Part 4: TC Classifier with Protocol Dispatch

### Step 7: Build a Multi-Protocol Handler

```clojure
(ns tc-classifier
  (:require [clj-ebpf.asm :as asm]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]
            [clj-ebpf.programs :as prog]
            [clj-ebpf.tc :as tc]))

(defn build-protocol-classifier
  "TC classifier that dispatches based on protocol.
   Shows how labels enable clean switch/case-like logic."
  []
  (asm/assemble-with-labels
    [;; Load SKB data pointers
     (dsl/mov-reg :r6 :r1)
     (dsl/ldx :w :r7 :r6 76)         ; data
     (dsl/ldx :w :r8 :r6 80)         ; data_end

     ;; Bounds check for Ethernet header
     (asm/check-bounds :r7 :r8 14 :ok :r9)

     ;; Load EtherType
     (dsl/ldx :h :r9 :r7 12)

     ;; Protocol dispatch (switch/case pattern)
     (asm/jmp-imm :jeq :r9 0x0008 :handle-ipv4)   ; IPv4
     (asm/jmp-imm :jeq :r9 0xDD86 :handle-ipv6)   ; IPv6
     (asm/jmp-imm :jeq :r9 0x0608 :handle-arp)    ; ARP
     (asm/jmp :handle-other)

     ;; IPv4 handler
     (asm/label :handle-ipv4)
     ;; Could add IP-level parsing here
     (asm/jmp :ok)

     ;; IPv6 handler
     (asm/label :handle-ipv6)
     ;; Could add IPv6-specific logic
     (asm/jmp :ok)

     ;; ARP handler
     (asm/label :handle-arp)
     ;; Could add ARP-specific logic
     (asm/jmp :ok)

     ;; Unknown protocol
     (asm/label :handle-other)
     ;; Pass unknown protocols

     ;; Default action: TC_ACT_OK (pass)
     (asm/label :ok)
     (dsl/mov :r0 net/TC-ACT-OK)
     (dsl/exit-insn)]))
```

## Part 5: Error Handling

### Step 8: Understand Label Errors

```clojure
;; Undefined label error
(try
  (asm/resolve-labels
    [(asm/jmp :undefined-label)
     (dsl/exit-insn)])
  (catch Exception e
    (println "Error:" (ex-message e))))
;; Output: Error: Undefined label: :undefined-label

;; Duplicate label error
(try
  (asm/resolve-labels
    [(asm/label :duplicate)
     (dsl/mov :r0 0)
     (asm/label :duplicate)
     (dsl/exit-insn)])
  (catch Exception e
    (println "Error:" (ex-message e))))
;; Output: Error: Duplicate label: :duplicate
```

## Exercises

### Exercise 1: State Machine

Build a BPF program that implements a simple state machine:
- State 0: If input > 5, go to state 1; otherwise stay
- State 1: If input == 0, go to state 2; otherwise stay
- State 2: Exit with success

Use labels for each state.

### Exercise 2: Binary Search

Implement a binary search decision tree using labels:
- Check if value < 50
  - If yes, check if < 25
  - If no, check if < 75
- Return the appropriate bucket (0-3)

### Exercise 3: Packet Type Counter

Build an XDP program that:
1. Parses packets to identify protocol (TCP, UDP, ICMP, other)
2. Uses labels for each protocol handler
3. Passes all packets (just identifies them)

## Key Takeaways

1. **Labels eliminate offset errors**: No more manual counting
2. **Labels are readable**: `:handle-tcp` vs `14`
3. **Labels are maintainable**: Add code without breaking jumps
4. **Labels work both ways**: Forward and backward jumps
5. **Labels compose**: Helper functions can use labels too

## Navigation

- **Previous**: [Lab 3.3 - Protocol Parser](lab-3-3-protocol-parser.md)
- **Next**: [Chapter 4 - Helper Functions](../../chapter-04/README.md)
- **Up**: [Chapter 3 - BPF Instruction Set](../README.md)

## Reference

- [clj-ebpf.asm namespace](../../../../src/clj_ebpf/asm.clj)
- [Label examples](../../../../examples/asm_labels.clj)
- [XDP DSL](../../../../src/clj_ebpf/dsl/xdp.clj)
- [TC DSL](../../../../src/clj_ebpf/dsl/tc.clj)
