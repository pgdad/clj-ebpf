# Lab 21.1: Event Structure Definition

**Duration**: 30 minutes | **Difficulty**: Beginner-Intermediate

## Objectives

In this lab, you will:
1. Define various event structures using `defevent`
2. Query structure metadata (size, offsets, types)
3. Generate store instructions
4. Design properly aligned structures

## Part 1: Basic Structure Definition

### Task 1.1: Simple Process Event

Define a basic process event structure:

```clojure
(ns lab-21-1-event-structures
  (:require [clj-ebpf.dsl.structs :as structs]))

;; TODO: Define SimpleProcessEvent with:
;; - timestamp (u64)
;; - pid (u32)
;; - uid (u32)

;; Verify:
;; (structs/event-size SimpleProcessEvent) => 16
;; (structs/event-field-offset SimpleProcessEvent :pid) => 8
```

### Task 1.2: Network Connection Event

Define a more complex network event:

```clojure
;; TODO: Define NetworkConnEvent with:
;; - timestamp (u64)
;; - pid (u32)
;; - tgid (u32)
;; - saddr (u32) - source IPv4 address
;; - daddr (u32) - destination IPv4 address
;; - sport (u16) - source port
;; - dport (u16) - destination port
;; - protocol (u8)
;; - flags (u8)
;; - padding (u8, 2 bytes)
;; - comm (char, 16 bytes)

;; Verify:
;; (structs/event-size NetworkConnEvent) => 48
```

### Task 1.3: File System Event

Define a file operation event with a large filename field:

```clojure
;; TODO: Define FileOpEvent with:
;; - timestamp (u64)
;; - pid (u32)
;; - operation (u32) - 0=open, 1=read, 2=write, 3=close
;; - inode (u64)
;; - size (u64)
;; - ret_code (i32)
;; - flags (u32)
;; - filename (char, 64 bytes)

;; Verify:
;; (structs/event-size FileOpEvent) => 104
```

## Part 2: Structure Queries

### Task 2.1: Query All Fields

Write a function that prints all field information:

```clojure
(defn print-event-layout [event-def]
  (println "Event:" (:name event-def))
  (println "Total size:" (structs/event-size event-def) "bytes")
  (println "Fields:")
  ;; TODO: Loop through fields and print:
  ;; - Field name
  ;; - Offset
  ;; - Size
  ;; - Type
  )

;; Usage:
(print-event-layout NetworkConnEvent)
```

### Task 2.2: Alignment Checker

Write a function to check if fields are properly aligned:

```clojure
(defn check-alignment [event-def]
  ;; TODO: For each field:
  ;; - Determine natural alignment (min of size and 8)
  ;; - Check if offset is divisible by alignment
  ;; - Report any misaligned fields
  )

;; Example output:
;; "Field :timestamp at offset 0 - OK (8-byte aligned)"
;; "Field :sport at offset 24 - OK (2-byte aligned)"
```

## Part 3: Store Instructions

### Task 3.1: Generate Individual Stores

Generate store instructions for filling an event:

```clojure
;; TODO: Generate store instructions for NetworkConnEvent

;; Store timestamp from r8
(def store-timestamp
  (structs/store-event-field :r6 NetworkConnEvent :timestamp :r8))

;; Store protocol = 6 (TCP) as immediate
(def store-protocol
  (structs/store-event-imm :r6 NetworkConnEvent :protocol 6))

;; Verify both produce Instruction records
```

### Task 3.2: Batch Store

Use batch store for multiple fields:

```clojure
;; TODO: Store these fields in one call:
;; - timestamp from r8
;; - pid from r7
;; - protocol as immediate 6
;; - flags as immediate 0

(def batch-stores
  (structs/store-event-fields :r6 NetworkConnEvent
    {;; Fill in the map
     }))

;; Should return a vector of 4 instructions
```

## Part 4: Design Challenge

### Task 4.1: Design an Optimized Event

Design an event structure for a security audit system that tracks:
- When (timestamp)
- Who (uid, gid, effective uid/gid)
- What (syscall number, arguments)
- Where (process info)
- Result (return code)

Requirements:
1. All fields must be naturally aligned
2. Total size should be a power of 2 or close to it
3. Most frequently accessed fields should be first
4. Include appropriate padding

```clojure
;; TODO: Define SecurityAuditEvent
;; Target size: 128 bytes or less
```

## Verification Checklist

- [ ] SimpleProcessEvent is 16 bytes
- [ ] NetworkConnEvent is 48 bytes
- [ ] FileOpEvent is 104 bytes
- [ ] All fields are properly aligned
- [ ] Store instructions generate correct offsets
- [ ] Batch store produces correct number of instructions

## Solution

See `solutions/lab_21_1_event_structures.clj` for the complete implementation.

## Navigation

- **Next**: [Lab 21.2 - Structured Tracer](lab-21-2-structured-tracer.md)
- **Up**: [Chapter 21 - Event Structures](../README.md)
