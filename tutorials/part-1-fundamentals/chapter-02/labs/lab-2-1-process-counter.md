# Lab 2.1: Process Counter

**Objective**: Track process execution counts using BPF hash maps

**Duration**: 45 minutes

## Overview

In this lab, you'll create a system that tracks how many times each process executes. You'll use a BPF hash map to store execution counts, a BPF program attached to a system call tracepoint to increment counters, and a userspace program to display the results.

This lab demonstrates:
- Creating hash maps
- Accessing maps from BPF programs
- Reading map data from userspace
- Complete kernel-userspace integration

## What You'll Learn

- How to create BPF hash maps
- How to update map values from BPF programs
- How to read and display map data from userspace
- How to attach BPF programs to tracepoints
- Proper error handling and resource cleanup

## Theory

### Hash Maps for Process Tracking

A hash map is ideal for process tracking because:
1. **Dynamic keys**: PIDs are not sequential or predictable
2. **O(1) lookup**: Fast access even with many processes
3. **Sparse data**: Most PIDs won't be active at once

### System Call Tracepoints

We'll use the `sched_process_exec` tracepoint which fires when a process calls `execve()`. This captures new process execution without syscall overhead.

### Map Structure

```
Key: PID (u32)    Value: Count (u64)
┌─────────────────────────────────┐
│ 1000  -->  42                   │
│ 1001  -->  15                   │
│ 2345  -->  7                    │
│ ...                             │
└─────────────────────────────────┘
```

## Implementation

### Step 1: Complete Program

Create `lab-2-1.clj`:

```clojure
(ns lab-2-1-process-counter
  "Lab 2.1: Process Counter using BPF hash maps"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Part 1: Map Creation
;; ============================================================================

(defn create-process-map []
  "Create a hash map to track process execution counts"
  (bpf/create-map :hash
    {:key-size 4          ; u32 for PID
     :value-size 8        ; u64 for counter
     :max-entries 10000}  ; Support up to 10,000 processes
    ))

;; ============================================================================
;; Part 2: BPF Program
;; ============================================================================

(defn create-counter-program [map-fd]
  "Create BPF program that increments process counter"
  (bpf/assemble
    (vec (concat
      ;; Get current PID/TGID
      (bpf/helper-get-current-pid-tgid)

      ;; Extract TGID (PID) from upper 32 bits
      ;; Result is in r0 as: [TGID:32][PID:32]
      ;; We want TGID for process tracking
      [(bpf/rsh :r0 32)]  ; Shift right to get TGID

      ;; Store PID on stack (key for map lookup)
      [(bpf/store-mem :dw :r10 -8 :r0)]  ; stack[-8] = PID

      ;; Lookup map[PID]
      ;; r1 = map pointer (pseudo map FD)
      [(bpf/ld-map-fd :r1 map-fd)]
      ;; r2 = key pointer (stack address)
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      ;; Call bpf_map_lookup_elem
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Check if key exists (r0 == NULL?)
      [(bpf/mov-reg :r7 :r0)]  ; Save pointer in r7
      [(bpf/jmp-imm :jne :r7 0 :update-existing)]

      ;; Key doesn't exist - create new entry with count = 1
      ;; Store initial value on stack
      [(bpf/store-mem :dw :r10 -16 1)]

      ;; Call bpf_map_update_elem
      [(bpf/ld-map-fd :r1 map-fd)]    ; r1 = map
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]              ; r2 = key (PID)
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]             ; r3 = value (1)
      [(bpf/mov :r4 0)]               ; r4 = flags (BPF_ANY)
      (bpf/helper-map-update-elem :r1 :r2 :r3)
      [(bpf/jmp :exit)]

      ;; :update-existing - increment counter
      ;; r7 contains pointer to value
      [(bpf/load-mem :dw :r6 :r7 0)]  ; Load current value
      [(bpf/add :r6 1)]               ; Increment
      [(bpf/store-mem :dw :r7 0 :r6)] ; Store back

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 3: Userspace Data Access
;; ============================================================================

(defn read-u32-le [^ByteBuffer buf]
  "Read u32 from ByteBuffer (little-endian)"
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (bit-and (.getInt buf 0) 0xFFFFFFFF))

(defn read-u64-le [^ByteBuffer buf]
  "Read u64 from ByteBuffer (little-endian)"
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf 0))

(defn get-process-name [pid]
  "Get process name from /proc/PID/comm"
  (try
    (let [path (str "/proc/" pid "/comm")
          name (slurp path)]
      (clojure.string/trim name))
    (catch Exception _
      "<unknown>")))

(defn read-process-counts [map-fd]
  "Read all process counts from map"
  (let [counts (atom {})]
    (bpf/map-for-each map-fd
      (fn [key value]
        (let [pid (read-u32-le key)
              count (read-u64-le value)
              name (get-process-name pid)]
          (swap! counts assoc pid {:name name :count count}))))
    @counts))

(defn display-top-processes [counts n]
  "Display top N processes by execution count"
  (println "\nTop" n "Processes by Execution Count:")
  (println "───────────────────────────────────────────")
  (println (format "%-8s %-20s %s" "PID" "NAME" "COUNT"))
  (println "───────────────────────────────────────────")
  (let [sorted (take n (sort-by (comp :count val) > counts))]
    (doseq [[pid {:keys [name count]}] sorted]
      (println (format "%-8d %-20s %d" pid name count)))))

;; ============================================================================
;; Part 4: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 2.1: Process Counter ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create map
  (println "\nStep 2: Creating process counter map...")
  (let [map-fd (create-process-map)]
    (println "✓ Map created (FD:" map-fd ")")

    (try
      ;; Create and load program
      (println "\nStep 3: Creating BPF program...")
      (let [program (create-counter-program map-fd)]
        (println "✓ Program assembled (" (/ (count program) 8) "instructions)")

        (println "\nStep 4: Loading program into kernel...")
        (let [prog-fd (bpf/load-program program :tracepoint)]
          (println "✓ Program loaded (FD:" prog-fd ")")

          (try
            ;; Attach to tracepoint
            (println "\nStep 5: Attaching to sched_process_exec tracepoint...")
            ;; Note: Tracepoint attachment will be implemented in Chapter 5
            ;; For now, we'll manually test the map operations
            (println "ℹ Tracepoint attachment requires Chapter 5 features")
            (println "ℹ Demonstrating map operations with test data...")

            ;; Simulate some process executions
            (println "\nStep 6: Simulating process executions...")
            (doseq [pid [1000 1001 1000 1002 1000 1001 1000]]
              (let [key (utils/u32 pid)
                    existing (bpf/map-lookup map-fd key)
                    new-count (if existing
                                (inc (read-u64-le existing))
                                1)]
                (bpf/map-update map-fd key (utils/u64 new-count) :any)))
            (println "✓ Simulated 7 executions")

            ;; Display results
            (println "\nStep 7: Reading and displaying results...")
            (let [counts (read-process-counts map-fd)]
              (println "\nTotal processes tracked:" (count counts))
              (display-top-processes counts 10))

            ;; Test individual lookup
            (println "\nStep 8: Testing individual lookup...")
            (let [test-pid 1000
                  key (utils/u32 test-pid)
                  value (bpf/map-lookup map-fd key)]
              (if value
                (println (format "✓ PID %d: %d executions"
                               test-pid
                               (read-u64-le value)))
                (println (format "✗ PID %d not found" test-pid))))

            ;; Test deletion
            (println "\nStep 9: Testing deletion...")
            (let [test-pid 1002
                  key (utils/u32 test-pid)]
              (bpf/map-delete map-fd key)
              (let [value (bpf/map-lookup map-fd key)]
                (if value
                  (println "✗ Deletion failed")
                  (println (format "✓ PID %d deleted successfully" test-pid)))))

            ;; Final state
            (println "\nStep 10: Final map state...")
            (let [counts (read-process-counts map-fd)]
              (display-top-processes counts 10))

            ;; Cleanup
            (println "\nStep 11: Cleanup...")
            (bpf/close-program prog-fd)
            (println "✓ Program closed")

            (catch Exception e
              (println "✗ Error:" (.getMessage e))
              (.printStackTrace e)))

          (finally
            (bpf/close-map map-fd)
            (println "✓ Map closed")))))

      (catch Exception e
        (println "✗ Error:" (.getMessage e))
        (.printStackTrace e))))

  (println "\n=== Lab 2.1 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-02/labs
clojure -M lab-2-1.clj
```

### Expected Output

```
=== Lab 2.1: Process Counter ===

Step 1: Initializing...

Step 2: Creating process counter map...
✓ Map created (FD: 3)

Step 3: Creating BPF program...
✓ Program assembled (12 instructions)

Step 4: Loading program into kernel...
✓ Program loaded (FD: 4)

Step 5: Attaching to sched_process_exec tracepoint...
ℹ Tracepoint attachment requires Chapter 5 features
ℹ Demonstrating map operations with test data...

Step 6: Simulating process executions...
✓ Simulated 7 executions

Step 7: Reading and displaying results...

Total processes tracked: 3

Top 10 Processes by Execution Count:
───────────────────────────────────────────
PID      NAME                 COUNT
───────────────────────────────────────────
1000     bash                 4
1001     ls                   2
1002     ps                   1

Step 8: Testing individual lookup...
✓ PID 1000: 4 executions

Step 9: Testing deletion...
✓ PID 1002 deleted successfully

Step 10: Final map state...

Top 10 Processes by Execution Count:
───────────────────────────────────────────
PID      NAME                 COUNT
───────────────────────────────────────────
1000     bash                 4
1001     ls                   2

Step 11: Cleanup...
✓ Program closed
✓ Map closed

=== Lab 2.1 Complete! ===
```

## Understanding the Code

### Map Creation

```clojure
(bpf/create-map :hash
  {:key-size 4          ; sizeof(u32) for PID
   :value-size 8        ; sizeof(u64) for counter
   :max-entries 10000}) ; Maximum 10,000 processes
```

The hash map stores PID → count mappings. Maximum 10,000 entries ensures we don't run out of memory.

### BPF Program Logic

```clojure
;; 1. Get PID
(bpf/helper-get-current-pid-tgid)
[(bpf/rsh :r0 32)]  ; Extract TGID (process ID)

;; 2. Lookup in map
[(bpf/ld-map-fd :r1 map-fd)]
[(bpf/mov-reg :r2 :r10)]
[(bpf/add :r2 -8)]
(bpf/helper-map-lookup-elem :r1 :r2)

;; 3. Branch: create new or update existing
[(bpf/jmp-imm :jne :r7 0 :update-existing)]
;; ... create new entry ...
;; :update-existing
;; ... increment counter ...
```

### Userspace Data Reading

```clojure
(defn read-process-counts [map-fd]
  (let [counts (atom {})]
    (bpf/map-for-each map-fd
      (fn [key value]
        (let [pid (read-u32-le key)
              count (read-u64-le value)]
          (swap! counts assoc pid {:name (get-process-name pid)
                                   :count count}))))
    @counts))
```

Iterates all map entries and builds a Clojure map with process information.

## Experiments

### Experiment 1: Change Map Size

```clojure
;; Try different max_entries
(bpf/create-map :hash
  {:key-size 4
   :value-size 8
   :max-entries 100})  ; Only 100 processes

;; What happens when you exceed the limit?
```

### Experiment 2: Use LRU Map

```clojure
;; Replace hash map with LRU hash map
(bpf/create-map :lru-hash
  {:key-size 4
   :value-size 8
   :max-entries 10})  ; Only keep 10 most recent

;; Oldest entries are automatically evicted
```

### Experiment 3: Per-CPU Counting

```clojure
;; Use per-CPU hash map for better performance
(bpf/create-map :percpu-hash
  {:key-size 4
   :value-size 8
   :max-entries 10000})

;; Userspace needs to aggregate per-CPU values
(defn read-percpu-counts [map-fd]
  (let [num-cpus (utils/num-cpus)]
    ;; Each value is now an array of num-cpus values
    ...))
```

### Experiment 4: Track Command Line

```clojure
;; Store command line instead of just count
(bpf/create-map :hash
  {:key-size 4
   :value-size 256  ; Store command line string
   :max-entries 10000})

;; BPF program needs to read /proc/[pid]/cmdline
;; or capture from execve arguments
```

## Troubleshooting

### Error: "Map creation failed"

**Possible causes**:
- Insufficient memory
- Invalid map parameters
- Missing permissions

**Solutions**:
```bash
# Check memory
free -h

# Check map limits
ulimit -l  # Locked memory limit

# Increase locked memory limit
ulimit -l unlimited

# Or run with sudo
sudo clojure -M lab-2-1.clj
```

### Error: "Program verification failed"

**Common issues**:
1. **Unbounded loops**: BPF verifier requires provable termination
2. **Invalid memory access**: All memory accesses must be bounds-checked
3. **Register state**: R1-R5 may be clobbered after helper calls

**Debug**:
```bash
# Check kernel logs for verifier errors
sudo dmesg | tail -20
```

### Error: "Map lookup returns null"

**Causes**:
- Key doesn't exist
- Wrong key size
- Wrong endianness

**Solutions**:
```clojure
;; Ensure correct endianness
(.order buf ByteOrder/LITTLE_ENDIAN)

;; Check key size matches map definition
(assert (= (.remaining key-buf) 4))  ; For u32 key
```

## Key Takeaways

✅ Hash maps provide O(1) key-value lookups
✅ Maps can be accessed from both BPF programs and userspace
✅ Map operations (lookup, update, delete) are atomic
✅ BPF programs must handle NULL returns from lookups
✅ Userspace must handle endianness correctly
✅ map_for_each enables iteration over all entries

## Next Steps

- **Next Lab**: [Lab 2.2 - Network Packet Histogram](lab-2-2-packet-histogram.md)
- **Previous Lab**: [Chapter 2 - BPF Maps](../README.md)
- **Chapter**: [Part I - Fundamentals](../../part-1-fundamentals/)

## Challenge

Extend the process counter to track:
1. Total CPU time per process
2. Number of context switches
3. Memory usage

Hint: You'll need to:
- Expand value size to store multiple metrics
- Use additional helpers (`bpf_get_current_task()`)
- Read from kernel task_struct

Solution in: [solutions/lab-2-1-challenge.clj](../solutions/lab-2-1-challenge.clj)
