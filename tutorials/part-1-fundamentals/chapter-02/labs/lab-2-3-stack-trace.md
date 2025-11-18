# Lab 2.3: Stack Trace Collector

**Objective**: Collect and display kernel stack traces using stack trace maps

**Duration**: 60 minutes

## Overview

In this lab, you'll build a profiler that captures kernel stack traces. You'll use a special BPF map type designed for storing stack traces, attach to a kernel function, and create a flame graph-style visualization of where the kernel spends its time.

This lab demonstrates:
- Stack trace maps (`BPF_MAP_TYPE_STACK_TRACE`)
- Using `bpf_get_stackid()` helper
- Combining multiple map types
- Kernel symbol resolution
- Profile data visualization

## What You'll Learn

- How to create and use stack trace maps
- How to capture kernel call stacks from BPF
- How to resolve kernel symbols
- How to aggregate and visualize profiling data
- Combining hash maps with stack trace maps

## Theory

### Stack Traces

A stack trace shows the call chain leading to the current point of execution:

```
Function Call Stack:
  do_syscall_64()
    ↓
  __x64_sys_read()
    ↓
  vfs_read()
    ↓
  new_sync_read()
    ↓
  generic_file_read_iter()
```

### Stack Trace Map

The `BPF_MAP_TYPE_STACK_TRACE` map stores arrays of instruction pointers (IPs):

```
┌─────────────────────────────────────┐
│ Stack Trace Map                     │
├──────────┬──────────────────────────┤
│ Stack ID │ Array of IPs             │
├──────────┼──────────────────────────┤
│    1     │ [ip1, ip2, ip3, ...]    │
│    2     │ [ip4, ip5, ip6, ...]    │
│    3     │ [ip7, ip8, ip9, ...]    │
│   ...    │ ...                      │
└──────────┴──────────────────────────┘
```

### bpf_get_stackid() Helper

The `bpf_get_stackid()` helper:
1. Captures current call stack
2. Looks up if identical stack already exists
3. Returns existing stack ID or allocates new one
4. Allows efficient stack deduplication

### Two-Map Pattern

We use two maps together:
1. **Stack Trace Map**: Stores unique stacks
2. **Hash Map**: Counts how often each stack occurs

```
┌──────────────┐      ┌──────────────────┐
│  Hash Map    │      │ Stack Trace Map  │
│  Stack ID    │      │     Stack ID     │
│    → Count   │      │   → IP Array     │
├──────────────┤      ├──────────────────┤
│  1 → 42      │  →   │  1 → [ip, ...]   │
│  2 → 15      │  →   │  2 → [ip, ...]   │
│  3 → 7       │  →   │  3 → [ip, ...]   │
└──────────────┘      └──────────────────┘
```

### Kernel Symbol Resolution

We resolve instruction pointers to function names using:
- `/proc/kallsyms` - kernel symbol table
- `/proc/modules` - loaded kernel modules
- Binary search for closest symbol

## Implementation

### Step 1: Complete Program

Create `lab-2-3.clj`:

```clojure
(ns lab-2-3-stack-trace
  "Lab 2.3: Stack Trace Collector using BPF stack trace maps"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str]
            [clojure.java.io :as io])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Part 1: Configuration
;; ============================================================================

(def max-stack-depth 127)  ; Maximum depth for stack traces
(def max-stacks 10000)     ; Maximum unique stacks to store

;; ============================================================================
;; Part 2: Map Creation
;; ============================================================================

(defn create-stack-map []
  "Create stack trace map"
  (bpf/create-map :stack-trace
    {:key-size 4          ; u32 for stack ID
     :value-size (* 8 max-stack-depth)  ; Array of u64 IPs
     :max-entries max-stacks}))

(defn create-counts-map []
  "Create hash map to count stack occurrences"
  (bpf/create-map :hash
    {:key-size 4          ; u32 for stack ID
     :value-size 8        ; u64 for count
     :max-entries max-stacks}))

;; ============================================================================
;; Part 3: BPF Program
;; ============================================================================

(defn create-profiler-program [stack-map-fd counts-map-fd]
  "Create BPF program that samples stack traces"
  (bpf/assemble
    (vec (concat
      ;; Get stack trace
      ;; r1 = context (from attachment point)
      ;; r2 = map fd (stack trace map)
      ;; r3 = flags (BPF_F_USER_STACK for user stacks, 0 for kernel)
      [(bpf/ld-map-fd :r2 stack-map-fd)]
      [(bpf/mov :r3 0)]  ; 0 = kernel stack
      (bpf/helper-get-stackid :r1 :r2)

      ;; r0 now contains stack ID (or negative on error)
      ;; Check for error
      [(bpf/jslt-imm :r0 0 :exit)]

      ;; Save stack ID
      [(bpf/mov-reg :r6 :r0)]

      ;; Store stack ID on stack (key for counts map)
      [(bpf/store-mem :dw :r10 -8 :r6)]

      ;; Lookup count for this stack
      [(bpf/ld-map-fd :r1 counts-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Check if stack ID exists in counts
      [(bpf/jmp-imm :jne :r0 0 :increment)]

      ;; New stack - initialize count to 1
      [(bpf/store-mem :dw :r10 -16 1)]
      [(bpf/ld-map-fd :r1 counts-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]   ; key = stack ID
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]  ; value = 1
      [(bpf/mov :r4 0)]    ; flags = BPF_ANY
      (bpf/helper-map-update-elem :r1 :r2 :r3)
      [(bpf/jmp :exit)]

      ;; :increment - Increment existing count
      [(bpf/mov-reg :r7 :r0)]  ; r7 = value pointer
      [(bpf/load-mem :dw :r8 :r7 0)]  ; r8 = current count
      [(bpf/add :r8 1)]                ; r8 = count + 1
      [(bpf/store-mem :dw :r7 0 :r8)]  ; *value = count + 1

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 4: Kernel Symbol Resolution
;; ============================================================================

(defn load-kallsyms []
  "Load kernel symbol table from /proc/kallsyms"
  (try
    (with-open [rdr (io/reader "/proc/kallsyms")]
      (into []
        (for [line (line-seq rdr)
              :let [parts (str/split line #"\s+")]
              :when (= (count parts) 3)]
          (let [[addr type sym] parts
                addr-long (Long/parseLong addr 16)]
            {:address addr-long
             :type type
             :symbol sym}))))
    (catch Exception e
      (println "Warning: Could not load /proc/kallsyms:" (.getMessage e))
      [])))

(defn resolve-kernel-symbol [address kallsyms]
  "Resolve kernel address to symbol name"
  (if (empty? kallsyms)
    (format "0x%x" address)
    ;; Binary search for closest symbol
    (let [idx (loop [lo 0
                     hi (dec (count kallsyms))]
                (if (>= lo hi)
                  lo
                  (let [mid (quot (+ lo hi) 2)
                        mid-addr (:address (kallsyms mid))]
                    (if (< mid-addr address)
                      (recur (inc mid) hi)
                      (recur lo mid)))))
          sym (get kallsyms (max 0 (dec idx)))
          offset (- address (:address sym))]
      (if (< offset 0x10000)  ; Within 64KB - likely same function
        (format "%s+0x%x" (:symbol sym) offset)
        (format "0x%x" address)))))

;; ============================================================================
;; Part 5: Userspace Data Access
;; ============================================================================

(defn read-u32-le [^ByteBuffer buf offset]
  "Read u32 from ByteBuffer at offset"
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (bit-and (.getInt buf offset) 0xFFFFFFFF))

(defn read-u64-le [^ByteBuffer buf offset]
  "Read u64 from ByteBuffer at offset"
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf offset))

(defn read-stack-trace [stack-map-fd stack-id]
  "Read stack trace IPs for given stack ID"
  (let [key (utils/u32 stack-id)
        value (bpf/map-lookup stack-map-fd key)]
    (when value
      (let [num-ips (/ (.remaining value) 8)]
        (into []
          (for [i (range num-ips)
                :let [ip (read-u64-le value (* i 8))]
                :when (not= ip 0)]  ; 0 indicates end of stack
            ip))))))

(defn read-stack-counts [counts-map-fd]
  "Read all stack IDs and their counts"
  (let [counts (atom {})]
    (bpf/map-for-each counts-map-fd
      (fn [key value]
        (let [stack-id (read-u32-le key 0)
              count (read-u64-le value 0)]
          (swap! counts assoc stack-id count))))
    @counts))

;; ============================================================================
;; Part 6: Visualization
;; ============================================================================

(defn format-stack-trace [ips kallsyms]
  "Format stack trace with resolved symbols"
  (for [ip ips]
    (resolve-kernel-symbol ip kallsyms)))

(defn display-stack-trace [stack-id ips count kallsyms]
  "Display a single stack trace with count"
  (println (format "\nStack ID %d (%d samples):" stack-id count))
  (println "═══════════════════════════════════════════")
  (let [symbols (format-stack-trace ips kallsyms)]
    (doseq [[depth sym] (map-indexed vector symbols)]
      (println (format "  %2d: %s" depth sym)))))

(defn display-top-stacks [stack-map-fd counts-map-fd kallsyms n]
  "Display top N stack traces by count"
  (let [counts (read-stack-counts counts-map-fd)
        sorted (take n (sort-by val > counts))]

    (println "\n\nTop" n "Stack Traces:")
    (println "═══════════════════════════════════════════════════════")

    (doseq [[stack-id count] sorted]
      (let [ips (read-stack-trace stack-map-fd stack-id)]
        (when ips
          (display-stack-trace stack-id ips count kallsyms))))))

(defn display-summary [counts-map-fd]
  "Display summary statistics"
  (let [counts (vals (read-stack-counts counts-map-fd))
        total (reduce + counts)
        unique (count counts)]
    (println "\nSummary:")
    (println "───────────────────────────────────────────")
    (println "Total samples     :" total)
    (println "Unique stacks     :" unique)
    (println "Avg samples/stack :" (if (pos? unique)
                                     (format "%.1f" (/ total unique))
                                     0))))

;; ============================================================================
;; Part 7: Test Data Generation
;; ============================================================================

(defn simulate-stack-traces [stack-map-fd counts-map-fd]
  "Simulate stack trace captures for testing"
  (println "\nSimulating stack trace captures...")

  ;; Create some synthetic stacks
  (let [test-stacks
        [[0xffffffff81000100 0xffffffff81000200 0xffffffff81000300]
         [0xffffffff81000100 0xffffffff81000200 0xffffffff81000400]
         [0xffffffff81000100 0xffffffff81000500]
         [0xffffffff81000600 0xffffffff81000700 0xffffffff81000800 0xffffffff81000900]]]

    ;; Simulate samples with different frequencies
    (doseq [[stack-id stack] (map-indexed vector test-stacks)
            _ (range (* (inc stack-id) 10))]  ; Varying frequencies

      ;; Store stack trace
      (let [stack-key (utils/u32 stack-id)
            ;; Create ByteBuffer for stack IPs
            stack-value (ByteBuffer/allocate (* 8 max-stack-depth))]
        (.order stack-value ByteOrder/LITTLE_ENDIAN)
        (doseq [[idx ip] (map-indexed vector stack)]
          (.putLong stack-value (* idx 8) ip))
        (.position stack-value 0)
        (bpf/map-update stack-map-fd stack-key stack-value :any))

      ;; Update count
      (let [count-key (utils/u32 stack-id)
            existing (bpf/map-lookup counts-map-fd count-key)
            new-count (if existing (inc (read-u64-le existing 0)) 1)]
        (bpf/map-update counts-map-fd count-key (utils/u64 new-count) :any))))

  (println "✓ Simulation complete"))

;; ============================================================================
;; Part 8: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 2.3: Stack Trace Collector ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Load kernel symbols
  (println "\nStep 2: Loading kernel symbols...")
  (let [kallsyms (load-kallsyms)]
    (println "✓ Loaded" (count kallsyms) "kernel symbols")

    ;; Create maps
    (println "\nStep 3: Creating maps...")
    (let [stack-map-fd (create-stack-map)
          counts-map-fd (create-counts-map)]
      (println "✓ Stack trace map created (FD:" stack-map-fd ")")
      (println "✓ Counts map created (FD:" counts-map-fd ")")
      (println "  Max stack depth:" max-stack-depth)
      (println "  Max stacks:" max-stacks)

      (try
        ;; Create profiler program
        (println "\nStep 4: Creating profiler program...")
        (let [program (create-profiler-program stack-map-fd counts-map-fd)]
          (println "✓ Program assembled (" (/ (count program) 8) "instructions)")

          (println "\nStep 5: Loading program into kernel...")
          (let [prog-fd (bpf/load-program program :kprobe)]
            (println "✓ Program loaded (FD:" prog-fd ")")

            (try
              ;; Note: Actual kprobe attachment requires Chapter 5
              (println "\nStep 6: Kprobe attachment...")
              (println "ℹ Kernel probe attachment requires Chapter 5")
              (println "ℹ Using simulated stack traces for demonstration...")

              ;; Simulate stack trace collection
              (simulate-stack-traces stack-map-fd counts-map-fd)

              ;; Display results
              (println "\nStep 7: Analyzing stack traces...")
              (display-summary counts-map-fd)
              (display-top-stacks stack-map-fd counts-map-fd kallsyms 5)

              ;; Test individual stack lookup
              (println "\n\nStep 8: Testing individual stack lookup...")
              (let [test-stack-id 2
                    ips (read-stack-trace stack-map-fd test-stack-id)
                    count (get (read-stack-counts counts-map-fd) test-stack-id 0)]
                (if ips
                  (do
                    (println "✓ Found stack" test-stack-id)
                    (display-stack-trace test-stack-id ips count kallsyms))
                  (println "✗ Stack" test-stack-id "not found")))

              ;; Cleanup
              (println "\n\nStep 9: Cleanup...")
              (bpf/close-program prog-fd)
              (println "✓ Program closed")

              (catch Exception e
                (println "✗ Error:" (.getMessage e))
                (.printStackTrace e)))

            (finally
              (bpf/close-map stack-map-fd)
              (bpf/close-map counts-map-fd)
              (println "✓ Maps closed")))))

        (catch Exception e
          (println "✗ Error:" (.getMessage e))
          (.printStackTrace e)))))

  (println "\n=== Lab 2.3 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-02/labs
clojure -M lab-2-3.clj
```

### Expected Output

```
=== Lab 2.3: Stack Trace Collector ===

Step 1: Initializing...

Step 2: Loading kernel symbols...
✓ Loaded 162847 kernel symbols

Step 3: Creating maps...
✓ Stack trace map created (FD: 3)
✓ Counts map created (FD: 4)
  Max stack depth: 127
  Max stacks: 10000

Step 4: Creating profiler program...
✓ Program assembled (20 instructions)

Step 5: Loading program into kernel...
✓ Program loaded (FD: 5)

Step 6: Kprobe attachment...
ℹ Kernel probe attachment requires Chapter 5
ℹ Using simulated stack traces for demonstration...

Simulating stack trace captures...
✓ Simulation complete

Step 7: Analyzing stack traces...

Summary:
───────────────────────────────────────────
Total samples     : 100
Unique stacks     : 4
Avg samples/stack : 25.0


Top 5 Stack Traces:
═══════════════════════════════════════════════════════

Stack ID 3 (40 samples):
═══════════════════════════════════════════
   0: entry_SYSCALL_64+0x100
   1: do_syscall_64+0x200
   2: __x64_sys_read+0x300
   3: vfs_read+0x400

Stack ID 2 (30 samples):
═══════════════════════════════════════════
   0: entry_SYSCALL_64+0x100
   1: __x64_sys_write+0x500

Stack ID 1 (20 samples):
═══════════════════════════════════════════
   0: entry_SYSCALL_64+0x100
   1: do_syscall_64+0x200
   2: __x64_sys_read+0x400

Stack ID 0 (10 samples):
═══════════════════════════════════════════
   0: entry_SYSCALL_64+0x100
   1: do_syscall_64+0x200
   2: __x64_sys_read+0x300


Step 8: Testing individual stack lookup...
✓ Found stack 2

Stack ID 2 (30 samples):
═══════════════════════════════════════════
   0: entry_SYSCALL_64+0x100
   1: __x64_sys_write+0x500


Step 9: Cleanup...
✓ Program closed
✓ Maps closed

=== Lab 2.3 Complete! ===
```

## Understanding the Code

### Stack Trace Map Creation

```clojure
(bpf/create-map :stack-trace
  {:key-size 4
   :value-size (* 8 max-stack-depth)  ; Array of u64 IPs
   :max-entries max-stacks})
```

Value size accommodates maximum stack depth of instruction pointers.

### Getting Stack ID

```clojure
;; In BPF program
[(bpf/ld-map-fd :r2 stack-map-fd)]
[(bpf/mov :r3 0)]  ; Flags: 0 = kernel stack
(bpf/helper-get-stackid :r1 :r2)
;; r0 = stack ID (or negative on error)
```

The helper automatically handles stack capture and deduplication.

### Two-Map Pattern

```clojure
;; Stack trace map: stack_id → IP array
(def stack-map (create-stack-map))

;; Counts map: stack_id → count
(def counts-map (create-counts-map))

;; BPF program:
;; 1. Get stack ID from stack trace map
;; 2. Increment count in counts map
```

This pattern efficiently tracks stack frequency.

### Symbol Resolution

```clojure
(defn resolve-kernel-symbol [address kallsyms]
  ;; Binary search for closest symbol address
  ;; Calculate offset from symbol start
  ;; Return "symbol+offset" format
  ...)
```

Converts raw addresses to human-readable function names.

## Experiments

### Experiment 1: User Space Stacks

```clojure
;; Capture user space stack instead of kernel
[(bpf/mov :r3 256)]  ; BPF_F_USER_STACK = 256
(bpf/helper-get-stackid :r1 :r2)

;; Requires different symbol resolution
;; Use /proc/[pid]/maps and binary parsing
```

### Experiment 2: Combined User + Kernel Stacks

```clojure
;; Get both stacks
(bpf/helper-get-stackid :r1 :r2)  ; Kernel stack
[(bpf/mov-reg :r6 :r0)]           ; Save kernel stack ID

[(bpf/mov :r3 256)]               ; BPF_F_USER_STACK
(bpf/helper-get-stackid :r1 :r2)  ; User stack
[(bpf/mov-reg :r7 :r0)]           ; Save user stack ID

;; Store both IDs
;; Composite key: (kernel_stack_id, user_stack_id)
```

### Experiment 3: Flame Graph Generation

```clojure
(defn generate-flame-graph [stack-map-fd counts-map-fd kallsyms output-file]
  "Generate flame graph data in folded format"
  (let [counts (read-stack-counts counts-map-fd)]
    (with-open [w (io/writer output-file)]
      (doseq [[stack-id count] counts]
        (let [ips (read-stack-trace stack-map-fd stack-id)
              symbols (format-stack-trace ips kallsyms)
              folded (str/join ";" (reverse symbols))]
          (.write w (str folded " " count "\n")))))))

;; Use with flamegraph.pl:
;; cat output.txt | flamegraph.pl > flame.svg
```

### Experiment 4: Off-CPU Profiling

```clojure
;; Attach to scheduler events
;; Capture stack when thread blocks
;; Measure time between block and wake

;; Maps needed:
;; - start_time: pid → timestamp
;; - stacks: stack_id → duration_sum
;; - counts: stack_id → count
```

## Troubleshooting

### Error: "bpf_get_stackid returns -EEXIST"

**Cause**: Stack map is full

**Solution**: Increase map size or use `BPF_F_REUSE_STACKID` flag:
```clojure
[(bpf/mov :r3 512)]  ; BPF_F_REUSE_STACKID = 512
```

### Error: "bpf_get_stackid returns -EFAULT"

**Cause**: Cannot walk stack (corrupted stack, missing frame pointers)

**Solution**: Enable frame pointers in kernel configuration or use ORC unwinder.

### Empty Stack Traces

**Causes**:
1. FP optimization disabled stack walking
2. Sampling point has no useful stack
3. Permission issues

**Debug**:
```clojure
;; Check if stack ID is valid but empty
(let [ips (read-stack-trace stack-map-fd stack-id)]
  (println "Stack depth:" (count ips))
  (println "IPs:" ips))
```

### Symbol Resolution Issues

**Causes**:
- `/proc/kallsyms` not readable (needs CAP_SYSLOG)
- KASLR (kernel address randomization) enabled

**Solutions**:
```bash
# Read kallsyms as root
sudo cat /proc/kallsyms > /tmp/kallsyms
# Then use the cached file

# Or disable KASLR (not recommended for production)
# Add to kernel command line: nokaslr
```

## Key Takeaways

✅ Stack trace maps store arrays of instruction pointers
✅ `bpf_get_stackid()` captures and deduplicates stacks
✅ Two-map pattern tracks stack frequency efficiently
✅ Symbol resolution requires `/proc/kallsyms`
✅ Stack traces are powerful for profiling and debugging
✅ Frame pointers or ORC unwinder needed for reliable stacks

## Next Steps

- **Next Chapter**: [Chapter 3 - BPF Instruction Set](../../chapter-03/README.md)
- **Previous Lab**: [Lab 2.2 - Network Packet Histogram](lab-2-2-packet-histogram.md)
- **Chapter**: [Chapter 2 - BPF Maps](../README.md)

## Challenge

Build a complete CPU profiler that:
1. Samples stacks at regular intervals (frequency-based)
2. Tracks both user and kernel stacks
3. Generates flame graph data
4. Supports filtering by process name or PID
5. Calculates percentages per function

Solution in: [solutions/lab-2-3-challenge.clj](../solutions/lab-2-3-challenge.clj)
