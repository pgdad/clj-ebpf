# Lab 4.1: Process Tree Monitor

**Objective**: Build a process ancestry tracker using process helper functions

**Duration**: 60 minutes

## Overview

In this lab, you'll build a tool that tracks process creation and maintains a process tree showing parent-child relationships. You'll use BPF helper functions to capture process information (PID, PPID, UID, process name) and build a complete process genealogy tracker.

This lab demonstrates:
- Using process/task helper functions
- Reading task_struct fields safely
- Tracking process relationships
- Building hierarchical data structures
- Real-time process monitoring

## What You'll Learn

- How to use `bpf_get_current_task()` and related helpers
- Reading fields from kernel structures safely
- Tracking parent-child process relationships
- Building and maintaining process trees
- Efficient data structures for hierarchical data
- Process lifecycle event handling

## Theory

### Linux Process Model

```
Process Tree:
┌─────────────────────────────────────┐
│  init (PID 1)                       │
├─────┬───────────────────────────────┤
│     ├─ systemd-journald (PID 142)  │
│     ├─ sshd (PID 897)               │
│     │   └─ sshd (PID 12045)         │
│     │       └─ bash (PID 12046)     │
│     │           └─ vim (PID 12123)  │
│     └─ cron (PID 923)               │
└─────────────────────────────────────┘
```

Every process (except PID 1) has a parent. When a process forks:
1. Child inherits parent's UID, GID, environment
2. Child gets new PID
3. Parent's PID becomes child's PPID

### task_struct Structure

The kernel represents processes with `struct task_struct`:

```c
struct task_struct {
    pid_t pid;                    // Process ID
    pid_t tgid;                   // Thread group ID (main thread PID)
    struct task_struct *parent;   // Parent process
    char comm[TASK_COMM_LEN];    // Process name (16 bytes)
    uid_t uid;                    // User ID
    gid_t gid;                    // Group ID
    // ... many more fields
};
```

BPF helpers provide safe access to these fields without direct memory access.

### Process Events

We track three key events:
1. **Fork**: New process created
2. **Exec**: Process replaces its program
3. **Exit**: Process terminates

## Implementation

### Step 1: Complete Program

Create `lab-4-1.clj`:

```clojure
(ns lab-4-1-process-tree
  "Lab 4.1: Process Tree Monitor using process helper functions"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Part 1: Data Structures
;; ============================================================================

;; Process info structure (stored in map)
;; struct process_info {
;;   u32 pid;
;;   u32 ppid;
;;   u32 uid;
;;   u32 gid;
;;   char comm[16];
;;   u64 start_time;
;; };

(def PROCESS_INFO_SIZE (+ 4 4 4 4 16 8))  ; 40 bytes

;; ============================================================================
;; Part 2: Maps
;; ============================================================================

(defn create-process-map []
  "Map: PID -> process_info"
  (bpf/create-map :hash
    {:key-size 4                    ; u32 PID
     :value-size PROCESS_INFO_SIZE  ; process_info struct
     :max-entries 10000}))

(defn create-parent-map []
  "Map: PID -> PPID (for quick parent lookup)"
  (bpf/create-map :hash
    {:key-size 4    ; u32 PID
     :value-size 4  ; u32 PPID
     :max-entries 10000}))

(defn create-events-map []
  "Ring buffer for process events"
  (bpf/create-map :ringbuf
    {:max-entries (* 256 1024)}))  ; 256KB

;; ============================================================================
;; Part 3: BPF Program - Process Fork Handler
;; ============================================================================

(defn create-fork-handler [process-map-fd parent-map-fd events-map-fd]
  "Handle process fork events (sched_process_fork tracepoint)"
  (bpf/assemble
    (vec (concat
      ;; ──────────────────────────────────────────────────────────
      ;; Step 1: Get current process info
      ;; ──────────────────────────────────────────────────────────

      ;; Get PID and TGID
      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r6 :r0)]       ; r6 = full pid_tgid
      [(bpf/rsh :r0 32)]             ; r0 = TGID (parent PID)
      [(bpf/mov-reg :r7 :r0)]       ; r7 = parent PID

      ;; Get UID and GID
      (bpf/helper-get-current-uid-gid)
      [(bpf/mov-reg :r8 :r0)]       ; r8 = full uid_gid
      [(bpf/rsh :r0 32)]             ; r0 = UID
      [(bpf/mov-reg :r9 :r0)]       ; r9 = UID

      ;; ──────────────────────────────────────────────────────────
      ;; Step 2: Get child PID from tracepoint context
      ;; ──────────────────────────────────────────────────────────

      ;; For sched_process_fork tracepoint:
      ;; child_pid is at offset 16 in context
      [(bpf/load-mem :w :r5 :r1 16)]  ; r5 = child_pid

      ;; ──────────────────────────────────────────────────────────
      ;; Step 3: Get process name (comm)
      ;; ──────────────────────────────────────────────────────────

      ;; Get comm on stack
      [(bpf/mov-reg :r1 :r10)]
      [(bpf/add :r1 -16)]  ; Stack buffer for comm
      [(bpf/mov :r2 16)]   ; TASK_COMM_LEN = 16
      (bpf/helper-get-current-comm :r1 :r2)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 4: Get timestamp
      ;; ──────────────────────────────────────────────────────────

      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r4 :r0)]  ; r4 = timestamp

      ;; ──────────────────────────────────────────────────────────
      ;; Step 5: Build process_info structure on stack
      ;; ──────────────────────────────────────────────────────────

      ;; We now have:
      ;; r5 = child PID
      ;; r7 = parent PID
      ;; r9 = UID
      ;; r8 = UID|GID (extract GID)
      ;; r4 = timestamp
      ;; stack[-16..-1] = comm

      ;; Extract GID from r8
      [(bpf/mov-reg :r3 :r8)]
      [(bpf/and :r3 0xFFFFFFFF)]  ; r3 = GID

      ;; Build structure on stack (starting at stack[-64])
      [(bpf/store-mem :w :r10 -64 :r5)]   ; pid
      [(bpf/store-mem :w :r10 -60 :r7)]   ; ppid
      [(bpf/store-mem :w :r10 -56 :r9)]   ; uid
      [(bpf/store-mem :w :r10 -52 :r3)]   ; gid
      ;; comm already at stack[-16..-1], copy to -48..-33
      [(bpf/load-mem :dw :r0 :r10 -16)]
      [(bpf/store-mem :dw :r10 -48 :r0)]
      [(bpf/load-mem :dw :r10 -8)]
      [(bpf/store-mem :dw :r10 -40 :r0)]
      ;; start_time
      [(bpf/store-mem :dw :r10 -32 :r4)]  ; timestamp

      ;; ──────────────────────────────────────────────────────────
      ;; Step 6: Store in process map
      ;; ──────────────────────────────────────────────────────────

      ;; Store child PID as key
      [(bpf/store-mem :w :r10 -68 :r5)]

      ;; Update process map
      [(bpf/ld-map-fd :r1 process-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -68)]  ; key = child PID
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -64)]  ; value = process_info
      [(bpf/mov :r4 0)]    ; flags = BPF_ANY
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 7: Store in parent map (PID -> PPID mapping)
      ;; ──────────────────────────────────────────────────────────

      [(bpf/ld-map-fd :r1 parent-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -68)]  ; key = child PID
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -60)]  ; value = PPID
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 8: Send event to ring buffer (optional)
      ;; ──────────────────────────────────────────────────────────

      ;; Could send fork event to userspace here
      ;; (omitted for brevity)

      ;; ──────────────────────────────────────────────────────────
      ;; Step 9: Return
      ;; ──────────────────────────────────────────────────────────

      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 4: BPF Program - Process Exit Handler
;; ============================================================================

(defn create-exit-handler [process-map-fd parent-map-fd]
  "Handle process exit events (sched_process_exit tracepoint)"
  (bpf/assemble
    (vec (concat
      ;; Get exiting process PID
      (bpf/helper-get-current-pid-tgid)
      [(bpf/rsh :r0 32)]  ; TGID
      [(bpf/mov-reg :r6 :r0)]

      ;; Store PID on stack for map operations
      [(bpf/store-mem :w :r10 -4 :r6)]

      ;; Delete from process map
      [(bpf/ld-map-fd :r1 process-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-delete-elem :r1 :r2)

      ;; Delete from parent map
      [(bpf/ld-map-fd :r1 parent-map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-delete-elem :r1 :r2)

      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

;; ============================================================================
;; Part 5: Userspace - Process Tree Construction
;; ============================================================================

(defn read-u32-le [^ByteBuffer buf offset]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getInt buf offset))

(defn read-u64-le [^ByteBuffer buf offset]
  (.order buf ByteOrder/LITTLE_ENDIAN)
  (.getLong buf offset))

(defn read-string [^ByteBuffer buf offset max-len]
  (.position buf offset)
  (let [bytes (byte-array max-len)
        _ (.get buf bytes)
        null-idx (or (first (keep-indexed
                             (fn [i b] (when (zero? b) i))
                             bytes))
                    max-len)]
    (String. bytes 0 null-idx "UTF-8")))

(defn parse-process-info [^ByteBuffer buf]
  "Parse process_info structure"
  {:pid (read-u32-le buf 0)
   :ppid (read-u32-le buf 4)
   :uid (read-u32-le buf 8)
   :gid (read-u32-le buf 12)
   :comm (read-string buf 16 16)
   :start-time (read-u64-le buf 32)})

(defn get-all-processes [process-map-fd]
  "Read all processes from map"
  (let [processes (atom {})]
    (bpf/map-for-each process-map-fd
      (fn [key value]
        (let [pid (read-u32-le key 0)
              info (parse-process-info value)]
          (swap! processes assoc pid info))))
    @processes))

(defn build-process-tree [processes]
  "Build hierarchical process tree"
  (let [children (group-by :ppid (vals processes))]
    (letfn [(build-node [pid depth]
              (when-let [proc (get processes pid)]
                {:process proc
                 :depth depth
                 :children (mapv #(build-node (:pid %) (inc depth))
                               (get children pid []))}))]
      ;; Start from init (PID 1) or roots
      (let [roots (filter #(or (= (:ppid %) 0)
                              (not (contains? processes (:ppid %))))
                         (vals processes))]
        (mapv #(build-node (:pid %) 0) roots)))))

(defn format-process-tree
  "Format process tree as ASCII art"
  ([tree] (format-process-tree tree ""))
  ([nodes prefix]
   (when (seq nodes)
     (let [lines (atom [])]
       (doseq [[idx node] (map-indexed vector nodes)
               :let [is-last (= idx (dec (count nodes)))
                     proc (:process node)
                     connector (if is-last "└─" "├─")
                     extension (if is-last "  " "│ ")]]
         (swap! lines conj
                (format "%s%s %s (PID: %d, PPID: %d, UID: %d)"
                       prefix
                       connector
                       (:comm proc)
                       (:pid proc)
                       (:ppid proc)
                       (:uid proc)))
         (when (seq (:children node))
           (swap! lines concat
                  (format-process-tree (:children node)
                                     (str prefix extension "  ")))))
       @lines))))

(defn display-process-tree [process-map-fd]
  "Display the complete process tree"
  (let [processes (get-all-processes process-map-fd)
        tree (build-process-tree processes)]

    (println "\n╔════════════════════════════════════════════════════════╗")
    (println "║              Process Tree                              ║")
    (println "╚════════════════════════════════════════════════════════╝")
    (println)

    (if (empty? processes)
      (println "No processes tracked yet")
      (do
        (println "Total processes:" (count processes))
        (println)
        (doseq [line (format-process-tree tree)]
          (println line))))

    (println)))

(defn display-process-stats [process-map-fd]
  "Display process statistics"
  (let [processes (vals (get-all-processes process-map-fd))
        by-user (group-by :uid processes)
        by-name (frequencies (map :comm processes))]

    (println "\nProcess Statistics:")
    (println "═══════════════════════════════════════")
    (println "Total processes:" (count processes))
    (println)
    (println "By User:")
    (doseq [[uid procs] (sort-by key by-user)]
      (println (format "  UID %4d: %3d processes" uid (count procs))))
    (println)
    (println "Top Process Names:")
    (doseq [[name count] (take 10 (sort-by val > by-name))]
      (println (format "  %-20s: %3d" name count)))))

;; ============================================================================
;; Part 6: Main Program
;; ============================================================================

(defn -main []
  (println "=== Lab 4.1: Process Tree Monitor ===\n")

  ;; Initialize
  (println "Step 1: Initializing...")
  (bpf/init!)

  ;; Create maps
  (println "\nStep 2: Creating maps...")
  (let [process-map-fd (create-process-map)
        parent-map-fd (create-parent-map)
        events-map-fd (create-events-map)]
    (println "✓ Process map created (FD:" process-map-fd ")")
    (println "✓ Parent map created (FD:" parent-map-fd ")")
    (println "✓ Events ring buffer created (FD:" events-map-fd ")")

    (try
      ;; Create BPF programs
      (println "\nStep 3: Creating BPF programs...")
      (let [fork-prog (create-fork-handler process-map-fd parent-map-fd events-map-fd)
            exit-prog (create-exit-handler process-map-fd parent-map-fd)]
        (println "✓ Fork handler assembled (" (/ (count fork-prog) 8) "instructions)")
        (println "✓ Exit handler assembled (" (/ (count exit-prog) 8) "instructions)")

        ;; Load programs
        (println "\nStep 4: Loading programs...")
        (let [fork-fd (bpf/load-program fork-prog :tracepoint)
              exit-fd (bpf/load-program exit-prog :tracepoint)]
          (println "✓ Fork handler loaded (FD:" fork-fd ")")
          (println "✓ Exit handler loaded (FD:" exit-fd ")")

          (try
            ;; Note: Actual tracepoint attachment requires Chapter 5
            (println "\nStep 5: Tracepoint attachment...")
            (println "ℹ Tracepoint attachment requires Chapter 5")
            (println "ℹ Would attach to:")
            (println "  - sched:sched_process_fork")
            (println "  - sched:sched_process_exit")

            ;; Simulate some process data
            (println "\nStep 6: Simulating process data...")
            (let [test-processes [[1 0 0 "init"]
                                [142 1 0 "systemd-journald"]
                                [897 1 0 "sshd"]
                                [12045 897 1000 "sshd"]
                                [12046 12045 1000 "bash"]
                                [12123 12046 1000 "vim"]
                                [923 1 0 "cron"]]]

              (doseq [[pid ppid uid comm] test-processes]
                (let [buf (ByteBuffer/allocate PROCESS_INFO_SIZE)]
                  (.order buf ByteOrder/LITTLE_ENDIAN)
                  (.putInt buf 0 pid)
                  (.putInt buf 4 ppid)
                  (.putInt buf 8 uid)
                  (.putInt buf 12 0)  ; gid
                  (.position buf 16)
                  (let [comm-bytes (.getBytes comm "UTF-8")]
                    (.put buf comm-bytes 0 (min (count comm-bytes) 15)))
                  (.putLong buf 32 (System/nanoTime))
                  (.position buf 0)

                  (bpf/map-update process-map-fd
                                 (utils/u32 pid)
                                 buf
                                 :any))))

            (println "✓ Added" (count test-processes) "test processes")

            ;; Display process tree
            (println "\nStep 7: Displaying process tree...")
            (display-process-tree process-map-fd)

            ;; Display statistics
            (println "\nStep 8: Displaying statistics...")
            (display-process-stats process-map-fd)

            ;; Cleanup
            (println "\nStep 9: Cleanup...")
            (bpf/close-program fork-fd)
            (bpf/close-program exit-fd)
            (println "✓ Programs closed")

            (catch Exception e
              (println "✗ Error:" (.getMessage e))
              (.printStackTrace e)))

          (finally
            (bpf/close-map process-map-fd)
            (bpf/close-map parent-map-fd)
            (bpf/close-map events-map-fd)
            (println "✓ Maps closed")))))

      (catch Exception e
        (println "✗ Error:" (.getMessage e))
        (.printStackTrace e))))

  (println "\n=== Lab 4.1 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-04/labs
clojure -M lab-4-1.clj
```

### Expected Output

```
=== Lab 4.1: Process Tree Monitor ===

Step 1: Initializing...

Step 2: Creating maps...
✓ Process map created (FD: 3)
✓ Parent map created (FD: 4)
✓ Events ring buffer created (FD: 5)

Step 3: Creating BPF programs...
✓ Fork handler assembled (35 instructions)
✓ Exit handler assembled (12 instructions)

Step 4: Loading programs...
✓ Fork handler loaded (FD: 6)
✓ Exit handler loaded (FD: 7)

Step 5: Tracepoint attachment...
ℹ Tracepoint attachment requires Chapter 5
ℹ Would attach to:
  - sched:sched_process_fork
  - sched:sched_process_exit

Step 6: Simulating process data...
✓ Added 7 test processes

Step 7: Displaying process tree...

╔════════════════════════════════════════════════════════╗
║              Process Tree                              ║
╚════════════════════════════════════════════════════════╝

Total processes: 7

└─ init (PID: 1, PPID: 0, UID: 0)
   ├─ systemd-journald (PID: 142, PPID: 1, UID: 0)
   ├─ sshd (PID: 897, PPID: 1, UID: 0)
   │   └─ sshd (PID: 12045, PPID: 897, UID: 1000)
   │      └─ bash (PID: 12046, PPID: 12045, UID: 1000)
   │         └─ vim (PID: 12123, PPID: 12046, UID: 1000)
   └─ cron (PID: 923, PPID: 1, UID: 0)


Step 8: Displaying statistics...

Process Statistics:
═══════════════════════════════════════
Total processes: 7

By User:
  UID    0:   4 processes
  UID 1000:   3 processes

Top Process Names:
  sshd                :   2
  init                :   1
  systemd-journald    :   1
  bash                :   1
  vim                 :   1
  cron                :   1

Step 9: Cleanup...
✓ Programs closed
✓ Maps closed

=== Lab 4.1 Complete! ===
```

## Understanding the Code

### Helper Usage - Get PID/TGID

```clojure
(bpf/helper-get-current-pid-tgid)
;; Returns: (TGID << 32) | PID

;; Extract both values:
[(bpf/mov-reg :r6 :r0)]       ; Save full value
[(bpf/and :r6 0xFFFFFFFF)]    ; r6 = PID (lower 32 bits)
[(bpf/rsh :r0 32)]             ; r0 = TGID (upper 32 bits)
```

### Helper Usage - Get Process Name

```clojure
[(bpf/mov-reg :r1 :r10)]
[(bpf/add :r1 -16)]  ; Stack buffer
[(bpf/mov :r2 16)]   ; TASK_COMM_LEN
(bpf/helper-get-current-comm :r1 :r2)
;; comm now at stack[-16..-1]
```

### Helper Usage - Timestamp

```clojure
(bpf/helper-ktime-get-ns)
;; r0 = nanoseconds since boot
[(bpf/store-mem :dw :r10 -32 :r0)]  ; Save timestamp
```

## Experiments

### Experiment 1: Track Process Lifetime

```clojure
;; On fork: record start time
;; On exit: calculate lifetime
(defn calculate-lifetime []
  ;; start_time from process_info
  (bpf/helper-ktime-get-ns)
  ;; delta = current - start
  ...)
```

### Experiment 2: Track exec() Events

```clojure
;; sched_process_exec tracepoint
;; Update comm field when process execs new program
(defn create-exec-handler []
  ;; Get new program name
  ;; Update process_info.comm
  ...)
```

### Experiment 3: Resource Usage Tracking

```clojure
;; Add CPU time, memory usage to process_info
;; Read from task_struct via bpf_probe_read_kernel
(defn read-task-stats [task-ptr]
  ;; task->utime (user CPU time)
  ;; task->stime (system CPU time)
  ;; task->mm->total_vm (virtual memory)
  ...)
```

### Experiment 4: Process Lineage

```clojure
(defn get-lineage [pid parent-map]
  "Get full ancestry chain"
  (loop [current pid
         lineage []]
    (if-let [parent (get parent-map current)]
      (recur parent (conj lineage current))
      (conj lineage current))))
```

## Troubleshooting

### Missing Processes

**Causes**:
- Program not attached to tracepoints
- Map size too small (processes evicted)
- Race condition on fork

**Solution**: Increase map size or use LRU map

### Incorrect Parent Relationships

**Check**:
- PPID extraction logic
- Tracepoint context structure
- Map update ordering

**Debug**:
```bash
# Check tracepoint format
cat /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
```

### Tree Display Issues

**Causes**:
- Orphaned processes (parent exited)
- Circular references (shouldn't happen)

**Solution**: Handle missing parents gracefully

## Key Takeaways

✅ Process helpers provide safe access to task info
✅ `get_current_pid_tgid` returns both PID and TGID
✅ `get_current_comm` reads process name safely
✅ `ktime_get_ns` provides timestamps for event correlation
✅ Process trees require both fork and exit tracking
✅ Hierarchical data structures need careful map design

## Next Steps

- **Next Lab**: [Lab 4.2 - File Access Latency Tracker](lab-4-2-file-latency.md)
- **Previous Lab**: [Chapter 4 - Helper Functions](../README.md)
- **Chapter**: [Part I - Fundamentals](../../part-1-fundamentals/)

## Challenge

Enhance the process tree monitor to:
1. Track thread creation (not just processes)
2. Monitor process resource usage (CPU, memory)
3. Detect suspicious parent-child relationships
4. Track container/namespace boundaries
5. Generate alerts on rapid process spawning
6. Export process tree to GraphViz DOT format

Solution in: [solutions/lab-4-1-challenge.clj](../solutions/lab-4-1-challenge.clj)
