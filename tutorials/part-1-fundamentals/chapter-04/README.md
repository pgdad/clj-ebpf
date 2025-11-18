# Chapter 4: Helper Functions

**Duration**: 3-4 hours | **Difficulty**: Intermediate

## Learning Objectives

By the end of this chapter, you will:
- Master the 210+ BPF helper functions available
- Understand helper categories and their use cases
- Use helpers for maps, time, process info, networking, and tracing
- Build practical monitoring and profiling tools
- Handle helper compatibility and kernel version requirements

## Prerequisites

- Completed [Chapter 3: BPF Instruction Set](../chapter-03/README.md)
- Understanding of Linux kernel concepts
- Familiarity with system calls and process management

## 4.1 What are BPF Helper Functions?

### Purpose

BPF helper functions are kernel-provided APIs that allow BPF programs to:
- **Interact with kernel data structures** safely
- **Access system information** (time, process info, CPU info)
- **Perform operations** not possible with instructions alone
- **Communicate with userspace** via maps and buffers

### Calling Convention

Helpers follow the same calling convention as BPF functions:

```
Helper Call:
┌─────────────────────────────────┐
│ Setup arguments in r1-r5        │
│   r1 = first argument           │
│   r2 = second argument          │
│   r3 = third argument           │
│   r4 = fourth argument          │
│   r5 = fifth argument           │
├─────────────────────────────────┤
│ call <helper_id>                │
├─────────────────────────────────┤
│ Get return value from r0        │
│   r0 = return value             │
│   r1-r5 may be clobbered        │
└─────────────────────────────────┘
```

### Safety and Restrictions

Helpers are the ONLY way BPF programs can:
- Access kernel memory safely
- Get current time
- Access process information
- Perform network operations
- Generate random numbers
- Print debug messages

Direct kernel memory access is forbidden by the verifier.

## 4.2 Helper Categories

### Map Helpers

**Purpose**: Interact with BPF maps

```clojure
;; Lookup element
(bpf/helper-map-lookup-elem map-ptr key-ptr)
;; Returns: pointer to value or NULL

;; Update element
(bpf/helper-map-update-elem map-ptr key-ptr value-ptr flags)
;; Returns: 0 on success, negative on error

;; Delete element
(bpf/helper-map-delete-elem map-ptr key-ptr)
;; Returns: 0 on success, negative on error

;; Get map value pointer
(bpf/helper-map-lookup-elem-percpu map-ptr key-ptr)
;; For per-CPU maps
```

**Common patterns**:
```clojure
;; Safe lookup with NULL check
(bpf/helper-map-lookup-elem :r1 :r2)
[(bpf/jmp-imm :jeq :r0 0 :not-found)]
;; r0 now contains valid pointer

;; Atomic increment in map
(bpf/helper-map-lookup-elem :r1 :r2)
[(bpf/jmp-imm :jeq :r0 0 :init)]
[(bpf/load-mem :dw :r3 :r0 0)]
[(bpf/add :r3 1)]
[(bpf/store-mem :dw :r0 0 :r3)]
```

### Time Helpers

**Purpose**: Get timestamps and monotonic time

```clojure
;; Monotonic time since boot (nanoseconds)
(bpf/helper-ktime-get-ns)
;; Returns: u64 nanoseconds

;; Boot time (nanoseconds)
(bpf/helper-ktime-get-boot-ns)
;; Returns: u64 nanoseconds (kernel 5.8+)

;; Coarse time (faster, less precise)
(bpf/helper-ktime-get-coarse-ns)
;; Returns: u64 nanoseconds (kernel 5.11+)
```

**Use cases**:
- Latency measurement
- Event timestamping
- Rate limiting
- Timeout detection

### Process/Task Helpers

**Purpose**: Get information about current process/thread

```clojure
;; Get PID and TGID
(bpf/helper-get-current-pid-tgid)
;; Returns: (TGID << 32) | PID

;; Get UID and GID
(bpf/helper-get-current-uid-gid)
;; Returns: (GID << 32) | UID

;; Get process name (comm)
(bpf/helper-get-current-comm buf-ptr size)
;; Returns: 0 on success

;; Get current task struct
(bpf/helper-get-current-task)
;; Returns: pointer to struct task_struct

;; Get current task struct (BTF)
(bpf/helper-get-current-task-btf)
;; Returns: BTF-aware task pointer (kernel 5.11+)
```

**Extract PID and TGID**:
```clojure
(bpf/helper-get-current-pid-tgid)
[(bpf/mov-reg :r6 :r0)]        ; Save full value
[(bpf/and :r6 0xFFFFFFFF)]     ; r6 = PID (lower 32 bits)
[(bpf/rsh :r0 32)]              ; r0 = TGID (upper 32 bits)
```

### CPU Helpers

**Purpose**: Get CPU and NUMA information

```clojure
;; Get current CPU number
(bpf/helper-get-smp-processor-id)
;; Returns: u32 CPU ID

;; Get NUMA node ID
(bpf/helper-get-numa-node-id)
;; Returns: s32 NUMA node (-1 if unavailable)
```

### Stack Helpers

**Purpose**: Capture stack traces

```clojure
;; Get stack trace ID
(bpf/helper-get-stackid ctx map flags)
;; Returns: stack ID (u32) or negative on error

;; Get stack trace directly
(bpf/helper-get-stack ctx buf size flags)
;; Returns: number of bytes written
```

**Flags**:
- `0`: Kernel stack
- `256` (`BPF_F_USER_STACK`): User stack
- `512` (`BPF_F_REUSE_STACKID`): Reuse existing stack IDs

### Probe Helpers

**Purpose**: Safely read kernel and user memory

```clojure
;; Read kernel memory
(bpf/helper-probe-read-kernel dst size src)
;; Returns: 0 on success

;; Read user memory
(bpf/helper-probe-read-user dst size src)
;; Returns: 0 on success

;; Read kernel string
(bpf/helper-probe-read-kernel-str dst size src)
;; Returns: length on success (including NUL)

;; Read user string
(bpf/helper-probe-read-user-str dst size src)
;; Returns: length on success (including NUL)
```

**Safe memory access**:
```clojure
;; Read 8 bytes from kernel pointer
[(bpf/mov-reg :r1 :r10)]       ; dst = stack
[(bpf/add :r1 -8)]
[(bpf/mov :r2 8)]               ; size = 8
[(bpf/mov-reg :r3 :r6)]        ; src = kernel pointer
(bpf/helper-probe-read-kernel :r1 :r2 :r3)
[(bpf/jmp-imm :jslt :r0 0 :error)]  ; Check error
```

### Perf Event Helpers

**Purpose**: Send data to perf event buffers

```clojure
;; Output to perf event
(bpf/helper-perf-event-output ctx map flags data size)
;; Returns: 0 on success

;; Get perf event sample period
(bpf/helper-perf-prog-read-value ctx buf bufsize)
;; Returns: 0 on success
```

### Ring Buffer Helpers

**Purpose**: Efficient event streaming (kernel 5.8+)

```clojure
;; Reserve space in ring buffer
(bpf/helper-ringbuf-reserve map size flags)
;; Returns: pointer to reserved space or NULL

;; Submit reserved space
(bpf/helper-ringbuf-submit data flags)
;; No return value

;; Discard reserved space
(bpf/helper-ringbuf-discard data flags)
;; No return value

;; Output to ring buffer (reserve + submit)
(bpf/helper-ringbuf-output map data size flags)
;; Returns: 0 on success
```

**Ring buffer pattern**:
```clojure
;; Reserve
(bpf/helper-ringbuf-reserve :r1 :r2)
[(bpf/mov-reg :r6 :r0)]  ; Save pointer
[(bpf/jmp-imm :jeq :r6 0 :exit)]  ; NULL check

;; Fill data
[(bpf/store-mem :dw :r6 0 :r7)]

;; Submit
[(bpf/mov-reg :r1 :r6)]
[(bpf/mov :r2 0)]
(bpf/helper-ringbuf-submit :r1)
```

### Debug Helpers

**Purpose**: Debug output (should not be used in production)

```clojure
;; Print to trace_pipe
(bpf/helper-trace-printk fmt fmt-size arg1 arg2 arg3)
;; Returns: number of bytes written

;; Print to trace log
(bpf/helper-trace-vprintk fmt fmt-size args-ptr args-size)
;; Returns: number of bytes written (kernel 5.16+)
```

**Note**: `trace_printk` has significant overhead and is for debugging only.

### Network Helpers

**Purpose**: Packet processing and network operations

```clojure
;; Checksum diff
(bpf/helper-csum-diff from from-size to to-size seed)
;; Returns: checksum difference

;; L3 checksum replace
(bpf/helper-l3-csum-replace skb offset from to flags)
;; Returns: 0 on success

;; L4 checksum replace
(bpf/helper-l4-csum-replace skb offset from to flags)
;; Returns: 0 on success

;; Clone/redirect packet
(bpf/helper-clone-redirect skb ifindex flags)
;; Returns: 0 on success

;; Change packet size
(bpf/helper-skb-change-tail skb len flags)
;; Returns: 0 on success
```

### Socket Helpers

**Purpose**: Socket operations and lookups

```clojure
;; Socket lookup
(bpf/helper-sk-lookup-tcp ctx tuple tuple-size netns flags)
;; Returns: socket pointer or NULL

;; Get socket cookie
(bpf/helper-get-socket-cookie ctx)
;; Returns: u64 socket cookie

;; Get socket UID
(bpf/helper-get-socket-uid skb)
;; Returns: u32 UID
```

### Control Flow Helpers

**Purpose**: Tail calls and program chaining

```clojure
;; Tail call (jump to another BPF program)
(bpf/helper-tail-call ctx prog-array-map index)
;; Does not return on success

;; Override return value
(bpf/helper-override-return regs rc)
;; Returns: 0 (kernel 4.16+, requires CONFIG_BPF_KPROBE_OVERRIDE)
```

### Random Helpers

**Purpose**: Generate random numbers

```clojure
;; Get pseudo-random number
(bpf/helper-get-prandom-u32)
;; Returns: u32 random number
```

## 4.3 Helper Compatibility

### Kernel Version Requirements

Different helpers were introduced in different kernel versions:

```clojure
;; Check helper compatibility
(bpf/helper-compatible? :helper-key :prog-type kernel-version)

;; Examples:
(bpf/helper-compatible? :map-lookup-elem :kprobe 0x031200)  ; 3.18+
;; => true

(bpf/helper-compatible? :ringbuf-reserve :xdp 0x050800)  ; 5.8+
;; => true
```

### Program Type Restrictions

Helpers have different availability based on program type:

| Helper | Socket | Kprobe | Tracepoint | XDP | TC | Cgroup |
|--------|--------|--------|------------|-----|----|----|
| map_lookup_elem | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| get_current_pid_tgid | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| probe_read_kernel | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| skb_load_bytes | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ |
| xdp_adjust_head | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ |

## 4.4 clj-ebpf Helper API

### Querying Helpers

```clojure
;; Get all helper metadata
bpf/helper-metadata  ; Map of all 210+ helpers

;; Get specific helper info
(bpf/get-helper-info :map-lookup-elem)
;; => {:id 1
;;     :name "bpf_map_lookup_elem"
;;     :signature {:return :ptr :args [:map-ptr :key-ptr]}
;;     :min-kernel "3.18"
;;     :prog-types :all
;;     :category :map
;;     :description "Lookup map element by key."}

;; Get helpers by category
(bpf/helpers-by-category :map)
;; => {:map-lookup-elem {...}, :map-update-elem {...}, ...}

;; Check availability
(bpf/available-helpers :kprobe)
;; => List of helpers available for kprobe programs
```

### Using Helper Wrappers

```clojure
;; Low-level: Manual register setup + call
[(bpf/mov-reg :r1 :r8)]  ; map pointer
[(bpf/mov-reg :r2 :r9)]  ; key pointer
[(bpf/call 1)]            ; bpf_map_lookup_elem

;; High-level: Helper wrapper (recommended)
(bpf/helper-map-lookup-elem :r8 :r9)
;; Automatically sets up r1, r2 and calls helper
```

### High-Level Patterns

```clojure
;; Safe map lookup with NULL check
(bpf/with-map-lookup map-reg key-reg null-offset
  ;; Code when value found
  ;; r0 contains value pointer
  )

;; Get full process info
(bpf/get-process-info pid-tgid-reg uid-gid-reg)
;; Returns both PID/TGID and UID/GID

;; Filter by PID
(bpf/filter-by-pid target-pid skip-offset)

;; Calculate time delta
(bpf/time-delta start-time-reg delta-reg)
```

## 4.5 Common Helper Patterns

### Pattern 1: Event Timestamping

```clojure
(defn timestamp-event []
  (vec (concat
    ;; Get timestamp
    (bpf/helper-ktime-get-ns)
    ;; Store in event structure
    [(bpf/store-mem :dw :r6 0 :r0)])))
```

### Pattern 2: Process Filtering

```clojure
(defn filter-by-process [target-pid target-uid]
  (vec (concat
    ;; Get PID/TGID
    (bpf/helper-get-current-pid-tgid)
    [(bpf/mov-reg :r6 :r0)]
    [(bpf/and :r6 0xFFFFFFFF)]  ; Extract PID
    [(bpf/jmp-imm :jne :r6 target-pid :skip)]

    ;; Get UID/GID
    (bpf/helper-get-current-uid-gid)
    [(bpf/rsh :r0 32)]  ; Extract UID
    [(bpf/jmp-imm :jne :r0 target-uid :skip)]

    ;; Process matches - continue
    )))
```

### Pattern 3: Safe String Reading

```clojure
(defn read-filename [ptr-reg dst-offset]
  (vec (concat
    ;; Setup for probe_read_user_str
    [(bpf/mov-reg :r1 :r10)]
    [(bpf/add :r1 dst-offset)]  ; dst on stack
    [(bpf/mov :r2 256)]          ; max size
    [(bpf/mov-reg :r3 ptr-reg)]  ; src pointer
    (bpf/helper-probe-read-user-str :r1 :r2 :r3)

    ;; Check error
    [(bpf/jslt-imm :r0 0 :error)])))
```

### Pattern 4: Latency Measurement

```clojure
(defn measure-latency [start-map-fd]
  ;; On entry: store start time
  (vec (concat
    (bpf/helper-ktime-get-ns)
    [(bpf/store-mem :dw :r10 -8 :r0)]  ; Save timestamp
    ;; Store in map with PID as key
    ...))

  ;; On exit: calculate delta
  (vec (concat
    ;; Lookup start time
    (bpf/helper-map-lookup-elem :r1 :r2)
    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/load-mem :dw :r6 :r0 0)]  ; r6 = start time

    ;; Get current time
    (bpf/helper-ktime-get-ns)
    [(bpf/sub-reg :r0 :r6)]  ; r0 = delta
    )))
```

## Labs

This chapter includes three hands-on labs:

### Lab 4.1: Process Tree Monitor
Use process helpers to build a process ancestry tracker

### Lab 4.2: File Access Latency Tracker
Use time helpers to measure filesystem operation latency

### Lab 4.3: Memory Allocation Profiler
Use stack helpers to profile memory allocations

## Navigation

- **Next**: [Lab 4.1 - Process Tree Monitor](labs/lab-4-1-process-tree.md)
- **Previous**: [Chapter 3 - BPF Instruction Set](../chapter-03/README.md)
- **Up**: [Part I - Fundamentals](../../part-1-fundamentals/)
- **Home**: [Tutorial Home](../../README.md)

## Additional Resources

- [BPF Helpers Reference](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
- [Kernel Helper Documentation](https://www.kernel.org/doc/html/latest/bpf/helpers.html)
- [libbpf Helper Guide](https://nakryiko.com/posts/bpf-tips-printk/)
