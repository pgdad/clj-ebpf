# Chapter 6: Tracepoints

**Duration**: 3-4 hours | **Difficulty**: Intermediate

## Learning Objectives

By the end of this chapter, you will:
- Understand tracepoints and their advantages over kprobes
- Discover and use kernel tracepoints
- Parse tracepoint arguments and context
- Attach BPF programs to various tracepoint categories
- Build system-wide monitoring tools
- Understand tracepoint stability guarantees

## Prerequisites

- Completed [Chapter 5: Kprobes](../chapter-05/)
- Understanding of kernel subsystems (scheduler, block layer, networking)
- Familiarity with kernel events and instrumentation
- Basic knowledge of system performance analysis

## 6.1 What are Tracepoints?

### Overview

**Tracepoints** are static instrumentation points explicitly placed in kernel code by developers:
- **Stable ABI**: Unlike kprobes, tracepoints have stable interfaces
- **Lower overhead**: Optimized fastpath when not active
- **Well-documented**: Each tracepoint has format description
- **Type-safe**: Arguments are properly typed structures

### Kprobes vs Tracepoints

| Feature | Kprobes | Tracepoints |
|---------|---------|-------------|
| **Placement** | Any function (dynamic) | Specific code points (static) |
| **Stability** | Unstable (functions may change) | Stable (maintained ABI) |
| **Overhead** | ~100-500ns when active | ~50-200ns when active |
| **Documentation** | kallsyms only | Full format descriptions |
| **Arguments** | Manual pt_regs parsing | Structured context |
| **Portability** | Kernel-version dependent | Portable across versions |

### When to Use Tracepoints

```
Use Tracepoints When:
✓ Stable, long-term monitoring
✓ Production environments
✓ Cross-kernel-version compatibility
✓ Well-known subsystem events
✓ Performance-critical paths

Use Kprobes When:
✓ Exploring unknown code paths
✓ Debugging specific issues
✓ Function not instrumented
✓ Need offset-based probing
✓ Rapid prototyping
```

## 6.2 Tracepoint Architecture

### How Tracepoints Work

```
Without BPF:
┌─────────────────────────────────┐
│ Kernel Function                 │
│   ├─ do work...                 │
│   ├─ trace_sched_switch(...)    │ ← Tracepoint (disabled = NOP)
│   └─ continue...                │
└─────────────────────────────────┘

With BPF Attached:
┌─────────────────────────────────┐
│ Kernel Function                 │
│   ├─ do work...                 │
│   ├─ trace_sched_switch(...)    │ ← Tracepoint enabled
│   │   ├─ Call BPF program       │ ← Your code runs!
│   │   └─ Return                 │
│   └─ continue...                │
└─────────────────────────────────┘
```

### Tracepoint Categories

The kernel organizes tracepoints into subsystems:

```bash
# View all tracepoint categories
ls /sys/kernel/debug/tracing/events/
```

**Major Categories**:

1. **syscalls**: System call entry/exit
   - `sys_enter_*` - Before syscall handler
   - `sys_exit_*` - After syscall handler

2. **sched**: Process scheduler events
   - `sched_switch` - Context switch
   - `sched_wakeup` - Process wakeup
   - `sched_process_fork` - Process creation
   - `sched_process_exit` - Process termination

3. **block**: Block I/O layer
   - `block_rq_issue` - Request issued to device
   - `block_rq_complete` - Request completed
   - `block_bio_queue` - Bio queued

4. **net**: Network stack
   - `net_dev_xmit` - Packet transmission
   - `netif_receive_skb` - Packet reception
   - `net_dev_queue` - TX queue events

5. **kmem**: Memory management
   - `kmalloc` - Kernel memory allocation
   - `kfree` - Kernel memory free
   - `mm_page_alloc` - Page allocation

6. **irq**: Interrupt handling
   - `irq_handler_entry` - IRQ handler start
   - `irq_handler_exit` - IRQ handler end
   - `softirq_entry` - Softirq start

7. **workqueue**: Kernel work queues
   - `workqueue_execute_start` - Work item starts
   - `workqueue_execute_end` - Work item completes

## 6.3 Discovering Tracepoints

### Listing Available Tracepoints

```bash
# List all tracepoints
sudo cat /sys/kernel/debug/tracing/available_events

# Count tracepoints
sudo cat /sys/kernel/debug/tracing/available_events | wc -l
# Typically 1000-2000 tracepoints

# List tracepoints in a category
ls /sys/kernel/debug/tracing/events/sched/

# View tracepoint format
cat /sys/kernel/debug/tracing/events/sched/sched_switch/format
```

### Tracepoint Format

Each tracepoint has a format file describing its arguments:

```
name: sched_switch
ID: 315
format:
    field:unsigned short common_type;     offset:0;  size:2;  signed:0;
    field:unsigned char common_flags;     offset:2;  size:1;  signed:0;
    field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
    field:int common_pid;                 offset:4;  size:4;  signed:1;

    field:char prev_comm[16];             offset:8;  size:16; signed:0;
    field:pid_t prev_pid;                 offset:24; size:4;  signed:1;
    field:int prev_prio;                  offset:28; size:4;  signed:1;
    field:long prev_state;                offset:32; size:8;  signed:1;
    field:char next_comm[16];             offset:40; size:16; signed:0;
    field:pid_t next_pid;                 offset:56; size:4;  signed:1;
    field:int next_prio;                  offset:60; size:4;  signed:1;

print fmt: "prev_comm=%s prev_pid=%d prev_prio=%d prev_state=%s%s ==> next_comm=%s next_pid=%d next_prio=%d"
```

**Key Information**:
- **offset**: Byte offset in context structure
- **size**: Field size in bytes
- **signed**: Whether integer is signed
- **common_***: Available in all tracepoints

### Using bpftool

```bash
# List BPF-attachable tracepoints
sudo bpftool perf list

# Show tracepoint details
sudo bpftool perf show

# List attached programs
sudo bpftool prog list type tracepoint
```

## 6.4 Tracepoint Context Structure

### Generic Context

All tracepoints receive a context pointer with common fields:

```c
struct trace_event_raw_sched_switch {
    struct trace_entry ent;  // Common header
    char prev_comm[16];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    pid_t next_pid;
    int next_prio;
};
```

### Reading Tracepoint Arguments

In BPF, the context pointer (register `r1`) points to the tracepoint structure:

```clojure
;; sched_switch context layout:
;; r1 = ctx (pointer to trace_event_raw_sched_switch)

;; Read prev_pid (offset 24, size 4)
[(bpf/load-mem :w :r2 :r1 24)]  ; r2 = prev_pid

;; Read next_pid (offset 56, size 4)
[(bpf/load-mem :w :r3 :r1 56)]  ; r3 = next_pid

;; Read prev_comm (offset 8, 16 bytes)
;; Need to use bpf_probe_read() for strings > 8 bytes
[(bpf/mov-reg :r2 :r10)]  ; dst = stack
[(bpf/add :r2 -16)]
[(bpf/mov-reg :r3 :r1)]   ; src = ctx
[(bpf/add :r3 8)]         ; + offset
[(bpf/mov :r4 16)]        ; size
(bpf/helper-probe-read :r2 :r3 :r4)
```

### Architecture Independence

Unlike kprobes with pt_regs, tracepoint offsets are architecture-independent:
- Same offsets on x86_64, ARM64, RISC-V, etc.
- Kernel ABI guarantees stability
- No need for architecture-specific code

## 6.5 Syscall Tracepoints

### Special Category: Raw Syscalls

Syscall tracepoints have a special format:

```bash
# Entry tracepoint
/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format

# Exit tracepoint
/sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/format
```

### Syscall Entry Format

```
name: sys_enter_openat
format:
    field:int __syscall_nr;        offset:8;  size:4; signed:1;
    field:int dfd;                 offset:16; size:8; signed:0;
    field:const char * filename;   offset:24; size:8; signed:0;
    field:int flags;               offset:32; size:8; signed:0;
    field:umode_t mode;            offset:40; size:8; signed:0;
```

### Syscall Exit Format

```
name: sys_exit_openat
format:
    field:int __syscall_nr;        offset:8;  size:4; signed:1;
    field:long ret;                offset:16; size:8; signed:1;
```

### Advantage Over Kprobes

Syscall tracepoints are simpler than kprobe-based syscall tracing:
- No pt_regs parsing needed
- Direct access to typed arguments
- Both entry and exit have consistent format
- Works for all syscalls uniformly

## 6.6 clj-ebpf Tracepoint API

### Attaching to Tracepoints

```clojure
(require '[clj-ebpf.core :as bpf])

;; Create program
(def prog-bytes (bpf/assemble instructions))

;; Load as tracepoint program
(def prog-fd (bpf/load-program prog-bytes :tracepoint))

;; Attach to tracepoint
;; Format: "category/name"
(def link-fd (bpf/attach-tracepoint prog-fd "sched/sched_switch"))

;; Detach
(bpf/detach-tracepoint link-fd)

;; Close
(bpf/close-program prog-fd)
```

### Tracepoint Categories

Common attachment patterns:

```clojure
;; Scheduler events
(bpf/attach-tracepoint prog-fd "sched/sched_switch")
(bpf/attach-tracepoint prog-fd "sched/sched_wakeup")
(bpf/attach-tracepoint prog-fd "sched/sched_process_fork")

;; Syscalls
(bpf/attach-tracepoint prog-fd "syscalls/sys_enter_openat")
(bpf/attach-tracepoint prog-fd "syscalls/sys_exit_openat")

;; Block I/O
(bpf/attach-tracepoint prog-fd "block/block_rq_issue")
(bpf/attach-tracepoint prog-fd "block/block_rq_complete")

;; Network
(bpf/attach-tracepoint prog-fd "net/net_dev_xmit")
(bpf/attach-tracepoint prog-fd "net/netif_receive_skb")

;; Memory
(bpf/attach-tracepoint prog-fd "kmem/kmalloc")
(bpf/attach-tracepoint prog-fd "kmem/kfree")
```

### Multiple Tracepoints

Attach the same program to multiple tracepoints:

```clojure
(defn attach-to-all-syscalls [prog-fd syscalls]
  (mapv (fn [syscall-name]
          (bpf/attach-tracepoint
            prog-fd
            (str "syscalls/sys_enter_" syscall-name)))
        syscalls))

;; Example
(def links
  (attach-to-all-syscalls
    prog-fd
    ["read" "write" "open" "close" "stat"]))
```

## 6.7 Common Patterns

### Pattern 1: Event Counting

```clojure
(defn create-event-counter [map-fd event-id]
  "Count occurrences of a tracepoint event"
  (bpf/assemble
    (vec (concat
      ;; Prepare key
      [(bpf/mov :r6 event-id)]
      [(bpf/store-mem :w :r10 -4 :r6)]

      ;; Lookup or initialize counter
      [(bpf/ld-map-fd :r1 map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If exists, increment
      [(bpf/jmp-imm :jeq :r0 0 :init)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]
      [(bpf/jmp :exit)]

      ;; :init - first occurrence
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -16 :r3)]
      [(bpf/ld-map-fd :r1 map-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))
```

### Pattern 2: Per-Process Tracking

```clojure
(defn track-per-process [ctx-reg map-fd offset]
  "Track events per PID using tracepoint context"
  (vec (concat
    ;; Get current PID
    (bpf/helper-get-current-pid-tgid)
    [(bpf/mov-reg :r6 :r0)]  ; Save full 64-bit
    [(bpf/rsh :r6 32)]       ; Extract TGID

    ;; Read value from context
    [(bpf/load-mem :dw :r7 ctx-reg offset)]

    ;; Store in map[PID]
    [(bpf/store-mem :w :r10 -4 :r6)]   ; key = PID
    [(bpf/store-mem :dw :r10 -16 :r7)] ; value

    [(bpf/ld-map-fd :r1 map-fd)]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -16)]
    [(bpf/mov :r4 0)]
    (bpf/helper-map-update-elem :r1 :r2 :r3))))
```

### Pattern 3: State Correlation

```clojure
(defn correlate-entry-exit [entry-map-fd event-map-fd]
  "Match entry/exit events for latency tracking"
  {:entry-handler
   (bpf/assemble
     (vec (concat
       ;; Record entry timestamp
       (bpf/helper-get-current-pid-tgid)
       [(bpf/mov-reg :r6 :r0)]
       (bpf/helper-ktime-get-ns)
       [(bpf/store-mem :dw :r10 -8 :r0)]
       [(bpf/store-mem :dw :r10 -16 :r6)]

       ;; Store in entry-map[PID]
       [(bpf/ld-map-fd :r1 entry-map-fd)]
       [(bpf/mov-reg :r2 :r10)]
       [(bpf/add :r2 -16)]
       [(bpf/mov-reg :r3 :r10)]
       [(bpf/add :r3 -8)]
       [(bpf/mov :r4 0)]
       (bpf/helper-map-update-elem :r1 :r2 :r3)
       [(bpf/mov :r0 0)]
       [(bpf/exit-insn)])))

   :exit-handler
   (bpf/assemble
     (vec (concat
       ;; Lookup entry timestamp
       (bpf/helper-get-current-pid-tgid)
       [(bpf/mov-reg :r6 :r0)]
       [(bpf/store-mem :dw :r10 -8 :r6)]

       [(bpf/ld-map-fd :r1 entry-map-fd)]
       [(bpf/mov-reg :r2 :r10)]
       [(bpf/add :r2 -8)]
       (bpf/helper-map-lookup-elem :r1 :r2)
       [(bpf/jmp-imm :jeq :r0 0 :exit)]

       ;; Calculate latency
       [(bpf/load-mem :dw :r7 :r0 0)]  ; start_time
       (bpf/helper-ktime-get-ns)
       [(bpf/sub-reg :r0 :r7)]         ; latency = now - start

       ;; Store event
       ...

       ;; :exit
       [(bpf/mov :r0 0)]
       [(bpf/exit-insn)])))})
```

## 6.8 Performance Optimization

### Tracepoint Overhead

Tracepoints have minimal overhead:

```
Inactive tracepoint:    ~2-5 CPU cycles (NOP)
Active tracepoint:      ~50-200ns per event
BPF program execution:  +variable (depends on program)
Map operations:         ~50-200ns per operation
Ring buffer submit:     ~100-300ns
```

### Best Practices

1. **Filter Early**: Reduce work for uninteresting events
   ```clojure
   ;; Filter by PID first
   (bpf/helper-get-current-pid-tgid)
   [(bpf/rsh :r0 32)]
   [(bpf/jmp-imm :jne :r0 TARGET_PID :exit)]
   ```

2. **Use Per-CPU Maps**: Avoid contention
   ```clojure
   (bpf/create-map :percpu-hash {:key-size 4 :value-size 8 ...})
   ```

3. **Batch Events**: Use ring buffers for high-frequency events
   ```clojure
   ;; Reserve space in ring buffer
   [(bpf/ld-map-fd :r1 ringbuf-fd)]
   [(bpf/mov :r2 EVENT_SIZE)]
   [(bpf/mov :r3 0)]
   (bpf/helper-ringbuf-reserve :r1 :r2)
   ```

4. **Sample High-Frequency Tracepoints**: Don't trace every event
   ```clojure
   (bpf/helper-get-prandom-u32)
   [(bpf/and :r0 0xFF)]  ; Modulo 256
   [(bpf/jmp-imm :jne :r0 0 :exit)]  ; 1/256 sampling
   ```

## 6.9 Tracepoint Stability

### Stable Tracepoints

These tracepoints have been stable for many kernel versions:

**Scheduler** (stable since 2.6.23+):
- `sched_switch`
- `sched_wakeup`
- `sched_process_fork`
- `sched_process_exit`

**Syscalls** (stable since 3.5+):
- `sys_enter_*`
- `sys_exit_*`

**Block** (stable since 2.6.32+):
- `block_rq_issue`
- `block_rq_complete`

**Network** (mostly stable since 3.10+):
- `net_dev_xmit`
- `netif_receive_skb`

### Version Considerations

Some tracepoints have evolved:
- Field names may change (rare)
- New fields added (common)
- Offsets may shift with new fields

**Solution**: Use BTF (BPF Type Format) for portable field access:
```clojure
;; Instead of hardcoded offsets:
[(bpf/load-mem :w :r2 :r1 24)]  ; Brittle

;; Use BTF-based access (if available):
(bpf/btf-read :r2 :r1 "prev_pid")  ; Portable
```

## 6.10 Debugging Tracepoints

### Common Issues

**1. Tracepoint Not Found**
```bash
# Check if tracepoint exists
ls /sys/kernel/debug/tracing/events/sched/sched_switch

# List all available
cat /sys/kernel/debug/tracing/available_events | grep sched
```

**2. Verifier Rejection**
```bash
# Check dmesg for errors
sudo dmesg | tail -20

# Common: incorrect offset, wrong size, unbounded access
```

**3. No Events Firing**
```bash
# Check if tracepoint is enabled
cat /sys/kernel/debug/tracing/events/sched/sched_switch/enable

# Enable manually (for testing)
echo 1 | sudo tee /sys/kernel/debug/tracing/events/sched/sched_switch/enable
```

### Debugging Tools

```bash
# Trace events manually (without BPF)
cd /sys/kernel/debug/tracing
echo 1 > events/sched/sched_switch/enable
cat trace_pipe

# Disable
echo 0 > events/sched/sched_switch/enable

# List BPF programs attached to tracepoints
sudo bpftool prog list type tracepoint

# Show program details
sudo bpftool prog show id <ID>

# Dump program with line info
sudo bpftool prog dump xlated id <ID> linum
```

## Labs

This chapter includes three hands-on labs:

### Lab 6.1: CPU Scheduler Tracer
Monitor process scheduling with sched_switch tracepoint

### Lab 6.2: Block I/O Latency Monitor
Track disk I/O latency using block layer tracepoints

### Lab 6.3: System Call Frequency Analyzer
Analyze syscall patterns with syscall tracepoints

## Navigation

- **Next**: [Lab 6.1 - CPU Scheduler Tracer](labs/lab-6-1-scheduler-tracer.md)
- **Previous**: [Chapter 5 - Kprobes](../chapter-05/README.md)
- **Up**: [Part II - Program Types](../../part-2-program-types/)
- **Home**: [Tutorial Home](../../README.md)

## Additional Resources

- [Linux Tracepoint Documentation](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [Understanding Tracepoints](https://www.kernel.org/doc/html/latest/trace/events.html)
- [BPF Tracepoint Programs](https://nakryiko.com/posts/bpf-tips-printk-tracing/)
- [Tracepoint Stability Policy](https://www.kernel.org/doc/Documentation/trace/tracepoint-analysis.txt)
- [Brendan Gregg on Tracepoints](http://www.brendangregg.com/blog/2019-01-01/learn-ebpf-tracing.html)
