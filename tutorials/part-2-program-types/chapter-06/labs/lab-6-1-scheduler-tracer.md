# Lab 6.1: CPU Scheduler Tracer

**Duration**: 45-60 minutes | **Difficulty**: Intermediate

## Learning Objectives

In this lab, you will:
- Attach BPF programs to scheduler tracepoints
- Parse tracepoint context structures
- Track process scheduling events
- Calculate CPU time and context switch statistics
- Monitor CPU affinity and scheduling patterns
- Detect scheduling anomalies

## Prerequisites

- Completed [Lab 5.3](../../chapter-05/labs/lab-5-3-syscall-monitor.md)
- Understanding of Linux process scheduler
- Familiarity with tracepoint concepts

## Introduction

The Linux scheduler is responsible for allocating CPU time to processes. The `sched_switch` tracepoint fires every time the kernel switches from one process to another, providing visibility into:
- Which processes are running
- How long they run
- CPU utilization patterns
- Context switch rates

## sched_switch Tracepoint Format

```bash
$ sudo cat /sys/kernel/debug/tracing/events/sched/sched_switch/format

name: sched_switch
ID: 315
format:
    field:unsigned short common_type;      offset:0;  size:2; signed:0;
    field:unsigned char common_flags;      offset:2;  size:1; signed:0;
    field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
    field:int common_pid;                  offset:4;  size:4; signed:1;

    field:char prev_comm[16];              offset:8;  size:16; signed:0;
    field:pid_t prev_pid;                  offset:24; size:4;  signed:1;
    field:int prev_prio;                   offset:28; size:4;  signed:1;
    field:long prev_state;                 offset:32; size:8;  signed:1;
    field:char next_comm[16];              offset:40; size:16; signed:0;
    field:pid_t next_pid;                  offset:56; size:4;  signed:1;
    field:int next_prio;                   offset:60; size:4;  signed:1;
```

**Key Fields**:
- `prev_comm`, `prev_pid`: Process being switched out
- `prev_state`: Why process is leaving CPU (running, sleeping, etc.)
- `next_comm`, `next_pid`: Process being switched in
- `prev_prio`, `next_prio`: Scheduling priorities

## Part 1: Basic Context Switch Counter

Let's start by counting context switches per CPU.

### Implementation

```clojure
(ns lab-6-1-scheduler-tracer
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.asm-dsl :refer :all]))

(def TASK_RUNNING 0)
(def TASK_INTERRUPTIBLE 1)
(def TASK_UNINTERRUPTIBLE 2)

;; Tracepoint context offsets for sched_switch
(def SCHED_SWITCH_OFFSETS
  {:prev-comm 8    ; char[16]
   :prev-pid 24    ; pid_t (4 bytes)
   :prev-prio 28   ; int (4 bytes)
   :prev-state 32  ; long (8 bytes)
   :next-comm 40   ; char[16]
   :next-pid 56    ; pid_t (4 bytes)
   :next-prio 60}) ; int (4 bytes)

(defn create-context-switch-counter
  "Count context switches per CPU"
  [counters-fd]
  (bpf/assemble
    (vec (concat
      ;; Get CPU ID as key
      (bpf/helper-get-smp-processor-id)
      [(bpf/mov-reg :r6 :r0)]  ; r6 = CPU ID
      [(bpf/store-mem :w :r10 -4 :r6)]

      ;; Lookup current count for this CPU
      [(bpf/ld-map-fd :r1 counters-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If exists, increment
      [(bpf/jmp-imm :jeq :r0 0 :init)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]
      [(bpf/jmp :exit)]

      ;; :init - Initialize counter to 1
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -16 :r3)]
      [(bpf/ld-map-fd :r1 counters-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn run-context-switch-counter []
  (println "Creating per-CPU context switch counter...")

  ;; Create map: CPU ID -> count
  (let [counters-fd (bpf/create-map :hash
                                     {:key-size 4
                                      :value-size 8
                                      :max-entries 256})]

    ;; Load program
    (let [prog-bytes (create-context-switch-counter counters-fd)
          prog-fd (bpf/load-program prog-bytes :tracepoint)]

      ;; Attach to sched_switch tracepoint
      (let [link-fd (bpf/attach-tracepoint prog-fd "sched/sched_switch")]

        (println "Attached to sched/sched_switch")
        (println "Counting context switches per CPU for 10 seconds...")
        (println "Press Ctrl+C to stop\n")

        ;; Monitor for 10 seconds
        (Thread/sleep 10000)

        ;; Read and display results
        (println "\nContext Switches per CPU:")
        (println "CPU | Count")
        (println "----|-------")

        (let [num-cpus (.. Runtime getRuntime availableProcessors)]
          (doseq [cpu (range num-cpus)]
            (let [count (bpf/map-lookup counters-fd (int-array [cpu]))]
              (when count
                (println (format "%-3d | %d" cpu (aget count 0)))))))

        ;; Cleanup
        (bpf/detach-tracepoint link-fd)
        (bpf/close-program prog-fd)
        (bpf/close-map counters-fd)))))
```

### Expected Output

```
Creating per-CPU context switch counter...
Attached to sched/sched_switch
Counting context switches per CPU for 10 seconds...
Press Ctrl+C to stop

Context Switches per CPU:
CPU | Count
----|-------
0   | 15234
1   | 12891
2   | 18456
3   | 11234
4   | 16789
5   | 13567
6   | 14234
7   | 12456
```

## Part 2: Per-Process CPU Time Tracker

Now let's track how much CPU time each process gets.

### Strategy

1. Use `sched_switch` to track when processes start/stop running
2. Store timestamps when process starts running
3. Calculate runtime when process stops
4. Aggregate total CPU time per process

### Implementation

```clojure
(defn create-process-runtime-tracker
  "Track total CPU time per process"
  [start-times-fd runtime-fd]
  (bpf/assemble
    (vec (concat
      ;; r8 = ctx pointer (save for later)
      [(bpf/mov-reg :r8 :r1)]

      ;; Read next_pid (process being scheduled in)
      [(bpf/load-mem :w :r2 :r8 (:next-pid SCHED_SWITCH_OFFSETS))]
      [(bpf/mov-reg :r6 :r2)]  ; r6 = next_pid

      ;; Get current timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r7 :r0)]  ; r7 = current_time

      ;; Store start time for next_pid
      [(bpf/store-mem :w :r10 -4 :r6)]   ; key = next_pid
      [(bpf/store-mem :dw :r10 -16 :r7)] ; value = timestamp

      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]  ; BPF_ANY
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; Now handle prev_pid (process being scheduled out)
      [(bpf/load-mem :w :r2 :r8 (:prev-pid SCHED_SWITCH_OFFSETS))]
      [(bpf/mov-reg :r6 :r2)]  ; r6 = prev_pid

      ;; Lookup start time for prev_pid
      [(bpf/store-mem :w :r10 -24 :r6)]
      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If no start time, skip (process just started or we missed it)
      [(bpf/jmp-imm :jeq :r0 0 :exit)]

      ;; Calculate runtime: current_time - start_time
      [(bpf/load-mem :dw :r3 :r0 0)]  ; r3 = start_time
      [(bpf/sub-reg :r7 :r3)]         ; r7 = runtime (current - start)

      ;; Update total runtime for prev_pid
      [(bpf/store-mem :w :r10 -32 :r6)]  ; key = prev_pid
      [(bpf/ld-map-fd :r1 runtime-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If exists, add to existing runtime
      [(bpf/jmp-imm :jeq :r0 0 :init-runtime)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add-reg :r3 :r7)]  ; total += runtime
      [(bpf/store-mem :dw :r0 0 :r3)]
      [(bpf/jmp :cleanup)]

      ;; :init-runtime - First runtime entry
      [(bpf/store-mem :dw :r10 -40 :r7)]
      [(bpf/ld-map-fd :r1 runtime-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -40)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; :cleanup - Delete start_time entry for prev_pid
      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      (bpf/helper-map-delete-elem :r1 :r2)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn run-process-runtime-tracker []
  (println "Creating per-process CPU time tracker...")

  ;; Create maps
  (let [start-times-fd (bpf/create-map :hash
                                        {:key-size 4   ; PID
                                         :value-size 8  ; timestamp
                                         :max-entries 10240})
        runtime-fd (bpf/create-map :hash
                                    {:key-size 4   ; PID
                                     :value-size 8  ; total runtime (ns)
                                     :max-entries 10240})]

    ;; Load and attach program
    (let [prog-bytes (create-process-runtime-tracker start-times-fd runtime-fd)
          prog-fd (bpf/load-program prog-bytes :tracepoint)
          link-fd (bpf/attach-tracepoint prog-fd "sched/sched_switch")]

      (println "Tracking CPU time per process for 10 seconds...")
      (Thread/sleep 10000)

      ;; Read and sort by CPU time
      (println "\nTop 20 Processes by CPU Time:")
      (println "PID   | CPU Time (ms) | CPU %")
      (println "------|---------------|-------")

      ;; Get all PIDs and their runtimes
      (let [pid-runtimes (atom [])
            total-time 10000000000] ; 10 seconds in nanoseconds

        ;; Iterate through runtime map
        ;; (In real code, you'd use bpf/map-get-next-key to iterate)
        ;; For now, we'll check common PIDs
        (doseq [pid (range 1 10000)]
          (when-let [runtime (bpf/map-lookup runtime-fd (int-array [pid]))]
            (let [runtime-ns (aget runtime 0)
                  runtime-ms (/ runtime-ns 1000000.0)
                  cpu-pct (* 100.0 (/ runtime-ns total-time))]
              (swap! pid-runtimes conj [pid runtime-ns runtime-ms cpu-pct]))))

        ;; Sort by runtime (descending)
        (let [sorted (->> @pid-runtimes
                          (sort-by second >)
                          (take 20))]
          (doseq [[pid _ runtime-ms cpu-pct] sorted]
            (println (format "%-5d | %13.2f | %5.2f%%" pid runtime-ms cpu-pct)))))

      ;; Cleanup
      (bpf/detach-tracepoint link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map start-times-fd)
      (bpf/close-map runtime-fd))))
```

### Expected Output

```
Creating per-process CPU time tracker...
Tracking CPU time per process for 10 seconds...

Top 20 Processes by CPU Time:
PID   | CPU Time (ms) | CPU %
------|---------------|-------
1234  |       3456.78 | 34.57%
5678  |       2345.67 | 23.46%
9012  |       1234.56 |  12.35%
3456  |        987.65 |   9.88%
7890  |        765.43 |   7.65%
...
```

## Part 3: Complete Scheduler Monitor with Ring Buffer

Let's create a comprehensive monitor that reports scheduling events to userspace.

### Event Structure

```clojure
(defrecord SchedEvent
  [timestamp      ; When event occurred (ns)
   cpu-id         ; Which CPU
   prev-pid       ; Process being scheduled out
   prev-comm      ; Process name (16 bytes)
   prev-prio      ; Priority
   prev-state     ; Process state
   next-pid       ; Process being scheduled in
   next-comm      ; Process name
   next-prio      ; Priority
   runtime])      ; How long prev ran (ns)
```

### Implementation

```clojure
(def EVENT_SIZE 96) ; Size of SchedEvent structure

(defn create-scheduler-monitor
  "Comprehensive scheduler monitoring with events"
  [start-times-fd events-fd]
  (bpf/assemble
    (vec (concat
      ;; r8 = ctx pointer
      [(bpf/mov-reg :r8 :r1)]

      ;; Reserve space in ring buffer
      [(bpf/ld-map-fd :r1 events-fd)]
      [(bpf/mov :r2 EVENT_SIZE)]
      [(bpf/mov :r3 0)]
      (bpf/helper-ringbuf-reserve :r1 :r2)

      ;; Check allocation
      [(bpf/jmp-imm :jeq :r0 0 :exit)]
      [(bpf/mov-reg :r9 :r0)]  ; r9 = event pointer

      ;; Get timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/store-mem :dw :r9 0 :r0)]  ; event->timestamp

      ;; Get CPU ID
      (bpf/helper-get-smp-processor-id)
      [(bpf/store-mem :w :r9 8 :r0)]   ; event->cpu_id

      ;; Read prev_pid
      [(bpf/load-mem :w :r2 :r8 (:prev-pid SCHED_SWITCH_OFFSETS))]
      [(bpf/store-mem :w :r9 12 :r2)]  ; event->prev_pid
      [(bpf/mov-reg :r6 :r2)]          ; r6 = prev_pid for later

      ;; Copy prev_comm (16 bytes)
      [(bpf/mov-reg :r1 :r9)]
      [(bpf/add :r1 16)]               ; dst = &event->prev_comm
      [(bpf/mov-reg :r2 :r8)]
      [(bpf/add :r2 (:prev-comm SCHED_SWITCH_OFFSETS))] ; src
      [(bpf/mov :r3 16)]               ; size
      (bpf/helper-probe-read :r1 :r2 :r3)

      ;; Read prev_prio
      [(bpf/load-mem :w :r2 :r8 (:prev-prio SCHED_SWITCH_OFFSETS))]
      [(bpf/store-mem :w :r9 32 :r2)]  ; event->prev_prio

      ;; Read prev_state
      [(bpf/load-mem :dw :r2 :r8 (:prev-state SCHED_SWITCH_OFFSETS))]
      [(bpf/store-mem :dw :r9 36 :r2)] ; event->prev_state

      ;; Read next_pid
      [(bpf/load-mem :w :r2 :r8 (:next-pid SCHED_SWITCH_OFFSETS))]
      [(bpf/store-mem :w :r9 44 :r2)]  ; event->next_pid
      [(bpf/mov-reg :r7 :r2)]          ; r7 = next_pid for later

      ;; Copy next_comm (16 bytes)
      [(bpf/mov-reg :r1 :r9)]
      [(bpf/add :r1 48)]               ; dst = &event->next_comm
      [(bpf/mov-reg :r2 :r8)]
      [(bpf/add :r2 (:next-comm SCHED_SWITCH_OFFSETS))] ; src
      [(bpf/mov :r3 16)]
      (bpf/helper-probe-read :r1 :r2 :r3)

      ;; Read next_prio
      [(bpf/load-mem :w :r2 :r8 (:next-prio SCHED_SWITCH_OFFSETS))]
      [(bpf/store-mem :w :r9 64 :r2)]  ; event->next_prio

      ;; Calculate runtime for prev process
      ;; Lookup start time
      [(bpf/store-mem :w :r10 -4 :r6)]  ; key = prev_pid
      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If found, calculate runtime
      [(bpf/jmp-imm :jeq :r0 0 :no-runtime)]
      [(bpf/load-mem :dw :r3 :r0 0)]    ; start_time
      [(bpf/load-mem :dw :r4 :r9 0)]    ; current_time (timestamp)
      [(bpf/sub-reg :r4 :r3)]           ; runtime = current - start
      [(bpf/store-mem :dw :r9 68 :r4)]  ; event->runtime
      [(bpf/jmp :update-start)]

      ;; :no-runtime
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :dw :r9 68 :r4)]  ; event->runtime = 0

      ;; :update-start - Store new start time for next_pid
      [(bpf/load-mem :dw :r4 :r9 0)]    ; timestamp
      [(bpf/store-mem :w :r10 -8 :r7)]  ; key = next_pid
      [(bpf/store-mem :dw :r10 -16 :r4)] ; value = timestamp

      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; Submit event
      [(bpf/mov-reg :r1 :r9)]
      [(bpf/mov :r2 0)]  ; flags
      (bpf/helper-ringbuf-submit :r1)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn parse-sched-event [byte-array]
  "Parse SchedEvent from byte array"
  (let [bb (java.nio.ByteBuffer/wrap byte-array)]
    (.order bb java.nio.ByteOrder/LITTLE_ENDIAN)
    {:timestamp (.getLong bb)
     :cpu-id (.getInt bb)
     :prev-pid (.getInt bb)
     :prev-comm (String. byte-array 16 16).trim
     :prev-prio (.getInt bb)
     :prev-state (.getLong bb)
     :next-pid (.getInt bb)
     :next-comm (String. byte-array 48 16).trim
     :next-prio (.getInt bb)
     :runtime (.getLong bb)}))

(defn run-scheduler-monitor []
  (println "Creating comprehensive scheduler monitor...")

  (let [start-times-fd (bpf/create-map :hash
                                        {:key-size 4
                                         :value-size 8
                                         :max-entries 10240})
        events-fd (bpf/create-map :ringbuf
                                   {:max-entries (* 256 1024)})] ; 256 KB

    (let [prog-bytes (create-scheduler-monitor start-times-fd events-fd)
          prog-fd (bpf/load-program prog-bytes :tracepoint)
          link-fd (bpf/attach-tracepoint prog-fd "sched/sched_switch")]

      (println "Monitoring scheduler events...")
      (println "Press Ctrl+C to stop\n")
      (println "TIME(ms) | CPU | PREV                          | NEXT")
      (println "---------|-----|-------------------------------|-------------------------------")

      ;; Poll ring buffer
      (let [running (atom true)
            start-time (System/nanoTime)]

        ;; Setup Ctrl+C handler
        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        ;; Poll loop
        (while @running
          (when-let [events (bpf/ringbuf-poll events-fd 100)] ; 100ms timeout
            (doseq [event-bytes events]
              (let [event (parse-sched-event event-bytes)
                    elapsed-ms (/ (- (:timestamp event) start-time) 1000000.0)
                    runtime-us (/ (:runtime event) 1000.0)]
                (println (format "%8.2f | %3d | %-12s [%5d] (%6.1fus) | %-12s [%5d]"
                                elapsed-ms
                                (:cpu-id event)
                                (:prev-comm event)
                                (:prev-pid event)
                                runtime-us
                                (:next-comm event)
                                (:next-pid event)))))))

        ;; Cleanup
        (bpf/detach-tracepoint link-fd)
        (bpf/close-program prog-fd)
        (bpf/close-map start-times-fd)
        (bpf/close-map events-fd)))))
```

### Expected Output

```
Creating comprehensive scheduler monitor...
Monitoring scheduler events...
Press Ctrl+C to stop

TIME(ms) | CPU | PREV                          | NEXT
---------|-----|-------------------------------|-------------------------------
    0.45 |   0 | firefox      [ 1234] ( 125.4us) | Xorg         [ 5678]
    0.67 |   1 | java         [ 9012] ( 234.5us) | systemd      [    1]
    1.23 |   0 | Xorg         [ 5678] (  45.2us) | kworker      [ 3456]
    1.45 |   2 | bash         [ 7890] ( 156.7us) | sshd         [ 2345]
    2.34 |   1 | systemd      [    1] (  12.3us) | java         [ 9012]
    2.56 |   0 | kworker      [ 3456] (  78.9us) | firefox      [ 1234]
...
```

## Exercises

### Exercise 1: Voluntary vs Involuntary Context Switches

Modify the monitor to distinguish between:
- **Voluntary**: Process voluntarily gave up CPU (sleeping, waiting for I/O)
- **Involuntary**: Process was preempted (time slice expired)

**Hint**: Check `prev_state`. If `prev_state == TASK_RUNNING`, it's involuntary.

### Exercise 2: CPU Affinity Tracker

Track which CPUs each process runs on:
- Build a bitmap of CPUs for each PID
- Detect processes that migrate frequently
- Calculate CPU affinity score

### Exercise 3: Scheduling Latency

Measure scheduling latency:
- Use `sched_wakeup` to mark when process becomes runnable
- Use `sched_switch` to mark when it actually runs
- Calculate: latency = run_time - wakeup_time

### Exercise 4: Priority Inversion Detection

Detect priority inversion scenarios:
- High-priority process waiting
- Low-priority process running
- Alert when this condition persists

## Summary

In this lab, you learned:
- How to attach BPF programs to tracepoints
- Parsing tracepoint context structures
- Tracking scheduling events and CPU time
- Using ring buffers for high-frequency events
- Correlating entry and exit events

## Navigation

- **Next**: [Lab 6.2 - Block I/O Latency Monitor](lab-6-2-block-io-monitor.md)
- **Previous**: [Chapter 6 Overview](../README.md)
- **Home**: [Tutorial Home](../../../README.md)
