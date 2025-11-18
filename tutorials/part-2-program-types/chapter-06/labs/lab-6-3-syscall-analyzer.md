# Lab 6.3: System Call Frequency Analyzer

**Duration**: 45-60 minutes | **Difficulty**: Intermediate

## Learning Objectives

In this lab, you will:
- Use syscall tracepoints for system-wide monitoring
- Track syscall frequency across all processes
- Analyze per-process syscall patterns
- Measure syscall latency distributions
- Detect anomalous syscall behavior
- Build a comprehensive syscall profiler

## Prerequisites

- Completed [Lab 6.2](lab-6-2-block-io-monitor.md)
- Understanding of Linux system calls
- Familiarity with syscall semantics

## Introduction

System calls are the primary interface between user applications and the kernel. Monitoring syscall patterns provides insights into:
- Application behavior
- Performance bottlenecks
- Security incidents
- Resource usage patterns

The `syscalls` tracepoint category provides entry and exit tracepoints for all system calls.

## Syscall Tracepoint Format

### Generic Entry Format

All `sys_enter_*` tracepoints share a common format:

```bash
$ sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format

name: sys_enter_read
ID: 622
format:
    field:unsigned short common_type;      offset:0;  size:2;
    field:unsigned char common_flags;      offset:2;  size:1;
    field:unsigned char common_preempt_count; offset:3; size:1;
    field:int common_pid;                  offset:4;  size:4;

    field:int __syscall_nr;                offset:8;  size:4;
    field:unsigned int fd;                 offset:16; size:8;
    field:char * buf;                      offset:24; size:8;
    field:size_t count;                    offset:32; size:8;
```

### Generic Exit Format

All `sys_exit_*` tracepoints share a common format:

```bash
$ sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format

name: sys_exit_read
ID: 621
format:
    field:unsigned short common_type;      offset:0;  size:2;
    field:unsigned char common_flags;      offset:2;  size:1;
    field:unsigned char common_preempt_count; offset:3; size:1;
    field:int common_pid;                  offset:4;  size:4;

    field:int __syscall_nr;                offset:8;  size:4;
    field:long ret;                        offset:16; size:8;
```

**Key Fields**:
- `__syscall_nr`: System call number
- `ret`: Return value (in exit tracepoint)
- Arguments: Syscall-specific (in entry tracepoint)

## Part 1: Global Syscall Frequency Counter

Let's start by counting how often each syscall is called system-wide.

### Implementation

```clojure
(ns lab-6-3-syscall-analyzer
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.asm-dsl :refer :all]))

;; Common offsets for all syscall tracepoints
(def SYSCALL_ENTER_OFFSETS
  {:syscall-nr 8   ; int (4 bytes)
   :arg0 16        ; First argument varies by syscall
   :arg1 24
   :arg2 32
   :arg3 40
   :arg4 48
   :arg5 56})

(def SYSCALL_EXIT_OFFSETS
  {:syscall-nr 8   ; int (4 bytes)
   :ret 16})       ; long (8 bytes)

;; Common syscall numbers (x86_64)
(def SYSCALL_NUMBERS
  {:read 0
   :write 1
   :open 2
   :close 3
   :stat 4
   :fstat 5
   :lstat 6
   :poll 7
   :lseek 8
   :mmap 9
   :mprotect 10
   :munmap 11
   :brk 12
   :rt-sigaction 13
   :rt-sigprocmask 14
   :ioctl 16
   :pread64 17
   :pwrite64 18
   :readv 19
   :writev 20
   :access 21
   :pipe 22
   :select 23
   :sched-yield 24
   :mremap 25
   :msync 26
   :dup 32
   :dup2 33
   :getpid 39
   :socket 41
   :connect 42
   :accept 43
   :sendto 44
   :recvfrom 45
   :bind 49
   :listen 50
   :clone 56
   :fork 57
   :vfork 58
   :execve 59
   :exit 60
   :wait4 61
   :kill 62
   :fcntl 72
   :getdents 78
   :getcwd 79
   :chdir 80
   :rename 82
   :mkdir 83
   :rmdir 84
   :unlink 87
   :readlink 89
   :gettimeofday 96
   :getuid 102
   :getgid 104
   :setuid 105
   :setgid 106
   :openat 257})

(def SYSCALL_NAMES
  (into {} (map (fn [[k v]] [v (name k)]) SYSCALL_NUMBERS)))

(defn create-syscall-counter
  "Count occurrences of each syscall"
  [counts-fd]
  (bpf/assemble
    (vec (concat
      ;; r8 = ctx pointer
      [(bpf/mov-reg :r8 :r1)]

      ;; Read syscall number
      [(bpf/load-mem :w :r6 :r8 (:syscall-nr SYSCALL_ENTER_OFFSETS))]

      ;; Use syscall number as key
      [(bpf/store-mem :w :r10 -4 :r6)]

      ;; Lookup current count
      [(bpf/ld-map-fd :r1 counts-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If exists, increment
      [(bpf/jmp-imm :jeq :r0 0 :init)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]
      [(bpf/jmp :exit)]

      ;; :init - First occurrence
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -16 :r3)]
      [(bpf/ld-map-fd :r1 counts-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn run-syscall-frequency-counter []
  (println "Creating global syscall frequency counter...")

  ;; Map: syscall_nr -> count
  (let [counts-fd (bpf/create-map :hash
                                   {:key-size 4
                                    :value-size 8
                                    :max-entries 512})]

    ;; Load program
    (let [prog-bytes (create-syscall-counter counts-fd)
          prog-fd (bpf/load-program prog-bytes :tracepoint)]

      ;; Attach to raw_syscalls:sys_enter
      ;; This catches ALL syscalls with a single tracepoint
      (let [link-fd (bpf/attach-tracepoint prog-fd "raw_syscalls/sys_enter")]

        (println "Counting syscalls for 10 seconds...")
        (println "Generate activity in another terminal\n")

        (Thread/sleep 10000)

        ;; Read and display top syscalls
        (println "\nTop 20 System Calls by Frequency:")
        (println "Syscall Number | Name              | Count      | % of Total")
        (println "---------------|-------------------|------------|------------")

        (let [syscall-counts (atom [])
              total (atom 0)]

          ;; Collect all counts
          (doseq [syscall-nr (range 512)]
            (when-let [count (bpf/map-lookup counts-fd (int-array [syscall-nr]))]
              (let [cnt (aget count 0)]
                (swap! total + cnt)
                (swap! syscall-counts conj [syscall-nr cnt]))))

          ;; Sort by count (descending) and take top 20
          (let [sorted (->> @syscall-counts
                            (sort-by second >)
                            (take 20))]
            (doseq [[syscall-nr cnt] sorted]
              (let [name (get SYSCALL_NAMES syscall-nr (format "syscall_%d" syscall-nr))
                    pct (* 100.0 (/ cnt @total))]
                (println (format "%-14d | %-17s | %10d | %5.1f%%"
                                syscall-nr name cnt pct)))))

          (println (format "\nTotal syscalls: %d" @total)))

        ;; Cleanup
        (bpf/detach-tracepoint link-fd)
        (bpf/close-program prog-fd)
        (bpf/close-map counts-fd)))))
```

### Expected Output

```
Creating global syscall frequency counter...
Counting syscalls for 10 seconds...
Generate activity in another terminal

Top 20 System Calls by Frequency:
Syscall Number | Name              | Count      | % of Total
---------------|-------------------|------------|------------
0              | read              |      45678 |  32.5%
1              | write             |      23456 |  16.7%
7              | poll              |      15234 |  10.8%
14             | rt-sigprocmask    |      12345 |   8.8%
16             | ioctl             |       9876 |   7.0%
72             | fcntl             |       6789 |   4.8%
13             | rt-sigaction      |       5432 |   3.9%
3              | close             |       4567 |   3.3%
257            | openat            |       3456 |   2.5%
9              | mmap              |       2345 |   1.7%
11             | munmap            |       2134 |   1.5%
...

Total syscalls: 140578
```

## Part 2: Per-Process Syscall Profiler

Now let's track which processes make which syscalls.

### Implementation

```clojure
(defn create-per-process-syscall-tracker
  "Track syscalls per process"
  [profile-fd]
  (bpf/assemble
    (vec (concat
      ;; r8 = ctx pointer
      [(bpf/mov-reg :r8 :r1)]

      ;; Get PID
      (bpf/helper-get-current-pid-tgid)
      [(bpf/rsh :r0 32)]  ; Extract TGID
      [(bpf/mov-reg :r6 :r0)]  ; r6 = PID

      ;; Read syscall number
      [(bpf/load-mem :w :r7 :r8 (:syscall-nr SYSCALL_ENTER_OFFSETS))]

      ;; Create composite key: (PID << 16) | syscall_nr
      ;; This allows up to 64K PIDs and 64K syscalls
      [(bpf/lsh :r6 16)]
      [(bpf/or-reg :r6 :r7)]  ; key = (PID << 16) | syscall_nr

      [(bpf/store-mem :dw :r10 -8 :r6)]

      ;; Lookup and increment
      [(bpf/ld-map-fd :r1 profile-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :init)]
      [(bpf/load-mem :dw :r3 :r0 0)]
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]
      [(bpf/jmp :exit)]

      ;; :init
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -16 :r3)]
      [(bpf/ld-map-fd :r1 profile-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn decode-composite-key [key]
  "Decode composite key into [PID syscall-nr]"
  (let [pid (bit-shift-right key 16)
        syscall-nr (bit-and key 0xFFFF)]
    [pid syscall-nr]))

(defn get-process-name [pid]
  "Get process name from /proc/PID/comm"
  (try
    (slurp (format "/proc/%d/comm" pid))
    (catch Exception _ (format "PID_%d" pid))))

(defn run-per-process-profiler []
  (println "Creating per-process syscall profiler...")

  (let [profile-fd (bpf/create-map :hash
                                    {:key-size 8   ; composite key
                                     :value-size 8  ; count
                                     :max-entries 100000})]

    (let [prog-bytes (create-per-process-syscall-tracker profile-fd)
          prog-fd (bpf/load-program prog-bytes :tracepoint)
          link-fd (bpf/attach-tracepoint prog-fd "raw_syscalls/sys_enter")]

      (println "Profiling syscalls per process for 10 seconds...\n")
      (Thread/sleep 10000)

      ;; Collect and organize data
      (let [process-profiles (atom {})]

        ;; Collect all entries
        ;; In real code, iterate with bpf_map_get_next_key
        ;; For demo, we'll check a range
        (doseq [pid (range 1 10000)
                syscall-nr (range 512)]
          (let [composite-key (bit-or (bit-shift-left pid 16) syscall-nr)]
            (when-let [count (bpf/map-lookup profile-fd (long-array [composite-key]))]
              (let [cnt (aget count 0)]
                (when (> cnt 0)
                  (swap! process-profiles update pid
                         (fnil conj []) [syscall-nr cnt]))))))

        ;; Display top processes
        (println "Top 10 Processes by Syscall Activity:")
        (println "=====================================\n")

        (let [process-totals (->> @process-profiles
                                   (map (fn [[pid calls]]
                                          [pid (reduce + (map second calls))]))
                                   (sort-by second >)
                                   (take 10))]

          (doseq [[pid total] process-totals]
            (let [comm (.trim (get-process-name pid))
                  calls (get @process-profiles pid)]

              (println (format "PID %d (%s) - %d total syscalls"
                              pid comm total))

              ;; Show top 5 syscalls for this process
              (let [top-calls (->> calls
                                    (sort-by second >)
                                    (take 5))]
                (doseq [[syscall-nr cnt] top-calls]
                  (let [name (get SYSCALL_NAMES syscall-nr
                                  (format "syscall_%d" syscall-nr))
                        pct (* 100.0 (/ cnt total))]
                    (println (format "  %-20s: %8d (%5.1f%%)"
                                    name cnt pct)))))
              (println)))))

      ;; Cleanup
      (bpf/detach-tracepoint link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map profile-fd))))
```

### Expected Output

```
Creating per-process syscall profiler...
Profiling syscalls per process for 10 seconds...

Top 10 Processes by Syscall Activity:
=====================================

PID 1234 (firefox) - 23456 total syscalls
  poll                :    12345 ( 52.6%)
  read                :     5678 ( 24.2%)
  write               :     3456 ( 14.7%)
  recvfrom            :     1234 (  5.3%)
  sendto              :      743 (  3.2%)

PID 5678 (java) - 18934 total syscalls
  read                :     8765 ( 46.3%)
  write               :     4321 ( 22.8%)
  mmap                :     2345 ( 12.4%)
  futex               :     1876 (  9.9%)
  rt-sigprocmask      :     1627 (  8.6%)

PID 9012 (postgres) - 15678 total syscalls
  read                :     7890 ( 50.3%)
  write               :     4567 ( 29.1%)
  lseek               :     2345 ( 15.0%)
  fsync               :      876 (  5.6%)

...
```

## Part 3: Syscall Latency Analyzer

Let's measure how long syscalls take to execute.

### Implementation

```clojure
(defn create-syscall-entry-handler
  "Record syscall entry timestamp"
  [start-times-fd]
  (bpf/assemble
    (vec (concat
      ;; Get PID
      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r6 :r0)]  ; r6 = full 64-bit (PID|TID)

      ;; Get timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r7 :r0)]

      ;; Store in map[PID|TID] = timestamp
      [(bpf/store-mem :dw :r10 -8 :r6)]
      [(bpf/store-mem :dw :r10 -16 :r7)]

      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn create-syscall-exit-handler
  "Calculate syscall latency"
  [start-times-fd latency-fd]
  (bpf/assemble
    (vec (concat
      ;; r8 = ctx
      [(bpf/mov-reg :r8 :r1)]

      ;; Get PID
      (bpf/helper-get-current-pid-tgid)
      [(bpf/mov-reg :r6 :r0)]

      ;; Get current time
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]  ; r9 = end_time

      ;; Lookup start time
      [(bpf/store-mem :dw :r10 -8 :r6)]
      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If not found, exit
      [(bpf/jmp-imm :jeq :r0 0 :exit)]

      ;; Calculate latency
      [(bpf/load-mem :dw :r3 :r0 0)]  ; start_time
      [(bpf/sub-reg :r9 :r3)]         ; latency = end - start
      [(bpf/mov-reg :r7 :r9)]

      ;; Read syscall number
      [(bpf/load-mem :w :r5 :r8 (:syscall-nr SYSCALL_EXIT_OFFSETS))]

      ;; Update latency stats for this syscall
      ;; Map value: {count, total_latency, max_latency}
      [(bpf/store-mem :w :r10 -16 :r5)]
      [(bpf/ld-map-fd :r1 latency-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -16)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :init-latency)]

      ;; Update existing
      [(bpf/load-mem :dw :r3 :r0 0)]  ; count
      [(bpf/add :r3 1)]
      [(bpf/store-mem :dw :r0 0 :r3)]

      [(bpf/load-mem :dw :r3 :r0 8)]  ; total
      [(bpf/add-reg :r3 :r7)]
      [(bpf/store-mem :dw :r0 8 :r3)]

      [(bpf/load-mem :dw :r3 :r0 16)] ; max
      [(bpf/jmp-reg :jge :r3 :r7 :cleanup)]
      [(bpf/store-mem :dw :r0 16 :r7)]
      [(bpf/jmp :cleanup)]

      ;; :init-latency
      [(bpf/mov :r3 1)]
      [(bpf/store-mem :dw :r10 -24 :r3)]  ; count = 1
      [(bpf/store-mem :dw :r10 -32 :r7)]  ; total = latency
      [(bpf/store-mem :dw :r10 -40 :r7)]  ; max = latency

      [(bpf/ld-map-fd :r1 latency-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -16)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -40)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; :cleanup - Delete start time
      [(bpf/ld-map-fd :r1 start-times-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-delete-elem :r1 :r2)

      ;; :exit
      [(bpf/mov :r0 0)]
      [(bpf/exit-insn)]))))

(defn run-syscall-latency-analyzer []
  (println "Creating syscall latency analyzer...")

  (let [start-times-fd (bpf/create-map :hash
                                        {:key-size 8
                                         :value-size 8
                                         :max-entries 10240})
        latency-fd (bpf/create-map :hash
                                    {:key-size 4
                                     :value-size 24  ; count, total, max
                                     :max-entries 512})]

    (let [entry-prog (create-syscall-entry-handler start-times-fd)
          exit-prog (create-syscall-exit-handler start-times-fd latency-fd)

          entry-fd (bpf/load-program entry-prog :tracepoint)
          exit-fd (bpf/load-program exit-prog :tracepoint)

          entry-link (bpf/attach-tracepoint entry-fd "raw_syscalls/sys_enter")
          exit-link (bpf/attach-tracepoint exit-fd "raw_syscalls/sys_exit")]

      (println "Measuring syscall latency for 10 seconds...\n")
      (Thread/sleep 10000)

      (println "Syscall Latency Statistics:")
      (println "Syscall          | Count      | Avg (μs) | Max (μs)  | Total (ms)")
      (println "-----------------|------------|----------|-----------|------------")

      (let [latencies (atom [])]

        ;; Collect all latency data
        (doseq [syscall-nr (range 512)]
          (when-let [stats (bpf/map-lookup latency-fd (int-array [syscall-nr]))]
            (let [count (aget stats 0)
                  total (aget stats 1)
                  max-lat (aget stats 2)]
              (when (> count 0)
                (swap! latencies conj
                       [syscall-nr count total max-lat])))))

        ;; Sort by total latency (most time spent)
        (let [sorted (->> @latencies
                          (sort-by #(nth % 2) >)
                          (take 20))]
          (doseq [[syscall-nr count total max-lat] sorted]
            (let [name (get SYSCALL_NAMES syscall-nr
                            (format "syscall_%d" syscall-nr))
                  avg-us (/ (/ total count) 1000.0)
                  max-us (/ max-lat 1000.0)
                  total-ms (/ total 1000000.0)]
              (println (format "%-16s | %10d | %8.2f | %9.2f | %10.2f"
                              name count avg-us max-us total-ms))))))

      ;; Cleanup
      (bpf/detach-tracepoint entry-link)
      (bpf/detach-tracepoint exit-link)
      (bpf/close-program entry-fd)
      (bpf/close-program exit-fd)
      (bpf/close-map start-times-fd)
      (bpf/close-map latency-fd))))
```

### Expected Output

```
Creating syscall latency analyzer...
Measuring syscall latency for 10 seconds...

Syscall Latency Statistics:
Syscall          | Count      | Avg (μs) | Max (μs)  | Total (ms)
-----------------|------------|----------|-----------|------------
read             |      45678 |     4.56 |    234.56 |     208.39
write            |      23456 |     3.21 |    156.78 |      75.30
poll             |      15234 |     2.34 |     45.67 |      35.65
ioctl            |       9876 |     1.23 |     12.34 |      12.15
recvfrom         |       8765 |     5.67 |    345.67 |      49.70
sendto           |       7654 |     4.32 |    234.56 |      33.07
openat           |       3456 |     8.90 |    567.89 |      30.76
close            |       4567 |     1.11 |     23.45 |       5.07
stat             |       2345 |     6.78 |    123.45 |      15.90
mmap             |       2345 |     2.34 |     34.56 |       5.49
...
```

## Exercises

### Exercise 1: Error Rate Tracking

Modify the analyzer to track syscall error rates:
- Count failed syscalls (ret < 0)
- Calculate error percentage per syscall
- Detect processes with high error rates

### Exercise 2: Argument Analysis

Analyze specific syscall arguments:
- Track file descriptor usage (read/write)
- Monitor file paths (open/openat)
- Analyze signal numbers (kill)
- Track network addresses (connect/accept)

### Exercise 3: Security Monitoring

Build a security monitor that detects:
- Privilege escalation attempts (setuid/setgid)
- Suspicious execve patterns
- Unusual syscall sequences
- Abnormal syscall frequencies

### Exercise 4: Application Profiler

Create an application-specific profiler:
- Filter by specific PID or process name
- Track syscall call stacks
- Correlate syscalls with application phases
- Generate flame graphs

## Summary

In this lab, you learned:
- How to use syscall tracepoints for system-wide monitoring
- Tracking syscall frequency and patterns
- Measuring syscall latency distributions
- Per-process syscall profiling
- Building comprehensive syscall analyzers

## Navigation

- **Next**: [Chapter 7 - XDP](../../chapter-07/README.md)
- **Previous**: [Lab 6.2 - Block I/O Monitor](lab-6-2-block-io-monitor.md)
- **Home**: [Tutorial Home](../../../README.md)
