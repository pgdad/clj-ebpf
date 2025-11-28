# Chapter 15 Labs: System Call Tracer

## Overview

These labs guide you through building a production-ready system call tracer
that captures syscall entry and exit events, logs arguments and return values,
and provides flexible filtering.

## Lab 15.1: Syscall Event Capture

**Objective**: Implement basic syscall event capture and formatting.

Build a system that:
- Captures syscall entry events (PID, syscall number, arguments)
- Captures syscall exit events (return value, duration)
- Correlates entry and exit events by thread ID
- Formats events for human-readable output

**Key Concepts**:
- Tracepoint programs for raw_syscalls/sys_enter and sys_exit
- Using maps to track active syscalls
- Event correlation using thread ID
- Timestamp calculation for duration

## Lab 15.2: Syscall Filtering

**Objective**: Implement configurable syscall filtering.

Build a filtering system that:
- Filters by PID (trace specific process)
- Filters by UID (trace specific user)
- Filters by syscall number (trace specific syscalls)
- Supports include and exclude lists
- Provides minimum duration filtering

**Key Concepts**:
- Configuration maps updated from userspace
- Bitmask filtering for syscall selection
- Dynamic filter updates without program reload

## Lab 15.3: Syscall Statistics and Aggregation

**Objective**: Implement syscall statistics collection and reporting.

Build a statistics system that:
- Counts syscalls per type
- Tracks total and average duration per syscall
- Counts errors (negative return values)
- Identifies top syscalls by count and latency
- Provides per-process statistics

**Key Concepts**:
- Per-CPU arrays for lock-free counting
- Aggregating statistics across CPUs
- Histogram buckets for latency distribution
- Periodic statistics export

## Running the Labs

```bash
cd solutions
clojure -M -m lab-15-1-syscall-capture test     # Run Lab 15.1 tests
clojure -M -m lab-15-2-syscall-filtering test   # Run Lab 15.2 tests
clojure -M -m lab-15-3-syscall-statistics test  # Run Lab 15.3 tests
```

## Solutions

Complete solutions are available in the `solutions/` directory.
