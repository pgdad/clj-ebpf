# Chapter 18 Labs: Performance Profiler

## Overview

These labs guide you through building a comprehensive performance profiler
using perf events, kprobes, and stack traces.

## Lab 18.1: CPU Profiling and Flamegraphs

**Objective**: Implement CPU sampling and flamegraph generation.

Build a profiler that:
- Samples CPU at configurable frequency
- Captures user and kernel stack traces
- Aggregates samples by stack
- Generates flamegraph-compatible output

## Lab 18.2: Memory Allocation Tracking

**Objective**: Implement memory allocation profiling.

Build a memory profiler that:
- Tracks allocation sizes and call sites
- Identifies memory-heavy code paths
- Detects potential memory leaks
- Reports allocation statistics

## Lab 18.3: I/O Latency Analysis

**Objective**: Implement I/O latency profiling.

Build an I/O profiler that:
- Measures block I/O latency
- Generates latency histograms
- Identifies slow I/O operations
- Calculates percentiles (p50, p90, p99)

## Running the Labs

```bash
cd solutions
clojure -M -m lab-18-1-cpu-profiling test
clojure -M -m lab-18-2-memory-tracking test
clojure -M -m lab-18-3-io-latency test
```
