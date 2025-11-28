# Chapter 24 Labs: Troubleshooting Guide

## Overview

These labs guide you through practical troubleshooting scenarios for
BPF programs in production environments.

## Lab 24.1: Verifier Error Handling

**Objective**: Learn to diagnose and fix common verifier rejections.

Practice troubleshooting:
- Unbounded loop errors
- Invalid memory access errors
- Stack overflow errors
- Uninitialized register errors

## Lab 24.2: Map Diagnostics

**Objective**: Debug map-related issues.

Build diagnostic tools that:
- Check map capacity and usage
- Detect map lookup failures
- Identify key size mismatches
- Monitor per-CPU map aggregation

## Lab 24.3: Performance Debugging

**Objective**: Debug performance issues in BPF programs.

Build performance tools that:
- Measure BPF program overhead
- Identify hot code paths
- Optimize map access patterns
- Implement sampling strategies

## Running the Labs

```bash
cd solutions
clojure -M -m lab-24-1-verifier-errors test
clojure -M -m lab-24-2-map-diagnostics test
clojure -M -m lab-24-3-performance test
```
