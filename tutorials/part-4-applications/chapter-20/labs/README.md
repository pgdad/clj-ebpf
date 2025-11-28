# Chapter 20 Labs: Database Query Analyzer

## Overview

These labs guide you through building a database query analyzer that captures
and analyzes SQL queries without modifying application code.

## Lab 20.1: Query Capture and Parsing

**Objective**: Implement query capture and normalization.

Build a query capture system that:
- Captures SQL queries from applications
- Parses query structure (SELECT, INSERT, UPDATE, DELETE)
- Normalizes queries by replacing literals with placeholders
- Extracts table and column references

## Lab 20.2: Query Statistics

**Objective**: Implement query performance statistics.

Build a statistics system that:
- Tracks query execution times
- Calculates min/max/avg/p99 latencies
- Groups statistics by normalized query
- Identifies slow queries

## Lab 20.3: N+1 Detection

**Objective**: Detect N+1 query patterns.

Build a detection system that:
- Identifies repeated similar queries
- Detects N+1 query patterns
- Calculates query frequency in time windows
- Suggests optimization strategies

## Running the Labs

```bash
cd solutions
clojure -M -m lab-20-1-query-capture test
clojure -M -m lab-20-2-query-statistics test
clojure -M -m lab-20-3-n-plus-one test
```
