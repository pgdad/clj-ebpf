# Chapter 19 Labs: Distributed Tracing

## Overview

These labs guide you through building an automatic distributed tracing system
that traces requests across services without code changes.

## Lab 19.1: Span Management

**Objective**: Implement span creation and management for distributed traces.

Build a span management system that:
- Creates unique trace and span IDs
- Manages parent-child span relationships
- Tracks span timing (start, end, duration)
- Supports span tags and logs

## Lab 19.2: Trace Context Propagation

**Objective**: Implement trace context propagation between services.

Build a context propagation system that:
- Extracts trace context from incoming requests
- Injects trace context into outgoing requests
- Supports W3C Trace Context format
- Handles missing or invalid context

## Lab 19.3: Service Dependency Graph

**Objective**: Build a service dependency graph from trace data.

Build a dependency tracking system that:
- Records service-to-service calls
- Calculates latency statistics
- Generates dependency graph visualization
- Detects circular dependencies

## Running the Labs

```bash
cd solutions
clojure -M -m lab-19-1-span-management test
clojure -M -m lab-19-2-trace-context test
clojure -M -m lab-19-3-service-graph test
```
