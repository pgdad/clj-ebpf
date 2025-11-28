# Chapter 22 Labs: Chaos Engineering Platform

## Overview

These labs guide you through building a chaos engineering platform that
safely injects faults to test system resilience.

## Lab 22.1: Experiment Definition

**Objective**: Implement chaos experiment definition and validation.

Build an experiment system that:
- Defines chaos experiments with hypotheses
- Specifies fault types and parameters
- Sets blast radius limits
- Validates experiment configuration

## Lab 22.2: Fault Injection

**Objective**: Implement fault injection mechanisms.

Build fault injectors that:
- Inject network latency and packet loss
- Simulate CPU and memory pressure
- Control fault intensity and duration
- Provide safe abort mechanisms

## Lab 22.3: SLO Monitoring

**Objective**: Implement SLO monitoring with automatic rollback.

Build a monitoring system that:
- Tracks SLO metrics during experiments
- Detects SLO violations
- Triggers automatic rollback
- Records experiment results

## Running the Labs

```bash
cd solutions
clojure -M -m lab-22-1-experiment-definition test
clojure -M -m lab-22-2-fault-injection test
clojure -M -m lab-22-3-slo-monitoring test
```
