# Chapter 17 Labs: Container Security Monitor

## Overview

These labs guide you through building a container security monitoring system
using LSM hooks and cgroup programs.

## Lab 17.1: Container Policy Engine

**Objective**: Implement a per-container security policy system.

Build a policy engine that:
- Defines security policies per container (cgroup ID)
- Specifies allowed syscalls, capabilities, and network rules
- Supports policy inheritance and override
- Provides policy validation

## Lab 17.2: Security Event Detection

**Objective**: Implement security event detection and classification.

Build detectors for:
- Privilege escalation attempts
- Container escape indicators
- Suspicious file access patterns
- Abnormal process execution

## Lab 17.3: Threat Response System

**Objective**: Implement automated threat response.

Build a response system that:
- Classifies threats by severity
- Takes automated actions (log, alert, block, kill)
- Supports custom response rules
- Provides audit logging

## Running the Labs

```bash
cd solutions
clojure -M -m lab-17-1-policy-engine test
clojure -M -m lab-17-2-security-events test
clojure -M -m lab-17-3-threat-response test
```
