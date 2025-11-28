# Chapter 21 Labs: Security Audit System

## Overview

These labs guide you through building a security audit system that monitors
system activity and detects policy violations.

## Lab 21.1: Audit Event Logging

**Objective**: Implement audit event capture and logging.

Build an audit logging system that:
- Captures security-relevant events
- Assigns severity levels
- Generates unique audit IDs
- Maintains tamper-evident logs

## Lab 21.2: Compliance Rule Engine

**Objective**: Implement a compliance rule checking engine.

Build a rule engine that:
- Defines compliance rules (CIS, PCI-DSS)
- Evaluates events against rules
- Tracks violations
- Generates compliance reports

## Lab 21.3: File Integrity Monitoring

**Objective**: Implement file integrity monitoring (FIM).

Build a FIM system that:
- Creates baseline hashes for files
- Detects file modifications
- Alerts on unauthorized changes
- Maintains audit trail

## Running the Labs

```bash
cd solutions
clojure -M -m lab-21-1-audit-logging test
clojure -M -m lab-21-2-compliance-engine test
clojure -M -m lab-21-3-file-integrity test
```
