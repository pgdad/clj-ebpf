# Chapter 16 Labs: Network Traffic Analyzer

## Overview

These labs guide you through building a high-performance network traffic analyzer
using XDP for line-rate packet processing.

## Lab 16.1: Packet Parsing

**Objective**: Implement network packet header parsing.

Build a parser that:
- Parses Ethernet headers (MAC addresses, EtherType)
- Parses IPv4 headers (addresses, protocol, TTL)
- Parses TCP/UDP headers (ports, flags)
- Handles malformed packets safely

## Lab 16.2: Flow Tracking

**Objective**: Implement 5-tuple flow tracking and aggregation.

Build a flow tracker that:
- Creates flow keys from 5-tuple (src/dst IP, src/dst port, protocol)
- Tracks per-flow statistics (packets, bytes, timestamps)
- Handles bidirectional flows
- Implements flow aging and cleanup

## Lab 16.3: Network Anomaly Detection

**Objective**: Implement network anomaly detection algorithms.

Build detectors for:
- Port scanning (single source, many destinations)
- SYN flooding (high SYN rate, few completions)
- Top talkers identification
- Protocol distribution analysis

## Running the Labs

```bash
cd solutions
clojure -M -m lab-16-1-packet-parsing test
clojure -M -m lab-16-2-flow-tracking test
clojure -M -m lab-16-3-anomaly-detection test
```
