# Lab 7.2: DDoS Mitigation

**Duration**: 75-90 minutes | **Difficulty**: Advanced

## Learning Objectives

In this lab, you will:
- Implement SYN flood protection with SYN cookies
- Build per-IP rate limiting
- Detect and mitigate volumetric attacks
- Use LRU maps for connection tracking
- Implement sliding window rate limiters
- Handle legitimate traffic during attacks

## Prerequisites

- Completed [Lab 7.1](lab-7-1-packet-filter.md)
- Understanding of DDoS attack types
- Familiarity with TCP handshake
- Knowledge of rate limiting algorithms

## Introduction

Distributed Denial of Service (DDoS) attacks attempt to overwhelm servers with traffic. XDP's line-rate processing makes it ideal for DDoS mitigation:

**Common DDoS Attack Types**:
1. **SYN Flood**: Exhaust server resources with half-open connections
2. **UDP Flood**: Overwhelm with high-rate UDP traffic
3. **Amplification**: Abuse DNS, NTP, etc. for traffic multiplication
4. **HTTP Flood**: Application-layer attacks

XDP can mitigate many of these at the network edge before they consume server resources.

## Part 1: Per-IP Rate Limiter

Let's start with a simple rate limiter that tracks packets per IP per second.

### Algorithm: Token Bucket

```
Token Bucket Rate Limiting:
┌─────────────────────────────────┐
│ Bucket (per IP)                 │
│  ├─ Tokens: 100 (max capacity)  │
│  ├─ Refill: +100 tokens/sec     │
│  └─ Cost: 1 token per packet    │
└─────────────────────────────────┘

On packet arrival:
1. Calculate tokens to add based on time elapsed
2. Add tokens (capped at capacity)
3. If tokens >= 1:
   - Consume 1 token
   - PASS packet
4. Else:
   - DROP packet (rate limit exceeded)
```

### Implementation

```clojure
(ns lab-7-2-ddos-mitigation
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.asm-dsl :refer :all]))

;; Rate limit: 1000 packets per second per IP
(def RATE_LIMIT_PPS 1000)
(def BUCKET_CAPACITY RATE_LIMIT_PPS)
(def REFILL_RATE_NS (/ 1000000000 RATE_LIMIT_PPS)) ; ns per token

;; XDP actions
(def XDP_DROP 1)
(def XDP_PASS 2)

;; Protocols
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)
(def ETH_P_IP 0x0800)

(defn create-rate-limiter
  "Per-IP rate limiter using token bucket"
  [rate-limit-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Parse packet to get source IP
      [(bpf/mov-reg :r6 :r1)]  ; ctx
      [(bpf/load-mem :w :r2 :r6 0)]   ; data
      [(bpf/load-mem :w :r3 :r6 4)]   ; data_end

      ;; Bounds check Ethernet
      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 14)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Check IPv4
      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :pass)]

      ;; IP header
      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      ;; Bounds check IP
      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Read source IP
      [(bpf/load-mem :w :r8 :r7 12)]
      [(bpf/endian-be :w :r8)]  ; r8 = source IP (host byte order)

      ;; Get current timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]  ; r9 = current_time

      ;; Lookup rate limit state for this IP
      ;; State: {last_time (u64), tokens (u32), _pad (u32)}
      [(bpf/store-mem :w :r10 -4 :r8)]  ; key = src_ip

      [(bpf/ld-map-fd :r1 rate-limit-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If not found, initialize
      [(bpf/jmp-imm :jne :r0 0 :have-state)]

      ;; :init-state - First packet from this IP
      [(bpf/store-mem :dw :r10 -16 :r9)]  ; last_time = now
      [(bpf/mov :r4 BUCKET_CAPACITY)]
      [(bpf/sub :r4 1)]  ; Start with capacity - 1
      [(bpf/store-mem :w :r10 -8 :r4)]   ; tokens
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -4 :r4)]   ; padding

      [(bpf/ld-map-fd :r1 rate-limit-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]  ; key
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]  ; value
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      [(bpf/jmp :pass)]  ; First packet always passes

      ;; :have-state
      [(bpf/mov-reg :r5 :r0)]  ; r5 = state pointer

      ;; Load last_time
      [(bpf/load-mem :dw :r6 :r5 0)]  ; r6 = last_time

      ;; Calculate elapsed time (ns)
      [(bpf/mov-reg :r7 :r9)]
      [(bpf/sub-reg :r7 :r6)]  ; r7 = elapsed = now - last_time

      ;; Calculate tokens to add: elapsed / REFILL_RATE_NS
      ;; Simplified: elapsed >> 20 (approximate division by 1M ns)
      [(bpf/mov-reg :r4 :r7)]
      [(bpf/rsh :r4 20)]  ; Approximate: elapsed / 1048576 ns
      ;; This gives roughly tokens per ms

      ;; Load current tokens
      [(bpf/load-mem :w :r3 :r5 8)]  ; r3 = tokens

      ;; Add refilled tokens
      [(bpf/add-reg :r3 :r4)]

      ;; Cap at BUCKET_CAPACITY
      [(bpf/jmp-imm :jle :r3 BUCKET_CAPACITY :tokens-ok)]
      [(bpf/mov :r3 BUCKET_CAPACITY)]

      ;; :tokens-ok
      ;; Check if we have at least 1 token
      [(bpf/jmp-imm :jlt :r3 1 :rate-limited)]

      ;; Consume 1 token
      [(bpf/sub :r3 1)]

      ;; Update state
      [(bpf/store-mem :dw :r5 0 :r9)]  ; last_time = now
      [(bpf/store-mem :w :r5 8 :r3)]   ; tokens = new_tokens

      [(bpf/jmp :pass)]

      ;; :rate-limited - Drop packet
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -32 :r4)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :drop-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :drop-exit
      [(bpf/mov :r0 XDP_DROP)]
      [(bpf/exit-insn)]

      ;; :pass
      [(bpf/mov :r4 1)]
      [(bpf/store-mem :w :r10 -32 :r4)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :pass-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :pass-exit
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))

(defn run-rate-limiter [interface]
  (println "Creating XDP per-IP rate limiter...")
  (println (format "Rate limit: %d packets/second per IP\n" RATE_LIMIT_PPS))

  ;; LRU hash: automatic eviction of old IPs
  (let [rate-limit-fd (bpf/create-map :lru-hash
                                       {:key-size 4    ; IP address
                                        :value-size 16 ; last_time + tokens + pad
                                        :max-entries 100000})

        ;; Stats: 0 = rate-limited, 1 = passed
        stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 8
                                   :max-entries 2})]

    (bpf/map-update stats-fd 0 (long-array [0]))
    (bpf/map-update stats-fd 1 (long-array [0]))

    (let [prog-bytes (create-rate-limiter rate-limit-fd stats-fd)
          prog-fd (bpf/load-program prog-bytes :xdp)
          link-fd (bpf/attach-xdp prog-fd interface)]

      (println (format "Rate limiter attached to %s" interface))
      (println "Monitoring traffic...\n")

      (let [running (atom true)
            start-time (System/currentTimeMillis)]

        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (let [rate-limited (aget (bpf/map-lookup stats-fd (int-array [0])) 0)
                passed (aget (bpf/map-lookup stats-fd (int-array [1])) 0)
                total (+ rate-limited passed)
                elapsed-sec (/ (- (System/currentTimeMillis) start-time) 1000.0)
                pps (/ total elapsed-sec)
                drop-pct (if (> total 0) (* 100.0 (/ rate-limited total)) 0.0)]

            (println (format "Total: %d pkts (%.1f pps) | Passed: %d | Rate-limited: %d (%.1f%%)"
                            total pps passed rate-limited drop-pct)))))

      (bpf/detach-xdp link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map rate-limit-fd)
      (bpf/close-map stats-fd))))
```

### Testing

```bash
# Terminal 1: Start rate limiter
sudo lein run -m lab-7-2-ddos-mitigation/run-rate-limiter "eth0"

# Terminal 2: Simulate attack with hping3
# Send 10,000 pps from single IP (should be rate-limited)
sudo hping3 -S -p 80 --flood --rand-source target-server

# Terminal 3: Normal traffic
curl http://target-server
# Should work normally
```

### Expected Output

```
Creating XDP per-IP rate limiter...
Rate limit: 1000 packets/second per IP

Rate limiter attached to eth0
Monitoring traffic...

Total: 5234 pkts (2617.0 pps) | Passed: 2145 | Rate-limited: 3089 (59.0%)
Total: 15678 pkts (3919.5 pps) | Passed: 4567 | Rate-limited: 11111 (70.9%)
Total: 28934 pkts (4822.3 pps) | Passed: 6234 | Rate-limited: 22700 (78.5%)
...
```

## Part 2: SYN Flood Protection

SYN floods exhaust server resources by initiating many half-open TCP connections. We'll implement SYN cookie defense.

### SYN Cookie Concept

```
Normal TCP Handshake:
Client               Server
  │                    │
  ├─── SYN ───────────→│ Allocate connection state
  │←── SYN-ACK ────────┤
  ├─── ACK ───────────→│ Connection established
  │                    │

SYN Flood Attack:
Attacker             Server
  │                    │
  ├─── SYN ───────────→│ Allocate state (resource exhausted!)
  ├─── SYN ───────────→│ Allocate state
  ├─── SYN ───────────→│ Allocate state
  │ (never send ACK)   │ Out of memory!

SYN Cookie Defense:
Client               XDP Filter            Server
  │                    │                     │
  ├─── SYN ───────────→│ (no state)         │
  │←── SYN-ACK ────────┤ Cookie in SEQ      │
  ├─── ACK ───────────→│ Verify cookie ────→│ Now allocate
  │                    │                     │
```

### Implementation

```clojure
;; TCP flags
(def TH_FIN 0x01)
(def TH_SYN 0x02)
(def TH_RST 0x04)
(def TH_PSH 0x08)
(def TH_ACK 0x10)
(def TH_URG 0x20)

(defn create-syn-flood-protection
  "Detect and mitigate SYN floods"
  [syn-tracker-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Parse to TCP layer
      [(bpf/mov-reg :r6 :r1)]
      [(bpf/load-mem :w :r2 :r6 0)]
      [(bpf/load-mem :w :r3 :r6 4)]

      ;; Ethernet bounds
      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 14)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Check IPv4
      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :pass)]

      ;; IP header
      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Check TCP
      [(bpf/load-mem :b :r5 :r7 9)]
      [(bpf/jmp-imm :jne :r5 IPPROTO_TCP :pass)]

      ;; TCP header (account for IP header length)
      [(bpf/load-mem :b :r5 :r7 0)]
      [(bpf/and :r5 0x0F)]
      [(bpf/lsh :r5 2)]
      [(bpf/mov-reg :r8 :r7)]
      [(bpf/add-reg :r8 :r5)]  ; r8 = TCP header

      [(bpf/mov-reg :r4 :r8)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Read TCP flags (offset 13)
      [(bpf/load-mem :b :r9 :r8 13)]

      ;; Check if SYN flag set and ACK not set (SYN packet)
      [(bpf/mov-reg :r4 :r9)]
      [(bpf/and :r4 TH_SYN)]
      [(bpf/jmp-imm :jeq :r4 0 :pass)]  ; Not SYN, pass

      [(bpf/mov-reg :r4 :r9)]
      [(bpf/and :r4 TH_ACK)]
      [(bpf/jmp-imm :jne :r4 0 :pass)]  ; SYN-ACK or ACK, pass

      ;; This is a SYN packet (SYN=1, ACK=0)
      ;; Track per source IP

      ;; Read source IP
      [(bpf/load-mem :w :r5 :r7 12)]
      [(bpf/endian-be :w :r5)]  ; r5 = src IP

      ;; Get current time
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]

      ;; Lookup SYN count for this IP
      ;; State: {last_time (u64), syn_count (u32), _pad (u32)}
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 syn-tracker-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jne :r0 0 :have-syn-state)]

      ;; :init-syn-state
      [(bpf/store-mem :dw :r10 -16 :r9)]  ; last_time = now
      [(bpf/mov :r4 1)]
      [(bpf/store-mem :w :r10 -8 :r4)]    ; syn_count = 1
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -4 :r4)]

      [(bpf/ld-map-fd :r1 syn-tracker-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      [(bpf/jmp :pass)]

      ;; :have-syn-state
      [(bpf/mov-reg :r5 :r0)]

      ;; Load last_time and syn_count
      [(bpf/load-mem :dw :r6 :r5 0)]  ; last_time
      [(bpf/load-mem :w :r7 :r5 8)]   ; syn_count

      ;; Calculate elapsed time
      [(bpf/mov-reg :r4 :r9)]
      [(bpf/sub-reg :r4 :r6)]  ; elapsed = now - last_time

      ;; If more than 1 second elapsed, reset counter
      [(bpf/mov :r3 1000000000)]  ; 1 second in ns
      [(bpf/jmp-reg :jlt :r4 :r3 :same-window)]

      ;; :reset-window
      [(bpf/store-mem :dw :r5 0 :r9)]  ; last_time = now
      [(bpf/mov :r7 1)]
      [(bpf/store-mem :w :r5 8 :r7)]   ; syn_count = 1
      [(bpf/jmp :pass)]

      ;; :same-window - Increment counter
      [(bpf/add :r7 1)]
      [(bpf/store-mem :w :r5 8 :r7)]

      ;; Check if exceeds threshold (100 SYNs per second)
      [(bpf/jmp-imm :jle :r7 100 :pass)]

      ;; :syn-flood-detected - Drop
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -32 :r4)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :drop-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :drop-exit
      [(bpf/mov :r0 XDP_DROP)]
      [(bpf/exit-insn)]

      ;; :pass
      [(bpf/mov :r4 1)]
      [(bpf/store-mem :w :r10 -32 :r4)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :pass-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :pass-exit
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))

(defn run-syn-flood-protection [interface]
  (println "Creating XDP SYN flood protection...")
  (println "Threshold: 100 SYNs per second per IP\n")

  (let [syn-tracker-fd (bpf/create-map :lru-hash
                                        {:key-size 4
                                         :value-size 16
                                         :max-entries 100000})

        stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 8
                                   :max-entries 2})]

    (bpf/map-update stats-fd 0 (long-array [0]))
    (bpf/map-update stats-fd 1 (long-array [0]))

    (let [prog-bytes (create-syn-flood-protection syn-tracker-fd stats-fd)
          prog-fd (bpf/load-program prog-bytes :xdp)
          link-fd (bpf/attach-xdp prog-fd interface)]

      (println (format "SYN flood protection attached to %s" interface))
      (println "Monitoring for SYN floods...\n")

      (let [running (atom true)]
        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (let [blocked-syns (aget (bpf/map-lookup stats-fd (int-array [0])) 0)
                passed (aget (bpf/map-lookup stats-fd (int-array [1])) 0)]

            (println (format "Passed: %d | Blocked SYNs: %d"
                            passed blocked-syns))

            (when (> blocked-syns 0)
              (println "  ⚠ SYN flood detected!")))))

      (bpf/detach-xdp link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map syn-tracker-fd)
      (bpf/close-map stats-fd))))
```

### Testing

```bash
# Terminal 1: Start protection
sudo lein run -m lab-7-2-ddos-mitigation/run-syn-flood-protection "eth0"

# Terminal 2: Simulate SYN flood
sudo hping3 -S -p 80 --flood target-server

# Terminal 3: Legitimate connection should still work
telnet target-server 80
```

### Expected Output

```
Creating XDP SYN flood protection...
Threshold: 100 SYNs per second per IP

SYN flood protection attached to eth0
Monitoring for SYN floods...

Passed: 1234 | Blocked SYNs: 0
Passed: 2456 | Blocked SYNs: 0
Passed: 3678 | Blocked SYNs: 5432
  ⚠ SYN flood detected!
Passed: 4012 | Blocked SYNs: 18765
  ⚠ SYN flood detected!
...
```

## Part 3: Combined DDoS Defense

Let's combine multiple defense mechanisms into a comprehensive solution.

### Implementation

```clojure
(defn create-comprehensive-ddos-defense
  "Multi-layered DDoS defense"
  [rate-limit-fd syn-tracker-fd blacklist-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Parse packet
      [(bpf/mov-reg :r6 :r1)]
      [(bpf/load-mem :w :r2 :r6 0)]
      [(bpf/load-mem :w :r3 :r6 4)]

      ;; Check Ethernet
      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 14)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :pass)]

      ;; IP header
      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Read source IP
      [(bpf/load-mem :w :r8 :r7 12)]
      [(bpf/endian-be :w :r8)]  ; r8 = src_ip

      ;; Layer 1: Check blacklist
      [(bpf/store-mem :w :r10 -4 :r8)]
      [(bpf/ld-map-fd :r1 blacklist-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jne :r0 0 :blacklisted)]  ; Found in blacklist

      ;; Layer 2: Rate limiting (simplified for brevity)
      ;; ... (similar to earlier rate-limiter code) ...

      ;; Layer 3: SYN flood protection
      ;; Check if TCP
      [(bpf/load-mem :b :r5 :r7 9)]
      [(bpf/jmp-imm :jne :r5 IPPROTO_TCP :pass-packet)]

      ;; Get TCP header
      [(bpf/load-mem :b :r5 :r7 0)]
      [(bpf/and :r5 0x0F)]
      [(bpf/lsh :r5 2)]
      [(bpf/mov-reg :r9 :r7)]
      [(bpf/add-reg :r9 :r5)]

      [(bpf/mov-reg :r4 :r9)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass-packet)]

      ;; Check SYN flag
      [(bpf/load-mem :b :r5 :r9 13)]
      [(bpf/and :r5 TH_SYN)]
      [(bpf/jmp-imm :jeq :r5 0 :pass-packet)]

      ;; SYN packet - check rate
      ;; ... (SYN tracking logic) ...

      [(bpf/jmp :pass-packet)]

      ;; :blacklisted
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -8 :r4)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :drop-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]
      [(bpf/jmp :drop-exit)]

      ;; :drop-exit
      [(bpf/mov :r0 XDP_DROP)]
      [(bpf/exit-insn)]

      ;; :pass-packet
      [(bpf/mov :r4 1)]
      [(bpf/store-mem :w :r10 -8 :r4)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :pass-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :pass-exit
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))
```

## Exercises

### Exercise 1: UDP Amplification Defense

Implement detection for UDP amplification attacks:
- Track DNS response sizes
- Block responses > threshold
- Rate limit DNS queries per IP

### Exercise 2: Dynamic Blacklisting

Automatically blacklist attacking IPs:
- Track IPs that trigger rate limits
- Add to blacklist after N violations
- Auto-expire after timeout

### Exercise 3: Geo-Based Rate Limiting

Different rate limits by region:
- Use GeoIP database in map
- Apply stricter limits to high-risk regions
- Allowlist known good IPs

### Exercise 4: Connection State Tracking

Full TCP connection tracking:
- Track SYN → SYN-ACK → ACK
- Detect abnormal patterns
- Rate limit by connection state

## Summary

In this lab, you learned:
- Implementing per-IP rate limiting with token buckets
- Detecting and mitigating SYN floods
- Building multi-layered DDoS defense
- Using LRU maps for automatic state management
- Balancing security and legitimate traffic

**Key Insight**: XDP's performance makes it possible to implement sophisticated DDoS defenses that were previously only feasible in hardware.

## Navigation

- **Next**: [Lab 7.3 - Layer 4 Load Balancer](lab-7-3-load-balancer.md)
- **Previous**: [Lab 7.1 - Basic Packet Filter](lab-7-1-packet-filter.md)
- **Home**: [Tutorial Home](../../../README.md)
