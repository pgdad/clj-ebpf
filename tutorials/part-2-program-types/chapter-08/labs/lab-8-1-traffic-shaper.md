# Lab 8.1: Traffic Shaper

**Duration**: 60-75 minutes | **Difficulty**: Advanced

## Learning Objectives

In this lab, you will:
- Implement bandwidth limiting for egress traffic
- Build a token bucket rate limiter
- Use TC BPF for traffic shaping
- Monitor bandwidth usage per interface
- Handle burst traffic with bucket capacity
- Implement per-flow rate limiting

## Prerequisites

- Completed [Lab 7.3](../../chapter-07/labs/lab-7-3-load-balancer.md)
- Understanding of token bucket algorithm
- Knowledge of bandwidth measurement
- Familiarity with TC concepts

## Introduction

Traffic shaping controls the rate at which packets are transmitted. This is essential for:
- **Bandwidth management**: Prevent link saturation
- **Fair sharing**: Distribute bandwidth among flows
- **SLA enforcement**: Guarantee bandwidth commitments
- **Cost control**: Stay within ISP limits

## Token Bucket Algorithm

The token bucket is a classic rate limiting algorithm:

```
┌─────────────────────────────────┐
│     Token Bucket                │
│                                 │
│  Capacity: C tokens (bytes)     │
│  Tokens: T (current)            │
│  Rate: R bytes/second           │
│                                 │
│  ┌───────────────────────────┐ │
│  │ ▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░ │ │  T tokens
│  └───────────────────────────┘ │
│            Capacity C           │
└─────────────────────────────────┘

Algorithm:
1. Refill: tokens += R * elapsed_time
2. Cap: tokens = min(tokens, C)
3. Check: if tokens >= packet_size:
      Send packet
      tokens -= packet_size
   else:
      Drop packet (or queue)
```

## Part 1: Simple Bandwidth Limiter

Let's implement a basic bandwidth limiter for egress traffic.

### Implementation

```clojure
(ns lab-8-1-traffic-shaper
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.asm-dsl :refer :all]))

;; TC actions
(def TC_ACT_OK 0)
(def TC_ACT_SHOT 2)

;; __sk_buff offsets (x86_64)
(def SKB_OFFSETS
  {:len 0          ; Packet length (u32)
   :pkt-type 4     ; Packet type (u32)
   :mark 20        ; fwmark (u32)
   :priority 32    ; Priority (u32)
   :protocol 16    ; Protocol (u16, network order)
   :data 76        ; Data pointer (u32)
   :data-end 80})  ; Data end pointer (u32)

;; Rate limit: 10 Mbps = 10,000,000 bits/sec = 1,250,000 bytes/sec
(def RATE_LIMIT_BPS 1250000)  ; bytes per second
(def BUCKET_CAPACITY (* RATE_LIMIT_BPS 2))  ; 2 seconds burst

(defn create-bandwidth-limiter
  "Limit egress bandwidth using token bucket"
  [state-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; r6 = skb
      [(bpf/mov-reg :r6 :r1)]

      ;; Get packet length
      [(bpf/load-mem :w :r7 :r6 (:len SKB_OFFSETS))]  ; r7 = packet length

      ;; Get current timestamp
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]  ; r9 = current_time (ns)

      ;; Lookup rate limiter state
      ;; State: {last_time (u64), tokens (u64)}
      [(bpf/mov :r5 0)]
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 state-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If not found, initialize
      [(bpf/jmp-imm :jne :r0 0 :have-state)]

      ;; :init-state
      [(bpf/store-mem :dw :r10 -16 :r9)]           ; last_time = now
      [(bpf/mov :r5 BUCKET_CAPACITY)]
      [(bpf/store-mem :dw :r10 -8 :r5)]            ; tokens = capacity

      [(bpf/ld-map-fd :r1 state-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      ;; First packet always passes
      [(bpf/jmp :accept)]

      ;; :have-state
      [(bpf/mov-reg :r5 :r0)]  ; r5 = state pointer

      ;; Load last_time and tokens
      [(bpf/load-mem :dw :r6 :r5 0)]   ; r6 = last_time
      [(bpf/load-mem :dw :r8 :r5 8)]   ; r8 = current tokens

      ;; Calculate elapsed time (ns)
      [(bpf/mov-reg :r4 :r9)]
      [(bpf/sub-reg :r4 :r6)]  ; elapsed = current_time - last_time

      ;; Convert elapsed time to seconds (approximate)
      ;; elapsed_sec = elapsed_ns / 1,000,000,000
      ;; For efficiency: elapsed_sec ~= elapsed_ns >> 30 (divide by ~1 billion)
      [(bpf/mov-reg :r3 :r4)]
      [(bpf/rsh :r3 30)]  ; r3 ~= elapsed in seconds (rough approximation)

      ;; Calculate tokens to add: rate * elapsed_sec
      ;; tokens_to_add = RATE_LIMIT_BPS * elapsed_sec
      [(bpf/mov :r2 RATE_LIMIT_BPS)]
      [(bpf/mul-reg :r2 :r3)]  ; r2 = tokens to add

      ;; Add tokens
      [(bpf/add-reg :r8 :r2)]  ; tokens += tokens_to_add

      ;; Cap at capacity
      [(bpf/mov :r3 BUCKET_CAPACITY)]
      [(bpf/jmp-reg :jle :r8 :r3 :tokens-ok)]
      [(bpf/mov-reg :r8 :r3)]  ; tokens = capacity

      ;; :tokens-ok
      ;; Check if we have enough tokens for this packet
      [(bpf/jmp-reg :jlt :r8 :r7 :rate-limited)]  ; if tokens < packet_len, drop

      ;; Enough tokens - consume them
      [(bpf/sub-reg :r8 :r7)]  ; tokens -= packet_len

      ;; Update state
      [(bpf/store-mem :dw :r5 0 :r9)]  ; last_time = now
      [(bpf/store-mem :dw :r5 8 :r8)]  ; tokens = new_tokens

      ;; Update stats: accepted
      [(bpf/jmp :accept)]

      ;; :rate-limited
      ;; Update stats: dropped
      [(bpf/mov :r5 1)]
      [(bpf/store-mem :w :r10 -32 :r5)]

      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :drop)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; Also count dropped bytes
      [(bpf/load-mem :dw :r4 :r0 8)]
      [(bpf/add-reg :r4 :r7)]  ; Add packet length
      [(bpf/store-mem :dw :r0 8 :r4)]

      ;; :drop
      [(bpf/mov :r0 TC_ACT_SHOT)]
      [(bpf/exit-insn)]

      ;; :accept
      [(bpf/mov :r5 0)]
      [(bpf/store-mem :w :r10 -32 :r5)]

      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :accept-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; Count accepted bytes
      [(bpf/load-mem :dw :r4 :r0 8)]
      [(bpf/add-reg :r4 :r7)]
      [(bpf/store-mem :dw :r0 8 :r4)]

      ;; :accept-exit
      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))

(defn run-bandwidth-limiter [interface rate-mbps]
  (println (format "Creating TC bandwidth limiter for %s" interface))
  (println (format "Rate limit: %d Mbps (%.2f MB/s)\n"
                   rate-mbps (/ rate-mbps 8.0)))

  ;; State map: key=0, value={last_time, tokens}
  (let [state-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 16
                                   :max-entries 1})

        ;; Stats: key=0 (accepted), key=1 (dropped)
        ;; Value: {count (u64), bytes (u64)}
        stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 16
                                   :max-entries 2})]

    ;; Initialize stats
    (bpf/map-update stats-fd 0 (byte-array 16))
    (bpf/map-update stats-fd 1 (byte-array 16))

    ;; Load and attach program
    (let [prog-bytes (create-bandwidth-limiter state-fd stats-fd)
          prog-fd (bpf/load-program prog-bytes :sched-cls)
          link-fd (bpf/attach-tc prog-fd interface :egress)]

      (println (format "Traffic shaper attached to %s egress" interface))
      (println "Monitoring bandwidth usage...\n")

      (let [running (atom true)
            start-time (System/currentTimeMillis)]

        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (let [accepted-data (bpf/map-lookup stats-fd (int-array [0]))
                dropped-data (bpf/map-lookup stats-fd (int-array [1]))

                ;; Parse {count (u64), bytes (u64)}
                accepted-count (when accepted-data
                                 (bit-or
                                   (bit-shift-left (aget accepted-data 7) 56)
                                   (bit-shift-left (aget accepted-data 6) 48)
                                   (bit-shift-left (aget accepted-data 5) 40)
                                   (bit-shift-left (aget accepted-data 4) 32)
                                   (bit-shift-left (aget accepted-data 3) 24)
                                   (bit-shift-left (aget accepted-data 2) 16)
                                   (bit-shift-left (aget accepted-data 1) 8)
                                   (aget accepted-data 0)))

                accepted-bytes (when accepted-data
                                 (bit-or
                                   (bit-shift-left (aget accepted-data 15) 56)
                                   (bit-shift-left (aget accepted-data 14) 48)
                                   (bit-shift-left (aget accepted-data 13) 40)
                                   (bit-shift-left (aget accepted-data 12) 32)
                                   (bit-shift-left (aget accepted-data 11) 24)
                                   (bit-shift-left (aget accepted-data 10) 16)
                                   (bit-shift-left (aget accepted-data 9) 8)
                                   (aget accepted-data 8)))

                dropped-count (when dropped-data
                                (bit-or
                                  (bit-shift-left (aget dropped-data 7) 56)
                                  (bit-shift-left (aget dropped-data 6) 48)
                                  (bit-shift-left (aget dropped-data 5) 40)
                                  (bit-shift-left (aget dropped-data 4) 32)
                                  (bit-shift-left (aget dropped-data 3) 24)
                                  (bit-shift-left (aget dropped-data 2) 16)
                                  (bit-shift-left (aget dropped-data 1) 8)
                                  (aget dropped-data 0)))

                dropped-bytes (when dropped-data
                                (bit-or
                                  (bit-shift-left (aget dropped-data 15) 56)
                                  (bit-shift-left (aget dropped-data 14) 48)
                                  (bit-shift-left (aget dropped-data 13) 40)
                                  (bit-shift-left (aget dropped-data 12) 32)
                                  (bit-shift-left (aget dropped-data 11) 24)
                                  (bit-shift-left (aget dropped-data 10) 16)
                                  (bit-shift-left (aget dropped-data 9) 8)
                                  (aget dropped-data 8)))

                elapsed-sec (/ (- (System/currentTimeMillis) start-time) 1000.0)
                accepted-mbps (if (and accepted-bytes (> elapsed-sec 0))
                                (* 8.0 (/ accepted-bytes 1000000.0 elapsed-sec))
                                0.0)
                dropped-mbps (if (and dropped-bytes (> elapsed-sec 0))
                               (* 8.0 (/ dropped-bytes 1000000.0 elapsed-sec))
                               0.0)]

            (println (format "Accepted: %d pkts, %.2f MB (%.2f Mbps) | Dropped: %d pkts, %.2f MB (%.2f Mbps)"
                            (or accepted-count 0)
                            (/ (or accepted-bytes 0) 1000000.0)
                            accepted-mbps
                            (or dropped-count 0)
                            (/ (or dropped-bytes 0) 1000000.0)
                            dropped-mbps)))))

      (bpf/detach-tc link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map state-fd)
      (bpf/close-map stats-fd))))
```

### Testing

```bash
# Terminal 1: Start traffic shaper (10 Mbps limit)
sudo lein run -m lab-8-1-traffic-shaper/run-bandwidth-limiter "eth0" 10

# Terminal 2: Generate high-rate traffic
# Should see rate limiting kick in
iperf3 -c target-server -b 50M

# Terminal 3: Monitor actual throughput
watch -n 1 'ifstat -i eth0'
```

### Expected Output

```
Creating TC bandwidth limiter for eth0
Rate limit: 10 Mbps (1.25 MB/s)

Traffic shaper attached to eth0 egress
Monitoring bandwidth usage...

Accepted: 1234 pkts, 1.85 MB (7.4 Mbps) | Dropped: 0 pkts, 0.00 MB (0.0 Mbps)
Accepted: 2890 pkts, 4.33 MB (8.7 Mbps) | Dropped: 145 pkts, 0.22 MB (0.9 Mbps)
Accepted: 4567 pkts, 6.85 MB (9.1 Mbps) | Dropped: 432 pkts, 0.65 MB (1.3 Mbps)
Accepted: 6234 pkts, 9.35 MB (9.8 Mbps) | Dropped: 789 pkts, 1.18 MB (2.4 Mbps)
...
```

## Part 2: Per-Flow Rate Limiting

Now let's implement per-flow (per-connection) rate limiting using 5-tuple hashing.

### Implementation

```clojure
(def ETH_P_IP 0x0800)
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

;; Per-flow rate limit: 1 Mbps per connection
(def PER_FLOW_RATE_BPS 125000)  ; 1 Mbps = 125,000 bytes/sec
(def PER_FLOW_CAPACITY (* PER_FLOW_RATE_BPS 2))

(defn create-per-flow-limiter
  "Rate limit each TCP/UDP flow independently"
  [flow-states-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; r6 = skb
      [(bpf/mov-reg :r6 :r1)]

      ;; Get packet length
      [(bpf/load-mem :w :r7 :r6 (:len SKB_OFFSETS))]

      ;; Load data pointers
      [(bpf/load-mem :w :r2 :r6 (:data SKB_OFFSETS))]    ; data
      [(bpf/load-mem :w :r3 :r6 (:data-end SKB_OFFSETS))] ; data_end

      ;; Parse to get 5-tuple for flow identification
      ;; Ethernet (14 bytes)
      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 14)]
      [(bpf/jmp-reg :jgt :r4 :r3 :accept)]  ; Too small, accept

      ;; Check IPv4
      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :accept)]

      ;; IP header
      [(bpf/mov-reg :r8 :r2)]
      [(bpf/add :r8 14)]

      [(bpf/mov-reg :r4 :r8)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :accept)]

      ;; Check TCP or UDP
      [(bpf/load-mem :b :r5 :r8 9)]
      [(bpf/jmp-imm :jeq :r5 IPPROTO_TCP :is-tcp-udp)]
      [(bpf/jmp-imm :jeq :r5 IPPROTO_UDP :is-tcp-udp)]
      [(bpf/jmp :accept)]  ; Not TCP/UDP, accept

      ;; :is-tcp-udp
      ;; Get L4 header
      [(bpf/load-mem :b :r5 :r8 0)]
      [(bpf/and :r5 0x0F)]
      [(bpf/lsh :r5 2)]
      [(bpf/mov-reg :r9 :r8)]
      [(bpf/add-reg :r9 :r5)]  ; r9 = L4 header

      [(bpf/mov-reg :r4 :r9)]
      [(bpf/add :r4 8)]
      [(bpf/jmp-reg :jgt :r4 :r3 :accept)]

      ;; Build flow key (5-tuple): src_ip + dst_ip + src_port + dst_port + proto
      ;; src_ip (offset 12 in IP)
      [(bpf/load-mem :w :r4 :r8 12)]
      [(bpf/store-mem :w :r10 -20 :r4)]

      ;; dst_ip (offset 16)
      [(bpf/load-mem :w :r4 :r8 16)]
      [(bpf/store-mem :w :r10 -16 :r4)]

      ;; src_port (offset 0 in L4)
      [(bpf/load-mem :h :r4 :r9 0)]
      [(bpf/store-mem :h :r10 -12 :r4)]

      ;; dst_port (offset 2)
      [(bpf/load-mem :h :r4 :r9 2)]
      [(bpf/store-mem :h :r10 -10 :r4)]

      ;; proto
      [(bpf/load-mem :b :r4 :r8 9)]
      [(bpf/store-mem :b :r10 -9 :r4)]

      ;; Lookup flow state
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r5 :r0)]  ; r5 = current_time

      [(bpf/ld-map-fd :r1 flow-states-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -20)]  ; Flow key
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jne :r0 0 :have-flow-state)]

      ;; :init-flow-state
      [(bpf/store-mem :dw :r10 -32 :r5)]  ; last_time = now
      [(bpf/mov :r4 PER_FLOW_CAPACITY)]
      [(bpf/store-mem :dw :r10 -24 :r4)]  ; tokens = capacity

      [(bpf/ld-map-fd :r1 flow-states-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -20)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -32)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      [(bpf/jmp :accept)]

      ;; :have-flow-state
      ;; Token bucket logic (similar to global limiter)
      ;; ... (load last_time, tokens, calculate refill, check/consume) ...

      ;; :flow-rate-limited
      [(bpf/jmp :drop)]

      ;; :drop
      [(bpf/mov :r0 TC_ACT_SHOT)]
      [(bpf/exit-insn)]

      ;; :accept
      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))

(defn run-per-flow-limiter [interface]
  (println "Creating per-flow rate limiter...")
  (println (format "Rate limit: 1 Mbps per TCP/UDP flow\n"))

  (let [flow-states-fd (bpf/create-map :lru-hash
                                        {:key-size 13  ; 5-tuple
                                         :value-size 16  ; {last_time, tokens}
                                         :max-entries 10000})

        stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 16
                                   :max-entries 2})]

    (let [prog-bytes (create-per-flow-limiter flow-states-fd stats-fd)
          prog-fd (bpf/load-program prog-bytes :sched-cls)
          link-fd (bpf/attach-tc prog-fd interface :egress)]

      (println (format "Per-flow limiter attached to %s egress" interface))
      (println "Monitoring...\n")

      (let [running (atom true)]
        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          ;; Display stats
          (let [accepted (bpf/map-lookup stats-fd (int-array [0]))
                dropped (bpf/map-lookup stats-fd (int-array [1]))]
            (println (format "Accepted: %d pkts | Dropped: %d pkts"
                            (or accepted 0) (or dropped 0))))))

      (bpf/detach-tc link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map flow-states-fd)
      (bpf/close-map stats-fd))))
```

## Part 3: Hierarchical Traffic Shaping

Implement class-based bandwidth allocation with priorities.

### Concept

```
Total Bandwidth: 10 Mbps
├─ High Priority (SSH, DNS): 3 Mbps guaranteed
├─ Medium Priority (HTTP): 5 Mbps guaranteed
└─ Low Priority (bulk): 2 Mbps guaranteed

When traffic is low, unused bandwidth is shared
```

### Implementation

```clojure
(def PRIORITY_HIGH 1)
(def PRIORITY_MEDIUM 2)
(def PRIORITY_LOW 3)

;; Bandwidth allocation (bytes per second)
(def CLASS_RATES
  {PRIORITY_HIGH 375000    ; 3 Mbps
   PRIORITY_MEDIUM 625000  ; 5 Mbps
   PRIORITY_LOW 250000})   ; 2 Mbps

(defn classify-packet
  "Classify packet into priority class"
  [data-reg data-end-reg]
  (vec (concat
    ;; Parse to TCP/UDP port
    ;; ... (packet parsing) ...

    ;; Classify by port
    ;; Port 22 (SSH) or 53 (DNS) -> HIGH
    [(bpf/jmp-imm :jeq :r9 22 :high-priority)]
    [(bpf/jmp-imm :jeq :r9 53 :high-priority)]

    ;; Port 80/443 (HTTP/HTTPS) -> MEDIUM
    [(bpf/jmp-imm :jeq :r9 80 :medium-priority)]
    [(bpf/jmp-imm :jeq :r9 443 :medium-priority)]

    ;; Everything else -> LOW
    [(bpf/jmp :low-priority)]

    ;; :high-priority
    [(bpf/mov :r0 PRIORITY_HIGH)]
    [(bpf/jmp :classify-done)]

    ;; :medium-priority
    [(bpf/mov :r0 PRIORITY_MEDIUM)]
    [(bpf/jmp :classify-done)]

    ;; :low-priority
    [(bpf/mov :r0 PRIORITY_LOW)]

    ;; :classify-done
    ;; r0 = priority class
    )))

(defn create-hierarchical-shaper
  "Multi-class traffic shaper with priority"
  [class-states-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Classify packet
      ;; ... (get priority class in r8) ...

      ;; Lookup class state
      [(bpf/store-mem :w :r10 -4 :r8)]  ; key = class
      [(bpf/ld-map-fd :r1 class-states-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; Token bucket for this class
      ;; ... (refill, check, consume) ...

      ;; If this class is rate-limited, check if we can borrow from other classes
      ;; (Work-conserving algorithm)
      ;; ...

      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))
```

## Exercises

### Exercise 1: Burst Handling

Improve burst handling:
- Implement variable bucket capacity
- Track burst statistics
- Adjust capacity dynamically

### Exercise 2: Work-Conserving Shaper

Make the shaper work-conserving:
- Allow classes to use unused bandwidth
- Implement bandwidth borrowing
- Guarantee minimum rates

### Exercise 3: Bidirectional Shaping

Shape both ingress and egress:
- Attach to both hooks
- Coordinate limits
- Handle asymmetric links

### Exercise 4: Real-Time Monitoring

Add detailed monitoring:
- Per-class statistics
- Bandwidth utilization graphs
- Drop reasons tracking

## Summary

In this lab, you learned:
- Implementing bandwidth limiting with token bucket
- Building per-flow rate limiters
- Creating hierarchical traffic shaping
- Using TC egress hook for traffic control
- Handling burst traffic patterns

## Navigation

- **Next**: [Lab 8.2 - QoS Classifier](lab-8-2-qos-classifier.md)
- **Previous**: [Chapter 8 Overview](../README.md)
- **Home**: [Tutorial Home](../../../README.md)
