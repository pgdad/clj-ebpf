# Lab 8.2: QoS Classifier

**Duration**: 60-75 minutes | **Difficulty**: Advanced

## Learning Objectives

In this lab, you will:
- Implement Quality of Service (QoS) packet classification
- Set packet priorities based on traffic type
- Mark packets with DSCP values
- Integrate with Linux qdisc for priority queuing
- Build application-aware traffic prioritization
- Monitor QoS effectiveness

## Prerequisites

- Completed [Lab 8.1](lab-8-1-traffic-shaper.md)
- Understanding of QoS concepts
- Knowledge of DSCP and ToS fields
- Familiarity with priority queuing

## Introduction

Quality of Service (QoS) ensures that critical traffic receives better treatment than bulk traffic. This is essential for:
- **VoIP and video**: Low latency, jitter-free
- **Interactive applications**: Responsive SSH, DNS
- **Background tasks**: Bulk downloads, backups

## QoS Mechanisms

### 1. Classification

Identify traffic type:
- By port (SSH: 22, DNS: 53, HTTP: 80)
- By protocol (ICMP, TCP, UDP)
- By application markers
- By source/destination

### 2. Marking

Tag packets for downstream processing:
- **ToS/DSCP**: IP header field (6 bits)
- **Priority**: Socket buffer priority
- **Classid**: TC class identifier
- **Mark**: Netfilter mark

### 3. Queuing

Separate queues per priority:
```
┌───────────────────────────────────┐
│  High Priority Queue (interactive)│ → Process first
├───────────────────────────────────┤
│  Medium Priority Queue (normal)   │ → Process second
├───────────────────────────────────┤
│  Low Priority Queue (bulk)        │ → Process last
└───────────────────────────────────┘
```

## DSCP Values

Differentiated Services Code Point (DSCP) is a 6-bit field in the IP ToS byte:

| DSCP | Binary  | Class | Use Case |
|------|---------|-------|----------|
| EF (46) | 101110 | Expedited Forwarding | VoIP, real-time |
| AF41 (34) | 100010 | Assured Forwarding | Video streaming |
| AF31 (26) | 011010 | Assured Forwarding | Streaming data |
| AF21 (18) | 010010 | Assured Forwarding | Bulk data |
| BE (0) | 000000 | Best Effort | Default |

## Part 1: Port-Based Classifier

Let's classify and prioritize traffic based on TCP/UDP ports.

### Implementation

```clojure
(ns lab-8-2-qos-classifier
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.asm-dsl :refer :all]))

;; TC actions
(def TC_ACT_OK 0)

;; Priority levels (Linux socket priorities)
(def PRIO_INTERACTIVE 0)  ; Highest
(def PRIO_NORMAL 3)       ; Default
(def PRIO_BULK 6)         ; Lowest

;; DSCP values
(def DSCP_EF 46)    ; Expedited Forwarding (VoIP)
(def DSCP_AF41 34)  ; High priority streaming
(def DSCP_AF21 18)  ; Medium priority
(def DSCP_BE 0)     ; Best effort

;; __sk_buff offsets
(def SKB_OFFSETS
  {:priority 32
   :data 76
   :data-end 80})

;; Protocol values
(def ETH_P_IP 0x0800)
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)
(def IPPROTO_ICMP 1)

(defn create-port-classifier
  "Classify and prioritize packets by port"
  [stats-fd]
  (bpf/assemble
    (vec (concat
      ;; r6 = skb
      [(bpf/mov-reg :r6 :r1)]

      ;; Load data pointers
      [(bpf/load-mem :w :r2 :r6 (:data SKB_OFFSETS))]
      [(bpf/load-mem :w :r3 :r6 (:data-end SKB_OFFSETS))]

      ;; Parse Ethernet
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

      ;; Check protocol
      [(bpf/load-mem :b :r5 :r7 9)]

      ;; ICMP -> High priority (network control)
      [(bpf/jmp-imm :jeq :r5 IPPROTO_ICMP :interactive)]

      ;; TCP/UDP -> Check ports
      [(bpf/jmp-imm :jeq :r5 IPPROTO_TCP :check-ports)]
      [(bpf/jmp-imm :jeq :r5 IPPROTO_UDP :check-ports)]
      [(bpf/jmp :normal)]  ; Other protocols -> normal

      ;; :check-ports
      ;; Get L4 header
      [(bpf/load-mem :b :r5 :r7 0)]
      [(bpf/and :r5 0x0F)]
      [(bpf/lsh :r5 2)]
      [(bpf/mov-reg :r8 :r7)]
      [(bpf/add-reg :r8 :r5)]  ; r8 = L4 header

      [(bpf/mov-reg :r4 :r8)]
      [(bpf/add :r4 4)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Read destination port
      [(bpf/load-mem :h :r9 :r8 2)]
      [(bpf/endian-be :h :r9)]

      ;; Classify by port
      ;; SSH (22), DNS (53) -> Interactive
      [(bpf/jmp-imm :jeq :r9 22 :interactive)]
      [(bpf/jmp-imm :jeq :r9 53 :interactive)]

      ;; HTTP (80), HTTPS (443) -> Normal
      [(bpf/jmp-imm :jeq :r9 80 :normal)]
      [(bpf/jmp-imm :jeq :r9 443 :normal)]

      ;; FTP (20, 21), SMTP (25) -> Bulk
      [(bpf/jmp-imm :jeq :r9 20 :bulk)]
      [(bpf/jmp-imm :jeq :r9 21 :bulk)]
      [(bpf/jmp-imm :jeq :r9 25 :bulk)]

      ;; Default -> Normal
      [(bpf/jmp :normal)]

      ;; :interactive - Set high priority and DSCP_EF
      [(bpf/mov :r5 PRIO_INTERACTIVE)]
      [(bpf/store-mem :w :r6 (:priority SKB_OFFSETS) :r5)]

      ;; Set DSCP_EF in IP ToS
      [(bpf/load-mem :b :r5 :r7 1)]  ; Load ToS byte
      [(bpf/and :r5 0x03)]           ; Clear DSCP (keep ECN)
      [(bpf/mov :r4 DSCP_EF)]
      [(bpf/lsh :r4 2)]              ; Shift to DSCP position
      [(bpf/or-reg :r5 :r4)]
      [(bpf/store-mem :b :r7 1 :r5)] ; Write back

      ;; Update stats[0]
      [(bpf/mov :r5 0)]
      [(bpf/jmp :update-stats)]

      ;; :normal - Set normal priority and DSCP_AF21
      [(bpf/mov :r5 PRIO_NORMAL)]
      [(bpf/store-mem :w :r6 (:priority SKB_OFFSETS) :r5)]

      [(bpf/load-mem :b :r5 :r7 1)]
      [(bpf/and :r5 0x03)]
      [(bpf/mov :r4 DSCP_AF21)]
      [(bpf/lsh :r4 2)]
      [(bpf/or-reg :r5 :r4)]
      [(bpf/store-mem :b :r7 1 :r5)]

      ;; Update stats[1]
      [(bpf/mov :r5 1)]
      [(bpf/jmp :update-stats)]

      ;; :bulk - Set low priority and DSCP_BE
      [(bpf/mov :r5 PRIO_BULK)]
      [(bpf/store-mem :w :r6 (:priority SKB_OFFSETS) :r5)]

      [(bpf/load-mem :b :r5 :r7 1)]
      [(bpf/and :r5 0x03)]
      ;; DSCP_BE = 0, so just keep ECN bits
      [(bpf/store-mem :b :r7 1 :r5)]

      ;; Update stats[2]
      [(bpf/mov :r5 2)]

      ;; :update-stats
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :pass)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :pass
      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))

(defn run-port-classifier [interface]
  (println "Creating QoS port-based classifier...")
  (println "\nClassification rules:")
  (println "  Interactive: SSH(22), DNS(53), ICMP -> Priority 0, DSCP EF")
  (println "  Normal:      HTTP(80), HTTPS(443)    -> Priority 3, DSCP AF21")
  (println "  Bulk:        FTP(20,21), SMTP(25)    -> Priority 6, DSCP BE")
  (println)

  ;; Stats: 0=interactive, 1=normal, 2=bulk
  (let [stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 8
                                   :max-entries 3})]

    (doseq [i (range 3)]
      (bpf/map-update stats-fd i (long-array [0])))

    (let [prog-bytes (create-port-classifier stats-fd)
          prog-fd (bpf/load-program prog-bytes :sched-cls)
          link-fd (bpf/attach-tc prog-fd interface :egress)]

      (println (format "Classifier attached to %s egress" interface))
      (println "Monitoring traffic classification...\n")

      (let [running (atom true)]
        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (let [interactive (aget (bpf/map-lookup stats-fd (int-array [0])) 0)
                normal (aget (bpf/map-lookup stats-fd (int-array [1])) 0)
                bulk (aget (bpf/map-lookup stats-fd (int-array [2])) 0)
                total (+ interactive normal bulk)
                int-pct (if (> total 0) (* 100.0 (/ interactive total)) 0.0)
                norm-pct (if (> total 0) (* 100.0 (/ normal total)) 0.0)
                bulk-pct (if (> total 0) (* 100.0 (/ bulk total)) 0.0)]

            (println (format "Total: %d | Interactive: %d (%.1f%%) | Normal: %d (%.1f%%) | Bulk: %d (%.1f%%)"
                            total interactive int-pct normal norm-pct bulk bulk-pct)))))

      (bpf/detach-tc link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map stats-fd))))
```

### Testing

```bash
# Terminal 1: Start classifier
sudo lein run -m lab-8-2-qos-classifier/run-port-classifier "eth0"

# Terminal 2: Generate different traffic types
# SSH (should be classified as interactive)
ssh user@server

# HTTP (should be classified as normal)
curl http://example.com

# FTP (should be classified as bulk)
ftp server
```

### Expected Output

```
Creating QoS port-based classifier...

Classification rules:
  Interactive: SSH(22), DNS(53), ICMP -> Priority 0, DSCP EF
  Normal:      HTTP(80), HTTPS(443)    -> Priority 3, DSCP AF21
  Bulk:        FTP(20,21), SMTP(25)    -> Priority 6, DSCP BE

Classifier attached to eth0 egress
Monitoring traffic classification...

Total: 1523 | Interactive: 234 (15.4%) | Normal: 1156 (75.9%) | Bulk: 133 (8.7%)
Total: 3456 | Interactive: 456 (13.2%) | Normal: 2789 (80.7%) | Bulk: 211 (6.1%)
Total: 5789 | Interactive: 678 (11.7%) | Normal: 4567 (78.9%) | Bulk: 544 (9.4%)
...
```

## Part 2: Application-Aware Classification

Use packet payload inspection for advanced classification.

### Implementation

```clojure
(defn detect-http-method [data-reg data-end-reg offset]
  "Detect HTTP method (GET, POST, etc.)"
  (vec (concat
    ;; Check for "GET " (0x47455420)
    [(bpf/mov-reg :r4 data-reg)]
    [(bpf/add :r4 offset)]
    [(bpf/add :r4 4)]
    [(bpf/jmp-reg :jgt :r4 data-end-reg :not-http)]

    [(bpf/mov-reg :r4 data-reg)]
    [(bpf/add :r4 offset)]
    [(bpf/load-mem :w :r5 :r4 0)]
    [(bpf/endian-be :w :r5)]
    [(bpf/jmp-imm :jeq :r5 0x47455420 :is-http-get)]  ; "GET "

    ;; Check for "POST" (0x504F5354)
    [(bpf/jmp-imm :jeq :r5 0x504F5354 :is-http-post)]  ; "POST"

    ;; Check for "PUT " (0x50555420)
    [(bpf/jmp-imm :jeq :r5 0x50555420 :is-http-put)]   ; "PUT "

    [(bpf/jmp :not-http)]

    ;; :is-http-get - Read operation, normal priority
    [(bpf/mov :r0 PRIO_NORMAL)]
    [(bpf/jmp :method-done)]

    ;; :is-http-post - Write operation, higher priority
    [(bpf/mov :r0 PRIO_INTERACTIVE)]
    [(bpf/jmp :method-done)]

    ;; :is-http-put
    [(bpf/mov :r0 PRIO_INTERACTIVE)]
    [(bpf/jmp :method-done)]

    ;; :not-http
    [(bpf/mov :r0 PRIO_NORMAL)]

    ;; :method-done
    ;; r0 = priority
    )))

(defn create-application-aware-classifier
  "Classify based on application-layer protocol"
  [stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Parse to TCP data
      ;; ... (Ethernet + IP + TCP headers) ...

      ;; Calculate TCP data offset
      [(bpf/load-mem :b :r5 :r8 12)]  ; TCP data offset field
      [(bpf/rsh :r5 4)]                ; Shift to get offset in 32-bit words
      [(bpf/lsh :r5 2)]                ; Convert to bytes
      [(bpf/mov-reg :r9 :r8)]
      [(bpf/add-reg :r9 :r5)]          ; r9 = TCP payload

      ;; Bounds check
      [(bpf/mov-reg :r4 :r9)]
      [(bpf/add :r4 8)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Detect HTTP
      (detect-http-method :r9 :r3 0)
      ;; r0 = priority

      ;; Set priority
      [(bpf/store-mem :w :r6 (:priority SKB_OFFSETS) :r0)]

      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]

      ;; :pass
      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))
```

## Part 3: Integration with Priority Queueing

Configure Linux qdisc to use priorities set by BPF.

### Setup Priority Qdisc

```bash
# Create prio qdisc with 3 bands
tc qdisc add dev eth0 root handle 1: prio bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1

# Band 0: High priority (interactive)
# Band 1: Normal priority
# Band 2: Low priority (bulk)

# View qdisc
tc qdisc show dev eth0

# View statistics
tc -s qdisc show dev eth0
```

### BPF Sets Priority, Qdisc Enforces

```clojure
(defn create-integrated-classifier
  "Classifier that works with prio qdisc"
  [stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Classify packet (as before)
      ;; ...

      ;; Set both priority and tc_classid
      ;; :interactive
      [(bpf/mov :r5 PRIO_INTERACTIVE)]
      [(bpf/store-mem :w :r6 (:priority SKB_OFFSETS) :r5)]

      ;; Set tc_classid to direct to band 0
      [(bpf/mov :r5 0x00010001)]  ; 1:1 (band 0)
      [(bpf/store-mem :w :r6 68 :r5)]  ; skb->tc_classid

      [(bpf/jmp :accept)]

      ;; :normal
      [(bpf/mov :r5 PRIO_NORMAL)]
      [(bpf/store-mem :w :r6 (:priority SKB_OFFSETS) :r5)]
      [(bpf/mov :r5 0x00010002)]  ; 1:2 (band 1)
      [(bpf/store-mem :w :r6 68 :r5)]

      [(bpf/jmp :accept)]

      ;; :bulk
      [(bpf/mov :r5 PRIO_BULK)]
      [(bpf/store-mem :w :r6 (:priority SKB_OFFSETS) :r5)]
      [(bpf/mov :r5 0x00010003)]  ; 1:3 (band 2)
      [(bpf/store-mem :w :r6 68 :r5)]

      ;; :accept
      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))
```

## Part 4: Dynamic QoS Adjustment

Adjust priorities based on network conditions.

### Implementation

```clojure
(defn create-adaptive-classifier
  "Dynamically adjust priorities based on congestion"
  [congestion-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Check congestion level
      [(bpf/mov :r5 0)]
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 congestion-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :no-congestion)]
      [(bpf/load-mem :w :r5 :r0 0)]  ; Load congestion level (0-100)

      ;; If congestion > 80%, be more aggressive with bulk traffic
      [(bpf/jmp-imm :jgt :r5 80 :high-congestion)]

      ;; :no-congestion or low congestion
      ;; Normal classification
      ;; ...

      ;; :high-congestion
      ;; Drop bulk traffic more aggressively
      ;; Prioritize only interactive traffic
      ;; ...

      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))
```

## Exercises

### Exercise 1: VoIP Detection

Implement VoIP traffic detection:
- Detect RTP streams
- Check packet size patterns
- Set lowest latency priority
- Mark with DSCP EF

### Exercise 2: Fair Queueing

Implement per-flow fair queueing:
- Track flows independently
- Ensure fairness among flows
- Detect greedy flows
- Penalize aggressive senders

### Exercise 3: Latency Measurement

Measure per-priority latency:
- Timestamp packets at ingress
- Measure at egress
- Calculate queueing delay
- Adjust priorities based on latency

### Exercise 4: Bandwidth Guarantees

Combine with Lab 8.1 for guaranteed bandwidth:
- Reserve bandwidth per class
- Allow borrowing when idle
- Enforce minimums under load
- Implement weighted fair queueing

## Summary

In this lab, you learned:
- Implementing packet classification for QoS
- Setting priorities and DSCP marks
- Application-aware traffic classification
- Integration with Linux qdisc
- Building adaptive QoS systems

## Navigation

- **Next**: [Lab 8.3 - Egress Firewall](lab-8-3-egress-firewall.md)
- **Previous**: [Lab 8.1 - Traffic Shaper](lab-8-1-traffic-shaper.md)
- **Home**: [Tutorial Home](../../../README.md)
