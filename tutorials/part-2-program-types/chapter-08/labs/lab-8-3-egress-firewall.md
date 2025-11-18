# Lab 8.3: Egress Firewall

**Duration**: 60-75 minutes | **Difficulty**: Advanced

## Learning Objectives

In this lab, you will:
- Implement outbound traffic filtering with TC
- Build egress firewall rules
- Detect and block data exfiltration
- Monitor outbound connections
- Implement process-based filtering
- Create security policies for egress traffic

## Prerequisites

- Completed [Lab 8.2](lab-8-2-qos-classifier.md)
- Understanding of firewall concepts
- Knowledge of security policies
- Familiarity with data exfiltration techniques

## Introduction

Egress filtering controls outbound traffic from your network. This is critical for:
- **Security**: Prevent data exfiltration
- **Compliance**: Enforce data protection policies
- **Malware containment**: Block C&C communication
- **Policy enforcement**: Restrict unauthorized services

Most firewalls focus on ingress (incoming), but egress filtering is equally important for defense-in-depth.

## Egress Threats

### 1. Data Exfiltration
```
Attacker steals data by:
- Large file transfers to external servers
- DNS tunneling
- ICMP tunneling
- Encrypted channels
```

### 2. Command & Control (C&C)
```
Malware communicates with attacker:
- Periodic beacons
- Downloads additional payloads
- Receives commands
```

### 3. Unauthorized Services
```
Users bypass policies:
- Personal cloud storage
- Unauthorized VPNs
- Peer-to-peer applications
```

## Part 1: Basic Egress Firewall

Let's implement a simple egress firewall with allow/deny rules.

### Implementation

```clojure
(ns lab-8-3-egress-firewall
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.asm-dsl :refer :all]))

;; TC actions
(def TC_ACT_OK 0)
(def TC_ACT_SHOT 2)

;; __sk_buff offsets
(def SKB_OFFSETS
  {:data 76
   :data-end 80})

;; Protocol values
(def ETH_P_IP 0x0800)
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

(defn ip-to-u32 [ip-str]
  (let [parts (mapv #(Integer/parseInt %) (clojure.string/split ip-str #"\."))]
    (bit-or
      (bit-shift-left (parts 0) 24)
      (bit-shift-left (parts 1) 16)
      (bit-shift-left (parts 2) 8)
      (parts 3))))

;; Blocked destinations
(def BLOCKED_IPS
  [(ip-to-u32 "192.168.100.50")   ; Suspicious server
   (ip-to-u32 "10.0.50.100")])    ; Unauthorized service

;; Blocked ports
(def BLOCKED_PORTS
  [23     ; Telnet (insecure)
   445    ; SMB (often exploited)
   3389   ; RDP (restrict external access)
   6667]) ; IRC (potential malware C&C)

(defn create-egress-firewall
  "Basic egress firewall with IP and port filtering"
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
      [(bpf/jmp-reg :jgt :r4 :r3 :accept)]

      ;; Check IPv4
      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :accept)]

      ;; IP header
      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :accept)]

      ;; Rule 1: Check destination IP
      [(bpf/load-mem :w :r8 :r7 16)]  ; dst IP
      [(bpf/endian-be :w :r8)]

      ;; Check against blocked IPs
      [(bpf/jmp-imm :jeq :r8 (ip-to-u32 "192.168.100.50") :block-ip)]
      [(bpf/jmp-imm :jeq :r8 (ip-to-u32 "10.0.50.100") :block-ip)]

      ;; Rule 2: Check destination port for TCP/UDP
      [(bpf/load-mem :b :r5 :r7 9)]
      [(bpf/jmp-imm :jeq :r5 IPPROTO_TCP :check-port)]
      [(bpf/jmp-imm :jeq :r5 IPPROTO_UDP :check-port)]
      [(bpf/jmp :accept)]  ; Not TCP/UDP, accept

      ;; :check-port
      ;; Get L4 header
      [(bpf/load-mem :b :r5 :r7 0)]
      [(bpf/and :r5 0x0F)]
      [(bpf/lsh :r5 2)]
      [(bpf/mov-reg :r9 :r7)]
      [(bpf/add-reg :r9 :r5)]  ; r9 = L4 header

      [(bpf/mov-reg :r4 :r9)]
      [(bpf/add :r4 4)]
      [(bpf/jmp-reg :jgt :r4 :r3 :accept)]

      ;; Read destination port
      [(bpf/load-mem :h :r5 :r9 2)]
      [(bpf/endian-be :h :r5)]

      ;; Check against blocked ports
      [(bpf/jmp-imm :jeq :r5 23 :block-port)]    ; Telnet
      [(bpf/jmp-imm :jeq :r5 445 :block-port)]   ; SMB
      [(bpf/jmp-imm :jeq :r5 3389 :block-port)]  ; RDP
      [(bpf/jmp-imm :jeq :r5 6667 :block-port)]  ; IRC

      ;; Passed all rules, accept
      [(bpf/jmp :accept)]

      ;; :block-ip
      [(bpf/mov :r5 0)]
      [(bpf/jmp :update-blocked)]

      ;; :block-port
      [(bpf/mov :r5 1)]

      ;; :update-blocked
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :drop)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :drop
      [(bpf/mov :r0 TC_ACT_SHOT)]
      [(bpf/exit-insn)]

      ;; :accept
      [(bpf/mov :r5 2)]
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :accept-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :accept-exit
      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))

(defn run-egress-firewall [interface]
  (println "Creating TC egress firewall...")
  (println "\nFirewall Rules:")
  (println "  Block IP: 192.168.100.50 (suspicious server)")
  (println "  Block IP: 10.0.50.100 (unauthorized service)")
  (println "  Block Port: 23 (Telnet), 445 (SMB), 3389 (RDP), 6667 (IRC)")
  (println)

  ;; Stats: 0=blocked by IP, 1=blocked by port, 2=accepted
  (let [stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 8
                                   :max-entries 3})]

    (doseq [i (range 3)]
      (bpf/map-update stats-fd i (long-array [0])))

    (let [prog-bytes (create-egress-firewall stats-fd)
          prog-fd (bpf/load-program prog-bytes :sched-cls)
          link-fd (bpf/attach-tc prog-fd interface :egress)]

      (println (format "Egress firewall attached to %s" interface))
      (println "Monitoring outbound traffic...\n")

      (let [running (atom true)]
        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (let [blocked-ip (aget (bpf/map-lookup stats-fd (int-array [0])) 0)
                blocked-port (aget (bpf/map-lookup stats-fd (int-array [1])) 0)
                accepted (aget (bpf/map-lookup stats-fd (int-array [2])) 0)
                total-blocked (+ blocked-ip blocked-port)]

            (println (format "Accepted: %d | Blocked: %d (IP: %d, Port: %d)"
                            accepted total-blocked blocked-ip blocked-port))

            (when (> total-blocked 0)
              (println "  ⚠ Security policy violations detected!")))))

      (bpf/detach-tc link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map stats-fd))))
```

### Testing

```bash
# Terminal 1: Start egress firewall
sudo lein run -m lab-8-3-egress-firewall/run-egress-firewall "eth0"

# Terminal 2: Try to connect to blocked IP
telnet 192.168.100.50
# Should be blocked

# Terminal 3: Try to connect to blocked port
telnet example.com 3389
# Should be blocked

# Terminal 4: Normal connection (should work)
curl http://example.com
```

### Expected Output

```
Creating TC egress firewall...

Firewall Rules:
  Block IP: 192.168.100.50 (suspicious server)
  Block IP: 10.0.50.100 (unauthorized service)
  Block Port: 23 (Telnet), 445 (SMB), 3389 (RDP), 6667 (IRC)

Egress firewall attached to eth0
Monitoring outbound traffic...

Accepted: 1234 | Blocked: 0 (IP: 0, Port: 0)
Accepted: 2456 | Blocked: 12 (IP: 5, Port: 7)
  ⚠ Security policy violations detected!
Accepted: 3789 | Blocked: 28 (IP: 12, Port: 16)
  ⚠ Security policy violations detected!
...
```

## Part 2: Data Exfiltration Detection

Detect suspicious large data transfers.

### Implementation

```clojure
(def EXFIL_THRESHOLD_BYTES (* 10 1024 1024))  ; 10 MB
(def EXFIL_WINDOW_NS (* 60 1000000000))        ; 60 seconds

(defn create-exfiltration-detector
  "Detect large data transfers (potential exfiltration)"
  [transfer-tracker-fd alerts-fd]
  (bpf/assemble
    (vec (concat
      ;; Get destination IP
      ;; ... (parse to get dst_ip in r8) ...

      ;; Get packet length
      [(bpf/load-mem :w :r7 :r6 0)]  ; packet length

      ;; Get current time
      (bpf/helper-ktime-get-ns)
      [(bpf/mov-reg :r9 :r0)]

      ;; Track bytes per destination IP
      [(bpf/store-mem :w :r10 -4 :r8)]  ; key = dst_ip

      [(bpf/ld-map-fd :r1 transfer-tracker-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jne :r0 0 :have-state)]

      ;; :init-state
      ;; State: {start_time (u64), bytes_transferred (u64)}
      [(bpf/store-mem :dw :r10 -16 :r9)]  ; start_time = now
      [(bpf/mov-reg :r4 :r7)]
      [(bpf/store-mem :dw :r10 -8 :r4)]   ; bytes = packet_len

      [(bpf/ld-map-fd :r1 transfer-tracker-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -24)]
      [(bpf/mov-reg :r3 :r10)]
      [(bpf/add :r3 -16)]
      [(bpf/mov :r4 0)]
      (bpf/helper-map-update-elem :r1 :r2 :r3)

      [(bpf/jmp :accept)]

      ;; :have-state
      [(bpf/mov-reg :r5 :r0)]  ; State pointer

      ;; Load start_time and bytes
      [(bpf/load-mem :dw :r6 :r5 0)]  ; start_time
      [(bpf/load-mem :dw :r4 :r5 8)]  ; bytes_transferred

      ;; Check if window expired
      [(bpf/mov-reg :r3 :r9)]
      [(bpf/sub-reg :r3 :r6)]  ; elapsed = now - start_time

      [(bpf/mov :r2 EXFIL_WINDOW_NS)]
      [(bpf/jmp-reg :jgt :r3 :r2 :reset-window)]

      ;; :update-window
      ;; Add bytes to counter
      [(bpf/add-reg :r4 :r7)]
      [(bpf/store-mem :dw :r5 8 :r4)]

      ;; Check threshold
      [(bpf/mov :r3 EXFIL_THRESHOLD_BYTES)]
      [(bpf/jmp-reg :jle :r4 :r3 :accept)]

      ;; :exfiltration-detected!
      ;; Alert and block
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -32 :r4)]

      [(bpf/ld-map-fd :r1 alerts-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -32)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :block)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :block
      [(bpf/mov :r0 TC_ACT_SHOT)]
      [(bpf/exit-insn)]

      ;; :reset-window
      [(bpf/store-mem :dw :r5 0 :r9)]  ; start_time = now
      [(bpf/mov-reg :r4 :r7)]
      [(bpf/store-mem :dw :r5 8 :r4)]  ; bytes = packet_len

      ;; :accept
      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))
```

## Part 3: DNS-Based Filtering

Block connections based on DNS queries (requires DNS lookup tracking).

### Concept

```
1. Monitor DNS queries (UDP port 53)
2. Track domain → IP mappings
3. Apply policies based on domains
4. Block traffic to blacklisted domains
```

### Implementation

```clojure
(defn create-dns-aware-firewall
  "Block based on domain names (requires DNS tracking)"
  [domain-map-fd blocked-ips-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Get destination IP
      ;; ... (parse packet to get dst_ip in r8) ...

      ;; Lookup if this IP is blocked
      [(bpf/store-mem :w :r10 -4 :r8)]

      [(bpf/ld-map-fd :r1 blocked-ips-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If found in blocked list, drop
      [(bpf/jmp-imm :jne :r0 0 :block)]

      ;; Accept
      [(bpf/jmp :accept)]

      ;; :block
      [(bpf/mov :r0 TC_ACT_SHOT)]
      [(bpf/exit-insn)]

      ;; :accept
      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))
```

### Companion DNS Tracker

```clojure
;; Separate program on ingress to track DNS responses
(defn create-dns-tracker
  "Parse DNS responses and populate domain-IP map"
  [domain-map-fd]
  (bpf/assemble
    (vec (concat
      ;; Check if UDP port 53 (DNS)
      ;; ... (parse to UDP) ...

      ;; Parse DNS response
      ;; Extract domain name and IP address
      ;; Update domain-map
      ;; ...

      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))
```

## Part 4: Connection Logging

Log all outbound connections for audit trails.

### Implementation

```clojure
(defrecord ConnectionLog
  [timestamp      ; When connection initiated
   src-ip         ; Source IP
   dst-ip         ; Destination IP
   dst-port       ; Destination port
   protocol       ; TCP/UDP/etc
   action])       ; ALLOWED or BLOCKED

(defn create-connection-logger
  "Log outbound connections to ring buffer"
  [events-fd]
  (bpf/assemble
    (vec (concat
      ;; Parse packet to get 5-tuple
      ;; ... (src_ip, dst_ip, src_port, dst_port, proto) ...

      ;; Reserve space in ring buffer
      [(bpf/ld-map-fd :r1 events-fd)]
      [(bpf/mov :r2 32)]  ; Event size
      [(bpf/mov :r3 0)]
      (bpf/helper-ringbuf-reserve :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :accept)]
      [(bpf/mov-reg :r9 :r0)]  ; Event pointer

      ;; Fill event
      (bpf/helper-ktime-get-ns)
      [(bpf/store-mem :dw :r9 0 :r0)]  ; timestamp

      ;; Copy IP addresses, ports, protocol
      ;; ...

      ;; Submit event
      [(bpf/mov-reg :r1 :r9)]
      [(bpf/mov :r2 0)]
      (bpf/helper-ringbuf-submit :r1)

      ;; :accept
      [(bpf/mov :r0 TC_ACT_OK)]
      [(bpf/exit-insn)]))))
```

## Exercises

### Exercise 1: GeoIP Blocking

Block connections to specific countries:
- Use GeoIP database in map
- Lookup destination IP
- Block based on country code
- Allowlist exceptions

### Exercise 2: Time-Based Policies

Implement time-based firewall rules:
- Allow certain traffic only during business hours
- Block non-business services after hours
- Weekend vs weekday policies

### Exercise 3: Bandwidth-Based Detection

Detect anomalies by bandwidth:
- Track bytes per destination
- Calculate moving average
- Detect sudden spikes
- Alert on anomalies

### Exercise 4: Application Fingerprinting

Identify applications by traffic patterns:
- Analyze packet sizes
- Check inter-packet timing
- Detect specific applications
- Apply per-app policies

## Summary

In this lab, you learned:
- Building egress firewalls with TC
- Detecting data exfiltration
- Implementing security policies
- Connection logging and monitoring
- Advanced filtering techniques

**Key Takeaway**: Egress filtering is critical for defense-in-depth security. While ingress firewalls protect from external attacks, egress firewalls prevent data loss and malware C&C communication.

## Navigation

- **Next**: [Chapter 9 - LSM](../../chapter-09/README.md)
- **Previous**: [Lab 8.2 - QoS Classifier](lab-8-2-qos-classifier.md)
- **Home**: [Tutorial Home](../../../README.md)
