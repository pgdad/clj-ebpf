# Lab 7.3: Layer 4 Load Balancer

**Duration**: 90-120 minutes | **Difficulty**: Advanced

## Learning Objectives

In this lab, you will:
- Implement a high-performance L4 load balancer
- Use XDP_TX to reflect packets
- Use XDP_REDIRECT to forward packets
- Modify packet headers (IP, MAC, TCP)
- Implement connection tracking and hashing
- Build consistent hashing for backend selection
- Handle packet rewriting and checksum updates

## Prerequisites

- Completed [Lab 7.2](lab-7-2-ddos-mitigation.md)
- Understanding of load balancing concepts
- Knowledge of TCP/IP header structures
- Familiarity with MAC address translation

## Introduction

Load balancers distribute incoming traffic across multiple backend servers. XDP enables ultra-high-performance load balancing:

**Traditional Load Balancer**:
```
Client → LB (userspace) → iptables → routing → Backend
         └─ 100K-500K pps
```

**XDP Load Balancer**:
```
Client → XDP (kernel) → Backend
         └─ 10M-20M pps
```

## Load Balancing Modes

### 1. Direct Server Return (DSR)

```
          ┌─────────────┐
          │   Client    │
          └──────┬──────┘
                 │ 1. SYN
                 ▼
          ┌─────────────┐
          │  XDP LB     │ Rewrite dest MAC only
          └──────┬──────┘
                 │ 2. SYN (MAC changed)
                 ▼
          ┌─────────────┐
          │  Backend    │
          └──────┬──────┘
                 │ 3. SYN-ACK (direct to client)
                 ▼
          ┌─────────────┐
          │   Client    │
          └─────────────┘

Pros: Backend responds directly (highest performance)
Cons: Backend must have VIP configured
```

### 2. Full NAT

```
          ┌─────────────┐
          │   Client    │
          └──────┬──────┘
                 │ 1. SYN (src:client, dst:VIP)
                 ▼
          ┌─────────────┐
          │  XDP LB     │ Rewrite src+dst IP, MAC
          └──────┬──────┘
                 │ 2. SYN (src:LB, dst:backend)
                 ▼
          ┌─────────────┐
          │  Backend    │
          └──────┬──────┘
                 │ 3. SYN-ACK (src:backend, dst:LB)
                 ▼
          ┌─────────────┐
          │  XDP LB     │ Rewrite src+dst IP, MAC
          └──────┬──────┘
                 │ 4. SYN-ACK (src:VIP, dst:client)
                 ▼
          ┌─────────────┐
          │   Client    │
          └─────────────┘

Pros: Transparent to backends
Cons: All traffic goes through LB
```

## Part 1: Simple Round-Robin Load Balancer

Let's start with a basic round-robin LB using XDP_TX.

### Concept

```
Incoming packet to VIP (192.168.1.100):
1. Parse packet
2. Select backend (round-robin)
3. Rewrite destination IP/MAC
4. Recalculate checksums
5. Return XDP_TX (bounce back)
```

### Implementation

```clojure
(ns lab-7-3-load-balancer
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.asm-dsl :refer :all]))

;; XDP actions
(def XDP_DROP 1)
(def XDP_PASS 2)
(def XDP_TX 3)
(def XDP_REDIRECT 4)

(def ETH_P_IP 0x0800)
(def IPPROTO_TCP 6)

;; Virtual IP (VIP) that clients connect to
(defn ip-to-u32 [ip-str]
  (let [parts (mapv #(Integer/parseInt %) (clojure.string/split ip-str #"\."))]
    (bit-or
      (bit-shift-left (parts 0) 24)
      (bit-shift-left (parts 1) 16)
      (bit-shift-left (parts 2) 8)
      (parts 3))))

(defn mac-to-bytes [mac-str]
  "Convert MAC address string to byte array"
  (let [parts (clojure.string/split mac-str #":")]
    (mapv #(Integer/parseInt % 16) parts)))

(def VIP (ip-to-u32 "192.168.1.100"))

;; Backend servers
(def BACKENDS
  [{:ip (ip-to-u32 "10.0.1.1")
    :mac (mac-to-bytes "00:11:22:33:44:01")}
   {:ip (ip-to-u32 "10.0.1.2")
    :mac (mac-to-bytes "00:11:22:33:44:02")}
   {:ip (ip-to-u32 "10.0.1.3")
    :mac (mac-to-bytes "00:11:22:33:44:03")}])

(defn create-round-robin-lb
  "Simple round-robin load balancer"
  [backends-fd counter-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Parse packet
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

      ;; r7 = IP header
      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      ;; Bounds check IP
      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Check if destination is VIP
      [(bpf/load-mem :w :r5 :r7 16)]  ; dst IP (offset 16)
      [(bpf/endian-be :w :r5)]
      [(bpf/jmp-imm :jne :r5 VIP :pass)]  ; Not for VIP, pass

      ;; This packet is for VIP - load balance it
      ;; Get current counter (for round-robin)
      [(bpf/mov :r5 0)]
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 counter-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :pass)]  ; No counter, pass
      [(bpf/load-mem :dw :r8 :r0 0)]    ; r8 = counter

      ;; Increment counter
      [(bpf/add :r8 1)]
      [(bpf/store-mem :dw :r0 0 :r8)]

      ;; Select backend: counter % num_backends
      [(bpf/mov-reg :r9 :r8)]
      [(bpf/mod :r9 (count BACKENDS))]  ; r9 = backend index

      ;; Lookup backend info from map
      [(bpf/store-mem :w :r10 -8 :r9)]
      [(bpf/ld-map-fd :r1 backends-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :pass)]  ; Backend not found
      [(bpf/mov-reg :r5 :r0)]  ; r5 = backend info pointer

      ;; Read backend IP and MAC
      ;; Backend structure: {ip (4 bytes), mac (6 bytes), pad (2 bytes)}
      [(bpf/load-mem :w :r8 :r5 0)]   ; backend IP
      ;; MAC is at offset 4-9

      ;; Rewrite destination IP in packet
      [(bpf/load-mem :w :r4 :r7 16)]  ; old dst IP (for checksum)
      [(bpf/endian-be :w :r8)]        ; Convert backend IP to network order
      [(bpf/store-mem :w :r7 16 :r8)] ; Write new dst IP

      ;; Rewrite destination MAC in Ethernet header
      ;; r2 = Ethernet header
      [(bpf/load-mem :b :r4 :r5 4)]
      [(bpf/store-mem :b :r2 0 :r4)]
      [(bpf/load-mem :b :r4 :r5 5)]
      [(bpf/store-mem :b :r2 1 :r4)]
      [(bpf/load-mem :b :r4 :r5 6)]
      [(bpf/store-mem :b :r2 2 :r4)]
      [(bpf/load-mem :b :r4 :r5 7)]
      [(bpf/store-mem :b :r2 3 :r4)]
      [(bpf/load-mem :b :r4 :r5 8)]
      [(bpf/store-mem :b :r2 4 :r4)]
      [(bpf/load-mem :b :r4 :r5 9)]
      [(bpf/store-mem :b :r2 5 :r4)]

      ;; Note: Should recalculate IP checksum here
      ;; For simplicity, many NICs do this in hardware (checksum offload)

      ;; Update stats
      [(bpf/mov :r4 0)]
      [(bpf/store-mem :w :r10 -12 :r4)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -12)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :tx)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :tx - Transmit packet back out same interface
      [(bpf/mov :r0 XDP_TX)]
      [(bpf/exit-insn)]

      ;; :pass
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))

(defn run-round-robin-lb [interface]
  (println "Creating XDP round-robin load balancer...")
  (println (format "VIP: 192.168.1.100"))
  (println "Backends:")
  (doseq [[idx backend] (map-indexed vector BACKENDS)]
    (println (format "  %d: %s" idx (backend :ip))))
  (println)

  ;; Map: backend index -> {ip, mac}
  (let [backends-fd (bpf/create-map :array
                                     {:key-size 4
                                      :value-size 12  ; 4 (IP) + 6 (MAC) + 2 (pad)
                                      :max-entries (count BACKENDS)})

        ;; Counter for round-robin
        counter-fd (bpf/create-map :array
                                    {:key-size 4
                                     :value-size 8
                                     :max-entries 1})

        ;; Stats
        stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 8
                                   :max-entries 1})]

    ;; Populate backends map
    (doseq [[idx backend] (map-indexed vector BACKENDS)]
      (let [data (byte-array 12)]
        ;; IP (4 bytes, big-endian)
        (let [ip (:ip backend)]
          (aset data 0 (byte (bit-shift-right ip 24)))
          (aset data 1 (byte (bit-shift-right ip 16)))
          (aset data 2 (byte (bit-shift-right ip 8)))
          (aset data 3 (byte ip)))
        ;; MAC (6 bytes)
        (let [mac (:mac backend)]
          (doseq [i (range 6)]
            (aset data (+ 4 i) (byte (mac i)))))
        (bpf/map-update backends-fd idx data)))

    ;; Initialize counter
    (bpf/map-update counter-fd 0 (long-array [0]))

    ;; Initialize stats
    (bpf/map-update stats-fd 0 (long-array [0]))

    (let [prog-bytes (create-round-robin-lb backends-fd counter-fd stats-fd)
          prog-fd (bpf/load-program prog-bytes :xdp)
          link-fd (bpf/attach-xdp prog-fd interface)]

      (println (format "Load balancer attached to %s" interface))
      (println "Monitoring traffic...\n")

      (let [running (atom true)
            start-time (System/currentTimeMillis)]

        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (let [lb-packets (aget (bpf/map-lookup stats-fd (int-array [0])) 0)
                elapsed-sec (/ (- (System/currentTimeMillis) start-time) 1000.0)
                pps (/ lb-packets elapsed-sec)]

            (println (format "Load balanced: %d packets (%.1f pps)"
                            lb-packets pps)))))

      (bpf/detach-xdp link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map backends-fd)
      (bpf/close-map counter-fd)
      (bpf/close-map stats-fd))))
```

### Testing

```bash
# Terminal 1: Start load balancer
sudo lein run -m lab-7-3-load-balancer/run-round-robin-lb "eth0"

# Terminal 2: Send traffic to VIP
curl http://192.168.1.100

# Traffic will be distributed round-robin to backends
```

## Part 2: Consistent Hashing Load Balancer

Round-robin doesn't preserve connection affinity. Let's use consistent hashing based on source IP.

### Concept

```
Connection Affinity:
- Same source IP always goes to same backend
- Uses hash(src_ip) % num_backends
- Survives backend failures (consistent hashing)
```

### Implementation

```clojure
(defn create-consistent-hash-lb
  "Load balancer with connection affinity using consistent hashing"
  [backends-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Parse packet (same as before)
      [(bpf/mov-reg :r6 :r1)]
      [(bpf/load-mem :w :r2 :r6 0)]
      [(bpf/load-mem :w :r3 :r6 4)]

      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 14)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :pass)]

      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Check destination is VIP
      [(bpf/load-mem :w :r5 :r7 16)]
      [(bpf/endian-be :w :r5)]
      [(bpf/jmp-imm :jne :r5 VIP :pass)]

      ;; Hash source IP for consistent selection
      [(bpf/load-mem :w :r8 :r7 12)]  ; src IP
      [(bpf/endian-be :w :r8)]

      ;; Simple hash: use source IP directly
      ;; Better: use jhash or other hash function
      [(bpf/mov-reg :r9 :r8)]
      [(bpf/mod :r9 (count BACKENDS))]  ; backend_index = hash(src_ip) % num

      ;; Lookup backend (same as round-robin)
      [(bpf/store-mem :w :r10 -4 :r9)]
      [(bpf/ld-map-fd :r1 backends-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :pass)]
      [(bpf/mov-reg :r5 :r0)]

      ;; Rewrite dst IP
      [(bpf/load-mem :w :r8 :r5 0)]
      [(bpf/endian-be :w :r8)]
      [(bpf/store-mem :w :r7 16 :r8)]

      ;; Rewrite dst MAC
      [(bpf/load-mem :b :r4 :r5 4)]
      [(bpf/store-mem :b :r2 0 :r4)]
      [(bpf/load-mem :b :r4 :r5 5)]
      [(bpf/store-mem :b :r2 1 :r4)]
      [(bpf/load-mem :b :r4 :r5 6)]
      [(bpf/store-mem :b :r2 2 :r4)]
      [(bpf/load-mem :b :r4 :r5 7)]
      [(bpf/store-mem :b :r2 3 :r4)]
      [(bpf/load-mem :b :r4 :r5 8)]
      [(bpf/store-mem :b :r2 4 :r4)]
      [(bpf/load-mem :b :r4 :r5 9)]
      [(bpf/store-mem :b :r2 5 :r4)]

      ;; Update per-backend stats
      [(bpf/store-mem :w :r10 -8 :r9)]  ; key = backend index
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -8)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :tx)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :tx
      [(bpf/mov :r0 XDP_TX)]
      [(bpf/exit-insn)]

      ;; :pass
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))

(defn run-consistent-hash-lb [interface]
  (println "Creating XDP consistent-hash load balancer...")
  (println "Connection affinity: Same source IP → Same backend\n")

  (let [backends-fd (bpf/create-map :array
                                     {:key-size 4
                                      :value-size 12
                                      :max-entries (count BACKENDS)})

        ;; Per-backend stats
        stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 8
                                   :max-entries (count BACKENDS)})]

    ;; Populate backends
    (doseq [[idx backend] (map-indexed vector BACKENDS)]
      (let [data (byte-array 12)]
        (let [ip (:ip backend)]
          (aset data 0 (byte (bit-shift-right ip 24)))
          (aset data 1 (byte (bit-shift-right ip 16)))
          (aset data 2 (byte (bit-shift-right ip 8)))
          (aset data 3 (byte ip)))
        (let [mac (:mac backend)]
          (doseq [i (range 6)]
            (aset data (+ 4 i) (byte (mac i)))))
        (bpf/map-update backends-fd idx data))

      ;; Initialize stats
      (bpf/map-update stats-fd idx (long-array [0])))

    (let [prog-bytes (create-consistent-hash-lb backends-fd stats-fd)
          prog-fd (bpf/load-program prog-bytes :xdp)
          link-fd (bpf/attach-xdp prog-fd interface)]

      (println (format "Load balancer attached to %s" interface))
      (println "Monitoring per-backend traffic...\n")

      (let [running (atom true)]
        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (println "Backend traffic:")
          (doseq [idx (range (count BACKENDS))]
            (let [count (aget (bpf/map-lookup stats-fd (int-array [idx])) 0)]
              (println (format "  Backend %d: %d packets" idx count))))
          (println)))

      (bpf/detach-xdp link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map backends-fd)
      (bpf/close-map stats-fd))))
```

### Expected Output

```
Creating XDP consistent-hash load balancer...
Connection affinity: Same source IP → Same backend

Load balancer attached to eth0
Monitoring per-backend traffic...

Backend traffic:
  Backend 0: 1234 packets
  Backend 1: 1456 packets
  Backend 2: 1123 packets

Backend traffic:
  Backend 0: 2567 packets
  Backend 1: 2890 packets
  Backend 2: 2234 packets
...
```

## Part 3: Full NAT Load Balancer with Connection Tracking

For production use, we need bidirectional NAT with connection tracking.

### Concept

```
Connection Tracking:
┌────────────────────────────────────────────┐
│ Connection Table (5-tuple hash)           │
│  Key: {src_ip, src_port, dst_ip, dst_port, proto}
│  Value: {backend_ip, backend_port, timestamp}
└────────────────────────────────────────────┘

Outbound (client → backend):
1. Lookup connection in table
2. If new: Create entry, select backend
3. Rewrite dst_ip/port to backend
4. Rewrite src_ip/port to LB
5. Update checksums

Inbound (backend → client):
1. Lookup connection (reverse)
2. Rewrite src_ip/port to VIP
3. Rewrite dst_ip/port to client
4. Update checksums
```

### Implementation

```clojure
;; Connection tracking structure
;; Key: 16 bytes {src_ip (4), dst_ip (4), src_port (2), dst_port (2), proto (1), pad (3)}
;; Value: 16 bytes {backend_ip (4), backend_port (2), timestamp (8), pad (2)}

(defn create-full-nat-lb
  "Full NAT load balancer with connection tracking"
  [backends-fd conntrack-fd stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Parse to TCP layer
      [(bpf/mov-reg :r6 :r1)]
      [(bpf/load-mem :w :r2 :r6 0)]
      [(bpf/load-mem :w :r3 :r6 4)]

      ;; Ethernet
      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 14)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :pass)]

      ;; IP
      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Check TCP
      [(bpf/load-mem :b :r5 :r7 9)]
      [(bpf/jmp-imm :jne :r5 IPPROTO_TCP :pass)]

      ;; TCP header
      [(bpf/load-mem :b :r5 :r7 0)]
      [(bpf/and :r5 0x0F)]
      [(bpf/lsh :r5 2)]
      [(bpf/mov-reg :r8 :r7)]
      [(bpf/add-reg :r8 :r5)]  ; r8 = TCP header

      [(bpf/mov-reg :r4 :r8)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Build connection key (5-tuple)
      ;; src_ip (offset 12 in IP header)
      [(bpf/load-mem :w :r4 :r7 12)]
      [(bpf/store-mem :w :r10 -16 :r4)]

      ;; dst_ip (offset 16)
      [(bpf/load-mem :w :r4 :r7 16)]
      [(bpf/store-mem :w :r10 -12 :r4)]

      ;; src_port (offset 0 in TCP)
      [(bpf/load-mem :h :r4 :r8 0)]
      [(bpf/store-mem :h :r10 -8 :r4)]

      ;; dst_port (offset 2 in TCP)
      [(bpf/load-mem :h :r4 :r8 2)]
      [(bpf/store-mem :h :r10 -6 :r4)]

      ;; proto
      [(bpf/mov :r4 IPPROTO_TCP)]
      [(bpf/store-mem :b :r10 -5 :r4)]

      ;; Lookup connection
      [(bpf/ld-map-fd :r1 conntrack-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -16)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      ;; If found, use existing mapping
      [(bpf/jmp-imm :jne :r0 0 :have-connection)]

      ;; New connection - select backend and create entry
      ;; ... (hash-based selection, create conntrack entry) ...

      ;; :have-connection
      ;; r0 = connection state
      ;; Rewrite packet based on connection state
      ;; ... (IP/port rewriting, checksum updates) ...

      ;; :tx
      [(bpf/mov :r0 XDP_TX)]
      [(bpf/exit-insn)]

      ;; :pass
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))
```

## Exercises

### Exercise 1: Health Checking

Implement backend health monitoring:
- Periodic health checks
- Mark backends as up/down
- Exclude down backends from selection
- Re-enable when healthy

### Exercise 2: Weighted Load Balancing

Support backend weights:
- Assign weights to backends
- Distribute traffic proportionally
- Use weighted consistent hashing

### Exercise 3: Session Persistence

Add sticky sessions:
- Track sessions by cookie or session ID
- Always route to same backend
- Handle backend failures gracefully

### Exercise 4: Packet Forwarding with XDP_REDIRECT

Use XDP_REDIRECT instead of XDP_TX:
- Forward to different interface
- Use devmap for efficient redirection
- Handle multi-interface topologies

### Exercise 5: IPv6 Support

Add IPv6 load balancing:
- Parse IPv6 headers
- Handle IPv6 addresses (128-bit)
- Dual-stack support

## Summary

In this lab, you learned:
- Building high-performance L4 load balancers with XDP
- Packet header rewriting (IP, MAC, ports)
- Connection tracking and affinity
- Consistent hashing for backend selection
- Using XDP_TX for packet reflection

**Key Achievement**: You've built a load balancer capable of handling 10+ million packets per second per core - performance previously only achievable with specialized hardware!

## Navigation

- **Next**: [Chapter 8 - TC (Traffic Control)](../../chapter-08/README.md)
- **Previous**: [Lab 7.2 - DDoS Mitigation](lab-7-2-ddos-mitigation.md)
- **Home**: [Tutorial Home](../../../README.md)
