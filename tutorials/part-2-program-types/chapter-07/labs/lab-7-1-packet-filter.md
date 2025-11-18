# Lab 7.1: Basic Packet Filter

**Duration**: 60-75 minutes | **Difficulty**: Advanced

## Learning Objectives

In this lab, you will:
- Parse Ethernet, IPv4, and TCP/UDP headers in XDP
- Implement packet filtering based on IP addresses and ports
- Use XDP return codes (DROP, PASS)
- Handle network byte order correctly
- Build a high-performance firewall
- Measure XDP performance

## Prerequisites

- Completed [Lab 6.3](../../chapter-06/labs/lab-6-3-syscall-analyzer.md)
- Strong understanding of TCP/IP networking
- Familiarity with packet structure and headers
- Root/sudo access for XDP attachment

## Introduction

XDP packet filtering operates at the earliest point in the network stack, providing line-rate filtering capabilities. This lab implements a simple but powerful firewall that can:
- Filter by source/destination IP addresses
- Filter by TCP/UDP ports
- Block specific protocols (ICMP, SSH, HTTP)
- Maintain statistics on dropped vs passed packets

## Part 1: Basic IP Address Filter

Let's start by filtering packets based on source IP address.

### Network Byte Order

**CRITICAL**: Network protocols use big-endian (network byte order). You must convert multi-byte values!

```clojure
;; IP addresses and ports are in big-endian
;; Example: IP 192.168.1.1 = 0xC0A80101 (big-endian)
;;                          = 0x0101A8C0 (little-endian on x86)

;; Always use endian conversion:
[(bpf/load-mem :h :r5 :r6 12)]  ; Load 16-bit value
[(bpf/endian-be :h :r5)]        ; Convert to host byte order

[(bpf/load-mem :w :r5 :r7 12)]  ; Load 32-bit value
[(bpf/endian-be :w :r5)]        ; Convert to host byte order
```

### Implementation

```clojure
(ns lab-7-1-packet-filter
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.asm-dsl :refer :all]))

;; Protocol numbers
(def IPPROTO_ICMP 1)
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

;; EtherTypes
(def ETH_P_IP 0x0800)
(def ETH_P_IPV6 0x86DD)
(def ETH_P_ARP 0x0806)

;; XDP actions
(def XDP_ABORTED 0)
(def XDP_DROP 1)
(def XDP_PASS 2)
(def XDP_TX 3)
(def XDP_REDIRECT 4)

;; Blocked IP addresses (in network byte order)
(defn ip-to-u32 [ip-str]
  "Convert IP string to u32 (big-endian)"
  (let [parts (mapv #(Integer/parseInt %) (clojure.string/split ip-str #"\."))]
    (bit-or
      (bit-shift-left (parts 0) 24)
      (bit-shift-left (parts 1) 16)
      (bit-shift-left (parts 2) 8)
      (parts 3))))

(def BLOCKED_IPS
  [(ip-to-u32 "10.0.0.1")      ; Example blocked IPs
   (ip-to-u32 "192.168.1.100")])

(defn create-ip-filter
  "Drop packets from blocked IP addresses"
  [stats-fd]
  (bpf/assemble
    (vec (concat
      ;; r1 = ctx (struct xdp_md *)
      [(bpf/mov-reg :r6 :r1)]  ; Save ctx

      ;; Load data and data_end pointers
      [(bpf/load-mem :w :r2 :r6 0)]   ; data
      [(bpf/load-mem :w :r3 :r6 4)]   ; data_end

      ;; r2 = Ethernet header
      ;; r3 = data_end

      ;; Bounds check: data + 14 (Ethernet header) <= data_end
      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 14)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]  ; Packet too small, pass

      ;; Read EtherType (offset 12, 2 bytes)
      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]  ; Convert to host byte order

      ;; Check if IPv4
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :pass)]

      ;; r7 = IP header (data + 14)
      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      ;; Bounds check: IP header + 20 <= data_end
      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Read source IP address (offset 12 in IP header)
      [(bpf/load-mem :w :r8 :r7 12)]
      [(bpf/endian-be :w :r8)]  ; Convert to host byte order

      ;; Check against blocked IPs
      ;; Check 10.0.0.1 (0x0A000001)
      [(bpf/jmp-imm :jeq :r8 (ip-to-u32 "10.0.0.1") :drop)]

      ;; Check 192.168.1.100 (0xC0A80164)
      [(bpf/jmp-imm :jeq :r8 (ip-to-u32 "192.168.1.100") :drop)]

      ;; Not blocked, pass the packet
      [(bpf/jmp :pass)]

      ;; :drop - Increment drop counter and return XDP_DROP
      ;; Update stats[0] (dropped packets)
      [(bpf/mov :r5 0)]
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :drop-no-stats)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :drop-no-stats
      [(bpf/mov :r0 XDP_DROP)]
      [(bpf/exit-insn)]

      ;; :pass - Increment pass counter and return XDP_PASS
      [(bpf/mov :r5 1)]
      [(bpf/store-mem :w :r10 -4 :r5)]

      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)

      [(bpf/jmp-imm :jeq :r0 0 :pass-no-stats)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :pass-no-stats
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))

(defn run-ip-filter [interface]
  (println "Creating XDP IP address filter...")

  ;; Stats map: key 0 = dropped, key 1 = passed
  (let [stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 8
                                   :max-entries 2})]

    ;; Initialize counters
    (bpf/map-update stats-fd 0 (long-array [0]))
    (bpf/map-update stats-fd 1 (long-array [0]))

    ;; Load and attach XDP program
    (let [prog-bytes (create-ip-filter stats-fd)
          prog-fd (bpf/load-program prog-bytes :xdp)
          link-fd (bpf/attach-xdp prog-fd interface)]

      (println (format "XDP filter attached to %s" interface))
      (println "Blocking IPs: 10.0.0.1, 192.168.1.100")
      (println "\nStatistics (updating every 2 seconds):")
      (println "Press Ctrl+C to stop\n")

      ;; Monitor statistics
      (let [running (atom true)]
        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (let [dropped (bpf/map-lookup stats-fd (int-array [0]))
                passed (bpf/map-lookup stats-fd (int-array [1]))
                dropped-count (if dropped (aget dropped 0) 0)
                passed-count (if passed (aget passed 0) 0)
                total (+ dropped-count passed-count)
                drop-pct (if (> total 0) (* 100.0 (/ dropped-count total)) 0.0)]

            (println (format "Packets: %d total | %d passed | %d dropped (%.1f%%)"
                            total passed-count dropped-count drop-pct)))))

      ;; Cleanup
      (bpf/detach-xdp link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map stats-fd))))
```

### Testing

```bash
# Terminal 1: Run the filter
sudo lein run -m lab-7-1-packet-filter/run-ip-filter "eth0"

# Terminal 2: Generate traffic
# From blocked IP (will be dropped)
ping -I 10.0.0.1 8.8.8.8

# From allowed IP (will pass)
ping 8.8.8.8
```

### Expected Output

```
Creating XDP IP address filter...
XDP filter attached to eth0
Blocking IPs: 10.0.0.1, 192.168.1.100

Statistics (updating every 2 seconds):
Press Ctrl+C to stop

Packets: 1523 total | 1420 passed | 103 dropped (6.8%)
Packets: 3456 total | 3210 passed | 246 dropped (7.1%)
Packets: 5789 total | 5432 passed | 357 dropped (6.2%)
...
```

## Part 2: TCP/UDP Port Filter

Now let's add filtering by TCP/UDP ports.

### Implementation

```clojure
;; Blocked ports
(def BLOCKED_PORTS
  [22    ; SSH
   23    ; Telnet
   3389  ; RDP
   ])

(defn create-port-filter
  "Drop packets to blocked TCP/UDP ports"
  [stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Load data and data_end
      [(bpf/mov-reg :r6 :r1)]  ; ctx
      [(bpf/load-mem :w :r2 :r6 0)]   ; data
      [(bpf/load-mem :w :r3 :r6 4)]   ; data_end

      ;; Check Ethernet header
      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 14)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Check EtherType for IPv4
      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :pass)]

      ;; IP header
      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      ;; Bounds check IP header
      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Read IP protocol
      [(bpf/load-mem :b :r5 :r7 9)]

      ;; Check if TCP (6) or UDP (17)
      [(bpf/jmp-imm :jeq :r5 IPPROTO_TCP :is-tcp-udp)]
      [(bpf/jmp-imm :jeq :r5 IPPROTO_UDP :is-tcp-udp)]
      [(bpf/jmp :pass)]  ; Not TCP/UDP, pass

      ;; :is-tcp-udp
      ;; Calculate transport header offset
      ;; IP header length = IHL * 4
      [(bpf/load-mem :b :r5 :r7 0)]
      [(bpf/and :r5 0x0F)]
      [(bpf/lsh :r5 2)]
      [(bpf/mov-reg :r8 :r7)]
      [(bpf/add-reg :r8 :r5)]  ; r8 = TCP/UDP header

      ;; Bounds check: TCP/UDP header + 8 <= data_end
      [(bpf/mov-reg :r4 :r8)]
      [(bpf/add :r4 8)]  ; Need at least 8 bytes for ports
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Read destination port (offset 2, 2 bytes)
      [(bpf/load-mem :h :r9 :r8 2)]
      [(bpf/endian-be :h :r9)]  ; Convert to host byte order

      ;; Check against blocked ports
      ;; Port 22 (SSH)
      [(bpf/jmp-imm :jeq :r9 22 :drop)]

      ;; Port 23 (Telnet)
      [(bpf/jmp-imm :jeq :r9 23 :drop)]

      ;; Port 3389 (RDP)
      [(bpf/jmp-imm :jeq :r9 3389 :drop)]

      ;; Not blocked, pass
      [(bpf/jmp :pass)]

      ;; :drop
      [(bpf/mov :r5 0)]
      [(bpf/store-mem :w :r10 -4 :r5)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :drop-no-stats)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :drop-no-stats
      [(bpf/mov :r0 XDP_DROP)]
      [(bpf/exit-insn)]

      ;; :pass
      [(bpf/mov :r5 1)]
      [(bpf/store-mem :w :r10 -4 :r5)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :pass-no-stats)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :pass-no-stats
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))

(defn run-port-filter [interface]
  (println "Creating XDP port filter...")

  (let [stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 8
                                   :max-entries 2})]

    (bpf/map-update stats-fd 0 (long-array [0]))
    (bpf/map-update stats-fd 1 (long-array [0]))

    (let [prog-bytes (create-port-filter stats-fd)
          prog-fd (bpf/load-program prog-bytes :xdp)
          link-fd (bpf/attach-xdp prog-fd interface)]

      (println (format "XDP filter attached to %s" interface))
      (println "Blocking ports: 22 (SSH), 23 (Telnet), 3389 (RDP)")
      (println "\nPress Ctrl+C to stop\n")

      (let [running (atom true)]
        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (let [dropped (bpf/map-lookup stats-fd (int-array [0]))
                passed (bpf/map-lookup stats-fd (int-array [1]))
                dropped-count (if dropped (aget dropped 0) 0)
                passed-count (if passed (aget passed 0) 0)]

            (println (format "Dropped: %d | Passed: %d"
                            dropped-count passed-count)))))

      (bpf/detach-xdp link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map stats-fd))))
```

### Testing

```bash
# Terminal 1: Run the filter
sudo lein run -m lab-7-1-packet-filter/run-port-filter "eth0"

# Terminal 2: Test SSH (should be blocked)
ssh user@server
# Connection will be dropped at XDP layer

# Terminal 3: Test HTTP (should pass)
curl http://example.com
# Works normally
```

## Part 3: Complete Multi-Criteria Filter

Let's combine IP, port, and protocol filtering with detailed statistics.

### Implementation

```clojure
(defn create-comprehensive-filter
  "Filter by IP, port, and protocol with detailed stats"
  [stats-fd]
  (bpf/assemble
    (vec (concat
      ;; Load ctx and packet pointers
      [(bpf/mov-reg :r6 :r1)]
      [(bpf/load-mem :w :r2 :r6 0)]   ; data
      [(bpf/load-mem :w :r3 :r6 4)]   ; data_end

      ;; Bounds check Ethernet
      [(bpf/mov-reg :r4 :r2)]
      [(bpf/add :r4 14)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Parse EtherType
      [(bpf/load-mem :h :r5 :r2 12)]
      [(bpf/endian-be :h :r5)]

      ;; Only handle IPv4
      [(bpf/jmp-imm :jne :r5 ETH_P_IP :pass)]

      ;; IP header
      [(bpf/mov-reg :r7 :r2)]
      [(bpf/add :r7 14)]

      ;; Bounds check IP
      [(bpf/mov-reg :r4 :r7)]
      [(bpf/add :r4 20)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Check 1: Block ICMP (protocol 1)
      [(bpf/load-mem :b :r5 :r7 9)]
      [(bpf/jmp-imm :jeq :r5 IPPROTO_ICMP :drop-icmp)]

      ;; Check 2: Block source IP 10.0.0.1
      [(bpf/load-mem :w :r8 :r7 12)]
      [(bpf/endian-be :w :r8)]
      [(bpf/jmp-imm :jeq :r8 (ip-to-u32 "10.0.0.1") :drop-ip)]

      ;; Check 3: For TCP/UDP, check ports
      [(bpf/load-mem :b :r5 :r7 9)]
      [(bpf/jmp-imm :jeq :r5 IPPROTO_TCP :check-port)]
      [(bpf/jmp-imm :jeq :r5 IPPROTO_UDP :check-port)]
      [(bpf/jmp :pass)]

      ;; :check-port
      ;; Calculate L4 header offset
      [(bpf/load-mem :b :r5 :r7 0)]
      [(bpf/and :r5 0x0F)]
      [(bpf/lsh :r5 2)]
      [(bpf/mov-reg :r8 :r7)]
      [(bpf/add-reg :r8 :r5)]

      ;; Bounds check L4
      [(bpf/mov-reg :r4 :r8)]
      [(bpf/add :r4 4)]
      [(bpf/jmp-reg :jgt :r4 :r3 :pass)]

      ;; Read destination port
      [(bpf/load-mem :h :r9 :r8 2)]
      [(bpf/endian-be :h :r9)]

      ;; Block port 80 (HTTP)
      [(bpf/jmp-imm :jeq :r9 80 :drop-port)]

      ;; Block port 22 (SSH)
      [(bpf/jmp-imm :jeq :r9 22 :drop-port)]

      ;; Pass
      [(bpf/jmp :pass)]

      ;; :drop-icmp - Stats index 0
      [(bpf/mov :r5 0)]
      [(bpf/jmp :update-drop-stats)]

      ;; :drop-ip - Stats index 1
      [(bpf/mov :r5 1)]
      [(bpf/jmp :update-drop-stats)]

      ;; :drop-port - Stats index 2
      [(bpf/mov :r5 2)]

      ;; :update-drop-stats
      [(bpf/store-mem :w :r10 -4 :r5)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :drop-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :drop-exit
      [(bpf/mov :r0 XDP_DROP)]
      [(bpf/exit-insn)]

      ;; :pass - Stats index 3
      [(bpf/mov :r5 3)]
      [(bpf/store-mem :w :r10 -4 :r5)]
      [(bpf/ld-map-fd :r1 stats-fd)]
      [(bpf/mov-reg :r2 :r10)]
      [(bpf/add :r2 -4)]
      (bpf/helper-map-lookup-elem :r1 :r2)
      [(bpf/jmp-imm :jeq :r0 0 :pass-exit)]
      [(bpf/load-mem :dw :r4 :r0 0)]
      [(bpf/add :r4 1)]
      [(bpf/store-mem :dw :r0 0 :r4)]

      ;; :pass-exit
      [(bpf/mov :r0 XDP_PASS)]
      [(bpf/exit-insn)]))))

(defn run-comprehensive-filter [interface]
  (println "Creating comprehensive XDP filter...")

  ;; Stats: 0=ICMP drops, 1=IP drops, 2=Port drops, 3=Passed
  (let [stats-fd (bpf/create-map :array
                                  {:key-size 4
                                   :value-size 8
                                   :max-entries 4})]

    (doseq [i (range 4)]
      (bpf/map-update stats-fd i (long-array [0])))

    (let [prog-bytes (create-comprehensive-filter stats-fd)
          prog-fd (bpf/load-program prog-bytes :xdp)
          link-fd (bpf/attach-xdp prog-fd interface)]

      (println (format "XDP filter attached to %s" interface))
      (println "\nFilter Rules:")
      (println "  - Drop all ICMP packets")
      (println "  - Drop packets from IP 10.0.0.1")
      (println "  - Drop TCP/UDP to ports 22, 80")
      (println "\nStatistics (updating every 2 seconds):")
      (println "Press Ctrl+C to stop\n")

      (let [running (atom true)
            start-time (System/currentTimeMillis)]

        (.. Runtime getRuntime
            (addShutdownHook
              (Thread. #(reset! running false))))

        (while @running
          (Thread/sleep 2000)

          (let [icmp-drops (aget (bpf/map-lookup stats-fd (int-array [0])) 0)
                ip-drops (aget (bpf/map-lookup stats-fd (int-array [1])) 0)
                port-drops (aget (bpf/map-lookup stats-fd (int-array [2])) 0)
                passed (aget (bpf/map-lookup stats-fd (int-array [3])) 0)
                total-drops (+ icmp-drops ip-drops port-drops)
                total (+ total-drops passed)
                elapsed-sec (/ (- (System/currentTimeMillis) start-time) 1000.0)
                pps (/ total elapsed-sec)]

            (println (format "Total: %d pkts (%.1f pps) | Passed: %d | Dropped: %d (ICMP: %d, IP: %d, Port: %d)"
                            total pps passed total-drops
                            icmp-drops ip-drops port-drops)))))

      (bpf/detach-xdp link-fd)
      (bpf/close-program prog-fd)
      (bpf/close-map stats-fd))))
```

### Expected Output

```
Creating comprehensive XDP filter...
XDP filter attached to eth0

Filter Rules:
  - Drop all ICMP packets
  - Drop packets from IP 10.0.0.1
  - Drop TCP/UDP to ports 22, 80

Statistics (updating every 2 seconds):
Press Ctrl+C to stop

Total: 1523 pkts (761.5 pps) | Passed: 1234 | Dropped: 289 (ICMP: 245, IP: 12, Port: 32)
Total: 3456 pkts (864.0 pps) | Passed: 2890 | Dropped: 566 (ICMP: 478, IP: 23, Port: 65)
Total: 5789 pkts (965.7 pps) | Passed: 4932 | Dropped: 857 (ICMP: 723, IP: 34, Port: 100)
...
```

## Exercises

### Exercise 1: IPv6 Support

Add support for IPv6 packets:
- Parse IPv6 headers (EtherType 0x86DD)
- Filter by IPv6 addresses (128-bit)
- Handle IPv6 extension headers

**Hint**: IPv6 header is 40 bytes, protocol at offset 6.

### Exercise 2: Dynamic Filter Rules

Use a BPF map to store filter rules:
- Key: IP address or port
- Value: Action (DROP or PASS)
- Update rules from userspace without reloading

### Exercise 3: Rate Limiting

Implement per-IP rate limiting:
- Track packets per IP per second
- Drop when threshold exceeded
- Use LRU hash map

### Exercise 4: GeoIP Filtering

Block traffic from specific countries:
- Maintain IP range map
- Lookup source IP in range map
- Drop based on country

### Exercise 5: Performance Benchmarking

Measure XDP performance:
- Use `pktgen` to generate high-rate traffic
- Measure packets per second
- Compare DROP vs PASS performance
- Test with different packet sizes

## Summary

In this lab, you learned:
- How to parse Ethernet, IP, and TCP/UDP headers in XDP
- Handling network byte order correctly
- Implementing packet filtering at line rate
- Using XDP return codes effectively
- Building high-performance firewalls

**Key Takeaway**: XDP provides unprecedented packet processing performance, enabling tasks that were previously impossible in software alone.

## Navigation

- **Next**: [Lab 7.2 - DDoS Mitigation](lab-7-2-ddos-mitigation.md)
- **Previous**: [Chapter 7 Overview](../README.md)
- **Home**: [Tutorial Home](../../../README.md)
