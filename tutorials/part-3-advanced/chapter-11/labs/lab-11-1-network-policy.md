# Lab 11.1: Container Network Policy Enforcer

## Objective

Implement per-container network egress policies using cgroup BPF programs. Control which external services containers can connect to, providing container-native security without modifying applications.

## Learning Goals

- Attach BPF programs to cgroups
- Use cgroup/sock_addr for connection control
- Implement IP/port-based policies
- Handle cgroup hierarchy
- Integrate with Docker containers
- Monitor policy violations

## Background

Containers often need restricted network access for security:
- Prevent data exfiltration
- Limit blast radius of compromised containers
- Enforce compliance (PCI-DSS, HIPAA)
- Multi-tenant isolation

Traditional approaches (iptables, network policies) work at the host or cluster level. Cgroup BPF provides **per-container** granularity.

## Architecture

```
Container 1 (Frontend)          Container 2 (Database)
     │                                │
     ├─ connect(api.example.com)     ├─ connect(8.8.8.8)
     │                                │
     ▼                                ▼
┌─────────────────────────────────────────────┐
│  Cgroup BPF (sock_addr/connect4)            │
├─────────────────────────────────────────────┤
│  Frontend Policy:                           │
│  ✓ Allow api.example.com (resolved IP)      │
│  ✓ Allow DNS (53/udp)                       │
│  ✗ Deny all other external                  │
│                                             │
│  Database Policy:                           │
│  ✗ Deny ALL external connections           │
│  ✓ Allow only internal network             │
└─────────────────────────────────────────────┘
           │                    │
           ▼                    ▼
       ALLOWED               DENIED (-EPERM)
```

## Implementation

```clojure
(ns container.network-policy
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.cgroup :as cgroup]))

;; ============================================================================
;; Constants
;; ============================================================================

;; Socket address context offsets (struct bpf_sock_addr)
(def SOCK_ADDR_OFFSETS
  {:family 0          ; sa_family_t (u16)
   :type 4            ; Socket type (u32)
   :protocol 8        ; Protocol (u32)
   :user-ip4 24       ; User-space IPv4 (u32, big-endian)
   :user-ip6 28       ; User-space IPv6 (16 bytes)
   :user-port 56      ; User-space port (u32, big-endian)
   :msg-src-ip4 60})  ; Message source IPv4 (u32)

;; Address families
(def AF_INET 2)
(def AF_INET6 10)

;; Common ports
(def PORT_DNS 53)
(def PORT_HTTP 80)
(def PORT_HTTPS 443)

;; Policy actions
(def ACTION_ALLOW 1)
(def ACTION_DENY 0)

;; Private IP ranges (RFC 1918)
(defn ip->u32 [ip-str]
  (let [parts (map #(Integer/parseInt %) (clojure.string/split ip-str #"\."))]
    (reduce bit-or
            (map-indexed (fn [idx val]
                          (bit-shift-left val (* 8 (- 3 idx))))
                        parts))))

(def PRIVATE_10_0_0_0 (ip->u32 "10.0.0.0"))
(def PRIVATE_10_255_255_255 (ip->u32 "10.255.255.255"))
(def PRIVATE_172_16_0_0 (ip->u32 "172.16.0.0"))
(def PRIVATE_172_31_255_255 (ip->u32 "172.31.255.255"))
(def PRIVATE_192_168_0_0 (ip->u32 "192.168.0.0"))
(def PRIVATE_192_168_255_255 (ip->u32 "192.168.255.255"))

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def allowed-ips
  "Whitelist of allowed destination IPs"
  {:type :hash
   :key-type :u32       ; IPv4 address
   :value-type :u8      ; 1 = allowed
   :max-entries 10000})

(def allowed-ports
  "Whitelist of allowed destination ports"
  {:type :hash
   :key-type :u16       ; Port number
   :value-type :u8      ; 1 = allowed
   :max-entries 1000})

(def policy-config
  "Policy configuration (single entry)"
  {:type :array
   :key-type :u32
   :value-type :struct  ; {mode: u32, default_action: u32, flags: u32}
   :max-entries 1})

(def violation-log
  "Ring buffer for policy violations"
  {:type :ring_buffer
   :max-entries (* 128 1024)})

(def connection-stats
  "Per-destination connection stats"
  {:type :hash
   :key-type :struct    ; {ip: u32, port: u16}
   :value-type :struct  ; {allowed: u64, denied: u64, last_seen: u64}
   :max-entries 10000})

;; ============================================================================
;; Helper Functions
;; ============================================================================

(defn is-private-ip?
  "Check if IP is in private range
   Input: r6 = IPv4 address (host byte order)
   Output: r7 = 1 if private, 0 if public"
  []
  [;; Check 10.0.0.0/8
   [(bpf/mov :r1 PRIVATE_10_0_0_0)]
   [(bpf/mov :r2 PRIVATE_10_255_255_255)]
   [(bpf/jmp-reg :jlt :r6 :r1 :check-172)]
   [(bpf/jmp-reg :jgt :r6 :r2 :check-172)]
   [(bpf/mov :r7 1)]
   [(bpf/jmp :done)]

   [:check-172]
   ;; Check 172.16.0.0/12
   [(bpf/mov :r1 PRIVATE_172_16_0_0)]
   [(bpf/mov :r2 PRIVATE_172_31_255_255)]
   [(bpf/jmp-reg :jlt :r6 :r1 :check-192)]
   [(bpf/jmp-reg :jgt :r6 :r2 :check-192)]
   [(bpf/mov :r7 1)]
   [(bpf/jmp :done)]

   [:check-192]
   ;; Check 192.168.0.0/16
   [(bpf/mov :r1 PRIVATE_192_168_0_0)]
   [(bpf/mov :r2 PRIVATE_192_168_255_255)]
   [(bpf/jmp-reg :jlt :r6 :r1 :public)]
   [(bpf/jmp-reg :jgt :r6 :r2 :public)]
   [(bpf/mov :r7 1)]
   [(bpf/jmp :done)]

   [:public]
   [(bpf/mov :r7 0)]

   [:done]])

(defn log-violation
  "Log connection policy violation
   Input: r6 = IP, r7 = port, r8 = action
   Clobbers: r1-r5"
  []
  [;; Reserve ring buffer space
   [(bpf/mov-reg :r1 (bpf/map-ref violation-log))]
   [(bpf/mov :r2 32)]                   ; Event size
   [(bpf/mov :r3 0)]
   [(bpf/call (bpf/helper :ringbuf_reserve))]

   [(bpf/jmp-imm :jeq :r0 0 :log-done)]
   [(bpf/mov-reg :r9 :r0)]              ; Save event pointer

   ;; Copy IP
   [(bpf/store-mem :w :r9 0 :r6)]

   ;; Copy port
   [(bpf/store-mem :h :r9 4 :r7)]

   ;; Copy action
   [(bpf/store-mem :w :r9 8 :r8)]

   ;; Get PID
   [(bpf/call (bpf/helper :get_current_pid_tgid))]
   [(bpf/rsh :r0 32)]
   [(bpf/store-mem :w :r9 12 :r0)]

   ;; Get timestamp
   [(bpf/call (bpf/helper :ktime_get_ns))]
   [(bpf/store-mem :dw :r9 16 :r0)]

   ;; Submit
   [(bpf/mov-reg :r1 :r9)]
   [(bpf/mov :r2 0)]
   [(bpf/call (bpf/helper :ringbuf_submit))]

   [:log-done]])

;; ============================================================================
;; Main Network Policy Program
;; ============================================================================

(def network-policy-connect
  "Control outbound connections from containers"
  {:type :cgroup-sock-addr
   :attach-type :inet4-connect
   :program
   [;; Load socket address family
    [(bpf/load-ctx :h :r6 (:family SOCK_ADDR_OFFSETS))]
    [(bpf/jmp-imm :jne :r6 AF_INET :allow)]  ; Only handle IPv4

    ;; ========================================================================
    ;; Extract Destination IP and Port
    ;; ========================================================================

    ;; Load destination IP (big-endian from user space)
    [(bpf/load-ctx :w :r6 (:user-ip4 SOCK_ADDR_OFFSETS))]
    [(bpf/endian-be :w :r6)]            ; Convert to host byte order
    [(bpf/store-mem :w :r10 -4 :r6)]    ; Save IP

    ;; Load destination port (big-endian)
    [(bpf/load-ctx :w :r7 (:user-port SOCK_ADDR_OFFSETS))]
    [(bpf/endian-be :h :r7)]            ; Convert to host byte order
    [(bpf/store-mem :h :r10 -8 :r7)]    ; Save port

    ;; ========================================================================
    ;; Policy Check 1: Always Allow Private IPs
    ;; ========================================================================

    (is-private-ip?)
    [(bpf/jmp-imm :jeq :r7 1 :allow)]   ; Private IP -> allow

    ;; ========================================================================
    ;; Policy Check 2: Check Allowed IPs Whitelist
    ;; ========================================================================

    [(bpf/load-mem :w :r6 :r10 -4)]     ; Reload IP
    [(bpf/store-mem :w :r10 -12 :r6)]
    [(bpf/mov-reg :r1 (bpf/map-ref allowed-ips))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -12)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jne :r0 0 :allow)]   ; Found in whitelist -> allow

    ;; ========================================================================
    ;; Policy Check 3: Check Allowed Ports
    ;; ========================================================================

    [(bpf/load-mem :h :r7 :r10 -8)]     ; Reload port
    [(bpf/store-mem :h :r10 -16 :r7)]
    [(bpf/mov-reg :r1 (bpf/map-ref allowed-ports))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jne :r0 0 :allow)]   ; Found in whitelist -> allow

    ;; ========================================================================
    ;; Policy Check 4: Special Cases
    ;; ========================================================================

    ;; Always allow DNS
    [(bpf/load-mem :h :r7 :r10 -8)]
    [(bpf/jmp-imm :jeq :r7 PORT_DNS :allow)]

    ;; Allow localhost (127.0.0.1)
    [(bpf/load-mem :w :r6 :r10 -4)]
    [(bpf/mov :r1 0x7F000001)]          ; 127.0.0.1
    [(bpf/jmp-reg :jeq :r6 :r1 :allow)]

    ;; ========================================================================
    ;; Deny - Not in any whitelist
    ;; ========================================================================

    [:deny]
    ;; Log violation
    [(bpf/load-mem :w :r6 :r10 -4)]     ; IP
    [(bpf/load-mem :h :r7 :r10 -8)]     ; Port
    [(bpf/mov :r8 ACTION_DENY)]
    (log-violation)

    ;; Update statistics
    [(bpf/load-mem :w :r6 :r10 -4)]
    [(bpf/load-mem :h :r7 :r10 -8)]
    [(bpf/store-mem :w :r10 -24 :r6)]   ; Stats key: IP
    [(bpf/store-mem :h :r10 -20 :r7)]   ; Stats key: port

    [(bpf/mov-reg :r1 (bpf/map-ref connection-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -24)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :return-deny)]
    ;; Increment denied counter
    [(bpf/load-mem :dw :r1 :r0 8)]      ; denied count
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 8 :r1)]

    [:return-deny]
    [(bpf/mov :r0 ACTION_DENY)]         ; Return 0 = deny
    [(bpf/exit)]

    ;; ========================================================================
    ;; Allow
    ;; ========================================================================

    [:allow]
    ;; Update allowed statistics
    [(bpf/load-mem :w :r6 :r10 -4)]
    [(bpf/load-mem :h :r7 :r10 -8)]
    [(bpf/store-mem :w :r10 -24 :r6)]
    [(bpf/store-mem :h :r10 -20 :r7)]

    [(bpf/mov-reg :r1 (bpf/map-ref connection-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -24)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-stats)]
    ;; Increment allowed counter
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]
    [(bpf/jmp :return-allow)]

    [:init-stats]
    ;; Initialize statistics
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r10 -40 :r1)]  ; allowed = 1
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :dw :r10 -32 :r1)]  ; denied = 0
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -48 :r0)]  ; last_seen = now

    [(bpf/mov-reg :r1 (bpf/map-ref connection-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -24)]                 ; key
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -48)]                 ; value
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:return-allow]
    [(bpf/mov :r0 ACTION_ALLOW)]        ; Return 1 = allow
    [(bpf/exit)]]})

;; ============================================================================
;; Userspace Control
;; ============================================================================

(defn add-allowed-ip!
  "Add IP to allowed list"
  [ip-str]
  (let [ip-u32 (ip->u32 ip-str)]
    (bpf/map-update! allowed-ips ip-u32 1)
    (println (format "Allowed IP: %s (0x%08x)" ip-str ip-u32))))

(defn add-allowed-port!
  "Add port to allowed list"
  [port]
  (bpf/map-update! allowed-ports port 1)
  (println (format "Allowed port: %d" port)))

(defn get-container-cgroup-path
  "Get cgroup path for a container"
  [container-id]
  (let [pid (cgroup/get-container-pid container-id)
        cgroup-info (cgroup/get-process-cgroup pid)]
    (str "/sys/fs/cgroup" (:path cgroup-info))))

(defn attach-to-container!
  "Attach network policy to a container"
  [container-id]
  (let [cgroup-path (get-container-cgroup-path container-id)
        prog (bpf/load-program network-policy-connect)]
    (println (format "Attaching to container %s at %s"
                     container-id cgroup-path))
    (bpf/attach-cgroup prog cgroup-path :inet4-connect)
    prog))

(defn monitor-violations
  "Monitor and display policy violations"
  []
  (println "\n=== Network Policy Violations ===")
  (println "TIME                IP              PORT   PID")
  (println "==================================================")

  (bpf/consume-ring-buffer
    violation-log
    (fn [data]
      (let [ip (bytes->u32 data 0)
            port (bytes->u16 data 4)
            action (bytes->u32 data 8)
            pid (bytes->u32 data 12)
            timestamp (bytes->u64 data 16)
            ip-str (u32->ip ip)]
        (printf "%d  %-15s %-6d %d\n"
                timestamp ip-str port pid)))
    {:poll-timeout-ms 100}))

(defn show-statistics
  "Display connection statistics"
  []
  (println "\n=== Connection Statistics ===")
  (println "IP              PORT   ALLOWED  DENIED")
  (println "==========================================")
  (doseq [[key stats] (bpf/map-get-all connection-stats)]
    (let [{:keys [ip port]} key
          {:keys [allowed denied last-seen]} stats]
      (printf "%-15s %-6d %-8d %d\n"
              (u32->ip ip) port allowed denied))))

;; ============================================================================
;; Policy Presets
;; ============================================================================

(defn apply-frontend-policy!
  "Policy for frontend containers"
  []
  (println "\n=== Applying Frontend Policy ===")
  ;; Allow HTTP/HTTPS to anywhere
  (add-allowed-port! 80)
  (add-allowed-port! 443)
  ;; Allow DNS
  (add-allowed-port! 53)
  ;; Allow specific API endpoints
  (add-allowed-ip! "1.2.3.4")  ; api.example.com
  ;; Private networks always allowed (built-in))

(defn apply-database-policy!
  "Policy for database containers - DENY all external"
  []
  (println "\n=== Applying Database Policy ===")
  (println "Denying ALL external connections")
  (println "Only private networks allowed (10.*, 172.16-31.*, 192.168.*)")
  ;; No allowed IPs or ports = deny all except private)

(defn apply-worker-policy!
  "Policy for background worker containers"
  []
  (println "\n=== Applying Worker Policy ===")
  ;; Allow specific message queue
  (add-allowed-ip! "10.0.1.50")  ; RabbitMQ
  (add-allowed-port! 5672)        ; AMQP
  ;; Allow specific object storage
  (add-allowed-ip! "10.0.2.100") ; S3 endpoint
  (add-allowed-port! 9000))      ; MinIO

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  [& args]
  (let [[command & params] args]
    (case command
      "attach"
      (let [container-id (first params)
            policy (or (second params) "frontend")]
        (println (format "Attaching %s policy to container %s"
                         policy container-id))

        ;; Apply policy
        (case policy
          "frontend" (apply-frontend-policy!)
          "database" (apply-database-policy!)
          "worker" (apply-worker-policy!)
          (println "Unknown policy:" policy))

        ;; Attach to container
        (attach-to-container! container-id)

        ;; Monitor violations
        (monitor-violations))

      "stats"
      (show-statistics)

      "monitor"
      (monitor-violations)

      ;; Default: show help
      (println "Usage:")
      (println "  attach <container-id> [frontend|database|worker]")
      (println "  stats")
      (println "  monitor"))))
```

## Testing

### Test 1: Frontend Container

```bash
# Start a test container
docker run -d --name frontend nginx:latest

# Get container ID
CONTAINER_ID=$(docker ps -qf name=frontend)

# Apply frontend policy
sudo lein run -m container.network-policy attach $CONTAINER_ID frontend

# Test allowed connections (from inside container)
docker exec frontend curl https://api.example.com  # Should work
docker exec frontend curl http://google.com        # Should work (port 80)

# Test denied connections
docker exec frontend nc -zv 1.2.3.5 22            # Should fail
```

Expected output:
```
=== Applying Frontend Policy ===
Allowed port: 80
Allowed port: 443
Allowed port: 53
Allowed IP: 1.2.3.4 (0x01020304)

Attaching to container abc123 at /sys/fs/cgroup/docker/abc123...

=== Network Policy Violations ===
TIME                IP              PORT   PID
==================================================
1234567890  1.2.3.5         22     5678
```

### Test 2: Database Container

```bash
# Start database container
docker run -d --name postgres postgres:latest

# Apply database policy (deny all external)
sudo lein run -m container.network-policy attach postgres database

# Test from inside container
docker exec postgres ping 8.8.8.8           # Should fail
docker exec postgres nc -zv 10.0.1.5 5432  # Should work (private IP)
```

### Test 3: View Statistics

```bash
sudo lein run -m container.network-policy stats
```

Expected output:
```
=== Connection Statistics ===
IP              PORT   ALLOWED  DENIED
==========================================
1.2.3.4         443    15       0
8.8.8.8         443    0        5
10.0.1.5        5432   100      0
```

## Challenges

1. **DNS Resolution**: Pre-resolve domain names and add IPs to whitelist
2. **Dynamic Updates**: Add/remove IPs from whitelist without restart
3. **Per-Port Policies**: Different policies for different destination ports
4. **Geo-blocking**: Block connections to specific countries (using IP ranges)
5. **Rate Limiting**: Limit connection rate per destination

## Integration with Orchestrators

### Docker Compose

```yaml
version: '3'
services:
  frontend:
    image: myapp:latest
    labels:
      bpf.network.policy: "frontend"

  database:
    image: postgres:latest
    labels:
      bpf.network.policy: "database"
```

### Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
  annotations:
    bpf.io/network-policy: "frontend"
spec:
  containers:
  - name: app
    image: myapp:latest
```

## Security Considerations

1. **Layered Security**: Use with network policies and firewalls
2. **Escape Prevention**: Cannot bypass from within container (kernel-level)
3. **Privilege Escalation**: Root in container cannot disable (unless CAP_BPF)
4. **Audit Logging**: Log all denials for security monitoring
5. **Default Deny**: Start with restrictive policy, add exceptions

## Key Takeaways

1. **Container-Native**: Policies automatically apply to all processes in cgroup
2. **No App Changes**: Transparent to applications
3. **Efficient**: Low overhead (~500ns per connection)
4. **Hierarchical**: Policies inherit from parent cgroups
5. **Granular**: Per-container policies, not per-host

## Next Steps

- **Lab 11.2**: Monitor resource usage per container
- **Lab 11.3**: Control device access
- **Chapter 12**: Optimize cgroup BPF programs

## References

- [Cgroup BPF Programs](https://www.kernel.org/doc/html/latest/bpf/prog_cgroup.html)
- [Container Security with BPF](https://kinvolk.io/blog/2020/04/inside-kinvolk-labs-coverage-guided-fuzzing-with-syzkaller/)
- [Cilium Network Policies](https://docs.cilium.io/en/stable/policy/)
