# Lab 9.3: Network Security Enforcer

## Objective

Implement network-level Mandatory Access Control (MAC) using LSM BPF socket hooks. This lab demonstrates how to enforce fine-grained network security policies at the process level, controlling which applications can make network connections.

## Learning Goals

- Use socket LSM hooks (`socket_connect`, `socket_bind`)
- Implement per-process network policies
- Control outbound connections by destination IP/port
- Enforce service binding restrictions
- Implement data exfiltration prevention
- Combine multiple LSM hooks for comprehensive security

## Background

LSM provides several socket-related hooks that enable network security enforcement:

| Hook | Purpose | When Called |
|------|---------|-------------|
| `socket_create` | Control socket creation | Before socket() |
| `socket_connect` | Control outbound connections | Before connect() |
| `socket_bind` | Control port binding | Before bind() |
| `socket_listen` | Control listening sockets | Before listen() |
| `socket_sendmsg` | Control data transmission | Before each send |
| `socket_recvmsg` | Control data reception | Before each receive |

This lab focuses on `socket_connect` and `socket_bind` for practical network access control.

## Architecture

```
Application: curl https://evil.com
        ↓
   connect() syscall
        ↓
   Kernel: __sys_connect()
        ↓
   LSM Hook: socket_connect
        ↓
   Our BPF Program
        ↓
   Check: 1. Is destination IP/port allowed?
          2. Is this process authorized?
          3. Rate limit exceeded?
        ↓
   YES: Return 0         NO: Return -EACCES
        ↓                    ↓
   Connection proceeds   Connection blocked
```

## Security Policies

### Policy 1: Destination-Based Control
- Block connections to suspicious IPs
- Block connections to non-standard ports
- Allow only approved external services

### Policy 2: Process-Based Control
- Only allow specific binaries to make connections
- Container/namespace-based policies
- UID/GID-based restrictions

### Policy 3: Data Exfiltration Prevention
- Rate limit connections per process
- Track data transfer volumes
- Alert on suspicious patterns

## Kernel Structures

```c
// socket_connect hook context
struct socket {
    socket_state state;           // Offset 0x0
    short type;                   // Offset 0x4
    unsigned long flags;          // Offset 0x8
    struct file *file;            // Offset 0x10
    struct sock *sk;              // Offset 0x18
};

// sockaddr structures
struct sockaddr_in {              // IPv4
    sa_family_t sin_family;       // Offset 0x0 (AF_INET = 2)
    __be16 sin_port;              // Offset 0x2 (big-endian)
    struct in_addr sin_addr;      // Offset 0x4
};

struct sockaddr_in6 {             // IPv6
    sa_family_t sin6_family;      // Offset 0x0 (AF_INET6 = 10)
    __be16 sin6_port;             // Offset 0x2
    struct in6_addr sin6_addr;    // Offset 0x8 (16 bytes)
};

// socket_bind hook context
// Same as socket_connect
```

## Implementation

```clojure
(ns security.network-enforcer
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]))

;; ============================================================================
;; Constants and Offsets
;; ============================================================================

;; Socket address families
(def AF_INET 2)
(def AF_INET6 10)

;; sockaddr_in offsets
(def SOCKADDR_IN_OFFSETS
  {:family 0x0       ; sa_family_t (u16)
   :port 0x2         ; __be16 (big-endian)
   :addr 0x4})       ; u32 (big-endian)

;; sockaddr_in6 offsets
(def SOCKADDR_IN6_OFFSETS
  {:family 0x0
   :port 0x2
   :addr 0x8})       ; 16 bytes

;; Socket types
(def SOCK_STREAM 1)   ; TCP
(def SOCK_DGRAM 2)    ; UDP
(def SOCK_RAW 3)      ; Raw sockets

;; Well-known ports
(def PORT_HTTP 80)
(def PORT_HTTPS 443)
(def PORT_SSH 22)
(def PORT_DNS 53)
(def PORT_SMTP 25)
(def PORT_FTP 21)

;; Private IP ranges (RFC 1918)
(def PRIVATE_IP_10_0_0_0 0x0A000000)      ; 10.0.0.0/8
(def PRIVATE_IP_172_16_0_0 0xAC100000)    ; 172.16.0.0/12
(def PRIVATE_IP_192_168_0_0 0xC0A80000)   ; 192.168.0.0/16

;; Suspicious IPs (for demo - normally from threat intel)
(def BLOCKED_IPS
  [(ip->u32 "192.0.2.1")       ; TEST-NET-1 (RFC 5737)
   (ip->u32 "198.51.100.1")    ; TEST-NET-2
   (ip->u32 "203.0.113.1")])   ; TEST-NET-3

;; Error codes
(def EACCES 13)
(def EPERM 1)

;; Rate limiting
(def MAX_CONNECTIONS_PER_MIN 100)
(def RATE_WINDOW_NS (* 60 1000000000))  ; 60 seconds

;; Event types
(def EVENT_CONNECT_ALLOWED 1)
(def EVENT_CONNECT_BLOCKED 2)
(def EVENT_BIND_ALLOWED 3)
(def EVENT_BIND_BLOCKED 4)

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def blocked-ips
  "Blocked destination IPs"
  {:type :hash
   :key-type :u32       ; IPv4 address (host byte order)
   :value-type :u8      ; 1 = blocked
   :max-entries 10000})

(def blocked-ports
  "Blocked destination ports"
  {:type :hash
   :key-type :u16       ; Port number
   :value-type :u8      ; 1 = blocked
   :max-entries 1000})

(def allowed-binaries
  "Binaries allowed to make network connections"
  {:type :hash
   :key-type :u64       ; Binary path hash
   :value-type :u8      ; 1 = allowed
   :max-entries 1024})

(def connection-rate
  "Track connection rate per process (PID -> last_time, count)"
  {:type :hash
   :key-type :u32       ; PID
   :value-type :struct  ; {last_time: u64, count: u32, bytes: u64}
   :max-entries 4096})

(def network-events
  "Ring buffer for network events"
  {:type :ring_buffer
   :max-entries (* 256 1024)})

(def policy-violations
  "Count policy violations per UID"
  {:type :hash
   :key-type :u32       ; UID
   :value-type :u64     ; Count
   :max-entries 1024})

;; ============================================================================
;; Helper Functions
;; ============================================================================

(defn check-rate-limit
  "Check if process exceeds connection rate limit
  Input: r6 = PID
  Output: r7 = 1 if rate exceeded, 0 otherwise
  Clobbers: r1-r5, r8-r9"
  []
  [;; Prepare key
   [(bpf/store-mem :w :r10 -4 :r6)]

   ;; Lookup current state
   [(bpf/mov-reg :r1 (bpf/map-ref connection-rate))]
   [(bpf/mov-reg :r2 :r10)]
   [(bpf/add :r2 -4)]
   [(bpf/call (bpf/helper :map_lookup_elem))]

   ;; Get current time
   [(bpf/call (bpf/helper :ktime_get_ns))]
   [(bpf/mov-reg :r9 :r0)]              ; r9 = current_time

   ;; If no entry exists, initialize
   [(bpf/jmp-imm :jne :r0 0 :check-existing)]

   ;; Initialize new entry
   [(bpf/store-mem :dw :r10 -16 :r9)]   ; last_time
   [(bpf/mov :r8 1)]
   [(bpf/store-mem :w :r10 -8 :r8)]     ; count = 1
   [(bpf/mov :r8 0)]
   [(bpf/store-mem :dw :r10 -24 :r8)]   ; bytes = 0

   [(bpf/mov-reg :r1 (bpf/map-ref connection-rate))]
   [(bpf/mov-reg :r2 :r10)]
   [(bpf/add :r2 -4)]                   ; key
   [(bpf/mov-reg :r3 :r10)]
   [(bpf/add :r3 -24)]                  ; value
   [(bpf/mov :r4 0)]
   [(bpf/call (bpf/helper :map_update_elem))]

   [(bpf/mov :r7 0)]                    ; Not rate limited
   [(bpf/jmp :rate-check-done)]

   [:check-existing]
   ;; Load existing data
   [(bpf/mov-reg :r5 :r0)]              ; Save map value pointer
   [(bpf/load-mem :dw :r6 :r5 0)]       ; last_time
   [(bpf/load-mem :w :r8 :r5 8)]        ; count

   ;; Check if outside window
   [(bpf/mov-reg :r4 :r9)]
   [(bpf/sub-reg :r4 :r6)]              ; elapsed = current - last
   [(bpf/mov :r3 RATE_WINDOW_NS)]
   [(bpf/jmp-reg :jgt :r4 :r3 :reset-window)]

   ;; Within window - check count
   [(bpf/add :r8 1)]
   [(bpf/store-mem :w :r5 8 :r8)]       ; Update count

   [(bpf/mov :r3 MAX_CONNECTIONS_PER_MIN)]
   [(bpf/jmp-reg :jle :r8 :r3 :not-rate-limited)]

   ;; Rate limit exceeded
   [(bpf/mov :r7 1)]
   [(bpf/jmp :rate-check-done)]

   [:reset-window]
   ;; Start new window
   [(bpf/store-mem :dw :r5 0 :r9)]      ; last_time = current
   [(bpf/mov :r8 1)]
   [(bpf/store-mem :w :r5 8 :r8)]       ; count = 1
   [(bpf/jmp :not-rate-limited)]

   [:not-rate-limited]
   [(bpf/mov :r7 0)]

   [:rate-check-done]])

(defn check-private-ip
  "Check if IP is in private range
  Input: r6 = IPv4 address (host byte order)
  Output: r7 = 1 if private, 0 if public
  Clobbers: r1-r3"
  []
  [;; Check 10.0.0.0/8
   [(bpf/mov-reg :r1 :r6)]
   [(bpf/rsh :r1 24)]                   ; Get first octet
   [(bpf/jmp-imm :jeq :r1 10 :is-private)]

   ;; Check 172.16.0.0/12
   [(bpf/mov-reg :r1 :r6)]
   [(bpf/rsh :r1 20)]                   ; Get first 12 bits
   [(bpf/mov :r2 0xAC1)]                ; 172.16 in hex
   [(bpf/jmp-reg :jeq :r1 :r2 :is-private)]

   ;; Check 192.168.0.0/16
   [(bpf/mov-reg :r1 :r6)]
   [(bpf/rsh :r1 16)]                   ; Get first 16 bits
   [(bpf/mov :r2 0xC0A8)]               ; 192.168 in hex
   [(bpf/jmp-reg :jeq :r1 :r2 :is-private)]

   ;; Public IP
   [(bpf/mov :r7 0)]
   [(bpf/jmp :ip-check-done)]

   [:is-private]
   [(bpf/mov :r7 1)]

   [:ip-check-done]])

(defn log-network-event
  "Log network event to ring buffer
  Input: Stack has event data
  Clobbers: r1-r5"
  []
  [;; Reserve space
   [(bpf/mov-reg :r1 (bpf/map-ref network-events))]
   [(bpf/mov :r2 64)]                   ; Event size
   [(bpf/mov :r3 0)]
   [(bpf/call (bpf/helper :ringbuf_reserve))]

   [(bpf/jmp-imm :jeq :r0 0 :log-done)]

   ;; Copy event data from stack (simplified for brevity)
   [(bpf/mov-reg :r5 :r0)]              ; Save pointer

   ;; Copy PID, UID, IP, Port, Decision
   [(bpf/load-mem :w :r1 :r10 -40)]     ; PID
   [(bpf/store-mem :w :r5 0 :r1)]
   [(bpf/load-mem :w :r1 :r10 -36)]     ; UID
   [(bpf/store-mem :w :r5 4 :r1)]
   [(bpf/load-mem :w :r1 :r10 -32)]     ; IP
   [(bpf/store-mem :w :r5 8 :r1)]
   [(bpf/load-mem :h :r1 :r10 -28)]     ; Port
   [(bpf/store-mem :h :r5 12 :r1)]
   [(bpf/load-mem :w :r1 :r10 -24)]     ; Decision
   [(bpf/store-mem :w :r5 14 :r1)]

   ;; Get timestamp
   [(bpf/call (bpf/helper :ktime_get_ns))]
   [(bpf/store-mem :dw :r5 16 :r0)]

   ;; Submit
   [(bpf/mov-reg :r1 :r5)]
   [(bpf/mov :r2 0)]
   [(bpf/call (bpf/helper :ringbuf_submit))]

   [:log-done]])

;; ============================================================================
;; socket_connect Hook
;; ============================================================================

(def socket-connect-enforcer
  "Enforce outbound connection policies"
  {:type :lsm
   :hook "socket_connect"
   :program
   [;; Arguments: (struct socket *sock, struct sockaddr *address, int addrlen)
    [(bpf/load-ctx :dw :r6 0)]          ; socket*
    [(bpf/load-ctx :dw :r7 8)]          ; sockaddr*
    [(bpf/load-ctx :w :r8 16)]          ; addrlen

    ;; Null checks
    [(bpf/jmp-imm :jeq :r6 0 :allow)]
    [(bpf/jmp-imm :jeq :r7 0 :allow)]

    ;; ========================================================================
    ;; Extract address family
    ;; ========================================================================

    [(bpf/load-mem :h :r9 :r7 0)]       ; Load sa_family
    [(bpf/store-mem :h :r10 -4 :r9)]

    ;; Only handle IPv4 for this lab (IPv6 support similar)
    [(bpf/jmp-imm :jne :r9 AF_INET :allow)]

    ;; ========================================================================
    ;; Extract IPv4 address and port
    ;; ========================================================================

    ;; Load port (big-endian)
    [(bpf/load-mem :h :r8 :r7 (:port SOCKADDR_IN_OFFSETS))]
    [(bpf/endian-be :h :r8)]            ; Convert to host byte order
    [(bpf/store-mem :h :r10 -8 :r8)]    ; Save port

    ;; Load IP address (big-endian)
    [(bpf/load-mem :w :r9 :r7 (:addr SOCKADDR_IN_OFFSETS))]
    [(bpf/endian-be :w :r9)]            ; Convert to host byte order
    [(bpf/store-mem :w :r10 -12 :r9)]   ; Save IP

    ;; ========================================================================
    ;; Get process information
    ;; ========================================================================

    ;; Get PID
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r10 -40 :r0)]   ; Save PID
    [(bpf/mov-reg :r6 :r0)]             ; Keep in r6

    ;; Get UID
    [(bpf/call (bpf/helper :get_current_uid_gid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r10 -36 :r0)]   ; Save UID

    ;; ========================================================================
    ;; Policy Check 1: Blocked IPs
    ;; ========================================================================

    [(bpf/load-mem :w :r7 :r10 -12)]    ; Load IP
    [(bpf/store-mem :w :r10 -16 :r7)]
    [(bpf/mov-reg :r1 (bpf/map-ref blocked-ips))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jne :r0 0 :deny)]    ; If in blocked list, deny

    ;; ========================================================================
    ;; Policy Check 2: Blocked Ports
    ;; ========================================================================

    [(bpf/load-mem :h :r7 :r10 -8)]     ; Load port
    [(bpf/store-mem :h :r10 -20 :r7)]
    [(bpf/mov-reg :r1 (bpf/map-ref blocked-ports))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -20)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jne :r0 0 :deny)]

    ;; ========================================================================
    ;; Policy Check 3: Rate Limiting
    ;; ========================================================================

    (check-rate-limit)
    [(bpf/jmp-imm :jeq :r7 1 :deny-rate)]

    ;; ========================================================================
    ;; Policy Check 4: Private vs Public IP restrictions
    ;; ========================================================================

    [(bpf/load-mem :w :r6 :r10 -12)]    ; IP
    (check-private-ip)
    ;; r7 = 1 if private, 0 if public

    ;; For demo: block connections to public IPs on non-standard ports
    [(bpf/jmp-imm :jeq :r7 1 :allow)]   ; Private IP - allow

    ;; Public IP - check port
    [(bpf/load-mem :h :r8 :r10 -8)]     ; port
    [(bpf/jmp-imm :jeq :r8 PORT_HTTP :allow)]
    [(bpf/jmp-imm :jeq :r8 PORT_HTTPS :allow)]
    [(bpf/jmp-imm :jeq :r8 PORT_DNS :allow)]
    ;; Non-standard port to public IP - potentially suspicious
    ;; For strict security, could deny here
    ;; [(bpf/jmp :deny)]

    [(bpf/jmp :allow)]

    ;; ========================================================================
    ;; Deny with Rate Limit Reason
    ;; ========================================================================

    [:deny-rate]
    [(bpf/mov :r9 2)]                    ; Reason = rate limit
    [(bpf/store-mem :w :r10 -24 :r9)]
    [(bpf/jmp :log-and-deny)]

    ;; ========================================================================
    ;; Deny with Policy Violation
    ;; ========================================================================

    [:deny]
    [(bpf/mov :r9 1)]                    ; Reason = policy
    [(bpf/store-mem :w :r10 -24 :r9)]

    [:log-and-deny]
    ;; Log event
    [(bpf/load-mem :w :r7 :r10 -12)]    ; IP
    [(bpf/store-mem :w :r10 -32 :r7)]
    [(bpf/load-mem :h :r7 :r10 -8)]     ; Port
    [(bpf/store-mem :h :r10 -28 :r7)]
    (log-network-event)

    ;; Increment violation counter
    [(bpf/load-mem :w :r7 :r10 -36)]    ; UID
    [(bpf/store-mem :w :r10 -48 :r7)]
    [(bpf/mov-reg :r1 (bpf/map-ref policy-violations))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -48)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-violation)]
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]
    [(bpf/jmp :return-deny)]

    [:init-violation]
    [(bpf/mov :r8 1)]
    [(bpf/store-mem :dw :r10 -56 :r8)]
    [(bpf/mov-reg :r1 (bpf/map-ref policy-violations))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -48)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -56)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:return-deny]
    [(bpf/mov :r0 (- EACCES))]          ; Return -EACCES
    [(bpf/exit)]

    ;; ========================================================================
    ;; Allow Connection
    ;; ========================================================================

    [:allow]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

;; ============================================================================
;; socket_bind Hook
;; ============================================================================

(def socket-bind-enforcer
  "Enforce port binding policies"
  {:type :lsm
   :hook "socket_bind"
   :program
   [;; Arguments: (struct socket *sock, struct sockaddr *address, int addrlen)
    [(bpf/load-ctx :dw :r6 0)]          ; socket*
    [(bpf/load-ctx :dw :r7 8)]          ; sockaddr*

    [(bpf/jmp-imm :jeq :r7 0 :allow)]

    ;; Check address family
    [(bpf/load-mem :h :r8 :r7 0)]
    [(bpf/jmp-imm :jne :r8 AF_INET :allow)]

    ;; Extract port
    [(bpf/load-mem :h :r8 :r7 2)]
    [(bpf/endian-be :h :r8)]

    ;; Get UID
    [(bpf/call (bpf/helper :get_current_uid_gid))]
    [(bpf/rsh :r0 32)]                  ; UID

    ;; Policy: Only root can bind to privileged ports (<1024)
    [(bpf/mov :r9 1024)]
    [(bpf/jmp-reg :jge :r8 :r9 :allow)] ; Port >= 1024, allow

    ;; Privileged port - check if root
    [(bpf/jmp-imm :jeq :r0 0 :allow)]   ; UID == 0 (root), allow

    ;; Non-root trying to bind privileged port - deny
    [(bpf/mov :r0 (- EACCES))]
    [(bpf/exit)]

    [:allow]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

;; ============================================================================
;; Userspace Control
;; ============================================================================

(defn ip->u32
  "Convert IP string to u32"
  [ip-str]
  (let [parts (map #(Integer/parseInt %) (clojure.string/split ip-str #"\."))]
    (reduce (fn [acc [idx val]]
              (bit-or acc (bit-shift-left val (* 8 (- 3 idx)))))
            0
            (map-indexed vector parts))))

(defn u32->ip
  "Convert u32 to IP string"
  [ip]
  (format "%d.%d.%d.%d"
          (bit-and (bit-shift-right ip 24) 0xFF)
          (bit-and (bit-shift-right ip 16) 0xFF)
          (bit-and (bit-shift-right ip 8) 0xFF)
          (bit-and ip 0xFF)))

(defn block-ip!
  "Add IP to block list"
  [ip-str]
  (let [ip-u32 (ip->u32 ip-str)]
    (bpf/map-update! blocked-ips ip-u32 1)
    (println "Blocked IP:" ip-str)))

(defn block-port!
  "Add port to block list"
  [port]
  (bpf/map-update! blocked-ports port 1)
  (println "Blocked port:" port))

(defn monitor-network-violations
  "Monitor and display network violations"
  []
  (println "Monitoring network violations...")
  (println "TIME                PID    UID    IP              PORT   REASON")
  (println "========================================================================")

  (bpf/consume-ring-buffer
    network-events
    (fn [data]
      (let [pid (bytes->u32 data 0)
            uid (bytes->u32 data 4)
            ip (bytes->u32 data 8)
            port (bytes->u16 data 12)
            decision (bytes->u32 data 14)
            timestamp (bytes->u64 data 16)]
        (when (pos? decision)
          (println (format "%d  %-6d %-6d %-15s %-6d %s"
                           timestamp pid uid (u32->ip ip) port
                           (case decision
                             1 "POLICY"
                             2 "RATE_LIMIT"
                             "UNKNOWN"))))))
    {:poll-timeout-ms 100}))

(defn setup-default-blocks!
  "Configure default blocked IPs and ports"
  []
  (println "Setting up default blocks...")

  ;; Block test IPs
  (doseq [ip ["192.0.2.1" "198.51.100.1" "203.0.113.1"]]
    (block-ip! ip))

  ;; Block dangerous ports
  (doseq [port [23    ; Telnet
                135   ; Windows RPC
                139   ; NetBIOS
                445   ; SMB
                3389  ; RDP
                6667]]  ; IRC
    (block-port! port)))

(defn dump-violations
  "Display violation statistics"
  []
  (println "\nNetwork Policy Violations:")
  (println "UID    Count")
  (println "===============")
  (doseq [[uid count] (bpf/map-get-all policy-violations)]
    (printf "%d\t%d\n" uid count)))

(defn -main
  []
  (println "Starting network security enforcer...")

  ;; Load and attach programs
  (let [connect-prog (bpf/load-program socket-connect-enforcer)
        bind-prog (bpf/load-program socket-bind-enforcer)]
    (bpf/attach-lsm connect-prog "socket_connect")
    (bpf/attach-lsm bind-prog "socket_bind")

    ;; Setup policies
    (setup-default-blocks!)

    (println "\nNetwork policies active. Press Ctrl-C to stop.\n")

    ;; Monitor violations
    (try
      (monitor-network-violations)
      (catch InterruptedException _
        (println "\n\nStopping...")
        (dump-violations)))))
```

## Testing

### Test 1: Block Specific IPs

```bash
# Terminal 1: Start enforcer
sudo lein run -m security.network-enforcer

# Terminal 2: Test connections
ping 192.0.2.1           # Should fail (blocked IP)
curl http://example.com  # Should work (allowed)
nc 203.0.113.1 80       # Should fail (blocked IP)
```

### Test 2: Port Restrictions

```bash
# Terminal 2
nc some-server.com 445   # Should fail (SMB blocked)
nc some-server.com 6667  # Should fail (IRC blocked)
nc some-server.com 80    # Should work
```

### Test 3: Privileged Port Binding

```bash
# As normal user
nc -l 80                 # Should fail (privileged port, non-root)
nc -l 8080               # Should work (non-privileged port)

# As root
sudo nc -l 80            # Should work (root on privileged port)
```

### Test 4: Rate Limiting

```bash
# Generate many connections rapidly
for i in {1..150}; do curl -s http://example.com > /dev/null & done

# Should see rate limit violations after 100 connections
```

## Security Considerations

1. **IPv6 Support**: This lab focuses on IPv4; production should handle IPv6
2. **DNS Bypass**: DNS lookups happen before connect - need separate controls
3. **Unix Sockets**: This lab only handles INET sockets
4. **Root Privileges**: Root can unload BPF programs
5. **Performance**: socket_connect is moderately hot - optimize for common case

## Advanced Enhancements

1. **Integration with Threat Intel**: Real-time blocklist updates from feeds
2. **Per-Container Policies**: Different rules per network namespace
3. **Application Fingerprinting**: Identify processes by more than path
4. **Geo-IP Blocking**: Block connections to specific countries
5. **Protocol Inspection**: Deep packet inspection for protocol violations

## Performance Analysis

```bash
# Benchmark connection performance
time for i in {1..1000}; do curl -s http://localhost:8080 > /dev/null; done

# With and without BPF to measure overhead
```

Expected overhead: 2-5% for connection establishment.

## Challenges

1. **Dynamic Blocklist**: Implement userspace daemon to update blocked IPs from API
2. **Connection Tracking**: Track full connection lifecycle (connect/send/recv/close)
3. **Anomaly Detection**: Alert on unusual connection patterns
4. **Integration with Firewall**: Coordinate with iptables/nftables
5. **Zero Trust**: Implement complete mutual TLS verification

## Real-World Applications

- **Container Security**: Enforce network policies for containers
- **Zero Trust Architecture**: Per-process network segmentation
- **Data Loss Prevention**: Prevent exfiltration to untrusted destinations
- **Compliance**: Enforce regulatory requirements (PCI-DSS, HIPAA)
- **Threat Prevention**: Block C&C servers, malware infrastructure

## References

- [LSM Socket Hooks](https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hooks.h)
- [Socket Security](https://www.kernel.org/doc/html/latest/security/lsm.html)
- [BPF LSM Network Security](https://docs.kernel.org/bpf/prog_lsm.html)
