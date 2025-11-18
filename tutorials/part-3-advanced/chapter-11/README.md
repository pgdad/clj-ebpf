# Chapter 11: Cgroups and Resource Control

## Introduction

Cgroup BPF programs enable fine-grained control and monitoring of resources on a per-container or per-process-group basis. They are essential for container security, multi-tenancy, and resource management in modern cloud environments.

## What are Cgroups?

**Cgroups (Control Groups)** are a Linux kernel feature that limits, accounts for, and isolates resource usage (CPU, memory, network, I/O) of process groups.

### Cgroup Hierarchy

```
/ (root cgroup)
├── system.slice/
│   ├── docker.service
│   └── kubelet.service
├── user.slice/
│   └── user-1000.slice/
└── machine.slice/
    ├── docker-abc123.scope  ← Container 1
    └── docker-def456.scope  ← Container 2
```

Each cgroup can have:
- Resource limits (CPU, memory)
- BPF programs attached
- Hierarchical inheritance of policies

## Cgroup BPF Programs

Cgroup BPF programs attach to cgroups and control or monitor operations for all processes in that cgroup.

### Key Characteristics

| Feature | Description |
|---------|-------------|
| **Scope** | All processes in a cgroup hierarchy |
| **Inheritance** | Child cgroups inherit parent's BPF programs |
| **Attach Point** | Cgroup directory path |
| **Use Case** | Per-container policies, multi-tenancy |
| **Kernel Version** | 4.10+ (varies by program type) |

### Cgroup vs Other Program Types

| Aspect | Cgroup BPF | LSM BPF | XDP/TC |
|--------|-----------|---------|--------|
| **Granularity** | Per-cgroup | System-wide | Per-interface |
| **Scope** | Process groups | All processes | Network packets |
| **Inheritance** | Yes | No | No |
| **Container-aware** | Native | Manual | Manual |
| **Resource control** | Yes | Limited | No |

## Cgroup BPF Program Types

### 1. cgroup/sock (Socket Creation)

**Attach Point**: `BPF_CGROUP_INET_SOCK_CREATE`
**When Called**: Socket creation (socket() syscall)
**Purpose**: Control which types of sockets can be created

```c
int cgroup_sock_prog(struct bpf_sock *sk);
// Return 1 = allow, 0 = deny
```

**Use Cases**:
- Prevent containers from creating raw sockets
- Block specific socket families (AF_INET6, AF_PACKET)
- Enforce socket type restrictions

### 2. cgroup/sock_addr (Bind/Connect)

**Attach Points**:
- `BPF_CGROUP_INET4_BIND` - IPv4 bind()
- `BPF_CGROUP_INET6_BIND` - IPv6 bind()
- `BPF_CGROUP_INET4_CONNECT` - IPv4 connect()
- `BPF_CGROUP_INET6_CONNECT` - IPv6 connect()

**When Called**: Before bind() or connect() operations
**Purpose**: Enforce network policies, modify addresses

```c
int cgroup_sock_addr_prog(struct bpf_sock_addr *ctx);
// Return 1 = allow, 0 = deny
// Can modify ctx->user_ip4, ctx->user_port
```

**Use Cases**:
- Container network policies (allow/deny connections)
- Transparent proxying (redirect connections)
- Port remapping
- IP address translation for containers

### 3. cgroup/sock_ops (Socket Operations)

**Attach Point**: `BPF_CGROUP_SOCK_OPS`
**When Called**: Various socket events (connect, passive open, data transfer)
**Purpose**: Monitor socket operations, set socket options

```c
int cgroup_sock_ops_prog(struct bpf_sock_ops *skops);
// Called on multiple events (skops->op)
```

**Events**:
- `BPF_SOCK_OPS_TIMEOUT_INIT` - Set connection timeout
- `BPF_SOCK_OPS_RWND_INIT` - Set receive window
- `BPF_SOCK_OPS_TCP_CONNECT_CB` - Connection established
- `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` - Active connection
- `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` - Passive connection

**Use Cases**:
- Per-container network statistics
- TCP parameter tuning per container
- Connection tracking
- Network accounting

### 4. cgroup/dev (Device Access Control)

**Attach Point**: `BPF_CGROUP_DEVICE`
**When Called**: Device access attempts
**Purpose**: Control access to devices (read/write/mknod)

```c
int cgroup_dev_prog(struct bpf_cgroup_dev_ctx *ctx);
// ctx->access_type: BPF_DEVCG_ACC_READ, WRITE, MKNOD
// ctx->major, ctx->minor: device numbers
// Return 1 = allow, 0 = deny
```

**Use Cases**:
- Prevent containers from accessing host devices
- Allow only specific devices (/dev/null, /dev/zero)
- Block direct disk access
- GPU access control

### 5. cgroup/sysctl (Sysctl Access)

**Attach Point**: `BPF_CGROUP_SYSCTL`
**When Called**: sysctl read/write operations
**Purpose**: Control sysctl parameter access

```c
int cgroup_sysctl_prog(struct bpf_sysctl *ctx);
// Return 1 = allow, 0 = deny
```

**Use Cases**:
- Prevent containers from modifying kernel parameters
- Read-only access to certain sysctls
- Audit sysctl changes

### 6. cgroup/sendmsg & cgroup/recvmsg

**Attach Points**: `BPF_CGROUP_UDP4_SENDMSG`, `BPF_CGROUP_UDP4_RECVMSG`, etc.
**When Called**: sendmsg()/recvmsg() syscalls
**Purpose**: Modify or filter messages

**Use Cases**:
- Packet filtering at socket layer
- Address translation
- Message inspection

## Cgroup Hierarchy and Inheritance

### Policy Inheritance

Programs attached to parent cgroups affect all children:

```
/sys/fs/cgroup/
├── [BPF: deny raw sockets]     ← Applies to all below
│
└── docker/
    ├── [BPF: allow only ports 80,443]  ← Applies to all containers
    │
    ├── container1/
    │   └── [BPF: log all connections]  ← Only container1
    │
    └── container2/                      ← Gets parent policies
```

### Effective Policy

The effective policy is the **intersection** of all programs in the hierarchy:
1. Root cgroup program runs first
2. Then child cgroup program
3. All must allow (return 1) for operation to succeed

### Override Behavior

Programs in child cgroups **cannot override** parent denials:
- Parent denies → operation blocked (child cannot allow)
- Parent allows → child can still deny

## Attaching Cgroup Programs

### Find Cgroup Path

```bash
# Container's cgroup
docker inspect <container-id> | jq '.[0].State.Pid'
cat /proc/<PID>/cgroup

# Example output:
# 0::/docker/abc123...

# Full path:
# /sys/fs/cgroup/docker/abc123...
```

### Attach Program

```clojure
(ns cgroup-example
  (:require [clj-ebpf.core :as bpf]))

;; Load program
(def prog (bpf/load-program cgroup-program))

;; Attach to cgroup
(bpf/attach-cgroup prog
                   "/sys/fs/cgroup/docker/abc123"
                   :cgroup-inet4-connect)

;; Detach
(bpf/detach-cgroup prog "/sys/fs/cgroup/docker/abc123")
```

## Common Patterns

### Pattern 1: IP Whitelist/Blacklist

```clojure
(def allowed-ips
  {:type :hash
   :key-type :u32    ; IPv4 address
   :value-type :u8   ; 1 = allowed
   :max-entries 1000})

(def connect-filter
  {:type :cgroup-sock-addr
   :attach-type :inet4-connect
   :program
   [;; Load destination IP
    [(bpf/load-ctx :w :r6 24)]        ; ctx->user_ip4

    ;; Check if allowed
    [(bpf/store-mem :w :r10 -4 :r6)]
    [(bpf/mov-reg :r1 (bpf/map-ref allowed-ips))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    ;; Allow if found, deny otherwise
    [(bpf/mov :r0 0)]                  ; Default: deny
    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/mov :r0 1)]                  ; Allow

    [:exit]
    [(bpf/exit)]]})
```

### Pattern 2: Port Restriction

```clojure
(def port-filter
  {:type :cgroup-sock-addr
   :attach-type :inet4-connect
   :program
   [;; Load destination port
    [(bpf/load-ctx :w :r6 28)]        ; ctx->user_port
    [(bpf/endian-be :h :r6)]          ; Convert to host byte order

    ;; Allow only ports 80, 443
    [(bpf/jmp-imm :jeq :r6 80 :allow)]
    [(bpf/jmp-imm :jeq :r6 443 :allow)]

    ;; Deny
    [(bpf/mov :r0 0)]
    [(bpf/exit)]

    [:allow]
    [(bpf/mov :r0 1)]
    [(bpf/exit)]]})
```

### Pattern 3: Connection Tracking

```clojure
(def connection-stats
  {:type :hash
   :key-type :struct   ; {src_ip, dst_ip, dst_port}
   :value-type :struct ; {count, bytes, last_seen}
   :max-entries 10000})

(def sock-ops-tracker
  {:type :cgroup-sock-ops
   :program
   [;; Check operation type
    [(bpf/load-ctx :w :r6 0)]         ; skops->op

    ;; Handle TCP_CONNECT_CB
    [(bpf/jmp-imm :jne :r6 4 :exit)]  ; BPF_SOCK_OPS_TCP_CONNECT_CB = 4

    ;; Extract connection info
    [(bpf/load-ctx :w :r7 20)]        ; remote_ip4
    [(bpf/load-ctx :w :r8 28)]        ; remote_port

    ;; Update statistics map
    ;; ... (map update logic)

    [:exit]
    [(bpf/mov :r0 1)]
    [(bpf/exit)]]})
```

### Pattern 4: Device Allowlist

```clojure
(def allowed-devices
  {:type :hash
   :key-type :u64     ; (major << 32) | minor
   :value-type :u8    ; 1 = allowed
   :max-entries 100})

(def device-filter
  {:type :cgroup-dev
   :program
   [;; Load major and minor
    [(bpf/load-ctx :w :r6 4)]         ; major
    [(bpf/load-ctx :w :r7 8)]         ; minor

    ;; Combine into key
    [(bpf/lsh :r6 32)]
    [(bpf/or-reg :r6 :r7)]

    ;; Check if allowed
    [(bpf/store-mem :dw :r10 -8 :r6)]
    [(bpf/mov-reg :r1 (bpf/map-ref allowed-devices))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    ;; Allow if found, deny otherwise
    [(bpf/mov :r0 0)]
    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/mov :r0 1)]

    [:exit]
    [(bpf/exit)]]})
```

## Container Integration

### Docker Integration

```bash
# Get container cgroup path
CONTAINER_ID=$(docker ps -q --filter name=myapp)
CGROUP_PATH=$(docker inspect $CONTAINER_ID \
  | jq -r '.[0].State.Pid' \
  | xargs -I {} cat /proc/{}/cgroup \
  | grep -o '/docker/.*' \
  | head -1)

# Full path
FULL_PATH="/sys/fs/cgroup${CGROUP_PATH}"

# Attach BPF program
sudo ./attach-cgroup-prog --cgroup "$FULL_PATH" --prog network-policy.o
```

### Kubernetes Integration

```yaml
# Pod with custom cgroup path
apiVersion: v1
kind: Pod
metadata:
  name: secured-pod
  annotations:
    bpf.io/cgroup-programs: "network-policy,device-filter"
spec:
  containers:
  - name: app
    image: myapp:latest
```

## Use Cases

### Use Case 1: Multi-Tenant Container Security

```
Scenario: Prevent containers from connecting to internal network

Solution:
- Attach cgroup/sock_addr program to /sys/fs/cgroup/docker/
- Block connections to 10.0.0.0/8 (internal network)
- Allow only external connections
```

### Use Case 2: Resource Accounting

```
Scenario: Track network usage per container for billing

Solution:
- Attach cgroup/sock_ops program
- Count bytes sent/received per connection
- Store in map indexed by cgroup ID
- Export metrics to billing system
```

### Use Case 3: Transparent Service Mesh

```
Scenario: Redirect all outbound HTTP to local proxy

Solution:
- Attach cgroup/sock_addr to CONNECT
- Rewrite destination IP to 127.0.0.1:8080
- Proxy handles actual connection
- No application changes needed
```

### Use Case 4: GPU Access Control

```
Scenario: Allow only specific containers to access GPU

Solution:
- Attach cgroup/dev program
- Check device major/minor for GPU (195/*)
- Allow only whitelisted cgroups
- Deny all others
```

## Performance Considerations

### Overhead

| Program Type | Overhead | When to Use |
|--------------|----------|-------------|
| sock | ~100ns per socket() | Always acceptable |
| sock_addr | ~500ns per connect() | Acceptable (infrequent) |
| sock_ops | ~200ns per event | Be selective on events |
| dev | ~50ns per access | Always acceptable |

### Optimization Tips

1. **Minimize Map Lookups**: Cache decisions when possible
2. **Use Per-CPU Maps**: Avoid contention in multi-container environments
3. **Early Exit**: Check simple conditions first
4. **Selective Events**: Only handle necessary sock_ops events
5. **Efficient Keys**: Use primitive types for map keys

## Debugging Cgroup Programs

### Check Attached Programs

```bash
# List programs on a cgroup
bpftool cgroup show /sys/fs/cgroup/docker/abc123

# Example output:
# ID       AttachType            AttachFlags     Name
# 42       connect4              0               block_internal
# 43       sock_ops              0               track_connections
```

### Common Issues

**Issue 1: Program Not Running**
```bash
# Verify cgroup path exists
ls -la /sys/fs/cgroup/docker/abc123

# Check if process is in cgroup
cat /sys/fs/cgroup/docker/abc123/cgroup.procs
```

**Issue 2: Denials Not Working**
```bash
# Check program order (parents run first)
bpftool cgroup tree /sys/fs/cgroup/docker

# Verify return values (0 = deny, 1 = allow)
bpftool prog dump xlated id 42
```

**Issue 3: Context Access Errors**
```bash
# Verify context structure offsets
# Different for sock, sock_addr, sock_ops, dev
bpftool btf dump file /sys/kernel/btf/vmlinux \
  | grep -A 20 "bpf_sock_addr"
```

## Security Considerations

### Defense in Depth

Cgroup BPF should be **one layer** of security:
1. Cgroup BPF programs (this chapter)
2. LSM BPF programs (Chapter 9)
3. Network policies (firewall, security groups)
4. Container runtime security (AppArmor, SELinux)

### Bypass Risks

**Risk**: Root in container can potentially bypass cgroup restrictions
**Mitigation**:
- Use LSM BPF for system-wide enforcement
- Properly configure user namespaces
- Limit capabilities (CAP_NET_ADMIN, etc.)

### Audit Logging

Always log denials for security monitoring:
```clojure
;; Log denied connection attempts
(when (denied? connection)
  (bpf/ringbuf-output event-buffer event-data))
```

## Kernel Version Requirements

| Feature | Minimum Kernel |
|---------|----------------|
| **cgroup/sock** | 4.10 |
| **cgroup/sock_addr** | 4.17 |
| **cgroup/sock_ops** | 4.13 |
| **cgroup/dev** | 4.15 |
| **cgroup/sysctl** | 5.2 |
| **Cgroup v2** | 4.5 (required for BPF) |

Check support:
```bash
# Check cgroup v2
mount | grep cgroup2

# If not mounted:
mount -t cgroup2 none /sys/fs/cgroup
```

## Best Practices

1. **Start Permissive**: Log denials before enforcing
2. **Test Per-Container**: Attach to specific containers first
3. **Monitor Performance**: Track program execution time
4. **Version Control**: Store BPF programs in Git
5. **Document Policies**: Clear comments on what/why
6. **Gradual Rollout**: Deploy to dev → staging → production
7. **Alerting**: Monitor BPF program failures
8. **Cleanup**: Detach programs when containers stop

## Summary

Cgroup BPF programs provide:

✅ **Per-Container Control** - Policies scoped to process groups
✅ **Automatic Inheritance** - Child cgroups get parent policies
✅ **Container-Native** - Works seamlessly with Docker/Kubernetes
✅ **Resource Control** - Network, device, sysctl enforcement
✅ **Multi-Tenancy** - Isolate tenants with different policies
✅ **Transparent** - No application changes required

**Key Takeaway**: Cgroup BPF is essential for container security and multi-tenant environments. It provides the granularity needed for per-container policies while maintaining performance.

## Next Steps

The following labs demonstrate practical cgroup BPF applications:

1. **Lab 11.1: Container Network Policy Enforcer** - Control outbound connections
2. **Lab 11.2: Resource Usage Monitor** - Track network usage per container
3. **Lab 11.3: Device Access Control** - Restrict device access

These labs will prepare you for building production container security systems.

## References

- [Cgroup BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_cgroup.html)
- [Cgroup v2 Documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [BPF and Containers](https://kinvolk.io/blog/2018/10/exploring-bpf-based-networking/)
