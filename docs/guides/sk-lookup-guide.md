# SK_LOOKUP Guide: Programmable Socket Lookup

This guide covers SK_LOOKUP programs for programmable socket lookup and dispatch.

## Overview

SK_LOOKUP (BPF_PROG_TYPE_SK_LOOKUP) enables:

- **Programmable socket selection** - Choose which socket handles connections
- **Custom dispatch logic** - Route based on any connection attribute
- **Multi-tenancy** - Multiple services on same IP:port
- **Service mesh** - Transparent socket steering

## Creating SK_LOOKUP Programs

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.sk-lookup :as sk-lookup])

;; Build program bytecode
(def bytecode
  (dsl/assemble
    (vec (concat
          (sk-lookup/sk-lookup-prologue :r6)
          [(sk-lookup/sk-lookup-get-local-port :r6 :r7)]
          ;; ... dispatch logic ...
          (sk-lookup/sk-lookup-pass)))))
```

## Attaching to Network Namespace

```clojure
(require '[clj-ebpf.programs :as progs])

;; Load program
(def prog
  (progs/load-program
    {:prog-type :sk-lookup
     :insns bytecode
     :license "GPL"}))

;; Attach to current namespace
(progs/attach-sk-lookup prog {})

;; Or specific namespace
(progs/attach-sk-lookup prog {:netns-path "/proc/1234/ns/net"})
```

## DSL Reference

### Context Access

| Function | Description |
|----------|-------------|
| `sk-lookup-prologue` | Save context pointer |
| `sk-lookup-get-local-port` | Load local port (host byte order) |
| `sk-lookup-get-remote-port` | Load remote port (network byte order) |
| `sk-lookup-get-protocol` | Load IP protocol |
| `sk-lookup-get-family` | Load address family |
| `sk-lookup-get-local-ip4` | Load local IPv4 address |
| `sk-lookup-get-remote-ip4` | Load remote IPv4 address |
| `sk-lookup-get-ifindex` | Load ingress interface index |

### Helper Functions

| Function | Helper ID | Description |
|----------|-----------|-------------|
| `sk-assign` | 124 | Assign socket to handle connection |
| `sk-lookup-tcp` | 84 | Lookup TCP socket by 4-tuple |
| `sk-lookup-udp` | 85 | Lookup UDP socket by 4-tuple |
| `sk-release` | 86 | Release socket reference |

### Common Patterns

| Function | Description |
|----------|-------------|
| `sk-lookup-check-port` | Check port and branch |
| `sk-lookup-check-protocol` | Check protocol and branch |
| `sk-lookup-assign-and-pass` | Assign socket and return SK_PASS |

### Return Patterns

| Function | Returns | Description |
|----------|---------|-------------|
| `sk-lookup-pass` | 1 | Continue with normal/assigned lookup |
| `sk-lookup-drop` | 0 | Drop the packet |

## bpf_sk_lookup Context

```
struct bpf_sk_lookup {
    __u64 sk;              // offset 0:  Selected socket
    __u32 family;          // offset 8:  AF_INET or AF_INET6
    __u32 protocol;        // offset 12: TCP (6) or UDP (17)
    __u32 remote_ip4;      // offset 16: Network byte order
    __u32 remote_ip6[4];   // offset 20: Network byte order
    __be16 remote_port;    // offset 36: Network byte order
    __u32 local_ip4;       // offset 40: Network byte order
    __u32 local_ip6[4];    // offset 44: Network byte order
    __u32 local_port;      // offset 60: Host byte order
    __u32 ingress_ifindex; // offset 64: Interface index
};
```

## Complete Examples

### Port-Based Filter

```clojure
(def port-filter
  (dsl/assemble
    (vec (concat
          (sk-lookup/sk-lookup-prologue :r6)
          [(sk-lookup/sk-lookup-get-local-port :r6 :r7)]
          [(dsl/jmp-imm :jeq :r7 8080 2)]
          (sk-lookup/sk-lookup-drop)
          (sk-lookup/sk-lookup-pass)))))
```

### Protocol Filter (TCP Only)

```clojure
(def tcp-only
  (dsl/assemble
    (vec (concat
          (sk-lookup/sk-lookup-prologue :r6)
          (sk-lookup/sk-lookup-check-protocol :r6 :r7 :tcp 2)
          (sk-lookup/sk-lookup-drop)
          (sk-lookup/sk-lookup-pass)))))
```

### Using Program Builder

```clojure
(def custom-filter
  (sk-lookup/build-sk-lookup-program
    {:ctx-reg :r6
     :body [(sk-lookup/sk-lookup-get-local-port :r6 :r7)
            (dsl/jmp-imm :jne :r7 443 2)
            (dsl/mov :r0 1)
            (dsl/exit-insn)]
     :default-action :drop}))
```

## Kernel Version Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| SK_LOOKUP programs | 5.9 |
| bpf_sk_assign | 5.9 |
| Network namespace attachment | 5.9 |

## Troubleshooting

### Common Issues

1. **"Permission denied"** - Need root or CAP_NET_ADMIN + CAP_BPF

2. **"Operation not permitted"** - Kernel 5.9+ required

3. **Socket assignment fails** - Socket must be listening and match protocol

### Debugging Commands

```bash
# List SK_LOOKUP programs
sudo bpftool prog list | grep sk_lookup

# List BPF links
sudo bpftool link list

# Check kernel version
uname -r
```

## See Also

- [Quick Start Tutorial](../tutorials/quick-start-sk-lookup.md)
- [Example: sk_lookup_steering.clj](../examples/sk_lookup_steering.clj)
- [SOCKMAP Guide](sockmap-guide.md)
