# Quick Start: SK_LOOKUP Programmable Socket Lookup

**Duration**: 45-60 minutes | **Difficulty**: Advanced

## Learning Objectives

By the end of this tutorial, you will:
- Understand SK_LOOKUP program architecture and use cases
- Know how to build programs that intercept socket lookups
- Use DSL helpers for context access and socket assignment
- Understand the attachment process via network namespaces
- Build custom socket dispatch logic

## Prerequisites

- Basic clj-ebpf knowledge (maps, programs, DSL)
- Understanding of TCP/UDP sockets
- Familiarity with network programming concepts
- Linux kernel 5.9+ (for SK_LOOKUP support)
- Root privileges for running examples

## Introduction

### What is SK_LOOKUP?

SK_LOOKUP (BPF_PROG_TYPE_SK_LOOKUP) enables **programmable socket lookup**. When the kernel needs to find a socket for an incoming packet (TCP SYN or UDP datagram), it normally searches listening sockets by IP/port. SK_LOOKUP programs run **before** this search and can select a specific socket, bypassing standard bind rules.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Incoming Packet                            │
│                   (TCP SYN or UDP datagram)                         │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               v
┌─────────────────────────────────────────────────────────────────────┐
│                     SK_LOOKUP BPF Program                           │
│                                                                     │
│  Context (bpf_sk_lookup):                                          │
│    - family (AF_INET/AF_INET6)                                     │
│    - protocol (TCP=6/UDP=17)                                       │
│    - remote_ip4/remote_ip6, remote_port                            │
│    - local_ip4/local_ip6, local_port                               │
│    - ingress_ifindex                                               │
│                                                                     │
│  Actions:                                                          │
│    - bpf_sk_assign: Select specific socket                         │
│    - SK_PASS: Continue with normal/assigned lookup                 │
│    - SK_DROP: Drop the packet                                      │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 v                         v
┌────────────────────────┐   ┌───────────────────────────────────────┐
│   SK_DROP              │   │   SK_PASS                              │
│   Packet dropped       │   │   Use assigned socket or normal lookup│
└────────────────────────┘   └───────────────────────────────────────┘
```

### Use Cases

| Use Case | Description |
|----------|-------------|
| Multi-tenant dispatch | Route connections to different services based on source IP |
| Port multiplexing | Multiple services on same port with custom routing |
| Service mesh | Transparent socket steering for service mesh implementations |
| Custom load balancing | Application-aware socket selection |
| Connection filtering | Drop connections based on custom criteria |

---

## Part 1: Understanding bpf_sk_lookup Context

### Context Structure

SK_LOOKUP programs receive `bpf_sk_lookup` context with connection information:

```clojure
(require '[clj-ebpf.dsl.sk-lookup :as sk-lookup])

;; Context field offsets
sk-lookup/sk-lookup-offsets
;; => {:sk              0      ; Selected socket pointer
;;     :family          8      ; AF_INET (2) or AF_INET6 (10)
;;     :protocol        12     ; TCP (6) or UDP (17)
;;     :remote-ip4      16     ; Remote IPv4 (network byte order)
;;     :remote-ip6      20     ; Remote IPv6 (16 bytes)
;;     :remote-port     36     ; Remote port (network byte order)
;;     :local-ip4       40     ; Local IPv4 (network byte order)
;;     :local-ip6       44     ; Local IPv6 (16 bytes)
;;     :local-port      60     ; Local port (host byte order)
;;     :ingress-ifindex 64}    ; Ingress interface
```

### Important: Byte Order

- **local_port**: Host byte order (can use directly)
- **remote_port**: Network byte order (big-endian)
- **IP addresses**: Network byte order (big-endian)

```clojure
;; Byte order conversion utilities
(sk-lookup/htons 8080)     ; => 0x901F (host to network, 16-bit)
(sk-lookup/htonl 0x7F000001) ; => 0x0100007F (host to network, 32-bit)

;; Parse IP address to integer
(sk-lookup/ipv4-to-int "192.168.1.1") ; => 0xC0A80101
```

---

## Part 2: Building SK_LOOKUP Programs

### Basic Program Structure

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.sk-lookup :as sk-lookup])

;; Minimal SK_LOOKUP program: pass everything
(def pass-all-insns
  (vec (concat
        ;; Save context pointer
        (sk-lookup/sk-lookup-prologue :r6)
        ;; Return SK_PASS
        (sk-lookup/sk-lookup-pass))))

;; Assemble to bytecode
(def bytecode (dsl/assemble pass-all-insns))
```

### Loading Context Fields

```clojure
;; Load specific fields from context
(sk-lookup/sk-lookup-get-local-port :r6 :r7)   ; Load local port
(sk-lookup/sk-lookup-get-remote-port :r6 :r7)  ; Load remote port
(sk-lookup/sk-lookup-get-protocol :r6 :r7)     ; Load protocol
(sk-lookup/sk-lookup-get-family :r6 :r7)       ; Load address family
(sk-lookup/sk-lookup-get-local-ip4 :r6 :r7)    ; Load local IPv4
(sk-lookup/sk-lookup-get-remote-ip4 :r6 :r7)   ; Load remote IPv4
(sk-lookup/sk-lookup-get-ifindex :r6 :r7)      ; Load interface index

;; Generic field loader
(sk-lookup/sk-lookup-load-field :r6 :r7 :local-port)
```

---

## Part 3: Port-Based Filtering

### Allow Specific Port

```clojure
(def port-8080-only
  "Only allow connections to port 8080."
  (vec (concat
        ;; Prologue: save context
        (sk-lookup/sk-lookup-prologue :r6)

        ;; Load local port
        [(sk-lookup/sk-lookup-get-local-port :r6 :r7)]

        ;; Check if port == 8080
        [(dsl/jmp-imm :jeq :r7 8080 2)]

        ;; Not port 8080 - drop
        (sk-lookup/sk-lookup-drop)

        ;; Port 8080 - pass
        (sk-lookup/sk-lookup-pass))))
```

### Using the check-port Helper

```clojure
;; Helper for port checking with branching
(sk-lookup/sk-lookup-check-port :r6 :r7 8080 3)
;; Generates:
;;   ldx w r7 r6 60     ; Load local_port
;;   jeq r7 8080 3      ; Jump 3 instructions if port matches
```

---

## Part 4: Protocol-Based Filtering

### TCP-Only Filter

```clojure
(def tcp-only
  "Only allow TCP connections."
  (vec (concat
        (sk-lookup/sk-lookup-prologue :r6)

        ;; Load protocol
        [(sk-lookup/sk-lookup-get-protocol :r6 :r7)]

        ;; Check if TCP (protocol == 6)
        [(dsl/jmp-imm :jeq :r7 6 2)]

        ;; Not TCP - drop
        (sk-lookup/sk-lookup-drop)

        ;; TCP - pass
        (sk-lookup/sk-lookup-pass))))
```

### Using the check-protocol Helper

```clojure
;; Check for TCP with keyword
(sk-lookup/sk-lookup-check-protocol :r6 :r7 :tcp 3)

;; Check for UDP with keyword
(sk-lookup/sk-lookup-check-protocol :r6 :r7 :udp 3)

;; Or use numeric protocol value
(sk-lookup/sk-lookup-check-protocol :r6 :r7 17 3)  ; UDP = 17
```

---

## Part 5: Using Program Builder

### build-sk-lookup-program

```clojure
(def https-filter
  (sk-lookup/build-sk-lookup-program
   {:ctx-reg :r6
    :body [(sk-lookup/sk-lookup-get-local-port :r6 :r7)
           (dsl/jmp-imm :jne :r7 443 2)  ; Skip to default if not 443
           (dsl/mov :r0 1)                ; SK_PASS for port 443
           (dsl/exit-insn)]
    :default-action :drop}))

;; https-filter is assembled bytecode (byte array)
```

---

## Part 6: Using defprogram Macro

```clojure
(require '[clj-ebpf.macros :refer [defprogram]])

(defprogram sk-lookup-multi-port
  "Allow ports 80, 443, and 8080."
  :type :sk-lookup
  :license "GPL"
  :body (vec (concat
              (sk-lookup/sk-lookup-prologue :r6)

              ;; Load local port
              [(sk-lookup/sk-lookup-get-local-port :r6 :r7)]

              ;; Check port 80
              [(dsl/jmp-imm :jeq :r7 80 6)]

              ;; Check port 443
              [(dsl/jmp-imm :jeq :r7 443 4)]

              ;; Check port 8080
              [(dsl/jmp-imm :jeq :r7 8080 2)]

              ;; Other ports - drop
              (sk-lookup/sk-lookup-drop)

              ;; Allowed ports - pass
              (sk-lookup/sk-lookup-pass))))
```

---

## Part 7: Socket Assignment with bpf_sk_assign

### The bpf_sk_assign Helper

When you want to assign a specific socket to handle a connection:

```clojure
;; Generate bpf_sk_assign call
(sk-lookup/sk-assign ctx-reg sk-reg flags)

;; ctx-reg: Register with bpf_sk_lookup context
;; sk-reg: Register with socket pointer
;; flags: Usually 0

;; Returns:
;;   0 on success
;;   negative errno on failure
```

### Complete Assignment Pattern

```clojure
;; Assign socket and return appropriate result
(sk-lookup/sk-lookup-assign-and-pass :r6 :r7)

;; Generates:
;;   mov r1 r6        ; ctx
;;   mov r2 r7        ; socket
;;   mov r3 0         ; flags
;;   call 124         ; bpf_sk_assign
;;   jne r0 0 2       ; Check result
;;   mov r0 1         ; Success: SK_PASS
;;   exit
;;   mov r0 1         ; Failure: still SK_PASS (let kernel retry)
;;   exit
```

---

## Part 8: Socket Lookup Helpers

### Looking Up Sockets

```clojure
;; bpf_sk_lookup_tcp - Find TCP socket by 4-tuple
(sk-lookup/sk-lookup-tcp ctx-reg tuple-ptr-reg tuple-size netns flags)

;; bpf_sk_lookup_udp - Find UDP socket by 4-tuple
(sk-lookup/sk-lookup-udp ctx-reg tuple-ptr-reg tuple-size netns flags)

;; bpf_sk_release - Release socket reference
(sk-lookup/sk-release sk-reg)
```

### Important: Socket Reference Management

Sockets obtained from `bpf_sk_lookup_tcp/udp` must be released with `bpf_sk_release`:

```clojure
;; Pattern: lookup, use, release
;; 1. Lookup socket
(sk-lookup/sk-lookup-tcp :r6 :r2 12 0 0)  ; Result in r0

;; 2. Check if found
;; (dsl/jmp-imm :jeq :r0 0 ...)  ; NULL check

;; 3. Use the socket (e.g., assign)
;; (sk-lookup/sk-assign :r6 :r0 0)

;; 4. Release reference
(sk-lookup/sk-release :r0)
```

---

## Part 9: Attaching SK_LOOKUP Programs

### Using attach-sk-lookup

```clojure
(require '[clj-ebpf.programs :as progs])

;; Load the program
(def sk-lookup-prog
  (progs/load-program
   {:prog-type :sk-lookup
    :insns bytecode
    :license "GPL"
    :prog-name "my_sk_lookup"}))

;; Attach to current network namespace
(def attached-prog
  (progs/attach-sk-lookup sk-lookup-prog {}))

;; Or specify namespace path
(def attached-prog
  (progs/attach-sk-lookup sk-lookup-prog
    {:netns-path "/proc/self/ns/net"}))

;; Or use pre-opened FD
(def attached-prog
  (progs/attach-sk-lookup sk-lookup-prog
    {:netns-fd netns-fd}))
```

### Detaching

```clojure
;; Detach SK_LOOKUP program
(progs/detach-sk-lookup attached-prog)

;; Or close program (detaches automatically)
(progs/close-program attached-prog)
```

---

## Part 10: Complete Example

### Port-Based Service Dispatcher

```clojure
(ns my-sk-lookup
  (:require [clj-ebpf.programs :as progs]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.sk-lookup :as sk-lookup]))

;; Build dispatcher program
(def dispatcher-bytecode
  (dsl/assemble
   (vec (concat
         ;; Prologue
         (sk-lookup/sk-lookup-prologue :r6)

         ;; Load local port
         [(sk-lookup/sk-lookup-get-local-port :r6 :r7)]

         ;; Port 80 (HTTP) - pass
         [(dsl/jmp-imm :jeq :r7 80 6)]

         ;; Port 443 (HTTPS) - pass
         [(dsl/jmp-imm :jeq :r7 443 4)]

         ;; Port 8080 (API) - pass
         [(dsl/jmp-imm :jeq :r7 8080 2)]

         ;; Other ports - drop
         (sk-lookup/sk-lookup-drop)

         ;; Allowed ports - pass to normal lookup
         (sk-lookup/sk-lookup-pass)))))

;; Load and attach (requires root)
(comment
  (def prog
    (progs/load-program
     {:prog-type :sk-lookup
      :insns dispatcher-bytecode
      :license "GPL"}))

  (def attached
    (progs/attach-sk-lookup prog {}))

  ;; Later: cleanup
  (progs/close-program attached))
```

---

## DSL Reference

### Context Access

| Function | Description |
|----------|-------------|
| `sk-lookup-prologue` | Save context pointer |
| `sk-lookup-load-field` | Load any context field |
| `sk-lookup-get-family` | Load address family |
| `sk-lookup-get-protocol` | Load IP protocol |
| `sk-lookup-get-local-port` | Load local port |
| `sk-lookup-get-remote-port` | Load remote port |
| `sk-lookup-get-local-ip4` | Load local IPv4 |
| `sk-lookup-get-remote-ip4` | Load remote IPv4 |
| `sk-lookup-get-ifindex` | Load interface index |

### Helper Functions

| Function | Description |
|----------|-------------|
| `sk-assign` | Assign socket (helper 124) |
| `sk-lookup-tcp` | Lookup TCP socket (helper 84) |
| `sk-lookup-udp` | Lookup UDP socket (helper 85) |
| `sk-release` | Release socket reference (helper 86) |

### Common Patterns

| Function | Description |
|----------|-------------|
| `sk-lookup-check-port` | Check port and branch |
| `sk-lookup-check-protocol` | Check protocol and branch |
| `sk-lookup-assign-and-pass` | Assign socket and return |

### Return Patterns

| Function | Description |
|----------|-------------|
| `sk-lookup-pass` | Return SK_PASS (1) |
| `sk-lookup-drop` | Return SK_DROP (0) |

---

## Troubleshooting

### Common Issues

1. **"Permission denied"**
   - Need root or CAP_NET_ADMIN + CAP_BPF

2. **"Operation not permitted" on attach**
   - Kernel 5.9+ required for SK_LOOKUP
   - Check `/proc/sys/kernel/osrelease`

3. **Program load fails**
   - Check verifier log in exception
   - Ensure all code paths return valid verdict

4. **Socket assignment fails**
   - Socket must be listening
   - Socket must match protocol (TCP/UDP)

### Debugging

```bash
# Check kernel version
uname -r

# List SK_LOOKUP programs
sudo bpftool prog list | grep sk_lookup

# Check BPF links
sudo bpftool link list
```

---

## Summary

You learned:
- SK_LOOKUP context structure and fields
- Building port and protocol filters
- Using DSL helpers for context access
- Socket assignment with bpf_sk_assign
- Attaching to network namespaces

---

## Next Steps

- **[SOCKMAP Tutorial](quick-start-sockmap.md)** - Socket redirection
- **[XSKMAP Tutorial](quick-start-xskmap.md)** - AF_XDP zero-copy

---

## Reference

### Kernel Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| SK_LOOKUP programs | 5.9 |
| bpf_sk_assign helper | 5.9 |
| Multiple SK_LOOKUP programs | 5.9 |

### Helper Function IDs

| Helper | ID | Description |
|--------|-----|-------------|
| `bpf_sk_assign` | 124 | Assign socket to connection |
| `bpf_sk_lookup_tcp` | 84 | Lookup TCP socket |
| `bpf_sk_lookup_udp` | 85 | Lookup UDP socket |
| `bpf_sk_release` | 86 | Release socket reference |

### Context Field Offsets

| Field | Offset | Size | Byte Order |
|-------|--------|------|------------|
| sk | 0 | 8 | - |
| family | 8 | 4 | host |
| protocol | 12 | 4 | host |
| remote_ip4 | 16 | 4 | network |
| remote_ip6 | 20 | 16 | network |
| remote_port | 36 | 2 | network |
| local_ip4 | 40 | 4 | network |
| local_ip6 | 44 | 16 | network |
| local_port | 60 | 4 | host |
| ingress_ifindex | 64 | 4 | host |
