# Quick Start: Socket Redirection with SOCKMAP and SOCKHASH

**Duration**: 45-60 minutes | **Difficulty**: Intermediate

## Learning Objectives

By the end of this tutorial, you will:
- Understand SOCKMAP and SOCKHASH map types
- Know when to use SK_SKB vs SK_MSG programs
- Build socket redirect helpers using the DSL
- Create high-performance socket proxies
- Attach programs to socket maps for kernel-level redirection

## Prerequisites

- Basic clj-ebpf knowledge (maps, programs, DSL)
- Understanding of TCP sockets
- Linux kernel 4.14+ (5.8+ recommended for full features)
- Root privileges for running examples

## Introduction

Socket redirection allows you to redirect data between sockets entirely in the kernel, bypassing the TCP/IP stack for connected sockets. This enables:

- **High-performance TCP proxies** - Zero-copy data transfer
- **Service mesh sidecars** - Intercept and redirect application traffic
- **Load balancers** - Distribute connections across backends
- **Connection splicing** - Join two sockets together

### Key Components

| Component | Purpose |
|-----------|---------|
| SOCKMAP | Array-based socket storage |
| SOCKHASH | Hash-based socket storage (flexible keys) |
| SK_SKB | Stream parser + verdict for sk_buff redirection |
| SK_MSG | Message verdict for sendmsg/sendfile redirection |

---

## Part 1: Understanding Socket Maps

### SOCKMAP vs SOCKHASH

```clojure
(require '[clj-ebpf.maps :as maps])

;; SOCKMAP: Array-based, indexed by integer
;; Good when you know the number of sockets upfront
(def sock-map (maps/create-sock-map 256 :map-name "sock_array"))

;; SOCKHASH: Hash-based, flexible keys
;; Good for connection tuples, sparse mappings
(def sock-hash (maps/create-sock-hash 1024
                 :key-size 12  ; e.g., src-ip + dst-ip + port
                 :map-name "sock_hash"))
```

### How Socket Maps Work

1. **Create the map** - SOCKMAP or SOCKHASH
2. **Load programs** - SK_SKB parser/verdict or SK_MSG verdict
3. **Attach programs to map** - Programs run when data arrives
4. **Add sockets to map** - From userspace after accepting connections
5. **Data flows through programs** - Kernel redirects between sockets

---

## Part 2: SK_SKB Programs

SK_SKB programs process stream data (TCP) and consist of two parts:

### Stream Parser

The parser determines message boundaries. It returns the number of bytes that form a complete message.

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.socket :as socket])

;; Simple parser: return full buffer length (no message framing)
(def parser-insns
  [(dsl/mov-reg :r6 :r1)      ; Save context (__sk_buff)
   (dsl/ldx :w :r0 :r6 0)     ; r0 = skb->len (offset 0 in __sk_buff)
   (dsl/exit-insn)])

;; Assemble to bytecode
(def parser-bytecode (dsl/assemble parser-insns))
```

### Stream Verdict

The verdict decides what to do with the message: pass, drop, or redirect.

```clojure
;; Simple verdict: pass all data to the socket
(def verdict-pass-insns
  (vec (concat
         (socket/sk-skb-prologue :r2 :r3)  ; Load data pointers
         (socket/sk-skb-pass))))            ; Return SK_PASS

;; Verdict with redirect to socket at index 0
(def verdict-redirect-insns
  (vec (concat
         (socket/sk-skb-prologue :r2 :r3)
         (socket/sk-redirect-map-with-fallback 5 0))))  ; map-fd=5, key=0
```

### SK_SKB Return Values

```clojure
;; Available actions
(socket/sk-skb-action :pass)    ; => 1 (SK_PASS)
(socket/sk-skb-action :drop)    ; => 0 (SK_DROP)

;; Convenience functions
(socket/sk-skb-pass)  ; Returns [mov r0 1, exit]
(socket/sk-skb-drop)  ; Returns [mov r0 0, exit]
```

---

## Part 3: SK_MSG Programs

SK_MSG programs process sendmsg()/sendfile() operations. They're useful for intercepting outbound data.

### SK_MSG Context

SK_MSG uses `sk_msg_md` context (different from SK_SKB's `__sk_buff`):

```clojure
;; Access fields from sk_msg_md
(socket/sk-msg-offset :data)         ; => 0
(socket/sk-msg-offset :data-end)     ; => 8
(socket/sk-msg-offset :remote-ip4)   ; => 20
(socket/sk-msg-offset :local-ip4)    ; => 24
(socket/sk-msg-offset :remote-port)  ; => 60
(socket/sk-msg-offset :local-port)   ; => 64
```

### Building SK_MSG Programs

```clojure
;; SK_MSG verdict that passes all messages
(def msg-pass-insns
  (vec (concat
         (socket/sk-msg-prologue :r6 :r2 :r3)
         (socket/sk-msg-pass))))

;; SK_MSG verdict that redirects to another socket
(def msg-redirect-insns
  (vec (concat
         (socket/sk-msg-prologue :r6 :r2 :r3)
         (socket/msg-redirect-map-with-fallback :r6 5 0))))  ; ctx, map-fd, key
```

### Loading a Field

```clojure
;; Load remote port from context
(def load-port-insn
  (socket/sk-msg-load-field :r6 :r5 :remote-port))
;; Generates: ldx w r5 r6 60
```

---

## Part 4: Redirect Helpers

The DSL provides helpers for all socket redirect operations:

### SK_SKB Redirect (bpf_sk_redirect_map)

```clojure
;; Redirect to SOCKMAP entry
(socket/sk-redirect-map map-fd key flags)
;; Generates: ld_map_fd r1, mov r2 key, mov r3 flags, call 52

;; Redirect to SOCKHASH entry (key is pointer)
(socket/sk-redirect-hash map-fd key-ptr-reg flags)
;; Generates: ld_map_fd r1, mov r2 key-ptr, mov r3 flags, call 72

;; With automatic exit instruction
(socket/sk-redirect-map-with-fallback map-fd key)
```

### SK_MSG Redirect (bpf_msg_redirect_map)

```clojure
;; Redirect message to SOCKMAP entry
(socket/msg-redirect-map ctx-reg map-fd key flags)
;; Generates: mov r1 ctx, ld_map_fd r2, mov r3 key, mov r4 flags, call 60

;; Redirect message to SOCKHASH entry
(socket/msg-redirect-hash ctx-reg map-fd key-ptr-reg flags)
;; Generates: mov r1 ctx, ld_map_fd r2, mov r3 key-ptr, mov r4 flags, call 71

;; With automatic exit instruction
(socket/msg-redirect-map-with-fallback ctx-reg map-fd key)
```

---

## Part 5: Attaching Programs to Maps

Unlike XDP/TC programs attached to interfaces, SK_SKB/SK_MSG programs attach to the socket map itself:

```clojure
(require '[clj-ebpf.programs :as progs])

;; Load SK_SKB parser program
(def parser-prog
  (progs/load-program
    {:prog-type :sk-skb
     :insns parser-bytecode
     :license "GPL"
     :prog-name "sk_parser"}))

;; Load SK_SKB verdict program
(def verdict-prog
  (progs/load-program
    {:prog-type :sk-skb
     :insns verdict-bytecode
     :license "GPL"
     :prog-name "sk_verdict"}))

;; Attach to SOCKMAP
(progs/attach-sk-skb parser-prog (:fd sock-map) :stream-parser)
(progs/attach-sk-skb verdict-prog (:fd sock-map) :stream-verdict)

;; For SK_MSG
(def msg-prog
  (progs/load-program
    {:prog-type :sk-msg
     :insns msg-bytecode
     :license "GPL"
     :prog-name "msg_verdict"}))

(progs/attach-sk-msg msg-prog (:fd sock-map))
```

### Detaching Programs

```clojure
;; Detach specific program
(progs/detach-sk-skb (:fd sock-map) :stream-parser :prog-fd (:fd parser-prog))
(progs/detach-sk-skb (:fd sock-map) :stream-verdict :prog-fd (:fd verdict-prog))
(progs/detach-sk-msg (:fd sock-map) :prog-fd (:fd msg-prog))

;; Detach all programs of a type
(progs/detach-sk-skb (:fd sock-map) :stream-parser)
```

---

## Part 6: Complete Example - Echo Server

This example creates an echo server where data is redirected back to the same socket:

```clojure
(ns examples.echo-server
  (:require [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as progs]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.socket :as socket]))

;; 1. Create SOCKMAP
(def sock-map (maps/create-sock-map 256 :map-name "echo_sockets"))

;; 2. Build parser (return full message length)
(def parser-bytecode
  (dsl/assemble
    [(dsl/mov-reg :r6 :r1)
     (dsl/ldx :w :r0 :r6 0)  ; skb->len
     (dsl/exit-insn)]))

;; 3. Build verdict (redirect to same socket at index 0)
(def verdict-bytecode
  (dsl/assemble
    (vec (concat
           (socket/sk-skb-prologue :r2 :r3)
           (socket/sk-redirect-map-with-fallback (:fd sock-map) 0)))))

;; 4. Load and attach programs
(def parser-prog
  (progs/load-program
    {:prog-type :sk-skb
     :insns parser-bytecode
     :license "GPL"}))

(def verdict-prog
  (progs/load-program
    {:prog-type :sk-skb
     :insns verdict-bytecode
     :license "GPL"}))

(progs/attach-sk-skb parser-prog sock-map :stream-parser)
(progs/attach-sk-skb verdict-prog sock-map :stream-verdict)

;; 5. In your server accept loop:
;; (maps/map-update sock-map 0 client-socket-fd)
;; Now data sent to the socket echoes back automatically!
```

---

## Part 7: Complete Example - TCP Proxy

A proxy pattern uses socket pairs where data from client redirects to backend and vice versa:

```clojure
(ns examples.tcp-proxy
  (:require [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as progs]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.socket :as socket]))

;; SOCKMAP for socket pairs
;; Even indices = client sockets
;; Odd indices = backend sockets
(def proxy-map (maps/create-sock-map 512 :map-name "proxy_sockets"))

;; SK_MSG verdict that redirects based on socket index
;; Client at index N redirects to backend at index N+1
;; Backend at index N+1 redirects to client at index N
(def msg-verdict-bytecode
  (dsl/assemble
    (vec (concat
           (socket/sk-msg-prologue :r6 :r2 :r3)
           ;; Simplified: always redirect to index 0
           ;; Real implementation would compute peer index
           (socket/msg-redirect-map-with-fallback :r6 (:fd proxy-map) 0)))))

(def msg-prog
  (progs/load-program
    {:prog-type :sk-msg
     :insns msg-verdict-bytecode
     :license "GPL"}))

(progs/attach-sk-msg msg-prog proxy-map)

;; For each connection pair:
;; (let [client-idx (* pair-id 2)
;;       backend-idx (inc client-idx)]
;;   (maps/map-update proxy-map client-idx client-fd)
;;   (maps/map-update proxy-map backend-idx backend-fd))
```

---

## Part 8: Using with Declarative Macros

Combine socket redirection with the declarative macro system:

```clojure
(require '[clj-ebpf.macros :refer [defmap-spec defprogram with-bpf-script]]
         '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.socket :as socket])

(defmap-spec echo-sockets
  "SOCKMAP for echo server"
  :type :sockmap
  :key-size 4
  :value-size 4
  :max-entries 256)

(defprogram sk-skb-echo-parser
  "Return full message length"
  :type :sk-skb
  :license "GPL"
  :body [(dsl/mov-reg :r6 :r1)
         (dsl/ldx :w :r0 :r6 0)
         (dsl/exit-insn)])

(defprogram sk-skb-echo-verdict
  "Pass all data (echo happens via redirect)"
  :type :sk-skb
  :license "GPL"
  :body (vec (concat
               (socket/sk-skb-prologue :r2 :r3)
               (socket/sk-skb-pass))))

;; Note: with-bpf-script attachment for :sk-skb is:
;; {:prog p :type :sk-skb :target sock-map :attach-type :stream-parser}
```

---

## Best Practices

### 1. Always Check Return Values

Redirect helpers return SK_PASS on success, SK_DROP on failure:

```clojure
;; The return value from bpf_sk_redirect_map is the action
;; Just return it directly
(socket/sk-redirect-map-with-fallback map-fd key)
;; Includes: call helper, exit (returns helper result)
```

### 2. Use SOCKHASH for Connection Tuples

When you need to look up by connection info:

```clojure
(def conn-hash
  (maps/create-sock-hash 10000
    :key-size 12  ; src-ip (4) + dst-ip (4) + port (4)
    :map-name "conn_map"))
```

### 3. Handle Socket Removal

Sockets are automatically removed from the map when closed, but you can also:

```clojure
;; Explicitly remove
(maps/map-delete sock-map key)
```

### 4. Consider SK_SKB vs SK_MSG

| Use Case | Program Type |
|----------|-------------|
| Redirect received data | SK_SKB (stream verdict) |
| Redirect sent data | SK_MSG |
| Parse message boundaries | SK_SKB (stream parser) |
| Connection-based routing | Either (SK_MSG often simpler) |

---

## Troubleshooting

### Program Not Triggering

1. Verify attachment: `sudo bpftool prog list`
2. Check map has sockets: `sudo bpftool map dump id <map-id>`
3. Verify socket is TCP (SOCKMAP only works with TCP)

### Redirect Failing

1. Target socket must be in the map
2. Key must exist in SOCKMAP/SOCKHASH
3. Check verifier log for helper usage errors

### Performance Issues

1. Use SK_MSG for sendmsg redirection (lower overhead)
2. Minimize per-packet processing in parser
3. Consider SOCKHASH for O(1) lookup with connection keys

---

## Summary

You learned how to:
- Create SOCKMAP and SOCKHASH for socket storage
- Build SK_SKB parser and verdict programs
- Build SK_MSG verdict programs
- Use redirect helpers for kernel-level socket splicing
- Attach programs to socket maps
- Build echo servers and TCP proxies

---

## Next Steps

- **[XDP Redirect Tutorial](quick-start-xdp-redirect.md)** - Interface-level packet redirection
- **[Chapter 8: TC and Networking](part-2-program-types/chapter-08/README.md)** - Traffic control programs
- **[Performance Optimization](part-3-advanced/chapter-12/README.md)** - High-performance techniques

---

## Reference

### DSL Functions

| Function | Description |
|----------|-------------|
| `socket/sk-skb-prologue` | SK_SKB program prologue |
| `socket/sk-msg-prologue` | SK_MSG program prologue |
| `socket/sk-redirect-map` | Redirect to SOCKMAP |
| `socket/sk-redirect-hash` | Redirect to SOCKHASH |
| `socket/msg-redirect-map` | SK_MSG redirect to SOCKMAP |
| `socket/msg-redirect-hash` | SK_MSG redirect to SOCKHASH |
| `socket/sk-skb-pass/drop` | SK_SKB return patterns |
| `socket/sk-msg-pass/drop` | SK_MSG return patterns |

### Map Functions

| Function | Description |
|----------|-------------|
| `maps/create-sock-map` | Create SOCKMAP (array-based) |
| `maps/create-sock-hash` | Create SOCKHASH (hash-based) |

### Program Functions

| Function | Description |
|----------|-------------|
| `progs/attach-sk-skb` | Attach SK_SKB to map |
| `progs/attach-sk-msg` | Attach SK_MSG to map |
| `progs/detach-sk-skb` | Detach SK_SKB from map |
| `progs/detach-sk-msg` | Detach SK_MSG from map |
