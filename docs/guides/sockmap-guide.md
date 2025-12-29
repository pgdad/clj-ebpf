# Socket Redirection Guide: SOCKMAP and SOCKHASH

This guide covers socket redirection using SOCKMAP, SOCKHASH, SK_SKB, and SK_MSG programs in clj-ebpf.

## Overview

Socket redirection enables kernel-level data transfer between TCP sockets, bypassing the normal TCP/IP stack for connected sockets. This provides:

- **Zero-copy transfers** - Data moves directly between sockets
- **Reduced latency** - No context switches to userspace
- **High throughput** - Millions of operations per second

## Map Types

### SOCKMAP

Array-based socket storage. Use when you have a fixed number of sockets or simple index-based lookups.

```clojure
(require '[clj-ebpf.maps :as maps])

(def sock-map
  (maps/create-sock-map max-entries
    :map-name "my_sockmap"   ; Optional BPF map name
    :key-size 4))            ; Default: 4 (u32 index)
```

**Parameters:**
- `max-entries` - Maximum number of sockets
- `:map-name` - Optional name for the BPF map
- `:key-size` - Key size in bytes (default: 4)

### SOCKHASH

Hash-based socket storage. Use when you need flexible keys like connection tuples.

```clojure
(def sock-hash
  (maps/create-sock-hash max-entries
    :key-size 12              ; Custom key size
    :map-name "conn_hash"))
```

**Common key formats:**
- 4 bytes: Simple integer identifier
- 12 bytes: src-ip + dst-ip + port
- 36 bytes: Full 5-tuple (src/dst IP + src/dst port + protocol)

## Program Types

### SK_SKB Programs

SK_SKB programs process stream data and use `__sk_buff` as context (same as socket filters and TC).

Two program types work together:

1. **Stream Parser** - Determines message boundaries
2. **Stream Verdict** - Decides action (pass/drop/redirect)

#### Stream Parser

```clojure
(require '[clj-ebpf.dsl :as dsl])

;; Return message length (or 0 for more data needed)
(def parser-insns
  [(dsl/mov-reg :r6 :r1)      ; Save context
   (dsl/ldx :w :r0 :r6 0)     ; r0 = skb->len
   (dsl/exit-insn)])
```

#### Stream Verdict

```clojure
(require '[clj-ebpf.dsl.socket :as socket])

;; Pass all data
(def verdict-pass
  (vec (concat
         (socket/sk-skb-prologue :r2 :r3)
         (socket/sk-skb-pass))))

;; Redirect to socket in map
(def verdict-redirect
  (vec (concat
         (socket/sk-skb-prologue :r2 :r3)
         (socket/sk-redirect-map-with-fallback map-fd key))))
```

### SK_MSG Programs

SK_MSG programs process sendmsg()/sendfile() operations. They use `sk_msg_md` as context.

```clojure
;; Pass message
(def msg-pass
  (vec (concat
         (socket/sk-msg-prologue :r6 :r2 :r3)
         (socket/sk-msg-pass))))

;; Redirect message
(def msg-redirect
  (vec (concat
         (socket/sk-msg-prologue :r6 :r2 :r3)
         (socket/msg-redirect-map-with-fallback :r6 map-fd key))))
```

## DSL Reference

### Prologues

```clojure
;; SK_SKB prologue (saves context, loads data pointers)
(socket/sk-skb-prologue data-reg data-end-reg)
(socket/sk-skb-prologue ctx-reg data-reg data-end-reg)

;; SK_MSG prologue
(socket/sk-msg-prologue ctx-reg data-reg data-end-reg)
```

### Return Patterns

```clojure
;; SK_SKB
(socket/sk-skb-pass)   ; Returns SK_PASS (1)
(socket/sk-skb-drop)   ; Returns SK_DROP (0)

;; SK_MSG
(socket/sk-msg-pass)   ; Returns SK_PASS (1)
(socket/sk-msg-drop)   ; Returns SK_DROP (0)
```

### Redirect Helpers

```clojure
;; SK_SKB -> SOCKMAP
(socket/sk-redirect-map map-fd key flags)
(socket/sk-redirect-map-with-fallback map-fd key)

;; SK_SKB -> SOCKHASH
(socket/sk-redirect-hash map-fd key-ptr-reg flags)

;; SK_MSG -> SOCKMAP
(socket/msg-redirect-map ctx-reg map-fd key flags)
(socket/msg-redirect-map-with-fallback ctx-reg map-fd key)

;; SK_MSG -> SOCKHASH
(socket/msg-redirect-hash ctx-reg map-fd key-ptr-reg flags)
```

### Socket Map Updates (from BPF)

```clojure
;; Add socket to SOCKMAP
(socket/sock-map-update map-fd key flags)

;; Add socket to SOCKHASH
(socket/sock-hash-update map-fd key-ptr-reg flags)
```

### Context Field Access (SK_MSG)

```clojure
;; sk_msg_md offsets
(socket/sk-msg-offset :data)         ; => 0
(socket/sk-msg-offset :data-end)     ; => 8
(socket/sk-msg-offset :family)       ; => 16
(socket/sk-msg-offset :remote-ip4)   ; => 20
(socket/sk-msg-offset :local-ip4)    ; => 24
(socket/sk-msg-offset :remote-port)  ; => 60
(socket/sk-msg-offset :local-port)   ; => 64
(socket/sk-msg-offset :size)         ; => 68

;; Load field
(socket/sk-msg-load-field ctx-reg dst-reg :remote-port)
```

## Program Attachment

### Attach to SOCKMAP/SOCKHASH

```clojure
(require '[clj-ebpf.programs :as progs])

;; Attach SK_SKB parser
(progs/attach-sk-skb parser-prog map-fd :stream-parser)

;; Attach SK_SKB verdict
(progs/attach-sk-skb verdict-prog map-fd :stream-verdict)

;; Attach SK_MSG verdict
(progs/attach-sk-msg msg-prog map-fd)
```

**Options:**
- `:flags` - Attach flags (default: 0)
- `:replace-fd` - Program FD to replace

### Detach from SOCKMAP/SOCKHASH

```clojure
;; Detach specific program
(progs/detach-sk-skb map-fd :stream-parser :prog-fd prog-fd)
(progs/detach-sk-msg map-fd :prog-fd prog-fd)

;; Detach all programs of type
(progs/detach-sk-skb map-fd :stream-parser)
(progs/detach-sk-msg map-fd)
```

## Helper Function IDs

| Helper | ID | Description |
|--------|-----|-------------|
| `bpf_sk_redirect_map` | 52 | SK_SKB redirect to SOCKMAP |
| `bpf_sock_map_update` | 53 | Add socket to SOCKMAP |
| `bpf_msg_redirect_map` | 60 | SK_MSG redirect to SOCKMAP |
| `bpf_sock_hash_update` | 70 | Add socket to SOCKHASH |
| `bpf_msg_redirect_hash` | 71 | SK_MSG redirect to SOCKHASH |
| `bpf_sk_redirect_hash` | 72 | SK_SKB redirect to SOCKHASH |

## Complete Examples

### Echo Server

```clojure
(ns example.echo-server
  (:require [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as progs]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.socket :as socket]))

;; 1. Create map
(def sock-map (maps/create-sock-map 256))

;; 2. Parser: return full length
(def parser-bytecode
  (dsl/assemble
    [(dsl/mov-reg :r6 :r1)
     (dsl/ldx :w :r0 :r6 0)
     (dsl/exit-insn)]))

;; 3. Verdict: redirect back to self
(def verdict-bytecode
  (dsl/assemble
    (vec (concat
           (socket/sk-skb-prologue :r2 :r3)
           (socket/sk-redirect-map-with-fallback (:fd sock-map) 0)))))

;; 4. Load and attach
(def parser (progs/load-program {:prog-type :sk-skb
                                  :insns parser-bytecode
                                  :license "GPL"}))
(def verdict (progs/load-program {:prog-type :sk-skb
                                   :insns verdict-bytecode
                                   :license "GPL"}))

(progs/attach-sk-skb parser sock-map :stream-parser)
(progs/attach-sk-skb verdict sock-map :stream-verdict)

;; 5. Add socket to map (socket echoes to itself)
;; (maps/map-update sock-map 0 socket-fd)
```

### TCP Proxy

```clojure
(ns example.tcp-proxy
  (:require [clj-ebpf.maps :as maps]
            [clj-ebpf.programs :as progs]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.socket :as socket]))

;; Map for socket pairs
(def proxy-map (maps/create-sock-map 1024))

;; SK_MSG verdict for bidirectional redirect
(def msg-bytecode
  (dsl/assemble
    (vec (concat
           (socket/sk-msg-prologue :r6 :r2 :r3)
           ;; Real implementation: compute peer index
           (socket/msg-redirect-map-with-fallback :r6 (:fd proxy-map) 0)))))

(def msg-prog
  (progs/load-program {:prog-type :sk-msg
                        :insns msg-bytecode
                        :license "GPL"}))

(progs/attach-sk-msg msg-prog proxy-map)

;; For each client/backend pair:
;; (maps/map-update proxy-map client-idx client-fd)
;; (maps/map-update proxy-map backend-idx backend-fd)
```

## Kernel Version Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| SOCKMAP | 4.14 |
| SOCKHASH | 4.18 |
| SK_SKB | 4.14 |
| SK_MSG | 4.17 |
| Full socket redirect | 5.8+ |

## Troubleshooting

### Common Issues

1. **"Invalid map type"** - Kernel doesn't support SOCKMAP/SOCKHASH
2. **Redirect fails silently** - Target socket not in map
3. **Program doesn't trigger** - Attachment to wrong map or socket not added

### Debugging

```bash
# List programs
sudo bpftool prog list

# List maps
sudo bpftool map list

# Dump map contents
sudo bpftool map dump id <map-id>

# Check attachments
sudo bpftool prog show id <prog-id>
```

## See Also

- [Quick Start Tutorial](../tutorials/quick-start-sockmap.md)
- [Example: sockmap_redirect.clj](../examples/sockmap_redirect.clj)
- [XDP Redirect Guide](xdp-redirect-guide.md)
