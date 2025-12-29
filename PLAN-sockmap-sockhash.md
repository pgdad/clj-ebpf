# Plan: SOCKMAP and SOCKHASH Implementation

## 1. Feature Description
**SOCKMAP** and **SOCKHASH** are specialized BPF maps used primarily for socket redirection (sk_skb) and socket filtering (sk_msg). They allow BPF programs to redirect traffic between sockets at the kernel level, bypassing the TCP/IP stack for high-performance proxying, load balancing, and service mesh sidecars.

- **SOCKMAP**: Array-based storage of open sockets.
- **SOCKHASH**: Hash-based storage of open sockets.

## 2. Implementation Details

### 2.1 Constants
Update `src/clj_ebpf/constants.clj` with:
- Map Types:
  - `BPF_MAP_TYPE_SOCKMAP`
  - `BPF_MAP_TYPE_SOCKHASH`
- Program Types:
  - `BPF_PROG_TYPE_SK_SKB`
  - `BPF_PROG_TYPE_SK_MSG`
- Attach Types:
  - `BPF_SK_SKB_STREAM_PARSER`
  - `BPF_SK_SKB_STREAM_VERDICT`
  - `BPF_SK_MSG_VERDICT`
- Helpers:
  - `bpf_sock_map_update`
  - `bpf_sock_hash_update`
  - `bpf_msg_redirect_map`
  - `bpf_msg_redirect_hash`
  - `bpf_sk_redirect_map`
  - `bpf_sk_redirect_hash`

### 2.2 Map Abstractions (`src/clj_ebpf/maps.clj`)
Add convenience functions:
- `create-sock-map`
- `create-sock-hash`
- **Note**: These maps store socket file descriptors (u32) as values during update from userspace, but the kernel converts them to kernel socket structures.

### 2.3 Program Attachment (`src/clj_ebpf/programs.clj`)
Implement `attach-sock-map` logic:
- These programs are attached *to the map itself*, not a network interface.
- Implement `bpf_prog_attach` wrapper for attaching `SK_SKB` programs to the map FD.

### 2.4 DSL Helpers (`src/clj_ebpf/dsl/socket.clj`)
Add helpers for the redirection functions:
- `redirect-msg-to-map`
- `redirect-msg-to-hash`

## 3. Testing Strategy

### 3.1 Unit Tests
- Create `test/clj_ebpf/maps/sockmap_test.clj`.
- Test creation of `SOCKMAP` and `SOCKHASH`.
- Verify map attributes (key size, value size requirements).

### 3.2 Integration Tests (Requires Mock/Privileges)
- **Test Case 1: Map Creation**: Verify successful creation of maps.
- **Test Case 2: Program Load**: Load a dummy `SK_SKB` program.
- **Test Case 3: Attachment**: Attach the dummy program to the map.
- **Test Case 4: Socket Update**: Open a real socket (e.g., simple TCP listener) and update the map with its FD.

## 4. Examples
Create `examples/sockmap_echo.clj`:
```clojure
(ns examples.sockmap-echo
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]))

;; 1. Create SOCKMAP
(def sock-map (maps/create-sock-map 10 :map-name "echo_map"))

;; 2. Define Parser (extracts length)
(def parser-prog
  (dsl/assemble [...] :prog-type :sk-skb))

;; 3. Define Verdict (redirects)
(def verdict-prog
  (dsl/assemble
    [...
     (dsl/call-helper :msg-redirect-map sock-map-fd 0 0)
     ...]
    :prog-type :sk-skb))

;; 4. Load & Attach
(def loaded-parser (bpf/load-program parser-prog ...))
(def loaded-verdict (bpf/load-program verdict-prog ...))

(bpf/attach-program-to-map loaded-parser sock-map :stream-parser)
(bpf/attach-program-to-map loaded-verdict sock-map :stream-verdict)

;; 5. Userspace: Add sockets to map
;; (bpf/map-update sock-map key socket-fd)
```

## 5. Tutorial Content
Add **Chapter 8.3: Socket Redirection** to `tutorials/part-4-applications/README.md`.
- Concept: Kernel-level socket splicing.
- Hands-on: Building a high-performance TCP proxy.
