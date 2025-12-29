# Plan: SK_LOOKUP Implementation

## 1. Feature Description
**BPF_PROG_TYPE_SK_LOOKUP** enables programmable socket lookup. When the kernel needs to find a socket for an incoming packet (e.g., TCP SYN), it typically searches listening sockets by IP/Port. `SK_LOOKUP` BPF programs run before this search and can pick a specific socket to receive the packet, ignoring standard bind rules. This enables features like binding to the same port on different IPs (beyond SO_REUSEPORT capabilities) or service-mesh-like steering.

## 2. Implementation Details

### 2.1 Constants
Update `src/clj_ebpf/constants.clj`:
- Program Type: `BPF_PROG_TYPE_SK_LOOKUP`.
- Attach Type: `BPF_SK_LOOKUP`.
- Helper: `bpf_sk_lookup` (return socket).
- Helper: `bpf_sk_release`.

### 2.2 Program Attachment (`src/clj_ebpf/programs.clj`)
- **Attachment Target**: Network Namespace (`/proc/self/ns/net`).
- Implement `attach-sk-lookup`.

### 2.3 Context Access
- Context is `struct bpf_sk_lookup`.
- DSL needs helpers to read fields like `remote_ip`, `remote_port`, `local_ip`, `local_port` from this context.

## 3. Testing Strategy

### 3.1 Unit Tests
- Create `test/clj_ebpf/programs/sk_lookup_test.clj`.

### 3.2 Integration Tests
- **Test Case 1**: Create two TCP listening sockets on different IPs but same port.
- **Test Case 2**: Attach SK_LOOKUP program that steers traffic based on custom logic (e.g., source IP) to one of the sockets.
- **Test Case 3**: Verify connection lands on expected socket.

## 4. Examples
Create `examples/sk_lookup_steering.clj`:
```clojure
(ns examples.sk-lookup-steering
  (:require [clj-ebpf.core :as bpf]))

(def lookup-prog
  (dsl/assemble
    [;; Check destination IP/Port
     ;; Find socket in a SOCKMAP or by looking up listening sockets
     ;; Select socket
     (dsl/call-helper :sk-assign socket-ptr 0)
     ...]
    :prog-type :sk-lookup))

(bpf/attach-sk-lookup (bpf/load-program lookup-prog ...) "/proc/self/ns/net")
```

## 5. Tutorial Content
Add **Chapter 17: Programmable Socket Lookup** to `tutorials/part-3-advanced/README.md`.
- Focus on multi-tenancy use cases (hosting multiple services on same port/IP).
