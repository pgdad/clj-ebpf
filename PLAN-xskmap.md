# Plan: XSKMAP (AF_XDP) Implementation

## 1. Feature Description
**XSKMAP** is the core BPF component for AF_XDP (XDP Sockets), a high-performance, zero-copy networking technology. It maps XDP sockets to queues on a network interface, allowing an XDP program to redirect specific packets directly to a userspace application via a shared memory ring buffer (UMEM).

## 2. Implementation Details

### 2.1 Constants
Update `src/clj_ebpf/constants.clj`:
- Map Type: `BPF_MAP_TYPE_XSKMAP`.
- Helpers: `bpf_redirect_map`.

### 2.2 Map Abstractions (`src/clj_ebpf/maps.clj`)
Add:
- `create-xsk-map`
- **Value Handling**: The value in an XSKMAP is a file descriptor to an open AF_XDP socket (`xsk_socket`).
  - Note: `clj-ebpf` currently manages BPF syscalls. Full AF_XDP support requires creating `AF_XDP` sockets, `mmap`ing UMEM, etc.
  - **Scope**: This plan covers the *BPF Map* side. A separate plan or future work would be needed for the full userspace AF_XDP socket management (which is non-trivial). For now, we enable the map creation and update so advanced users can bridge it with other libraries or raw syscalls.

## 3. Testing Strategy

### 3.1 Unit Tests
- Create `test/clj_ebpf/maps/xskmap_test.clj`.
- Verify map creation properties.

### 3.2 Integration Tests
- **Test Case 1**: Create XSKMAP.
- **Test Case 2**: Attempt to update (requires a valid XDP socket FD, might need to mock or skip if full AF_XDP setup is too complex for basic CI).
- **Test Case 3**: Verify XDP program compilation with `redirect_map` pointing to XSKMAP.

## 4. Examples
Create `examples/xdp_xsk_bypass.clj`:
```clojure
(ns examples.xdp-xsk-bypass
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]))

;; Create XSKMAP
(def xsks (maps/create-xsk-map 64 :map-name "xsks"))

;; XDP program logic (conceptual)
;; if (packet_destined_for_app) {
;;    return bpf_redirect_map(xsks, queue_id, 0);
;; }
;; return XDP_PASS;
```

## 5. Tutorial Content
Add **Chapter 9.2: AF_XDP and XSKMAP** to `tutorials/part-4-applications/README.md`.
- Explain the zero-copy architecture.
- Role of XSKMAP as the bridge between Kernel XDP and Userspace Socket.
