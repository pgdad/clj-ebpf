# Plan: DEVMAP and DEVMAP_HASH Implementation

## 1. Feature Description
**DEVMAP** and **DEVMAP_HASH** are specialized BPF maps used by XDP (eXpress Data Path) programs to redirect packets to specific network interfaces. They enable high-performance layer 2 forwarding and load balancing directly from the network driver.

- **DEVMAP**: Array-based storage of network interface indices (ifindexes).
- **DEVMAP_HASH**: Hash-based storage of ifindexes, allowing sparse or non-contiguous indexing.

## 2. Implementation Details

### 2.1 Constants
Update `src/clj_ebpf/constants.clj`:
- Map Types:
  - `BPF_MAP_TYPE_DEVMAP`
  - `BPF_MAP_TYPE_DEVMAP_HASH`
- Helpers:
  - `bpf_redirect_map`

### 2.2 Map Abstractions (`src/clj_ebpf/maps.clj`)
Add functions:
- `create-dev-map`: For array-based ifindex mapping.
- `create-dev-map-hash`: For hash-based ifindex mapping.
- **Value Structure**: While simple update uses just the ifindex (u32), creating these maps often involves `struct bpf_devmap_val` to configure another BPF program on the egress path (XDP chaining). Support optional value size configuration for this.

### 2.3 DSL Helpers (`src/clj_ebpf/dsl/xdp.clj`)
Add/Verify helpers:
- `redirect-map`: Wrapper for `bpf_redirect_map` helper.

## 3. Testing Strategy

### 3.1 Unit Tests
- Create `test/clj_ebpf/maps/devmap_test.clj`.
- Test creation of both map types.
- Validate key/value size constraints (Key size is 4 for array, arbitrary for hash. Value size is usually 4 or sizeof(bpf_devmap_val)).

### 3.2 Integration Tests
- **Test Case 1**: Create a DEVMAP.
- **Test Case 2**: Populate DEVMAP with loopback interface index.
- **Test Case 3**: Load XDP program using `bpf_redirect_map`.
- **Test Case 4**: Attach XDP program to loopback and verify packets flow (using `bpf_prog_test_run` or counters).

## 4. Examples
Create `examples/xdp_redirect_devmap.clj`:
```clojure
(ns examples.xdp-redirect-devmap
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]))

;; Create map to store interfaces
(def dev-map (maps/create-dev-map 64 :map-name "tx_port"))

;; Populate: Index 1 -> Interface "eth0"
(def eth0-idx (bpf/if-name->index "eth0"))
(bpf/map-update dev-map 1 eth0-idx)

;; XDP Program: Redirect based on lookup
(def redirect-prog
  (dsl/assemble
    [;; ... determine output index in r2 ...
     (dsl/call-helper :redirect-map (:fd dev-map) 0)
     (dsl/exit-insn)]))
```

## 5. Tutorial Content
Add **Chapter 9.1: XDP Redirection** to `tutorials/part-2-program-types/chapter-04-xdp/README.md`.
- Explain `XDP_REDIRECT` vs `bpf_redirect_map`.
- Usage of DEVMAPs for L2 forwarding.
