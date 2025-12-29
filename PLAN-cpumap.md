# Plan: CPUMAP Implementation

## 1. Feature Description
**CPUMAP** is a specialized BPF map type used by XDP programs to redirect packets to a specific CPU for processing by the kernel networking stack (SKB creation). This allows for custom Receive Side Scaling (RSS) logic, load distribution, and isolating network processing to specific cores.

## 2. Implementation Details

### 2.1 Constants
Update `src/clj_ebpf/constants.clj`:
- Map Type: `BPF_MAP_TYPE_CPUMAP`.
- Helpers: `bpf_redirect_map`.

### 2.2 Map Abstractions (`src/clj_ebpf/maps.clj`)
Add:
- `create-cpu-map`
- **Configuration**: CPUMAP values are complex. They are `struct bpf_cpumap_val` containing:
  - `qsize`: Queue size for the target CPU.
  - `mss`: Max segment size (optional).
- Implement a helper to serialize `bpf_cpumap_val` for map updates from Clojure.

### 2.3 DSL Helpers
- Reuse `redirect-map` (same helper as DEVMAP).

## 3. Testing Strategy

### 3.1 Unit Tests
- Create `test/clj_ebpf/maps/cpumap_test.clj`.
- Test creation parameters.
- Test `bpf_cpumap_val` serialization helper.

### 3.2 Integration Tests
- **Test Case 1**: Create CPUMAP.
- **Test Case 2**: Update map for CPU 0 with custom queue size (e.g., 2048).
- **Test Case 3**: Load XDP program redirecting to CPU 0 via map.

## 4. Examples
Create `examples/xdp_cpumap_lb.clj`:
```clojure
(ns examples.xdp-cpumap-lb
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]))

;; Custom RSS: Redirect to CPUs
(def cpu-map (maps/create-cpu-map 8 :map-name "cpu_redirect"))

;; Configure CPU 0 and 1
(maps/update-cpu-map-entry cpu-map 0 {:qsize 1024})
(maps/update-cpu-map-entry cpu-map 1 {:qsize 1024})

;; XDP Program
(def lb-prog
  (dsl/assemble
    [;; Round-robin or hash logic to pick CPU index
     ;; ...
     (dsl/call-helper :redirect-map (:fd cpu-map) 0)
     (dsl/exit-insn)]))
```

## 5. Tutorial Content
Add section **Advanced XDP: CPU Redirection** to `tutorials/part-2-program-types/chapter-04-xdp/README.md`.
- Discuss standard RSS vs BPF-controlled RSS.
- Benefits for performance scaling.
