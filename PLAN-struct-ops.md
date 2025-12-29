# Plan: STRUCT_OPS Implementation

## 1. Feature Description
**BPF_PROG_TYPE_STRUCT_OPS** allows BPF programs to implement kernel function pointers defined in structures. The most common use case is implementing TCP congestion control algorithms entirely in BPF (replacing kernel modules). It essentially allows BPF to act as a kernel module for specific subsystems.

## 2. Implementation Details

### 2.1 Constants
Update `src/clj_ebpf/constants.clj`:
- Program Type: `BPF_PROG_TYPE_STRUCT_OPS`.
- Map Type: `BPF_MAP_TYPE_STRUCT_OPS`.
- Attach Type: `BPF_STRUCT_OPS`.

### 2.2 Program Loading (`src/clj_ebpf/programs.clj`)
Loading struct_ops is complex:
1. Parse Kernel BTF to find the target struct definition (e.g., `tcp_congestion_ops`).
2. Create a `BPF_MAP_TYPE_STRUCT_OPS` map.
3. The map value layout matches the kernel struct layout.
4. Function pointers in the map value are replaced with file descriptors of the BPF programs implementing those functions.
5. Updating the map with the `BPF_F_LINK` flag registers the ops with the kernel.

**New Functions**:
- `load-struct-ops-program`: Load the individual function implementations.
- `register-struct-ops`: Orchestrate the map creation and registration process. Requires robust BTF parsing support (which exists in `clj-ebpf.btf`).

### 2.3 BTF Integration
- Ensure `clj-ebpf.btf` can introspect function signatures of the target struct members to validate the BPF program types.

## 3. Testing Strategy

### 3.1 Unit Tests
- Create `test/clj_ebpf/programs/struct_ops_test.clj`.
- Mock BTF data to simulate `tcp_congestion_ops`.

### 3.2 Integration Tests
- **Test Case 1**: Implement a minimal TCP congestion control ops (e.g., one that just calls the default cubic functions or does nothing).
- **Test Case 2**: Register it.
- **Test Case 3**: Verify it appears in `sysctl net.ipv4.tcp_available_congestion_control`.

## 4. Examples
Create `examples/tcp_congestion_bpf.clj`:
```clojure
(ns examples.tcp-congestion-bpf
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.programs :as progs]))

;; 1. Define BPF implementation for 'ssthresh'
(def ssthresh-prog
  (dsl/assemble [...] :prog-type :struct-ops))

;; 2. Define BPF implementation for 'cong_avoid'
(def cong-avoid-prog
  (dsl/assemble [...] :prog-type :struct-ops))

;; 3. Register
(progs/register-struct-ops
  "my_congestion_algo"
  "tcp_congestion_ops"
  {:ssthresh ssthresh-prog
   :cong_avoid cong-avoid-prog
   :name "bpf_cubic"})
```

## 5. Tutorial Content
Add **Chapter 15: Kernel Extension with Struct Ops** to `tutorials/part-3-advanced/README.md`.
- Focus on TCP congestion control as the primary example.
