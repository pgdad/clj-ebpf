# Plan: FLOW_DISSECTOR Implementation

## 1. Feature Description
**BPF_PROG_TYPE_FLOW_DISSECTOR** allows users to implement custom packet parsing logic in the kernel. This is used by the kernel networking stack (e.g., for flow hashing, ECMP routing) when it needs to dissect a packet protocol. It overrides the built-in C-based flow dissector.

## 2. Implementation Details

### 2.1 Constants
Update `src/clj_ebpf/constants.clj`:
- Program Type: `BPF_PROG_TYPE_FLOW_DISSECTOR`.
- Attach Type: `BPF_FLOW_DISSECTOR`.

### 2.2 Program Attachment (`src/clj_ebpf/programs.clj`)
- **Attachment Target**: Flow dissectors are attached to the network namespace (netns).
- Implement `attach-flow-dissector` using `BPF_PROG_ATTACH` (or `bpf_link_create` on newer kernels) targeting a netns file descriptor (usually `/proc/self/ns/net`).

### 2.3 Context Access
- The context is `struct __sk_buff`. Standard skb accessors work.
- Output is written to `struct bpf_flow_keys` (passed as a parameter or accessed/returned).

## 3. Testing Strategy

### 3.1 Unit Tests
- Create `test/clj_ebpf/programs/flow_dissector_test.clj`.

### 3.2 Integration Tests
- **Test Case 1**: Load a flow dissector that parses custom headers (e.g., GRE or a custom protocol).
- **Test Case 2**: Attach to current netns.
- **Test Case 3**: Send traffic and verify correct flow classification (difficult to assert directly without advanced setup, usually verified by checking if traffic isn't dropped or is routed correctly based on the custom hash). Alternatively, use `BPF_PROG_TEST_RUN` with `data_in` (packet) and check `data_out` (flow keys).

## 4. Examples
Create `examples/flow_dissector_custom.clj`:
```clojure
(ns examples.flow-dissector-custom
  (:require [clj-ebpf.core :as bpf]))

(def dissector-prog
  (dsl/assemble [...] :prog-type :flow-dissector))

(def loaded (bpf/load-program dissector-prog ...))

;; Attach to current network namespace
(bpf/attach-flow-dissector loaded "/proc/self/ns/net")
```

## 5. Tutorial Content
Add **Chapter 16: Custom Protocol Parsing** to `tutorials/part-3-advanced/README.md`.
- Use `BPF_PROG_TEST_RUN` to demonstrate the dissector extracting keys from a raw packet byte array.
