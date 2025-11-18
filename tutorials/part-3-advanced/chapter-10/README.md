# Chapter 10: CO-RE (Compile Once - Run Everywhere)

## Introduction

CO-RE (Compile Once - Run Everywhere) is a groundbreaking eBPF feature that solves the kernel portability problem. It allows BPF programs to work across different kernel versions without recompilation, making BPF applications truly portable.

## The Portability Problem

### Traditional Challenges

Before CO-RE, BPF programs faced severe portability issues:

```c
// Pre-CO-RE: Hard-coded offsets
struct task_struct *task = (void *)PT_REGS_PARM1(ctx);
int pid = *(int *)(task + 1234);  // Offset 1234 for kernel 5.4
                                   // But offset 1240 for kernel 5.10!
```

**Problems**:
1. **Kernel Structure Changes**: Field offsets change between kernel versions
2. **Architecture Differences**: Offsets differ between x86_64 and ARM64
3. **Config Variations**: Kernel config options affect structure layout
4. **Maintenance Nightmare**: Need separate binaries for each kernel version

### Example: task_struct Changes

The `task_struct` structure has evolved significantly:

| Kernel Version | pid Offset | comm Offset | Changes |
|----------------|------------|-------------|---------|
| 4.19 | 1120 | 1400 | Baseline |
| 5.4 | 1176 | 1472 | New fields added |
| 5.10 | 1184 | 1488 | Reordering |
| 5.15 | 1192 | 1504 | More fields |
| 6.0 | 1200 | 1520 | Continued evolution |

**Without CO-RE**: You need 5 different compiled programs.
**With CO-RE**: One program works on all versions.

## BTF (BPF Type Format)

BTF is the foundation that enables CO-RE.

### What is BTF?

BTF is a compact format for encoding type information about kernel structures, similar to DWARF debug info but optimized for BPF:

```
BTF Type Information:
├─ Structure Definitions
│  ├─ task_struct
│  │  ├─ Field: pid (offset: X, type: int)
│  │  ├─ Field: comm (offset: Y, type: char[16])
│  │  └─ Field: cred (offset: Z, type: struct cred*)
│  └─ ...
├─ Enum Definitions
├─ Function Signatures
└─ Type Relationships
```

### BTF Components

**1. vmlinux BTF**: Describes all kernel types
```bash
# Check if BTF is available
ls -lh /sys/kernel/btf/vmlinux
# -r--r--r-- 1 root root 5.2M Jan 1 12:00 /sys/kernel/btf/vmlinux
```

**2. Module BTF**: Type info for kernel modules
```bash
ls /sys/kernel/btf/ | head
vmlinux
nf_conntrack
ip_tables
xt_conntrack
...
```

**3. BPF Program BTF**: Type info embedded in BPF programs

### Checking BTF Support

```bash
# Method 1: Check for BTF file
[ -f /sys/kernel/btf/vmlinux ] && echo "BTF supported" || echo "No BTF"

# Method 2: Check kernel config
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
# CONFIG_DEBUG_INFO_BTF=y

# Method 3: Check bpftool
bpftool btf dump file /sys/kernel/btf/vmlinux format c | head
```

## CO-RE Concepts

### Core Relocations

CO-RE uses **relocations** to adjust field accesses at load time:

```
Compile Time:                    Load Time:
┌─────────────────┐             ┌──────────────────┐
│ BPF Program     │             │ Kernel BTF       │
│                 │             │                  │
│ field_offset    │             │ task_struct:     │
│   (placeholder) │─────────────▶│   pid = 1200    │
│                 │             │   comm = 1520   │
└─────────────────┘             └──────────────────┘
                                         │
                                         ▼
                                ┌──────────────────┐
                                │ Relocated Program│
                                │ field_offset=1200│
                                └──────────────────┘
```

### Relocation Types

CO-RE supports several relocation types:

#### 1. Field Offset Relocations
```clojure
;; Access task->pid
(bpf/core-field-offset "task_struct" "pid")
;; Resolves to actual offset at load time
```

#### 2. Field Existence Checks
```clojure
;; Check if field exists in this kernel version
(bpf/core-field-exists "task_struct" "new_field")
;; Returns 1 if exists, 0 otherwise
```

#### 3. Field Size Relocations
```clojure
;; Get size of field
(bpf/core-field-size "task_struct" "pid")
;; Returns actual size (4 bytes for int)
```

#### 4. Type Size Relocations
```clojure
;; Get size of entire structure
(bpf/core-type-size "task_struct")
;; Returns structure size on this kernel
```

#### 5. Type Existence Checks
```clojure
;; Check if type exists
(bpf/core-type-exists "new_struct")
;; Returns 1 if defined, 0 otherwise
```

#### 6. Enum Value Relocations
```clojure
;; Get enum value
(bpf/core-enum-value "task_state" "TASK_RUNNING")
;; Returns actual enum value
```

## CO-RE in Practice

### Traditional vs CO-RE Approach

**Traditional (Fragile)**:
```clojure
;; Hard-coded offset - breaks on different kernels
(def task-struct-pid-offset 1200)

(def read-pid-traditional
  [(bpf/mov-reg :r1 :r6)]              ; r6 = task_struct*
  [(bpf/add :r1 task-struct-pid-offset)] ; Add hard-coded offset
  [(bpf/load-mem :w :r2 :r1 0)])       ; Load PID
```

**CO-RE (Portable)**:
```clojure
;; Relocation placeholder - resolved at load time
(def read-pid-core
  [(bpf/mov-reg :r1 :r6)]                      ; r6 = task_struct*
  [(bpf/core-field-offset :r2 "task_struct" "pid")]  ; Get offset
  [(bpf/add-reg :r1 :r2)]                      ; Add actual offset
  [(bpf/load-mem :w :r2 :r1 0)])               ; Load PID
```

### Adaptive Programs

CO-RE enables programs that adapt to kernel capabilities:

```clojure
(def adaptive-monitor
  [;; Check if new field exists (kernel 5.15+)
   (bpf/core-field-exists :r0 "task_struct" "sched_statistics")
   (bpf/jmp-imm :jeq :r0 0 :use-old-field)

   ;; Modern kernel path: use new field
   [:use-new-field]
   (bpf/core-field-offset :r1 "task_struct" "sched_statistics")
   ;; ... access new statistics ...
   (bpf/jmp :done)

   ;; Legacy kernel path: use old field
   [:use-old-field]
   (bpf/core-field-offset :r1 "task_struct" "old_statistics")
   ;; ... access old statistics ...

   [:done]])
```

## clj-ebpf CO-RE Helpers

### Basic CO-RE Functions

```clojure
(ns example.core-demo
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.btf :as btf]))

;; Check BTF availability
(btf/btf-available?)
;; => true

;; Get structure definition
(btf/get-struct-info "task_struct")
;; => {:size 9344
;;     :fields [{:name "pid" :offset 1200 :type :int}
;;              {:name "comm" :offset 1520 :type [:array :char 16]}
;;              ...]}

;; Get field offset
(btf/get-field-offset "task_struct" "pid")
;; => 1200

;; Check field existence
(btf/field-exists? "task_struct" "new_field")
;; => false
```

### CO-RE Assembly Helpers

```clojure
;; Field offset relocation
(bpf/core-field-offset reg struct-name field-name)
;; Generates relocation instruction

;; Field exists check
(bpf/core-field-exists reg struct-name field-name)
;; Generates existence check

;; Type size
(bpf/core-type-size reg type-name)
;; Gets structure size

;; Field size
(bpf/core-field-size reg struct-name field-name)
;; Gets field size
```

### High-Level Patterns

```clojure
;; Safe structure field read
(defn core-read-field
  "Read field from structure with CO-RE"
  [struct-ptr struct-type field-name dest-reg]
  [(bpf/mov-reg :r1 struct-ptr)]
   (bpf/core-field-offset :r2 struct-type field-name)
   [(bpf/add-reg :r1 :r2)]
   [(bpf/load-mem :dw dest-reg :r1 0)]))

;; Usage
(core-read-field :r6 "task_struct" "pid" :r7)
;; r6 = task_struct pointer
;; r7 = PID (after execution)
```

## Kernel Version Compatibility

### Version Detection

```clojure
(defn get-kernel-version []
  (let [version (bpf/get-kernel-version)]
    {:major (bit-shift-right version 16)
     :minor (bit-and (bit-shift-right version 8) 0xFF)
     :patch (bit-and version 0xFF)}))

(get-kernel-version)
;; => {:major 5, :minor 15, :patch 0}
```

### Conditional Compilation

```clojure
(defn create-version-adaptive-prog []
  (let [kernel-ver (get-kernel-version)]
    (if (>= (:minor kernel-ver) 15)
      ;; Use modern features for 5.15+
      (create-modern-program)
      ;; Use legacy approach for older kernels
      (create-legacy-program))))
```

### Feature Detection

```clojure
(defn detect-kernel-features []
  {:btf-available (btf/btf-available?)
   :has-ringbuf (btf/type-exists? "bpf_ringbuf")
   :has-new-helper (bpf/helper-available? :ringbuf_output)
   :task-sched-stats (btf/field-exists? "task_struct" "sched_statistics")})
```

## CO-RE Limitations

### What CO-RE Cannot Do

1. **Function Signature Changes**: CO-RE doesn't help if function arguments change
2. **Semantic Changes**: Field meaning changes aren't captured
3. **Removed Fields**: Can detect absence but must handle gracefully
4. **Macro Values**: #define constants aren't in BTF (use __builtin_preserve_enum_value)

### Workarounds

```clojure
;; Handle removed fields
(def robust-field-read
  [(bpf/core-field-exists :r0 "task_struct" "potentially_removed_field")
   (bpf/jmp-imm :jeq :r0 0 :field-missing)

   ;; Field exists - read it
   (bpf/core-field-offset :r1 "task_struct" "potentially_removed_field")
   ;; ... use field ...
   (bpf/jmp :done)

   [:field-missing]
   ;; Field doesn't exist - use default or alternative
   [(bpf/mov :r1 0)]  ; Default value

   [:done]])
```

## Performance Considerations

### Relocation Overhead

- **Compile Time**: Slight increase due to relocation metadata
- **Load Time**: One-time overhead for relocation resolution (~1-10ms)
- **Runtime**: **ZERO** overhead - offsets resolved at load time

### Best Practices

1. **Use CO-RE for Structure Access**: Always use CO-RE for kernel structures
2. **Cache Offsets**: For repeated access, calculate offset once
3. **Minimize Relocations**: Group field accesses when possible
4. **Test Across Versions**: Validate on multiple kernel versions

## Debugging CO-RE Programs

### Common Issues

**Issue 1: BTF Not Available**
```bash
# Error: BTF is not found
# Solution: Check kernel BTF support
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
# Rebuild kernel with BTF if needed
```

**Issue 2: Relocation Failure**
```bash
# Error: libbpf: failed to find BTF for extern 'task_struct'
# Solution: Verify structure name spelling and BTF availability
bpftool btf dump file /sys/kernel/btf/vmlinux | grep "STRUCT 'task_struct'"
```

**Issue 3: Field Not Found**
```bash
# Error: CO-RE relocation failed: field not found
# Solution: Check field existence first or handle missing field
```

### Debugging Tools

```bash
# Dump BTF information
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Check program BTF
bpftool prog dump xlated id <prog-id> linum

# Inspect relocations
bpftool gen object output.o input.o

# Debug relocation issues
export LIBBPF_LOG_LEVEL=debug
```

## Real-World Use Cases

### Use Case 1: Universal Process Monitor
Single binary that works on all kernel versions 4.19+:
```clojure
;; Monitors processes across kernel versions
;; Adapts to available fields
;; Falls back gracefully on older kernels
```

### Use Case 2: Cloud Provider Tools
BPF tools that work across different cloud providers:
- AWS (custom kernels)
- GCP (container-optimized OS)
- Azure (various distros)
- On-premise (diverse kernel versions)

### Use Case 3: Distribution Packaging
Single .deb/.rpm package for all supported kernels:
```bash
# One package works on:
# - Ubuntu 20.04 (kernel 5.4)
# - Ubuntu 22.04 (kernel 5.15)
# - Ubuntu 24.04 (kernel 6.2)
```

## Migration Guide

### Converting Legacy Programs to CO-RE

**Step 1: Identify Hard-Coded Offsets**
```clojure
;; Before: Hard-coded
(def TASK_PID_OFFSET 1200)
[(bpf/add :r1 TASK_PID_OFFSET)]
```

**Step 2: Replace with CO-RE**
```clojure
;; After: CO-RE
(bpf/core-field-offset :r2 "task_struct" "pid")
[(bpf/add-reg :r1 :r2)]
```

**Step 3: Add Existence Checks for New Fields**
```clojure
;; Check before using newer fields
(bpf/core-field-exists :r0 "task_struct" "new_field")
[(bpf/jmp-imm :jeq :r0 0 :skip-new-field)]
```

**Step 4: Test Across Kernels**
```bash
# Test on multiple kernel versions
for version in 5.4 5.10 5.15 6.0; do
    run-in-container kernel-$version test-program
done
```

## Future of CO-RE

### Ongoing Developments

1. **Extended Relocations**: More relocation types
2. **User-Space Structure Support**: BTF for user programs
3. **Better Error Messages**: Improved diagnostics
4. **IDE Integration**: Editor support for CO-RE development

### Community Resources

- [Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf CO-RE Guide](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [BTF Specification](https://www.kernel.org/doc/html/latest/bpf/btf.html)

## Summary

CO-RE is revolutionary for BPF portability:

✅ **Compile Once, Run Everywhere** - Single binary for all kernels
✅ **Zero Runtime Overhead** - Relocations resolved at load time
✅ **Type Safety** - Leverages BTF for validation
✅ **Forward Compatible** - Graceful degradation on older kernels
✅ **Development Friendly** - Simplified maintenance and distribution

**Key Takeaway**: Always use CO-RE for production BPF programs. The portability benefits far outweigh the minimal additional complexity.

## Next Steps

The following labs demonstrate practical CO-RE usage:

1. **Lab 10.1: Portable Process Monitor** - Read task_struct fields portably
2. **Lab 10.2: Kernel Version Adaptive Program** - Branch on field availability
3. **Lab 10.3: Structure Field Inspector** - Dynamic BTF exploration tool

These labs will solidify your understanding of CO-RE and prepare you for building truly portable BPF applications.
