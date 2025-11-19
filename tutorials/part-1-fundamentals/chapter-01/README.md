# Chapter 1: Introduction to eBPF

**Duration**: 1-2 hours | **Difficulty**: Beginner

## Learning Objectives

By the end of this chapter, you will:
- Understand what eBPF is and why it matters
- Know the eBPF architecture and lifecycle
- Set up a development environment for clj-ebpf
- Write and run your first eBPF program
- Query system capabilities

## Prerequisites

- Basic Clojure knowledge
- Linux system (kernel 5.8+)
- Java 25+ installed (for Panama API support)
- Clojure CLI tools installed

## 1.1 What is eBPF?

### Brief History: From BPF to eBPF

**BPF (Berkeley Packet Filter)** was created in 1992 for efficient packet filtering. **eBPF (extended BPF)** emerged in 2014, transforming BPF from a packet filter into a general-purpose virtual machine that can run sandboxed programs in the Linux kernel.

### Why eBPF Matters

eBPF enables you to:
- **Observe** system behavior with minimal overhead
- **Secure** systems with dynamic policy enforcement
- **Network** with high-performance packet processing
- **Profile** applications without instrumentation

### eBPF vs Traditional Kernel Modules

| Aspect | eBPF | Kernel Modules |
|--------|------|----------------|
| Safety | Verified safe by kernel | Can crash kernel |
| Loading | Hot-loaded, no reboot | Often requires reboot |
| Portability | Runs across kernel versions | Recompile for each version |
| Performance | JIT-compiled to native code | Native code |
| Complexity | Limited instruction set | Full C capabilities |

### Safety and Verification

The eBPF verifier ensures programs:
- Terminate (no infinite loops)
- Don't access invalid memory
- Are of bounded complexity
- Only call approved helper functions

## 1.2 eBPF Architecture Overview

### eBPF Program Lifecycle

```
┌─────────────┐
│  Write BPF  │  1. Write program in clj-ebpf DSL
│   Program   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Assemble   │  2. Compile DSL to BPF instructions
│    to BPF   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Verify    │  3. Kernel verifies program safety
│   Program   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  JIT Compile│  4. JIT to native machine code
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Attach    │  5. Attach to hook point
│  to Hook    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Execute   │  6. Run on events
│  on Events  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Detach    │  7. Detach and unload
│  & Unload   │
└─────────────┘
```

### eBPF Maps

Maps are the primary way to:
- Share data between kernel and userspace
- Share data between multiple BPF programs
- Store state across invocations

### Program Types

- **Kprobes**: Dynamic kernel function tracing
- **Tracepoints**: Static kernel tracepoints
- **XDP**: Fast packet processing
- **TC**: Traffic control
- **Cgroups**: Container control
- **LSM**: Security hooks

## 1.3 The clj-ebpf DSL Philosophy

### Why Clojure for eBPF?

- **REPL-driven development**: Immediate feedback
- **Immutable data structures**: Safer programming
- **Lisp expressiveness**: DSL naturally fits
- **JVM ecosystem**: Rich tooling and libraries
- **Functional composition**: Build complex from simple

### DSL Design Principles

1. **Clojure-idiomatic**: Use keywords, maps, vectors
2. **Type-safe**: Compile-time checks where possible
3. **Composable**: Build complex programs from simple parts
4. **Transparent**: DSL maps directly to BPF instructions
5. **Practical**: Helper functions for common patterns

### Comparison with C-based BPF

**C + libbpf**:
```c
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_printk("execve called by PID %d\\n", pid_tgid >> 32);
    return 0;
}
```

**clj-ebpf**:
```clojure
(def trace-execve
  (bpf/assemble
    (vec (concat
      (bpf/helper-get-current-pid-tgid)
      (bpf/extract-tgid :r0 :r1)
      ;; Log PID (simplified - full version in lab)
      [(bpf/mov :r0 0)
       (bpf/exit-insn)]))))
```

## 1.4 Environment Setup

### Installing clj-ebpf

Add to `deps.edn`:
```clojure
{:deps {clj-ebpf {:local/root "/path/to/clj-ebpf"}}}
```

### Kernel Requirements

Check kernel version:
```bash
uname -r  # Should be 5.8 or higher
```

Required kernel config:
```bash
grep CONFIG_BPF /boot/config-$(uname -r)
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_DEBUG_INFO_BTF=y (for CO-RE)
```

### BPF Filesystem

Mount BPF filesystem:
```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

Or add to `/etc/fstab`:
```
bpf  /sys/fs/bpf  bpf  defaults  0  0
```

### Permissions

You need either:
- **CAP_BPF** capability (kernel 5.8+), or
- **CAP_SYS_ADMIN** (older kernels), or
- Run as root

Check capabilities:
```bash
sudo getcap $(which clojure)
```

Grant CAP_BPF (kernel 5.8+):
```bash
sudo setcap cap_bpf,cap_perfmon+eip $(which java)
```

## Labs

This chapter includes two hands-on labs:

### Lab 1.1: Hello eBPF
Your first eBPF program that loads and executes

### Lab 1.2: System Information
Query system capabilities and eBPF features

## Navigation

- **Next**: [Lab 1.1 - Hello eBPF](labs/lab-1-1-hello-ebpf.md)
- **Up**: [Part I - Fundamentals](../../part-1-fundamentals/)
- **Home**: [Tutorial Home](../../README.md)

## Additional Resources

- [Linux eBPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [eBPF.io](https://ebpf.io/)
- [Brendan Gregg's eBPF Resources](http://www.brendangregg.com/ebpf.html)
