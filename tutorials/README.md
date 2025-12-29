# Comprehensive eBPF Programming Tutorial with clj-ebpf

A complete, hands-on guide to mastering eBPF programming in Clojure, from fundamentals to production-ready applications.

## 🎯 Overview

This tutorial teaches you everything needed to build production-grade eBPF applications using the clj-ebpf DSL. Through 25 comprehensive chapters and 8 complete real-world applications, you'll learn:

- eBPF fundamentals and architecture
- All major program types (XDP, TC, LSM, kprobes, tracepoints, cgroups)
- Advanced topics (CO-RE portability, performance optimization)
- Production deployment, monitoring, and troubleshooting
- Best practices and design patterns

**Total**: 25 chapters | 75+ labs | 8 complete applications | 80-100 hours

## 📚 Tutorial Structure

### Part I: Fundamentals (Chapters 1-4)

Build a solid foundation in eBPF concepts and the clj-ebpf DSL.

**[Chapter 1: Introduction to eBPF](part-1-fundamentals/chapter-01/README.md)**
- What is eBPF and why it matters
- eBPF architecture and lifecycle
- The clj-ebpf DSL philosophy
- Environment setup and "Hello eBPF"

**[Chapter 2: BPF Maps - The Foundation](part-1-fundamentals/chapter-02/README.md)**
- Hash maps, array maps, and specialized types
- Map operations and lifecycle
- Labs: Process counter, packet histogram, stack trace collector

**[Chapter 3: The BPF Instruction Set and DSL](part-1-fundamentals/chapter-03/README.md)**
- BPF register model and calling conventions
- Arithmetic, logic, memory, and control flow
- The clj-ebpf instruction DSL
- Labs: Packet filter, syscall argument capture, protocol parser

**[Chapter 4: BPF Helper Functions](part-1-fundamentals/chapter-04/README.md)**
- Essential helpers for process info, time, maps
- Tracing and event output helpers
- Helper patterns in clj-ebpf
- Labs: Process tree monitor, file latency tracker, memory profiler

---

### Part II: Program Types and Attach Points (Chapters 5-9)

Master all major eBPF program types and learn when to use each.

**[Chapter 5: Kprobes and Kretprobes](part-2-program-types/chapter-01/README.md)**
- Dynamic kernel instrumentation
- Function arguments and return values
- Labs: Kernel function tracer, TCP connection tracker, mutex contention analyzer

**[Chapter 6: Tracepoints and Raw Tracepoints](part-2-program-types/chapter-02/README.md)**
- Static instrumentation points
- Syscall, scheduler, network, and block I/O tracepoints
- Labs: System call monitor, scheduler latency analyzer, block I/O monitor

**[Chapter 7: XDP (eXpress Data Path)](part-2-program-types/chapter-03/README.md)**
- Line-rate packet processing (15+ Mpps)
- Packet parsing and modification
- Labs: DDoS protection, Layer 4 load balancer, packet sampling

**[Chapter 8: TC (Traffic Control) and Networking](part-2-program-types/chapter-04/README.md)**
- TC ingress and egress programs
- Socket filters and SOCKMAP
- Labs: Bandwidth limiter, protocol filter, latency injection

**[Chapter 9: Cgroups and Resource Control](part-2-program-types/chapter-05/README.md)**
- Per-container/per-process control
- Socket and device access control
- Labs: Network policy enforcer, resource monitor, application sandboxing

---

### Part III: Advanced Topics (Chapters 10-14)

Deep dive into advanced eBPF features for production systems.

**[Chapter 10: CO-RE (Compile Once - Run Everywhere)](part-3-advanced/chapter-01/README.md)**
- Solving kernel version portability
- BTF (BPF Type Format)
- CO-RE relocations and helpers
- Labs: Portable process monitor, version-adaptive programs, structure inspector

**[Chapter 11: LSM (Linux Security Modules) BPF Hooks](part-3-advanced/chapter-02/README.md)**
- Security policy enforcement
- File, process, network, and IPC hooks
- Labs: File access control, execution guardian, connection firewall

**[Chapter 12: Performance Optimization](part-3-advanced/chapter-03/README.md)**
- Verifier limits and optimization techniques
- Per-CPU data structures and scalability
- Labs: High-performance packet counter, zero-copy events, adaptive sampling

**[Chapter 13: Event Processing and Ring Buffers](part-3-advanced/chapter-04/README.md)**
- Perf buffers vs ring buffers
- Event batching, filtering, and aggregation
- Labs: Real-time event processor, log aggregator, Prometheus exporter

**[Chapter 14: Testing and Debugging](part-3-advanced/chapter-05/README.md)**
- REPL-driven development
- Verifier errors and debugging techniques
- Testing strategies and common pitfalls
- Labs: Test framework, verifier error resolver, regression detector

---

### Part IV: Real-World Applications (Chapters 15-22)

Build 8 complete, production-ready eBPF applications.

**[Chapter 15: System Call Tracer](part-4-applications/chapter-15/README.md)** ⭐
Complete strace-like tool with <5% overhead
- Trace all syscalls for processes
- Capture arguments and return values
- Multiple output formats (text, JSON, CSV)
- **50K events/sec throughput**

**[Chapter 16: Network Traffic Analyzer](part-4-applications/chapter-16/README.md)** ⭐
Comprehensive network analysis with XDP
- Real-time packet capture and statistics
- Protocol distribution and flow tracking
- Anomaly detection (port scans, DDoS)
- **15 Mpps throughput, <500ns latency**

**[Chapter 17: Container Security Monitor](part-4-applications/chapter-17/README.md)** ⭐
Multi-layer security for containers
- LSM hooks for file and process control
- Cgroup network policy enforcement
- Threat detection (cryptominers, container escapes)
- **<1% overhead, 1M+ policy checks/sec**

**[Chapter 18: Performance Profiler](part-4-applications/chapter-18/README.md)** ⭐
System-wide and per-process profiling
- CPU sampling with flamegraph generation
- Memory allocation and leak tracking
- I/O latency histograms
- **99 Hz sampling, 1-2% overhead**

**[Chapter 19: Distributed Tracing](part-4-applications/chapter-19/README.md)** ⭐
Zero-instrumentation tracing across microservices
- Automatic HTTP/gRPC span creation
- Service dependency graphs
- Jaeger/Zipkin export
- **<1% overhead, <10μs latency added**

**[Chapter 20: Database Query Analyzer](part-4-applications/chapter-20/README.md)** ⭐
Database performance without touching the DB
- MySQL/PostgreSQL query capture
- N+1 detection and slow query analysis
- Automatic index recommendations
- **<0.5% overhead**

**[Chapter 21: Security Audit System](part-4-applications/chapter-21/README.md)** ⭐
Compliance and threat monitoring
- File integrity monitoring (FIM)
- Privileged command tracking
- Compliance rules (CIS, PCI-DSS, HIPAA, SOC 2)
- Forensic timeline generation
- **<2% overhead, tamper-proof logging**

**[Chapter 22: Chaos Engineering Platform](part-4-applications/chapter-22/README.md)** ⭐
Test system resilience with controlled faults
- Network fault injection (latency, packet loss)
- Resource exhaustion (CPU, memory, I/O)
- Blast radius control and SLO monitoring
- Automated rollback on violations
- **<1% overhead when inactive**

---

### Part V: Production and Best Practices (Chapters 23-25)

Deploy and operate eBPF applications in production environments.

**[Chapter 23: Production Deployment](part-5-production/chapter-01/README.md)**
- Canary and blue-green deployment strategies
- Monitoring, metrics, and alerting
- Resource management and security hardening
- Configuration management
- Lab: Complete BPF program lifecycle manager

**[Chapter 24: Troubleshooting Guide](part-5-production/chapter-02/README.md)**
- Common verifier rejections and solutions
- Map and helper function debugging
- Performance issue diagnosis
- Production incident patterns and runbooks
- Diagnostic tools (bpftool, trace_pipe)

**[Chapter 25: Advanced Patterns and Best Practices](part-5-production/chapter-03/README.md)**
- Design patterns (aggregation, sampling, state machines)
- Code organization and modularity
- Performance optimization patterns
- Security best practices
- Comprehensive testing strategies

---

## 🆕 New clj-ebpf Features

The clj-ebpf library includes several powerful features for development and testing:

### High-Level Declarative Macros (`clj-ebpf.macros`)

**[Quick Start: Declarative Macros](quick-start-macros.md)** - Learn to write BPF applications with 60% less code!

Three powerful macros reduce boilerplate and make BPF programming more Clojure-like:

```clojure
(require '[clj-ebpf.macros :refer [defmap-spec defprogram with-bpf-script]]
         '[clj-ebpf.dsl :as dsl])

;; Define a reusable map specification
(defmap-spec packet-counter
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 256)

;; Define a BPF program declaratively
(defprogram xdp-pass
  "Pass all packets through"
  :type :xdp
  :body [(dsl/mov :r0 2)      ; XDP_PASS
         (dsl/exit-insn)])

;; Automatic lifecycle management
(with-bpf-script
  {:maps   [counter packet-counter]
   :progs  [prog xdp-pass]
   :attach [{:prog prog :type :xdp :target "lo"}]}

  (println "XDP attached! FD:" (:fd prog))
  (Thread/sleep 5000))
;; Automatic cleanup: detach, unload, close
```

**Key Benefits:**
- `defmap-spec` - Define reusable map specifications with sensible defaults
- `defprogram` - Define programs with DSL body, automatic bytecode assembly
- `with-bpf-script` - Complete lifecycle management with automatic cleanup

See the [Macros Guide](../docs/guides/macros.md) for comprehensive documentation.

### Socket Redirection with SOCKMAP/SOCKHASH

**[Quick Start: Socket Redirection](quick-start-sockmap.md)** - Build high-performance TCP proxies with kernel-level socket splicing!

SOCKMAP and SOCKHASH enable zero-copy data transfer between sockets:

```clojure
(require '[clj-ebpf.maps :as maps]
         '[clj-ebpf.dsl.socket :as socket]
         '[clj-ebpf.programs :as progs])

;; Create socket map
(def sock-map (maps/create-sock-map 256 :map-name "proxy_sockets"))

;; Build SK_SKB verdict that redirects to another socket
(def verdict-bytecode
  (dsl/assemble
    (vec (concat
           (socket/sk-skb-prologue :r2 :r3)
           (socket/sk-redirect-map-with-fallback (:fd sock-map) 0)))))

;; Load and attach to map
(def verdict-prog (progs/load-program {:prog-type :sk-skb ...}))
(progs/attach-sk-skb verdict-prog sock-map :stream-verdict)

;; Add sockets - data now flows between them in kernel!
(maps/map-update sock-map 0 client-fd)
(maps/map-update sock-map 1 backend-fd)
```

**Use Cases:**
- High-performance TCP proxies (zero-copy)
- Service mesh sidecars
- Load balancers with connection splicing
- Application-transparent traffic redirection

**Key Components:**
- `create-sock-map` / `create-sock-hash` - Socket storage maps
- `sk-skb-prologue` / `sk-msg-prologue` - Program prologues
- `sk-redirect-map` / `msg-redirect-map` - Redirect helpers
- `attach-sk-skb` / `attach-sk-msg` - Program attachment

See the [Socket Redirection Guide](../docs/guides/sockmap-guide.md) for comprehensive documentation.

### AF_XDP Zero-Copy Networking with XSKMAP

**[Quick Start: AF_XDP with XSKMAP](quick-start-xskmap.md)** - Deliver packets directly to userspace with zero-copy!

XSKMAP enables high-performance packet processing by bypassing the kernel network stack:

```clojure
(require '[clj-ebpf.maps :as maps]
         '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.dsl.xdp :as xdp])

;; Create XSKMAP for AF_XDP sockets
(def xsk-map (maps/create-xsk-map 4 :map-name "xsks"))

;; XDP program redirects packets to XSK based on queue
(def xdp-bytecode
  (dsl/assemble
    (vec (concat
          [(dsl/mov-reg :r6 :r1)
           (dsl/ldx :w :r4 :r6 16)]  ; rx_queue_index
          (xdp/xdp-redirect-to-xsk (:fd xsk-map) :r4)))))

;; Attach XDP program
(bpf/attach-xdp prog "eth0" :mode :native)
```

**Use Cases:**
- Packet capture at line rate
- Custom protocol processing
- High-frequency trading systems
- Network functions (NFV)
- Ultra-low latency applications

**Key Components:**
- `create-xsk-map` - AF_XDP socket storage
- `xdp-redirect-to-xsk` - Redirect to XSK socket
- `xdp-redirect-to-xsk-by-queue` - Common redirect pattern
- `xdp-load-ctx-field :rx-queue-index` - Get queue for XSKMAP key

See the [XSKMAP Guide](../docs/guides/xskmap-guide.md) for comprehensive documentation.

### Programmable Socket Lookup with SK_LOOKUP

**[Quick Start: SK_LOOKUP](quick-start-sk-lookup.md)** - Implement custom socket dispatch and multi-tenant routing!

SK_LOOKUP programs intercept socket lookups and can select which socket handles connections:

```clojure
(require '[clj-ebpf.dsl.sk-lookup :as sk-lookup])

;; Build SK_LOOKUP program that filters by port
(def bytecode
  (dsl/assemble
    (vec (concat
          (sk-lookup/sk-lookup-prologue :r6)
          [(sk-lookup/sk-lookup-get-local-port :r6 :r7)]
          [(dsl/jmp-imm :jeq :r7 8080 2)]
          (sk-lookup/sk-lookup-drop)
          (sk-lookup/sk-lookup-pass)))))

;; Load and attach to network namespace
(def prog (progs/load-program
            {:prog-type :sk-lookup
             :insns bytecode
             :license "GPL"}))
(progs/attach-sk-lookup prog {})
```

**Key Components:**
- `sk-lookup-prologue` - Save context pointer
- `sk-lookup-get-local-port` - Load local port
- `sk-lookup-check-port` - Check port and branch
- `sk-assign` - Assign socket to handle connection

See the [SK_LOOKUP Guide](../docs/guides/sk-lookup-guide.md) for comprehensive documentation.

### Custom Packet Parsing with FLOW_DISSECTOR

**[Quick Start: FLOW_DISSECTOR](quick-start-flow-dissector.md)** - Implement custom packet parsing for RSS/ECMP flow hashing!

FLOW_DISSECTOR programs override the kernel's flow dissector for custom protocol handling:

```clojure
(require '[clj-ebpf.dsl.flow-dissector :as fd])

;; Build FLOW_DISSECTOR that parses IPv4/TCP 5-tuple
(def bytecode
  (dsl/assemble
    (vec (concat
          (fd/flow-dissector-prologue :r6 :r2 :r3)
          [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
          (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)
          (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)
          (fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)
          (fd/flow-dissector-ok)))))

;; Load and attach to network namespace
(def prog (progs/load-program
            {:prog-type :flow-dissector
             :insns bytecode
             :license "GPL"}))
(progs/attach-flow-dissector prog {})
```

**Use Cases:**
- Custom protocol handling (GRE, VXLAN, proprietary encapsulation)
- Protocol-specific flow hashing
- RSS optimization for custom traffic
- Debugging packet classification

**Key Components:**
- `flow-dissector-prologue` - Setup context and data pointers
- `flow-dissector-parse-ethernet` - Parse Ethernet header
- `flow-dissector-parse-ipv4` - Parse IPv4 header and addresses
- `flow-dissector-parse-tcp-ports` - Parse TCP/UDP ports
- `flow-keys-set-*` - Set individual flow_keys fields

See the [FLOW_DISSECTOR Guide](../docs/guides/flow-dissector-guide.md) for comprehensive documentation.

### Multi-Architecture Support (`clj-ebpf.arch`)

Automatic detection and platform-specific constants for x86_64, ARM64, s390x, PPC64LE, and RISC-V:

```clojure
(require '[clj-ebpf.arch :as arch])

arch/current-arch      ; => :x86_64
arch/arch-name         ; => "x86-64 (AMD64)"
(arch/get-syscall-nr :bpf)  ; => 321 (platform-specific)
```

### Structured Error Handling (`clj-ebpf.errors`)

Rich error types with automatic retry and diagnostics:

```clojure
(require '[clj-ebpf.errors :as errors])

;; Error classification
(errors/verifier-error? e)    ; Verifier rejection
(errors/permission-error? e)  ; Permission issues
(errors/transient-error? e)   ; Retriable errors

;; Automatic retry on transient errors
(errors/with-retry {:max-retries 3}
  (potentially-flaky-operation))

;; Formatted error output
(errors/format-error e)       ; Multi-line diagnostic
```

### Mock Syscall Layer (`clj-ebpf.mock`)

Test BPF logic without CAP_BPF privileges:

```clojure
(require '[clj-ebpf.mock :as mock])

(mock/with-mock-bpf
  ;; All BPF operations use in-memory simulation
  (let [m (maps/create-map :hash 100 4 8)]
    (maps/map-update m key val)
    (maps/map-lookup m key)))

;; Inject failures for testing error handling
(mock/with-mock-failure :map-lookup {:errno :eagain})
```

### Test Utilities (`clj-ebpf.test-utils`)

Fixtures, data generators, and assertions for testing:

```clojure
(require '[clj-ebpf.test-utils :as tu])

;; Check capabilities
(tu/has-bpf-capabilities?)

;; Test fixtures
(use-fixtures :each tu/mock-fixture)

;; Data generators
(tu/make-key 42)              ; Byte array key
(tu/make-value 100)           ; Byte array value
(tu/build-test-packet :protocol :tcp)  ; Network packet

;; Assertions
(tu/assert-bytes-equal expected actual)
(tu/assert-throws-errno :eperm ...)

;; Performance benchmarking
(tu/benchmark-op 1000 my-operation)
```

### DSL Submodules

Focused imports for cleaner code:

```clojure
;; Instead of everything from core:
(:require [clj-ebpf.core :as bpf])

;; Import specific DSL modules:
(:require [clj-ebpf.dsl.core :as dsl]       ; Unified DSL
          [clj-ebpf.dsl.alu :as alu]        ; ALU operations
          [clj-ebpf.dsl.mem :as mem]        ; Memory operations
          [clj-ebpf.dsl.jump :as jmp]       ; Jump/control flow
          [clj-ebpf.dsl.atomic :as atomic]) ; Atomic operations
```

### Atomic Operations (`clj-ebpf.dsl.atomic`)

Comprehensive atomic memory operations for concurrent BPF programs:

```clojure
(require '[clj-ebpf.dsl.atomic :as atomic])

;; Basic atomic operations
(atomic/atomic-add :dw :r10 :r1 -8)     ; [r10 - 8] += r1
(atomic/atomic-xchg :dw :r10 :r1 -8)    ; Exchange
(atomic/atomic-cmpxchg :dw :r10 :r1 -8) ; Compare-exchange

;; Fetch variants (return old value)
(atomic/atomic-fetch-add :dw :r10 :r1 -8)

;; High-level patterns
(atomic/atomic-inc :dw :r10 :r1 -8)     ; Increment
(atomic/atomic-set-bit :dw :r10 :r1 3 -8) ; Set bit 3

;; Check kernel support
(atomic/atomic-available? :fetch-add "5.12")
```

### Backpressure Consumer (`clj-ebpf.events`)

Flow control for high-throughput event processing:

```clojure
(require '[clj-ebpf.events :as events])

(events/with-backpressure-consumer
  [consumer {:map ringbuf-map
             :queue-size 10000
             :handler process-fn}]

  ;; Monitor health
  (events/get-backpressure-stats consumer)
  (events/backpressure-healthy? consumer))
```

### Property-Based Testing

Generators and properties for comprehensive testing:

```clojure
;; In test/clj_ebpf/generators.clj
;; Generate valid BPF instructions, map configs, etc.

;; In test/clj_ebpf/properties.clj
;; Property-based tests for map operations
```

---

## 🚀 Getting Started

### Prerequisites

- **Clojure**: Basic knowledge required
- **Linux**: Ubuntu 20.04+ or similar (kernel 5.8+)
- **Systems**: Understanding of processes, networking, syscalls

### Installation

```bash
# Check kernel version (need 5.8+)
uname -r

# Install dependencies
sudo apt-get install clang llvm libelf-dev

# Clone repository
git clone https://github.com/yourorg/clj-ebpf
cd clj-ebpf

# Install clj-ebpf
clj -M:install

# Verify BPF support
sudo clj -M:check-bpf
```

### Run Your First Program

```clojure
;; hello.clj - Your first eBPF program
(require '[clj-ebpf.core :as bpf])

(def hello-program
  {:type :tracepoint
   :category "syscalls"
   :name "sys_enter_execve"
   :program
   [(bpf/mov :r0 0)
    (bpf/exit)]})

;; Load and attach
(with-open [prog (bpf/load-program hello-program)]
  (bpf/attach-tracepoint prog "syscalls" "sys_enter_execve")
  (println "Program attached! Press Ctrl+C to stop")
  @(promise))
```

Run it:
```bash
sudo clj hello.clj
```

---

## 📊 Progress Tracking

Track your progress through the tutorial:

- [ ] Part I: Fundamentals (4 chapters)
  - [ ] Chapter 1: Introduction to eBPF
  - [ ] Chapter 2: BPF Maps
  - [ ] Chapter 3: BPF Instructions
  - [ ] Chapter 4: Helper Functions

- [ ] Part II: Program Types (5 chapters)
  - [ ] Chapter 5: Kprobes
  - [ ] Chapter 6: Tracepoints
  - [ ] Chapter 7: XDP
  - [ ] Chapter 8: TC
  - [ ] Chapter 9: Cgroups

- [ ] Part III: Advanced Topics (5 chapters)
  - [ ] Chapter 10: CO-RE
  - [ ] Chapter 11: LSM
  - [ ] Chapter 12: Performance
  - [ ] Chapter 13: Event Processing
  - [ ] Chapter 14: Testing & Debugging

- [ ] Part IV: Applications (8 chapters)
  - [ ] Chapter 15: System Call Tracer
  - [ ] Chapter 16: Network Analyzer
  - [ ] Chapter 17: Container Security
  - [ ] Chapter 18: Performance Profiler
  - [ ] Chapter 19: Distributed Tracing
  - [ ] Chapter 20: Database Analyzer
  - [ ] Chapter 21: Security Audit
  - [ ] Chapter 22: Chaos Engineering

- [ ] Part V: Production (3 chapters)
  - [ ] Chapter 23: Deployment
  - [ ] Chapter 24: Troubleshooting
  - [ ] Chapter 25: Best Practices

---

## 🎓 Learning Path

### Beginner Path (Weeks 1-4)
Start here if you're new to eBPF:
1. Complete Part I (Fundamentals)
2. Complete Part II (Program Types)
3. Build Chapter 15 (System Call Tracer)
4. Build Chapter 16 (Network Analyzer)

### Intermediate Path (Weeks 5-8)
For those with basic eBPF knowledge:
1. Review Part II as needed
2. Complete Part III (Advanced Topics)
3. Build 4 applications from Part IV
4. Study Chapter 23 (Deployment)

### Advanced Path (Weeks 9-12)
For production deployments:
1. Build all 8 applications from Part IV
2. Complete Part V (Production)
3. Deploy to production environment
4. Build your own custom application

---

## 💡 Key Concepts Quick Reference

### When to Use Each Program Type

| Use Case | Program Type | Chapter |
|----------|-------------|---------|
| Trace kernel functions | Kprobes | 5 |
| Trace syscalls | Tracepoints | 6 |
| High-speed packet processing | XDP | 7 |
| Packet modification/routing | TC | 8 |
| Per-container policy | Cgroups | 9 |
| Security enforcement | LSM | 11 |

### Performance Characteristics

| Application | Overhead | Throughput | Latency |
|-------------|----------|------------|---------|
| System Call Tracer | <5% | 50K events/sec | - |
| Network Analyzer | <1% | 15 Mpps | <500ns |
| Container Security | <1% | 1M checks/sec | - |
| Performance Profiler | 1-2% | 99 Hz | - |
| Distributed Tracing | <1% | - | +10μs |
| Database Analyzer | <0.5% | - | - |
| Security Audit | <2% | - | - |
| Chaos Engineering | <1% | - | - |

---

## 🛠️ Common Issues

### Issue: Verifier Rejection

```
Error: back-edge from insn 45 to 23
```

**Solution**: See [Chapter 24 - Troubleshooting](part-5-production/chapter-02/README.md#pattern-1-unbounded-loops)

### Issue: Program Not Triggering

**Checklist**:
1. Is program loaded? `sudo bpftool prog list`
2. Is attach point correct?
3. Are events actually occurring?
4. Check filters (PID, UID, etc.)

See [Chapter 24 - Production Incidents](part-5-production/chapter-02/README.md#incident-events-not-reaching-userspace)

### Issue: High CPU Overhead

**Solutions**:
1. Add early exit filters (Chapter 25)
2. Use sampling instead of full tracing (Chapter 12)
3. Aggregate in kernel (Chapter 25)

See [Chapter 12 - Performance Optimization](part-3-advanced/chapter-03/README.md)

---

## 📖 Additional Resources

### clj-ebpf Documentation
- [Architecture Decision Records](../docs/adr/README.md) - Design decisions and rationale
- [API Documentation](../docs/guides/intro.md) - Generated with codox (`clj -X:codox`)

### eBPF Documentation
- [eBPF.io Official Docs](https://ebpf.io)
- [Cilium BPF Reference](https://docs.cilium.io/en/stable/bpf/)
- [Linux Kernel BPF Docs](https://www.kernel.org/doc/html/latest/bpf/)

### Tools
- **bpftool**: Inspection and debugging
- **bpftrace**: High-level tracing language
- **kubectl-trace**: Kubernetes BPF tracing

### Books
- "BPF Performance Tools" by Brendan Gregg
- "Linux Observability with BPF" by David Calavera
- "Learning eBPF" by Liz Rice

### Community
- [eBPF Slack](https://ebpf.io/slack)
- [BPF Mailing List](https://lore.kernel.org/bpf/)
- [r/eBPF Reddit](https://reddit.com/r/ebpf)

---

## 🤝 Contributing

Found an issue or want to improve the tutorial?

1. **Report Issues**: [GitHub Issues](https://github.com/yourorg/clj-ebpf/issues)
2. **Suggest Improvements**: Open a discussion
3. **Submit PRs**: We welcome contributions!

---

## 📝 License

This tutorial is licensed under [MIT License](../LICENSE).

---

## 🎉 What's Next?

After completing this tutorial:

1. **Build Your Own App** - Apply what you learned to solve real problems
2. **Contribute to clj-ebpf** - Help improve the library
3. **Share Your Knowledge** - Write blog posts, give talks
4. **Explore Kernel Internals** - Deep dive into verifier, JIT compiler
5. **Join the Community** - Help others learn eBPF

---

**Ready to begin?** Start with [Chapter 1: Introduction to eBPF](part-1-fundamentals/chapter-01/README.md)!

**Questions?** Check the [Troubleshooting Guide](part-5-production/chapter-02/README.md) or open an issue.

**Happy BPF Programming!** 🚀
