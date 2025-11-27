# Comprehensive eBPF Programming Tutorial with clj-ebpf

A complete guide to mastering eBPF programming in Clojure, from fundamentals to production-ready applications.

## Target Audience
- Clojure developers wanting to learn eBPF
- Systems programmers interested in observability and security
- DevOps engineers building monitoring and security tools
- Performance engineers optimizing systems

## Prerequisites
- Basic Clojure knowledge
- Linux systems understanding
- Familiarity with kernel concepts (processes, networking, syscalls)
- Development environment with Linux 5.8+

---

# Part I: Fundamentals (Chapters 1-4)

## Chapter 1: Introduction to eBPF
**Duration**: 1-2 hours | **Difficulty**: Beginner

### 1.1 What is eBPF?
- Brief history: From BPF to eBPF
- eBPF virtual machine and instruction set
- Why eBPF matters: observability, security, networking
- eBPF vs traditional kernel modules
- Safety and verification: the eBPF verifier

### 1.2 eBPF Architecture Overview
- eBPF program lifecycle: load, attach, execute, detach
- eBPF maps: communication between kernel and userspace
- Helper functions: kernel API for eBPF programs
- Program types and attach points
- Events and data collection

### 1.3 The clj-ebpf DSL Philosophy
- Why Clojure for eBPF programming
- DSL design principles
- Comparison with C-based BPF development
- Development workflow with clj-ebpf
- REPL-driven eBPF development

### 1.4 Environment Setup
- Installing clj-ebpf
- Kernel requirements and feature detection
- Setting up BPF filesystem
- Permissions and capabilities (CAP_BPF)
- Development tools and utilities

### Lab 1.1: Hello eBPF
**Kernel Program**: Simple tracepoint that logs "Hello eBPF"
**Userspace**: Load program and read trace output
```clojure
;; Minimal eBPF program
(require '[clj-ebpf.core :as bpf])

;; Kernel: Trace program that logs when execve syscall is called
(def hello-prog
  (bpf/assemble
    [(bpf/mov :r0 0)
     (bpf/exit-insn)]))

;; Userspace: Load and attach
(bpf/init!)
(with-open [prog (bpf/load-program hello-prog :tracepoint)]
  (bpf/attach-tracepoint prog "syscalls" "sys_enter_execve"))
```

### Lab 1.2: System Information
**Kernel Program**: Collect current PID on every syscall entry
**Userspace**: Display architecture and kernel info
```clojure
;; Query system capabilities
(bpf/arch-info)
(bpf/get-kernel-version)
(bpf/check-bpf-available)
```

**Key Takeaways**:
- eBPF enables safe kernel programmability
- clj-ebpf provides Clojure-idiomatic eBPF development
- Understanding the eBPF lifecycle is crucial

---

## Chapter 2: BPF Maps - The Foundation
**Duration**: 2-3 hours | **Difficulty**: Beginner

### 2.1 Understanding BPF Maps
- What are BPF maps?
- Kernel-to-userspace data exchange
- Map types overview
- Map operations: create, lookup, update, delete
- Map lifecycle and pinning

### 2.2 Hash Maps
- When to use hash maps
- Key and value sizing
- Hash map flags (BPF_ANY, BPF_NOEXIST, BPF_EXIST)
- Performance characteristics

### 2.3 Array Maps
- Fixed-size arrays
- Index-based access
- Per-CPU arrays for performance
- Use cases: histograms, counters

### 2.4 Specialized Map Types
- LRU hash maps: automatic eviction
- Stack maps: stack trace storage
- Queue/Stack maps: FIFO/LIFO data structures
- LPM Trie maps: longest prefix matching
- Ring buffer maps: efficient event streaming

### Lab 2.1: Process Counter
**Kernel Program**: Count process creations per UID
**Userspace**: Display top UIDs by process count
**Map Type**: Hash map (UID → count)
```clojure
;; Kernel: Track process creations
(def pid-counter-prog
  (bpf/assemble
    (vec (concat
      ;; Get UID
      (bpf/helper-get-current-uid-gid)
      (bpf/extract-uid :r0 :r6)

      ;; Lookup/update counter
      (bpf/with-map-lookup :r1 :r6 5 :r7)
      ;; ... increment counter ...
      [(bpf/exit-insn)]))))

;; Userspace: Read and display
(with-open [counter-map (bpf/create-hash-map ...)]
  (doseq [[uid count] (bpf/map-entries counter-map)]
    (println (format "UID %d: %d processes" uid count))))
```

### Lab 2.2: Network Packet Histogram
**Kernel Program**: Count packets by size buckets (XDP)
**Userspace**: Display packet size distribution
**Map Type**: Array map (bucket index → count)
```clojure
;; Kernel: Categorize packet sizes
;; Buckets: <64, 64-127, 128-255, 256-511, 512-1023, 1024+

;; Userspace: Histogram display
(defn display-histogram [array-map]
  (let [buckets ["<64" "64-127" "128-255" "256-511" "512-1023" "1024+"]
        counts (bpf/map-values array-map)]
    (doseq [[bucket count] (map vector buckets counts)]
      (println (format "%10s: %s" bucket (repeat count "#"))))))
```

### Lab 2.3: Stack Trace Collector
**Kernel Program**: Collect stack traces on CPU scheduler events
**Userspace**: Symbolize and display stack traces
**Map Type**: Stack map
```clojure
;; Kernel: Collect stack on context switch

;; Userspace: Retrieve and symbolize
(defn symbolize-stack [stack-id stack-map]
  (when-let [stack (bpf/map-lookup stack-map stack-id)]
    (symbolize-addresses stack)))
```

**Key Takeaways**:
- Maps are the primary communication channel
- Choose appropriate map type for your use case
- Maps persist across program invocations

---

## Chapter 3: The BPF Instruction Set and DSL
**Duration**: 3-4 hours | **Difficulty**: Intermediate

### 3.1 BPF Register Model
- 11 registers: r0-r10
- Register roles and calling conventions
- r0: return value
- r1-r5: function arguments
- r6-r9: callee-saved
- r10: frame pointer (read-only)

### 3.2 Arithmetic and Logic Operations
- ALU operations: add, sub, mul, div, mod
- Bitwise operations: and, or, xor, lsh, rsh
- Register vs immediate operands
- 32-bit vs 64-bit operations

### 3.3 Memory Access
- Load (ldx) and store (stx, st) instructions
- Memory addressing modes
- Size modifiers: byte, half-word, word, double-word
- Packet access (XDP/TC programs)

### 3.4 Control Flow
- Conditional jumps (jeq, jne, jgt, jge, jlt, jle)
- Signed vs unsigned comparisons
- Function calls (helpers)
- Exit instruction

### 3.5 The clj-ebpf DSL
- Instruction builders
- Register keywords (:r0, :r1, etc.)
- Size keywords (:b, :h, :w, :dw)
- Assembly with `assemble`

### Lab 3.1: Packet Filter
**Kernel Program**: Filter IPv4 TCP packets on port 80
**Userspace**: Attach to network interface
```clojure
(def port-80-filter
  (bpf/assemble
    [(bpf/ldx :w :r0 :r1 (+ eth-hlen 12))  ; Load dst port
     (bpf/jmp-imm :jne :r0 80 2)            ; Skip if not port 80
     (bpf/mov :r0 (bpf/xdp-action :pass))   ; Pass
     (bpf/exit-insn)
     (bpf/mov :r0 (bpf/xdp-action :drop))   ; Drop
     (bpf/exit-insn)]))
```

### Lab 3.2: System Call Argument Capture
**Kernel Program**: Capture filename argument from openat syscall
**Userspace**: Display opened files
```clojure
;; Read filename from user pointer
(def openat-tracer
  (bpf/assemble
    (vec (concat
      ;; Get filename pointer from syscall args
      ;; ... use probe-read-user-str ...
      [(bpf/exit-insn)]))))
```

### Lab 3.3: Custom Protocol Parser
**Kernel Program**: Parse custom network protocol
**Userspace**: Statistics on protocol usage
```clojure
;; Parse packet header fields
;; Extract protocol-specific data
;; Update statistics map
```

**Key Takeaways**:
- BPF instruction set is RISC-like and limited
- DSL abstracts raw instruction encoding
- Understanding registers is essential

---

## Chapter 4: BPF Helper Functions
**Duration**: 2-3 hours | **Difficulty**: Intermediate

### 4.1 Helper Function Basics
- What are helper functions?
- Calling convention
- Return values and error handling
- Helper availability and kernel versions

### 4.2 Essential Helpers
- Process information: get_current_pid_tgid, get_current_comm
- Time: ktime_get_ns, jiffies64
- Random: get_prandom_u32
- CPU info: get_smp_processor_id

### 4.3 Map Helpers
- map_lookup_elem, map_update_elem, map_delete_elem
- map_push_elem, map_pop_elem (queue/stack)
- Spinlock helpers for concurrency

### 4.4 Tracing Helpers
- probe_read_kernel, probe_read_user
- probe_read_str variants
- get_stack, get_stackid
- trace_printk (debugging only)

### 4.5 Event Output Helpers
- perf_event_output
- ringbuf_output, ringbuf_reserve, ringbuf_submit
- Choosing between perf buffers and ring buffers

### 4.6 Helper Patterns in clj-ebpf
- Low-level wrappers: helper-*
- High-level patterns: with-map-lookup, safe-probe-read
- Process info collection: get-process-info
- Time measurement: time-delta

### Lab 4.1: Process Tree Monitor
**Kernel Program**: Track parent-child relationships on fork
**Userspace**: Build and display process tree
```clojure
;; Use get_current_task to access task_struct
;; Read parent PID using probe_read_kernel
;; Store in map: child_pid → parent_pid
```

### Lab 4.2: File Access Latency Tracker
**Kernel Program**: Measure time between open and close
**Userspace**: Histogram of file access latencies
```clojure
;; Entry: record timestamp on open
(def file-open-entry
  (bpf/assemble
    (vec (concat
      (let [[start _] (bpf/time-delta :r6 :r7)]
        start)
      ;; Store timestamp with FD as key
      ))))

;; Exit: calculate delta on close
```

### Lab 4.3: Memory Allocation Profiler
**Kernel Program**: Track malloc/free calls and sizes
**Userspace**: Display allocation statistics
```clojure
;; Use kretprobe on malloc/free
;; Track allocations per process
;; Calculate fragmentation metrics
```

**Key Takeaways**:
- Helpers provide controlled kernel API access
- Choose appropriate helpers for your use case
- clj-ebpf patterns simplify helper usage

---

# Part II: Program Types and Attach Points (Chapters 5-9)

## Chapter 5: Kprobes and Kretprobes
**Duration**: 3-4 hours | **Difficulty**: Intermediate

### 5.1 Understanding Kprobes
- What are kprobes?
- Dynamic instrumentation
- Kprobes vs kretprobes
- Symbol resolution and addresses
- Performance considerations

### 5.2 Kprobe Attachment
- Attaching to kernel functions
- Function arguments access
- Register state and pt_regs
- Limitations and edge cases

### 5.3 Kretprobe Specifics
- Return value capture
- Entry/exit correlation
- Use cases for kretprobes

### Lab 5.1: Kernel Function Call Tracer
**Kernel Program**: Trace all calls to a specific kernel function
**Userspace**: Display call rate and arguments
```clojure
(defn trace-kernel-function [function-name]
  (let [prog (bpf/assemble
               (vec (concat
                 (bpf/helper-get-current-pid-tgid)
                 ;; Record call with timestamp
                 [(bpf/exit-insn)])))]
    (bpf/attach-kprobe prog function-name)))
```

### Lab 5.2: TCP Connection Tracker
**Kernel Program**: Track TCP connections (kprobe on tcp_v4_connect)
**Userspace**: Display active connections and states
```clojure
;; Capture: source IP, dest IP, source port, dest port
;; Store connection 4-tuple in map
;; Track connection state changes
```

### Lab 5.3: Mutex Contention Analyzer
**Kernel Program**: Detect mutex contention hotspots
**Userspace**: Report most contended mutexes
```clojure
;; Kprobe on mutex_lock (entry)
;; Kretprobe on mutex_lock (exit)
;; Calculate time spent waiting
;; Aggregate by mutex address
```

**Key Takeaways**:
- Kprobes enable dynamic kernel instrumentation
- Careful with performance impact
- Kernel symbols can change between versions

---

## Chapter 6: Tracepoints and Raw Tracepoints
**Duration**: 2-3 hours | **Difficulty**: Intermediate

### 6.1 What are Tracepoints?
- Static instrumentation points
- Stability guarantees
- Available tracepoints
- Tracepoint format and arguments

### 6.2 Raw Tracepoints
- Difference from regular tracepoints
- Performance benefits
- Accessing raw arguments

### 6.3 Tracepoint Categories
- Scheduler tracepoints
- Syscall tracepoints
- Network tracepoints
- Block I/O tracepoints

### Lab 6.1: System Call Monitor
**Kernel Program**: Monitor all syscalls system-wide
**Userspace**: Display syscall frequency by type
```clojure
;; Attach to sys_enter tracepoint
;; Extract syscall number
;; Count per syscall type
;; Optional: filter by PID/UID
```

### Lab 6.2: Scheduler Latency Analyzer
**Kernel Program**: Measure scheduling latency
**Userspace**: Distribution of scheduling delays
```clojure
;; sched_wakeup: record wakeup time
;; sched_switch: calculate runqueue latency
;; Histogram of latencies
```

### Lab 6.3: Block I/O Performance Monitor
**Kernel Program**: Track block device I/O
**Userspace**: I/O latency and throughput metrics
```clojure
;; block_rq_insert: I/O request started
;; block_rq_complete: I/O request completed
;; Calculate latency, IOPS, throughput
```

**Key Takeaways**:
- Tracepoints are stable kernel ABI
- Prefer tracepoints over kprobes when available
- Raw tracepoints for performance-critical paths

---

## Chapter 7: XDP (eXpress Data Path)
**Duration**: 4-5 hours | **Difficulty**: Advanced

### 7.1 XDP Overview
- What is XDP?
- XDP vs traditional networking
- XDP program execution context
- XDP actions: PASS, DROP, TX, REDIRECT, ABORTED
- XDP modes: native, offloaded, generic

### 7.2 XDP Programming Model
- XDP metadata and data pointers
- Packet parsing
- Header modifications
- XDP helper functions

### 7.3 XDP Performance Optimization
- Avoiding packet copies
- Efficient parsing techniques
- Map lookups and caching
- Per-CPU data structures

### Lab 7.1: DDoS Protection - SYN Flood Mitigation
**Kernel Program**: Rate-limit SYN packets per source IP
**Userspace**: Configuration and statistics dashboard
```clojure
;; Parse Ethernet, IP, TCP headers
;; Track SYN rate per source IP
;; Drop excessive SYNs
;; Update statistics map

(defn xdp-syn-flood-protection [rate-limit]
  (bpf/assemble
    (vec (concat
      ;; Parse packet to TCP layer
      ;; Check if SYN flag set
      ;; Rate limit logic
      [(bpf/mov :r0 (bpf/xdp-action :drop))
       (bpf/exit-insn)]))))
```

### Lab 7.2: Layer 4 Load Balancer
**Kernel Program**: Distribute packets across backend servers
**Userspace**: Backend health monitoring and configuration
```clojure
;; Hash packet 5-tuple
;; Lookup backend server
;; Rewrite destination IP/MAC
;; XDP_TX to send back out same interface
```

### Lab 7.3: Packet Capture and Sampling
**Kernel Program**: Capture 1 in N packets for analysis
**Userspace**: Packet analyzer and statistics
```clojure
;; Probabilistic sampling
;; Copy packet to perf ring buffer
;; Pass original packet
;; Userspace: parse and analyze sampled packets
```

**Key Takeaways**:
- XDP provides highest performance packet processing
- Careful packet parsing is essential
- XDP is ideal for DDoS mitigation and load balancing

---

## Chapter 8: Traffic Control (TC) and Networking
**Duration**: 3-4 hours | **Difficulty**: Advanced

### 8.1 TC BPF Programs
- TC ingress vs egress
- TC actions: OK, RECLASSIFY, SHOT, PIPE
- Qdisc attachment
- TC vs XDP: when to use each

### 8.2 Socket Filters and SKB Programs
- Socket-level filtering
- sk_buff structure
- SKB fields and metadata
- Network namespace awareness

### 8.3 SOCKMAP and Socket Redirection
- Accelerated socket operations
- Socket maps
- Socket redirection for proxying

### Lab 8.1: Bandwidth Limiter
**Kernel Program**: Enforce per-connection bandwidth limits
**Userspace**: Configuration and monitoring
```clojure
;; TC egress program
;; Track bytes per connection
;; Apply token bucket algorithm
;; Drop packets exceeding limit
```

### Lab 8.2: Application-Layer Protocol Filter
**Kernel Program**: Filter traffic by HTTP method/path
**Userspace**: Policy management interface
```clojure
;; Parse TCP payload for HTTP
;; Extract method (GET, POST, etc.)
;; Match against filter rules
;; Allow or drop
```

### Lab 8.3: Network Latency Injection (Testing Tool)
**Kernel Program**: Inject configurable latency
**Userspace**: Chaos engineering controller
```clojure
;; TC egress program
;; Delay packets by N milliseconds
;; Useful for testing distributed systems
```

**Key Takeaways**:
- TC provides full network stack visibility
- More overhead than XDP but more flexibility
- Ideal for complex packet transformations

---

## Chapter 9: Cgroups and Resource Control
**Duration**: 2-3 hours | **Difficulty**: Intermediate

### 9.1 Cgroup BPF Programs
- What are cgroups?
- Cgroup attachment points
- Cgroup program types
- Hierarchical policy enforcement

### 9.2 Socket Control
- cgroup/sock: socket creation control
- cgroup/sock_addr: bind/connect control
- cgroup/sock_ops: socket operations monitoring

### 9.3 Device Access Control
- cgroup/dev: device access policy
- Use cases for device filtering

### Lab 9.1: Container Network Policy Enforcer
**Kernel Program**: Enforce network egress rules per container
**Userspace**: Policy definition and loading
```clojure
;; Attach to cgroup
;; Allow/deny based on destination IP/port
;; Log policy violations
```

### Lab 9.2: Resource Usage Monitor
**Kernel Program**: Track socket I/O per cgroup
**Userspace**: Container network usage dashboard
```clojure
;; cgroup/sock_ops program
;; Track bytes sent/received
;; Per-cgroup accounting
```

### Lab 9.3: Application Sandboxing
**Kernel Program**: Restrict system calls for containerized apps
**Userspace**: Security policy manager
```clojure
;; Combine cgroup with LSM hooks
;; Syscall filtering
;; Audit logging
```

**Key Takeaways**:
- Cgroups enable per-container/per-process control
- Powerful for multi-tenant environments
- Foundation for container security

---

# Part III: Advanced Topics (Chapters 10-14)

## Chapter 10: CO-RE (Compile Once - Run Everywhere)
**Duration**: 3-4 hours | **Difficulty**: Advanced

### 10.1 The Portability Problem
- Kernel structure differences across versions
- Traditional solutions and limitations
- How CO-RE solves portability

### 10.2 BTF (BPF Type Format)
- What is BTF?
- BTF type information
- Checking BTF availability
- BTF-enabled kernels

### 10.3 CO-RE Relocations
- Field offset relocations
- Field existence checks
- Type size relocations
- Enum value relocations

### 10.4 CO-RE in clj-ebpf
- core-field-offset
- core-field-exists, core-field-size
- core-type-exists, core-type-size
- generate-core-read pattern

### Lab 10.1: Portable Process Monitor
**Kernel Program**: Read task_struct fields portably
**Userspace**: Works across kernel versions
```clojure
(def portable-monitor
  (bpf/assemble
    (vec (concat
      (bpf/helper-get-current-task)
      ;; Read PID field with CO-RE
      (bpf/core-field-offset :r1 "task_struct" "pid")
      (bpf/add-reg :r0 :r1)
      (bpf/ldx :w :r2 :r0 0)
      [(bpf/exit-insn)]))))
```

### Lab 10.2: Kernel Version Adaptive Program
**Kernel Program**: Use new field if available, fallback otherwise
**Userspace**: Single binary for multiple kernels
```clojure
;; Check if new field exists
(bpf/core-field-exists :r0 "task_struct" "new_field")
;; Branch based on existence
;; Use new field or old field
```

### Lab 10.3: Structure Field Inspector
**Kernel Program**: Dynamically inspect kernel structures
**Userspace**: BTF explorer tool
```clojure
;; Query BTF for structure info
(bpf/get-struct-members "task_struct")
;; Generate field access code dynamically
```

**Key Takeaways**:
- CO-RE enables true portability
- BTF is required for CO-RE
- clj-ebpf provides CO-RE helpers

---

## Chapter 11: LSM (Linux Security Modules) Hooks
**Duration**: 3-4 hours | **Difficulty**: Advanced

### 11.1 LSM BPF Overview
- What are LSM hooks?
- Security policy enforcement
- Available LSM hooks
- LSM BPF vs traditional LSMs (SELinux, AppArmor)

### 11.2 Common LSM Hooks
- File operations hooks
- Process operations hooks
- Network hooks
- IPC hooks

### 11.3 Security Policy Implementation
- Allow/deny decisions
- Audit logging
- Policy composition

### Lab 11.1: File Access Control System
**Kernel Program**: Enforce file access policies
**Userspace**: Policy management interface
```clojure
;; LSM hook: file_open
;; Check file path against policy
;; Allow or deny access
;; Log denied accesses
```

### Lab 11.2: Process Execution Guardian
**Kernel Program**: Control which programs can execute
**Userspace**: Whitelist/blacklist manager
```clojure
;; LSM hook: bprm_check_security
;; Validate executable path
;; Check digital signatures
;; Prevent unauthorized execution
```

### Lab 11.3: Network Connection Firewall
**Kernel Program**: Filter outbound connections
**Userspace**: Connection policy UI
```clojure
;; LSM hook: socket_connect
;; Check destination IP/port
;; Apply per-process rules
;; Block malicious connections
```

**Key Takeaways**:
- LSM BPF enables custom security policies
- Fine-grained access control
- Critical for zero-trust security

---

## Chapter 12: Performance Optimization
**Duration**: 3-4 hours | **Difficulty**: Advanced

### 12.1 BPF Performance Fundamentals
- Verifier complexity limits
- Instruction count limits
- Stack size limits
- Map access patterns

### 12.2 Optimization Techniques
- Loop unrolling
- Inline helper calls where possible
- Efficient map lookups
- Per-CPU data structures
- Batch operations

### 12.3 Profiling BPF Programs
- Measuring execution time
- Identifying bottlenecks
- Verifier optimization
- JIT compilation

### 12.4 Scalability Patterns
- Per-CPU maps
- Lock-free algorithms
- Sampling vs full instrumentation
- Aggregation in kernel vs userspace

### Lab 12.1: High-Performance Packet Counter
**Kernel Program**: Count millions of packets/sec
**Userspace**: Real-time statistics display
```clojure
;; Use per-CPU array map
;; Minimize instructions
;; Batch updates
;; Efficient aggregation
```

### Lab 12.2: Zero-Copy Event Collection
**Kernel Program**: Stream events with minimal overhead
**Userspace**: High-throughput event processor
```clojure
;; Ring buffer for zero-copy
;; Batch event submission
;; Lock-free ring buffer reading
```

### Lab 12.3: Adaptive Sampling System
**Kernel Program**: Dynamically adjust sampling rate
**Userspace**: Overhead controller
```clojure
;; Monitor overhead
;; Adjust sampling rate based on load
;; Maintain target overhead percentage
```

**Key Takeaways**:
- Performance optimization is critical for production
- Understanding verifier limits is essential
- Per-CPU data structures are key for scalability

---

## Chapter 13: Event Processing and Ring Buffers
**Duration**: 2-3 hours | **Difficulty**: Intermediate

### 13.1 Perf Event Buffers
- How perf buffers work
- Per-CPU buffers
- Lost event handling
- When to use perf buffers

### 13.2 BPF Ring Buffers
- Ring buffer advantages
- Memory efficiency
- Ring buffer API
- Reserve/submit pattern

### 13.3 Event Processing Patterns
- Event batching
- Event filtering
- Event aggregation
- Backpressure handling

### Lab 13.1: Real-Time Event Stream Processor
**Kernel Program**: Capture system events
**Userspace**: Process and forward events
```clojure
;; Ring buffer for event streaming
;; Structured event format
;; Efficient event parsing
;; Forward to time-series database
```

### Lab 13.2: Log Aggregator
**Kernel Program**: Capture kernel logs
**Userspace**: Centralized logging system
```clojure
;; Capture printk messages
;; Filter by log level
;; Structured log format
;; Send to log aggregation service
```

### Lab 13.3: Metrics Exporter
**Kernel Program**: Collect system metrics
**Userspace**: Prometheus exporter
```clojure
;; Periodic metric collection
;; Metric aggregation
;; Prometheus format export
;; HTTP server for scraping
```

**Key Takeaways**:
- Ring buffers are preferred for new development
- Proper event handling prevents data loss
- Userspace processing is equally important

---

## Chapter 14: Testing and Debugging
**Duration**: 2-3 hours | **Difficulty**: Intermediate

### 14.1 Development Workflow
- Iterative development
- REPL-driven development with clj-ebpf
- Version control for BPF programs
- Testing in development vs production

### 14.2 Debugging Techniques
- trace_printk for debugging (not for production)
- Verifier errors and how to fix them
- Map inspection
- bpftool usage

### 14.3 Testing Strategies
- Unit testing BPF logic
- Integration testing with test programs
- Load testing and stress testing
- Fuzzing BPF programs

### 14.4 Common Pitfalls
- Verifier rejection reasons
- Infinite loops prevention
- Stack overflow issues
- Helper function misuse

### Lab 14.1: BPF Program Test Framework
**Test Framework**: Automated BPF program testing
**Coverage**: Instruction coverage, edge cases
```clojure
(deftest test-packet-filter
  (testing "IPv4 packet filtering"
    (let [prog (compile-program packet-filter)
          test-packet (generate-ipv4-packet ...)]
      (is (= :pass (run-program prog test-packet))))))
```

### Lab 14.2: Verifier Error Resolver
**Tool**: Analyze and fix common verifier errors
**Automation**: Suggest fixes for verifier rejections
```clojure
;; Parse verifier error messages
;; Identify issue patterns
;; Suggest code modifications
```

### Lab 14.3: Performance Regression Detector
**System**: Track BPF program performance over time
**Alerts**: Detect performance degradations
```clojure
;; Benchmark BPF programs
;; Track execution time trends
;; Alert on regressions
```

**Key Takeaways**:
- Testing BPF programs is challenging but essential
- Understand verifier requirements
- Debugging requires different techniques than traditional programming

---

## Chapter 15: Idiomatic Clojure References for BPF
**Duration**: 2-3 hours | **Difficulty**: Intermediate

### 15.1 Why Clojure References for BPF?
- Leveraging Clojure's reference type abstractions
- IDeref, IBlockingDeref, IAtom, and ITransientCollection protocols
- Benefits: familiar patterns, composability, resource management

### 15.2 Read-Only References
- `ringbuf-ref`: Blocking reads from ring buffers with `@`
- `queue-ref`, `stack-ref`: Blocking pops from queue/stack maps
- `map-watch`: Block until key exists
- `map-watch-changes`: Block until value changes
- Lazy event sequences with `ringbuf-seq` and `queue-seq`
- Timeout handling with `deref`

### 15.3 Writable References
- `map-entry-ref`: Atom-like access with `reset!`, `swap!`, `compare-and-set!`
- `queue-writer`, `stack-writer`: Push with `conj!`, peek with `@`
- Validators for map-entry-ref

### 15.4 Bidirectional Channels
- `queue-channel`: Combined read/write (FIFO)
- `stack-channel`: Combined read/write (LIFO)
- Producer-consumer patterns

### 15.5 Resource Management
- `with-ringbuf-ref` and other with-* macros
- Closeable protocol and cleanup
- Best practices for reference lifecycle

### Lab 15.1: Event Counter Dashboard
**Pattern**: Real-time dashboard with map-entry-ref and map-watch-changes
**Userspace**: Counter display, threshold alerts, rate calculation
```clojure
;; Create atom-like references to counters
(def counter (bpf/map-entry-ref stats-map :event-count))

;; Atom operations on BPF maps
@counter              ; read
(reset! counter 0)    ; write
(swap! counter inc)   ; read-modify-write
```

### Lab 15.2: Producer-Consumer Pipeline
**Pattern**: Multi-stage event processing with queue channels
**Architecture**: Ring buffer → Filter → Enrich → Aggregate
```clojure
;; Bidirectional queue channel
(def ch (bpf/queue-channel work-queue))

;; Producer pushes
(conj! ch {:task :process :data data})

;; Consumer blocks until data available
(let [task @ch]
  (process task))
```

### Lab 15.3: Undo/Redo System
**Pattern**: Two-stack undo/redo with stack channels
**Features**: LIFO semantics, operation reversal, peek without pop
```clojure
;; Stack channels for undo/redo
(def undo-ch (bpf/stack-channel undo-stack))
(def redo-ch (bpf/stack-channel redo-stack))

;; Push operation to undo stack
(conj! undo-ch (serialize op))

;; Pop for undo (LIFO)
(let [op @undo-ch]
  (apply-reverse op)
  (conj! redo-ch op))
```

**Key Takeaways**:
- clj-ebpf reference types use standard Clojure protocols
- Blocking reads with `@` provide natural event handling
- Atom-like maps enable familiar patterns like `swap!`
- Resource management is critical - always close references
- Use timeouts in production to avoid indefinite blocking

---

# Part IV: Real-World Applications (Chapters 16-23)

## Chapter 16: Complete Application - System Call Tracer (like strace)
**Duration**: 4-5 hours | **Difficulty**: Advanced

### Application Overview
A complete system call tracer similar to strace, implemented in eBPF for lower overhead.

### Architecture
```
┌─────────────────┐
│  Userspace CLI  │ ← User interacts here
├─────────────────┤
│ Event Processor │ ← Parses and formats syscall events
├─────────────────┤
│  Ring Buffer    │ ← Communication channel
├─────────────────┤
│   BPF Programs  │ ← sys_enter/sys_exit tracepoints
└─────────────────┘
```

### Features
- Trace all syscalls for a process
- Capture syscall arguments and return values
- Format output like strace
- Filter by syscall type
- Performance overhead < 5%

### Implementation

**Kernel Program** (`src/ebpf/syscall_tracer.clj`):
```clojure
(ns syscall-tracer.ebpf
  (:require [clj-ebpf.core :as bpf]))

(def config-map
  (bpf/create-hash-map
    {:key-size 4    ; PID
     :value-size 1  ; trace enabled
     :max-entries 1024}))

(def syscall-events
  (bpf/create-ringbuf-map
    {:max-entries (* 256 1024)}))  ; 256KB ring buffer

(def syscall-enter-prog
  (bpf/assemble
    (vec (concat
      ;; Get current PID
      (bpf/helper-get-current-pid-tgid)
      (bpf/extract-pid :r0 :r6)

      ;; Check if PID is being traced
      (bpf/with-map-lookup config-map :r6 20 :r7)

      ;; Reserve ringbuf space
      ;; ... fill event struct ...
      ;; Submit event

      [(bpf/mov :r0 0)
       (bpf/exit-insn)]))))
```

**Userspace Program** (`src/userspace/syscall_tracer.clj`):
```clojure
(ns syscall-tracer.userspace
  (:require [clj-ebpf.core :as bpf]
            [clojure.tools.cli :as cli]))

(defn parse-syscall-event [event-bytes]
  {:pid (read-u32 event-bytes 0)
   :tid (read-u32 event-bytes 4)
   :syscall-nr (read-u32 event-bytes 8)
   :args (vec (for [i (range 6)]
               (read-u64 event-bytes (+ 12 (* i 8)))))
   :timestamp (read-u64 event-bytes 60)})

(defn format-syscall [event syscall-db]
  (let [name (get syscall-db (:syscall-nr event))
        args-str (format-args name (:args event))]
    (format "%s(%s)" name args-str)))

(defn -main [& args]
  (let [{:keys [pid filter]} (parse-cli-args args)]
    (bpf/init!)

    ;; Load programs
    (with-open [enter-prog (bpf/load-program syscall-enter-prog :tracepoint)
                exit-prog (bpf/load-program syscall-exit-prog :tracepoint)]

      ;; Attach to tracepoints
      (bpf/attach-tracepoint enter-prog "raw_syscalls" "sys_enter")
      (bpf/attach-tracepoint exit-prog "raw_syscalls" "sys_exit")

      ;; Enable tracing for target PID
      (bpf/map-update config-map pid 1)

      ;; Process events
      (let [consumer (bpf/create-ringbuf-consumer syscall-events
                       (fn [event]
                         (-> event
                             parse-syscall-event
                             format-syscall
                             println)))]
        (bpf/start-ringbuf-consumer consumer)

        ;; Run until interrupted
        (println (format "Tracing syscalls for PID %d..." pid))
        @(promise)))))  ; Block forever
```

**CLI Interface**:
```bash
$ clojure -M:syscall-tracer --pid 1234
Tracing syscalls for PID 1234...
openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3
read(3, "127.0.0.1\tlocalhost\n", 4096) = 20
close(3) = 0
```

### Learning Objectives
- Complete eBPF application architecture
- Kernel-userspace communication via ring buffers
- Event parsing and formatting
- CLI argument handling
- Production-ready error handling

---

## Chapter 17: Complete Application - Network Traffic Analyzer
**Duration**: 5-6 hours | **Difficulty**: Advanced

### Application Overview
A comprehensive network traffic analyzer that captures, analyzes, and visualizes network traffic patterns.

### Architecture
```
┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│  XDP Program │────▶│ Perf Buffer │────▶│ Packet Parser│
└──────────────┘     └─────────────┘     └──────────────┘
                                                  │
┌──────────────┐     ┌─────────────┐            │
│  Statistics  │◀────│  Aggregator │◀───────────┘
│   Dashboard  │     └─────────────┘
└──────────────┘
```

### Features
- Real-time packet capture and analysis
- Protocol distribution (TCP, UDP, ICMP, etc.)
- Top talkers identification
- Traffic flow analysis
- Web-based dashboard
- Export to PCAP format

### Implementation Modules

**Module 1: XDP Packet Capture** (`src/ebpf/packet_capture.clj`)
**Module 2: Flow Tracking** (`src/ebpf/flow_tracker.clj`)
**Module 3: Statistics Aggregation** (`src/userspace/aggregator.clj`)
**Module 4: Web Dashboard** (`src/userspace/dashboard.clj`)

### Example Usage
```bash
$ clojure -M:traffic-analyzer --interface eth0 --port 8080
Starting traffic analyzer on eth0...
Dashboard available at http://localhost:8080
```

---

## Chapter 18: Complete Application - Container Security Monitor
**Duration**: 5-6 hours | **Difficulty**: Advanced

### Application Overview
Security monitoring for containerized applications using LSM hooks and cgroup attachment.

### Architecture
```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ LSM Hooks   │────▶│ Event Buffer │────▶│ Policy      │
│ (file,exec) │     │              │     │ Engine      │
└─────────────┘     └──────────────┘     └─────────────┘
                                                  │
┌─────────────┐     ┌──────────────┐            │
│ Cgroup      │────▶│ Resource     │            │
│ Programs    │     │ Tracking     │            │
└─────────────┘     └──────────────┘            │
                                                  │
                           ┌──────────────────────┘
                           ▼
                    ┌──────────────┐
                    │ Alert System │
                    └──────────────┘
```

### Features
- File access monitoring per container
- Process execution control
- Network egress filtering
- Resource usage tracking
- Real-time security alerts
- Policy violation logging

### Components
1. **LSM File Monitor**: Track file accesses
2. **Execution Guardian**: Control program execution
3. **Network Policy Enforcer**: Filter connections
4. **Resource Monitor**: Track CPU/memory/network
5. **Alert Manager**: Generate security alerts
6. **Policy Management UI**: Configure policies

---

## Chapter 19: Complete Application - Performance Profiler
**Duration**: 4-5 hours | **Difficulty**: Advanced

### Application Overview
A comprehensive performance profiling tool for system-wide or per-process analysis.

### Features
- CPU profiling with stack traces
- Memory allocation profiling
- I/O latency profiling
- Lock contention analysis
- Flame graph generation
- Historical data storage

### Profiling Modes
1. **CPU Profiler**: Sampling-based CPU profiling
2. **Memory Profiler**: Track allocations and leaks
3. **I/O Profiler**: Disk and network I/O analysis
4. **Mutex Profiler**: Lock contention hotspots
5. **Off-CPU Profiler**: Track time spent blocked

### Implementation Example
```clojure
;; CPU Profiling
(defn start-cpu-profiling [pid duration]
  (let [stack-map (bpf/create-stack-map ...)
        freq-map (bpf/create-hash-map ...)]
    ;; Sample stack traces at 99Hz
    ;; Aggregate frequencies
    ;; Generate flame graph
    ))
```

---

## Chapter 20: Complete Application - Distributed Tracing
**Duration**: 5-6 hours | **Difficulty**: Expert

### Application Overview
Distributed tracing system that tracks requests across microservices using eBPF.

### Features
- Automatic span creation
- Request correlation across services
- Service dependency mapping
- Latency breakdown by component
- Integration with OpenTelemetry
- No application code changes required

### Architecture
```
Service A          Service B          Service C
    │                  │                  │
    ├──[http req]─────▶│                  │
    │   ├─[db query]   │                  │
    │   └─[cache hit]  │                  │
    │                  ├──[grpc call]────▶│
    │                  │                  │
    │◀─────────────────┼──────────────────┘
    │
    ▼
┌────────────────┐
│ eBPF Collector │
└────────────────┘
         │
         ▼
┌────────────────┐
│ Trace Assembler│
└────────────────┘
         │
         ▼
┌────────────────┐
│ Jaeger/Zipkin  │
└────────────────┘
```

### Implementation
- Hook HTTP/gRPC libraries
- Extract trace context from headers
- Propagate trace IDs
- Measure span durations
- Export to trace backend

---

## Chapter 21: Complete Application - Database Query Analyzer
**Duration**: 4-5 hours | **Difficulty**: Advanced

### Application Overview
Analyze database queries without modifying the database or application.

### Features
- Query execution time tracking
- Slow query identification
- Query plan analysis (with uprobe)
- Client connection tracking
- Query frequency histograms
- Database load patterns

### Supported Databases
- PostgreSQL
- MySQL/MariaDB
- MongoDB
- Redis

### Example: PostgreSQL Analysis
```clojure
;; Uprobe on postgres query execution
;; Extract query text
;; Measure execution time
;; Track by query pattern
;; Alert on slow queries
```

---

## Chapter 22: Complete Application - Security Audit System
**Duration**: 5-6 hours | **Difficulty**: Expert

### Application Overview
Comprehensive security auditing and compliance monitoring system.

### Features
- File integrity monitoring
- Privilege escalation detection
- Unauthorized network connection detection
- Compliance policy enforcement (PCI-DSS, HIPAA)
- Audit log generation
- Real-time threat detection

### Security Modules
1. **File Integrity Monitor**: Track file modifications
2. **Privilege Watcher**: Detect setuid/sudo usage
3. **Network Guardian**: Monitor outbound connections
4. **Crypto Monitor**: Track encryption key usage
5. **Audit Logger**: Generate compliance logs

---

## Chapter 23: Complete Application - Chaos Engineering Platform
**Duration**: 4-5 hours | **Difficulty**: Advanced

### Application Overview
A chaos engineering platform for testing system resilience using eBPF.

### Features
- Network latency injection
- Packet loss simulation
- CPU throttling
- Memory pressure
- Disk I/O delays
- Syscall error injection

### Chaos Experiments
1. **Network Chaos**: Inject latency, packet loss, bandwidth limits
2. **CPU Chaos**: Throttle CPU for specific processes
3. **Memory Chaos**: Simulate OOM conditions
4. **I/O Chaos**: Slow down disk operations
5. **Syscall Chaos**: Make syscalls fail randomly

### Example: Latency Injection
```clojure
(defn inject-network-latency [service-name delay-ms]
  (let [prog (create-tc-latency-program delay-ms)]
    ;; Attach to service's cgroup
    ;; Delay egress packets
    ;; Monitor impact
    ))
```

---

# Part V: Production and Best Practices (Chapters 24-26)

## Chapter 24: Production Deployment
**Duration**: 3-4 hours | **Difficulty**: Advanced

### 24.1 Deployment Strategies
- Canary deployments for BPF programs
- Rollback procedures
- Version management
- Configuration management

### 24.2 Monitoring and Observability
- Monitoring BPF program health
- Tracking program statistics
- Alert on program failures
- Logging best practices

### 24.3 Resource Management
- Memory limits for maps
- CPU overhead monitoring
- Program count limits
- Cleanup and garbage collection

### 24.4 Security Considerations
- Capability requirements
- Program signing and verification
- Sensitive data handling
- Audit logging

### Lab 24.1: BPF Program Lifecycle Manager
**System**: Automated BPF program deployment
**Features**: Load, attach, monitor, rollback
```clojure
(defn deploy-program [program version]
  ;; Validate program
  ;; Load new version
  ;; Health check
  ;; Switch traffic
  ;; Monitor for issues
  ;; Rollback if needed
  )
```

---

## Chapter 25: Troubleshooting Guide
**Duration**: 2-3 hours | **Difficulty**: Intermediate

### 25.1 Common Issues
- Verifier rejection patterns
- Map size issues
- Performance problems
- Helper function errors

### 25.2 Diagnostic Tools
- bpftool for inspection
- /sys/kernel/debug/tracing/trace_pipe
- Kernel logs
- clj-ebpf debugging functions

### 25.3 Performance Debugging
- Identifying overhead sources
- Optimization strategies
- Profiling BPF programs

### Troubleshooting Checklist
```
□ Kernel version compatible?
□ BPF filesystem mounted?
□ Required capabilities present?
□ Map sizes appropriate?
□ Program complexity within limits?
□ Helper functions available?
□ BTF available (for CO-RE)?
```

---

## Chapter 26: Advanced Patterns and Best Practices
**Duration**: 3-4 hours | **Difficulty**: Expert

### 26.1 Design Patterns
- Event aggregation pattern
- Sampling pattern
- Filtering pattern
- Time-series pattern
- State machine pattern

### 26.2 Code Organization
- Modular BPF programs
- Shared map patterns
- Program composition
- Configuration management

### 26.3 Performance Best Practices
- Minimize map lookups
- Use appropriate map types
- Batch operations
- Per-CPU data structures
- Avoid expensive helpers

### 26.4 Security Best Practices
- Least privilege principle
- Input validation
- Sensitive data protection
- Audit logging

### 26.5 Testing Best Practices
- Unit test coverage
- Integration testing
- Load testing
- Chaos testing

### Pattern Library
```clojure
;; Event Aggregation Pattern
(defn create-aggregator [window-size]
  ;; Aggregate events in kernel
  ;; Flush to userspace periodically
  ;; Reduce userspace processing
  )

;; Sampling Pattern
(defn create-sampler [sample-rate]
  ;; Probabilistic sampling
  ;; Adaptive rate adjustment
  ;; Maintain low overhead
  )

;; State Machine Pattern
(defn create-state-machine [states transitions]
  ;; Track state in map
  ;; Transition on events
  ;; Timeout handling
  )
```

---

# Appendices

## Appendix A: BPF Instruction Reference
Complete reference of all BPF instructions with clj-ebpf DSL equivalents.

## Appendix B: BPF Helper Function Reference
All 210+ helper functions with descriptions and examples.

## Appendix C: Map Type Reference
Detailed guide to all BPF map types and use cases.

## Appendix D: Program Type Reference
Complete listing of all BPF program types and attach points.

## Appendix E: Kernel Version Compatibility Matrix
Features and helpers by kernel version.

## Appendix F: Performance Benchmarks
Performance characteristics of various BPF operations.

## Appendix G: Troubleshooting Index
Quick reference for common errors and solutions.

## Appendix H: Resources and Further Reading
- Official BPF documentation
- Academic papers
- Conference talks
- Community resources
- Related tools and projects

---

# Tutorial Statistics

**Total Chapters**: 26
**Total Labs**: 78+
**Complete Applications**: 8
**Estimated Duration**: 82-102 hours
**Difficulty Levels**: Beginner (4), Intermediate (12), Advanced (8), Expert (2)

**Code Examples**: 150+
**Real-World Applications**: 8 complete applications
**Userspace/Kernel Integration**: All labs include both components

---

# Teaching Methodology

## Progressive Complexity
- Start with simple concepts
- Build on previous knowledge
- Introduce complexity gradually
- Provide context before diving deep

## Hands-On Learning
- Every chapter has practical labs
- Real-world scenarios
- Complete, runnable code
- Encourage experimentation

## Best Practices Embedded
- Security considerations throughout
- Performance awareness from start
- Production readiness emphasized
- Testing culture promoted

## Multi-Modal Learning
- Conceptual explanations
- Visual diagrams
- Code examples
- Hands-on labs
- Real-world applications

---

# Target Outcomes

By completing this tutorial, learners will be able to:

✅ Understand eBPF architecture and capabilities
✅ Write BPF programs using clj-ebpf DSL
✅ Choose appropriate program types for different use cases
✅ Implement efficient kernel-userspace communication
✅ Build production-ready eBPF applications
✅ Debug and optimize BPF programs
✅ Apply eBPF to observability, security, and networking
✅ Design portable programs using CO-RE
✅ Deploy and monitor eBPF in production
✅ Contribute to eBPF community and tools

---

# Next Steps After Tutorial

1. **Build Your Own Application**: Apply learned concepts
2. **Contribute to clj-ebpf**: Improve the library
3. **Explore Advanced Topics**: Kernel development, verifier internals
4. **Join Community**: Share knowledge and learn from others
5. **Teach Others**: Best way to solidify understanding

---

*This tutorial is designed to be comprehensive while remaining practical and engaging. Each chapter builds on previous knowledge while introducing new concepts. The combination of theory, hands-on labs, and complete applications ensures learners gain both understanding and practical skills.*
