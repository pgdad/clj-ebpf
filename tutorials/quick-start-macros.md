# Quick Start: High-Level Declarative Macros

**Duration**: 30-45 minutes | **Difficulty**: Beginner

## Learning Objectives

By the end of this tutorial, you will:
- Understand the benefits of declarative macros over traditional API
- Define reusable BPF map specifications with `defmap-spec`
- Define BPF programs declaratively with `defprogram`
- Manage complete BPF lifecycles with `with-bpf-script`
- Write BPF applications with 60% less boilerplate

## Prerequisites

- Basic Clojure knowledge
- clj-ebpf installed and working
- Familiarity with BPF concepts (maps, programs, attachments)

## Introduction

The high-level declarative macros provide a more "Clojure-like" experience for BPF programming. Instead of manually managing bytecode assembly, map creation, program loading, attachment, and cleanup, you declare what you want and let the macros handle the details.

### Traditional vs Declarative Approach

**Traditional (verbose)**:
```clojure
;; 25+ lines of boilerplate
(bpf/with-map [m {:map-type :hash
                  :key-size 4
                  :value-size 4
                  :max-entries 1000
                  :map-name "my_map"
                  :key-serializer utils/int->bytes
                  :key-deserializer utils/bytes->int
                  :value-serializer utils/int->bytes
                  :value-deserializer utils/bytes->int}]
  (bpf/with-program [prog {:prog-type :xdp
                           :insns (dsl/assemble [(dsl/mov :r0 2)
                                                 (dsl/exit-insn)])
                           :license "GPL"
                           :prog-name "my_prog"}]
    (let [attached (bpf/attach-xdp prog "lo" 0 :skb)]
      (try
        ;; Your code here
        (finally
          (bpf/detach-xdp "lo"))))))
```

**Declarative (concise)**:
```clojure
;; 10 lines - 60% less code
(defmap-spec my-map :type :hash :key-size 4 :value-size 4 :max-entries 1000)
(defprogram my-prog :type :xdp :body [(dsl/mov :r0 2) (dsl/exit-insn)])

(with-bpf-script
  {:maps [m my-map] :progs [p my-prog] :attach [{:prog p :type :xdp :target "lo"}]}
  ;; Your code here - cleanup is automatic
  )
```

---

## Part 1: defmap-spec - Reusable Map Specifications

The `defmap-spec` macro creates a named, reusable BPF map specification.

### Basic Syntax

```clojure
(require '[clj-ebpf.macros :refer [defmap-spec]])

(defmap-spec map-name
  :type map-type
  :key-size key-bytes
  :value-size value-bytes
  :max-entries count)
```

### Example 1: Simple Hash Map

```clojure
(defmap-spec connection-tracker
  :type :hash
  :key-size 4        ; 4-byte key (e.g., IP address)
  :value-size 8      ; 8-byte value (e.g., counter)
  :max-entries 10000)
```

This creates a var `connection-tracker` containing the map specification.

### Example 2: Array Map with Custom Name

```clojure
(defmap-spec packet-counters
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 256
  :map-name "pkt_counters")  ; Custom BPF map name
```

### Example 3: Per-CPU Map for High Performance

```clojure
(defmap-spec cpu-stats
  "Per-CPU statistics for zero-contention counters"
  :type :percpu-array
  :key-size 4
  :value-size 16
  :max-entries 64)
```

### Example 4: Ring Buffer for Events

```clojure
(defmap-spec event-buffer
  :type :ringbuf
  :key-size 0           ; Not used for ringbuf
  :value-size 0         ; Not used for ringbuf
  :max-entries 262144)  ; 256KB buffer
```

### Supported Map Types

| Type | Description | Use Case |
|------|-------------|----------|
| `:hash` | Hash table | General key-value storage |
| `:array` | Fixed-size array | Index-based access |
| `:lru-hash` | LRU eviction hash | Cache with automatic eviction |
| `:percpu-hash` | Per-CPU hash | High-concurrency counters |
| `:percpu-array` | Per-CPU array | Per-CPU statistics |
| `:lru-percpu-hash` | LRU per-CPU hash | High-concurrency cache |
| `:stack` | LIFO stack | Stack traces, call stacks |
| `:queue` | FIFO queue | Event queuing |
| `:ringbuf` | Ring buffer | High-performance event streaming |
| `:lpm-trie` | Longest prefix match | IP routing, CIDR lookups |

### Inspecting a Map Spec

```clojure
;; View the generated specification
connection-tracker
;; => {:map-type :hash
;;     :key-size 4
;;     :value-size 8
;;     :max-entries 10000
;;     :map-flags 0
;;     :map-name "connection-tracker"
;;     :key-serializer #function[...]
;;     :value-serializer #function[...]
;;     ...}
```

---

## Part 2: defprogram - Declarative Program Definition

The `defprogram` macro defines BPF programs with DSL instructions.

### Basic Syntax

```clojure
(require '[clj-ebpf.macros :refer [defprogram]]
         '[clj-ebpf.dsl :as dsl])

(defprogram prog-name
  :type program-type
  :body [dsl-instructions...])
```

### Example 1: Simple XDP Pass-All

```clojure
(defprogram xdp-pass-all
  :type :xdp
  :body [(dsl/mov :r0 2)      ; XDP_PASS = 2
         (dsl/exit-insn)])
```

### Example 2: XDP Drop-All with Docstring

```clojure
(defprogram xdp-drop-all
  "XDP program that drops all incoming packets.
   Use for testing or emergency traffic blocking."
  :type :xdp
  :license "GPL"
  :body [(dsl/mov :r0 1)      ; XDP_DROP = 1
         (dsl/exit-insn)])
```

### Example 3: Kprobe with Custom Options

```clojure
(defprogram syscall-tracer
  "Trace system calls for debugging"
  :type :kprobe
  :license "Dual MIT/GPL"
  :opts {:log-level 2         ; Verbose verifier logging
         :prog-name "sys_tracer"}
  :body [(dsl/call 14)        ; bpf_get_current_pid_tgid()
         (dsl/mov-reg :r6 :r0) ; Save result
         (dsl/mov :r0 0)       ; Return 0
         (dsl/exit-insn)])
```

### Example 4: XDP with Packet Size Check

```clojure
(defprogram xdp-size-filter
  "Pass packets larger than 60 bytes, drop smaller ones"
  :type :xdp
  :body [;; r1 = ctx (XDP context pointer)
         ;; Load data_end pointer
         (dsl/ldx :w :r2 :r1 4)   ; r2 = ctx->data_end
         ;; Load data pointer
         (dsl/ldx :w :r3 :r1 0)   ; r3 = ctx->data
         ;; Calculate packet size: r2 = data_end - data
         (dsl/sub-reg :r2 :r3)
         ;; if size > 60, jump to pass
         (dsl/jmp-imm :jgt :r2 60 2)
         ;; Drop small packets
         (dsl/mov :r0 1)          ; XDP_DROP
         (dsl/exit-insn)
         ;; Pass large packets
         (dsl/mov :r0 2)          ; XDP_PASS
         (dsl/exit-insn)])
```

### Supported Program Types

| Type | Description | Attach Point |
|------|-------------|--------------|
| `:xdp` | eXpress Data Path | Network interface |
| `:tc` | Traffic Control | TC qdisc |
| `:kprobe` | Kernel probe | Kernel function entry |
| `:kretprobe` | Kernel return probe | Kernel function exit |
| `:tracepoint` | Static tracepoint | Kernel tracepoint |
| `:raw-tracepoint` | Raw tracepoint | Raw kernel tracepoint |
| `:uprobe` | User probe | Userspace function entry |
| `:uretprobe` | User return probe | Userspace function exit |
| `:cgroup-skb` | Cgroup SKB | Cgroup network |
| `:cgroup-sock` | Cgroup socket | Cgroup socket operations |
| `:lsm` | LSM hook | Security hook |
| `:socket-filter` | Socket filter | Socket |

### Inspecting a Program Spec

```clojure
;; View the specification
xdp-pass-all
;; => {:prog-type :xdp
;;     :license "GPL"
;;     :prog-name "xdp-pass-all"
;;     :log-level 1
;;     :body-fn #function[...]
;;     :body-source [(dsl/mov :r0 2) (dsl/exit-insn)]}

;; Get assembled bytecode
((:body-fn xdp-pass-all))
;; => #object[byte[] ...]  (16 bytes)

;; Check bytecode size
(count ((:body-fn xdp-pass-all)))
;; => 16  (2 instructions * 8 bytes)
```

---

## Part 3: with-bpf-script - Lifecycle Management

The `with-bpf-script` macro handles the complete lifecycle: create maps, load programs, attach, execute body, then automatically detach, unload, and close everything.

### Basic Syntax

```clojure
(require '[clj-ebpf.macros :refer [with-bpf-script]])

(with-bpf-script
  {:maps   [binding1 map-spec1, binding2 map-spec2]
   :progs  [binding1 prog-spec1, binding2 prog-spec2]
   :attach [attach-spec1, attach-spec2]}
  body...)
```

### Example 1: Simple XDP Attachment

```clojure
(defmap-spec counter-map
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 1)

(defprogram xdp-counter
  :type :xdp
  :body [(dsl/mov :r0 2)
         (dsl/exit-insn)])

(with-bpf-script
  {:maps   [counter counter-map]
   :progs  [prog xdp-counter]
   :attach [{:prog prog :type :xdp :target "lo"}]}

  (println "XDP program attached to loopback!")
  (println "Program FD:" (:fd prog))
  (println "Map FD:" (:fd counter))

  ;; Initialize and use the counter
  (bpf/map-update counter 0 0)
  (Thread/sleep 5000)
  (println "Counter value:" (bpf/map-lookup counter 0)))

;; Everything is automatically cleaned up here
```

### Example 2: Multiple Maps and Programs

```clojure
(defmap-spec stats-map
  :type :percpu-array
  :key-size 4
  :value-size 8
  :max-entries 16)

(defmap-spec config-map
  :type :array
  :key-size 4
  :value-size 4
  :max-entries 1)

(defprogram ingress-filter
  :type :xdp
  :body [(dsl/mov :r0 2) (dsl/exit-insn)])

(defprogram egress-monitor
  :type :tc
  :body [(dsl/mov :r0 0) (dsl/exit-insn)])

(with-bpf-script
  {:maps   [stats stats-map
            config config-map]
   :progs  [ingress ingress-filter
            egress egress-monitor]
   :attach [{:prog ingress :type :xdp :target "eth0"}
            {:prog egress :type :tc :target "eth0" :direction :egress}]}

  (println "Both programs attached!")
  (println "Stats map FD:" (:fd stats))
  (println "Config map FD:" (:fd config))

  ;; Use both maps
  (bpf/map-update config 0 1)  ; Enable feature

  (Thread/sleep 10000))
```

### Example 3: Kprobe Tracing

```clojure
(defprogram schedule-tracer
  :type :kprobe
  :body [(dsl/mov :r0 0)
         (dsl/exit-insn)])

(with-bpf-script
  {:progs  [tracer schedule-tracer]
   :attach [{:prog tracer :type :kprobe :function "schedule"}]}

  (println "Tracing kernel schedule() function...")
  (Thread/sleep 5000)
  (println "Done tracing!"))
```

### Example 4: Tracepoint Attachment

```clojure
(defprogram execve-tracer
  :type :tracepoint
  :body [(dsl/call 14)        ; get_current_pid_tgid
         (dsl/mov :r0 0)
         (dsl/exit-insn)])

(with-bpf-script
  {:progs  [tracer execve-tracer]
   :attach [{:prog tracer
             :type :tracepoint
             :category "syscalls"
             :event "sys_enter_execve"}]}

  (println "Tracing execve syscalls...")
  (Thread/sleep 10000))
```

---

## Part 4: Attachment Types Reference

### XDP Attachments

```clojure
{:prog binding
 :type :xdp
 :target "eth0"           ; Network interface
 :mode :skb               ; :skb (generic), :native, or :offload
 :flags 0}                ; Optional flags
```

### TC Attachments

```clojure
{:prog binding
 :type :tc
 :target "eth0"           ; Network interface
 :direction :ingress      ; :ingress or :egress
 :priority 1}             ; Filter priority
```

### Kprobe/Kretprobe Attachments

```clojure
;; Kprobe (function entry)
{:prog binding
 :type :kprobe
 :function "do_sys_open"}

;; Kretprobe (function exit)
{:prog binding
 :type :kretprobe
 :function "do_sys_open"}
```

### Tracepoint Attachments

```clojure
{:prog binding
 :type :tracepoint
 :category "syscalls"
 :event "sys_enter_read"}
```

### Uprobe/Uretprobe Attachments

```clojure
;; By symbol name
{:prog binding
 :type :uprobe
 :binary "/usr/bin/bash"
 :symbol "readline"}

;; By offset
{:prog binding
 :type :uprobe
 :binary "/usr/bin/myapp"
 :offset 0x1234}
```

### Cgroup Attachments

```clojure
;; Cgroup SKB (network)
{:prog binding
 :type :cgroup-skb
 :cgroup-path "/sys/fs/cgroup/my-container"
 :direction :ingress}     ; :ingress or :egress

;; Cgroup socket
{:prog binding
 :type :cgroup-sock
 :cgroup-path "/sys/fs/cgroup/my-container"}
```

### LSM Attachments

```clojure
{:prog binding
 :type :lsm
 :hook "bprm_check_security"}
```

---

## Part 5: Convenience Functions

For more control, use the convenience functions directly:

### load-defprogram

```clojure
(require '[clj-ebpf.macros :refer [load-defprogram]])

(defprogram my-prog :type :xdp :body [...])

(let [prog (load-defprogram my-prog)]
  (try
    ;; Use prog...
    (println "Loaded with FD:" (:fd prog))
    (finally
      (bpf/close-program prog))))
```

### create-defmap

```clojure
(require '[clj-ebpf.macros :refer [create-defmap]])

(defmap-spec my-map :type :hash :key-size 4 :value-size 4 :max-entries 100)

(let [m (create-defmap my-map)]
  (try
    ;; Use map...
    (bpf/map-update m 1 100)
    (println "Value:" (bpf/map-lookup m 1))
    (finally
      (bpf/close-map m))))
```

---

## Lab: Build a Packet Counter

Let's build a complete XDP packet counter using the macros.

### Step 1: Define the Map

```clojure
(ns my-packet-counter
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.macros :refer [defmap-spec defprogram with-bpf-script]]
            [clj-ebpf.dsl :as dsl]))

(defmap-spec packet-stats
  "Array to store packet statistics"
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 4)  ; [total, passed, dropped, bytes]
```

### Step 2: Define the Program

```clojure
(defprogram xdp-packet-counter
  "Count packets and pass them through"
  :type :xdp
  :license "GPL"
  :body [;; Just pass all packets for now
         ;; (A real counter would update the map)
         (dsl/mov :r0 2)      ; XDP_PASS
         (dsl/exit-insn)])
```

### Step 3: Run with Lifecycle Management

```clojure
(defn run-counter [interface duration-ms]
  (println "Starting packet counter on" interface)

  (with-bpf-script
    {:maps   [stats packet-stats]
     :progs  [counter xdp-packet-counter]
     :attach [{:prog counter :type :xdp :target interface :mode :skb}]}

    (println "XDP program attached!")
    (println "Program FD:" (:fd counter))
    (println "Stats map FD:" (:fd stats))

    ;; Initialize counters
    (doseq [i (range 4)]
      (bpf/map-update stats i 0))

    (println (str "\nCounting packets for " (/ duration-ms 1000) " seconds..."))
    (Thread/sleep duration-ms)

    ;; Read final stats
    (println "\n=== Results ===")
    (println "Total packets:" (bpf/map-lookup stats 0))
    (println "Passed:" (bpf/map-lookup stats 1))
    (println "Dropped:" (bpf/map-lookup stats 2))
    (println "Total bytes:" (bpf/map-lookup stats 3)))

  (println "\nCleanup complete!"))

;; Run it (requires root)
;; (run-counter "lo" 10000)
```

---

## Best Practices

### 1. Define Specs at Namespace Level

```clojure
;; Good: Top-level definitions
(defmap-spec my-map ...)
(defprogram my-prog ...)

;; Avoid: Inside functions
(defn setup []
  (defmap-spec temp-map ...))  ; Don't do this
```

### 2. Use Descriptive Names

The var name becomes the default BPF object name:

```clojure
;; Good: Descriptive
(defmap-spec tcp-connection-tracker ...)
(defprogram xdp-syn-flood-filter ...)

;; Avoid: Cryptic
(defmap-spec m1 ...)
(defprogram p ...)
```

### 3. Always Use with-bpf-script for Complete Setups

```clojure
;; Good: Automatic cleanup
(with-bpf-script {...}
  (do-work))

;; Risky: Manual cleanup required
(let [prog (load-defprogram my-prog)]
  (try
    (do-work)
    (finally
      (bpf/close-program prog))))
```

### 4. Use Verbose Logging During Development

```clojure
(defprogram debug-prog
  :type :xdp
  :opts {:log-level 2}  ; Verbose verifier output
  :body [...])
```

### 5. Document Your Programs

```clojure
(defprogram rate-limiter
  "Rate limit incoming connections to 1000/sec per source IP.

   Uses token bucket algorithm with:
   - Bucket size: 1000 tokens
   - Refill rate: 1000 tokens/sec

   Returns XDP_DROP for rate-limited packets."
  :type :xdp
  :body [...])
```

---

## Summary

| Macro | Purpose | Key Benefit |
|-------|---------|-------------|
| `defmap-spec` | Define map specifications | Reusable, named, with defaults |
| `defprogram` | Define program specifications | DSL body, automatic assembly |
| `with-bpf-script` | Lifecycle management | Automatic cleanup, attachment |

### When to Use Macros

- Quick scripts and experiments
- REPL-driven development
- Simple programs without dynamic map FD injection
- Learning and tutorials

### When to Use Lower-Level API

- Dynamic map references in programs
- Complex resource lifecycles
- Hot reloading programs
- Fine-grained control

---

## Next Steps

1. **Read the guide**: [docs/guides/macros.md](../docs/guides/macros.md) for comprehensive documentation
2. **Try examples**: [examples/macro_dsl.clj](../examples/macro_dsl.clj) for more patterns
3. **Explore DSL**: [Chapter 3: BPF Instructions](part-1-fundamentals/chapter-03/README.md) for DSL details
4. **Build applications**: [Part IV: Applications](part-4-applications/) for real-world examples

---

## Navigation

- **Home**: [Tutorial Home](README.md)
- **Next**: [Chapter 1: Introduction to eBPF](part-1-fundamentals/chapter-01/README.md)
- **Reference**: [Macros Guide](../docs/guides/macros.md)
