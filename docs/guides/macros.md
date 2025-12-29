# High-Level Declarative Macros

This guide covers the high-level declarative macros that reduce boilerplate and make clj-ebpf more idiomatic for Clojure developers.

## Overview

The macros module provides three main constructs:

1. **`defmap-spec`** - Define reusable BPF map specifications
2. **`defprogram`** - Define BPF programs declaratively with DSL instructions
3. **`with-bpf-script`** - Lifecycle management for complete BPF setups

## Why Use These Macros?

Traditional BPF programming in clj-ebpf requires verbose setup:

```clojure
;; Traditional approach - lots of boilerplate
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

With the declarative macros:

```clojure
;; Declarative approach - 60% less code
(defmap-spec my-map
  :type :hash
  :key-size 4
  :value-size 4
  :max-entries 1000)

(defprogram my-prog
  :type :xdp
  :body [(dsl/mov :r0 2)
         (dsl/exit-insn)])

(with-bpf-script
  {:maps [m my-map]
   :progs [p my-prog]
   :attach [{:prog p :type :xdp :target "lo"}]}
  ;; Your code here - cleanup is automatic
  )
```

## defmap-spec

Define a reusable BPF map specification.

### Syntax

```clojure
(defmap-spec name
  :type map-type
  :key-size key-size
  :value-size value-size
  :max-entries max-entries
  ;; Optional parameters
  :flags map-flags
  :map-name "custom_name"
  :key-serializer serialize-fn
  :key-deserializer deserialize-fn
  :value-serializer serialize-fn
  :value-deserializer deserialize-fn)
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `:type` | Yes | - | Map type: `:hash`, `:array`, `:lru-hash`, `:percpu-hash`, `:percpu-array`, `:lru-percpu-hash`, `:stack`, `:queue`, `:ringbuf`, `:lpm-trie` |
| `:key-size` | Yes | - | Size of key in bytes |
| `:value-size` | Yes | - | Size of value in bytes |
| `:max-entries` | Yes | - | Maximum number of entries |
| `:flags` | No | 0 | Map creation flags |
| `:map-name` | No | var name | Name string for the map |
| `:key-serializer` | No | `int->bytes` | Function to serialize keys |
| `:key-deserializer` | No | `bytes->int` | Function to deserialize keys |
| `:value-serializer` | No | `int->bytes` | Function to serialize values |
| `:value-deserializer` | No | `bytes->int` | Function to deserialize values |

### Examples

```clojure
;; Simple hash map
(defmap-spec event-map
  :type :hash
  :key-size 4
  :value-size 16
  :max-entries 10000)

;; Array map with custom name
(defmap-spec counter-array
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 256
  :map-name "packet_counters")

;; Per-CPU map for high-performance counters
(defmap-spec percpu-stats
  :type :percpu-array
  :key-size 4
  :value-size 8
  :max-entries 16)

;; Ring buffer for events
(defmap-spec event-ringbuf
  :type :ringbuf
  :key-size 0
  :value-size 0
  :max-entries (* 256 1024))  ; 256KB
```

### Usage

```clojure
;; Create map manually
(let [m (bpf/create-defmap event-map)]
  (try
    (bpf/map-update m 1 some-value)
    (finally
      (bpf/close-map m))))

;; Or use with-bpf-script for automatic lifecycle
(with-bpf-script {:maps [m event-map]}
  (bpf/map-update m 1 some-value))
```

## defprogram

Define a BPF program declaratively with DSL instructions.

### Syntax

```clojure
(defprogram name
  :type prog-type
  :body [instructions...]
  ;; Optional parameters
  :license "GPL"
  :opts {:log-level 1
         :prog-name "custom_name"})
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `:type` | Yes | - | Program type: `:kprobe`, `:kretprobe`, `:uprobe`, `:uretprobe`, `:tracepoint`, `:raw-tracepoint`, `:xdp`, `:tc`, `:cgroup-skb`, `:cgroup-sock`, `:lsm`, `:fentry`, `:fexit`, `:socket-filter` |
| `:body` | Yes | - | Vector of DSL instructions |
| `:license` | No | "GPL" | License string |
| `:opts` | No | `{}` | Additional options |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `:log-level` | 1 | Verifier log verbosity (0=off, 1=basic, 2=verbose) |
| `:prog-name` | var name | Program name for debugging |

### Examples

```clojure
;; XDP program that passes all packets
(defprogram xdp-pass-all
  :type :xdp
  :body [(dsl/mov :r0 2)      ; XDP_PASS
         (dsl/exit-insn)])

;; XDP program that drops all packets
(defprogram xdp-drop-all
  :type :xdp
  :body [(dsl/mov :r0 1)      ; XDP_DROP
         (dsl/exit-insn)])

;; Kprobe that gets PID
(defprogram pid-tracer
  :type :kprobe
  :opts {:log-level 2}
  :body [(dsl/call 14)            ; get_current_pid_tgid
         (dsl/mov-reg :r6 :r0)    ; save result
         (dsl/mov :r0 0)
         (dsl/exit-insn)])

;; Complex XDP with bounds checking
(defprogram xdp-with-check
  :type :xdp
  :body [;; Save context
         (dsl/mov-reg :r6 :r1)
         ;; Load data pointers
         (dsl/ldx :w :r2 :r6 0)
         (dsl/ldx :w :r3 :r6 4)
         ;; Bounds check
         (dsl/mov-reg :r4 :r2)
         (dsl/add :r4 14)
         (dsl/jmp-reg :jgt :r4 :r3 2)
         ;; Pass
         (dsl/mov :r0 2)
         (dsl/exit-insn)
         ;; Also pass (bounds check failed)
         (dsl/mov :r0 2)
         (dsl/exit-insn)])
```

### Usage

```clojure
;; Load program manually
(let [prog (bpf/load-defprogram xdp-pass-all)]
  (try
    ;; Use program
    (finally
      (bpf/close-program prog))))

;; Or use with-bpf-script
(with-bpf-script {:progs [p xdp-pass-all]}
  ;; Use program
  )
```

### Inspecting Programs

```clojure
;; Get program metadata
(:prog-type xdp-pass-all)     ; => :xdp
(:license xdp-pass-all)        ; => "GPL"
(:prog-name xdp-pass-all)      ; => "xdp-pass-all"

;; Get assembled bytecode
((:body-fn xdp-pass-all))      ; => byte-array

;; Inspect original body
(:body-source xdp-pass-all)    ; => quoted body form
```

## with-bpf-script

Lifecycle management macro that handles creation, attachment, and cleanup of BPF resources.

### Syntax

```clojure
(with-bpf-script
  {:maps [binding1 map-spec1
          binding2 map-spec2]
   :progs [binding1 prog-spec1
           binding2 prog-spec2]
   :attach [attach-spec1
            attach-spec2]}
  body...)
```

### Configuration

| Key | Description |
|-----|-------------|
| `:maps` | Vector of `[binding map-spec]` pairs |
| `:progs` | Vector of `[binding prog-spec]` pairs |
| `:attach` | Vector of attachment specifications |

### Attachment Specifications

Each attachment spec is a map with:

| Key | Required | Description |
|-----|----------|-------------|
| `:prog` | Yes | Binding name of program to attach |
| `:type` | Yes | Attachment type |
| `:target` | Usually | Target (interface, function, etc.) |

### Attachment Types

#### XDP Attachments

```clojure
{:prog p
 :type :xdp
 :target "eth0"
 :flags 0           ; Optional
 :mode :skb}        ; Optional: :skb, :native, or :offload
```

#### Kprobe Attachments

```clojure
{:prog p
 :type :kprobe
 :function "schedule"}

;; For kretprobe
{:prog p
 :type :kretprobe
 :function "schedule"}
```

#### Tracepoint Attachments

```clojure
{:prog p
 :type :tracepoint
 :category "sched"
 :event "sched_switch"}
```

#### Uprobe Attachments

```clojure
{:prog p
 :type :uprobe
 :binary "/usr/bin/bash"
 :symbol "readline"}

;; With offset
{:prog p
 :type :uprobe
 :binary "/usr/bin/bash"
 :offset 0x12345}
```

#### Cgroup Attachments

```clojure
;; SKB
{:prog p
 :type :cgroup-skb
 :cgroup-path "/sys/fs/cgroup/my-group"
 :direction :ingress}  ; or :egress

;; Sock
{:prog p
 :type :cgroup-sock
 :cgroup-path "/sys/fs/cgroup/my-group"}
```

#### LSM Attachments

```clojure
{:prog p
 :type :lsm
 :hook "bprm_check_security"}
```

### Complete Example

```clojure
(ns my-xdp-app
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.macros :refer [defprogram defmap-spec with-bpf-script]]
            [clj-ebpf.dsl :as dsl]))

;; Define map for packet counter
(defmap-spec packet-counter
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 1)

;; Define XDP program
(defprogram count-packets
  :type :xdp
  :body [(dsl/mov :r0 2)      ; XDP_PASS
         (dsl/exit-insn)])

(defn run-counter []
  (with-bpf-script
    {:maps   [counter packet-counter]
     :progs  [prog count-packets]
     :attach [{:prog prog :type :xdp :target "lo"}]}

    (println "XDP attached to loopback")
    (println "Counter FD:" (:fd counter))
    (println "Program FD:" (:fd prog))

    ;; Initialize counter
    (bpf/map-update counter 0 0)

    ;; Run for 10 seconds
    (println "Counting packets for 10 seconds...")
    (Thread/sleep 10000)

    ;; Read final count
    (println "Total packets:" (bpf/map-lookup counter 0)))

  ;; All resources automatically cleaned up here
  (println "Done!"))
```

## When to Use These Macros

### Good Use Cases

1. **Quick scripts and experiments** - Rapid prototyping in the REPL
2. **Simple programs** - Programs that don't need dynamic map FD injection
3. **Standardized setups** - When you have a standard pattern you reuse
4. **Learning/Tutorials** - Reduces cognitive load for newcomers

### When to Use Lower-Level API

1. **Dynamic map references** - Programs that embed map FDs at assembly time
2. **Complex lifecycles** - When you need fine-grained resource control
3. **Multiple attachment points** - When one program attaches to many targets
4. **Hot reloading** - When you need to update programs without full teardown

## Best Practices

1. **Define specs at namespace level** - Use `defprogram` and `defmap-spec` at the top level for clarity
2. **Use descriptive names** - The var name becomes the default BPF object name
3. **Always use `with-bpf-script` for complete setups** - It ensures proper cleanup
4. **Check program bytecode** - Use `(:body-fn prog-spec)` to verify assembly
5. **Set appropriate log levels** - Use `:log-level 2` in opts during development

## API Reference

### Macros

- `defmap-spec` - Define map specification
- `defprogram` - Define program specification
- `with-bpf-script` - Lifecycle management

### Functions

- `load-defprogram` - Load a program from spec
- `create-defmap` - Create a map from spec

## See Also

- [examples/macro_dsl.clj](../../examples/macro_dsl.clj) - Comprehensive examples
- [examples/simple_kprobe.clj](../../examples/simple_kprobe.clj) - Comparison with traditional approach
- [BPF DSL Guide](./dsl.md) - DSL instruction reference
