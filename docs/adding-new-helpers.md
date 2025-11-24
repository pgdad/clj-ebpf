# Adding New eBPF Helper Functions to clj-ebpf

This guide demonstrates how to extend clj-ebpf with new BPF helper functions using Clojure.

## Table of Contents

1. [Overview](#overview)
2. [Helper Function Structure](#helper-function-structure)
3. [Adding New Helpers](#adding-new-helpers)
4. [Using Custom Helpers](#using-custom-helpers)
5. [Complete Example](#complete-example)
6. [Best Practices](#best-practices)

## Overview

BPF helper functions are kernel functions that BPF programs can call to interact with the kernel. As new Linux kernel versions introduce new helpers, you can extend clj-ebpf to support them.

**Key Components:**
- **Helper Metadata**: Function signature, compatibility, and documentation
- **Helper Registry**: Central map of all available helpers
- **DSL Integration**: Using helpers in BPF programs
- **Query Functions**: Finding compatible helpers for your use case

## Helper Function Structure

Each helper is defined in the `helper-metadata` map in `src/clj_ebpf/helpers.clj`:

```clojure
(def helper-metadata
  {:helper-keyword
   {:id           123                           ; Unique helper ID from kernel
    :name         "bpf_helper_name"            ; Kernel function name
    :signature    {:return :type               ; Return type
                   :args [:arg1 :arg2]}        ; Argument types
    :min-kernel   "5.10"                       ; Minimum kernel version
    :prog-types   #{:xdp :kprobe :tracepoint}  ; Compatible program types (:all for all)
    :category     :network                      ; Functional category
    :description  "What this helper does"}})   ; Human-readable description
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `:id` | Integer | Helper function ID from Linux kernel (see `include/uapi/linux/bpf.h`) |
| `:name` | String | C function name as it appears in kernel |
| `:signature` | Map | Return type and argument types |
| `:min-kernel` | String | Minimum kernel version that supports this helper |
| `:prog-types` | Set or `:all` | BPF program types that can use this helper |
| `:category` | Keyword | Functional category for organization |
| `:description` | String | Brief explanation of what the helper does |

### Type Annotations

**Return Types:**
- `:void` - No return value
- `:long`, `:s64` - Signed 64-bit integer
- `:u64` - Unsigned 64-bit integer
- `:u32` - Unsigned 32-bit integer
- `:ptr` - Pointer (may be NULL)

**Argument Types:**
- `:ctx-ptr` - BPF program context pointer
- `:map-ptr` - BPF map pointer
- `:key-ptr`, `:value-ptr` - Key/value pointers
- `:buf-ptr`, `:data-ptr` - Buffer/data pointers
- `:size`, `:len` - Size/length values
- `:flags` - Flag bitmask
- `:u32`, `:u64`, `:long` - Integer values

### Categories

Common categories include:
- `:map` - Map operations
- `:network` - Networking (SKB, XDP)
- `:probe` - Memory probing
- `:trace` - Stack traces, profiling
- `:time` - Timing functions
- `:info` - Process/system information
- `:debug` - Debugging utilities
- `:socket` - Socket operations
- `:xdp` - XDP-specific
- `:perf` - Performance events
- `:ringbuf` - Ring buffer operations

## Adding New Helpers

### Step 1: Find Helper Information

Check the Linux kernel source for new helpers:

```bash
# View BPF helper definitions
cat /usr/include/linux/bpf.h | grep "FN(bpf_"

# Or check kernel source
git clone https://github.com/torvalds/linux
grep -r "BPF_CALL_" linux/kernel/bpf/
```

### Step 2: Add to Helper Metadata

Edit `src/clj_ebpf/helpers.clj` and add your helper:

```clojure
(def helper-metadata
  {
   ;; ... existing helpers ...

   ;; New helper for kernel 6.3+
   :ktime-get-real-ns
   {:id 212
    :name "bpf_ktime_get_real_ns"
    :signature {:return :u64 :args []}
    :min-kernel "6.3"
    :prog-types :all
    :category :time
    :description "Get real (wall-clock) time in nanoseconds since Unix epoch."}

   :skb-set-tstamp
   {:id 213
    :name "bpf_skb_set_tstamp"
    :signature {:return :long :args [:skb-ptr :tstamp :tstamp-type]}
    :min-kernel "6.3"
    :prog-types #{:sched-cls :sched-act}
    :category :network
    :description "Set packet timestamp with specific type (mono/real/delivery)."}

   ;; New networking helper
   :skb-get-nlattr
   {:id 214
    :name "bpf_skb_get_nlattr"
    :signature {:return :long :args [:skb-ptr :attr-type :offset-ptr]}
    :min-kernel "6.4"
    :prog-types #{:sched-cls :sched-act}
    :category :network
    :description "Get netlink attribute from skb at specified offset."}

   ;; New tracing helper
   :get-task-exe-file
   {:id 215
    :name "bpf_get_task_exe_file"
    :signature {:return :ptr :args [:task-ptr]}
    :min-kernel "6.4"
    :prog-types #{:kprobe :tracepoint :lsm}
    :category :trace
    :description "Get executable file pointer from task_struct."}
   })
```

### Step 3: Add to DSL (Optional)

If you want DSL support for easier access, add to `src/clj_ebpf/dsl.clj`:

```clojure
(def bpf-helpers
  "Common BPF helper function IDs"
  {:map-lookup-elem        1
   :map-update-elem        2
   ;; ... existing helpers ...
   :ktime-get-real-ns      212  ; Your new helper
   :skb-set-tstamp         213
   :skb-get-nlattr         214
   :get-task-exe-file      215
   })
```

## Using Custom Helpers

### Querying Helper Information

```clojure
(require '[clj-ebpf.helpers :as helpers])

;; Get information about a specific helper
(helpers/get-helper-info :ktime-get-real-ns)
;; => {:id 212, :name "bpf_ktime_get_real_ns", ...}

;; Get just the ID
(helpers/get-helper-id :ktime-get-real-ns)
;; => 212

;; List all helpers in a category
(helpers/helpers-by-category :time)
;; => ([:ktime-get-ns {...}] [:jiffies64 {...}] [:ktime-get-real-ns {...}] ...)

;; List all categories
(helpers/list-categories)
;; => (:map :probe :time :network :debug ...)

;; Get helpers compatible with a program type
(helpers/available-helpers :xdp)
;; => All helpers that work with XDP programs

;; Check if helper is compatible
(helpers/helper-compatible? :ktime-get-real-ns :xdp "6.3")
;; => true

;; Print detailed information
(helpers/print-helper-info :ktime-get-real-ns)
;; Prints formatted documentation
```

### Using in BPF Programs via DSL

```clojure
(require '[clj-ebpf.dsl :as dsl])

;; Call the new helper using its ID
(def get-wall-time-program
  (dsl/assemble [(dsl/call 212)  ; Call bpf_ktime_get_real_ns
                 (dsl/exit-insn)]))

;; Or use the helper map
(def get-wall-time-program-2
  (dsl/assemble [(dsl/call (:ktime-get-real-ns dsl/bpf-helpers))
                 (dsl/exit-insn)]))
```

### Using in Compiled BPF Programs

When compiling C code:

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_real_ns();  // Use new helper

    // Store timestamp with real wall-clock time
    bpf_printk("File opened at epoch time: %llu\\n", ts);

    return 0;
}
```

Then load with clj-ebpf:

```clojure
(require '[clj-ebpf.core :as bpf])

;; Load compiled program that uses new helper
(def prog-fd (bpf/load-program-from-elf "trace_open.o" "trace_open"))
```

## Complete Example

### Example 1: Adding a New Timing Helper

```clojure
;; File: src/clj_ebpf/helpers.clj
;; Add to helper-metadata map:

:ktime-get-real-ns
{:id 212
 :name "bpf_ktime_get_real_ns"
 :signature {:return :u64 :args []}
 :min-kernel "6.3"
 :prog-types :all
 :category :time
 :description "Get real (wall-clock) time in nanoseconds since Unix epoch."}
```

**Usage:**

```clojure
(require '[clj-ebpf.helpers :as helpers]
         '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.core :as bpf])

;; Query the helper
(def helper-info (helpers/get-helper-info :ktime-get-real-ns))
(println "Helper ID:" (:id helper-info))
(println "Requires kernel:" (:min-kernel helper-info))

;; Use in BPF program
(def timestamp-program
  (dsl/assemble [;; Get wall-clock timestamp
                 (dsl/call 212)
                 ;; r0 now contains nanoseconds since Unix epoch
                 ;; Store to map or process...
                 (dsl/exit-insn)]))

;; Load and use
(bpf/with-program [prog {:prog-type :kprobe
                         :insns timestamp-program
                         :license "GPL"
                         :prog-name "real_time_tracer"}]
  (bpf/attach-kprobe prog {:function "do_sys_open"}))
```

### Example 2: Adding a Network Helper

```clojure
;; Add to helper-metadata:

:skb-set-tstamp
{:id 213
 :name "bpf_skb_set_tstamp"
 :signature {:return :long :args [:skb-ptr :tstamp :tstamp-type]}
 :min-kernel "6.3"
 :prog-types #{:sched-cls :sched-act}
 :category :network
 :description "Set packet timestamp with specific type (mono/real/delivery)."}
```

**Usage in TC Program:**

```clojure
(require '[clj-ebpf.dsl :as dsl]
         '[clj-ebpf.tc :as tc])

;; Constants for timestamp types
(def BPF_SKB_TSTAMP_DELIVERY 0)
(def BPF_SKB_TSTAMP_SCHED 1)

;; TC program that sets packet delivery timestamp
(def set-delivery-time
  (dsl/assemble [;; r1 = skb (from context)
                 ;; Get current monotonic time
                 (dsl/call (:ktime-get-ns dsl/bpf-helpers))
                 ;; r2 = timestamp value
                 (dsl/mov-reg :r2 :r0)
                 ;; r3 = timestamp type (delivery)
                 (dsl/mov :r3 BPF_SKB_TSTAMP_DELIVERY)
                 ;; r1 = skb (context passed in r1)
                 ;; Call bpf_skb_set_tstamp(skb, ts, type)
                 (dsl/call 213)
                 ;; Return TC_ACT_OK
                 (dsl/mov :r0 (:ok dsl/tc-action))
                 (dsl/exit-insn)]))

;; Load and attach to interface
(def prog-fd (tc/load-tc-program set-delivery-time :sched-cls
                                 :prog-name "set_pkt_tstamp"
                                 :license "GPL"))

(tc/attach-tc-filter "eth0" prog-fd :ingress)
```

### Example 3: Adding Multiple Related Helpers

```clojure
;; Add a set of helpers for a new feature (e.g., new cgroup helpers)

:cgroup-set-ancestor-cgroup-id
{:id 216
 :name "bpf_cgroup_set_ancestor_cgroup_id"
 :signature {:return :long :args [:cgroup-ptr :level :id]}
 :min-kernel "6.5"
 :prog-types #{:cgroup-skb :sock-ops}
 :category :cgroup
 :description "Set ancestor cgroup ID at specified level."}

:cgroup-get-current-level
{:id 217
 :name "bpf_cgroup_get_current_level"
 :signature {:return :long :args []}
 :min-kernel "6.5"
 :prog-types :all
 :category :cgroup
 :description "Get current cgroup hierarchy level."}
```

**Usage:**

```clojure
(require '[clj-ebpf.helpers :as helpers])

;; Find all cgroup-related helpers
(def cgroup-helpers (helpers/helpers-by-category :cgroup))

(doseq [[k v] cgroup-helpers]
  (println (format "%s (ID: %d) - %s"
                   (:name v)
                   (:id v)
                   (:description v))))

;; Check kernel version compatibility
(def my-kernel "6.5")
(def available (helpers/available-helpers :cgroup-skb my-kernel))

(println "Available cgroup helpers for kernel" my-kernel ":")
(doseq [[k v] available]
  (println " -" (:name v)))
```

## Best Practices

### 1. Verify Helper ID

Always verify the helper ID matches the kernel source:

```bash
# Check kernel headers
grep -n "BPF_FUNC_ktime_get_real_ns" /usr/include/linux/bpf.h
grep -A2 "enum bpf_func_id" /usr/include/linux/bpf.h
```

### 2. Document Thoroughly

Include comprehensive metadata:

```clojure
:my-new-helper
{:id 999
 :name "bpf_my_new_helper"
 :signature {:return :long :args [:ctx-ptr :flags]}
 :min-kernel "6.x"
 :prog-types #{:xdp :sched-cls}
 :category :network
 :description "Detailed description including:
                - What arguments mean
                - Return value semantics (0=success, <0=error)
                - Any special requirements or restrictions
                - Example use cases"}
```

### 3. Check Compatibility

Before using a helper, verify compatibility:

```clojure
(defn safe-use-helper [helper-key prog-type kernel-version]
  (if (helpers/helper-compatible? helper-key prog-type kernel-version)
    (do
      (println "✓ Helper" helper-key "is compatible")
      (helpers/get-helper-id helper-key))
    (do
      (println "✗ Helper" helper-key "not available")
      nil)))

;; Usage
(when-let [helper-id (safe-use-helper :ktime-get-real-ns :xdp "6.3")]
  ;; Use the helper
  (dsl/call helper-id))
```

### 4. Test with Kernel Version Detection

```clojure
(require '[clj-ebpf.core :as bpf]
         '[clj-ebpf.helpers :as helpers])

(defn build-program-with-helpers [prog-type]
  (let [kernel-ver (bpf/get-kernel-version)
        available (helpers/available-helpers prog-type kernel-ver)]
    (println "Building program with" (count available) "available helpers")
    ;; Build program using only available helpers
    ))
```

### 5. Organize by Kernel Version

Group helpers by kernel version for easy reference:

```clojure
;; helpers.clj
(def helpers-by-kernel
  "Helpers organized by kernel version"
  {"6.3" #{:ktime-get-real-ns :skb-set-tstamp}
   "6.4" #{:skb-get-nlattr :get-task-exe-file}
   "6.5" #{:cgroup-set-ancestor-cgroup-id}})

(defn helpers-for-kernel [min-version]
  (filter #(<= (compare (:min-kernel (second %)) min-version) 0)
          helper-metadata))
```

### 6. Create Helper Wrappers

Create high-level wrappers for common patterns:

```clojure
;; File: src/clj_ebpf/helpers_ext.clj
(ns clj-ebpf.helpers-ext
  "High-level helper function wrappers"
  (:require [clj-ebpf.helpers :as helpers]
            [clj-ebpf.dsl :as dsl]))

(defn call-helper
  "Generate DSL instructions to call a helper by keyword"
  [helper-key & args]
  (if-let [helper-id (helpers/get-helper-id helper-key)]
    (concat
      ;; Setup arguments in registers r1-r5
      (mapcat (fn [reg-idx arg]
                [(dsl/mov (keyword (str "r" (inc reg-idx))) arg)])
              (range) args)
      ;; Call the helper
      [(dsl/call helper-id)])
    (throw (ex-info "Unknown helper" {:helper helper-key}))))

;; Usage
(def my-program
  (dsl/assemble
    (concat
      ;; Get real time: r0 = bpf_ktime_get_real_ns()
      (call-helper :ktime-get-real-ns)
      ;; Use timestamp in r0
      [(dsl/exit-insn)])))
```

### 7. Version-Aware Programs

Build programs that adapt to available helpers:

```clojure
(defn build-timestamp-program [kernel-version]
  (let [use-real-time? (helpers/helper-compatible?
                         :ktime-get-real-ns :xdp kernel-version)]
    (dsl/assemble
      (concat
        ;; Use real time if available, otherwise monotonic
        (if use-real-time?
          [(dsl/call 212)]  ; bpf_ktime_get_real_ns
          [(dsl/call 5)])   ; bpf_ktime_get_ns
        [(dsl/exit-insn)]))))
```

## Testing New Helpers

### Unit Test Example

```clojure
;; File: test/clj_ebpf/helpers_test.clj
(ns clj-ebpf.helpers-test
  (:require [clojure.test :refer :all]
            [clj-ebpf.helpers :as helpers]))

(deftest test-new-helper-metadata
  (testing "ktime-get-real-ns helper metadata"
    (let [info (helpers/get-helper-info :ktime-get-real-ns)]
      (is (= 212 (:id info)))
      (is (= "bpf_ktime_get_real_ns" (:name info)))
      (is (= :u64 (:return (:signature info))))
      (is (= "6.3" (:min-kernel info)))
      (is (= :all (:prog-types info)))
      (is (= :time (:category info))))))

(deftest test-helper-compatibility
  (testing "Helper compatibility checks"
    (is (helpers/helper-compatible? :ktime-get-real-ns :xdp "6.3"))
    (is (not (helpers/helper-compatible? :ktime-get-real-ns :xdp "6.2")))
    (is (helpers/helper-compatible? :ktime-get-real-ns :kprobe "6.5"))))

(deftest test-helpers-by-category
  (testing "Retrieve helpers by category"
    (let [time-helpers (helpers/helpers-by-category :time)]
      (is (some #(= :ktime-get-real-ns (first %)) time-helpers))
      (is (some #(= :ktime-get-ns (first %)) time-helpers)))))
```

## Summary

Adding new eBPF helper functions to clj-ebpf involves:

1. **Find Helper Information**: Check kernel source for ID, signature, and requirements
2. **Add Metadata**: Define helper in `helper-metadata` map with complete information
3. **Update DSL** (optional): Add to `bpf-helpers` map for easier access
4. **Query and Use**: Use query functions to check compatibility and get helper IDs
5. **Test**: Verify helper works with different program types and kernel versions

The clj-ebpf helper system provides:
- ✅ Type-safe helper definitions
- ✅ Compatibility checking
- ✅ Documentation generation
- ✅ Category-based organization
- ✅ Kernel version awareness
- ✅ Introspection and discovery

This makes it easy to extend clj-ebpf as new helpers are added to the Linux kernel while maintaining backward compatibility and providing rich metadata for users.
