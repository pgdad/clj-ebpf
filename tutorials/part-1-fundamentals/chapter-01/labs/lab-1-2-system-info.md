# Lab 1.2: System Information

**Objective**: Query system capabilities and eBPF features

**Duration**: 30 minutes

## Overview

In this lab, you'll learn how to query your system's eBPF capabilities, kernel features, and available helper functions. Understanding your system's capabilities is crucial for writing portable eBPF programs.

## What You'll Learn

- How to query kernel version and features
- How to check BPF filesystem status
- How to discover available helper functions
- How to check architecture and system information
- How to verify eBPF feature support

## Theory

### Kernel Version

eBPF features are tied to kernel versions:
- **3.18**: Basic BPF support
- **4.1**: BPF maps, helper functions
- **4.4**: Tail calls, array maps
- **4.7**: Tracepoint support
- **5.8**: CAP_BPF capability, BTF improvements
- **5.10**: Ring buffers, sleepable BPF
- **6.0+**: Enhanced features (signed modules, etc.)

### BPF Filesystem

The BPF filesystem (`/sys/fs/bpf`) provides:
- Persistence for BPF objects (maps, programs)
- Pin/unpin operations for sharing between processes
- Inspection of loaded BPF programs

### Helper Functions

Helper functions are kernel-provided APIs for BPF programs. Availability depends on:
- Kernel version
- Program type
- Kernel configuration

### System Architecture

Understanding your architecture (x86_64, ARM64) is important for:
- Instruction encoding differences
- Register availability
- Performance characteristics

## Implementation

### Step 1: Create the Project

Create `lab-1-2.clj`:
```clojure
(ns lab-1-2-system-info
  "Lab 1.2: System Information - Query eBPF capabilities"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.java.io :as io]))

(defn check-bpf-filesystem []
  "Check if BPF filesystem is mounted"
  (let [bpf-fs-path "/sys/fs/bpf"]
    (if (.exists (io/file bpf-fs-path))
      {:mounted true :path bpf-fs-path}
      {:mounted false :path bpf-fs-path})))

(defn format-kernel-version [version]
  "Format kernel version as human-readable string"
  (let [major (bit-shift-right (bit-and version 0xFF0000) 16)
        minor (bit-shift-right (bit-and version 0x00FF00) 8)
        patch (bit-and version 0x0000FF)]
    (format "%d.%d.%d" major minor patch)))

(defn check-kernel-features [kernel-version]
  "Check which eBPF features are available based on kernel version"
  (let [version-hex kernel-version
        features {:basic-bpf (>= version-hex 0x031200)       ; 3.18
                  :bpf-maps (>= version-hex 0x040100)        ; 4.1
                  :tail-calls (>= version-hex 0x040400)      ; 4.4
                  :tracepoints (>= version-hex 0x040700)     ; 4.7
                  :xdp (>= version-hex 0x040800)            ; 4.8
                  :cgroup-bpf (>= version-hex 0x040A00)     ; 4.10
                  :btf (>= version-hex 0x040E00)            ; 4.14
                  :cap-bpf (>= version-hex 0x050800)        ; 5.8
                  :ringbuf (>= version-hex 0x050800)        ; 5.8
                  :sleepable-bpf (>= version-hex 0x050A00)  ; 5.10
                  :lsm-bpf (>= version-hex 0x050700)}]      ; 5.7
    features))

(defn display-helper-summary []
  "Display summary of available helper functions"
  (let [all-helpers bpf/helper-metadata
        by-category (group-by #(get-in (val %) [:category]) all-helpers)
        categories [:map :probe :time :process :cpu :stack :perf :ringbuf
                   :debug :control :cgroup :sync :util :network :socket
                   :lsm :security]]
    (println "\nHelper Functions by Category:")
    (println "-----------------------------")
    (doseq [cat categories]
      (let [helpers (get by-category cat [])]
        (when (seq helpers)
          (println (format "  %-12s: %3d helpers" (name cat) (count helpers))))))
    (println (format "\n  Total: %d helpers" (count all-helpers)))))

(defn display-sample-helpers []
  "Display details for some common helper functions"
  (println "\nSample Helper Functions:")
  (println "------------------------")
  (let [sample-helpers [:map-lookup-elem :get-current-pid-tgid
                       :ktime-get-ns :probe-read-kernel
                       :perf-event-output :ringbuf-output]]
    (doseq [helper-key sample-helpers]
      (when-let [info (bpf/get-helper-info helper-key)]
        (println (format "\n%s (ID: %d)" (:name info) (:id info)))
        (println (format "  Min Kernel: %s" (:min-kernel info)))
        (println (format "  Category: %s" (name (:category info))))
        (println (format "  %s" (:description info)))))))

(defn -main []
  (println "=== Lab 1.2: System Information ===\n")

  ;; Step 1: Initialize and get kernel version
  (println "Step 1: Querying kernel version...")
  (let [init-result (bpf/init!)
        kernel-version (:kernel-version init-result)]
    (println "Kernel version (hex):" (format "0x%06x" kernel-version))
    (println "Kernel version:" (format-kernel-version kernel-version))

    ;; Step 2: Check BPF filesystem
    (println "\nStep 2: Checking BPF filesystem...")
    (let [fs-info (check-bpf-filesystem)]
      (if (:mounted fs-info)
        (println (format "✓ BPF filesystem mounted at %s" (:path fs-info)))
        (println (format "✗ BPF filesystem NOT mounted at %s" (:path fs-info)))))

    ;; Step 3: Check architecture
    (println "\nStep 3: Checking system architecture...")
    (let [arch (utils/get-arch)]
      (println "Architecture:" (name arch))
      (println "Architecture value:" (utils/arch-value arch))
      (case arch
        :x86-64 (println "✓ x86-64 architecture (amd64)")
        :aarch64 (println "✓ ARM64 architecture (aarch64)")
        (println "✓ Other architecture")))

    ;; Step 4: Check eBPF features
    (println "\nStep 4: Checking eBPF feature support...")
    (let [features (check-kernel-features kernel-version)]
      (println "\nAvailable Features:")
      (doseq [[feature available?] (sort-by first features)]
        (println (format "  %-20s: %s"
                        (name feature)
                        (if available? "✓" "✗")))))

    ;; Step 5: Query helper functions
    (println "\nStep 5: Querying helper functions...")
    (display-helper-summary)
    (display-sample-helpers)

    ;; Step 6: Check specific capabilities
    (println "\nStep 6: Checking specific capabilities...")

    ;; Check if we can load a simple program
    (try
      (let [test-prog (bpf/assemble [(bpf/mov :r0 0) (bpf/exit-insn)])
            prog-fd (bpf/load-program test-prog :socket-filter)]
        (println "✓ Can load BPF programs")
        (bpf/close-program prog-fd))
      (catch Exception e
        (println "✗ Cannot load BPF programs:" (.getMessage e))))

    ;; Check helper availability for different program types
    (println "\nHelper Availability by Program Type:")
    (let [prog-types [:socket-filter :kprobe :tracepoint :xdp :perf-event
                     :cgroup-skb :cgroup-sock :lsm]
          sample-helper :map-lookup-elem]
      (doseq [prog-type prog-types]
        (let [available? (bpf/helper-compatible? sample-helper prog-type kernel-version)]
          (println (format "  %-20s: %s"
                          (name prog-type)
                          (if available? "✓" "✗")))))))

  (println "\n=== Lab 1.2 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-01/labs
clojure -M lab-1-2.clj
```

### Expected Output

```
=== Lab 1.2: System Information ===

Step 1: Querying kernel version...
Kernel version (hex): 0x050f00
Kernel version: 5.15.0

Step 2: Checking BPF filesystem...
✓ BPF filesystem mounted at /sys/fs/bpf

Step 3: Checking system architecture...
Architecture: x86-64
Architecture value: 62
✓ x86-64 architecture (amd64)

Step 4: Checking eBPF feature support...

Available Features:
  basic-bpf           : ✓
  bpf-maps            : ✓
  btf                 : ✓
  cap-bpf             : ✓
  cgroup-bpf          : ✓
  lsm-bpf             : ✓
  ringbuf             : ✓
  sleepable-bpf       : ✓
  tail-calls          : ✓
  tracepoints         : ✓
  xdp                 : ✓

Step 5: Querying helper functions...

Helper Functions by Category:
-----------------------------
  map         :  25 helpers
  probe       :  18 helpers
  time        :   5 helpers
  process     :  12 helpers
  cpu         :   6 helpers
  stack       :   8 helpers
  perf        :  10 helpers
  ringbuf     :   6 helpers
  debug       :   4 helpers
  control     :   9 helpers
  cgroup      :  15 helpers
  sync        :   3 helpers
  util        :  22 helpers
  network     :  35 helpers
  socket      :  18 helpers
  lsm         :   8 helpers
  security    :   6 helpers

  Total: 210 helpers

Sample Helper Functions:
------------------------

bpf_map_lookup_elem (ID: 1)
  Min Kernel: 3.18
  Category: map
  Lookup map element by key. Returns pointer to value or NULL.

bpf_get_current_pid_tgid (ID: 14)
  Min Kernel: 4.2
  Category: process
  Get current task's PID and TGID.

bpf_ktime_get_ns (ID: 5)
  Min Kernel: 4.1
  Category: time
  Get time since boot in nanoseconds.

bpf_probe_read_kernel (ID: 113)
  Min Kernel: 5.5
  Category: probe
  Safely read from kernel memory.

bpf_perf_event_output (ID: 25)
  Min Kernel: 4.4
  Category: perf
  Output data to perf event buffer.

bpf_ringbuf_output (ID: 130)
  Min Kernel: 5.8
  Category: ringbuf
  Output data to ring buffer.

Step 6: Checking specific capabilities...
✓ Can load BPF programs

Helper Availability by Program Type:
  socket-filter       : ✓
  kprobe              : ✓
  tracepoint          : ✓
  xdp                 : ✓
  perf-event          : ✓
  cgroup-skb          : ✓
  cgroup-sock         : ✓
  lsm                 : ✓

=== Lab 1.2 Complete! ===
```

## Understanding the Code

### Kernel Version Parsing

```clojure
(defn format-kernel-version [version]
  (let [major (bit-shift-right (bit-and version 0xFF0000) 16)
        minor (bit-shift-right (bit-and version 0x00FF00) 8)
        patch (bit-and version 0x0000FF)]
    (format "%d.%d.%d" major minor patch)))
```

The kernel version is encoded as a 32-bit integer:
- Bits 16-23: Major version
- Bits 8-15: Minor version
- Bits 0-7: Patch version

Example: `0x050f00` = 5.15.0

### Feature Detection

```clojure
(defn check-kernel-features [kernel-version]
  (let [features {:basic-bpf (>= version-hex 0x031200)
                  :bpf-maps (>= version-hex 0x040100)
                  ;; ... more features
                  }]
    features))
```

This checks kernel version against known feature introduction versions, allowing you to conditionally use features.

### Helper Function Queries

```clojure
;; Get all helpers in a category
(bpf/helpers-by-category :map)

;; Check if helper is compatible
(bpf/helper-compatible? :map-lookup-elem :kprobe kernel-version)

;; Get helper metadata
(bpf/get-helper-info :ktime-get-ns)
```

## Experiments

### Experiment 1: Find Helpers for Your Use Case

```clojure
;; Find all time-related helpers
(def time-helpers (bpf/helpers-by-category :time))
(doseq [[k v] time-helpers]
  (println (:name v) "-" (:description v)))

;; Find all map operations
(def map-helpers (bpf/helpers-by-category :map))
(println "Map helpers:" (count map-helpers))
```

### Experiment 2: Check Helper Compatibility

```clojure
;; Check which program types can use a specific helper
(def helper :probe-read-kernel)
(def prog-types [:kprobe :tracepoint :xdp :socket-filter])

(doseq [prog-type prog-types]
  (let [compat? (bpf/helper-compatible? helper prog-type kernel-version)]
    (println (format "%s + %s: %s" helper prog-type (if compat? "✓" "✗")))))
```

### Experiment 3: Minimum Kernel Version Check

```clojure
;; Check if your kernel supports ring buffers
(defn supports-ringbuf? [kernel-version]
  (>= kernel-version 0x050800))  ; 5.8.0

(if (supports-ringbuf? kernel-version)
  (println "✓ Ring buffers supported")
  (println "✗ Ring buffers NOT supported - need kernel 5.8+"))
```

## Troubleshooting

### Error: "BPF filesystem not mounted"

**Solution**: Mount the BPF filesystem:
```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

Or add to `/etc/fstab` for persistence:
```
bpf  /sys/fs/bpf  bpf  defaults  0  0
```

### Error: "Cannot load BPF programs"

**Possible causes**:
1. **Insufficient permissions**: Need CAP_BPF or CAP_SYS_ADMIN
2. **Old kernel**: Need at least kernel 3.18, preferably 5.8+
3. **BPF disabled**: Check `CONFIG_BPF_SYSCALL=y` in kernel config

**Solutions**:
```bash
# Grant capabilities (kernel 5.8+)
sudo setcap cap_bpf,cap_perfmon+eip $(which java)

# Or run with sudo
sudo clojure -M lab-1-2.clj

# Check kernel config
grep CONFIG_BPF /boot/config-$(uname -r)
```

### Helpers Show as Unavailable

Some helpers may not be available due to:
- **Kernel version**: Helper introduced in newer kernel
- **Kernel configuration**: Feature disabled at compile time
- **Architecture**: Some helpers are architecture-specific

Check helper metadata for minimum kernel version:
```clojure
(let [info (bpf/get-helper-info :ringbuf-output)]
  (println "Minimum kernel:" (:min-kernel info)))
```

## Key Takeaways

✅ Kernel version determines available eBPF features
✅ Helper functions have minimum kernel version requirements
✅ Helper availability depends on program type
✅ BPF filesystem provides persistence for BPF objects
✅ System architecture affects instruction encoding
✅ Feature detection enables portable code

## Next Steps

- **Next Lab**: [Chapter 2 - BPF Maps](../../chapter-02/README.md)
- **Previous Lab**: [Lab 1.1 - Hello eBPF](lab-1-1-hello-ebpf.md)
- **Chapter**: [Chapter 1 - Introduction](../README.md)

## Challenge

Write a function that:
1. Determines the minimum kernel version needed for a list of helpers
2. Checks if the current kernel supports all of them
3. Suggests alternatives if any are unavailable

Example:
```clojure
(check-helper-requirements [:map-lookup-elem :ringbuf-output :probe-read-kernel])
;; => {:min-kernel "5.8.0"
;;     :current-kernel "5.15.0"
;;     :supported? true
;;     :missing []}
```

Solution in: [solutions/lab-1-2-challenge.clj](../solutions/lab-1-2-challenge.clj)
