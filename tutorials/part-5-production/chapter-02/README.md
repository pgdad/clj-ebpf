# Chapter 24: Troubleshooting Guide

## Overview

A comprehensive guide to diagnosing and fixing common eBPF issues. Learn systematic debugging approaches, diagnostic tools, and solutions to frequent problems encountered in production.

**Topics**:
- Common verifier rejections and fixes
- Map and helper function issues
- Performance debugging
- Diagnostic tools and techniques
- Production incident patterns

## 24.1 Verifier Rejection Patterns

### Pattern 1: Unbounded Loops

**Error**:
```
back-edge from insn 45 to 23
```

**Cause**: The verifier detected a loop without proven termination.

**Solution**:
```clojure
;; ❌ BAD: Unbounded loop
(defn bad-loop []
  [(bpf/mov :r1 0)
   [:loop]
   (bpf/add :r1 1)
   (bpf/jmp :loop)])  ; Infinite loop

;; ✅ GOOD: Bounded loop with #pragma unroll
(defn good-loop []
  ;; Use loop unrolling for small iterations
  (vec (mapcat
         (fn [i]
           [(bpf/mov :r2 i)
            (bpf/add :r1 :r2)])
         (range 10))))  ; Unrolled 10 iterations

;; ✅ GOOD: Explicit iteration count
(defn bounded-loop []
  [(bpf/mov :r1 0)  ; counter
   (bpf/mov :r2 10) ; max iterations

   [:loop]
   ;; Loop body...
   (bpf/add :r1 1)

   ;; Explicit bound check
   (bpf/jmp-reg :jlt :r1 :r2 :loop)  ; Jump if r1 < 10
   (bpf/exit-insn)])
```

### Pattern 2: Invalid Memory Access

**Error**:
```
R1 invalid mem access 'inv'
invalid access to packet, off=0 size=14, R0(id=0,off=0,r=0)
```

**Cause**: Accessing memory without proper bounds checking.

**Solution**:
```clojure
;; ❌ BAD: No bounds check before packet access
(defn bad-packet-access []
  [(bpf/load-ctx :dw :r2 0)]      ; data
   (bpf/load-mem :w :r0 :r2 12)]) ; VERIFIER REJECTS: unbounded access

;; ✅ GOOD: Proper bounds checking
(defn good-packet-access []
  [(bpf/load-ctx :dw :r2 0)]      ; data (start of packet)
   (bpf/load-ctx :dw :r3 8)]      ; data_end

   ;; Calculate packet pointer + offset
   (bpf/mov-reg :r4 :r2)
   (bpf/add :r4 14)                ; Eth header size

   ;; Bounds check: if (r4 > data_end) goto drop
   (bpf/jmp-reg :jgt :r4 :r3 :drop)

   ;; Now safe to access
   (bpf/load-mem :w :r0 :r2 12)
   (bpf/jmp :pass)

   [:drop]
   (bpf/mov :r0 0)
   (bpf/exit-insn)

   [:pass]
   ;; ... continue processing
   ])
```

### Pattern 3: Stack Overflow

**Error**:
```
tried to allocate 600 bytes from stack, max is 512
```

**Cause**: Exceeding 512-byte stack limit.

**Solution**:
```clojure
;; ❌ BAD: Large stack allocation
(defn bad-stack-usage []
  [(bpf/store-mem :dw :r10 -600 :r1)])  ; 600 bytes, exceeds limit

;; ✅ GOOD: Use map for large data
(def scratch-map
  {:type :array
   :key-type :u32
   :value-type [512 :u8]  ; Large buffer in map
   :max-entries 1})

(defn good-large-data []
  [;; Use map instead of stack
   (bpf/mov :r1 0)  ; key = 0
   (bpf/store-mem :w :r10 -4 :r1)
   (bpf/mov-reg :r1 (bpf/map-ref scratch-map))
   (bpf/mov-reg :r2 :r10)
   (bpf/add :r2 -4)
   (bpf/call (bpf/helper :map_lookup_elem))
   ;; r0 now points to 512-byte buffer
   ])
```

### Pattern 4: Uninitialized Register

**Error**:
```
R2 !read_ok
```

**Cause**: Reading from a register before it's initialized.

**Solution**:
```clojure
;; ❌ BAD: Using uninitialized register
(defn bad-register-use []
  [(bpf/add :r1 :r2)])  ; r2 never initialized

;; ✅ GOOD: Initialize all registers
(defn good-register-use []
  [(bpf/mov :r2 0)      ; Initialize r2
   (bpf/add :r1 :r2)])
```

### Pattern 5: Invalid Return Value

**Error**:
```
At program exit R0 has invalid value
```

**Cause**: BPF program must return appropriate value for program type.

**Solution**:
```clojure
;; ❌ BAD: Missing or invalid return
(defn bad-xdp-program []
  [(bpf/mov :r1 123)
   (bpf/exit-insn)])  ; r0 not set to valid XDP action

;; ✅ GOOD: Return valid XDP action
(defn good-xdp-program []
  [(bpf/mov :r0 (bpf/xdp-action :pass))  ; Valid: XDP_PASS
   (bpf/exit-insn)])

;; ✅ GOOD: Return 0 for tracepoint
(defn good-tracepoint []
  [(bpf/mov :r0 0)
   (bpf/exit-insn)])

;; ✅ GOOD: Return 0 or -EPERM for LSM
(defn good-lsm []
  [;; Deny access
   (bpf/mov :r0 -1)  ; -EPERM
   (bpf/exit-insn)])
```

## 24.2 Map Issues

### Issue: Map Lookup Returns NULL

**Symptoms**: Map lookup always returns 0 (NULL)

**Debugging**:
```clojure
(defn debug-map-lookup [map-ref key]
  "Debug why map lookup fails"

  ;; 1. Check map exists
  (when-not (bpf/map-exists? map-ref)
    (println "❌ Map doesn't exist"))

  ;; 2. Check key is correct type/size
  (let [map-info (bpf/get-map-info map-ref)]
    (when (not= (count key) (:key-size map-info))
      (println (format "❌ Key size mismatch: expected %d, got %d"
                      (:key-size map-info) (count key)))))

  ;; 3. Dump all map entries
  (println "Map contents:")
  (doseq [[k v] (bpf/map-get-all map-ref)]
    (println (format "  %s -> %s" k v)))

  ;; 4. Try lookup from userspace
  (let [result (bpf/map-lookup map-ref key)]
    (if result
      (println "✅ Lookup successful from userspace")
      (println "❌ Lookup failed from userspace too"))))
```

**Common Causes**:
1. Key not in map (not yet inserted)
2. Key size mismatch
3. Key value doesn't match (e.g., byte order)
4. Map is per-CPU and need to check each CPU

**Solutions**:
```clojure
;; Initialize map with default values
(defn initialize-map [map-ref default-value]
  (doseq [i (range max-keys)]
    (bpf/map-update! map-ref i default-value)))

;; Ensure key size matches
(defn create-map-with-correct-key-size []
  (bpf/create-hash-map
    {:key-size 8      ; u64
     :value-size 8
     :max-entries 1000}))

;; Handle per-CPU maps correctly
(defn read-percpu-map [map-ref key]
  (let [values (bpf/map-lookup map-ref key)]  ; Returns array of per-CPU values
    (reduce + values)))  ; Sum across all CPUs
```

### Issue: Map Full (No Space)

**Error**: Map update fails, ENOSPC

**Debugging**:
```clojure
(defn check-map-capacity [map-ref]
  (let [info (bpf/get-map-info map-ref)
        entries (count (bpf/map-get-all map-ref))]
    (println (format "Map usage: %d / %d (%.1f%% full)"
                    entries
                    (:max-entries info)
                    (* 100.0 (/ entries (:max-entries info)))))))
```

**Solutions**:
```clojure
;; 1. Increase map size (before loading)
(def larger-map
  {:type :hash
   :key-type :u64
   :value-type :u64
   :max-entries 100000})  ; Increased from 10000

;; 2. Use LRU map for automatic eviction
(def lru-map
  {:type :lru_hash
   :key-type :u64
   :value-type :u64
   :max-entries 10000})  ; Automatically evicts least recently used

;; 3. Manually evict old entries
(defn evict-old-entries [map-ref cutoff-time]
  (doseq [[k v] (bpf/map-get-all map-ref)]
    (when (< (:timestamp v) cutoff-time)
      (bpf/map-delete! map-ref k))))
```

## 24.3 Helper Function Issues

### Issue: Helper Not Available

**Error**:
```
unknown func bpf_helper_name
```

**Cause**: Helper not available in current kernel version

**Solution**:
```clojure
(defn check-helper-availability []
  "Check if required helpers are available"
  (let [required-helpers [:map_lookup_elem
                          :map_update_elem
                          :ktime_get_ns
                          :get_current_pid_tgid
                          :ringbuf_output]]

    (doseq [helper required-helpers]
      (if (bpf/helper-available? helper)
        (println (format "✅ %s available" helper))
        (println (format "❌ %s NOT available (kernel too old?)" helper))))))

;; Fallback to alternative helper
(defn get-time []
  (if (bpf/helper-available? :ktime_get_ns)
    [(bpf/call (bpf/helper :ktime_get_ns))]
    ;; Fallback to jiffies64 on older kernels
    [(bpf/call (bpf/helper :jiffies64))]))
```

### Issue: Invalid Helper Arguments

**Error**:
```
R1 type=inv expected=fp
```

**Cause**: Helper function called with wrong register types

**Solution**:
```clojure
;; ❌ BAD: Wrong register types
(defn bad-helper-call []
  [(bpf/mov :r1 123)  ; r1 should be map pointer, not immediate
   (bpf/call (bpf/helper :map_lookup_elem))])

;; ✅ GOOD: Correct register types
(defn good-helper-call [map-ref]
  [;; r1 = map pointer
   (bpf/mov-reg :r1 (bpf/map-ref map-ref))

   ;; r2 = pointer to key (on stack)
   (bpf/mov-reg :r2 :r10)
   (bpf/add :r2 -8)

   ;; Call helper
   (bpf/call (bpf/helper :map_lookup_elem))])
```

## 24.4 Performance Issues

### Issue: High CPU Overhead

**Symptoms**: System CPU usage increased after loading BPF program

**Debugging**:
```clojure
(defn profile-bpf-overhead []
  "Measure CPU overhead from BPF programs"
  (let [before (get-cpu-stats)]

    ;; Let BPF run for 60 seconds
    (Thread/sleep 60000)

    (let [after (get-cpu-stats)
          overhead (- (:bpf-time after) (:bpf-time before))
          total-time (- (:total-time after) (:total-time before))]

      (println (format "BPF CPU overhead: %.2f%%"
                      (* 100.0 (/ overhead total-time))))

      ;; Break down by program
      (doseq [prog (bpf/get-all-programs)]
        (println (format "  %s: %.2fms total"
                        (:name prog)
                        (/ (:run-time-ns prog) 1000000.0)))))))
```

**Solutions**:
```clojure
;; 1. Add early exits to filter events
(defn optimized-filter []
  [;; Filter by PID first (cheap check)
   (bpf/call (bpf/helper :get_current_pid_tgid))
   (bpf/rsh :r0 32)
   (bpf/jmp-imm :jne :r0 target-pid :exit)  ; Exit early if not target PID

   ;; ... expensive processing only for target PID ...

   [:exit]
   (bpf/mov :r0 0)
   (bpf/exit-insn)])

;; 2. Use sampling instead of tracing all events
(defn add-sampling [sample-rate]
  [;; Sample 1 in N events
   (bpf/call (bpf/helper :get_prandom_u32))
   (bpf/mod :r0 sample-rate)
   (bpf/jmp-imm :jne :r0 0 :exit)  ; Skip if not sampled

   ;; ... process sampled event ...

   [:exit]
   (bpf/mov :r0 0)
   (bpf/exit-insn)])

;; 3. Aggregate in kernel, emit less frequently
(def aggregation-map
  {:type :percpu_hash  ; Per-CPU for lock-free updates
   :key-type :u32
   :value-type :u64
   :max-entries 10000})
```

### Issue: High Memory Usage

**Debugging**:
```clojure
(defn analyze-map-memory []
  "Analyze memory usage of BPF maps"
  (let [maps (bpf/get-all-maps)]

    (println "Map memory usage:")
    (doseq [map-info maps]
      (let [entry-size (+ (:key-size map-info) (:value-size map-info))
            total-size (* entry-size (:max-entries map-info))
            actual-entries (count (bpf/map-get-all (:id map-info)))]

        (println (format "  %s: %d MB allocated, %d entries used"
                        (:name map-info)
                        (/ total-size 1024 1024)
                        actual-entries))))))
```

**Solutions**:
```clojure
;; 1. Reduce map sizes
(def optimized-map
  {:type :hash
   :key-type :u32     ; Was :u64, reduced by half
   :value-type :u32   ; Was structure, now just counter
   :max-entries 10000}) ; Was 100000

;; 2. Use LRU to automatically limit memory
(def lru-map
  {:type :lru_hash
   :max-entries 10000})  ; Hard limit, auto-evicts

;; 3. Periodic cleanup
(defn periodic-map-cleanup []
  (future
    (while true
      (Thread/sleep 300000)  ; Every 5 minutes
      (cleanup-old-entries))))
```

## 24.5 Production Incident Patterns

### Incident: Program Suddenly Stops Working

**Investigation**:
```bash
# 1. Check if program is still loaded
$ sudo bpftool prog list

# 2. Check kernel logs for BPF errors
$ sudo dmesg | grep -i bpf

# 3. Check program statistics
$ sudo bpftool prog show id <ID>

# 4. Check maps still exist
$ sudo bpftool map list
```

**Common Causes**:
1. Program was unloaded (check process still running)
2. Kernel module unloaded (for programs attached to kernel modules)
3. Map was deleted
4. System upgrade changed kernel internals (CO-RE should prevent this)

**Solution**:
```clojure
;; Pin program and maps to BPF filesystem for persistence
(defn pin-program-and-maps [prog map-refs]
  ;; Pin program
  (bpf/pin-program prog "/sys/fs/bpf/my-program")

  ;; Pin maps
  (doseq [[name map-ref] map-refs]
    (bpf/pin-map map-ref (str "/sys/fs/bpf/maps/" name)))

  (println "✅ Program and maps pinned (will survive process restart)"))

;; Load pinned program on restart
(defn load-pinned-program []
  (if (file-exists? "/sys/fs/bpf/my-program")
    (bpf/load-pinned-program "/sys/fs/bpf/my-program")
    (load-and-pin-new-program)))
```

### Incident: Events Not Reaching Userspace

**Investigation**:
```clojure
(defn debug-event-flow []
  "Debug why events aren't reaching userspace"

  ;; 1. Check if BPF program is running
  (println "BPF program run count:"
          (:run-count (bpf/get-prog-stats prog-id)))

  ;; 2. Check if events are being produced
  (println "Events in ring buffer:"
          (bpf/ringbuf-query map-ref))

  ;; 3. Check if consumer is running
  (println "Consumer thread alive:"
          (.isAlive consumer-thread))

  ;; 4. Check for dropped events
  (let [stats (bpf/ringbuf-stats map-ref)]
    (when (> (:drops stats) 0)
      (println (format "⚠️  %d events dropped (buffer full)" (:drops stats))))))
```

**Common Causes**:
1. Ring buffer full (consumer too slow)
2. Consumer thread crashed
3. BPF program filtering out events
4. BPF program not being triggered

**Solutions**:
```clojure
;; 1. Increase ring buffer size
(def larger-ringbuf
  {:type :ring_buffer
   :max-entries (* 16 1024 1024)})  ; 16MB instead of 4MB

;; 2. Add monitoring for consumer health
(defn monitor-consumer [consumer]
  (future
    (while true
      (Thread/sleep 5000)
      (when-not (.isAlive consumer)
        (println "❌ Consumer thread died, restarting...")
        (restart-consumer)))))

;; 3. Add debug events to verify program is running
(defn add-debug-event []
  [;; Emit debug event every N executions
   (bpf/call (bpf/helper :get_prandom_u32))
   (bpf/mod :r0 1000)
   (bpf/jmp-imm :jne :r0 0 :skip-debug)

   ;; Emit debug event
   ;; ...

   [:skip-debug]
   ;; Continue normal processing
   ])
```

### Incident: Kernel Panic After Loading Program

**Cause**: BPF bug (rare but possible) or kernel bug triggered by BPF

**Prevention**:
```clojure
;; 1. Test extensively in development
(deftest stress-test-program
  (dotimes [_ 1000000]
    (trigger-program-execution)))

;; 2. Canary deploy to single host first
(defn safe-production-deploy [program]
  ;; Deploy to one host
  (deploy-to-host "canary-host-1" program)

  ;; Monitor for crashes
  (Thread/sleep 3600000)  ; 1 hour

  ;; Check kernel logs for panics
  (when (check-kernel-panics "canary-host-1")
    (throw (ex-info "Kernel panic detected on canary" {})))

  ;; Deploy to all hosts
  (deploy-to-all-hosts program))

;; 3. Enable kernel crash dumps
$ sudo sysctl -w kernel.panic=1  # Reboot on panic
$ sudo sysctl -w kernel.panic_on_oops=1
```

## 24.6 Diagnostic Tools

### bpftool

```bash
# List all BPF programs
$ sudo bpftool prog list

# Show program details
$ sudo bpftool prog show id 42

# Dump program instructions
$ sudo bpftool prog dump xlated id 42

# Dump program JIT code
$ sudo bpftool prog dump jited id 42

# List all maps
$ sudo bpftool map list

# Dump map contents
$ sudo bpftool map dump id 24

# Update map entry
$ sudo bpftool map update id 24 key 1 value 42

# Delete map entry
$ sudo bpftool map delete id 24 key 1

# Show BTF information
$ sudo bpftool btf list

# Generate skeleton code
$ sudo bpftool gen skeleton program.o > program.skel.h
```

### Trace Pipe

```bash
# View trace_printk output
$ sudo cat /sys/kernel/debug/tracing/trace_pipe

# Filter for specific program
$ sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "my-program"
```

### clj-ebpf Debugging

```clojure
;; Enable verbose logging
(bpf/set-log-level :debug)

;; Dump program instructions before loading
(bpf/dump-program program)

;; Verify program after loading
(bpf/verify-program program)

;; Inspect map contents
(bpf/dump-map map-ref)

;; Monitor program statistics
(bpf/watch-program-stats prog-id 1000)  ; Update every 1s
```

## Troubleshooting Checklist

When encountering BPF issues, work through this checklist:

```
□ Check kernel version >= 5.8 (or minimum for your features)
□ Verify BPF filesystem is mounted (/sys/fs/bpf)
□ Check process has required capabilities (CAP_BPF, CAP_PERFMON)
□ Review verifier errors in dmesg
□ Verify program is loaded (bpftool prog list)
□ Check program run count (is it being triggered?)
□ Inspect map contents (bpftool map dump)
□ Monitor for dropped events
□ Check kernel logs for BPF errors
□ Verify CO-RE/BTF available (for CO-RE programs)
□ Test program in isolation
□ Review program resource usage (CPU, memory)
□ Check for kernel version incompatibilities
```

## Summary

Effective BPF troubleshooting requires:
- **Understanding verifier patterns** - Know common rejections and fixes
- **Systematic debugging** - Use diagnostic tools methodically
- **Monitoring** - Track program health in production
- **Testing** - Catch issues before production
- **Documentation** - Keep runbooks for common issues

**Next Chapter**: [Chapter 25: Advanced Patterns and Best Practices](../chapter-03/README.md)
