# Lab 10.2: Kernel Version Adaptive Program

## Objective

Build a BPF program that adapts its behavior based on kernel version and available features. This lab demonstrates how to write programs that gracefully degrade on older kernels while taking advantage of new features when available.

## Learning Goals

- Use CO-RE field existence checks
- Implement version-adaptive logic
- Graceful fallback strategies
- Runtime feature detection
- Conditional code paths based on kernel capabilities

## Background

Kernel features evolve over time. New fields are added to structures, old fields are renamed or removed, and new helpers become available. CO-RE allows programs to detect these changes at runtime and adapt accordingly.

### Example Evolution: Task Scheduler Statistics

Different kernels expose scheduler statistics differently:

**Kernel 4.19-5.13**: `task_struct->sched_entity.sum_exec_runtime`
```c
struct task_struct {
    struct sched_entity se;  // Contains runtime stats
};
```

**Kernel 5.14+**: `task_struct->se.sum_exec_runtime` (same location, different access)

**Kernel 6.0+**: Additional field `task_struct->sched_info.last_arrival`

Our program will:
1. Check which fields exist
2. Use the most appropriate field for statistics
3. Fall back gracefully if fields are missing

## Architecture

```
┌──────────────────────────────────┐
│  BPF Program                     │
├──────────────────────────────────┤
│  ┌────────────────────────────┐ │
│  │ Feature Detection          │ │
│  │ - Field A exists?          │ │
│  │ - Field B exists?          │ │
│  │ - Helper X available?      │ │
│  └────────────────────────────┘ │
│            │                     │
│            ▼                     │
│  ┌────────────────────────────┐ │
│  │ Branch on Capabilities     │ │
│  ├────────────────────────────┤ │
│  │ Modern Kernel Path         │ │
│  │ - Use new fields           │ │
│  │ - Rich statistics          │ │
│  │                            │ │
│  │ Legacy Kernel Path         │ │
│  │ - Use old fields           │ │
│  │ - Basic statistics         │ │
│  │                            │ │
│  │ Minimal Kernel Path        │ │
│  │ - Essential data only      │ │
│  └────────────────────────────┘ │
└──────────────────────────────────┘
```

## Implementation

```clojure
(ns adaptive-program.core
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.btf :as btf]))

;; ============================================================================
;; Feature Detection
;; ============================================================================

(defn detect-kernel-features
  "Detect available kernel features at userspace startup"
  []
  (let [features
        {:btf-available (btf/btf-available?)
         :kernel-version (bpf/get-kernel-version)

         ;; Check task_struct fields
         :has-state-field (btf/field-exists? "task_struct" "state")
         :has-__state-field (btf/field-exists? "task_struct" "__state")
         :has-sched-info (btf/field-exists? "task_struct" "sched_info")
         :has-sum-exec-runtime (btf/field-exists? "sched_entity" "sum_exec_runtime")

         ;; Check helper availability (kernel version based)
         :has-ringbuf (>= (bpf/get-kernel-version) 0x050800)  ; 5.8+
         :has-ktime-get-boot-ns (>= (bpf/get-kernel-version) 0x050700)  ; 5.7+

         ;; Check for modern structures
         :has-bpf-ringbuf (btf/type-exists? "bpf_ringbuf")
         :has-bpf-spin-lock (btf/type-exists? "bpf_spin_lock")}]

    (println "\n=== Detected Kernel Features ===")
    (doseq [[feature available?] features]
      (println (format "  %-25s %s"
                       (name feature)
                       (if available? "✓ YES" "✗ NO"))))
    features))

(def detected-features (atom nil))

;; ============================================================================
;; Constants
;; ============================================================================

(def FEATURE_MODERN 0)    ; Kernel 6.0+
(def FEATURE_STANDARD 1)  ; Kernel 5.8-5.15
(def FEATURE_LEGACY 2)    ; Kernel 5.2-5.7
(def FEATURE_MINIMAL 3)   ; Kernel 4.19-5.1

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def task-stats
  "Per-task statistics (PID -> stats struct)"
  {:type :hash
   :key-type :u32
   :value-type :struct  ; {runtime_ns: u64, switches: u64, last_seen: u64}
   :max-entries 10000})

(def feature-config
  "Feature level configuration (single entry)"
  {:type :array
   :key-type :u32
   :value-type :u32  ; Feature level
   :max-entries 1})

(def events
  "Event ring buffer (if available) or perf buffer fallback"
  {:type :ring_buffer
   :max-entries (* 128 1024)})

;; ============================================================================
;; Adaptive Field Access Helpers
;; ============================================================================

(defn read-task-state-adaptive
  "Read task state, handling both 'state' and '__state' fields
  Kernel < 5.14: uses 'state' (volatile long)
  Kernel >= 5.14: uses '__state' (unsigned int)"
  [task-reg dest-reg]
  [;; Try modern field first (__state)
   (bpf/core-field-exists :r0 "task_struct" "__state")
   [(bpf/jmp-imm :jeq :r0 0 :try-legacy-state)]

   ;; Modern path: __state exists
   [:use-modern-state]
   (bpf/core-field-offset :r1 "task_struct" "__state")
   [(bpf/mov-reg :r2 task-reg)]
   [(bpf/add-reg :r2 :r1)]
   [(bpf/load-mem :w dest-reg :r2 0)]    ; unsigned int (32-bit)
   [(bpf/jmp :state-done)]

   ;; Legacy path: try 'state'
   [:try-legacy-state]
   (bpf/core-field-exists :r0 "task_struct" "state")
   [(bpf/jmp-imm :jeq :r0 0 :state-not-found)]

   [:use-legacy-state]
   (bpf/core-field-offset :r1 "task_struct" "state")
   [(bpf/mov-reg :r2 task-reg)]
   [(bpf/add-reg :r2 :r1)]
   [(bpf/load-mem :dw dest-reg :r2 0)]   ; volatile long (64-bit)
   [(bpf/jmp :state-done)]

   ;; Fallback: state not found (shouldn't happen)
   [:state-not-found]
   [(bpf/mov dest-reg 0)]

   [:state-done]])

(defn read-runtime-stats-adaptive
  "Read scheduler runtime statistics adaptively"
  [task-reg dest-reg]
  [;; Check for sched_info (modern kernels 5.8+)
   (bpf/core-field-exists :r0 "task_struct" "sched_info")
   [(bpf/jmp-imm :jeq :r0 0 :try-se-runtime)]

   ;; Modern path: use sched_info
   [:use-sched-info]
   ;; task->sched_info.last_arrival exists in 6.0+
   (bpf/core-field-exists :r0 "sched_info" "last_arrival")
   [(bpf/jmp-imm :jeq :r0 0 :use-basic-sched-info)]

   ;; Ultra-modern: detailed sched_info
   (bpf/core-field-offset :r1 "task_struct" "sched_info")
   [(bpf/mov-reg :r2 task-reg)]
   [(bpf/add-reg :r2 :r1)]
   ;; Read sched_info.last_arrival
   (bpf/core-field-offset :r1 "sched_info" "last_arrival")
   [(bpf/add-reg :r2 :r1)]
   [(bpf/load-mem :dw dest-reg :r2 0)]
   [(bpf/jmp :runtime-done)]

   [:use-basic-sched-info]
   ;; Basic sched_info without last_arrival
   (bpf/core-field-offset :r1 "task_struct" "sched_info")
   [(bpf/mov-reg :r2 task-reg)]
   [(bpf/add-reg :r2 :r1)]
   ;; Read some other sched_info field
   [(bpf/load-mem :dw dest-reg :r2 0)]
   [(bpf/jmp :runtime-done)]

   ;; Legacy path: use sched_entity
   [:try-se-runtime]
   (bpf/core-field-exists :r0 "task_struct" "se")
   [(bpf/jmp-imm :jeq :r0 0 :no-runtime)]

   [:use-se-runtime]
   ;; task->se.sum_exec_runtime
   (bpf/core-field-offset :r1 "task_struct" "se")
   [(bpf/mov-reg :r2 task-reg)]
   [(bpf/add-reg :r2 :r1)]
   ;; Now read sum_exec_runtime from sched_entity
   (bpf/core-field-offset :r1 "sched_entity" "sum_exec_runtime")
   [(bpf/add-reg :r2 :r1)]
   [(bpf/load-mem :dw dest-reg :r2 0)]
   [(bpf/jmp :runtime-done)]

   [:no-runtime]
   ;; No runtime stats available - use current time as proxy
   [(bpf/call (bpf/helper :ktime_get_ns))]
   [(bpf/mov-reg dest-reg :r0)]

   [:runtime-done]])

;; ============================================================================
;; Main Adaptive Program
;; ============================================================================

(def adaptive-scheduler-monitor
  "Scheduler monitor that adapts to kernel capabilities"
  {:type :tracepoint
   :category "sched"
   :name "sched_switch"
   :program
   [;; Get current task
    [(bpf/call (bpf/helper :get_current_task))]
    [(bpf/mov-reg :r6 :r0)]
    [(bpf/jmp-imm :jeq :r6 0 :exit)]

    ;; ========================================================================
    ;; Determine Feature Level
    ;; ========================================================================

    ;; Load feature level from config
    [(bpf/mov :r7 0)]
    [(bpf/store-mem :w :r10 -4 :r7)]
    [(bpf/mov-reg :r1 (bpf/map-ref feature-config))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    ;; Default to STANDARD if not set
    [(bpf/mov :r9 FEATURE_STANDARD)]
    [(bpf/jmp-imm :jeq :r0 0 :feature-loaded)]
    [(bpf/load-mem :w :r9 :r0 0)]

    [:feature-loaded]

    ;; ========================================================================
    ;; Read PID
    ;; ========================================================================

    (bpf/core-field-offset :r1 "task_struct" "pid")
    [(bpf/mov-reg :r2 :r6)]
    [(bpf/add-reg :r2 :r1)]
    [(bpf/load-mem :w :r7 :r2 0)]
    [(bpf/store-mem :w :r10 -8 :r7)]     ; Save PID

    ;; ========================================================================
    ;; Branch on Feature Level
    ;; ========================================================================

    [(bpf/jmp-imm :jeq :r9 FEATURE_MODERN :modern-path)]
    [(bpf/jmp-imm :jeq :r9 FEATURE_STANDARD :standard-path)]
    [(bpf/jmp-imm :jeq :r9 FEATURE_LEGACY :legacy-path)]
    [(bpf/jmp :minimal-path)]

    ;; ========================================================================
    ;; Modern Path (Kernel 6.0+)
    ;; ========================================================================

    [:modern-path]
    ;; Read task state (adaptive)
    (read-task-state-adaptive :r6 :r8)
    [(bpf/store-mem :w :r10 -12 :r8)]

    ;; Read detailed runtime stats
    (read-runtime-stats-adaptive :r6 :r8)
    [(bpf/store-mem :dw :r10 -24 :r8)]

    ;; Get high-resolution timestamp (ktime_get_boot_ns available 5.7+)
    [(bpf/call (bpf/helper :ktime_get_boot_ns))]
    [(bpf/store-mem :dw :r10 -32 :r0)]

    ;; Submit to ring buffer (available 5.8+)
    [(bpf/mov-reg :r1 (bpf/map-ref events))]
    [(bpf/mov :r2 64)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]
    [(bpf/jmp-imm :jeq :r0 0 :update-map)]
    ;; ... fill event and submit ...
    [(bpf/jmp :update-map)]

    ;; ========================================================================
    ;; Standard Path (Kernel 5.8-5.15)
    ;; ========================================================================

    [:standard-path]
    ;; Read basic stats
    (read-task-state-adaptive :r6 :r8)
    [(bpf/store-mem :w :r10 -12 :r8)]

    ;; Basic runtime
    (read-runtime-stats-adaptive :r6 :r8)
    [(bpf/store-mem :dw :r10 -24 :r8)]

    ;; Regular timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -32 :r0)]

    [(bpf/jmp :update-map)]

    ;; ========================================================================
    ;; Legacy Path (Kernel 5.2-5.7)
    ;; ========================================================================

    [:legacy-path]
    ;; Minimal stats only
    (read-task-state-adaptive :r6 :r8)
    [(bpf/store-mem :w :r10 -12 :r8)]

    ;; Try to get runtime, may not be available
    (read-runtime-stats-adaptive :r6 :r8)
    [(bpf/store-mem :dw :r10 -24 :r8)]

    [(bpf/jmp :update-map)]

    ;; ========================================================================
    ;; Minimal Path (Kernel 4.19-5.1)
    ;; ========================================================================

    [:minimal-path]
    ;; Only track context switches with timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -32 :r0)]
    ;; No state or runtime - just count switches

    ;; ========================================================================
    ;; Update Statistics Map (All Paths)
    ;; ========================================================================

    [:update-map]
    ;; Lookup existing stats
    [(bpf/load-mem :w :r7 :r10 -8)]      ; PID
    [(bpf/store-mem :w :r10 -40 :r7)]
    [(bpf/mov-reg :r1 (bpf/map-ref task-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -40)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-stats)]

    ;; Update existing
    [(bpf/load-mem :dw :r1 :r0 0)]       ; runtime_ns
    [(bpf/load-mem :dw :r2 :r10 -24)]    ; new runtime
    [(bpf/add-reg :r1 :r2)]
    [(bpf/store-mem :dw :r0 0 :r1)]

    [(bpf/load-mem :dw :r1 :r0 8)]       ; switches
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 8 :r1)]

    [(bpf/load-mem :dw :r1 :r10 -32)]    ; last_seen
    [(bpf/store-mem :dw :r0 16 :r1)]

    [(bpf/jmp :exit)]

    [:init-stats]
    ;; Initialize new entry
    [(bpf/load-mem :dw :r1 :r10 -24)]
    [(bpf/store-mem :dw :r10 -56 :r1)]   ; runtime_ns
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r10 -48 :r1)]   ; switches = 1
    [(bpf/load-mem :dw :r1 :r10 -32)]
    [(bpf/store-mem :dw :r10 -64 :r1)]   ; last_seen

    [(bpf/mov-reg :r1 (bpf/map-ref task-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -40)]                  ; key
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -64)]                  ; value
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

;; ============================================================================
;; Userspace Control
;; ============================================================================

(defn determine-feature-level
  "Determine the best feature level for current kernel"
  [features]
  (cond
    ;; Modern: 6.0+ with all features
    (and (:has-sched-info features)
         (:has-ringbuf features)
         (:has-ktime-get-boot-ns features))
    FEATURE_MODERN

    ;; Standard: 5.8-5.15 with ring buffer
    (and (:has-se features)
         (:has-ringbuf features))
    FEATURE_STANDARD

    ;; Legacy: 5.2-5.7 with BTF but limited features
    (:btf-available features)
    FEATURE_LEGACY

    ;; Minimal: 4.19-5.1
    :else
    FEATURE_MINIMAL))

(defn format-feature-level [level]
  (case level
    0 "MODERN (6.0+)"
    1 "STANDARD (5.8-5.15)"
    2 "LEGACY (5.2-5.7)"
    3 "MINIMAL (4.19-5.1)"
    "UNKNOWN"))

(defn display-stats []
  (println "\n=== Task Statistics ===")
  (println "PID      Switches  Runtime(ms)  Last Seen")
  (println "================================================")
  (doseq [[pid stats] (bpf/map-get-all task-stats)]
    (let [switches (get stats :switches 0)
          runtime-ns (get stats :runtime_ns 0)
          runtime-ms (/ runtime-ns 1000000.0)
          last-seen (get stats :last_seen 0)]
      (printf "%-8d %-9d %-12.2f %d\n"
              pid switches runtime-ms last-seen))))

(defn -main []
  (println "=== Kernel Version Adaptive Program ===\n")

  ;; Detect features
  (reset! detected-features (detect-kernel-features))

  ;; Determine feature level
  (let [level (determine-feature-level @detected-features)]
    (println (format "\nUsing feature level: %s\n"
                     (format-feature-level level)))

    ;; Load and configure program
    (let [prog (bpf/load-program adaptive-scheduler-monitor)]
      ;; Set feature level in map
      (bpf/map-update! feature-config 0 level)

      ;; Attach
      (bpf/attach-tracepoint prog "sched" "sched_switch")

      (println "Monitoring scheduler events...")
      (println "Press Ctrl-C to view statistics\n")

      ;; Run for a while
      (Thread/sleep 10000)

      ;; Display results
      (display-stats))))
```

## Testing

### Test 1: Feature Detection

```bash
sudo lein run -m adaptive-program.core
```

Expected output shows detected features:
```
=== Detected Kernel Features ===
  btf-available             ✓ YES
  kernel-version            ✓ YES
  has-state-field           ✗ NO
  has-__state-field         ✓ YES
  has-sched-info            ✓ YES
  has-sum-exec-runtime      ✓ YES
  has-ringbuf               ✓ YES
  has-ktime-get-boot-ns     ✓ YES
  has-bpf-ringbuf           ✓ YES
  has-bpf-spin-lock         ✓ YES

Using feature level: MODERN (6.0+)
```

### Test 2: Cross-Kernel Testing

Test on different kernel versions:

```bash
# Modern kernel (6.0+)
docker run --privileged ubuntu:24.04 ...
# Expected: MODERN feature level

# Standard kernel (5.15)
docker run --privileged ubuntu:22.04 ...
# Expected: STANDARD feature level

# Legacy kernel (5.4)
docker run --privileged ubuntu:20.04 ...
# Expected: LEGACY or STANDARD level
```

### Test 3: Statistics Collection

Let program run, then view statistics:
```
=== Task Statistics ===
PID      Switches  Runtime(ms)  Last Seen
================================================
1        245       1234.56      1234567890123456
1234     12        45.67        1234567890123457
5678     156       789.12       1234567890123458
```

## Challenges

1. **Auto-Detection**: Automatically choose code path without userspace config
2. **Hybrid Approach**: Use modern features when available, legacy as fallback
3. **Helper Adaptation**: Adapt to available BPF helpers
4. **Map Type Selection**: Choose best map type based on kernel support
5. **Performance**: Minimize overhead of feature detection

## Key Takeaways

1. **CO-RE Enables Adaptation**: Field existence checks allow runtime branching
2. **Graceful Degradation**: Programs work on all kernels with reduced features
3. **Feature Detection**: Check capabilities at both compile and runtime
4. **Single Binary**: One program adapts to any kernel version
5. **Future-Proof**: New features automatically utilized when available

## Next Steps

- **Lab 10.3**: Build a BTF structure inspector tool
- **Chapter 12**: Performance optimization for adaptive programs
- Learn how to minimize relocation overhead

## References

- [CO-RE Field Existence](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [Kernel Version Detection](https://docs.kernel.org/bpf/libbpf/program_types.html)
- [Adaptive BPF Patterns](https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html)
