# Chapter 25: Advanced Patterns and Best Practices

## Overview

Master advanced eBPF design patterns, code organization strategies, and best practices for building production-grade observability and security systems. This chapter synthesizes lessons from all previous chapters into reusable patterns.

**Topics**:
- Design patterns for common scenarios
- Code organization and modularity
- Performance optimization patterns
- Security hardening patterns
- Testing strategies
- Production-ready architecture

## 25.1 Design Patterns

### Pattern: Event Aggregation

**Problem**: Too many events overwhelming userspace (millions per second).

**Solution**: Aggregate in kernel, flush periodically to userspace.

```clojure
(ns patterns.aggregation
  (:require [clj-ebpf.core :as bpf]))

;; Kernel: Aggregate events in per-CPU map
(def event-aggregator
  "Aggregate events by key in kernel"
  {:type :tracepoint
   :category "syscalls"
   :name "sys_enter_openat"
   :program
   [;; Extract aggregation key (e.g., filename)
    [(bpf/load-ctx :dw :r6 offsetof(filename))]

    ;; Lookup aggregation bucket
    [(bpf/store-mem :dw :r10 -8 :r6)]
    [(bpf/mov-reg :r1 (bpf/map-ref aggregation-map))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    ;; Increment counter
    [(bpf/jmp-imm :jeq :r0 0 :init)]
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]
    [(bpf/jmp :done)]

    [:init]
    ;; Initialize new bucket
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r10 -16 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref aggregation-map))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -16)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:done]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

(def aggregation-map
  {:type :percpu_hash  ; Per-CPU for lock-free updates
   :key-type [256 :u8] ; Filename
   :value-type :u64     ; Count
   :max-entries 10000})

;; Userspace: Flush aggregated events periodically
(defn flush-aggregations []
  "Flush and reset aggregations every 10 seconds"
  (loop []
    (Thread/sleep 10000)

    ;; Read all aggregations
    (let [aggregations (bpf/map-get-all aggregation-map)]

      ;; Process aggregated events
      (doseq [[key count] aggregations]
        (process-aggregated-event key count))

      ;; Clear map for next window
      (bpf/map-clear! aggregation-map))

    (recur)))

;; Result: 1M events/sec → 1K aggregated events every 10s
;; 1000× reduction in userspace processing
```

### Pattern: Adaptive Sampling

**Problem**: Need low overhead but also need detailed data when issues occur.

**Solution**: Dynamically adjust sampling rate based on system health.

```clojure
(def sampling-config
  {:type :array
   :key-type :u32
   :value-type :u32  ; Current sampling rate
   :max-entries 1})

(defn create-adaptive-sampler []
  "Sample at dynamic rate based on load"
  {:program
   [;; Load current sampling rate
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -4 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref sampling-config))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]
    [(bpf/load-mem :w :r7 :r0 0)]  ; r7 = sampling rate

    ;; Generate random number
    [(bpf/call (bpf/helper :get_prandom_u32))]
    [(bpf/mod-reg :r0 :r7)]  ; r0 = rand() % rate

    ;; Skip if not sampled
    [(bpf/jmp-imm :jne :r0 0 :exit)]

    ;; Process sampled event
    ;; ...

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

;; Userspace: Adjust sampling rate based on load
(defn adaptive-sampling-controller []
  (loop []
    (Thread/sleep 5000)

    (let [cpu-usage (get-cpu-usage)
          current-rate (bpf/map-lookup sampling-config 0)]

      (cond
        ;; High CPU load → reduce sampling
        (> cpu-usage 80.0)
        (let [new-rate (min 10000 (* current-rate 2))]
          (println (format "High CPU, reducing sampling: 1:%d → 1:%d"
                          current-rate new-rate))
          (bpf/map-update! sampling-config 0 new-rate))

        ;; Low CPU load → increase sampling
        (< cpu-usage 20.0)
        (let [new-rate (max 10 (/ current-rate 2))]
          (println (format "Low CPU, increasing sampling: 1:%d → 1:%d"
                          current-rate new-rate))
          (bpf/map-update! sampling-config 0 new-rate))))

    (recur)))
```

### Pattern: Time-Window Aggregation

**Problem**: Need to track metrics over sliding time windows.

**Solution**: Use array map with time buckets.

```clojure
(def time-buckets
  {:type :array
   :key-type :u32
   :value-type :u64  ; Count for this bucket
   :max-entries 60}) ; 60 second window

(defn time-window-counter []
  "Count events in 60-second sliding window"
  {:program
   [;; Get current time
    [(bpf/call (bpf/helper :ktime_get_ns))]

    ;; Calculate bucket index (second within minute)
    [(bpf/div :r0 1000000000)]  ; ns → seconds
    [(bpf/mod :r0 60)]          ; second % 60
    [(bpf/mov-reg :r6 :r0)]     ; r6 = bucket index

    ;; Lookup bucket
    [(bpf/store-mem :w :r10 -4 :r6)]
    [(bpf/mov-reg :r1 (bpf/map-ref time-buckets))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]

    ;; Increment bucket count
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]})

;; Userspace: Query sliding window total
(defn get-window-total []
  "Get total count for last 60 seconds"
  (let [buckets (bpf/map-get-all time-buckets)]
    (reduce + (vals buckets))))

;; Userspace: Rotate buckets
(defn rotate-buckets []
  "Clear old buckets as time advances"
  (loop []
    (Thread/sleep 1000)

    (let [current-second (mod (quot (System/currentTimeMillis) 1000) 60)
          next-second (mod (inc current-second) 60)]

      ;; Clear next bucket (about to be overwritten)
      (bpf/map-update! time-buckets next-second 0))

    (recur)))
```

### Pattern: State Machine

**Problem**: Track complex multi-state workflows (e.g., connection lifecycle).

**Solution**: Store state in map, transition on events.

```clojure
(defrecord ConnectionState
  [state :u8          ; CONNECTING, ESTABLISHED, CLOSING, CLOSED
   start-time :u64
   bytes-sent :u64
   bytes-received :u64])

(def connection-states
  {:type :hash
   :key-type :u32      ; Connection ID (socket address)
   :value-type :struct ; ConnectionState
   :max-entries 100000})

(defn connection-state-machine []
  "Track TCP connection state transitions"
  {:on-connect
   [;; Create new connection state
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/mov-reg :r6 :r0)]  ; Connection ID

    ;; Initialize state
    [(bpf/mov :r1 1)]  ; CONNECTING
    [(bpf/store-mem :b :r10 -32 :r1)]
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -24 :r0)]  ; start_time
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :dw :r10 -16 :r1)]  ; bytes_sent = 0
    [(bpf/store-mem :dw :r10 -8 :r1)]   ; bytes_received = 0

    ;; Store in map
    [(bpf/store-mem :dw :r10 -40 :r6)]
    [(bpf/mov-reg :r1 (bpf/map-ref connection-states))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -40)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -32)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]]

   :on-established
   [;; Lookup connection
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/mov-reg :r6 :r0)]
    [(bpf/store-mem :dw :r10 -8 :r6)]
    [(bpf/mov-reg :r1 (bpf/map-ref connection-states))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -8)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]

    ;; Transition: CONNECTING → ESTABLISHED
    [(bpf/mov :r1 2)]  ; ESTABLISHED
    [(bpf/store-mem :b :r0 0 :r1)]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]

   :on-send
   [;; Update bytes_sent
    ;; ...
    ]

   :on-close
   [;; Transition: * → CLOSED
    ;; Emit final metrics
    ;; Delete from map
    ]})
```

### Pattern: Hierarchical Filtering

**Problem**: Need multi-level filtering (global → per-container → per-process).

**Solution**: Chain filter lookups from general to specific.

```clojure
(def global-filters
  {:type :array
   :key-type :u32
   :value-type :u8  ; enabled/disabled
   :max-entries 1})

(def cgroup-filters
  {:type :hash
   :key-type :u64   ; Cgroup ID
   :value-type :u8
   :max-entries 1000})

(def process-filters
  {:type :hash
   :key-type :u32   ; PID
   :value-type :u8
   :max-entries 10000})

(defn hierarchical-filter []
  "Check filters from global → cgroup → process"
  {:program
   [;; 1. Check global filter
    [(bpf/mov :r1 0)]
    [(bpf/store-mem :w :r10 -4 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref global-filters))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -4)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :deny)]
    [(bpf/load-mem :b :r1 :r0 0)]
    [(bpf/jmp-imm :jeq :r1 0 :deny)]  ; Global filter disabled

    ;; 2. Check cgroup filter
    [(bpf/call (bpf/helper :get_current_cgroup_id))]
    [(bpf/store-mem :dw :r10 -16 :r0)]
    [(bpf/mov-reg :r1 (bpf/map-ref cgroup-filters))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :allow)]  ; Not in cgroup filter → allow
    [(bpf/load-mem :b :r1 :r0 0)]
    [(bpf/jmp-imm :jeq :r1 0 :deny)]   ; Cgroup filter disabled → deny

    ;; 3. Check process filter
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :w :r10 -24 :r0)]
    [(bpf/mov-reg :r1 (bpf/map-ref process-filters))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -24)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :allow)]  ; Not in process filter → allow
    [(bpf/load-mem :b :r1 :r0 0)]
    [(bpf/jmp-imm :jeq :r1 0 :deny)]   ; Process filter disabled → deny

    [:allow]
    ;; All filters passed, process event
    ;; ...
    [(bpf/jmp :exit)]

    [:deny]
    [(bpf/mov :r0 0)]
    [:exit]
    [(bpf/exit)]]})
```

## 25.2 Code Organization

### Modular BPF Programs

```clojure
;; src/ebpf/common/helpers.clj
(ns ebpf.common.helpers
  (:require [clj-ebpf.core :as bpf]))

(defn get-process-info []
  "Reusable: Get PID, TID, UID, GID"
  [(bpf/call (bpf/helper :get_current_pid_tgid))
   (bpf/mov-reg :r6 :r0)  ; Save PID/TID
   (bpf/call (bpf/helper :get_current_uid_gid))
   (bpf/mov-reg :r7 :r0)]) ; Save UID/GID

(defn bounds-check [data data-end offset size]
  "Reusable: Packet bounds check"
  [(bpf/mov-reg :r4 data)
   (bpf/add :r4 (+ offset size))
   (bpf/jmp-reg :jgt :r4 data-end :drop)
   ;; ... continue if check passed
   [:drop]
   (bpf/mov :r0 0)
   (bpf/exit-insn)])

;; src/ebpf/common/maps.clj
(ns ebpf.common.maps)

(defn create-stats-map [max-entries]
  {:type :percpu_hash
   :key-type :u64
   :value-type :u64
   :max-entries max-entries})

(defn create-event-buffer [size-bytes]
  {:type :ring_buffer
   :max-entries size-bytes})

;; src/ebpf/network/packet_filter.clj
(ns ebpf.network.packet-filter
  (:require [clj-ebpf.core :as bpf]
            [ebpf.common.helpers :as helpers]
            [ebpf.common.maps :as maps]))

(def packet-stats (maps/create-stats-map 10000))
(def filtered-packets (maps/create-event-buffer (* 4 1024 1024)))

(defn packet-filter-program []
  (vec (concat
         ;; Use reusable helpers
         (helpers/get-process-info)

         ;; Use reusable bounds check
         (helpers/bounds-check :r2 :r3 0 14)

         ;; Program-specific logic
         ;; ...
         )))
```

### Shared Map Patterns

```clojure
;; Multiple programs sharing same maps
(def shared-process-map
  "Shared across multiple programs"
  {:type :hash
   :key-type :u32
   :value-type :struct
   :max-entries 10000
   :pinned "/sys/fs/bpf/shared/processes"})  ; Pinned for sharing

;; Program 1: Writes process info
(defn process-tracker []
  {:program
   [;; Write to shared map
    ;; ...
    ]})

;; Program 2: Reads process info
(defn process-auditor []
  {:program
   [;; Read from same shared map
    ;; ...
    ]})

;; Load and pin maps once
(defn setup-shared-maps []
  (let [map-ref (bpf/create-map shared-process-map)]
    (bpf/pin-map map-ref "/sys/fs/bpf/shared/processes")
    map-ref))

;; Programs reference pinned map
(defn load-program-with-shared-map []
  (let [shared-map (bpf/load-pinned-map "/sys/fs/bpf/shared/processes")]
    (bpf/load-program (process-tracker) :kprobe
                     {:maps {:processes shared-map}})))
```

### Configuration Management

```clojure
;; config/programs.edn
{:network-analyzer
 {:enabled true
  :attach-to "eth0"
  :sampling-rate 100
  :maps {:flows {:max-entries 100000}
         :packets {:max-entries (* 4 1024 1024)}}}

 :syscall-tracer
 {:enabled false
  :filter-pids [1234 5678]
  :maps {:events {:max-entries (* 1 1024 1024)}}}}

;; Load configuration
(defn load-program-config [program-name]
  (get-in (load-config "config/programs.edn") [program-name]))

;; Apply configuration
(defn create-program-from-config [program-name]
  (let [config (load-program-config program-name)]
    (when (:enabled config)
      (let [maps (create-maps-from-config (:maps config))
            program (create-program program-name config maps)]
        (load-and-attach program (:attach-to config))))))
```

## 25.3 Performance Best Practices

### Minimize Map Lookups

```clojure
;; ❌ BAD: Multiple lookups of same key
(defn bad-multiple-lookups []
  [;; Lookup 1
   (bpf/call (bpf/helper :map_lookup_elem))
   (bpf/load-mem :dw :r1 :r0 0)

   ;; ... other code ...

   ;; Lookup 2 (same key!)
   (bpf/call (bpf/helper :map_lookup_elem))
   (bpf/load-mem :dw :r2 :r0 8)])

;; ✅ GOOD: Single lookup, cache result
(defn good-cached-lookup []
  [;; Lookup once
   (bpf/call (bpf/helper :map_lookup_elem))
   (bpf/mov-reg :r9 :r0)  ; Cache pointer

   ;; Use cached pointer multiple times
   (bpf/load-mem :dw :r1 :r9 0)
   ;; ... other code ...
   (bpf/load-mem :dw :r2 :r9 8)])
```

### Use Per-CPU Data Structures

```clojure
;; ❌ BAD: Shared map with lock contention
(def slow-stats-map
  {:type :hash  ; Contention on updates
   :key-type :u32
   :value-type :u64
   :max-entries 1000})

;; ✅ GOOD: Per-CPU map, lock-free updates
(def fast-stats-map
  {:type :percpu_hash  ; No contention
   :key-type :u32
   :value-type :u64
   :max-entries 1000})

;; Userspace: Sum per-CPU values
(defn get-total-from-percpu [map-ref key]
  (let [per-cpu-values (bpf/map-lookup map-ref key)]
    (reduce + per-cpu-values)))
```

### Batch Map Operations

```clojure
;; ❌ BAD: Individual lookups
(defn slow-batch-read []
  (doseq [key (range 1000)]
    (bpf/map-lookup map-ref key)))

;; ✅ GOOD: Batch lookup (kernel 5.6+)
(defn fast-batch-read []
  (bpf/map-lookup-batch map-ref (range 1000)))
```

### Early Exit Optimization

```clojure
;; ✅ GOOD: Filter early, avoid expensive operations
(defn optimized-early-exit []
  [;; Cheap check first (PID filter)
   (bpf/call (bpf/helper :get_current_pid_tgid))
   (bpf/rsh :r0 32)
   (bpf/jmp-imm :jne :r0 target-pid :exit)  ; Exit early if not target

   ;; Expensive operations only for target PID
   (bpf/call (bpf/helper :get_stack))
   (bpf/call (bpf/helper :probe_read_user))
   ;; ...

   [:exit]
   (bpf/mov :r0 0)
   (bpf/exit-insn)])
```

## 25.4 Security Best Practices

### Input Validation

```clojure
(defn validate-input []
  "Always validate untrusted input"
  [;; Load size from packet
   (bpf/load-mem :h :r7 :r2 offsetof(size))

   ;; Validate size is reasonable
   (bpf/jmp-imm :jgt :r7 1500 :drop)  ; MTU limit

   ;; Validate offset doesn't overflow
   (bpf/mov-reg :r8 :r2)
   (bpf/add-reg :r8 :r7)
   (bpf/jmp-reg :jgt :r8 :r3 :drop)  ; Check against data_end

   ;; Now safe to use
   ;; ...

   [:drop]
   (bpf/mov :r0 0)
   (bpf/exit-insn)])
```

### Sensitive Data Protection

```clojure
;; Sanitize before logging
(defn sanitize-path [path]
  (-> path
      (str/replace #"/home/[^/]+" "/home/USER")
      (str/replace #"/root" "/root")))

(defn sanitize-env-vars [env]
  (remove #(re-matches #"(?i).*(password|token|key|secret).*" (:name %))
          env))

;; Don't log full packet contents in production
(defn safe-packet-logging []
  [;; Log only headers, not payload
   ;; Or hash payload
   ;; Never log credentials
   ])
```

### Least Privilege

```clojure
(defn setup-with-least-privilege []
  ;; Start with all required capabilities
  (check-required-capabilities [:CAP_BPF :CAP_PERFMON :CAP_NET_ADMIN])

  ;; Load programs
  (load-all-programs)

  ;; Drop unnecessary capabilities
  (drop-capabilities [:CAP_NET_ADMIN])  ; Keep only CAP_BPF

  ;; Run with minimal capabilities
  (run-event-loop))
```

## 25.5 Testing Best Practices

### Unit Testing BPF Logic

```clojure
(ns ebpf.network.packet-filter-test
  (:require [clojure.test :refer :all]
            [clj-ebpf.core :as bpf]
            [ebpf.network.packet-filter :as filter]))

(deftest test-packet-filter
  (testing "TCP port 80 packets are passed"
    (let [prog (bpf/compile-program (filter/create-filter))
          packet (test-helpers/create-tcp-packet {:dst-port 80})]

      (is (= :pass (bpf/run-program-in-simulator prog packet)))))

  (testing "TCP port 443 packets are passed"
    (let [prog (bpf/compile-program (filter/create-filter))
          packet (test-helpers/create-tcp-packet {:dst-port 443})]

      (is (= :pass (bpf/run-program-in-simulator prog packet)))))

  (testing "TCP port 22 packets are dropped"
    (let [prog (bpf/compile-program (filter/create-filter))
          packet (test-helpers/create-tcp-packet {:dst-port 22})]

      (is (= :drop (bpf/run-program-in-simulator prog packet))))))

(deftest test-map-operations
  (testing "Map updates work correctly"
    (with-open [map-ref (bpf/create-test-map)]
      (bpf/map-update! map-ref 1 100)
      (is (= 100 (bpf/map-lookup map-ref 1)))

      (bpf/map-delete! map-ref 1)
      (is (nil? (bpf/map-lookup map-ref 1))))))
```

### Integration Testing

```clojure
(deftest integration-test-syscall-tracer
  (testing "Syscall tracer captures open() calls"
    (with-program-loaded (syscall-tracer/create)
      ;; Perform syscall
      (spit "/tmp/test-file" "test")

      ;; Wait for event
      (Thread/sleep 1000)

      ;; Verify event was captured
      (let [events (get-captured-events)]
        (is (some #(and (= (:syscall %) :open)
                       (str/includes? (:path %) "test-file"))
                 events))))))
```

### Load Testing

```clojure
(deftest load-test-high-throughput
  (testing "Program handles 100K events/sec"
    (with-program-loaded (create-program)
      ;; Generate high load
      (dotimes [_ 100000]
        (trigger-event))

      ;; Check overhead is acceptable
      (let [cpu-overhead (measure-cpu-overhead)]
        (is (< cpu-overhead 5.0)  ; Less than 5% CPU
            (format "CPU overhead too high: %.2f%%" cpu-overhead)))

      ;; Check no events were dropped
      (let [stats (bpf/get-ringbuf-stats event-buffer)]
        (is (zero? (:drops stats))
            (format "%d events dropped" (:drops stats)))))))
```

## 25.6 Production Architecture Pattern

Complete example of production-ready architecture:

```clojure
(ns production.architecture
  (:require [clj-ebpf.core :as bpf]))

;; ============================================================================
;; Configuration
;; ============================================================================

(def config
  {:programs
   [{:name :network-analyzer
     :enabled true
     :attach "eth0"
     :sampling-rate 1000}
    {:name :syscall-tracer
     :enabled true
     :filter-pids [1234]}]

   :monitoring
   {:prometheus-port 9090
    :health-check-interval-ms 10000}

   :resources
   {:max-memory-mb 1000
    :max-cpu-percent 5}})

;; ============================================================================
;; Lifecycle Management
;; ============================================================================

(defprotocol ProgramLifecycle
  (start [this])
  (stop [this])
  (health-check [this])
  (get-stats [this]))

(defrecord BPFProgram [name program-ref maps-refs config]
  ProgramLifecycle

  (start [this]
    (println (format "Starting %s..." name))

    ;; Load program
    (let [prog (bpf/load-program (:program config) (:type config))]
      ;; Attach
      (doseq [attach-point (:attach-points config)]
        (bpf/attach program-ref attach-point))

      ;; Pin for persistence
      (bpf/pin-program prog (str "/sys/fs/bpf/" (name name)))

      (assoc this :program-ref prog)))

  (stop [this]
    (println (format "Stopping %s..." name))

    ;; Detach
    (bpf/detach-program program-ref)

    ;; Unload
    (bpf/unload-program program-ref))

  (health-check [this]
    (let [stats (bpf/get-prog-stats program-ref)]
      {:healthy (and
                  (> (:run-count stats) 0)
                  (< (:error-count stats) (* 0.01 (:run-count stats))))
       :stats stats}))

  (get-stats [this]
    (bpf/get-prog-stats program-ref)))

;; ============================================================================
;; Monitoring
;; ============================================================================

(defn start-monitoring [programs]
  (future
    (loop []
      (Thread/sleep (:health-check-interval-ms (:monitoring config)))

      ;; Health check all programs
      (doseq [prog programs]
        (let [health (health-check prog)]
          (when-not (:healthy health)
            (alert-unhealthy-program prog health))))

      ;; Export metrics
      (export-metrics programs)

      (recur))))

;; ============================================================================
;; Main Application
;; ============================================================================

(defn -main []
  ;; Setup
  (bpf/init!)
  (check-requirements)

  ;; Load programs
  (let [programs (map create-program-from-config
                     (filter :enabled (:programs config)))]

    ;; Start programs
    (doseq [prog programs]
      (start prog))

    ;; Start monitoring
    (start-monitoring programs)

    ;; Start event processing
    (start-event-processors programs)

    ;; Graceful shutdown
    (.addShutdownHook (Runtime/getRuntime)
      (Thread. (fn []
                (println "Shutting down...")
                (doseq [prog programs]
                  (stop prog))
                (println "Shutdown complete"))))

    ;; Block forever
    @(promise)))
```

## Summary

Advanced eBPF development requires:
- **Design patterns** - Reusable solutions for common problems
- **Code organization** - Modular, maintainable programs
- **Performance optimization** - Minimize overhead, maximize throughput
- **Security hardening** - Validate input, protect sensitive data
- **Comprehensive testing** - Unit, integration, and load tests
- **Production architecture** - Monitoring, health checks, graceful shutdown

You now have all the tools to build production-grade eBPF systems!

## Tutorial Complete! 🎉

Congratulations on completing the Comprehensive eBPF Programming Tutorial!

You've learned:
- ✅ eBPF fundamentals and architecture
- ✅ All major program types and attach points
- ✅ Advanced topics (CO-RE, LSM, performance)
- ✅ 8 complete real-world applications
- ✅ Production deployment and operations
- ✅ Advanced patterns and best practices

### Next Steps

1. **Build Your Own Application** - Apply what you've learned
2. **Contribute to clj-ebpf** - Help improve the library
3. **Explore Kernel Internals** - Deep dive into the verifier and JIT
4. **Join the Community** - Share knowledge on forums and conferences
5. **Teach Others** - Solidify your understanding by teaching

### Resources

- [eBPF Official Documentation](https://ebpf.io)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [clj-ebpf GitHub Repository](https://github.com/yourorg/clj-ebpf)

**Happy BPF Programming!** 🚀
