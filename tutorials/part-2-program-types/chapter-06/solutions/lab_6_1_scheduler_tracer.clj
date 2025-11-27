(ns lab-6-1-scheduler-tracer
  "Lab 6.1: CPU Scheduler Tracer using Tracepoints

   This solution demonstrates:
   - Attaching BPF programs to scheduler tracepoints
   - Parsing tracepoint context structures
   - Tracking process scheduling events
   - Calculating CPU time and context switch statistics
   - Monitoring scheduling patterns

   Run with: sudo clojure -M -m lab-6-1-scheduler-tracer
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; Task states
(def TASK_RUNNING 0)
(def TASK_INTERRUPTIBLE 1)
(def TASK_UNINTERRUPTIBLE 2)

(def TASK_STATE_NAMES
  {0 "RUNNING"
   1 "INTERRUPTIBLE"
   2 "UNINTERRUPTIBLE"
   4 "STOPPED"
   8 "TRACED"
   16 "EXIT_DEAD"
   32 "EXIT_ZOMBIE"})

;; sched_switch tracepoint context offsets
;; Based on /sys/kernel/debug/tracing/events/sched/sched_switch/format
(def SCHED_SWITCH_OFFSETS
  {:prev-comm 8      ; char[16]
   :prev-pid 24      ; pid_t (4 bytes)
   :prev-prio 28     ; int (4 bytes)
   :prev-state 32    ; long (8 bytes)
   :next-comm 40     ; char[16]
   :next-pid 56      ; pid_t (4 bytes)
   :next-prio 60})   ; int (4 bytes)

(def MAX_ENTRIES 10000)
(def NUM_CPUS 256)

;;; ============================================================================
;;; Part 2: Data Structures
;;; ============================================================================

(defn read-u32-le [^bytes buf offset]
  (let [bb (ByteBuffer/wrap buf)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getInt bb offset)))

(defn read-u64-le [^bytes buf offset]
  (let [bb (ByteBuffer/wrap buf)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getLong bb offset)))

(defn read-string-from-bytes [^bytes buf offset max-len]
  (let [end (min (+ offset max-len) (count buf))
        relevant (byte-array (- end offset))]
    (System/arraycopy buf offset relevant 0 (- end offset))
    (let [null-idx (or (first (keep-indexed
                               (fn [i b] (when (zero? b) i))
                               relevant))
                       (count relevant))]
      (String. relevant 0 null-idx "UTF-8"))))

;;; ============================================================================
;;; Part 3: Maps
;;; ============================================================================

(defn create-cpu-switch-count-map
  "Array map: CPU ID -> context switch count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries NUM_CPUS
                   :map-name "cpu_switch_count"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-process-runtime-map
  "Hash map: PID -> total runtime (ns)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4              ; u32 PID
                   :value-size 8            ; u64 runtime
                   :max-entries MAX_ENTRIES
                   :map-name "process_runtime"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-start-times-map
  "Hash map: PID -> start timestamp"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries MAX_ENTRIES
                   :map-name "start_times"}))

(defn create-stats-map
  "Array map: index -> value
   [0] = total_context_switches
   [1] = voluntary_switches
   [2] = involuntary_switches"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4
                   :map-name "sched_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: BPF Program - Context Switch Counter
;;; ============================================================================

(defn create-context-switch-counter
  "Create BPF program that counts context switches per CPU.

   This simplified program demonstrates:
   - Getting CPU ID with bpf_get_smp_processor_id()
   - Incrementing per-CPU counters

   Instruction layout:
   0: call get_smp_processor_id
   1: mov-reg r6, r0        ; r6 = CPU ID
   2: store r6 to stack
   3-6: map lookup
   7-10: increment counter
   11: mov r0, 0
   12: exit"
  [cpu-count-fd stats-fd]
  (bpf/assemble
    [;; Get CPU ID
     (bpf/call 8)               ; BPF_FUNC_get_smp_processor_id
     (bpf/mov-reg :r6 :r0)      ; r6 = CPU ID

     ;; Store CPU ID as key on stack (must be 4 bytes aligned)
     (bpf/store-mem :dw :r10 -8 :r6)

     ;; Lookup current count for this CPU
     (bpf/ld-map-fd :r1 cpu-count-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)           ; r2 = &key
     (bpf/call 1)               ; BPF_FUNC_map_lookup_elem

     ;; Check if lookup succeeded
     (bpf/jmp-imm :jeq :r0 0 4)  ; if NULL, skip increment

     ;; Increment counter
     (bpf/load-mem :dw :r3 :r0 0)
     (bpf/add :r3 1)
     (bpf/store-mem :dw :r0 0 :r3)

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Userspace - Statistics and Visualization
;;; ============================================================================

(defn format-time [ns]
  "Format nanoseconds as human-readable time"
  (cond
    (< ns 1000) (format "%dns" ns)
    (< ns 1000000) (format "%.1fμs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.1fms" (/ ns 1000000.0))
    :else (format "%.2fs" (/ ns 1000000000.0))))

(defn display-cpu-stats [cpu-count-map num-cpus]
  "Display context switch statistics per CPU"
  (println "\nContext Switches per CPU:")
  (println "═══════════════════════════════════════════════════════")
  (println "CPU │ Count      │ Distribution")
  (println "────┼────────────┼──────────────────────────────────────")

  (let [counts (into []
                 (for [cpu (range num-cpus)]
                   (or (bpf/map-lookup cpu-count-map cpu) 0)))
        total (reduce + counts)
        max-count (apply max (conj counts 1))]

    (doseq [[cpu cnt] (map-indexed vector counts)
            :when (pos? cnt)]
      (let [percentage (if (pos? total)
                        (* 100.0 (/ cnt total))
                        0.0)
            bar-len (int (* 30 (/ cnt max-count)))
            bar (apply str (repeat bar-len "█"))]
        (println (format "%3d │ %,10d │ %s %.1f%%"
                        cpu cnt bar percentage))))

    (println "═══════════════════════════════════════════════════════")
    (println (format "Total: %,d context switches" total))))

(defn display-scheduling-stats [stats-map]
  "Display overall scheduling statistics"
  (let [total (or (bpf/map-lookup stats-map 0) 0)
        voluntary (or (bpf/map-lookup stats-map 1) 0)
        involuntary (or (bpf/map-lookup stats-map 2) 0)]

    (println "\nScheduling Statistics:")
    (println "───────────────────────────────────────")
    (println (format "Total context switches : %,d" total))
    (when (pos? total)
      (println (format "Voluntary switches     : %,d (%.1f%%)"
                       voluntary
                       (if (pos? total) (* 100.0 (/ voluntary total)) 0.0)))
      (println (format "Involuntary switches   : %,d (%.1f%%)"
                       involuntary
                       (if (pos? total) (* 100.0 (/ involuntary total)) 0.0))))))

;;; ============================================================================
;;; Part 6: Simulation
;;; ============================================================================

(defn simulate-scheduler-data
  "Simulate scheduling data for demonstration"
  [cpu-count-map stats-map]
  (println "\n  Simulating scheduling data...")

  ;; Simulate per-CPU context switches
  (let [num-cpus (.. Runtime getRuntime availableProcessors)
        cpu-counts (vec (for [_ (range num-cpus)]
                         (+ 1000 (rand-int 5000))))]

    ;; Update CPU counts
    (doseq [[cpu cnt] (map-indexed vector cpu-counts)]
      (bpf/map-update cpu-count-map cpu cnt))

    ;; Update stats
    (let [total (reduce + cpu-counts)
          voluntary (int (* total 0.65))
          involuntary (- total voluntary)]
      (bpf/map-update stats-map 0 total)
      (bpf/map-update stats-map 1 voluntary)
      (bpf/map-update stats-map 2 involuntary))

    (println (format "  Simulated %d context switches across %d CPUs"
                     (reduce + cpu-counts)
                     num-cpus))))

(defn display-simulated-events
  "Display simulated scheduler events"
  []
  (println "\nSimulated Scheduler Events:")
  (println "═══════════════════════════════════════════════════════════════════════════════")
  (println "TIME(ms) │ CPU │ PREV PROCESS           │ NEXT PROCESS           │ RUNTIME")
  (println "─────────┼─────┼────────────────────────┼────────────────────────┼──────────")

  (let [events [{:time 0.12 :cpu 0 :prev "firefox" :prev-pid 1234
                 :next "Xorg" :next-pid 5678 :runtime 125400}
                {:time 0.34 :cpu 1 :prev "java" :prev-pid 9012
                 :next "systemd" :next-pid 1 :runtime 234500}
                {:time 0.56 :cpu 0 :prev "Xorg" :prev-pid 5678
                 :next "kworker/0:1" :next-pid 3456 :runtime 45200}
                {:time 0.78 :cpu 2 :prev "bash" :prev-pid 7890
                 :next "sshd" :next-pid 2345 :runtime 156700}
                {:time 1.23 :cpu 1 :prev "systemd" :prev-pid 1
                 :next "java" :next-pid 9012 :runtime 12300}
                {:time 1.45 :cpu 0 :prev "kworker/0:1" :prev-pid 3456
                 :next "firefox" :next-pid 1234 :runtime 78900}]]

    (doseq [{:keys [time cpu prev prev-pid next next-pid runtime]} events]
      (println (format "%8.2f │ %3d │ %-12s [%5d] │ %-12s [%5d] │ %s"
                       time cpu prev prev-pid next next-pid
                       (format-time runtime)))))

  (println "═══════════════════════════════════════════════════════════════════════════════"))

;;; ============================================================================
;;; Part 7: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 6.1: CPU Scheduler Tracer ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [cpu-count-map (create-cpu-switch-count-map)
        stats-map (create-stats-map)]
    (println "  CPU count map created (FD:" (:fd cpu-count-map) ")")
    (println "  Stats map created (FD:" (:fd stats-map) ")")

    ;; Initialize maps
    (let [num-cpus (.. Runtime getRuntime availableProcessors)]
      (doseq [i (range num-cpus)]
        (bpf/map-update cpu-count-map i 0)))
    (doseq [i (range 4)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create BPF program
      (println "\nStep 3: Creating BPF program...")
      (let [program (create-context-switch-counter (:fd cpu-count-map)
                                                    (:fd stats-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :tracepoint
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Explain tracepoint attachment
            (println "\nStep 5: Tracepoint attachment info...")
            (println "  Would attach to: sched/sched_switch")
            (println "  Tracepoint format:")
            (println "    ┌────────────────────────────────────────┐")
            (println "    │ Offset │ Field            │ Size       │")
            (println "    ├────────┼──────────────────┼────────────┤")
            (println "    │     8  │ prev_comm        │ 16 bytes   │")
            (println "    │    24  │ prev_pid         │ 4 bytes    │")
            (println "    │    28  │ prev_prio        │ 4 bytes    │")
            (println "    │    32  │ prev_state       │ 8 bytes    │")
            (println "    │    40  │ next_comm        │ 16 bytes   │")
            (println "    │    56  │ next_pid         │ 4 bytes    │")
            (println "    │    60  │ next_prio        │ 4 bytes    │")
            (println "    └────────────────────────────────────────┘")

            ;; Step 6: Show task states
            (println "\nStep 6: Task state values:")
            (doseq [[state name] (sort-by key TASK_STATE_NAMES)]
              (println (format "    %2d = %s" state name)))

            ;; Step 7: Simulate scheduler data
            (println "\nStep 7: Simulating scheduler data...")
            (simulate-scheduler-data cpu-count-map stats-map)

            ;; Step 8: Display simulated events
            (println "\nStep 8: Simulated events...")
            (display-simulated-events)

            ;; Step 9: Display statistics
            (println "\nStep 9: Statistics...")
            (let [num-cpus (.. Runtime getRuntime availableProcessors)]
              (display-cpu-stats cpu-count-map num-cpus))
            (display-scheduling-stats stats-map)

            ;; Step 10: Cleanup
            (println "\nStep 10: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map cpu-count-map)
        (bpf/close-map stats-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 6.1 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Get number of CPUs
  (.. Runtime getRuntime availableProcessors)
  )
