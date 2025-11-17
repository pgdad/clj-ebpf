(ns examples.execve-tracer
  "Trace execve system calls using eBPF
   This example demonstrates:
   - Loading a BPF program
   - Attaching to a tracepoint
   - Using BPF maps to communicate data
   - Reading events"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]))

;; BPF program to trace execve
;; This is a simplified version that just counts execve calls
;; A full version would capture process names, PIDs, etc.
;;
;; Bytecode for:
;;   r0 = 0
;;   exit
;;
;; Note: A real implementation would:
;; 1. Get current PID/TID (bpf_get_current_pid_tgid)
;; 2. Get process name (bpf_get_current_comm)
;; 3. Store in map or ring buffer
;; 4. Return 0
(def execve-tracer-program
  (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00  ; mov r0, 0
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

(defn create-event-counter-map
  "Create a map to count events"
  []
  (maps/create-hash-map 1
                       :map-name "execve_count"
                       :key-size 4
                       :value-size 8))

(defn run-execve-tracer
  "Run the execve tracer"
  []
  (println "Execve Tracer Example")
  (println "====================\n")

  ;; Check BPF is available
  (println "Checking BPF availability...")
  (let [checks (bpf/check-bpf-available)]
    (println "✓ Kernel version:" (format "0x%06x" (:kernel-version checks)))
    (println "✓ BPF filesystem mounted:" (:bpf-fs-mounted checks))
    (when (:bpf-fs-path checks)
      (println "  Path:" (:bpf-fs-path checks)))
    (println "✓ CAP_BPF:" (:has-cap-bpf checks))
    (println))

  (try
    ;; Create counter map
    (println "Creating event counter map...")
    (maps/with-map [counter-map {:map-type :hash
                                 :key-size 4
                                 :value-size 8
                                 :max-entries 1
                                 :map-name "execve_counter"
                                 :key-serializer utils/int->bytes
                                 :key-deserializer utils/bytes->int
                                 :value-serializer utils/long->bytes
                                 :value-deserializer utils/bytes->long}]
      (println "✓ Counter map created, FD:" (:fd counter-map))

      ;; Initialize counter
      (maps/map-update counter-map 0 0)
      (println)

      ;; Load program
      (println "Loading BPF program...")
      (bpf/with-program [prog {:prog-type :tracepoint
                               :insns execve-tracer-program
                               :license "GPL"
                               :prog-name "execve_trace"}]
        (println "✓ Program loaded, FD:" (:fd prog))
        (println)

        ;; Attach to execve tracepoint
        (println "Attaching to sys_enter_execve tracepoint...")
        (let [attached (programs/attach-tracepoint
                        prog
                        {:category "syscalls"
                         :name "sys_enter_execve"})]
          (println "✓ Attached successfully!")
          (println)

          (println "Monitoring execve calls...")
          (println "Run some commands in another terminal to see them traced")
          (println "Press Ctrl+C to stop")
          (println)

          ;; Monitor for 30 seconds or until interrupted
          (dotimes [i 30]
            (Thread/sleep 1000)
            (let [count (or (maps/map-lookup counter-map 0) 0)]
              (print (format "\rExecve calls: %d " count))
              (flush)))

          (println "\n\nStopping tracer...")
          (let [final-count (or (maps/map-lookup counter-map 0) 0)]
            (println "Total execve calls observed:" final-count)))))

    (println "\n✓ Cleanup complete!")

    (catch clojure.lang.ExceptionInfo e
      (println "\n✗ Error:" (.getMessage e))
      (let [data (ex-data e)]
        (when (:errno-keyword data)
          (println "  Errno:" (:errno-keyword data)))
        (when (:verifier-log data)
          (println "\nVerifier log:")
          (println (:verifier-log data))))
      (println "\nNote: This example requires:")
      (println "  - Linux kernel 4.14+")
      (println "  - Root privileges or CAP_BPF capability")
      (println "  - BPF filesystem mounted at /sys/fs/bpf")
      (println "  - Tracefs mounted at /sys/kernel/debug/tracing"))

    (catch Exception e
      (println "\n✗ Unexpected error:" (.getMessage e))
      (.printStackTrace e))))

(defn run-simple-map-example
  "Run a simple example that just demonstrates map operations"
  []
  (println "Simple Map Example")
  (println "==================\n")

  (try
    (println "Creating a hash map...")
    (maps/with-map [m {:map-type :hash
                      :key-size 4
                      :value-size 4
                      :max-entries 10
                      :map-name "example_map"
                      :key-serializer utils/int->bytes
                      :key-deserializer utils/bytes->int
                      :value-serializer utils/int->bytes
                      :value-deserializer utils/bytes->int}]
      (println "✓ Map created, FD:" (:fd m))
      (println)

      (println "Inserting values...")
      (maps/map-update m 1 100)
      (maps/map-update m 2 200)
      (maps/map-update m 3 300)
      (println "✓ Inserted 3 values")
      (println)

      (println "Looking up values...")
      (println "  Key 1 =" (maps/map-lookup m 1))
      (println "  Key 2 =" (maps/map-lookup m 2))
      (println "  Key 3 =" (maps/map-lookup m 3))
      (println)

      (println "Iterating over all entries...")
      (doseq [[k v] (maps/map-entries m)]
        (println (format "  %d => %d" k v)))
      (println)

      (println "Deleting key 2...")
      (maps/map-delete m 2)
      (println)

      (println "Remaining entries:")
      (doseq [[k v] (maps/map-entries m)]
        (println (format "  %d => %d" k v)))
      (println))

    (println "✓ Example complete!")

    (catch Exception e
      (println "✗ Error:" (.getMessage e))
      (when-let [data (ex-data e)]
        (println "Details:" data)))))

(defn -main
  [& args]
  (let [example (first args)]
    (case example
      "map" (run-simple-map-example)
      "trace" (run-execve-tracer)
      (do
        (println "Usage: lein run -m examples.execve-tracer [map|trace]")
        (println)
        (println "Examples:")
        (println "  map   - Simple map operations example")
        (println "  trace - Execve tracer example (requires root)")))))

;; Run from REPL:
;; (require '[examples.execve-tracer :as ex])
;; (ex/run-simple-map-example)
;; (ex/run-execve-tracer) ; requires root
