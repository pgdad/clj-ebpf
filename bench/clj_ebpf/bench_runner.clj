(ns clj-ebpf.bench-runner
  "Main entry point for running all benchmarks.

   Usage:
     clj -M:bench              # Run all benchmarks
     clj -M:bench maps         # Run only map benchmarks
     clj -M:bench events       # Run only event benchmarks"
  (:require [clj-ebpf.bench-core :as bench]
            [clj-ebpf.bench-maps :as bench-maps]
            [clj-ebpf.bench-events :as bench-events]))

(defn print-header []
  (println)
  (println "╔══════════════════════════════════════════════════════════════╗")
  (println "║              clj-ebpf Performance Benchmarks                 ║")
  (println "╚══════════════════════════════════════════════════════════════╝")
  (println)
  (println "System Information:")
  (println (format "  Java:    %s (%s)"
                   (System/getProperty "java.version")
                   (System/getProperty "java.vendor")))
  (println (format "  OS:      %s %s"
                   (System/getProperty "os.name")
                   (System/getProperty "os.version")))
  (println (format "  Arch:    %s" (System/getProperty "os.arch")))
  (println (format "  CPUs:    %d" (.availableProcessors (Runtime/getRuntime))))
  (println (format "  Max Mem: %.0f MB"
                   (/ (.maxMemory (Runtime/getRuntime)) 1048576.0)))
  (println)
  (println "Configuration:")
  (println (format "  Quick bench: %s" bench/*quick-bench*))
  (println))

(defn run-maps []
  (println "Running map benchmarks...")
  (bench-maps/run-all-benchmarks))

(defn run-events []
  (println "Running event benchmarks...")
  (bench-events/run-all-benchmarks))

(defn run-all []
  (run-maps)
  (run-events))

(defn -main [& args]
  (print-header)
  (let [suite (first args)]
    (case suite
      "maps" (run-maps)
      "events" (run-events)
      nil (run-all)
      (do
        (println (str "Unknown benchmark suite: " suite))
        (println "Available: maps, events (or no argument for all)")
        (System/exit 1))))
  (println)
  (println "All benchmarks complete.")
  (System/exit 0))
