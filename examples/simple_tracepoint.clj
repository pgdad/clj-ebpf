(ns simple-tracepoint
  "Simple tracepoint example - trace sched_switch

   This example demonstrates two approaches:
   1. Using the new declarative macros (defprogram, with-bpf-script)
   2. Using the traditional explicit approach

   The new macros reduce boilerplate significantly."
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.macros :refer [defprogram with-bpf-script]]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.syscall :as syscall]))

;; ============================================================================
;; NEW WAY: Using declarative macros
;; ============================================================================

;; Define the program declaratively - much cleaner!
(defprogram simple-tracepoint-prog
  :type :raw-tracepoint
  :license "GPL"
  :opts {:prog-name "simple_tp"}
  :body [(dsl/mov :r0 0)
         (dsl/exit-insn)])

;; ============================================================================
;; OLD WAY: Manual bytecode (kept for reference)
;; ============================================================================

;; Simple BPF program that just returns 0 (does nothing but is valid)
;; This is the bytecode for:
;;   r0 = 0  -> opcode: 0xb7 (BPF_MOV | BPF_K | BPF_ALU64), dst=0, src=0, off=0, imm=0
;;   exit    -> opcode: 0x95 (BPF_EXIT | BPF_JMP)
(def simple-bpf-program
  (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00   ; r0 = 0
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

(defn run-simple-tracepoint []
  (println "Simple tracepoint example")
  (println "==========================\n")

  ;; Check BPF is available
  (println "Checking BPF availability...")
  (let [checks (bpf/check-bpf-available)]
    (println "Kernel version:" (format "0x%06x" (:kernel-version checks)))
    (println "BPF filesystem mounted:" (:bpf-fs-mounted checks))
    (println "CAP_BPF:" (:has-cap-bpf checks))
    (println))

  (println "Loading BPF program for tracepoint...")
  (try
    (bpf/with-program [prog {:prog-type :raw-tracepoint
                             :insns simple-bpf-program
                             :license "GPL"
                             :prog-name "simple_tp"}]
      (println "Program loaded successfully! FD:" (:fd prog))
      (println "Program type:" (:type prog))
      (println "Instruction count:" (:insn-count prog))
      (println)

      (println "Attaching to sched:sched_switch tracepoint...")
      (let [tp-fd (syscall/raw-tracepoint-open "sched_switch" (:fd prog))]
        (println "Attached successfully! Tracepoint FD:" tp-fd)
        (println)

        (println "Press Ctrl+C to exit...")
        (println "The tracepoint is now active and will be called on every context switch")
        (println "(though this simple program does nothing)")
        (Thread/sleep 5000)

        (println "\nDetaching and cleaning up...")
        (syscall/close-fd tp-fd)))

    (println "Done!")

    (catch Exception e
      (println "Error:" (.getMessage e))
      (.printStackTrace e)
      (when-let [data (ex-data e)]
        (println "Details:" data)
        (when-let [log (:verifier-log data)]
          (println "\nVerifier log:")
          (println log))))))

;; ============================================================================
;; NEW WAY: Using declarative macros
;; ============================================================================

(defn run-with-macros
  "Run tracepoint using the new declarative macro approach."
  []
  (println "\n=== Using Declarative Macros (New Way) ===\n")

  (println "Program spec:")
  (println "  Type:" (:prog-type simple-tracepoint-prog))
  (println "  License:" (:license simple-tracepoint-prog))
  (println "  Name:" (:prog-name simple-tracepoint-prog))
  (println)

  (println "Loading program using load-defprogram...")
  (try
    (let [prog (bpf/load-defprogram simple-tracepoint-prog)]
      (try
        (println "Program loaded! FD:" (:fd prog))
        (println "Instruction count:" (:insn-count prog))
        (println)

        (println "Attaching to sched_switch tracepoint...")
        (let [tp-fd (syscall/raw-tracepoint-open "sched_switch" (:fd prog))]
          (try
            (println "Attached! Tracepoint FD:" tp-fd)
            (println)
            (println "Tracing for 3 seconds...")
            (Thread/sleep 3000)
            (println "Done!")
            (finally
              (syscall/close-fd tp-fd))))

        (finally
          (bpf/close-program prog))))

    (catch Exception e
      (println "Error (may need sudo):" (.getMessage e)))))

(defn -main
  [& args]
  (println "Simple Tracepoint Example")
  (println "=========================")

  (if (some #{"--new" "-n"} args)
    ;; Just run the new way
    (run-with-macros)
    ;; Run traditional way
    (run-simple-tracepoint))

  (println)
  (println "Tip: Run with --new to see the declarative macro approach"))
