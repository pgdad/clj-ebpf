(ns simple-kprobe
  "Simple kprobe example - trace schedule() kernel function

   This example demonstrates two approaches:
   1. Using the new declarative macros (defprogram, with-bpf-script)
   2. Using the traditional explicit bytecode approach

   The new macros reduce boilerplate and make the code more readable."
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.macros :refer [defprogram with-bpf-script]]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]))

;; ============================================================================
;; NEW WAY: Using declarative macros
;; ============================================================================

;; Define the kprobe program declaratively
(defprogram simple-kprobe-prog
  :type :kprobe
  :license "GPL"
  :opts {:prog-name "simple_kprobe"}
  :body [(dsl/mov :r0 0)      ; Return 0
         (dsl/exit-insn)])

;; ============================================================================
;; OLD WAY: Manual bytecode (kept for reference)
;; ============================================================================

;; Simple BPF program that just returns 0 (does nothing but is valid)
;; This is the bytecode for:
;;   r0 = 0
;;   exit
(def simple-bpf-program
  (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00  ; mov r0, 0
               0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00])) ; exit

(defn run-simple-kprobe
  "Run a simple kprobe that attaches to sys_clone"
  []
  (println "Simple kprobe example")
  (println "=====================\n")

  ;; Check BPF is available
  (println "Checking BPF availability...")
  (let [checks (bpf/check-bpf-available)]
    (println "Kernel version:" (format "0x%06x" (:kernel-version checks)))
    (println "BPF filesystem mounted:" (:bpf-fs-mounted checks))
    (println "CAP_BPF:" (:has-cap-bpf checks))
    (println))

  (println "Loading BPF program...")
  (try
    (bpf/with-program [prog {:prog-type :kprobe
                             :insns simple-bpf-program
                             :license "GPL"
                             :prog-name "simple_kprobe"}]
      (println "Program loaded successfully! FD:" (:fd prog))
      (println "Program type:" (:type prog))
      (println "Instruction count:" (:insn-count prog))
      (println)

      (println "Attaching to schedule...")
      (let [attached (programs/attach-kprobe prog {:function "schedule"})]
        (println "Attached successfully!")
        (println "Attachments:" (count (:attachments attached)))
        (println)

        (println "Press Ctrl+C to exit...")
        (println "The kprobe is now active and will be called on every schedule()")
        (println "(though this simple program does nothing)")
        (Thread/sleep 10000)

        (println "\nDetaching and cleaning up...")))

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
;; NEW WAY: Using with-bpf-script macro
;; ============================================================================

(defn run-with-macros
  "Run kprobe using the new declarative macro approach."
  []
  (println "\n=== Using Declarative Macros (New Way) ===\n")

  (println "Program spec defined with defprogram:")
  (println "  Type:" (:prog-type simple-kprobe-prog))
  (println "  License:" (:license simple-kprobe-prog))
  (println "  Name:" (:prog-name simple-kprobe-prog))
  (println "  Bytecode size:" (count ((:body-fn simple-kprobe-prog))) "bytes")
  (println)

  (println "Loading with with-bpf-script...")
  (try
    (with-bpf-script
      {:progs  [prog simple-kprobe-prog]
       :attach [{:prog prog :type :kprobe :function "schedule"}]}

      (println "Program loaded! FD:" (:fd prog))
      (println "Attached to schedule()")
      (println)
      (println "Tracing for 5 seconds...")
      (println "(The program just returns 0, but demonstrates the macro workflow)")
      (Thread/sleep 5000)
      (println "Done!"))

    (println "\nResources automatically cleaned up.")

    (catch Exception e
      (println "Error (may need sudo):" (.getMessage e)))))

(defn -main
  [& args]
  (println "Simple Kprobe Example")
  (println "=====================")

  (if (some #{"--new" "-n"} args)
    ;; Run with macros
    (run-with-macros)
    ;; Run traditional way
    (run-simple-kprobe))

  (println)
  (println "Tip: Run with --new to see the declarative macro approach"))

;; Run from REPL:
;; (require '[examples.simple-kprobe :as ex])
;; (ex/run-simple-kprobe)
;; (ex/run-with-macros)
