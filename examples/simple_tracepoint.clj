(ns simple-tracepoint
  "Simple tracepoint example - trace sched_switch"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.syscall :as syscall]))

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

(defn -main
  [& args]
  (run-simple-tracepoint))
