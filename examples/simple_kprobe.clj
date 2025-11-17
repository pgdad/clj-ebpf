(ns simple-kprobe
  "Simple kprobe example - trace sys_clone system call"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps]))

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

      (println "Attaching to sys_clone...")
      (let [attached (programs/attach-kprobe prog {:function "__x64_sys_clone"})]
        (println "Attached successfully!")
        (println "Attachments:" (count (:attachments attached)))
        (println)

        (println "Press Ctrl+C to exit...")
        (println "The kprobe is now active and will be called on every sys_clone")
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

(defn -main
  [& args]
  (run-simple-kprobe))

;; Run from REPL:
;; (require '[examples.simple-kprobe :as ex])
;; (ex/run-simple-kprobe)
