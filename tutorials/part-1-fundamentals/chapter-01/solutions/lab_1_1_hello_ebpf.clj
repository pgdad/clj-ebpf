(ns lab-1-1-hello-ebpf
  "Lab 1.1: Hello eBPF - Your first BPF program

   This solution demonstrates:
   - Initializing clj-ebpf
   - Creating a minimal BPF program
   - Loading it into the kernel
   - Proper cleanup

   Run with: clojure -M -m lab-1-1-hello-ebpf
   Note: Requires root/CAP_BPF privileges for kernel operations"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.errors :as errors]))

(defn display-platform-info
  "Display platform and architecture information"
  []
  (println "Platform Information:")
  (println "  Architecture:" arch/arch-name)
  (println "  Arch keyword:" arch/current-arch)
  (println "  BPF syscall number:" (arch/get-syscall-nr :bpf)))

(defn create-hello-program
  "Create the simplest possible BPF program.
   This program just returns 0 and exits."
  []
  (bpf/assemble
    [;; mov r0, 0  - Set return value to 0 (success)
     (bpf/mov :r0 0)
     ;; exit - Return from program
     (bpf/exit-insn)]))

(defn load-and-run-program
  "Load the BPF program into the kernel and verify it works"
  [program]
  (println "\nLoading program into kernel...")
  (let [prog-fd (bpf/load-program {:prog-type :socket-filter :insns program})]
    (println "  Program loaded successfully!")
    (println "  Program FD:" prog-fd)
    (println "  Program passed verifier")

    ;; Return the fd for cleanup
    prog-fd))

(defn cleanup-program
  "Unload the BPF program"
  [prog-fd]
  (println "\nCleaning up...")
  (bpf/close-program prog-fd)
  (println "  Program unloaded"))

(defn run-lab []
  (println "=== Lab 1.1: Hello eBPF ===\n")

  ;; Step 0: Display platform info
  (println "Step 0: Platform Information")
  (display-platform-info)

  ;; Step 1: Initialize clj-ebpf
  (println "\nStep 1: Initializing clj-ebpf...")
  (let [init-result (bpf/init!)]
    (println "  Kernel version:" (format "0x%06x" (:kernel-version init-result)))
    (println "  BPF filesystem:" (if (:bpf-fs-mounted init-result)
                                   "mounted"
                                   "NOT mounted")))

  ;; Step 2: Create BPF program
  (println "\nStep 2: Creating BPF program...")
  (let [hello-program (create-hello-program)]
    (println "  Program assembled successfully!")
    (println "  Program size:" (count hello-program) "bytes")
    (println "  Instructions:" (/ (count hello-program) 8))

    ;; Step 3: Load and run
    (println "\nStep 3: Loading program...")
    (try
      (let [prog-fd (load-and-run-program hello-program)]

        ;; Step 4: Cleanup
        (cleanup-program prog-fd)

        (println "\n=== Lab 1.1 Complete! ===")
        true)

      (catch Exception e
        (println "\nError:" (.getMessage e))
        (println (errors/format-error e))

        (cond
          (errors/permission-error? e)
          (do
            (println "\nPermission Error - Try:")
            (println "  - Run with sudo")
            (println "  - Add CAP_BPF: sudo setcap cap_bpf+eip $(which java)"))

          (errors/verifier-error? e)
          (do
            (println "\nVerifier Error - Check:")
            (println "  - Program ends with exit instruction")
            (println "  - All registers initialized before use"))

          :else
          (do
            (println "\nTroubleshooting:")
            (println "  - Check BPF filesystem: ls /sys/fs/bpf")
            (println "  - Check kernel version: uname -r (need 5.8+)")))

        false))))

;; Challenge solution: Create a BPF program that adds two numbers,
;; multiplies by 3, and returns the result
(defn create-challenge-program
  "Challenge: (5 + 7) * 3 = 36"
  []
  (bpf/assemble
    [;; r0 = 5
     (bpf/mov :r0 5)
     ;; r0 = r0 + 7 = 12
     (bpf/add :r0 7)
     ;; r0 = r0 * 3 = 36
     (bpf/mul :r0 3)
     ;; exit with result in r0
     (bpf/exit-insn)]))

(defn run-challenge []
  (println "\n=== Lab 1.1 Challenge: Math Operations ===\n")
  (println "Creating program: (5 + 7) * 3 = 36")

  (let [program (create-challenge-program)]
    (println "Program size:" (count program) "bytes")
    (println "Instructions:" (/ (count program) 8))

    (try
      (let [prog-fd (bpf/load-program {:prog-type :socket-filter :insns program})]
        (println "Challenge program loaded successfully!")
        (println "Program FD:" prog-fd)
        (bpf/close-program prog-fd)
        (println "\n=== Challenge Complete! ===")
        true)
      (catch Exception e
        (println "Error:" (.getMessage e))
        false))))

(defn -main [& args]
  (let [result (run-lab)]
    (when result
      (run-challenge))
    (System/exit (if result 0 1))))

;; For REPL usage
(comment
  (run-lab)
  (run-challenge)

  ;; Experiment 1: Change return value
  (def prog-42 (bpf/assemble [(bpf/mov :r0 42) (bpf/exit-insn)]))

  ;; Experiment 2: Multiple instructions
  (def prog-add (bpf/assemble
                  [(bpf/mov :r0 10)
                   (bpf/add :r0 32)
                   (bpf/exit-insn)]))

  ;; Experiment 3: This will fail - no exit instruction
  ;; (def prog-invalid (bpf/assemble [(bpf/mov :r0 0)]))
  )
