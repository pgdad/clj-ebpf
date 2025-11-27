(ns lab-6-3-syscall-analyzer
  "Lab 6.3: System Call Frequency Analyzer using Tracepoints

   This solution demonstrates:
   - Using syscall tracepoints for system-wide monitoring
   - Tracking syscall frequency across all processes
   - Per-process syscall profiling
   - Measuring syscall latency distributions
   - Detecting anomalous syscall behavior

   Run with: sudo clojure -M -m lab-6-3-syscall-analyzer
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Constants and Syscall Numbers
;;; ============================================================================

;; Common offsets for syscall tracepoints
(def SYSCALL_ENTER_OFFSETS
  {:syscall-nr 8      ; int (4 bytes)
   :arg0 16           ; First argument
   :arg1 24
   :arg2 32
   :arg3 40
   :arg4 48
   :arg5 56})

(def SYSCALL_EXIT_OFFSETS
  {:syscall-nr 8      ; int (4 bytes)
   :ret 16})          ; long (8 bytes)

;; Common x86_64 syscall numbers
(def SYSCALL_NUMBERS
  {:read 0
   :write 1
   :open 2
   :close 3
   :stat 4
   :fstat 5
   :lstat 6
   :poll 7
   :lseek 8
   :mmap 9
   :mprotect 10
   :munmap 11
   :brk 12
   :rt-sigaction 13
   :rt-sigprocmask 14
   :ioctl 16
   :pread64 17
   :pwrite64 18
   :readv 19
   :writev 20
   :access 21
   :pipe 22
   :select 23
   :sched-yield 24
   :dup 32
   :dup2 33
   :getpid 39
   :socket 41
   :connect 42
   :accept 43
   :sendto 44
   :recvfrom 45
   :bind 49
   :listen 50
   :clone 56
   :fork 57
   :vfork 58
   :execve 59
   :exit 60
   :wait4 61
   :kill 62
   :fcntl 72
   :flock 73
   :fsync 74
   :fdatasync 75
   :getdents 78
   :getcwd 79
   :chdir 80
   :rename 82
   :mkdir 83
   :rmdir 84
   :unlink 87
   :readlink 89
   :gettimeofday 96
   :getuid 102
   :getgid 104
   :setuid 105
   :setgid 106
   :geteuid 107
   :getegid 108
   :epoll-create 213
   :epoll-ctl 233
   :epoll-wait 232
   :openat 257
   :futex 202
   :nanosleep 35})

;; Reverse lookup: number -> name
(def SYSCALL_NAMES
  (into {} (map (fn [[k v]] [v (name k)]) SYSCALL_NUMBERS)))

(def MAX_ENTRIES 10000)
(def MAX_SYSCALLS 512)

;;; ============================================================================
;;; Part 2: Maps
;;; ============================================================================

(defn create-syscall-count-map
  "Array map: syscall_nr -> count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries MAX_SYSCALLS
                   :map-name "syscall_counts"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-latency-map
  "Array map: syscall_nr -> {count, total_latency, max_latency}"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 24           ; 3 * u64
                   :max-entries MAX_SYSCALLS
                   :map-name "syscall_latency"}))

(defn create-start-times-map
  "Hash map: (pid_tgid) -> start_timestamp"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8
                   :value-size 8
                   :max-entries MAX_ENTRIES
                   :map-name "syscall_start"}))

(defn create-error-count-map
  "Array map: syscall_nr -> error_count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries MAX_SYSCALLS
                   :map-name "syscall_errors"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 3: BPF Program - Syscall Entry Handler
;;; ============================================================================

(defn create-syscall-entry-handler
  "Create BPF program to count syscall entries.

   This simplified program demonstrates:
   - Reading syscall number from tracepoint context
   - Incrementing syscall counter
   - Recording entry timestamp for latency measurement

   Instruction layout:
   0: mov-reg r8, r1        ; save ctx
   1: call get_current_pid_tgid
   2: mov-reg r6, r0        ; r6 = pid_tgid
   3: call ktime_get_ns
   4: mov-reg r7, r0        ; r7 = timestamp
   5-8: store start time
   9: mov r0, 0
   10: exit"
  [counts-fd start-times-fd]
  (bpf/assemble
    [;; Save ctx pointer
     (bpf/mov-reg :r8 :r1)

     ;; Get PID/TGID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r6 :r0)      ; r6 = pid_tgid

     ;; Get timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r7 :r0)      ; r7 = timestamp

     ;; Store start time: map[pid_tgid] = timestamp
     (bpf/store-mem :dw :r10 -8 :r6)
     (bpf/store-mem :dw :r10 -16 :r7)

     (bpf/ld-map-fd :r1 start-times-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)           ; r2 = &key
     (bpf/mov-reg :r3 :r10)
     (bpf/add :r3 -16)          ; r3 = &value
     (bpf/mov :r4 0)            ; flags = BPF_ANY
     (bpf/call 2)               ; BPF_FUNC_map_update_elem

     ;; Note: Full implementation would also increment syscall counter
     ;; This requires reading syscall_nr from ctx which varies by arch

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 4: BPF Program - Syscall Exit Handler
;;; ============================================================================

(defn create-syscall-exit-handler
  "Create BPF program to handle syscall exits.

   This simplified program demonstrates:
   - Looking up start time
   - Calculating latency
   - Checking return value for errors

   Instruction layout:
   0: mov-reg r8, r1
   1: call get_current_pid_tgid
   2: mov-reg r6, r0
   3: call ktime_get_ns
   4: mov-reg r9, r0
   5-8: lookup start time
   9: mov r0, 0
   10: exit"
  [start-times-fd latency-fd error-count-fd]
  (bpf/assemble
    [;; Save ctx pointer
     (bpf/mov-reg :r8 :r1)

     ;; Get PID/TGID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid
     (bpf/mov-reg :r6 :r0)

     ;; Get current timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns
     (bpf/mov-reg :r9 :r0)      ; r9 = end_time

     ;; Lookup start time
     (bpf/store-mem :dw :r10 -8 :r6)
     (bpf/ld-map-fd :r1 start-times-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)
     (bpf/call 1)               ; BPF_FUNC_map_lookup_elem

     ;; Note: Full implementation would:
     ;; 1. Calculate latency = end_time - start_time
     ;; 2. Read return value and check if negative (error)
     ;; 3. Update latency statistics
     ;; 4. Delete start time entry

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Userspace - Statistics and Visualization
;;; ============================================================================

(defn format-latency [ns]
  "Format nanoseconds as human-readable time"
  (cond
    (< ns 1000) (format "%dns" ns)
    (< ns 1000000) (format "%.1fμs" (/ ns 1000.0))
    (< ns 1000000000) (format "%.1fms" (/ ns 1000000.0))
    :else (format "%.2fs" (/ ns 1000000000.0))))

(defn display-syscall-frequency [counts-map]
  "Display syscall frequency statistics"
  (println "\nTop 25 System Calls by Frequency:")
  (println "═══════════════════════════════════════════════════════════════════")
  (println "Syscall Nr │ Name              │ Count       │ % of Total │ Bar")
  (println "───────────┼───────────────────┼─────────────┼────────────┼──────────")

  (let [syscall-counts (for [nr (range MAX_SYSCALLS)
                             :let [cnt (or (bpf/map-lookup counts-map nr) 0)]
                             :when (pos? cnt)]
                         [nr cnt])
        total (reduce + (map second syscall-counts))
        max-count (apply max (conj (map second syscall-counts) 1))
        sorted (->> syscall-counts
                    (sort-by second >)
                    (take 25))]

    (doseq [[nr cnt] sorted]
      (let [name (get SYSCALL_NAMES nr (format "syscall_%d" nr))
            pct (if (pos? total) (* 100.0 (/ cnt total)) 0.0)
            bar-len (int (* 20 (/ cnt max-count)))
            bar (apply str (repeat bar-len "█"))]
        (println (format "%10d │ %-17s │ %,11d │ %9.2f%% │ %s"
                        nr name cnt pct bar))))

    (println "═══════════════════════════════════════════════════════════════════")
    (println (format "Total syscalls: %,d" total))))

(defn display-syscall-latency [latency-map counts-map]
  "Display syscall latency statistics"
  (println "\nSyscall Latency Statistics (Top 20 by Total Time):")
  (println "═══════════════════════════════════════════════════════════════════════════════")
  (println "Syscall          │ Count       │ Avg Latency │ Max Latency │ Total Time")
  (println "─────────────────┼─────────────┼─────────────┼─────────────┼─────────────")

  ;; For simulation, use counts map with synthetic latencies
  (let [latency-data (for [nr (range MAX_SYSCALLS)
                           :let [cnt (or (bpf/map-lookup counts-map nr) 0)]
                           :when (pos? cnt)]
                       (let [name (get SYSCALL_NAMES nr (format "syscall_%d" nr))
                             ;; Simulate average latency based on syscall type
                             avg-ns (case nr
                                      0 4500    ; read
                                      1 3200    ; write
                                      7 2300    ; poll
                                      16 1200   ; ioctl
                                      9 2500    ; mmap
                                      44 5600   ; sendto
                                      45 6700   ; recvfrom
                                      257 8900  ; openat
                                      3 1100    ; close
                                      (* 500 (inc (rand-int 10))))
                             max-ns (* avg-ns (+ 2 (rand-int 20)))
                             total-ns (* cnt avg-ns)]
                         [name cnt avg-ns max-ns total-ns]))
        sorted (->> latency-data
                    (sort-by #(nth % 4) >)
                    (take 20))]

    (doseq [[name cnt avg-ns max-ns total-ns] sorted]
      (println (format "%-16s │ %,11d │ %11s │ %11s │ %s"
                       name cnt
                       (format-latency avg-ns)
                       (format-latency max-ns)
                       (format-latency total-ns))))

    (println "═══════════════════════════════════════════════════════════════════════════════")))

(defn display-error-rates [counts-map error-map]
  "Display syscall error rates"
  (println "\nSyscall Error Rates (Top 10 by Error Count):")
  (println "═══════════════════════════════════════════════════════════════════")
  (println "Syscall          │ Total       │ Errors      │ Error Rate")
  (println "─────────────────┼─────────────┼─────────────┼───────────")

  (let [error-data (for [nr (range MAX_SYSCALLS)
                         :let [cnt (or (bpf/map-lookup counts-map nr) 0)
                               err (or (bpf/map-lookup error-map nr) 0)]
                         :when (pos? err)]
                     [(get SYSCALL_NAMES nr (format "syscall_%d" nr))
                      cnt err])
        sorted (->> error-data
                    (sort-by #(nth % 2) >)
                    (take 10))]

    (doseq [[name cnt err] sorted]
      (let [rate (if (pos? cnt) (* 100.0 (/ err cnt)) 0.0)]
        (println (format "%-16s │ %,11d │ %,11d │ %8.2f%%"
                         name cnt err rate))))

    (println "═══════════════════════════════════════════════════════════════════")))

;;; ============================================================================
;;; Part 6: Simulation
;;; ============================================================================

(defn simulate-syscall-data
  "Simulate syscall monitoring data"
  [counts-map error-map]
  (println "\n  Simulating syscall data...")

  ;; Simulate syscall frequency (realistic distribution)
  (let [syscall-counts
        {0 45678      ; read
         1 23456      ; write
         7 15234      ; poll
         14 12345     ; rt_sigprocmask
         16 9876      ; ioctl
         72 6789      ; fcntl
         13 5432      ; rt_sigaction
         3 4567       ; close
         257 3456     ; openat
         9 2345       ; mmap
         11 2134      ; munmap
         202 8765     ; futex
         44 1234      ; sendto
         45 1123      ; recvfrom
         41 456       ; socket
         42 389       ; connect
         59 25        ; execve
         56 50        ; clone
         57 15        ; fork
         105 3        ; setuid
         62 2}]       ; kill

    ;; Update counts
    (doseq [[nr cnt] syscall-counts]
      (bpf/map-update counts-map nr cnt))

    ;; Simulate errors
    (let [errors {257 150      ; openat - file not found
                  42 80        ; connect - connection refused
                  0 20         ; read - interrupted
                  1 15         ; write - broken pipe
                  4 200}]      ; stat - no such file
      (doseq [[nr cnt] errors]
        (bpf/map-update error-map nr cnt)))

    (println (format "  Simulated %,d syscalls with %d types"
                     (reduce + (vals syscall-counts))
                     (count syscall-counts)))))

(defn display-simulated-profile
  "Display simulated per-process syscall profile"
  []
  (println "\nTop Processes by Syscall Activity:")
  (println "═══════════════════════════════════════════════════════════════════════════")

  (let [processes [{:pid 1234 :comm "firefox" :total 23456
                    :top [["poll" 12345 52.6]
                          ["read" 5678 24.2]
                          ["write" 3456 14.7]
                          ["recvfrom" 1234 5.3]
                          ["sendto" 743 3.2]]}
                   {:pid 5678 :comm "java" :total 18934
                    :top [["read" 8765 46.3]
                          ["write" 4321 22.8]
                          ["mmap" 2345 12.4]
                          ["futex" 1876 9.9]
                          ["rt_sigprocmask" 1627 8.6]]}
                   {:pid 9012 :comm "postgres" :total 15678
                    :top [["read" 7890 50.3]
                          ["write" 4567 29.1]
                          ["lseek" 2345 15.0]
                          ["fsync" 876 5.6]]}
                   {:pid 3456 :comm "nginx" :total 12345
                    :top [["poll" 6543 53.0]
                          ["write" 3210 26.0]
                          ["read" 1543 12.5]
                          ["accept" 654 5.3]
                          ["close" 395 3.2]]}]]

    (doseq [{:keys [pid comm total top]} processes]
      (println (format "\nPID %d (%s) - %,d total syscalls" pid comm total))
      (doseq [[name cnt pct] top]
        (println (format "  %-20s: %,8d (%5.1f%%)" name cnt pct)))))

  (println "\n═══════════════════════════════════════════════════════════════════════════"))

;;; ============================================================================
;;; Part 7: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 6.3: System Call Frequency Analyzer ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [counts-map (create-syscall-count-map)
        error-map (create-error-count-map)
        start-times-map (create-start-times-map)
        latency-map (create-latency-map)]
    (println "  Syscall counts map created (FD:" (:fd counts-map) ")")
    (println "  Error counts map created (FD:" (:fd error-map) ")")
    (println "  Start times map created (FD:" (:fd start-times-map) ")")
    (println "  Latency map created (FD:" (:fd latency-map) ")")

    ;; Initialize maps
    (doseq [i (range MAX_SYSCALLS)]
      (bpf/map-update counts-map i 0)
      (bpf/map-update error-map i 0))

    (try
      ;; Step 3: Create BPF programs
      (println "\nStep 3: Creating BPF programs...")
      (let [entry-prog (create-syscall-entry-handler (:fd counts-map)
                                                      (:fd start-times-map))
            exit-prog (create-syscall-exit-handler (:fd start-times-map)
                                                    (:fd latency-map)
                                                    (:fd error-map))]
        (println "  Entry handler assembled (" (/ (count entry-prog) 8) "instructions)")
        (println "  Exit handler assembled (" (/ (count exit-prog) 8) "instructions)")

        ;; Step 4: Load programs
        (println "\nStep 4: Loading programs into kernel...")
        (let [entry-loaded (bpf/load-program {:prog-type :tracepoint
                                              :insns entry-prog})
              exit-loaded (bpf/load-program {:prog-type :tracepoint
                                              :insns exit-prog})]
          (println "  Entry handler loaded (FD:" (:fd entry-loaded) ")")
          (println "  Exit handler loaded (FD:" (:fd exit-loaded) ")")

          (try
            ;; Step 5: Explain tracepoint attachment
            (println "\nStep 5: Syscall tracepoint info...")
            (println "  Would attach to:")
            (println "    - raw_syscalls/sys_enter (all syscall entries)")
            (println "    - raw_syscalls/sys_exit (all syscall exits)")
            (println)
            (println "  Tracepoint context format:")
            (println "    ┌──────────────────────────────────────┐")
            (println "    │ Field        │ Offset │ Description  │")
            (println "    ├──────────────┼────────┼──────────────┤")
            (println "    │ __syscall_nr │     8  │ Syscall num  │")
            (println "    │ arg0-arg5    │ 16-56  │ Arguments    │")
            (println "    │ ret          │    16  │ Return value │")
            (println "    └──────────────────────────────────────┘")

            ;; Step 6: Show common syscall numbers
            (println "\nStep 6: Common syscall numbers (x86_64):")
            (let [common-syscalls [:read :write :open :close :poll :mmap :ioctl
                                   :socket :connect :execve :openat :futex]]
              (doseq [syscall common-syscalls]
                (println (format "    %3d = %s" (get SYSCALL_NUMBERS syscall) (name syscall)))))

            ;; Step 7: Simulate syscall data
            (println "\nStep 7: Simulating syscall data...")
            (simulate-syscall-data counts-map error-map)

            ;; Step 8: Display frequency statistics
            (println "\nStep 8: Frequency analysis...")
            (display-syscall-frequency counts-map)

            ;; Step 9: Display latency statistics
            (println "\nStep 9: Latency analysis...")
            (display-syscall-latency latency-map counts-map)

            ;; Step 10: Display error rates
            (println "\nStep 10: Error analysis...")
            (display-error-rates counts-map error-map)

            ;; Step 11: Display per-process profile
            (println "\nStep 11: Per-process profile...")
            (display-simulated-profile)

            ;; Step 12: Cleanup
            (println "\nStep 12: Cleanup...")
            (bpf/close-program entry-loaded)
            (bpf/close-program exit-loaded)
            (println "  Programs closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map counts-map)
        (bpf/close-map error-map)
        (bpf/close-map start-times-map)
        (bpf/close-map latency-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 6.3 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Lookup syscall name
  (get SYSCALL_NAMES 59)  ; => "execve"

  ;; Lookup syscall number
  (get SYSCALL_NUMBERS :read)  ; => 0
  )
