(ns lab-4-1-process-tree
  "Lab 4.1: Process Tree Monitor using process helper functions

   This solution demonstrates:
   - Using process/task helper functions
   - Reading task_struct fields safely
   - Tracking process relationships
   - Building hierarchical data structures
   - Real-time process monitoring

   Run with: sudo clojure -M -m lab-4-1-process-tree
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; ============================================================================
;;; Part 1: Data Structures
;;; ============================================================================

;; Process info structure (stored in map)
;; struct process_info {
;;   u32 pid;        // offset 0
;;   u32 ppid;       // offset 4
;;   u32 uid;        // offset 8
;;   u32 gid;        // offset 12
;;   char comm[16];  // offset 16
;;   u64 start_time; // offset 32
;; };

(def PROCESS_INFO_SIZE (+ 4 4 4 4 16 8))  ; 40 bytes

;;; ============================================================================
;;; Part 2: Maps
;;; ============================================================================

(defn create-process-map
  "Map: PID -> process_info"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4                    ; u32 PID
                   :value-size PROCESS_INFO_SIZE  ; process_info struct
                   :max-entries 10000
                   :map-name "process_info"}))

(defn create-parent-map
  "Map: PID -> PPID (for quick parent lookup)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4    ; u32 PID
                   :value-size 4  ; u32 PPID
                   :max-entries 10000
                   :map-name "parent_map"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/int->bytes
                   :value-deserializer utils/bytes->int}))

;;; ============================================================================
;;; Part 3: BPF Program - Process Info Capturer
;;; ============================================================================

(defn create-process-info-program
  "Create BPF program that demonstrates helper function usage.

   This simplified program demonstrates:
   - bpf_get_current_pid_tgid() - Get process ID
   - bpf_get_current_uid_gid() - Get user ID
   - bpf_get_current_comm() - Get process name (requires stack buffer)
   - bpf_ktime_get_ns() - Get timestamp

   Note: Full implementation with comm reading requires tracepoint/kprobe
   attachment which is covered in Chapter 5.

   Instruction layout:
   0: call bpf_get_current_pid_tgid
   1: mov-reg r6, r0     ; save pid_tgid
   2: rsh r6, 32         ; extract TGID (PID)
   3: call bpf_get_current_uid_gid
   4: mov-reg r7, r0     ; save uid_gid
   5: rsh r7, 32         ; extract UID
   6: call bpf_ktime_get_ns
   7: mov-reg r8, r0     ; save timestamp
   8: mov r0, 0          ; return 0
   9: exit"
  []
  (bpf/assemble
    [;; Step 1: Get PID/TGID
     (bpf/call 14)              ; BPF_FUNC_get_current_pid_tgid = 14
     (bpf/mov-reg :r6 :r0)      ; r6 = pid_tgid
     (bpf/rsh :r6 32)           ; r6 = TGID (process ID)

     ;; Step 2: Get UID/GID
     (bpf/call 15)              ; BPF_FUNC_get_current_uid_gid = 15
     (bpf/mov-reg :r7 :r0)      ; r7 = uid_gid
     (bpf/rsh :r7 32)           ; r7 = UID

     ;; Step 3: Get timestamp
     (bpf/call 5)               ; BPF_FUNC_ktime_get_ns = 5
     (bpf/mov-reg :r8 :r0)      ; r8 = timestamp

     ;; Return 0
     (bpf/mov :r0 0)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 4: Userspace - Process Tree Construction
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

(defn parse-process-info [^bytes buf]
  "Parse process_info structure from raw bytes"
  {:pid (read-u32-le buf 0)
   :ppid (read-u32-le buf 4)
   :uid (read-u32-le buf 8)
   :gid (read-u32-le buf 12)
   :comm (read-string-from-bytes buf 16 16)
   :start-time (read-u64-le buf 32)})

(defn get-all-processes [process-map]
  "Read all processes from map"
  (into {}
        (for [[k v] (bpf/map-entries process-map)
              :let [pid (read-u32-le k 0)
                    info (parse-process-info v)]]
          [pid info])))

(defn build-process-tree [processes]
  "Build hierarchical process tree"
  (let [children (group-by :ppid (vals processes))]
    (letfn [(build-node [pid depth]
              (when-let [proc (get processes pid)]
                {:process proc
                 :depth depth
                 :children (vec (keep #(build-node (:pid %) (inc depth))
                                     (get children pid [])))}))]
      ;; Start from roots (processes with no known parent)
      (let [roots (filter #(or (= (:ppid %) 0)
                              (not (contains? processes (:ppid %))))
                         (vals processes))]
        (vec (keep #(build-node (:pid %) 0) roots))))))

(defn format-process-tree
  "Format process tree as ASCII art"
  ([tree] (format-process-tree tree ""))
  ([nodes prefix]
   (when (seq nodes)
     (let [lines (atom [])]
       (doseq [[idx node] (map-indexed vector nodes)
               :when node
               :let [is-last (= idx (dec (count nodes)))
                     proc (:process node)
                     connector (if is-last "└─" "├─")
                     extension (if is-last "  " "│ ")]]
         (swap! lines conj
                (format "%s%s %s (PID: %d, PPID: %d, UID: %d)"
                       prefix
                       connector
                       (:comm proc)
                       (:pid proc)
                       (:ppid proc)
                       (:uid proc)))
         (when (seq (:children node))
           (swap! lines concat
                  (format-process-tree (:children node)
                                     (str prefix extension "  ")))))
       @lines))))

(defn display-process-tree [process-map]
  "Display the complete process tree"
  (let [processes (get-all-processes process-map)
        tree (build-process-tree processes)]

    (println "\n╔════════════════════════════════════════════════════════╗")
    (println "║              Process Tree                              ║")
    (println "╚════════════════════════════════════════════════════════╝")
    (println)

    (if (empty? processes)
      (println "No processes tracked yet")
      (do
        (println "Total processes:" (count processes))
        (println)
        (doseq [line (format-process-tree tree)]
          (println line))))

    (println)))

(defn display-process-stats [process-map]
  "Display process statistics"
  (let [processes (vals (get-all-processes process-map))
        by-user (group-by :uid processes)
        by-name (frequencies (map :comm processes))]

    (println "\nProcess Statistics:")
    (println "═══════════════════════════════════════")
    (println "Total processes:" (count processes))
    (println)
    (println "By User:")
    (doseq [[uid procs] (sort-by key by-user)]
      (println (format "  UID %4d: %3d processes" uid (count procs))))
    (println)
    (println "Top Process Names:")
    (doseq [[name cnt] (take 10 (sort-by val > by-name))]
      (println (format "  %-20s: %3d" name cnt)))))

;;; ============================================================================
;;; Part 5: Simulation Data
;;; ============================================================================

(defn create-process-info-bytes
  "Create process_info struct as bytes"
  [pid ppid uid gid comm start-time]
  (let [buf (ByteBuffer/allocate PROCESS_INFO_SIZE)]
    (.order buf ByteOrder/LITTLE_ENDIAN)
    (.putInt buf 0 pid)
    (.putInt buf 4 ppid)
    (.putInt buf 8 uid)
    (.putInt buf 12 gid)
    ;; comm (16 bytes, null-padded)
    (.position buf 16)
    (let [comm-bytes (.getBytes comm "UTF-8")]
      (.put buf comm-bytes 0 (min (count comm-bytes) 15)))
    (.putLong buf 32 start-time)
    (.array buf)))

(defn simulate-process-data
  "Simulate process data for demonstration"
  [process-map parent-map]
  (println "\n  Simulating process data...")

  (let [test-processes [[1 0 0 0 "init"]
                        [142 1 0 0 "systemd-journald"]
                        [897 1 0 0 "sshd"]
                        [12045 897 1000 1000 "sshd"]
                        [12046 12045 1000 1000 "bash"]
                        [12123 12046 1000 1000 "vim"]
                        [12150 12046 1000 1000 "clojure"]
                        [923 1 0 0 "cron"]
                        [1024 1 0 0 "nginx"]
                        [1025 1024 33 33 "nginx-worker"]
                        [1026 1024 33 33 "nginx-worker"]]]

    (doseq [[pid ppid uid gid comm] test-processes]
      (let [key-bytes (utils/int->bytes pid)
            value-bytes (create-process-info-bytes pid ppid uid gid comm (System/nanoTime))]
        (bpf/map-update process-map key-bytes value-bytes)
        (bpf/map-update parent-map pid ppid)))

    (println "  Added" (count test-processes) "test processes")))

;;; ============================================================================
;;; Part 6: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 4.1: Process Tree Monitor ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating maps...")
  (let [process-map (create-process-map)
        parent-map (create-parent-map)]
    (println "  Process map created (FD:" (:fd process-map) ")")
    (println "  Parent map created (FD:" (:fd parent-map) ")")

    (try
      ;; Step 3: Create BPF program
      (println "\nStep 3: Creating BPF program...")
      (let [program (create-process-info-program)]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :kprobe
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Explain tracepoint attachment
            (println "\nStep 5: Tracepoint attachment info...")
            (println "  Note: Tracepoint attachment requires Chapter 5")
            (println "  Would attach to:")
            (println "    - sched:sched_process_fork")
            (println "    - sched:sched_process_exit")

            ;; Step 6: Simulate process data
            (println "\nStep 6: Simulating process data...")
            (simulate-process-data process-map parent-map)

            ;; Step 7: Display process tree
            (println "\nStep 7: Displaying process tree...")
            (display-process-tree process-map)

            ;; Step 8: Display statistics
            (println "\nStep 8: Displaying statistics...")
            (display-process-stats process-map)

            ;; Step 9: Process lineage example
            (println "\nStep 9: Process lineage example...")
            (println "  Lineage for PID 12123 (vim):")
            (let [lineage (loop [pid 12123
                                 chain []]
                            (let [ppid (bpf/map-lookup parent-map pid)]
                              (if (and ppid (pos? ppid))
                                (recur ppid (conj chain pid))
                                (conj chain pid))))]
              (println "   " (str/join " -> " (map str (reverse lineage)))))

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
        (bpf/close-map process-map)
        (bpf/close-map parent-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 4.1 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test tree building
  (let [processes {1 {:pid 1 :ppid 0 :comm "init"}
                   2 {:pid 2 :ppid 1 :comm "bash"}
                   3 {:pid 3 :ppid 2 :comm "vim"}}]
    (build-process-tree processes))
  )
