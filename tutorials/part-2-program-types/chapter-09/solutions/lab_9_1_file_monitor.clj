(ns lab-9-1-file-monitor
  "Lab 9.1: LSM File Access Monitor

   This solution demonstrates:
   - LSM (Linux Security Modules) BPF concepts
   - File access monitoring and logging
   - Sensitive file detection
   - Security event tracking
   - LSM hook return values (monitoring only - always allows)

   Note: LSM BPF requires kernel 5.7+ with BTF and LSM BPF enabled.
   This solution simulates LSM concepts using tracepoints as fallback.

   Run with: sudo clojure -M -m lab-9-1-file-monitor
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.time Instant LocalDateTime ZoneId]
           [java.time.format DateTimeFormatter]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; File open flags (from fcntl.h)
(def O_RDONLY 0x0000)
(def O_WRONLY 0x0001)
(def O_RDWR 0x0002)
(def O_CREAT 0x0040)
(def O_TRUNC 0x0200)
(def O_APPEND 0x0400)

;; LSM return values
(def LSM_ALLOW 0)
(def LSM_DENY -1)  ; -EPERM

;; Event types
(def EVENT_FILE_ACCESS 1)
(def EVENT_SENSITIVE_ACCESS 2)

;; Sensitive path patterns
(def SENSITIVE_PATHS
  #{"/etc/passwd"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/ssh"
    "/root"
    "/var/log"
    "/proc/kcore"
    "/dev/mem"})

(def SENSITIVE_PREFIXES
  ["/etc/"
   "/root/"
   "/var/log/"
   "/proc/"
   "/sys/kernel/"])

;;; ============================================================================
;;; Part 2: BPF Maps
;;; ============================================================================

(defn create-stats-map
  "Array map for file access statistics:
   [0] = total_accesses
   [1] = sensitive_accesses
   [2] = read_only_accesses
   [3] = write_accesses"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4
                   :map-name "file_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-uid-access-map
  "Hash map: UID -> access count"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries 1024
                   :map-name "uid_access"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 3: LSM BPF Program (Simplified)
;;; ============================================================================

(defn create-file-monitor-program
  "Create LSM-style monitoring program.

   This program demonstrates the file_open LSM hook concept:
   1. Receives context with struct file* pointer
   2. Tracks access statistics
   3. Always returns 0 (ALLOW) - monitoring only

   Note: Real LSM programs use :lsm program type, but require BTF.
   This uses :tracepoint style for broader compatibility."
  [stats-fd]
  (bpf/assemble
    [;; r6 = context pointer
     (bpf/mov-reg :r6 :r1)

     ;; Default stats key = 0 (total accesses)
     (bpf/mov :r9 0)

     ;; Store stats key
     (bpf/store-mem :dw :r10 -8 :r9)

     ;; Lookup stats entry
     (bpf/ld-map-fd :r1 stats-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)
     (bpf/call 1)  ; bpf_map_lookup_elem

     ;; If NULL, skip increment
     (bpf/jmp-imm :jeq :r0 0 3)

     ;; Increment counter
     (bpf/load-mem :dw :r1 :r0 0)
     (bpf/add :r1 1)
     (bpf/store-mem :dw :r0 0 :r1)

     ;; Return 0 (LSM_ALLOW) - monitoring only
     (bpf/mov :r0 LSM_ALLOW)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 4: File Access Classification
;;; ============================================================================

(defn is-sensitive-path?
  "Check if path matches sensitive patterns"
  [path]
  (or (contains? SENSITIVE_PATHS path)
      (some #(str/starts-with? path %) SENSITIVE_PREFIXES)))

(defn classify-access-flags
  "Classify file access by flags"
  [flags]
  (let [mode (bit-and flags 0x3)]
    {:mode (case mode
             0 :read-only
             1 :write-only
             2 :read-write
             :unknown)
     :create? (pos? (bit-and flags O_CREAT))
     :truncate? (pos? (bit-and flags O_TRUNC))
     :append? (pos? (bit-and flags O_APPEND))}))

(defn flags->string
  "Convert open flags to readable string"
  [flags]
  (let [mode (bit-and flags 0x3)]
    (str (case mode
           0 "O_RDONLY"
           1 "O_WRONLY"
           2 "O_RDWR"
           "UNKNOWN")
         (when (pos? (bit-and flags O_CREAT)) "|O_CREAT")
         (when (pos? (bit-and flags O_TRUNC)) "|O_TRUNC")
         (when (pos? (bit-and flags O_APPEND)) "|O_APPEND"))))

;;; ============================================================================
;;; Part 5: Simulated File Access Events
;;; ============================================================================

(defn generate-file-access-event
  "Generate a simulated file access event"
  []
  (let [paths ["/etc/passwd" "/etc/shadow" "/home/user/file.txt"
               "/var/log/syslog" "/tmp/test.txt" "/root/.bashrc"
               "/proc/cpuinfo" "/usr/bin/ls" "/etc/hosts"
               "/var/lib/data.db" "/opt/app/config.json"]
        flags-options [O_RDONLY O_WRONLY O_RDWR
                       (bit-or O_WRONLY O_CREAT)
                       (bit-or O_RDWR O_TRUNC)
                       (bit-or O_WRONLY O_APPEND)]
        uids [0 1000 1001 65534]]  ; root, users, nobody
    {:pid (+ 1000 (rand-int 30000))
     :uid (rand-nth uids)
     :path (rand-nth paths)
     :flags (rand-nth flags-options)
     :timestamp (System/currentTimeMillis)
     :comm (rand-nth ["cat" "vim" "less" "tail" "grep" "python3" "bash"])}))

(defn simulate-file-access
  "Simulate file access events"
  [num-events]
  (repeatedly num-events generate-file-access-event))

;;; ============================================================================
;;; Part 6: Event Processing and Statistics
;;; ============================================================================

(defn process-file-event
  "Process a file access event and update statistics"
  [event stats]
  (let [{:keys [path flags uid]} event
        sensitive? (is-sensitive-path? path)
        access-type (classify-access-flags flags)]

    ;; Update statistics
    (swap! stats update :total inc)
    (when sensitive?
      (swap! stats update :sensitive inc))
    (case (:mode access-type)
      :read-only (swap! stats update :read-only inc)
      :write-only (swap! stats update :write inc)
      :read-write (swap! stats update :write inc)
      nil)

    ;; Track per-UID access
    (swap! stats update-in [:by-uid uid] (fnil inc 0))

    ;; Track sensitive access per UID
    (when sensitive?
      (swap! stats update-in [:sensitive-by-uid uid] (fnil inc 0)))

    ;; Return annotated event
    (assoc event
           :sensitive? sensitive?
           :access-type access-type)))

;;; ============================================================================
;;; Part 7: Display Functions
;;; ============================================================================

(defn format-timestamp
  "Format timestamp for display"
  [ts]
  (let [instant (Instant/ofEpochMilli ts)
        ldt (LocalDateTime/ofInstant instant (ZoneId/systemDefault))
        formatter (DateTimeFormatter/ofPattern "HH:mm:ss.SSS")]
    (.format ldt formatter)))

(defn display-lsm-info
  "Display LSM file monitoring information"
  []
  (println "\nLSM File Access Monitor:")
  (println "===============================================")
  (println "")
  (println "  LSM Hook: file_open")
  (println "  Mode: MONITORING ONLY (always allows)")
  (println "")
  (println "  Sensitive Paths Monitored:")
  (println "    /etc/passwd, /etc/shadow, /etc/sudoers")
  (println "    /root/*, /var/log/*, /proc/*, /sys/kernel/*")
  (println "")
  (println "  Return Values:")
  (println "    0  = ALLOW (monitoring mode)")
  (println "   -1  = DENY (not used in this lab)")
  (println "==============================================="))

(defn display-event
  "Display a single file access event"
  [event]
  (let [{:keys [pid uid path flags comm timestamp sensitive?]} event
        time-str (format-timestamp timestamp)
        flags-str (flags->string flags)
        sens-marker (if sensitive? "[!]" "   ")]
    (printf "%s %s %-6d %-5d %-8s %-18s %s\n"
            sens-marker time-str pid uid comm flags-str path)))

(defn display-events-header
  "Display header for events table"
  []
  (println "\n    TIME         PID    UID   COMM     FLAGS              PATH")
  (println "==============================================================================="))

(defn display-statistics
  "Display file access statistics"
  [{:keys [total sensitive read-only write by-uid sensitive-by-uid]}]
  (println "\nFile Access Statistics:")
  (println "===============================================")
  (println (format "  Total accesses     : %,d" total))
  (println (format "  Sensitive accesses : %,d (%.1f%%)"
                   sensitive (* 100.0 (/ sensitive (max 1 total)))))
  (println (format "  Read-only          : %,d" read-only))
  (println (format "  Write operations   : %,d" write))
  (println "")
  (println "  Access by UID:")
  (doseq [[uid count] (sort-by val > by-uid)]
    (let [uid-name (case uid
                     0 "root"
                     65534 "nobody"
                     (str "user" uid))]
      (println (format "    %-10s (UID %5d): %,d accesses" uid-name uid count))))
  (println "")
  (println "  Sensitive Access by UID:")
  (doseq [[uid count] (sort-by val > sensitive-by-uid)]
    (let [uid-name (case uid
                     0 "root"
                     65534 "nobody"
                     (str "user" uid))]
      (println (format "    %-10s (UID %5d): %,d sensitive accesses" uid-name uid count))))
  (println "==============================================="))

(defn display-security-assessment
  "Display security assessment based on events"
  [stats]
  (let [{:keys [sensitive-by-uid total sensitive]} stats
        high-risk-users (filter (fn [[uid cnt]]
                                  (and (not= uid 0)
                                       (> cnt 5)))
                                sensitive-by-uid)]
    (println "\nSecurity Assessment:")
    (println "===============================================")
    (if (seq high-risk-users)
      (do
        (println "  [!] HIGH RISK: Non-root users accessing sensitive files")
        (doseq [[uid cnt] high-risk-users]
          (println (format "      UID %d: %d sensitive file accesses" uid cnt))))
      (println "  [OK] No unusual sensitive file access patterns"))

    (when (> (/ sensitive (max 1 total)) 0.3)
      (println "  [!] WARNING: High percentage of sensitive file access"))

    (println "===============================================")))

;;; ============================================================================
;;; Part 8: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 9.1: LSM File Access Monitor ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [stats-map (create-stats-map)
        uid-map (create-uid-access-map)]
    (println "  Stats map created (FD:" (:fd stats-map) ")")
    (println "  UID access map created (FD:" (:fd uid-map) ")")

    ;; Initialize stats
    (doseq [i (range 4)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create LSM-style program
      (println "\nStep 3: Creating LSM-style file monitor program...")
      (let [program (create-file-monitor-program (:fd stats-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :tracepoint
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display LSM info
            (println "\nStep 5: LSM hook information...")
            (display-lsm-info)

            ;; Step 6: Simulate file access
            (println "\nStep 6: Simulating file access events...")
            (let [num-events 50
                  _ (println (format "  Generating %d file access events..." num-events))
                  events (simulate-file-access num-events)
                  stats (atom {:total 0 :sensitive 0 :read-only 0 :write 0
                              :by-uid {} :sensitive-by-uid {}})
                  processed-events (mapv #(process-file-event % stats) events)]

              ;; Step 7: Display events
              (println "\nStep 7: File access events (showing sensitive [!])...")
              (display-events-header)
              (doseq [event (take 20 (sort-by #(if (:sensitive? %) 0 1) processed-events))]
                (display-event event))
              (println (format "  ... and %d more events" (- num-events 20)))

              ;; Step 8: Display statistics
              (println "\nStep 8: File access statistics...")
              (display-statistics @stats)

              ;; Step 9: Security assessment
              (println "\nStep 9: Security assessment...")
              (display-security-assessment @stats)

              ;; Step 10: Update BPF maps
              (println "\nStep 10: Updating BPF maps...")
              (bpf/map-update stats-map 0 (:total @stats))
              (bpf/map-update stats-map 1 (:sensitive @stats))
              (bpf/map-update stats-map 2 (:read-only @stats))
              (bpf/map-update stats-map 3 (:write @stats))

              (println (format "  stats[0] (total)     = %,d" (bpf/map-lookup stats-map 0)))
              (println (format "  stats[1] (sensitive) = %,d" (bpf/map-lookup stats-map 1)))
              (println (format "  stats[2] (read-only) = %,d" (bpf/map-lookup stats-map 2)))
              (println (format "  stats[3] (write)     = %,d" (bpf/map-lookup stats-map 3))))

            ;; Step 11: Cleanup
            (println "\nStep 11: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map stats-map)
        (bpf/close-map uid-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 9.1 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test path sensitivity
  (is-sensitive-path? "/etc/passwd")    ; true
  (is-sensitive-path? "/etc/shadow")    ; true
  (is-sensitive-path? "/home/user/x")   ; false
  (is-sensitive-path? "/var/log/syslog"); true

  ;; Test flag classification
  (classify-access-flags O_RDONLY)
  (classify-access-flags (bit-or O_WRONLY O_CREAT))
  )
