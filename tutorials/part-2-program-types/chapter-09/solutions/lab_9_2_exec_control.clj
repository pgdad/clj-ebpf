(ns lab-9-2-exec-control
  "Lab 9.2: LSM Process Execution Control

   This solution demonstrates:
   - LSM bprm_check_security hook concepts
   - Binary whitelist/blacklist enforcement
   - Policy-based execution control
   - Security violation logging
   - Hash-based executable verification

   Note: LSM BPF requires kernel 5.7+ with BTF and LSM BPF enabled.
   This solution simulates LSM enforcement concepts.

   Run with: sudo clojure -M -m lab-9-2-exec-control
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.time Instant LocalDateTime ZoneId]
           [java.time.format DateTimeFormatter]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; LSM return values
(def LSM_ALLOW 0)
(def LSM_DENY -1)   ; -EPERM

;; Policy modes
(def POLICY_BLACKLIST 0)
(def POLICY_WHITELIST 1)

;; Event types
(def EVENT_EXEC_ALLOWED 1)
(def EVENT_EXEC_BLOCKED 2)

;; Dangerous binaries (blacklist)
(def DANGEROUS_BINARIES
  #{"/usr/bin/netcat"
    "/usr/bin/nc"
    "/bin/nc"
    "/usr/bin/wget"
    "/usr/bin/curl"
    "/usr/bin/nmap"
    "/usr/bin/tcpdump"
    "/usr/bin/telnet"})

;; Safe system binaries (whitelist)
(def SAFE_BINARIES
  #{"/bin/bash"
    "/bin/sh"
    "/usr/bin/bash"
    "/usr/bin/sh"
    "/usr/bin/ls"
    "/usr/bin/cat"
    "/usr/bin/grep"
    "/usr/bin/vim"
    "/usr/bin/nano"
    "/usr/bin/less"
    "/usr/bin/head"
    "/usr/bin/tail"
    "/usr/bin/ps"
    "/usr/bin/top"
    "/usr/bin/systemctl"
    "/usr/bin/sudo"})

;; Dangerous path prefixes
(def DANGEROUS_PREFIXES
  ["/tmp/"
   "/dev/shm/"
   "/var/tmp/"])

;;; ============================================================================
;;; Part 2: Hash Functions
;;; ============================================================================

(defn djb2-hash
  "DJB2 hash algorithm (matching the BPF version)"
  [s]
  (reduce (fn [hash c]
            (unchecked-add
             (unchecked-multiply hash 33)
             (int c)))
          5381
          s))

(defn path->hash
  "Convert path to hash for map lookup"
  [path]
  (djb2-hash path))

;;; ============================================================================
;;; Part 3: BPF Maps
;;; ============================================================================

(defn create-config-map
  "Array map for configuration:
   [0] = policy_mode (0=blacklist, 1=whitelist)"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 4
                   :max-entries 1
                   :map-name "exec_config"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/int->bytes
                   :value-deserializer utils/bytes->int}))

(defn create-blacklist-map
  "Hash map: path_hash -> blocked (1)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8
                   :value-size 1
                   :max-entries 1024
                   :map-name "blacklist"
                   :key-serializer utils/long->bytes
                   :key-deserializer utils/bytes->long
                   :value-serializer (fn [v] (byte-array [(byte v)]))
                   :value-deserializer (fn [b] (aget b 0))}))

(defn create-whitelist-map
  "Hash map: path_hash -> allowed (1)"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8
                   :value-size 1
                   :max-entries 4096
                   :map-name "whitelist"
                   :key-serializer utils/long->bytes
                   :key-deserializer utils/bytes->long
                   :value-serializer (fn [v] (byte-array [(byte v)]))
                   :value-deserializer (fn [b] (aget b 0))}))

(defn create-violation-map
  "Hash map: UID -> violation count"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 4
                   :value-size 8
                   :max-entries 1024
                   :map-name "violations"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-stats-map
  "Array map for statistics:
   [0] = allowed_count
   [1] = blocked_count"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 2
                   :map-name "exec_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: LSM BPF Program (Simplified)
;;; ============================================================================

(defn create-exec-control-program
  "Create LSM-style execution control program.

   This program demonstrates the bprm_check_security LSM hook concept:
   1. Receives context with linux_binprm* pointer
   2. Checks executable against policy (blacklist/whitelist)
   3. Returns 0 (ALLOW) or -1 (DENY)

   Note: Real LSM programs use :lsm program type.
   This uses :tracepoint style for broader compatibility."
  [stats-fd config-fd]
  (bpf/assemble
    [;; r6 = context pointer
     (bpf/mov-reg :r6 :r1)

     ;; Default to allow (r9 = stats key, 0 = allowed)
     (bpf/mov :r9 0)

     ;; Load config (policy mode)
     (bpf/mov :r7 0)
     (bpf/store-mem :dw :r10 -8 :r7)
     (bpf/ld-map-fd :r1 config-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)
     (bpf/call 1)  ; bpf_map_lookup_elem

     ;; r0 has config pointer or NULL
     ;; For demo, we'll just update stats

     ;; Update stats
     (bpf/store-mem :dw :r10 -8 :r9)
     (bpf/ld-map-fd :r1 stats-fd)
     (bpf/mov-reg :r2 :r10)
     (bpf/add :r2 -8)
     (bpf/call 1)

     ;; If NULL, skip increment
     (bpf/jmp-imm :jeq :r0 0 3)

     ;; Increment counter
     (bpf/load-mem :dw :r1 :r0 0)
     (bpf/add :r1 1)
     (bpf/store-mem :dw :r0 0 :r1)

     ;; Return LSM decision (0 = allow in this demo)
     (bpf/mov :r0 LSM_ALLOW)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Policy Enforcement (Userspace Simulation)
;;; ============================================================================

(defn is-dangerous-path?
  "Check if path is in a dangerous location"
  [path]
  (some #(str/starts-with? path %) DANGEROUS_PREFIXES))

(defn check-blacklist
  "Check if path is blacklisted"
  [path blacklist-set]
  (or (contains? blacklist-set path)
      (is-dangerous-path? path)))

(defn check-whitelist
  "Check if path is whitelisted"
  [path whitelist-set]
  (contains? whitelist-set path))

(defn evaluate-policy
  "Evaluate execution policy for a path"
  [path policy-mode blacklist-set whitelist-set]
  (case policy-mode
    :blacklist
    (if (check-blacklist path blacklist-set)
      {:decision :blocked :reason "Blacklisted binary"}
      {:decision :allowed :reason "Not in blacklist"})

    :whitelist
    (if (check-whitelist path whitelist-set)
      {:decision :allowed :reason "Whitelisted binary"}
      {:decision :blocked :reason "Not in whitelist"})))

;;; ============================================================================
;;; Part 6: Simulated Execution Events
;;; ============================================================================

(defn generate-exec-event
  "Generate a simulated execution event"
  []
  (let [all-paths (concat
                    (vec SAFE_BINARIES)
                    (vec DANGEROUS_BINARIES)
                    ["/tmp/malware.sh"
                     "/dev/shm/backdoor"
                     "/home/user/script.py"
                     "/opt/app/server"])
        uids [0 1000 1001 65534]]
    {:pid (+ 1000 (rand-int 30000))
     :ppid (+ 1 (rand-int 1000))
     :uid (rand-nth uids)
     :path (rand-nth all-paths)
     :timestamp (System/currentTimeMillis)
     :argc (+ 1 (rand-int 5))}))

(defn simulate-exec-events
  "Simulate execution events"
  [num-events]
  (repeatedly num-events generate-exec-event))

;;; ============================================================================
;;; Part 7: Event Processing and Statistics
;;; ============================================================================

(defn process-exec-event
  "Process an execution event and apply policy"
  [event policy-mode blacklist-set whitelist-set stats]
  (let [{:keys [path uid]} event
        policy-result (evaluate-policy path policy-mode blacklist-set whitelist-set)
        blocked? (= (:decision policy-result) :blocked)]

    ;; Update statistics
    (if blocked?
      (do
        (swap! stats update :blocked inc)
        (swap! stats update-in [:blocked-by-uid uid] (fnil inc 0))
        (swap! stats update-in [:blocked-paths path] (fnil inc 0)))
      (swap! stats update :allowed inc))

    ;; Return annotated event
    (merge event policy-result)))

;;; ============================================================================
;;; Part 8: Display Functions
;;; ============================================================================

(defn format-timestamp
  "Format timestamp for display"
  [ts]
  (let [instant (Instant/ofEpochMilli ts)
        ldt (LocalDateTime/ofInstant instant (ZoneId/systemDefault))
        formatter (DateTimeFormatter/ofPattern "HH:mm:ss.SSS")]
    (.format ldt formatter)))

(defn display-exec-control-info
  "Display execution control information"
  [policy-mode]
  (println "\nProcess Execution Control:")
  (println "===============================================")
  (println "")
  (println "  LSM Hook: bprm_check_security")
  (println (format "  Policy Mode: %s" (name policy-mode)))
  (println "")
  (if (= policy-mode :blacklist)
    (do
      (println "  Blacklisted Binaries:")
      (doseq [path (take 5 DANGEROUS_BINARIES)]
        (println (format "    [X] %s" path)))
      (println (format "    ... and %d more" (- (count DANGEROUS_BINARIES) 5))))
    (do
      (println "  Whitelisted Binaries:")
      (doseq [path (take 5 SAFE_BINARIES)]
        (println (format "    [+] %s" path)))
      (println (format "    ... and %d more" (- (count SAFE_BINARIES) 5)))))
  (println "")
  (println "  Dangerous Path Prefixes:")
  (doseq [prefix DANGEROUS_PREFIXES]
    (println (format "    [!] %s*" prefix)))
  (println "")
  (println "  Return Values:")
  (println "    0  = ALLOW (execution proceeds)")
  (println "   -1  = DENY (EPERM - execution blocked)")
  (println "==============================================="))

(defn display-exec-event
  "Display a single execution event"
  [event]
  (let [{:keys [pid uid path timestamp decision reason]} event
        time-str (format-timestamp timestamp)
        decision-marker (if (= decision :blocked) "[BLOCKED]" "[ALLOWED]")]
    (printf "%s %s %-6d %-5d %s\n"
            decision-marker time-str pid uid path)
    (when (= decision :blocked)
      (printf "         Reason: %s\n" reason))))

(defn display-events-header
  "Display header for events table"
  []
  (println "\nDECISION  TIME         PID    UID   PATH")
  (println "==============================================================================="))

(defn display-statistics
  "Display execution control statistics"
  [{:keys [allowed blocked blocked-by-uid blocked-paths]}]
  (let [total (+ allowed blocked)]
    (println "\nExecution Control Statistics:")
    (println "===============================================")
    (println (format "  Total executions   : %,d" total))
    (println (format "  Allowed            : %,d (%.1f%%)"
                     allowed (* 100.0 (/ allowed (max 1 total)))))
    (println (format "  Blocked            : %,d (%.1f%%)"
                     blocked (* 100.0 (/ blocked (max 1 total)))))
    (println "")

    (when (seq blocked-by-uid)
      (println "  Blocked by UID:")
      (doseq [[uid count] (sort-by val > blocked-by-uid)]
        (let [uid-name (case uid
                         0 "root"
                         65534 "nobody"
                         (str "user" uid))]
          (println (format "    %-10s (UID %5d): %,d blocked" uid-name uid count))))
      (println ""))

    (when (seq blocked-paths)
      (println "  Top Blocked Paths:")
      (doseq [[path count] (take 5 (sort-by val > blocked-paths))]
        (println (format "    %s (%d attempts)" path count))))

    (println "===============================================")))

(defn display-security-diagram
  "Display security decision flow diagram"
  []
  (println "\nExecution Security Flow:")
  (println "===============================================")
  (println "")
  (println "  User: ./program")
  (println "       |")
  (println "       v")
  (println "  execve() syscall")
  (println "       |")
  (println "       v")
  (println "  +------------------+")
  (println "  | bprm_check_security |")
  (println "  | (LSM BPF Hook)   |")
  (println "  +--------+---------+")
  (println "           |")
  (println "     +-----+-----+")
  (println "     |           |")
  (println "     v           v")
  (println "  ALLOW        DENY")
  (println "  (ret 0)    (ret -EPERM)")
  (println "     |           |")
  (println "     v           v")
  (println "  Process     execve()")
  (println "  Runs        Returns")
  (println "              EPERM")
  (println "")
  (println "==============================================="))

;;; ============================================================================
;;; Part 9: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 9.2: LSM Process Execution Control ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [config-map (create-config-map)
        blacklist-map (create-blacklist-map)
        stats-map (create-stats-map)]
    (println "  Config map created (FD:" (:fd config-map) ")")
    (println "  Blacklist map created (FD:" (:fd blacklist-map) ")")
    (println "  Stats map created (FD:" (:fd stats-map) ")")

    ;; Initialize config (blacklist mode)
    (bpf/map-update config-map 0 POLICY_BLACKLIST)
    ;; Initialize stats
    (bpf/map-update stats-map 0 0)
    (bpf/map-update stats-map 1 0)

    (try
      ;; Step 3: Populate blacklist
      (println "\nStep 3: Populating blacklist...")
      (doseq [path DANGEROUS_BINARIES]
        (let [hash (path->hash path)]
          (bpf/map-update blacklist-map hash 1)))
      (println (format "  Added %d entries to blacklist" (count DANGEROUS_BINARIES)))

      ;; Step 4: Create execution control program
      (println "\nStep 4: Creating LSM-style execution control program...")
      (let [program (create-exec-control-program (:fd stats-map) (:fd config-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 5: Load program
        (println "\nStep 5: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :tracepoint
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 6: Display control info
            (println "\nStep 6: Execution control configuration...")
            (display-exec-control-info :blacklist)

            ;; Step 7: Show security flow
            (println "\nStep 7: Security decision flow...")
            (display-security-diagram)

            ;; Step 8: Simulate execution events
            (println "\nStep 8: Simulating process executions...")
            (let [num-events 30
                  _ (println (format "  Generating %d execution attempts..." num-events))
                  events (simulate-exec-events num-events)
                  stats (atom {:allowed 0 :blocked 0
                              :blocked-by-uid {} :blocked-paths {}})
                  processed-events (mapv #(process-exec-event
                                            % :blacklist DANGEROUS_BINARIES
                                            SAFE_BINARIES stats)
                                         events)]

              ;; Step 9: Display events
              (println "\nStep 9: Execution events...")
              (display-events-header)
              ;; Show blocked events first, then allowed
              (let [blocked (filter #(= (:decision %) :blocked) processed-events)
                    allowed (filter #(= (:decision %) :allowed) processed-events)]
                (doseq [event (take 10 blocked)]
                  (display-exec-event event))
                (when (> (count blocked) 10)
                  (println (format "  ... and %d more blocked" (- (count blocked) 10))))
                (println "")
                (doseq [event (take 5 allowed)]
                  (display-exec-event event))
                (when (> (count allowed) 5)
                  (println (format "  ... and %d more allowed" (- (count allowed) 5)))))

              ;; Step 10: Display statistics
              (println "\nStep 10: Execution control statistics...")
              (display-statistics @stats)

              ;; Step 11: Update BPF maps
              (println "\nStep 11: Updating BPF maps...")
              (bpf/map-update stats-map 0 (:allowed @stats))
              (bpf/map-update stats-map 1 (:blocked @stats))

              (println (format "  stats[0] (allowed) = %,d" (bpf/map-lookup stats-map 0)))
              (println (format "  stats[1] (blocked) = %,d" (bpf/map-lookup stats-map 1))))

            ;; Step 12: Cleanup
            (println "\nStep 12: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map config-map)
        (bpf/close-map blacklist-map)
        (bpf/close-map stats-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 9.2 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test hash function
  (djb2-hash "/usr/bin/nc")
  (djb2-hash "/bin/bash")

  ;; Test policy evaluation
  (evaluate-policy "/usr/bin/nc" :blacklist DANGEROUS_BINARIES SAFE_BINARIES)
  (evaluate-policy "/bin/bash" :blacklist DANGEROUS_BINARIES SAFE_BINARIES)
  (evaluate-policy "/tmp/malware" :blacklist DANGEROUS_BINARIES SAFE_BINARIES)
  )
