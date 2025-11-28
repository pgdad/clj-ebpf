(ns lab-11-3-device-control
  "Lab 11.3: Device Access Control

   This solution demonstrates:
   - Cgroup dev BPF concepts for device access control
   - Device major/minor number handling
   - Device whitelisting (safe devices)
   - Blocking dangerous devices (block devices, raw hardware)
   - Access type control (read/write/mknod)
   - Device access violation tracking

   Note: Cgroup BPF requires cgroup v2 and kernel 4.15+.
   This solution simulates cgroup concepts using tracepoint as fallback.

   Run with: sudo clojure -M -m lab-11-3-device-control
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.time Instant LocalDateTime ZoneId]
           [java.time.format DateTimeFormatter]))

;;; ============================================================================
;;; Part 1: Constants and Configuration
;;; ============================================================================

;; Device access types
(def BPF_DEVCG_ACC_MKNOD 1)
(def BPF_DEVCG_ACC_READ 2)
(def BPF_DEVCG_ACC_WRITE 4)

;; Common device major numbers (from /proc/devices and linux/major.h)
(def MAJOR_MEM 1)           ; /dev/null, /dev/zero, /dev/random, etc.
(def MAJOR_PTY_MASTER 2)    ; PTY masters
(def MAJOR_PTY_SLAVE 3)     ; PTY slaves
(def MAJOR_TTY 5)           ; /dev/tty, /dev/console
(def MAJOR_LOOP 7)          ; /dev/loop*
(def MAJOR_SCSI_DISK 8)     ; /dev/sd* (SCSI disks)
(def MAJOR_FUSE 10)         ; FUSE devices
(def MAJOR_INPUT 13)        ; Input devices
(def MAJOR_USB 180)         ; USB devices
(def MAJOR_NVIDIA_GPU 195)  ; NVIDIA GPUs

;; Common device minor numbers for major=1 (mem devices)
(def MINOR_MEM 1)           ; /dev/mem (dangerous!)
(def MINOR_KMEM 2)          ; /dev/kmem (dangerous!)
(def MINOR_NULL 3)          ; /dev/null
(def MINOR_PORT 4)          ; /dev/port (dangerous!)
(def MINOR_ZERO 5)          ; /dev/zero
(def MINOR_FULL 7)          ; /dev/full
(def MINOR_RANDOM 8)        ; /dev/random
(def MINOR_URANDOM 9)       ; /dev/urandom

;; Denial reasons
(def REASON_BLOCK_DEVICE 1)
(def REASON_NOT_WHITELISTED 2)
(def REASON_ACCESS_TYPE 3)
(def REASON_DANGEROUS 4)

;;; ============================================================================
;;; Part 2: Device Information
;;; ============================================================================

(def well-known-devices
  "Map of major:minor -> device info"
  {[1 3] {:name "/dev/null" :safe true :description "Null device"}
   [1 5] {:name "/dev/zero" :safe true :description "Zero device"}
   [1 7] {:name "/dev/full" :safe true :description "Full device"}
   [1 8] {:name "/dev/random" :safe true :description "Random number generator"}
   [1 9] {:name "/dev/urandom" :safe true :description "Non-blocking random"}
   [1 1] {:name "/dev/mem" :safe false :description "Physical memory (DANGEROUS)"}
   [1 2] {:name "/dev/kmem" :safe false :description "Kernel memory (DANGEROUS)"}
   [1 4] {:name "/dev/port" :safe false :description "I/O ports (DANGEROUS)"}
   [5 0] {:name "/dev/tty" :safe true :description "Current TTY"}
   [5 1] {:name "/dev/console" :safe false :description "System console"}
   [5 2] {:name "/dev/ptmx" :safe true :description "PTY master"}
   [8 0] {:name "/dev/sda" :safe false :description "First SCSI disk"}
   [8 1] {:name "/dev/sda1" :safe false :description "First partition"}
   [195 0] {:name "/dev/nvidia0" :safe false :description "NVIDIA GPU 0"}
   [195 255] {:name "/dev/nvidiactl" :safe false :description "NVIDIA control"}})

(defn get-device-info
  "Get device info by major/minor"
  [major minor]
  (or (get well-known-devices [major minor])
      (cond
        ;; Block devices (major >= 8)
        (>= major MAJOR_SCSI_DISK)
        {:name (format "/dev/sd? (major=%d, minor=%d)" major minor)
         :safe false
         :description "Block device"}

        ;; NVIDIA devices
        (= major MAJOR_NVIDIA_GPU)
        {:name (format "/dev/nvidia%d" minor)
         :safe false
         :description "NVIDIA GPU device"}

        ;; Input devices
        (= major MAJOR_INPUT)
        {:name (format "/dev/input/event%d" minor)
         :safe false
         :description "Input device"}

        :else
        {:name (format "unknown (%d:%d)" major minor)
         :safe false
         :description "Unknown device"})))

;;; ============================================================================
;;; Part 3: BPF Maps
;;; ============================================================================

(defn create-allowed-devices-map
  "Hash map: Device key (major<<32|minor) -> allowed access types"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8
                   :value-size 4
                   :max-entries 1000
                   :map-name "allowed_devices"
                   :key-serializer utils/long->bytes
                   :key-deserializer utils/bytes->long
                   :value-serializer utils/int->bytes
                   :value-deserializer utils/bytes->int}))

(defn create-violation-count-map
  "Hash map: Container ID -> violation count"
  []
  (bpf/create-map {:map-type :hash
                   :key-size 8
                   :value-size 8
                   :max-entries 1000
                   :map-name "violation_count"
                   :key-serializer utils/long->bytes
                   :key-deserializer utils/bytes->long
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

(defn create-stats-map
  "Array map for device access statistics:
   [0] = total_access_attempts
   [1] = allowed_accesses
   [2] = denied_accesses
   [3] = block_device_denials"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size 8
                   :max-entries 4
                   :map-name "dev_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: BPF Program (Device Access Tracker)
;;; ============================================================================

(defn create-device-monitor-program
  "Create BPF program that tracks device access attempts.

   This demonstrates the cgroup/dev hook concept:
   1. Receives context with device info (major, minor, access type)
   2. Checks against whitelist
   3. Blocks dangerous devices

   Note: Real cgroup programs use :cgroup-dev program type.
   This uses :tracepoint style for broader compatibility."
  [stats-fd]
  (bpf/assemble
    [;; r6 = context pointer
     (bpf/mov-reg :r6 :r1)

     ;; Default stats key = 0 (total access attempts)
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

     ;; Return 1 (ALLOW) - monitoring only
     (bpf/mov :r0 1)
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Device Profiles
;;; ============================================================================

(def minimal-profile
  "Minimal device access - ultra-secure"
  {:name "Minimal"
   :description "Only essential pseudo-devices"
   :allowed-devices #{[1 3]   ; /dev/null
                      [1 5]   ; /dev/zero
                      [1 9]}  ; /dev/urandom
   :allowed-access-types #{BPF_DEVCG_ACC_READ BPF_DEVCG_ACC_WRITE}})

(def standard-profile
  "Standard container profile"
  {:name "Standard"
   :description "Common container devices"
   :allowed-devices #{[1 3]   ; /dev/null
                      [1 5]   ; /dev/zero
                      [1 7]   ; /dev/full
                      [1 8]   ; /dev/random
                      [1 9]   ; /dev/urandom
                      [5 0]   ; /dev/tty
                      [5 2]}  ; /dev/ptmx
   :allowed-access-types #{BPF_DEVCG_ACC_READ BPF_DEVCG_ACC_WRITE}})

(def gpu-profile
  "Profile with GPU access"
  {:name "GPU"
   :description "Standard + NVIDIA GPU devices"
   :allowed-devices #{[1 3] [1 5] [1 7] [1 8] [1 9] [5 0] [5 2]
                      [195 0]     ; /dev/nvidia0
                      [195 255]   ; /dev/nvidiactl
                      [195 254]}  ; /dev/nvidia-uvm
   :allowed-access-types #{BPF_DEVCG_ACC_READ BPF_DEVCG_ACC_WRITE}})

(def privileged-profile
  "Privileged profile (DANGEROUS - for testing only)"
  {:name "Privileged"
   :description "All devices allowed (DANGEROUS)"
   :allowed-devices :all
   :allowed-access-types #{BPF_DEVCG_ACC_READ BPF_DEVCG_ACC_WRITE BPF_DEVCG_ACC_MKNOD}})

(defn get-profile [profile-name]
  (case profile-name
    :minimal minimal-profile
    :standard standard-profile
    :gpu gpu-profile
    :privileged privileged-profile
    standard-profile))

;;; ============================================================================
;;; Part 6: Device Access Evaluation
;;; ============================================================================

(defn access-type->string
  "Convert access type bitmask to string"
  [access-type]
  (str/join "|"
            (filter identity
                    [(when (pos? (bit-and access-type BPF_DEVCG_ACC_MKNOD)) "MKNOD")
                     (when (pos? (bit-and access-type BPF_DEVCG_ACC_READ)) "READ")
                     (when (pos? (bit-and access-type BPF_DEVCG_ACC_WRITE)) "WRITE")])))

(defn is-block-device?
  "Check if device is a block device (dangerous)"
  [major]
  (>= major MAJOR_SCSI_DISK))

(defn is-dangerous-device?
  "Check if device is inherently dangerous"
  [major minor]
  (or
    ;; Block devices
    (is-block-device? major)
    ;; Memory access devices
    (and (= major MAJOR_MEM)
         (contains? #{MINOR_MEM MINOR_KMEM MINOR_PORT} minor))
    ;; Console
    (and (= major MAJOR_TTY) (= minor 1))))

(defn evaluate-device-access
  "Evaluate device access against profile.
   Returns {:decision :allowed/:denied :reason keyword :details string}"
  [access-request profile]
  (let [{:keys [major minor access-type]} access-request
        {:keys [allowed-devices allowed-access-types]} profile
        device-key [major minor]
        device-info (get-device-info major minor)]
    (cond
      ;; Privileged profile allows everything
      (= allowed-devices :all)
      {:decision :allowed
       :reason :privileged
       :details "Privileged profile - all access allowed"}

      ;; Block dangerous devices regardless of profile
      (is-dangerous-device? major minor)
      {:decision :denied
       :reason :dangerous
       :details (format "Dangerous device: %s" (:name device-info))}

      ;; Block all block devices
      (is-block-device? major)
      {:decision :denied
       :reason :block-device
       :details (format "Block device not allowed: major=%d" major)}

      ;; Check if device is in whitelist
      (not (contains? allowed-devices device-key))
      {:decision :denied
       :reason :not-whitelisted
       :details (format "Device not in whitelist: %s" (:name device-info))}

      ;; Check access type
      (not (contains? allowed-access-types access-type))
      {:decision :denied
       :reason :access-type
       :details (format "Access type not allowed: %s"
                        (access-type->string access-type))}

      :else
      {:decision :allowed
       :reason :whitelisted
       :details (format "Allowed: %s" (:name device-info))})))

;;; ============================================================================
;;; Part 7: Simulated Device Access Events
;;; ============================================================================

(defn generate-device-access-event
  "Generate a simulated device access event"
  []
  (let [devices [[1 3]    ; /dev/null
                 [1 5]    ; /dev/zero
                 [1 8]    ; /dev/random
                 [1 9]    ; /dev/urandom
                 [1 1]    ; /dev/mem (dangerous)
                 [5 0]    ; /dev/tty
                 [5 2]    ; /dev/ptmx
                 [8 0]    ; /dev/sda (block)
                 [8 1]    ; /dev/sda1 (block)
                 [195 0]  ; /dev/nvidia0
                 [10 229] ; /dev/fuse
                 [13 64]] ; /dev/input/event0
        access-types [BPF_DEVCG_ACC_READ
                      BPF_DEVCG_ACC_WRITE
                      (bit-or BPF_DEVCG_ACC_READ BPF_DEVCG_ACC_WRITE)]
        containers ["container-web" "container-api" "container-ml"
                    "container-db" "container-worker"]]
    (let [[major minor] (rand-nth devices)]
      {:container-id (rand-nth containers)
       :major major
       :minor minor
       :access-type (rand-nth access-types)
       :timestamp (System/currentTimeMillis)})))

(defn simulate-device-accesses
  "Simulate device access events"
  [num-events]
  (repeatedly num-events generate-device-access-event))

;;; ============================================================================
;;; Part 8: Event Processing
;;; ============================================================================

(defn process-device-event
  "Process a device access event and update statistics"
  [event profile stats]
  (let [{:keys [container-id major minor access-type]} event
        result (evaluate-device-access event profile)
        device-info (get-device-info major minor)]

    ;; Update statistics
    (swap! stats update :total inc)
    (if (= (:decision result) :allowed)
      (swap! stats update :allowed inc)
      (do
        (swap! stats update :denied inc)
        (case (:reason result)
          :block-device (swap! stats update :block-device-denials inc)
          :dangerous (swap! stats update :dangerous-denials inc)
          nil)
        (swap! stats update-in [:violations-by-container container-id] (fnil inc 0))
        (swap! stats update-in [:violations-by-device [major minor]] (fnil inc 0))))

    (assoc event
           :result result
           :device-info device-info)))

;;; ============================================================================
;;; Part 9: Display Functions
;;; ============================================================================

(defn format-timestamp
  "Format timestamp for display"
  [ts]
  (let [instant (Instant/ofEpochMilli ts)
        ldt (LocalDateTime/ofInstant instant (ZoneId/systemDefault))
        formatter (DateTimeFormatter/ofPattern "HH:mm:ss.SSS")]
    (.format ldt formatter)))

(defn display-cgroup-dev-info
  "Display cgroup device control information"
  []
  (println "\nCgroup Device Access Control:")
  (println "===============================================")
  (println "")
  (println "  Cgroup Hook: cgroup/dev")
  (println "  Mode: DEVICE WHITELIST ENFORCEMENT")
  (println "")
  (println "  Access Types:")
  (println "    MKNOD (1) - Create device node")
  (println "    READ  (2) - Read from device")
  (println "    WRITE (4) - Write to device")
  (println "")
  (println "  Always Blocked:")
  (println "    - Block devices (/dev/sd*, /dev/nvme*)")
  (println "    - /dev/mem, /dev/kmem, /dev/port")
  (println "    - /dev/console")
  (println "")
  (println "  Always Allowed (in standard profile):")
  (println "    - /dev/null, /dev/zero, /dev/full")
  (println "    - /dev/random, /dev/urandom")
  (println "    - /dev/tty, /dev/ptmx")
  (println "==============================================="))

(defn display-profile-info
  "Display current profile configuration"
  [profile]
  (println "\nActive Profile:" (:name profile))
  (println "===============================================")
  (println "  Description:" (:description profile))
  (println "")
  (println "  Allowed Devices:")
  (if (= (:allowed-devices profile) :all)
    (println "    [!] ALL DEVICES (DANGEROUS)")
    (doseq [device-key (:allowed-devices profile)]
      (let [[major minor] device-key
            info (get-device-info major minor)]
        (println (format "    %s (%d:%d)" (:name info) major minor)))))
  (println "")
  (println "  Allowed Access Types:")
  (println "    " (access-type->string
                   (reduce bit-or (:allowed-access-types profile))))
  (println "==============================================="))

(defn display-device-event
  "Display a device access event"
  [event]
  (let [{:keys [container-id major minor access-type timestamp result device-info]} event
        {:keys [decision details]} result
        time-str (format-timestamp timestamp)
        status (if (= decision :allowed) "OK " "BLK")
        access-str (access-type->string access-type)]
    (printf "%s %s %-15s %3d:%-3d %-20s %-6s %s\n"
            status time-str container-id major minor
            (:name device-info) access-str details)))

(defn display-events-header
  "Display header for events table"
  []
  (println "\n    TIME         CONTAINER       MAJ:MIN DEVICE               ACCESS RESULT")
  (println "================================================================================"))

(defn display-statistics
  "Display device access statistics"
  [{:keys [total allowed denied block-device-denials dangerous-denials
           violations-by-container violations-by-device]}]
  (println "\nDevice Access Statistics:")
  (println "===============================================")
  (println (format "  Total access attempts : %,d" (or total 0)))
  (println (format "  Allowed               : %,d (%.1f%%)"
                   (or allowed 0)
                   (* 100.0 (/ (or allowed 0) (max 1 (or total 1))))))
  (println (format "  Denied                : %,d (%.1f%%)"
                   (or denied 0)
                   (* 100.0 (/ (or denied 0) (max 1 (or total 1))))))
  (println "")
  (println "  Denial Breakdown:")
  (println (format "    Block device denials  : %,d" (or block-device-denials 0)))
  (println (format "    Dangerous device      : %,d" (or dangerous-denials 0)))
  (println "")
  (when (seq violations-by-container)
    (println "  Violations by Container:")
    (doseq [[container count] (sort-by val > violations-by-container)]
      (println (format "    %-18s: %,d violations" container count)))
    (println ""))
  (when (seq violations-by-device)
    (println "  Most Blocked Devices:")
    (doseq [[[major minor] count] (take 5 (sort-by val > violations-by-device))]
      (let [info (get-device-info major minor)]
        (println (format "    %-20s (%d:%d): %,d attempts"
                         (:name info) major minor count)))))
  (println "==============================================="))

(defn display-security-assessment
  "Display security assessment"
  [stats profile]
  (println "\nSecurity Assessment:")
  (println "===============================================")

  ;; Profile assessment
  (case (:name profile)
    "Privileged"
    (println "  [!] CRITICAL: Using privileged profile - ALL devices accessible")
    "GPU"
    (println "  [!] WARNING: GPU access enabled - verify authorization")
    "Standard"
    (println "  [OK] Standard profile - common devices only")
    "Minimal"
    (println "  [OK] Minimal profile - maximum security")
    (println "  [?] Unknown profile"))

  ;; Violation assessment
  (let [{:keys [denied block-device-denials dangerous-denials]} stats]
    (when (pos? (or block-device-denials 0))
      (println (format "  [!] Block device access attempts: %d" block-device-denials)))
    (when (pos? (or dangerous-denials 0))
      (println (format "  [!] Dangerous device access attempts: %d" dangerous-denials)))
    (when (and (zero? (or block-device-denials 0))
               (zero? (or dangerous-denials 0)))
      (println "  [OK] No dangerous device access attempts")))

  (println "==============================================="))

;;; ============================================================================
;;; Part 10: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 11.3: Device Access Control ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create maps
  (println "\nStep 2: Creating BPF maps...")
  (let [allowed-devices-map (create-allowed-devices-map)
        violation-count-map (create-violation-count-map)
        stats-map (create-stats-map)]
    (println "  Allowed devices map created (FD:" (:fd allowed-devices-map) ")")
    (println "  Violation count map created (FD:" (:fd violation-count-map) ")")
    (println "  Stats map created (FD:" (:fd stats-map) ")")

    ;; Initialize stats
    (doseq [i (range 4)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create device monitor program
      (println "\nStep 3: Creating cgroup/dev monitor program...")
      (let [program (create-device-monitor-program (:fd stats-map))]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")

        ;; Step 4: Load program
        (println "\nStep 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :tracepoint
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")

          (try
            ;; Step 5: Display cgroup/dev info
            (println "\nStep 5: Cgroup device hook information...")
            (display-cgroup-dev-info)

            ;; Step 6: Select and display profile
            (let [profile (get-profile :standard)]
              (println "\nStep 6: Profile configuration...")
              (display-profile-info profile)

              ;; Populate allowed devices map
              (when (not= (:allowed-devices profile) :all)
                (doseq [device-key (:allowed-devices profile)]
                  (let [[major minor] device-key
                        key (bit-or (bit-shift-left major 32) minor)
                        access-mask (reduce bit-or (:allowed-access-types profile))]
                    (bpf/map-update allowed-devices-map key access-mask))))

              ;; Step 7: Simulate device accesses
              (println "\nStep 7: Simulating device access attempts...")
              (let [num-events 40
                    _ (println (format "  Generating %d device access events..." num-events))
                    events (simulate-device-accesses num-events)
                    stats (atom {:total 0 :allowed 0 :denied 0
                                 :block-device-denials 0 :dangerous-denials 0
                                 :violations-by-container {}
                                 :violations-by-device {}})
                    processed-events (mapv #(process-device-event % profile stats) events)]

                ;; Step 8: Display events
                (println "\nStep 8: Device access events (showing denied first)...")
                (display-events-header)
                (let [sorted-events (sort-by (fn [e]
                                               (if (= (get-in e [:result :decision]) :denied)
                                                 0 1))
                                             processed-events)]
                  (doseq [event (take 20 sorted-events)]
                    (display-device-event event))
                  (println (format "  ... and %d more events" (- num-events 20))))

                ;; Step 9: Display statistics
                (println "\nStep 9: Device access statistics...")
                (display-statistics @stats)

                ;; Step 10: Security assessment
                (println "\nStep 10: Security assessment...")
                (display-security-assessment @stats profile)

                ;; Step 11: Update BPF maps
                (println "\nStep 11: Updating BPF maps...")
                (bpf/map-update stats-map 0 (:total @stats))
                (bpf/map-update stats-map 1 (:allowed @stats))
                (bpf/map-update stats-map 2 (:denied @stats))
                (bpf/map-update stats-map 3 (or (:block-device-denials @stats) 0))

                (println (format "  stats[0] (total)       = %,d" (bpf/map-lookup stats-map 0)))
                (println (format "  stats[1] (allowed)     = %,d" (bpf/map-lookup stats-map 1)))
                (println (format "  stats[2] (denied)      = %,d" (bpf/map-lookup stats-map 2)))
                (println (format "  stats[3] (block_dev)   = %,d" (bpf/map-lookup stats-map 3)))))

            ;; Step 12: Cleanup
            (println "\nStep 12: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (.printStackTrace e))

      (finally
        (bpf/close-map allowed-devices-map)
        (bpf/close-map violation-count-map)
        (bpf/close-map stats-map)
        (println "  Maps closed"))))

  (println "\n=== Lab 11.3 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Test device info
  (get-device-info 1 3)   ; /dev/null
  (get-device-info 8 0)   ; /dev/sda
  (get-device-info 195 0) ; /dev/nvidia0

  ;; Test access evaluation
  (evaluate-device-access
    {:major 1 :minor 3 :access-type BPF_DEVCG_ACC_READ}
    standard-profile)

  (evaluate-device-access
    {:major 8 :minor 0 :access-type BPF_DEVCG_ACC_READ}
    standard-profile)
  )
