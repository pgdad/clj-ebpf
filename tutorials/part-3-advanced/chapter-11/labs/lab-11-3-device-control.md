# Lab 11.3: Device Access Control

## Objective

Control container access to devices using cgroup/dev BPF programs. Implement fine-grained device whitelisting to prevent containers from accessing unauthorized hardware.

## Learning Goals

- Use cgroup/dev programs for device access control
- Understand device major/minor numbers
- Implement device whitelists
- Handle different access types (read/write/mknod)
- Secure container environments

## Background

Containers should only access devices they need. By default, Docker allows access to many devices. This creates security risks:
- Containers could access host disks directly
- GPU access without authorization
- Reading sensitive device data
- Creating device nodes

Cgroup/dev BPF provides kernel-level enforcement.

## Implementation

```clojure
(ns container.device-control
  (:require [clj-ebpf.core :as bpf]))

;; Device access types
(def BPF_DEVCG_ACC_MKNOD 1)
(def BPF_DEVCG_ACC_READ 2)
(def BPF_DEVCG_ACC_WRITE 4)

;; struct bpf_cgroup_dev_ctx offsets
(def DEV_CTX_OFFSETS
  {:access-type 0    ; u32
   :major 4          ; u32
   :minor 8})        ; u32

;; Common device major numbers
(def MAJOR_MEM 1)           ; /dev/null, /dev/zero, etc.
(def MAJOR_TTY 5)           ; /dev/tty
(def MAJOR_RANDOM 1)        ; /dev/random, /dev/urandom
(def MAJOR_NVIDIA_GPU 195)  ; NVIDIA GPUs
(def MAJOR_FUSE 10)         ; FUSE devices
(def MAJOR_BLOCK_START 8)   ; Block devices (sda, sdb, etc.)

;; Common device minor numbers for /dev/mem (major=1)
(def MINOR_NULL 3)
(def MINOR_ZERO 5)
(def MINOR_RANDOM 8)
(def MINOR_URANDOM 9)

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def allowed-devices
  "Whitelist of allowed devices"
  {:type :hash
   :key-type :u64       ; (major << 32) | minor
   :value-type :u32     ; Allowed access types (bitmask)
   :max-entries 1000})

(def device-access-log
  "Log of device access attempts"
  {:type :ring_buffer
   :max-entries (* 128 1024)})

(def violation-count
  "Count violations per cgroup"
  {:type :hash
   :key-type :u64       ; Cgroup ID
   :value-type :u64     ; Count
   :max-entries 1000})

;; ============================================================================
;; Main Device Control Program
;; ============================================================================

(def device-access-control
  "Control device access from containers"
  {:type :cgroup-dev
   :program
   [;; Load access type
    [(bpf/load-ctx :w :r6 (:access-type DEV_CTX_OFFSETS))]
    [(bpf/store-mem :w :r10 -4 :r6)]    ; Save access_type

    ;; Load major and minor
    [(bpf/load-ctx :w :r7 (:major DEV_CTX_OFFSETS))]
    [(bpf/load-ctx :w :r8 (:minor DEV_CTX_OFFSETS))]

    ;; ========================================================================
    ;; Quick Allow: Essential Safe Devices
    ;; ========================================================================

    ;; Always allow /dev/null (major=1, minor=3)
    [(bpf/jmp-imm :jne :r7 MAJOR_MEM :check-tty)]
    [(bpf/jmp-imm :jne :r8 MINOR_NULL :check-zero)]
    [(bpf/jmp :allow)]

    [:check-zero]
    ;; Allow /dev/zero (major=1, minor=5)
    [(bpf/jmp-imm :jne :r8 MINOR_ZERO :check-random)]
    [(bpf/jmp :allow)]

    [:check-random]
    ;; Allow /dev/random and /dev/urandom (minor=8,9)
    [(bpf/jmp-imm :jeq :r8 MINOR_RANDOM :allow)]
    [(bpf/jmp-imm :jeq :r8 MINOR_URANDOM :allow)]

    [:check-tty]
    ;; Allow /dev/tty (major=5)
    [(bpf/jmp-imm :jeq :r7 MAJOR_TTY :allow)]

    ;; ========================================================================
    ;; Quick Deny: Dangerous Devices
    ;; ========================================================================

    ;; Block all block devices (sda, sdb, etc.) - major >= 8
    [(bpf/jmp-imm :jge :r7 MAJOR_BLOCK_START :deny-block-device)]

    ;; Block GPU devices (unless explicitly allowed)
    [(bpf/jmp-imm :jeq :r7 MAJOR_NVIDIA_GPU :check-whitelist)]

    ;; ========================================================================
    ;; Check Whitelist
    ;; ========================================================================

    [:check-whitelist]
    ;; Combine major and minor into key
    [(bpf/lsh :r7 32)]
    [(bpf/or-reg :r7 :r8)]              ; r7 = (major << 32) | minor

    ;; Look up in whitelist
    [(bpf/store-mem :dw :r10 -16 :r7)]
    [(bpf/mov-reg :r1 (bpf/map-ref allowed-devices))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -16)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :deny)]    ; Not in whitelist -> deny

    ;; Check if requested access type is allowed
    [(bpf/load-mem :w :r1 :r0 0)]       ; Allowed access types
    [(bpf/load-mem :w :r2 :r10 -4)]     ; Requested access type
    [(bpf/and-reg :r1 :r2)]
    [(bpf/jmp-imm :jeq :r1 0 :deny)]    ; Access type not allowed -> deny

    [(bpf/jmp :allow)]

    ;; ========================================================================
    ;; Deny - Block Device Access
    ;; ========================================================================

    [:deny-block-device]
    ;; Log that we blocked a block device
    [(bpf/mov :r9 1)]                   ; Reason: block device
    [(bpf/jmp :log-denial)]

    [:deny]
    [(bpf/mov :r9 0)]                   ; Reason: not whitelisted

    [:log-denial]
    ;; Get cgroup ID
    [(bpf/call (bpf/helper :get_current_cgroup_id))]
    [(bpf/store-mem :dw :r10 -24 :r0)]

    ;; Reserve log entry
    [(bpf/mov-reg :r1 (bpf/map-ref device-access-log))]
    [(bpf/mov :r2 48)]                  ; Event size
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    [(bpf/jmp-imm :jeq :r0 0 :update-violations)]
    [(bpf/mov-reg :r8 :r0)]

    ;; Fill event
    [(bpf/load-ctx :w :r1 (:major DEV_CTX_OFFSETS))]
    [(bpf/store-mem :w :r8 0 :r1)]
    [(bpf/load-ctx :w :r1 (:minor DEV_CTX_OFFSETS))]
    [(bpf/store-mem :w :r8 4 :r1)]
    [(bpf/load-mem :w :r1 :r10 -4)]
    [(bpf/store-mem :w :r8 8 :r1)]
    [(bpf/store-mem :w :r8 12 :r9)]     ; Reason
    [(bpf/load-mem :dw :r1 :r10 -24)]
    [(bpf/store-mem :dw :r8 16 :r1)]    ; Cgroup ID
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r8 24 :r0)]    ; Timestamp

    ;; Submit
    [(bpf/mov-reg :r1 :r8)]
    [(bpf/mov :r2 0)]
    [(bpf/call (bpf/helper :ringbuf_submit))]

    [:update-violations]
    ;; Increment violation counter
    [(bpf/load-mem :dw :r7 :r10 -24)]
    [(bpf/store-mem :dw :r10 -32 :r7)]

    [(bpf/mov-reg :r1 (bpf/map-ref violation-count))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -32)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-count)]
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]
    [(bpf/jmp :return-deny)]

    [:init-count]
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r10 -40 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref violation-count))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -32)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -40)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:return-deny]
    [(bpf/mov :r0 0)]                   ; Return 0 = DENY
    [(bpf/exit)]

    ;; ========================================================================
    ;; Allow
    ;; ========================================================================

    [:allow]
    [(bpf/mov :r0 1)]                   ; Return 1 = ALLOW
    [(bpf/exit)]]})

;; ============================================================================
;; Userspace Management
;; ============================================================================

(defn device-key [major minor]
  "Create device map key"
  (bit-or (bit-shift-left major 32) minor))

(defn add-allowed-device!
  "Add device to whitelist"
  [major minor access-types device-name]
  (let [key (device-key major minor)
        access-mask (reduce bit-or access-types)]
    (bpf/map-update! allowed-devices key access-mask)
    (println (format "Allowed: %s (major=%d, minor=%d, access=0x%x)"
                     device-name major minor access-mask))))

(defn allow-device-read! [major minor name]
  (add-allowed-device! major minor [BPF_DEVCG_ACC_READ] name))

(defn allow-device-write! [major minor name]
  (add-allowed-device! major minor [BPF_DEVCG_ACC_WRITE] name))

(defn allow-device-rw! [major minor name]
  (add-allowed-device! major minor
                       [BPF_DEVCG_ACC_READ BPF_DEVCG_ACC_WRITE]
                       name))

;; ============================================================================
;; Device Profiles
;; ============================================================================

(defn apply-minimal-profile!
  "Minimal device access (ultra-secure)"
  []
  (println "\n=== Applying Minimal Profile ===")
  (println "Allowing only: /dev/null, /dev/zero, /dev/urandom")
  ;; Built-in quick allows in BPF program
  ;; No additional devices needed
  )

(defn apply-standard-profile!
  "Standard container profile"
  []
  (println "\n=== Applying Standard Profile ===")
  ;; Built-in safe devices + common devices
  (allow-device-rw! 136 0 "/dev/pts/0")   ; PTY
  (allow-device-rw! 4 64 "/dev/ttyS0"))   ; Serial

(defn apply-gpu-profile!
  "Profile with GPU access"
  []
  (println "\n=== Applying GPU Profile ===")
  (apply-standard-profile!)
  ;; NVIDIA GPU devices
  (allow-device-rw! 195 0 "/dev/nvidia0")
  (allow-device-rw! 195 255 "/dev/nvidiactl")
  (allow-device-rw! 195 254 "/dev/nvidia-uvm"))

(defn apply-privileged-profile!
  "Privileged profile (DANGEROUS - for testing only)"
  []
  (println "\n=== WARNING: Applying Privileged Profile ===")
  (println "This allows access to block devices!")
  ;; Allow block devices (dangerous!)
  (doseq [minor (range 0 16)]
    (allow-device-rw! 8 minor (format "/dev/sda%d" minor))))

;; ============================================================================
;; Monitoring
;; ============================================================================

(defn monitor-violations []
  (println "\n=== Device Access Violations ===")
  (println "TIME         CGROUP_ID        MAJOR MINOR ACCESS  REASON")
  (println "===========================================================")

  (bpf/consume-ring-buffer
    device-access-log
    (fn [data]
      (let [major (bytes->u32 data 0)
            minor (bytes->u32 data 4)
            access (bytes->u32 data 8)
            reason (bytes->u32 data 12)
            cgroup-id (bytes->u64 data 16)
            timestamp (bytes->u64 data 24)
            access-str (cond
                        (bit-test access 0) "MKNOD"
                        (bit-test access 1) "READ"
                        (bit-test access 2) "WRITE"
                        :else "UNKNOWN")
            reason-str (case reason
                         0 "NOT_WHITELISTED"
                         1 "BLOCK_DEVICE"
                         "UNKNOWN")]
        (printf "%d %-16x %-5d %-5d %-7s %s\n"
                timestamp cgroup-id major minor access-str reason-str)))
    {:poll-timeout-ms 100}))

(defn show-violation-stats []
  (println "\n=== Violation Statistics ===")
  (println "CGROUP_ID        VIOLATIONS")
  (println "=============================")
  (doseq [[cgroup-id count] (bpf/map-get-all violation-count)]
    (printf "%-16x %d\n" cgroup-id count)))

;; ============================================================================
;; Main
;; ============================================================================

(defn -main [& args]
  (let [[command profile container-id] args]
    (println "Container Device Access Control")

    ;; Apply profile
    (case (or profile "standard")
      "minimal" (apply-minimal-profile!)
      "standard" (apply-standard-profile!)
      "gpu" (apply-gpu-profile!)
      "privileged" (apply-privileged-profile!)
      (do
        (println "Unknown profile, using standard")
        (apply-standard-profile!)))

    ;; Load and attach program
    (let [prog (bpf/load-program device-access-control)
          cgroup-path (if container-id
                       (get-container-cgroup-path container-id)
                       "/sys/fs/cgroup")]
      (bpf/attach-cgroup prog cgroup-path :device)

      (case command
        "monitor" (monitor-violations)
        "stats" (show-violation-stats)
        (do
          (println "\nMonitoring violations (Ctrl-C to stop)...")
          (monitor-violations))))))
```

## Testing

```bash
# Apply standard profile to container
sudo lein run -m container.device-control monitor standard mycontainer

# Test from inside container
docker exec mycontainer dd if=/dev/zero of=/tmp/test bs=1M count=10  # Should work
docker exec mycontainer dd if=/dev/sda of=/tmp/disk bs=1M count=1    # Should fail
```

Expected output:
```
=== Device Access Violations ===
TIME         CGROUP_ID        MAJOR MINOR ACCESS  REASON
===========================================================
1234567890   abc123def456     8     0     READ    BLOCK_DEVICE
```

## Challenges

1. **Dynamic Devices**: Handle hotplugged devices
2. **Device Mapping**: Map major/minor to device names
3. **Temporary Access**: Grant temporary device access
4. **Audit Compliance**: Full audit trail of device access
5. **Performance**: Optimize for containers with many devices

## Key Takeaways

- cgroup/dev provides kernel-level device access control
- Essential for container security
- Prevents unauthorized hardware access
- Zero overhead for allowed devices

Chapter 11 is now complete! Let me commit these files.

## References

- [Linux Device Numbers](https://www.kernel.org/doc/Documentation/admin-guide/devices.txt)
- [Cgroup Device Controller](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/devices.html)
