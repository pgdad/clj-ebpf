# Lab 9.2: Process Execution Control

## Objective

Implement a process execution control system using LSM BPF to enforce security policies on binary execution. This lab demonstrates enforcement (actually denying operations) rather than just monitoring.

## Learning Goals

- Enforce security policies with LSM return values
- Use the `bprm_check_security` hook
- Implement whitelist/blacklist execution policies
- Handle hash-based verification
- Log security violations

## Background

The `bprm_check_security` LSM hook is called during `execve()` system calls, before a new program is executed. It provides a critical security checkpoint where we can:
- Verify executable integrity (hashes)
- Enforce path-based policies
- Implement application whitelisting
- Prevent unauthorized code execution
- Block known malicious binaries

**Key difference from Lab 9.1**: We return **negative errno** to deny execution, not just log it.

## Architecture

```
User: ./malicious_binary
        ↓
   execve() syscall
        ↓
   Kernel: do_execve()
        ↓
   LSM Hook: bprm_check_security
        ↓
   Our BPF Program
        ↓
   Check: Is binary allowed?
        ↓
   YES: Return 0         NO: Return -EPERM
        ↓                    ↓
   Execution proceeds   Execution blocked
        ↓                    ↓
   Process runs         execve() fails with EPERM
```

## Security Policies

We'll implement three policy modes:

### 1. Blacklist Mode (Default)
Block specific dangerous binaries:
- `/usr/bin/netcat` (nc)
- `/usr/bin/wget` (can exfiltrate data)
- `/usr/bin/curl` (can exfiltrate data)
- Shell interpreters in untrusted locations

### 2. Whitelist Mode (High Security)
Only allow execution of approved binaries:
- System binaries in `/usr/bin/`, `/bin/`
- Approved applications
- Deny everything else by default

### 3. Hash Verification Mode
Verify executable SHA256 hashes against known-good values.

## Kernel Structures

```c
// bprm_check_security hook context
struct linux_binprm {
    struct vm_area_struct *vma;    // Offset 0x0
    unsigned long vma_pages;       // Offset 0x8
    struct mm_struct *mm;          // Offset 0x10
    unsigned long p;               // Offset 0x18
    int argc, envc;                // Offset 0x20, 0x24
    const char *filename;          // Offset 0x28
    const char *interp;            // Offset 0x30
    struct file *file;             // Offset 0x38
    struct cred *cred;             // Offset 0x40
};

struct cred {
    uid_t uid;                     // Offset 0x4
    gid_t gid;                     // Offset 0x8
    uid_t euid;                    // Offset 0xc
    gid_t egid;                    // Offset 0x10
};
```

## Implementation

```clojure
(ns security.exec-control
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]))

;; ============================================================================
;; Constants and Offsets
;; ============================================================================

;; linux_binprm offsets
(def BINPRM_OFFSETS
  {:filename 0x28      ; const char*
   :file 0x38          ; struct file*
   :cred 0x40})        ; struct cred*

;; cred structure offsets
(def CRED_OFFSETS
  {:uid 0x4
   :gid 0x8
   :euid 0xc
   :egid 0x10})

;; Policy modes
(def POLICY_BLACKLIST 0)
(def POLICY_WHITELIST 1)
(def POLICY_HASH_VERIFY 2)

;; Error codes
(def EPERM 1)           ; Operation not permitted
(def EACCES 13)         ; Permission denied

;; Maximum path length
(def MAX_PATH 256)

;; Event types
(def EVENT_EXEC_ALLOWED 1)
(def EVENT_EXEC_BLOCKED 2)

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def config
  "Configuration map - single entry"
  {:type :array
   :key-type :u32
   :value-type :u32      ; Policy mode
   :max-entries 1})

(def blacklist
  "Blocked executables (path hash -> 1)"
  {:type :hash
   :key-type :u64       ; Path hash
   :value-type :u8      ; 1 = blocked
   :max-entries 1024})

(def whitelist
  "Allowed executables (path hash -> 1)"
  {:type :hash
   :key-type :u64       ; Path hash
   :value-type :u8      ; 1 = allowed
   :max-entries 4096})

(def exec-events
  "Ring buffer for execution events"
  {:type :ring_buffer
   :max_entries (* 128 1024)})

(def violation-count
  "Count violations per UID"
  {:type :hash
   :key-type :u32       ; UID
   :value-type :u64     ; Count
   :max-entries 1024})

;; ============================================================================
;; Helper Functions
;; ============================================================================

(defn simple-hash-string
  "Simple string hashing (DJB2 algorithm)
  Input: r6 = string pointer, r7 = max length
  Output: r8 = hash value
  Clobbers: r1-r4"
  []
  [[(bpf/mov :r8 5381)]                 ; hash = 5381

   ;; Loop through string
   [(bpf/mov :r9 0)]                    ; counter = 0
   [:hash-loop]
   [(bpf/jmp-reg :jge :r9 :r7 :hash-done)]  ; if counter >= max, done

   ;; Load byte
   [(bpf/mov-reg :r1 :r6)]
   [(bpf/add-reg :r1 :r9)]
   [(bpf/load-mem :b :r2 :r1 0)]

   ;; Check for null terminator
   [(bpf/jmp-imm :jeq :r2 0 :hash-done)]

   ;; hash = hash * 33 + c
   [(bpf/mov-reg :r3 :r8)]
   [(bpf/lsh :r3 5)]                    ; hash << 5
   [(bpf/add-reg :r3 :r8)]              ; (hash << 5) + hash = hash * 33
   [(bpf/add-reg :r3 :r2)]              ; + c
   [(bpf/mov-reg :r8 :r3)]

   [(bpf/add :r9 1)]
   [(bpf/jmp :hash-loop)]

   [:hash-done]])

(defn check-path-pattern
  "Check if path matches dangerous patterns
  Input: r6 = path string pointer
  Output: r7 = 1 if dangerous, 0 otherwise
  Clobbers: r1-r4"
  []
  [[(bpf/mov :r7 0)]                    ; Default: not dangerous

   ;; Check for /tmp/ prefix (scripts in /tmp are risky)
   [(bpf/load-mem :w :r1 :r6 0)]
   [(bpf/mov :r2 0x706d742f)]           ; "/tmp" little-endian
   [(bpf/jmp-reg :jeq :r1 :r2 :is-dangerous)]

   ;; Check for /dev/shm/ prefix (shared memory - risky)
   [(bpf/load-mem :dw :r1 :r6 0)]
   [(bpf/mov :r2 0x6d68732f7665642f)]   ; "/dev/shm" little-endian
   [(bpf/jmp-reg :jeq :r1 :r2 :is-dangerous)]

   ;; Check for hidden files (starts with /.)
   [(bpf/load-mem :h :r1 :r6 0)]
   [(bpf/mov :r2 0x2e2f)]               ; "/." little-endian
   [(bpf/jmp-reg :jeq :r1 :r2 :is-dangerous)]

   [(bpf/jmp :check-done)]

   [:is-dangerous]
   [(bpf/mov :r7 1)]

   [:check-done]])

(defn log-exec-event
  "Log execution event to ring buffer
  Input: r6 = path, r7 = PID, r8 = UID, r9 = decision (0=allow, 1=block)
  Clobbers: r1-r5"
  []
  [;; Reserve ring buffer space
   [(bpf/mov-reg :r1 (bpf/map-ref exec-events))]
   [(bpf/mov :r2 288)]                  ; Event size
   [(bpf/mov :r3 0)]
   [(bpf/call (bpf/helper :ringbuf_reserve))]

   [(bpf/jmp-imm :jeq :r0 0 :log-done)]
   [(bpf/store-mem :dw :r10 -8 :r0)]    ; Save event pointer

   ;; Copy PID
   [(bpf/load-mem :dw :r1 :r10 -16)]    ; r7 saved earlier
   [(bpf/load-mem :dw :r2 :r10 -8)]
   [(bpf/store-mem :w :r2 0 :r1)]

   ;; Copy UID
   [(bpf/load-mem :dw :r1 :r10 -24)]    ; r8 saved earlier
   [(bpf/load-mem :dw :r2 :r10 -8)]
   [(bpf/store-mem :w :r2 4 :r1)]

   ;; Copy decision
   [(bpf/load-mem :dw :r1 :r10 -32)]    ; r9 saved earlier
   [(bpf/load-mem :dw :r2 :r10 -8)]
   [(bpf/store-mem :w :r2 8 :r1)]

   ;; Copy path (first 256 bytes)
   [(bpf/mov-reg :r1 :r6)]              ; Source
   [(bpf/load-mem :dw :r2 :r10 -8)]     ; Dest
   [(bpf/add :r2 12)]
   [(bpf/mov :r3 256)]
   [(bpf/call (bpf/helper :probe_read_kernel_str))]

   ;; Get timestamp
   [(bpf/call (bpf/helper :ktime_get_ns))]
   [(bpf/load-mem :dw :r2 :r10 -8)]
   [(bpf/store-mem :dw :r2 268 :r0)]

   ;; Submit event
   [(bpf/load-mem :dw :r1 :r10 -8)]
   [(bpf/mov :r2 0)]
   [(bpf/call (bpf/helper :ringbuf_submit))]

   [:log-done]])

;; ============================================================================
;; Main LSM Program
;; ============================================================================

(def exec-control-prog
  "Process execution control via bprm_check_security"
  {:type :lsm
   :hook "bprm_check_security"
   :program
   [;; Load linux_binprm* from context
    [(bpf/load-ctx :dw :r6 0)]
    [(bpf/jmp-imm :jeq :r6 0 :allow)]

    ;; Load filename pointer
    [(bpf/load-mem :dw :r7 :r6 (:filename BINPRM_OFFSETS))]
    [(bpf/jmp-imm :jeq :r7 0 :allow)]

    ;; Read filename to stack
    [(bpf/mov-reg :r1 :r10)]
    [(bpf/add :r1 (- MAX_PATH))]
    [(bpf/mov :r2 MAX_PATH)]
    [(bpf/mov-reg :r3 :r7)]
    [(bpf/call (bpf/helper :probe_read_kernel_str))]

    ;; Save path pointer
    [(bpf/mov-reg :r6 :r10)]
    [(bpf/add :r6 (- MAX_PATH))]
    [(bpf/store-mem :dw :r10 -8 :r6)]

    ;; Get current PID
    [(bpf/call (bpf/helper :get_current_pid_tgid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :dw :r10 -16 :r0)]   ; Save PID

    ;; Get current UID
    [(bpf/call (bpf/helper :get_current_uid_gid))]
    [(bpf/rsh :r0 32)]
    [(bpf/store-mem :dw :r10 -24 :r0)]   ; Save UID
    [(bpf/mov-reg :r8 :r0)]              ; Keep in r8

    ;; ========================================================================
    ;; Load policy mode from config
    ;; ========================================================================

    [(bpf/mov :r7 0)]                    ; Key = 0
    [(bpf/store-mem :w :r10 -40 :r7)]
    [(bpf/mov-reg :r1 (bpf/map-ref config))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -40)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    ;; Default to blacklist mode if lookup fails
    [(bpf/mov :r9 POLICY_BLACKLIST)]
    [(bpf/jmp-imm :jeq :r0 0 :mode-loaded)]
    [(bpf/load-mem :w :r9 :r0 0)]

    [:mode-loaded]

    ;; ========================================================================
    ;; Compute path hash
    ;; ========================================================================

    [(bpf/load-mem :dw :r6 :r10 -8)]     ; Reload path pointer
    [(bpf/mov :r7 MAX_PATH)]
    (simple-hash-string)
    ;; r8 now contains hash
    [(bpf/store-mem :dw :r10 -48 :r8)]   ; Save hash

    ;; ========================================================================
    ;; Check policy based on mode
    ;; ========================================================================

    ;; If mode == POLICY_BLACKLIST
    [(bpf/jmp-imm :jne :r9 POLICY_BLACKLIST :check-whitelist)]

    ;; === Blacklist Mode ===
    [:blacklist-mode]
    ;; Lookup hash in blacklist
    [(bpf/mov-reg :r1 (bpf/map-ref blacklist))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -48)]                  ; Hash pointer
    [(bpf/call (bpf/helper :map_lookup_elem))]

    ;; If found in blacklist, deny
    [(bpf/jmp-imm :jne :r0 0 :deny)]

    ;; Also check path patterns
    [(bpf/load-mem :dw :r6 :r10 -8)]
    (check-path-pattern)
    [(bpf/jmp-imm :jeq :r7 1 :deny)]

    ;; Not in blacklist, allow
    [(bpf/jmp :allow)]

    ;; === Whitelist Mode ===
    [:check-whitelist]
    [(bpf/jmp-imm :jne :r9 POLICY_WHITELIST :allow)]  ; Unknown mode = allow

    [:whitelist-mode]
    ;; Lookup hash in whitelist
    [(bpf/mov-reg :r1 (bpf/map-ref whitelist))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -48)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    ;; If NOT in whitelist, deny
    [(bpf/jmp-imm :jeq :r0 0 :deny)]

    ;; In whitelist, allow
    [(bpf/jmp :allow)]

    ;; ========================================================================
    ;; Deny Execution
    ;; ========================================================================

    [:deny]
    ;; Log denial event
    [(bpf/load-mem :dw :r6 :r10 -8)]     ; path
    [(bpf/load-mem :dw :r7 :r10 -16)]    ; PID
    [(bpf/load-mem :dw :r8 :r10 -24)]    ; UID
    [(bpf/mov :r9 1)]                    ; decision = BLOCK
    [(bpf/store-mem :dw :r10 -16 :r7)]   ; Save for log-exec-event
    [(bpf/store-mem :dw :r10 -24 :r8)]
    [(bpf/store-mem :dw :r10 -32 :r9)]
    (log-exec-event)

    ;; Increment violation counter
    [(bpf/load-mem :dw :r7 :r10 -24)]    ; UID
    [(bpf/store-mem :w :r10 -56 :r7)]
    [(bpf/mov-reg :r1 (bpf/map-ref violation-count))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -56)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-violation-count)]
    ;; Increment existing
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]
    [(bpf/jmp :return-deny)]

    [:init-violation-count]
    ;; Initialize counter
    [(bpf/mov :r8 1)]
    [(bpf/store-mem :dw :r10 -64 :r8)]
    [(bpf/mov-reg :r1 (bpf/map-ref violation-count))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -56)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -64)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:return-deny]
    [(bpf/mov :r0 (- EPERM))]           ; Return -EPERM
    [(bpf/exit)]

    ;; ========================================================================
    ;; Allow Execution
    ;; ========================================================================

    [:allow]
    ;; Log allowed event (optional, comment out for performance)
    ;; [(bpf/load-mem :dw :r6 :r10 -8)]
    ;; [(bpf/load-mem :dw :r7 :r10 -16)]
    ;; [(bpf/load-mem :dw :r8 :r10 -24)]
    ;; [(bpf/mov :r9 0)]                 ; decision = ALLOW
    ;; (log-exec-event)

    [(bpf/mov :r0 0)]                    ; Return 0 = ALLOW
    [(bpf/exit)]]})

;; ============================================================================
;; Userspace Control Program
;; ============================================================================

(defn string->hash
  "Compute DJB2 hash of string (matching BPF version)"
  [s]
  (reduce (fn [hash c]
            (+ (* hash 33) (int c)))
          5381
          s))

(defn add-to-blacklist!
  "Add path to blacklist"
  [path]
  (let [hash (string->hash path)]
    (bpf/map-update! blacklist hash 1)
    (println "Blacklisted:" path "(hash:" hash ")")))

(defn add-to-whitelist!
  "Add path to whitelist"
  [path]
  (let [hash (string->hash path)]
    (bpf/map-update! whitelist hash 1)
    (println "Whitelisted:" path "(hash:" hash ")")))

(defn set-policy-mode!
  "Set enforcement policy mode"
  [mode]
  (bpf/map-update! config 0 mode)
  (println "Policy mode set to:"
           (case mode
             0 "BLACKLIST"
             1 "WHITELIST"
             "UNKNOWN")))

(defn monitor-violations
  "Monitor and display execution violations"
  []
  (bpf/consume-ring-buffer
    exec-events
    (fn [data]
      (let [pid (bytes->u32 data 0)
            uid (bytes->u32 data 4)
            decision (bytes->u32 data 8)
            path (bytes->str data 12 256)
            timestamp (bytes->u64 data 268)]
        (when (= decision 1)  ; Only show blocks
          (println (format "[BLOCKED] PID=%d UID=%d Path=%s"
                           pid uid path)))))
    {:poll-timeout-ms 100}))

(defn setup-default-blacklist!
  "Configure default dangerous binaries"
  []
  (println "Setting up default blacklist...")
  (doseq [path ["/usr/bin/netcat"
                "/usr/bin/nc"
                "/usr/bin/wget"
                "/usr/bin/curl"
                "/bin/netcat"
                "/bin/nc"]]
    (add-to-blacklist! path)))

(defn setup-system-whitelist!
  "Configure whitelist for common system binaries"
  []
  (println "Setting up system whitelist...")
  (doseq [path ["/bin/bash"
                "/bin/sh"
                "/usr/bin/ls"
                "/usr/bin/cat"
                "/usr/bin/vim"
                "/usr/bin/nano"
                "/usr/bin/systemctl"
                "/usr/bin/sudo"]]
    (add-to-whitelist! path)))

(defn dump-violations
  "Display violation statistics"
  []
  (println "\nViolation Statistics:")
  (println "UID    Count")
  (println "===============")
  (doseq [[uid count] (bpf/map-get-all violation-count)]
    (printf "%d\t%d\n" uid count)))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  [& args]
  (let [mode (or (first args) "blacklist")]
    (println "Starting execution control system...")
    (println "Mode:" mode)

    ;; Load and attach BPF program
    (let [prog (bpf/load-program exec-control-prog)]
      (bpf/attach-lsm prog "bprm_check_security")

      ;; Configure policy
      (case mode
        "blacklist"
        (do
          (set-policy-mode! POLICY_BLACKLIST)
          (setup-default-blacklist!))

        "whitelist"
        (do
          (set-policy-mode! POLICY_WHITELIST)
          (setup-system-whitelist!))

        (println "Unknown mode:" mode))

      (println "\nExecution control active. Monitoring violations...")
      (println "Press Ctrl-C to stop and view statistics\n")

      ;; Monitor violations
      (try
        (monitor-violations)
        (catch InterruptedException _
          (println "\n\nStopping...")
          (dump-violations))))))
```

## Testing

### Test 1: Blacklist Mode

```bash
# Terminal 1: Start with blacklist mode
sudo lein run -m security.exec-control blacklist

# Terminal 2: Try blocked commands
nc -l 1234          # Should be blocked
wget http://example.com  # Should be blocked
ls /etc             # Should work (not blacklisted)
```

Expected output:
```
[BLOCKED] PID=12345 UID=1000 Path=/usr/bin/nc
[BLOCKED] PID=12346 UID=1000 Path=/usr/bin/wget
```

### Test 2: Whitelist Mode

```bash
# Terminal 1: Start with whitelist mode
sudo lein run -m security.exec-control whitelist

# Terminal 2: Try various commands
ls /etc             # Should work (whitelisted)
cat /etc/passwd     # Should work (whitelisted)
python3             # Should be blocked (not in whitelist)
```

### Test 3: Dynamic Policy Updates

Add interactive REPL:
```clojure
(defn repl-mode
  []
  (println "Interactive policy editor")
  (loop []
    (print "> ")
    (flush)
    (let [input (read-line)
          parts (clojure.string/split input #" ")]
      (case (first parts)
        "blacklist" (add-to-blacklist! (second parts))
        "whitelist" (add-to-whitelist! (second parts))
        "stats" (dump-violations)
        "quit" :done
        (println "Unknown command"))
      (when (not= (first parts) "quit")
        (recur)))))
```

## Security Considerations

1. **Fail Open**: On errors, default to allowing execution to avoid system lockout
2. **Bypass Risk**: Hardlinks and symlinks can bypass path-based checks
3. **Hash Collisions**: DJB2 is not cryptographic - consider SHA256 for production
4. **Performance**: bprm_check_security is not a hot path, overhead is acceptable
5. **Root Bypass**: UID 0 could disable BPF programs - consider immutable attachment

## Advanced Enhancements

1. **Cryptographic Hashing**: Use SHA256 with `bpf_ima_file_hash` helper
2. **Argument Checking**: Inspect argv to detect suspicious arguments
3. **Parent Process Checking**: Only allow certain binaries from trusted parents
4. **Time-Based Policies**: Different rules for different times of day
5. **Machine Learning**: Integrate with userspace ML for anomaly detection

## Performance Impact

Measured with:
```bash
# Baseline
time for i in {1..1000}; do /bin/true; done

# With BPF
# Run exec-control, then:
time for i in {1..1000}; do /bin/true; done
```

Expected overhead: <5% (bprm_check_security is infrequent)

## Challenges

1. **Script Interpreters**: Block Python scripts but allow Python binary
2. **Container Integration**: Different policies per container namespace
3. **Audit Logging**: Export events to SIEM system
4. **Policy Templates**: Create pre-built policies for common scenarios
5. **Emergency Override**: Implement secure way to disable enforcement

## References

- [Application Whitelisting](https://attack.mitre.org/mitigations/M1038/)
- [Kernel exec flow](https://elixir.bootlin.com/linux/latest/source/fs/exec.c)
- [BPF LSM enforcement patterns](https://docs.kernel.org/bpf/prog_lsm.html)
