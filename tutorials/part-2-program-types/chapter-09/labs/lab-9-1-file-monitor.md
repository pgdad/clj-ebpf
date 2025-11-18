# Lab 9.1: File Access Monitor

## Objective

Create an LSM BPF program that monitors file access operations, tracking which processes open sensitive files. This lab demonstrates basic LSM concepts without enforcing policies (monitoring only).

## Learning Goals

- Attach BPF programs to LSM hooks
- Access kernel structures via BTF
- Extract process and file metadata
- Log security events to ring buffer
- Understand LSM return values

## Background

The `file_open` LSM hook is called whenever a process opens a file. It receives a `struct file*` pointer containing:
- File path (dentry/inode)
- File permissions and mode
- Open flags (read/write/append)

Our program will:
1. Extract the file path
2. Get current process information (PID, UID, command name)
3. Check if the file is "sensitive" (e.g., in /etc/, /root/)
4. Log the access to userspace
5. Always return 0 (allow) - monitoring only

## Architecture

```
User Process: vim /etc/shadow
        ↓
   open() syscall
        ↓
   Kernel: do_filp_open()
        ↓
   LSM Hook: file_open
        ↓
   Our BPF Program
        ↓
   Extract: PID, UID, comm, filepath
        ↓
   Check: Is sensitive file?
        ↓
   Log event → Ring Buffer → Userspace
        ↓
   Return 0 (ALLOW)
```

## Kernel Structures

```c
// LSM hook context
struct file {
    struct path f_path;        // Offset 0x18
    struct inode *f_inode;     // Offset 0x20
    const struct file_operations *f_op;
    unsigned int f_flags;      // Offset 0x38
    fmode_t f_mode;           // Offset 0x3c
};

struct path {
    struct vfsmount *mnt;     // Offset 0x0
    struct dentry *dentry;    // Offset 0x8
};

struct dentry {
    struct qstr d_name;       // Offset 0x20
    struct inode *d_inode;    // Offset 0x30
};

struct qstr {
    const unsigned char *name; // Offset 0x8
};
```

## Event Structure

```clojure
(def FILE_ACCESS_EVENT
  {:pid :u32        ; Process ID
   :uid :u32        ; User ID
   :flags :u32      ; File open flags
   :comm [16 :u8]   ; Process name
   :path [256 :u8]  ; File path
   :timestamp :u64}) ; Nanosecond timestamp
```

## Sensitive Path Patterns

We'll monitor access to:
- `/etc/passwd` - User account database
- `/etc/shadow` - Password hashes
- `/etc/sudoers` - Sudo configuration
- `/root/*` - Root's home directory
- `/var/log/*` - System logs

## Implementation

```clojure
(ns security.file-monitor
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]))

;; ============================================================================
;; Constants and Offsets
;; ============================================================================

;; File structure offsets
(def FILE_OFFSETS
  {:f-path 0x18      ; struct path (16 bytes)
   :f-inode 0x20     ; struct inode*
   :f-flags 0x38     ; unsigned int
   :f-mode 0x3c})    ; fmode_t

(def PATH_OFFSETS
  {:mnt 0x0         ; struct vfsmount*
   :dentry 0x8})    ; struct dentry*

(def DENTRY_OFFSETS
  {:d-name 0x20     ; struct qstr (16 bytes)
   :d-inode 0x30})  ; struct inode*

(def QSTR_OFFSETS
  {:name 0x8})      ; const char*

;; File open flags (from fcntl.h)
(def O_RDONLY 0x0000)
(def O_WRONLY 0x0001)
(def O_RDWR 0x0002)
(def O_CREAT 0x0040)
(def O_TRUNC 0x0200)
(def O_APPEND 0x0400)

;; Event types
(def EVENT_FILE_ACCESS 1)
(def EVENT_SENSITIVE_ACCESS 2)

;; Maximum path length
(def MAX_PATH_LEN 256)

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def events
  "Ring buffer for file access events"
  {:type :ring_buffer
   :max_entries (* 256 1024)})  ; 256 KB buffer

(def access-stats
  "Track access counts per UID"
  {:type :hash
   :key-type :u32       ; UID
   :value-type :u64     ; Access count
   :max-entries 1024})

;; ============================================================================
;; Helper Functions (as BPF code blocks)
;; ============================================================================

(defn extract-file-path
  "Extract file path from struct file*
  Input: r6 = struct file*
  Output: Writes path to stack at r10-256
  Clobbers: r1-r5, r7-r8"
  []
  [;; Load struct path from file->f_path
   [(bpf/mov-reg :r7 :r6)]
   [(bpf/add :r7 (:f-path FILE_OFFSETS))]

   ;; Load dentry from path->dentry
   [(bpf/load-mem :dw :r7 :r7 (:dentry PATH_OFFSETS))]
   [(bpf/jmp-imm :jeq :r7 0 :path-error)]

   ;; Load qstr from dentry->d_name
   [(bpf/mov-reg :r8 :r7)]
   [(bpf/add :r8 (:d-name DENTRY_OFFSETS))]

   ;; Load name pointer from qstr->name
   [(bpf/load-mem :dw :r3 :r8 (:name QSTR_OFFSETS))]
   [(bpf/jmp-imm :jeq :r3 0 :path-error)]

   ;; Read path string to stack
   [(bpf/mov-reg :r1 :r10)]
   [(bpf/add :r1 (- MAX_PATH_LEN))]
   [(bpf/mov :r2 MAX_PATH_LEN)]
   [(bpf/call (bpf/helper :probe_read_kernel_str))]

   [(bpf/jmp :path-done)]

   [:path-error]
   ;; Write "(unknown)" to stack on error
   [(bpf/mov-reg :r1 :r10)]
   [(bpf/add :r1 (- MAX_PATH_LEN))]
   [(bpf/mov :r2 0x6e776f6e6b6e7528)]  ; "(unknow"
   [(bpf/store-mem :dw :r1 0 :r2)]
   [(bpf/mov :r2 0x0000000029)]        ; "n)"
   [(bpf/store-mem :dw :r1 8 :r2)]

   [:path-done]])

(defn check-sensitive-path
  "Check if path matches sensitive patterns
  Input: r8 = pointer to path string (on stack)
  Output: r9 = 1 if sensitive, 0 otherwise
  Clobbers: r1-r3"
  []
  [;; Initialize result to 0 (not sensitive)
   [(bpf/mov :r9 0)]

   ;; Check for /etc/ prefix
   [(bpf/load-mem :w :r1 :r8 0)]        ; Load first 4 bytes
   [(bpf/mov :r2 0x6374652f)]           ; "/etc" in little-endian
   [(bpf/jmp-reg :jeq :r1 :r2 :is-sensitive)]

   ;; Check for /root/ prefix
   [(bpf/load-mem :dw :r1 :r8 0)]       ; Load first 8 bytes
   [(bpf/mov :r2 0x746f6f722f)]         ; "/root" in little-endian
   [(bpf/rsh :r1 16)]                   ; Shift to align
   [(bpf/jmp-reg :jeq :r1 :r2 :is-sensitive)]

   ;; Check for /var/log/ prefix
   [(bpf/load-mem :dw :r1 :r8 0)]
   [(bpf/mov :r2 0x676f6c2f7261762f)]   ; "/var/log" in little-endian
   [(bpf/jmp-reg :jeq :r1 :r2 :is-sensitive)]

   [(bpf/jmp :check-done)]

   [:is-sensitive]
   [(bpf/mov :r9 1)]

   [:check-done]])

(defn extract-process-info
  "Extract current process information
  Output: Writes to stack at r10-288 (comm) and r10-280 (pid/uid)
  Clobbers: r1-r4"
  []
  [;; Get current PID and TID
   [(bpf/call (bpf/helper :get_current_pid_tgid))]
   [(bpf/mov-reg :r7 :r0)]              ; Save for later
   [(bpf/rsh :r7 32)]                   ; Extract PID
   [(bpf/store-mem :w :r10 -280 :r7)]   ; Store PID on stack

   ;; Get current UID and GID
   [(bpf/call (bpf/helper :get_current_uid_gid))]
   [(bpf/rsh :r0 32)]                   ; Extract UID
   [(bpf/store-mem :w :r10 -276 :r0)]   ; Store UID on stack

   ;; Get current command name
   [(bpf/mov-reg :r1 :r10)]
   [(bpf/add :r1 -288)]
   [(bpf/mov :r2 16)]                   ; TASK_COMM_LEN
   [(bpf/call (bpf/helper :get_current_comm))]])

;; ============================================================================
;; Main LSM Program
;; ============================================================================

(def file-open-monitor
  "Monitor file_open LSM hook"
  {:type :lsm
   :hook "file_open"
   :program
   [;; Load struct file* from context
    [(bpf/load-ctx :dw :r6 0)]          ; r6 = struct file*
    [(bpf/jmp-imm :jeq :r6 0 :allow)]   ; Null check

    ;; Extract file open flags
    [(bpf/load-mem :w :r7 :r6 (:f-flags FILE_OFFSETS))]
    [(bpf/store-mem :w :r10 -272 :r7)]  ; Store flags on stack

    ;; Extract file path
    (extract-file-path)

    ;; Check if sensitive
    [(bpf/mov-reg :r8 :r10)]
    [(bpf/add :r8 (- MAX_PATH_LEN))]
    (check-sensitive-path)
    ;; r9 now contains 1 if sensitive, 0 otherwise

    ;; Extract process information
    (extract-process-info)

    ;; Get timestamp
    [(bpf/call (bpf/helper :ktime_get_ns))]
    [(bpf/store-mem :dw :r10 -264 :r0)] ; Store timestamp on stack

    ;; ========================================================================
    ;; Prepare event structure for ring buffer
    ;; ========================================================================

    ;; Reserve space in ring buffer
    [(bpf/mov-reg :r1 (bpf/map-ref events))]
    [(bpf/mov :r2 288)]                 ; Event size
    [(bpf/mov :r3 0)]                   ; Flags
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    ;; Check if reservation succeeded
    [(bpf/jmp-imm :jeq :r0 0 :update-stats)]
    [(bpf/mov-reg :r8 :r0)]             ; Save event pointer

    ;; Copy PID (4 bytes)
    [(bpf/load-mem :w :r1 :r10 -280)]
    [(bpf/store-mem :w :r8 0 :r1)]

    ;; Copy UID (4 bytes)
    [(bpf/load-mem :w :r1 :r10 -276)]
    [(bpf/store-mem :w :r8 4 :r1)]

    ;; Copy flags (4 bytes)
    [(bpf/load-mem :w :r1 :r10 -272)]
    [(bpf/store-mem :w :r8 8 :r1)]

    ;; Copy comm (16 bytes) - use loop unrolling
    [(bpf/load-mem :dw :r1 :r10 -288)]
    [(bpf/store-mem :dw :r8 12 :r1)]
    [(bpf/load-mem :dw :r1 :r10 -280)]
    [(bpf/store-mem :dw :r8 20 :r1)]

    ;; Copy path (256 bytes) - partial copy for efficiency (first 64 bytes)
    [(bpf/mov :r9 0)]                   ; Counter
    [:copy-loop]
    [(bpf/jmp-imm :jge :r9 64 :copy-done)]
    [(bpf/mov-reg :r1 :r10)]
    [(bpf/add :r1 (- MAX_PATH_LEN))]
    [(bpf/add-reg :r1 :r9)]
    [(bpf/load-mem :b :r2 :r1 0)]       ; Load byte
    [(bpf/mov-reg :r3 :r8)]
    [(bpf/add :r3 28)]                  ; Offset to path field
    [(bpf/add-reg :r3 :r9)]
    [(bpf/store-mem :b :r3 0 :r2)]      ; Store byte
    [(bpf/add :r9 1)]
    ;; Check for null terminator
    [(bpf/jmp-imm :jeq :r2 0 :copy-done)]
    [(bpf/jmp :copy-loop)]

    [:copy-done]
    ;; Copy timestamp (8 bytes)
    [(bpf/load-mem :dw :r1 :r10 -264)]
    [(bpf/store-mem :dw :r8 284 :r1)]

    ;; Submit event to ring buffer
    [(bpf/mov-reg :r1 :r8)]             ; Event pointer
    [(bpf/mov :r2 0)]                   ; Flags
    [(bpf/call (bpf/helper :ringbuf_submit))]

    ;; ========================================================================
    ;; Update access statistics
    ;; ========================================================================

    [:update-stats]
    ;; Load UID for map key
    [(bpf/load-mem :w :r7 :r10 -276)]
    [(bpf/store-mem :w :r10 -292 :r7)]

    ;; Lookup or initialize counter
    [(bpf/mov-reg :r1 (bpf/map-ref access-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -292)]                ; Key pointer (UID)
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jne :r0 0 :update-existing)]

    ;; Initialize new entry
    [(bpf/mov :r8 1)]                   ; Initial count
    [(bpf/store-mem :dw :r10 -304 :r8)]
    [(bpf/mov-reg :r1 (bpf/map-ref access-stats))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -292)]                ; Key pointer
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -304)]                ; Value pointer
    [(bpf/mov :r4 0)]                   ; Flags
    [(bpf/call (bpf/helper :map_update_elem))]
    [(bpf/jmp :allow)]

    [:update-existing]
    ;; Increment existing counter
    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]

    ;; ========================================================================
    ;; Return decision
    ;; ========================================================================

    [:allow]
    [(bpf/mov :r0 0)]                   ; Return 0 = ALLOW
    [(bpf/exit)]]})

;; ============================================================================
;; Userspace Program
;; ============================================================================

(defn parse-file-access-event
  "Parse file access event from ring buffer"
  [data]
  (let [pid (bytes->u32 data 0)
        uid (bytes->u32 data 4)
        flags (bytes->u32 data 8)
        comm (bytes->str data 12 16)
        path (bytes->str data 28 256)
        timestamp (bytes->u64 data 284)]
    {:pid pid
     :uid uid
     :flags flags
     :comm comm
     :path path
     :timestamp timestamp}))

(defn flags->string
  "Convert open flags to readable string"
  [flags]
  (let [mode (bit-and flags 0x3)]
    (str (case mode
           0 "O_RDONLY"
           1 "O_WRONLY"
           2 "O_RDWR"
           "UNKNOWN")
         (when (bit-test flags 6) "|O_CREAT")
         (when (bit-test flags 9) "|O_TRUNC")
         (when (bit-test flags 10) "|O_APPEND"))))

(defn format-timestamp
  "Convert nanoseconds to readable time"
  [ns]
  (let [seconds (quot ns 1000000000)
        nanos (rem ns 1000000000)]
    (format "%d.%09d" seconds nanos)))

(defn monitor-file-access
  "Monitor and display file access events"
  []
  (println "Starting file access monitor...")
  (println "Monitoring sensitive file access (Ctrl-C to stop)")
  (println)
  (println "TIME                PID    UID    COMM            FLAGS          PATH")
  (println "===================================================================================")

  ;; Load and attach BPF program
  (let [prog (bpf/load-program file-open-monitor)
        _attached (bpf/attach-lsm prog "file_open")]

    ;; Process events from ring buffer
    (bpf/consume-ring-buffer
      (get-in file-open-monitor [:maps :events])
      (fn [data]
        (let [event (parse-file-access-event data)
              time-str (format-timestamp (:timestamp event))
              flags-str (flags->string (:flags event))]
          (printf "%-20s %-6d %-6d %-15s %-14s %s\n"
                  time-str
                  (:pid event)
                  (:uid event)
                  (:comm event)
                  flags-str
                  (:path event))))
      {:poll-timeout-ms 100})))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  []
  (try
    (monitor-file-access)
    (catch InterruptedException _
      (println "\nStopping monitor..."))
    (catch Exception e
      (println "Error:" (.getMessage e))
      (.printStackTrace e))))
```

## Testing

### Test 1: Monitor Normal File Access

```bash
# Terminal 1: Run monitor
sudo lein run -m security.file-monitor

# Terminal 2: Access files
cat /etc/passwd
vim /etc/hosts
ls /root/
```

Expected output:
```
TIME                PID    UID    COMM            FLAGS          PATH
===================================================================================
1234567890.123456789 12345  1000   cat             O_RDONLY       /etc/passwd
1234567890.234567890 12346  1000   vim             O_RDWR         /etc/hosts
1234567890.345678901 12347  0      ls              O_RDONLY       /root/
```

### Test 2: Monitor Write Operations

```bash
# Terminal 2
echo "test" >> /tmp/test.txt
sudo vim /etc/sudoers
```

Expected output shows different flags (O_WRONLY|O_CREAT, O_RDWR).

### Test 3: Check Statistics

Add a function to dump access-stats map:
```clojure
(defn dump-stats
  "Display access statistics by UID"
  []
  (println "\nAccess Statistics by UID:")
  (doseq [[uid count] (bpf/map-get-all access-stats)]
    (printf "UID %d: %d accesses\n" uid count)))
```

## Security Considerations

1. **Monitoring Only**: This lab intentionally does not enforce policies
2. **Performance**: File access is a hot path - keep monitoring lightweight
3. **Privacy**: Be aware that paths may contain sensitive information
4. **Storage**: Ring buffer can overflow under heavy load - increase size if needed

## Performance Analysis

Measure overhead with:
```bash
# Without BPF
time find /usr -name "*.so" > /dev/null

# With BPF
# Run monitor, then in another terminal:
time find /usr -name "*.so" > /dev/null
```

Expected overhead: 5-15% for file-intensive workloads.

## Challenges

1. **Selective Monitoring**: Modify to only log access to specific directories
2. **Rate Limiting**: Implement per-process rate limiting to reduce event spam
3. **Path Matching**: Add wildcard pattern matching for flexible rules
4. **Aggregation**: Count accesses per file in a separate map
5. **Anomaly Detection**: Alert when unusual access patterns occur

## Next Steps

- **Lab 9.2**: Enforcement policies - actually deny operations
- **Lab 9.3**: Network security with socket hooks
- **Chapter 10**: Advanced BPF features (CO-RE, BTF)

## References

- `/sys/kernel/security/lsm` - LSM configuration
- `struct file` definition in kernel source
- [LSM Hook Points](https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h)
