# Chapter 9: LSM (Linux Security Modules)

## Introduction

LSM BPF programs attach to Linux Security Module hooks, enabling custom security policies and Mandatory Access Control (MAC) in the kernel. Unlike traditional LSMs (SELinux, AppArmor), LSM BPF allows dynamic, programmable security policies without kernel modules.

## What are LSM Hooks?

LSM hooks are strategically placed checkpoints throughout the kernel where security decisions are made:

```
User Space Application
        ↓
    System Call
        ↓
    Kernel Code
        ↓
    LSM Hook ← BPF Program Attached Here
        ↓
  Security Decision (ALLOW/DENY)
        ↓
    Operation Proceeds or Fails
```

## LSM BPF vs Traditional LSMs

| Feature | Traditional LSM | LSM BPF |
|---------|----------------|---------|
| **Loading** | Kernel module or built-in | Dynamic via BPF |
| **Flexibility** | Static policies | Programmable policies |
| **Performance** | Compiled C code | JIT-compiled BPF |
| **Safety** | Can crash kernel | Verified safe |
| **Updates** | Requires reboot | Hot-reload |
| **Stacking** | Multiple LSMs (limited) | Works with existing LSMs |

## Common LSM Hooks

LSM BPF provides 150+ hooks covering various kernel subsystems:

### File Operations
- `file_open` - Before opening a file
- `file_permission` - Before read/write operations
- `file_ioctl` - Before ioctl operations
- `file_mprotect` - Before changing memory protections
- `file_lock` - Before file locking

### Process/Task Operations
- `task_alloc` - Before task allocation
- `task_free` - Before task freeing
- `task_kill` - Before sending signals
- `bprm_check_security` - Before executing programs
- `bprm_committed_creds` - After credential changes

### Network Operations
- `socket_create` - Before socket creation
- `socket_connect` - Before connection attempts
- `socket_bind` - Before binding to addresses
- `socket_sendmsg` - Before sending messages
- `socket_recvmsg` - Before receiving messages

### IPC Operations
- `shm_alloc_security` - Shared memory allocation
- `msg_queue_msgrcv` - Message queue receive
- `sem_semop` - Semaphore operations

### Kernel Module Operations
- `kernel_module_request` - Before module loading
- `kernel_read_file` - Before reading kernel files

## Hook Arguments

Each LSM hook receives specific arguments. Example for `bprm_check_security`:

```clojure
;; Hook signature: int bprm_check_security(struct linux_binprm *bprm)
;; Arguments in BPF:
;; ctx + 0: struct linux_binprm *bprm pointer

(def LINUX_BINPRM_OFFSETS
  {:filename 0      ; const char *filename
   :argc 8          ; int argc
   :envc 12         ; int envc
   :file 16         ; struct file *file
   :cred 24})       ; const struct cred *cred
```

## Return Values

LSM BPF programs return integers indicating security decisions:

| Return Value | Meaning | Effect |
|--------------|---------|--------|
| **0** | Allow | Operation proceeds normally |
| **Negative errno** | Deny | Operation fails with error |
| **-EPERM (1)** | Permission denied | Most common denial |
| **-EACCES (13)** | Access denied | Alternative denial |

**Important**: Return 0 to allow, negative errno to deny.

## BTF and CO-RE

LSM BPF requires BTF (BPF Type Format) support for:
- Type-safe structure access
- Kernel version portability
- Compile Once, Run Everywhere (CO-RE)

Check BTF availability:
```bash
ls /sys/kernel/btf/vmlinux  # Should exist on modern kernels (5.2+)
```

## Security Contexts

LSM hooks operate in kernel security context with access to:

### Process Credentials (struct cred)
```clojure
(def CRED_OFFSETS
  {:uid 4           ; User ID
   :gid 8           ; Group ID
   :euid 12         ; Effective UID
   :egid 16         ; Effective GID
   :fsuid 20        ; Filesystem UID
   :fsgid 24})      ; Filesystem GID
```

### Inode Metadata (struct inode)
```clojure
(def INODE_OFFSETS
  {:i_mode 0        ; File mode (type + permissions)
   :i_uid 4         ; Owner UID
   :i_gid 8         ; Owner GID
   :i_size 16       ; File size
   :i_ino 24})      ; Inode number
```

### Task Metadata (struct task_struct)
```clojure
(def TASK_OFFSETS
  {:pid 8           ; Process ID
   :tgid 12         ; Thread group ID
   :comm 16         ; Command name (16 bytes)
   :cred 32})       ; Credentials pointer
```

## Use Cases

### 1. Container Security
- Restrict syscalls per container
- Enforce filesystem boundaries
- Control network access
- Prevent privilege escalation

### 2. Zero Trust Security
- Process-level network policies
- File access auditing
- Credential monitoring
- Lateral movement detection

### 3. Compliance Enforcement
- PCI-DSS controls
- HIPAA access logging
- SOC2 audit trails
- GDPR data access monitoring

### 4. Runtime Application Security
- Prevent code injection
- Control library loading
- Monitor file writes
- Network egress control

### 5. Ransomware Prevention
- Detect mass file encryption
- Block unauthorized file modifications
- Monitor suspicious process trees
- Prevent data exfiltration

## Performance Considerations

### Overhead
- **Hook Invocation**: ~100-500 nanoseconds per call
- **BPF Execution**: Depends on program complexity
- **Map Lookups**: ~50-100 ns for hash maps
- **Ring Buffer Events**: ~200-500 ns per event

### Hot Paths
Some LSM hooks are in **very hot paths**:
- `file_permission` - Called on every read/write
- `socket_sendmsg` - Called for every network send
- `task_kill` - Called for every signal

**Optimization strategies**:
1. Use early filtering (check common cases first)
2. Minimize map operations
3. Use per-CPU maps when possible
4. Cache security decisions
5. Use bloom filters for quick negative checks

### Cold Paths
Some hooks are infrequent and can tolerate more overhead:
- `bprm_check_security` - Only on exec
- `kernel_module_request` - Only on module load
- `file_open` - Relatively infrequent

## LSM BPF Program Structure

```clojure
(ns security.file-monitor
  (:require [clj-ebpf.core :as bpf]))

(def file-monitor-prog
  {:type :lsm
   :hook "file_open"  ; LSM hook name
   :program
   [(bpf/load-ctx :dw :r6 0)]  ; Load struct file* from ctx

   ;; Extract file path, check permissions, log events

   [(bpf/mov :r0 0)]           ; Return 0 = ALLOW
   [(bpf/exit)]]})
```

## Comparison with Other Program Types

| Aspect | LSM BPF | Kprobes | Tracepoints |
|--------|---------|---------|-------------|
| **Purpose** | Security enforcement | Dynamic tracing | Static tracing |
| **Return Effect** | Can block operations | No effect | No effect |
| **Stability** | Stable API (hook names) | Unstable (function names) | Stable API |
| **Performance** | Low overhead | Medium overhead | Low overhead |
| **Privileges** | Can deny operations | Observe only | Observe only |
| **BTF Required** | Yes (5.7+) | No | No |

## Kernel Version Requirements

| Feature | Minimum Kernel |
|---------|----------------|
| **LSM BPF Basic** | 5.7 |
| **Most LSM Hooks** | 5.7-5.10 |
| **Sleepable LSM** | 5.11 |
| **Full Hook Coverage** | 5.15+ |

Check support:
```bash
# Check if LSM BPF is enabled
cat /sys/kernel/security/lsm | grep bpf

# If not present, enable in kernel boot params:
# lsm=lockdown,yama,integrity,apparmor,bpf
```

## Security Decisions Example

```clojure
;; Block execution of specific binaries
(def BLOCKED_BINARIES
  #{"/usr/bin/netcat"
    "/bin/nc"
    "/usr/bin/wget"})

(def program
  [(bpf/load-ctx :dw :r6 0)]     ; struct linux_binprm *bprm
  [(bpf/load-mem :dw :r7 :r6 0)] ; bprm->filename

  ;; Check if filename is in blocked set
  ;; If blocked: return -EPERM (-1)
  ;; If allowed: return 0

  [(bpf/mov :r0 0)]              ; Allow by default
  [(bpf/exit)])
```

## Logging and Auditing

LSM programs often need to log security events:

```clojure
(def EVENT_FILE_OPEN 1)
(def EVENT_DENIED 2)

(def event-buffer
  {:type :ring_buffer
   :max_entries 1024})

(def log-event
  ;; Build event structure
  [(bpf/mov :r1 EVENT_FILE_OPEN)]
  [(bpf/store-mem :w :r10 -16 :r1)]  ; event.type

  ;; Store UID, PID, filename, timestamp

  ;; Submit to ring buffer
  [(bpf/mov :r1 (bpf/map-ref event-buffer))]
  [(bpf/mov :r2 :r10)]
  [(bpf/add :r2 -64)]                 ; Event data pointer
  [(bpf/mov :r3 64)]                  ; Size
  [(bpf/mov :r4 0)]                   ; Flags
  [(bpf/call (bpf/helper :ringbuf_output))])
```

## Best Practices

### 1. Default Allow Policy
Always default to allowing operations unless explicitly denied:
```clojure
;; GOOD: Explicit denials only
[(bpf/mov :r0 0)]        ; Allow by default
[(bpf/jmp-imm :jeq :r7 BLOCKED_UID :deny)]
;; ... more checks ...
[:deny]
[(bpf/mov :r0 -1)]       ; Deny specific cases
[(bpf/exit)]
```

### 2. Fail Open on Errors
If map lookups fail or data is unavailable, allow the operation:
```clojure
;; GOOD: Fail open
[(bpf/call (bpf/helper :map_lookup_elem))]
[(bpf/jmp-imm :jeq :r0 0 :allow)]  ; If lookup fails, allow
```

### 3. Minimize False Positives
Security policies should be precise to avoid disrupting legitimate operations.

### 4. Comprehensive Logging
Log both allowed and denied operations for forensics:
```clojure
;; Log before making decision
[(bpf/call (bpf/helper :ringbuf_output))]
;; Then return decision
[(bpf/mov :r0 -1)]  ; Deny
```

### 5. Performance Testing
Test LSM programs under load to ensure acceptable overhead:
```bash
# Benchmark with and without LSM BPF
sysbench fileio --file-test-mode=rndrd run
```

## Common Patterns

### Pattern 1: UID-Based Access Control
```clojure
;; Only allow root (UID 0) to execute
[(bpf/call (bpf/helper :get_current_uid_gid))]
[(bpf/rsh :r0 32)]               ; Extract UID
[(bpf/jmp-imm :jeq :r0 0 :allow)]
[(bpf/mov :r0 -1)]               ; Deny non-root
[:allow]
[(bpf/mov :r0 0)]                ; Allow root
```

### Pattern 2: Path-Based Filtering
```clojure
;; Block access to /etc/shadow
[(bpf/load-ctx :dw :r6 0)]       ; Get filename pointer
[(bpf/mov :r1 :r10)]
[(bpf/add :r1 -16)]
[(bpf/mov :r2 13)]               ; Length of "/etc/shadow"
[(bpf/mov :r3 :r6)]
[(bpf/call (bpf/helper :probe_read_kernel_str))]
;; Compare with "/etc/shadow"
```

### Pattern 3: Network Policy Enforcement
```clojure
;; Block connections to specific IPs
[(bpf/load-ctx :dw :r6 0)]       ; struct sockaddr*
[(bpf/load-mem :w :r7 :r6 4)]    ; sin_addr (IPv4)
[(bpf/endian-be :w :r7)]
[(bpf/jmp-imm :jeq :r7 BLOCKED_IP :deny)]
```

## Debugging LSM Programs

### 1. Check BPF Logs
```bash
dmesg | grep -i bpf
```

### 2. Verify Attachment
```bash
bpftool prog list | grep lsm
```

### 3. Check Return Values
Use `bpf_printk` to debug decisions:
```clojure
[(bpf/mov :r1 :r7)]              ; Decision value
[(bpf/call (bpf/helper :trace_printk))]
```

View output:
```bash
cat /sys/kernel/debug/tracing/trace_pipe
```

## Next Steps

The following labs demonstrate practical LSM BPF applications:

1. **Lab 9.1: File Access Monitor** - Track and audit file operations
2. **Lab 9.2: Process Execution Control** - Enforce binary execution policies
3. **Lab 9.3: Network Security Enforcer** - Control network connections with MAC policies

## References

- [LSM BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)
- [Available LSM Hooks](https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hooks.h)
- [BPF LSM Examples](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf/progs)
