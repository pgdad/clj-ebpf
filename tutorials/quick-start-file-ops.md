# Quick Start: File Operations with openat Syscall

**Duration**: 15-20 minutes | **Difficulty**: Beginner

## Learning Objectives

By the end of this tutorial, you will:
- Understand how clj-ebpf provides low-level file access via syscalls
- Know the available open flags and when to use them
- Be able to open, create, and manage files using `file-open`
- Handle errors properly when working with file operations
- Understand the cross-architecture support for file operations

## Prerequisites

- Basic Clojure knowledge
- clj-ebpf installed
- Linux environment (any architecture)

## Introduction

### Why Low-Level File Access?

clj-ebpf provides `file-open`, a low-level file opening function that uses the Linux `openat` syscall directly via Java's Panama FFI. This offers:

- **Direct syscall access** - No JVM overhead for file operations
- **Full control** - Access to all Linux open flags
- **Cross-architecture support** - Works on x86_64, arm64, s390x, ppc64le, riscv64
- **Integration** - Consistent with other clj-ebpf syscall operations

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Clojure Code                              │
│  (syscall/file-open "/path/file" O_RDONLY)                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     clj-ebpf.syscall                             │
│  - Allocates path string in native memory                       │
│  - Calls raw-syscall with openat syscall number                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Java Panama FFI                                │
│  - Creates MemorySegment for string                             │
│  - Invokes syscall via downcall handle                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Linux Kernel                                │
│  openat(AT_FDCWD, "/path/file", O_RDONLY, mode)                 │
│  Returns: file descriptor (positive) or error (negative)        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Part 1: Basic File Operations

### Opening Files

The `file-open` function opens files and returns a file descriptor:

```clojure
(require '[clj-ebpf.syscall :as syscall])

;; Open existing file for reading
(let [fd (syscall/file-open "/etc/passwd" syscall/O_RDONLY)]
  (println "Opened file, fd:" fd)
  ;; Use the file descriptor...
  (syscall/close-fd fd))
```

### Function Signature

```clojure
(file-open path flags)        ;; Uses default mode 0644
(file-open path flags mode)   ;; Specify mode explicitly
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | String | File path (absolute or relative) |
| `flags` | Integer | Open flags (O_RDONLY, O_WRONLY, etc.) |
| `mode` | Integer | File permissions for creation (octal, e.g., 0644) |

### Return Value

- **Success**: Returns a positive integer file descriptor
- **Error**: Throws `ExceptionInfo` with error details

---

## Part 2: Open Flags

### Basic Access Modes

| Flag | Value | Description |
|------|-------|-------------|
| `O_RDONLY` | 0x0000 | Open for reading only |
| `O_WRONLY` | 0x0001 | Open for writing only |
| `O_RDWR` | 0x0002 | Open for reading and writing |

```clojure
;; Read-only access
(syscall/file-open "/etc/passwd" syscall/O_RDONLY)

;; Write-only access
(syscall/file-open "/tmp/output.txt" syscall/O_WRONLY)

;; Read-write access
(syscall/file-open "/tmp/data.txt" syscall/O_RDWR)
```

### Creation Flags

| Flag | Value | Description |
|------|-------|-------------|
| `O_CREAT` | 0x0040 | Create file if it doesn't exist |
| `O_EXCL` | 0x0080 | Fail if file exists (with O_CREAT) |
| `O_TRUNC` | 0x0200 | Truncate file to zero length |

```clojure
;; Create new file (or open existing)
(syscall/file-open "/tmp/new.txt"
                   (bit-or syscall/O_CREAT syscall/O_WRONLY)
                   0644)

;; Create exclusively (fail if exists)
(syscall/file-open "/tmp/lock.pid"
                   (bit-or syscall/O_CREAT syscall/O_EXCL syscall/O_WRONLY)
                   0600)

;; Truncate existing file
(syscall/file-open "/tmp/log.txt"
                   (bit-or syscall/O_WRONLY syscall/O_TRUNC))
```

### Behavior Flags

| Flag | Value | Description |
|------|-------|-------------|
| `O_APPEND` | 0x0400 | Append to end of file |
| `O_NONBLOCK` | 0x0800 | Non-blocking I/O |
| `O_CLOEXEC` | 0x80000 | Close on exec |

```clojure
;; Append mode (writes go to end)
(syscall/file-open "/var/log/app.log"
                   (bit-or syscall/O_WRONLY syscall/O_APPEND syscall/O_CREAT)
                   0644)

;; Close-on-exec (security best practice)
(syscall/file-open "/tmp/temp.txt"
                   (bit-or syscall/O_CREAT syscall/O_RDWR syscall/O_CLOEXEC)
                   0600)
```

---

## Part 3: File Permissions

When creating files with `O_CREAT`, the `mode` parameter specifies permissions:

### Common Permission Modes

| Mode | Meaning |
|------|---------|
| `0644` | Owner: read/write, Group: read, Others: read |
| `0600` | Owner: read/write only |
| `0755` | Owner: all, Group: read/execute, Others: read/execute |
| `0666` | Everyone: read/write (modified by umask) |

```clojure
;; Create private file (owner only)
(syscall/file-open "/tmp/secret.txt"
                   (bit-or syscall/O_CREAT syscall/O_WRONLY)
                   0600)

;; Create world-readable file
(syscall/file-open "/tmp/public.txt"
                   (bit-or syscall/O_CREAT syscall/O_WRONLY)
                   0644)

;; Default mode (0644) when not specified
(syscall/file-open "/tmp/default.txt"
                   (bit-or syscall/O_CREAT syscall/O_WRONLY))
```

---

## Part 4: Error Handling

### Exception Structure

When an error occurs, `file-open` throws `ExceptionInfo` with:

```clojure
{:path "/failed/path"     ;; The path that failed
 :flags 0                 ;; The flags used
 :mode 0644               ;; The mode used
 :errno 2                 ;; Raw errno value
 :error :enoent}          ;; Error keyword
```

### Common Errors

| Error | Errno | Description |
|-------|-------|-------------|
| `:enoent` | 2 | File not found |
| `:eacces` | 13 | Permission denied |
| `:eexist` | 17 | File exists (with O_EXCL) |
| `:eisdir` | 21 | Is a directory |
| `:emfile` | 24 | Too many open files |
| `:enodev` | 19 | No such device |

### Handling Errors

```clojure
(try
  (syscall/file-open "/nonexistent/file" syscall/O_RDONLY)
  (catch clojure.lang.ExceptionInfo e
    (let [data (ex-data e)]
      (case (:error data)
        :enoent (println "File not found:" (:path data))
        :eacces (println "Permission denied")
        :eexist (println "File already exists")
        (println "Unknown error:" (:error data))))))
```

---

## Part 5: Practical Patterns

### Lock File Pattern

Use `O_EXCL` for exclusive access:

```clojure
(defn with-lock-file [lock-path f]
  (let [fd (try
             (syscall/file-open lock-path
                                (bit-or syscall/O_CREAT
                                        syscall/O_EXCL
                                        syscall/O_WRONLY)
                                0644)
             (catch clojure.lang.ExceptionInfo e
               (when (= :eexist (:error (ex-data e)))
                 (throw (ex-info "Lock already held" {:lock lock-path})))
               (throw e)))]
    (try
      (f)
      (finally
        (syscall/close-fd fd)
        (.delete (java.io.File. lock-path))))))

;; Usage
(with-lock-file "/tmp/myapp.lock"
  (fn [] (println "Critical section")))
```

### Safe File Creation

Avoid race conditions with `O_EXCL`:

```clojure
(defn create-unique-file [base-path]
  (loop [attempt 0]
    (when (< attempt 100)
      (let [path (str base-path "." (System/currentTimeMillis) "." attempt)]
        (try
          (syscall/file-open path
                             (bit-or syscall/O_CREAT
                                     syscall/O_EXCL
                                     syscall/O_WRONLY)
                             0600)
          (catch clojure.lang.ExceptionInfo e
            (if (= :eexist (:error (ex-data e)))
              (recur (inc attempt))
              (throw e))))))))
```

### Log File Append

Use `O_APPEND` for concurrent-safe logging:

```clojure
(defn append-log [log-path message]
  (let [fd (syscall/file-open log-path
                              (bit-or syscall/O_CREAT
                                      syscall/O_WRONLY
                                      syscall/O_APPEND)
                              0644)]
    (try
      ;; Write message to fd...
      fd
      (finally
        (syscall/close-fd fd)))))
```

---

## Part 6: Cross-Architecture Support

### Syscall Numbers

The `openat` syscall number varies by architecture:

| Architecture | Syscall Number |
|--------------|----------------|
| x86_64 | 257 |
| arm64 | 56 |
| riscv64 | 56 |
| s390x | 288 |
| ppc64le | 286 |

clj-ebpf automatically uses the correct syscall number for your platform:

```clojure
(require '[clj-ebpf.arch :as arch])

;; Check current architecture
(println "Architecture:" arch/arch-name)
(println "openat syscall:" (arch/get-syscall-nr :openat))
```

### AT_FDCWD

The `AT_FDCWD` constant (-100) tells `openat` to interpret relative paths from the current working directory:

```clojure
;; Both are equivalent:
(syscall/file-open "relative/path.txt" syscall/O_RDONLY)
(syscall/file-open "./relative/path.txt" syscall/O_RDONLY)
```

---

## Summary

### Key Functions

| Function | Purpose |
|----------|---------|
| `file-open` | Open/create files using openat syscall |
| `close-fd` | Close a file descriptor |

### Key Constants

| Constant | Purpose |
|----------|---------|
| `O_RDONLY` | Read-only access |
| `O_WRONLY` | Write-only access |
| `O_RDWR` | Read-write access |
| `O_CREAT` | Create file |
| `O_EXCL` | Exclusive creation |
| `O_TRUNC` | Truncate file |
| `O_APPEND` | Append mode |
| `O_CLOEXEC` | Close on exec |
| `AT_FDCWD` | Current directory |

### Best Practices

1. **Always close file descriptors** - Use try/finally or with-open patterns
2. **Use O_CLOEXEC** - Prevents fd leaks to child processes
3. **Check permissions** - Handle `:eacces` errors gracefully
4. **Use O_EXCL for locks** - Prevents race conditions
5. **Set appropriate modes** - Use 0600 for sensitive files

---

## Next Steps

- Explore the [File Operations Example](../examples/file_operations.clj)
- Learn about [BPF Maps](quick-start-macros.md) for storing data
- See the [API Reference](../docs/api/clj-ebpf.syscall.html)
