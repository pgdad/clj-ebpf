(ns file-operations
  "File Operations Example

   This example demonstrates the file-open functionality in clj-ebpf,
   which uses the openat syscall via Panama FFI for low-level file access.

   Key Features:
   - Direct syscall access without JVM overhead
   - Full control over open flags and modes
   - Cross-architecture support (x86_64, arm64, s390x, ppc64le, riscv64)
   - Integration with other clj-ebpf syscall operations

   Usage:
     clojure -M:examples -m file-operations"
  (:require [clj-ebpf.syscall :as syscall]
            [clj-ebpf.arch :as arch])
  (:import [java.io File]))

;; ============================================================================
;; Section 1: Basic File Operations
;; ============================================================================

(defn demo-basic-open
  "Demonstrate basic file opening operations."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 1: BASIC FILE OPERATIONS")
  (println (apply str (repeat 70 "=")) "\n")

  ;; Example 1: Open existing file for reading
  (println "Example 1: Open Existing File for Reading")
  (println "------------------------------------------")
  (let [fd (syscall/file-open "/etc/passwd" syscall/O_RDONLY)]
    (println "  (syscall/file-open \"/etc/passwd\" syscall/O_RDONLY)")
    (println "  Result: fd =" fd)
    (syscall/close-fd fd)
    (println "  File closed successfully\n"))

  ;; Example 2: Open /dev/null
  (println "Example 2: Open /dev/null")
  (println "-------------------------")
  (let [fd (syscall/file-open "/dev/null" syscall/O_WRONLY)]
    (println "  (syscall/file-open \"/dev/null\" syscall/O_WRONLY)")
    (println "  Result: fd =" fd)
    (syscall/close-fd fd)
    (println "  Useful for discarding output\n"))

  ;; Example 3: Open special device
  (println "Example 3: Open Random Device")
  (println "------------------------------")
  (let [fd (syscall/file-open "/dev/urandom" syscall/O_RDONLY)]
    (println "  (syscall/file-open \"/dev/urandom\" syscall/O_RDONLY)")
    (println "  Result: fd =" fd)
    (syscall/close-fd fd)
    (println "  Can read random bytes from this fd\n")))

;; ============================================================================
;; Section 2: Creating Files
;; ============================================================================

(defn demo-create-file
  "Demonstrate file creation with various modes."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 2: CREATING FILES")
  (println (apply str (repeat 70 "=")) "\n")

  ;; Example 1: Create new file
  (println "Example 1: Create New File")
  (println "--------------------------")
  (let [test-file "/tmp/clj-ebpf-demo-create.txt"
        fd (syscall/file-open test-file
                              (bit-or syscall/O_CREAT syscall/O_WRONLY)
                              0644)]
    (println "  (syscall/file-open path")
    (println "                      (bit-or syscall/O_CREAT syscall/O_WRONLY)")
    (println "                      0644)")
    (println "  Created file:" test-file)
    (println "  Result: fd =" fd)
    (syscall/close-fd fd)
    (.delete (File. test-file))
    (println "  Cleaned up test file\n"))

  ;; Example 2: Create with exclusive flag
  (println "Example 2: Create with O_EXCL (Exclusive)")
  (println "------------------------------------------")
  (let [test-file "/tmp/clj-ebpf-demo-excl.txt"
        fd (syscall/file-open test-file
                              (bit-or syscall/O_CREAT
                                      syscall/O_EXCL
                                      syscall/O_WRONLY)
                              0600)]
    (println "  (syscall/file-open path")
    (println "                      (bit-or syscall/O_CREAT")
    (println "                              syscall/O_EXCL")
    (println "                              syscall/O_WRONLY)")
    (println "                      0600)")
    (println "  O_EXCL ensures file doesn't already exist")
    (println "  Useful for lock files and atomic creation")
    (println "  Result: fd =" fd)
    (syscall/close-fd fd)
    (.delete (File. test-file))
    (println "  Cleaned up test file\n"))

  ;; Example 3: Create and truncate
  (println "Example 3: Create with O_TRUNC")
  (println "-------------------------------")
  (let [test-file "/tmp/clj-ebpf-demo-trunc.txt"]
    ;; Create file with some content
    (spit test-file "Previous content that will be truncated")
    (println "  Initial file size:" (.length (File. test-file)) "bytes")
    (let [fd (syscall/file-open test-file
                                (bit-or syscall/O_WRONLY syscall/O_TRUNC))]
      (println "  (syscall/file-open path")
      (println "                      (bit-or syscall/O_WRONLY syscall/O_TRUNC))")
      (println "  O_TRUNC truncates file to zero length")
      (syscall/close-fd fd))
    (println "  File size after O_TRUNC:" (.length (File. test-file)) "bytes")
    (.delete (File. test-file))
    (println "  Cleaned up test file\n")))

;; ============================================================================
;; Section 3: File Open Flags
;; ============================================================================

(defn demo-flags
  "Demonstrate various open flags and their combinations."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 3: FILE OPEN FLAGS")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Available O_* Constants:")
  (println "------------------------")
  (println (format "  O_RDONLY    = 0x%04X  (Open for reading only)" syscall/O_RDONLY))
  (println (format "  O_WRONLY    = 0x%04X  (Open for writing only)" syscall/O_WRONLY))
  (println (format "  O_RDWR      = 0x%04X  (Open for reading and writing)" syscall/O_RDWR))
  (println (format "  O_CREAT     = 0x%04X  (Create file if doesn't exist)" syscall/O_CREAT))
  (println (format "  O_EXCL      = 0x%04X  (Fail if file exists, with O_CREAT)" syscall/O_EXCL))
  (println (format "  O_TRUNC     = 0x%04X  (Truncate file to zero length)" syscall/O_TRUNC))
  (println (format "  O_APPEND    = 0x%04X  (Append to end of file)" syscall/O_APPEND))
  (println (format "  O_NONBLOCK  = 0x%04X  (Non-blocking I/O)" syscall/O_NONBLOCK))
  (println (format "  O_CLOEXEC   = 0x%05X (Close on exec)" syscall/O_CLOEXEC))
  (println)

  (println "Common Flag Combinations:")
  (println "-------------------------")
  (println "  Create and write (new file):")
  (println "    (bit-or O_CREAT O_WRONLY)")
  (println (format "    = 0x%04X" (bit-or syscall/O_CREAT syscall/O_WRONLY)))
  (println)
  (println "  Create and truncate (overwrite existing):")
  (println "    (bit-or O_CREAT O_WRONLY O_TRUNC)")
  (println (format "    = 0x%04X" (bit-or syscall/O_CREAT syscall/O_WRONLY syscall/O_TRUNC)))
  (println)
  (println "  Append to file:")
  (println "    (bit-or O_WRONLY O_APPEND)")
  (println (format "    = 0x%04X" (bit-or syscall/O_WRONLY syscall/O_APPEND)))
  (println)
  (println "  Create exclusive with close-on-exec:")
  (println "    (bit-or O_CREAT O_EXCL O_WRONLY O_CLOEXEC)")
  (println (format "    = 0x%05X" (bit-or syscall/O_CREAT syscall/O_EXCL
                                          syscall/O_WRONLY syscall/O_CLOEXEC)))
  (println))

;; ============================================================================
;; Section 4: Architecture Information
;; ============================================================================

(defn demo-architecture
  "Show architecture-specific syscall information."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 4: ARCHITECTURE INFORMATION")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Current Architecture:" arch/arch-name)
  (println "Arch keyword:" arch/current-arch)
  (println)

  (println "openat Syscall Numbers by Architecture:")
  (println "---------------------------------------")
  (println "  x86_64:   257")
  (println "  arm64:    56  (generic syscall table)")
  (println "  riscv64:  56  (generic syscall table)")
  (println "  s390x:    288")
  (println "  ppc64le:  286")
  (println)

  (println "Current system openat syscall number:" (arch/get-syscall-nr :openat))
  (println)

  (println "AT_FDCWD Constant:")
  (println "------------------")
  (println "  Value:" syscall/AT_FDCWD)
  (println "  Purpose: Use current working directory for relative paths")
  (println "  When opening 'foo.txt', it's equivalent to './foo.txt'\n"))

;; ============================================================================
;; Section 5: Error Handling
;; ============================================================================

(defn demo-error-handling
  "Demonstrate error handling for file operations."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 5: ERROR HANDLING")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Example 1: File Not Found (ENOENT)")
  (println "----------------------------------")
  (try
    (syscall/file-open "/nonexistent/path/file.txt" syscall/O_RDONLY)
    (println "  ERROR: Should have thrown exception!")
    (catch clojure.lang.ExceptionInfo e
      (let [data (ex-data e)]
        (println "  Caught exception:" (.getMessage e))
        (println "  Error keyword:" (:error data))
        (println "  Errno value:" (:errno data))
        (println "  Path:" (:path data))
        (println))))

  (println "Example 2: Permission Denied (EACCES)")
  (println "-------------------------------------")
  (try
    (syscall/file-open "/etc/shadow" syscall/O_RDONLY)
    (println "  Opened /etc/shadow (running as root?)")
    (catch clojure.lang.ExceptionInfo e
      (let [data (ex-data e)]
        (println "  Caught exception:" (.getMessage e))
        (println "  Error keyword:" (:error data))
        (println "  (Expected when not running as root)\n"))))

  (println "Example 3: File Exists (EEXIST) with O_EXCL")
  (println "-------------------------------------------")
  (let [test-file "/tmp/clj-ebpf-demo-exists.txt"]
    ;; Create file first
    (let [fd (syscall/file-open test-file
                                (bit-or syscall/O_CREAT syscall/O_WRONLY)
                                0644)]
      (syscall/close-fd fd))
    (try
      (syscall/file-open test-file
                         (bit-or syscall/O_CREAT syscall/O_EXCL syscall/O_WRONLY)
                         0644)
      (println "  ERROR: Should have thrown exception!")
      (catch clojure.lang.ExceptionInfo e
        (let [data (ex-data e)]
          (println "  Caught exception:" (.getMessage e))
          (println "  Error keyword:" (:error data))
          (println "  O_EXCL prevents overwriting existing files"))))
    (.delete (File. test-file))))

;; ============================================================================
;; Section 6: Practical Use Cases
;; ============================================================================

(defn demo-use-cases
  "Demonstrate practical use cases for file-open."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 6: PRACTICAL USE CASES")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Use Case 1: Lock File Pattern")
  (println "-----------------------------")
  (let [lock-file "/tmp/clj-ebpf-demo.lock"]
    (println "  Creating exclusive lock file...")
    (try
      (let [fd (syscall/file-open lock-file
                                  (bit-or syscall/O_CREAT
                                          syscall/O_EXCL
                                          syscall/O_WRONLY)
                                  0644)]
        (println "  Lock acquired, fd =" fd)
        ;; Do work...
        (Thread/sleep 100)
        (syscall/close-fd fd)
        (.delete (File. lock-file))
        (println "  Lock released and file cleaned up\n"))
      (catch clojure.lang.ExceptionInfo e
        (println "  Lock already held by another process"))))

  (println "Use Case 2: Log File Append")
  (println "---------------------------")
  (let [log-file "/tmp/clj-ebpf-demo.log"]
    (let [fd (syscall/file-open log-file
                                (bit-or syscall/O_CREAT
                                        syscall/O_WRONLY
                                        syscall/O_APPEND)
                                0644)]
      (println "  Opened log file with O_APPEND")
      (println "  All writes go to end of file")
      (println "  fd =" fd)
      (syscall/close-fd fd)
      (.delete (File. log-file))
      (println "  Cleaned up\n")))

  (println "Use Case 3: Temp File with Close-on-Exec")
  (println "----------------------------------------")
  (let [tmp-file (str "/tmp/clj-ebpf-temp-" (System/currentTimeMillis) ".tmp")]
    (let [fd (syscall/file-open tmp-file
                                (bit-or syscall/O_CREAT
                                        syscall/O_RDWR
                                        syscall/O_CLOEXEC)
                                0600)]
      (println "  Created temp file with O_CLOEXEC")
      (println "  FD will be closed automatically on exec()")
      (println "  Permissions: 0600 (owner read/write only)")
      (println "  fd =" fd)
      (syscall/close-fd fd)
      (.delete (File. tmp-file))
      (println "  Cleaned up\n"))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all file operations demonstrations."
  [& _args]
  (println)
  (println "╔══════════════════════════════════════════════════════════════════════╗")
  (println "║               clj-ebpf File Operations Example                       ║")
  (println "║                                                                      ║")
  (println "║  Demonstrates the file-open function using openat syscall           ║")
  (println "║  via Java Panama FFI for low-level file access.                     ║")
  (println "╚══════════════════════════════════════════════════════════════════════╝")

  (demo-basic-open)
  (demo-create-file)
  (demo-flags)
  (demo-architecture)
  (demo-error-handling)
  (demo-use-cases)

  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Example complete!")
  (println (apply str (repeat 70 "=")) "\n"))
