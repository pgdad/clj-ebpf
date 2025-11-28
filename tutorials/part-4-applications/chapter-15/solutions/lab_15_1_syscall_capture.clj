(ns lab-15-1-syscall-capture
  "Lab 15.1: Syscall Event Capture

   This solution demonstrates:
   - Capturing syscall entry and exit events
   - Correlating events by thread ID
   - Calculating syscall duration
   - Formatting events for display

   Run with: clojure -M -m lab-15-1-syscall-capture test"
  (:require [clojure.string :as str])
  (:import [java.time Instant LocalDateTime ZoneId]
           [java.time.format DateTimeFormatter]))

;;; ============================================================================
;;; Part 1: Syscall Name Database
;;; ============================================================================

(def syscall-names
  "Common Linux x86_64 syscall numbers to names"
  {0   "read"
   1   "write"
   2   "open"
   3   "close"
   4   "stat"
   5   "fstat"
   6   "lstat"
   7   "poll"
   8   "lseek"
   9   "mmap"
   10  "mprotect"
   11  "munmap"
   12  "brk"
   13  "rt_sigaction"
   14  "rt_sigprocmask"
   15  "rt_sigreturn"
   16  "ioctl"
   17  "pread64"
   18  "pwrite64"
   19  "readv"
   20  "writev"
   21  "access"
   22  "pipe"
   23  "select"
   24  "sched_yield"
   25  "mremap"
   32  "dup"
   33  "dup2"
   35  "nanosleep"
   39  "getpid"
   41  "socket"
   42  "connect"
   43  "accept"
   44  "sendto"
   45  "recvfrom"
   46  "sendmsg"
   47  "recvmsg"
   48  "shutdown"
   49  "bind"
   50  "listen"
   56  "clone"
   57  "fork"
   58  "vfork"
   59  "execve"
   60  "exit"
   61  "wait4"
   62  "kill"
   72  "fcntl"
   78  "getdents"
   79  "getcwd"
   80  "chdir"
   82  "rename"
   83  "mkdir"
   84  "rmdir"
   85  "creat"
   86  "link"
   87  "unlink"
   88  "symlink"
   89  "readlink"
   90  "chmod"
   91  "fchmod"
   92  "chown"
   93  "fchown"
   95  "umask"
   96  "gettimeofday"
   102 "getuid"
   104 "getgid"
   105 "setuid"
   106 "setgid"
   107 "geteuid"
   108 "getegid"
   110 "getppid"
   111 "getpgrp"
   186 "gettid"
   217 "getdents64"
   231 "exit_group"
   257 "openat"
   262 "newfstatat"
   263 "unlinkat"
   288 "accept4"
   293 "pipe2"})

(defn syscall-name
  "Get syscall name from number"
  [nr]
  (get syscall-names nr (format "syscall_%d" nr)))

;;; ============================================================================
;;; Part 2: Syscall Entry Event
;;; ============================================================================

(defrecord SyscallEntry
  [pid tid uid syscall-nr args timestamp-ns comm])

(defn create-entry
  "Create a syscall entry event"
  [pid tid uid syscall-nr args comm]
  (->SyscallEntry pid tid uid syscall-nr args (System/nanoTime) comm))

(defn entry->map
  "Convert entry record to map"
  [entry]
  {:pid (:pid entry)
   :tid (:tid entry)
   :uid (:uid entry)
   :syscall-nr (:syscall-nr entry)
   :syscall-name (syscall-name (:syscall-nr entry))
   :args (:args entry)
   :timestamp-ns (:timestamp-ns entry)
   :comm (:comm entry)})

;;; ============================================================================
;;; Part 3: Active Call Tracking
;;; ============================================================================

(def active-calls
  "Track active syscalls by thread ID"
  (atom {}))

(defn track-entry!
  "Record syscall entry for later correlation"
  [entry]
  (swap! active-calls assoc (:tid entry) entry))

(defn lookup-entry
  "Look up entry for a given thread ID"
  [tid]
  (get @active-calls tid))

(defn remove-entry!
  "Remove entry after exit"
  [tid]
  (swap! active-calls dissoc tid))

(defn clear-active-calls!
  "Clear all active calls"
  []
  (reset! active-calls {}))

;;; ============================================================================
;;; Part 4: Syscall Exit and Complete Event
;;; ============================================================================

(defrecord SyscallEvent
  [pid tid uid syscall-nr syscall-name args ret duration-ns timestamp-ns comm error?])

(defn complete-syscall
  "Complete a syscall by correlating entry with exit"
  [tid ret]
  (when-let [entry (lookup-entry tid)]
    (let [exit-time (System/nanoTime)
          duration (- exit-time (:timestamp-ns entry))]
      (remove-entry! tid)
      (->SyscallEvent
        (:pid entry)
        (:tid entry)
        (:uid entry)
        (:syscall-nr entry)
        (syscall-name (:syscall-nr entry))
        (:args entry)
        ret
        duration
        exit-time
        (:comm entry)
        (neg? ret)))))

;;; ============================================================================
;;; Part 5: Event Formatting
;;; ============================================================================

(def time-formatter
  (DateTimeFormatter/ofPattern "HH:mm:ss.SSS"))

(defn format-timestamp
  "Format timestamp for display"
  [timestamp-ns]
  (let [instant (Instant/ofEpochSecond 0 timestamp-ns)
        local-time (LocalDateTime/ofInstant instant (ZoneId/systemDefault))]
    (.format local-time time-formatter)))

(defn format-duration
  "Format duration in microseconds"
  [duration-ns]
  (let [us (/ duration-ns 1000.0)]
    (cond
      (< us 1) (format "%.0f ns" (double duration-ns))
      (< us 1000) (format "%.1f μs" us)
      (< us 1000000) (format "%.2f ms" (/ us 1000))
      :else (format "%.2f s" (/ us 1000000)))))

(defn format-args
  "Format syscall arguments"
  [syscall-name args]
  (let [arg-strs (map #(if (neg? %)
                         (format "%d" %)
                         (format "0x%x" %))
                      args)]
    (str/join ", " (take 3 arg-strs))))

(defn format-return
  "Format return value"
  [ret error?]
  (if error?
    (format "%d (error)" ret)
    (format "%d" ret)))

(defn format-event-text
  "Format event for text display"
  [event]
  (format "%-12s %-6d %-16s %-15s %-30s %-10s %s"
          (format-timestamp (:timestamp-ns event))
          (:pid event)
          (:comm event)
          (:syscall-name event)
          (format-args (:syscall-name event) (:args event))
          (format-return (:ret event) (:error? event))
          (format-duration (:duration-ns event))))

(defn format-event-json
  "Format event as JSON"
  [event]
  (format "{\"timestamp\":%d,\"pid\":%d,\"comm\":\"%s\",\"syscall\":\"%s\",\"ret\":%d,\"duration_ns\":%d,\"error\":%s}"
          (:timestamp-ns event)
          (:pid event)
          (:comm event)
          (:syscall-name event)
          (:ret event)
          (:duration-ns event)
          (:error? event)))

(defn format-event-csv
  "Format event as CSV"
  [event]
  (format "%d,%d,%s,%s,%d,%d"
          (:timestamp-ns event)
          (:pid event)
          (:comm event)
          (:syscall-name event)
          (:ret event)
          (:duration-ns event)))

(defn format-event
  "Format event in specified format"
  [event format-type]
  (case format-type
    :text (format-event-text event)
    :json (format-event-json event)
    :csv (format-event-csv event)
    (format-event-text event)))

(defn print-header
  "Print column headers for text format"
  []
  (println (format "%-12s %-6s %-16s %-15s %-30s %-10s %s"
                   "TIME" "PID" "COMM" "SYSCALL" "ARGS" "RET" "DURATION"))
  (println (str/join "" (repeat 100 "─"))))

;;; ============================================================================
;;; Part 6: Event Processing Pipeline
;;; ============================================================================

(defn process-entry
  "Process a syscall entry event"
  [pid tid uid syscall-nr args comm]
  (let [entry (create-entry pid tid uid syscall-nr args comm)]
    (track-entry! entry)
    entry))

(defn process-exit
  "Process a syscall exit event"
  [tid ret]
  (complete-syscall tid ret))

(defn simulate-syscall
  "Simulate a complete syscall (for testing)"
  [pid comm syscall-nr args ret duration-ns]
  (let [tid pid  ; Simplify: use pid as tid
        uid 1000]
    (process-entry pid tid uid syscall-nr args comm)
    ;; Simulate duration
    (Thread/sleep (max 1 (/ duration-ns 1000000)))
    (process-exit tid ret)))

;;; ============================================================================
;;; Part 7: Event Collection
;;; ============================================================================

(def collected-events
  "Store collected events"
  (atom []))

(defn collect-event!
  "Add event to collection"
  [event]
  (when event
    (swap! collected-events conj event)))

(defn get-events
  "Get all collected events"
  []
  @collected-events)

(defn clear-events!
  "Clear collected events"
  []
  (reset! collected-events []))

;;; ============================================================================
;;; Part 8: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 15.1 Tests ===\n")

  ;; Test 1: Syscall name lookup
  (println "Test 1: Syscall Name Lookup")
  (assert (= "read" (syscall-name 0)) "read syscall")
  (assert (= "write" (syscall-name 1)) "write syscall")
  (assert (= "openat" (syscall-name 257)) "openat syscall")
  (assert (= "syscall_999" (syscall-name 999)) "unknown syscall")
  (println "  All syscall names resolve correctly")
  (println "  PASSED\n")

  ;; Test 2: Entry creation
  (println "Test 2: Entry Creation")
  (let [entry (create-entry 1234 1234 1000 0 [3 0x7fff0000 4096] "bash")]
    (assert (= 1234 (:pid entry)) "pid")
    (assert (= 0 (:syscall-nr entry)) "syscall-nr")
    (assert (pos? (:timestamp-ns entry)) "timestamp"))
  (println "  Entry created with correct fields")
  (println "  PASSED\n")

  ;; Test 3: Entry tracking
  (println "Test 3: Entry Tracking")
  (clear-active-calls!)
  (let [entry (create-entry 1234 5678 1000 1 [1 0x7fff1000 100] "test")]
    (track-entry! entry)
    (assert (= entry (lookup-entry 5678)) "lookup")
    (remove-entry! 5678)
    (assert (nil? (lookup-entry 5678)) "removed"))
  (println "  Entries tracked and removed correctly")
  (println "  PASSED\n")

  ;; Test 4: Syscall completion
  (println "Test 4: Syscall Completion")
  (clear-active-calls!)
  (let [_ (process-entry 1234 5678 1000 0 [3 0x7fff 4096] "bash")
        _ (Thread/sleep 10)
        event (process-exit 5678 100)]
    (assert (some? event) "event created")
    (assert (= 1234 (:pid event)) "pid preserved")
    (assert (= "read" (:syscall-name event)) "syscall name")
    (assert (= 100 (:ret event)) "return value")
    (assert (pos? (:duration-ns event)) "duration calculated")
    (assert (not (:error? event)) "not error"))
  (println "  Syscall completed with correct correlation")
  (println "  PASSED\n")

  ;; Test 5: Error detection
  (println "Test 5: Error Detection")
  (clear-active-calls!)
  (let [_ (process-entry 1234 5678 1000 2 [0x7fff 0 0] "test")
        event (process-exit 5678 -2)]  ; ENOENT
    (assert (:error? event) "error detected")
    (assert (= -2 (:ret event)) "error code"))
  (println "  Negative return values detected as errors")
  (println "  PASSED\n")

  ;; Test 6: Duration formatting
  (println "Test 6: Duration Formatting")
  (assert (str/includes? (format-duration 500) "ns") "nanoseconds")
  (assert (str/includes? (format-duration 5000) "μs") "microseconds")
  (assert (str/includes? (format-duration 5000000) "ms") "milliseconds")
  (assert (str/includes? (format-duration 5000000000) "s") "seconds")
  (println "  Durations formatted correctly")
  (println "  PASSED\n")

  ;; Test 7: Event formatting
  (println "Test 7: Event Formatting")
  (let [event (->SyscallEvent 1234 1234 1000 0 "read" [3 0x7fff 4096]
                              100 50000 (System/nanoTime) "bash" false)]
    (let [text (format-event event :text)]
      (assert (str/includes? text "1234") "pid in text")
      (assert (str/includes? text "bash") "comm in text")
      (assert (str/includes? text "read") "syscall in text"))
    (let [json (format-event event :json)]
      (assert (str/includes? json "\"pid\":1234") "pid in json")
      (assert (str/includes? json "\"syscall\":\"read\"") "syscall in json"))
    (let [csv (format-event event :csv)]
      (assert (str/includes? csv "1234") "pid in csv")
      (assert (str/includes? csv "bash") "comm in csv")))
  (println "  Events formatted in all formats")
  (println "  PASSED\n")

  ;; Test 8: Multiple concurrent syscalls
  (println "Test 8: Multiple Concurrent Syscalls")
  (clear-active-calls!)
  (process-entry 1000 1001 1000 0 [3] "proc1")
  (process-entry 2000 2001 1000 1 [1] "proc2")
  (process-entry 3000 3001 1000 2 [0] "proc3")
  (assert (= 3 (count @active-calls)) "three active")
  (let [e1 (process-exit 1001 100)
        e2 (process-exit 2001 50)
        e3 (process-exit 3001 3)]
    (assert (= "read" (:syscall-name e1)) "first syscall")
    (assert (= "write" (:syscall-name e2)) "second syscall")
    (assert (= "open" (:syscall-name e3)) "third syscall")
    (assert (= 0 (count @active-calls)) "all completed"))
  (println "  Concurrent syscalls handled correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 9: Demo
;;; ============================================================================

(defn run-demo
  "Run demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 15.1: Syscall Event Capture")
  (println (str/join "" (repeat 60 "=")) "\n")

  (clear-active-calls!)
  (clear-events!)

  ;; Simulate some syscalls
  (println "=== Simulating Syscall Events ===\n")
  (print-header)

  (let [syscalls [{:pid 1234 :comm "bash" :nr 257 :args [-100 0x7fff 0] :ret 3 :dur 45000}
                  {:pid 1234 :comm "bash" :nr 0 :args [3 0x7fff 4096] :ret 1024 :dur 12000}
                  {:pid 1234 :comm "bash" :nr 3 :args [3] :ret 0 :dur 5000}
                  {:pid 5678 :comm "curl" :nr 41 :args [2 1 6] :ret 4 :dur 15000}
                  {:pid 5678 :comm "curl" :nr 42 :args [4 0x7fff 16] :ret 0 :dur 1250000}
                  {:pid 5678 :comm "curl" :nr 0 :args [4 0x7fff 8192] :ret -11 :dur 100000}]]

    (doseq [sc syscalls]
      (process-entry (:pid sc) (:pid sc) 1000 (:nr sc) (:args sc) (:comm sc))
      (Thread/sleep (max 1 (/ (:dur sc) 1000000)))
      (when-let [event (process-exit (:pid sc) (:ret sc))]
        (collect-event! event)
        (println (format-event event :text)))))

  (println)

  ;; Show JSON format
  (println "=== JSON Output ===\n")
  (doseq [event (take 2 (get-events))]
    (println (format-event event :json)))

  (println)

  ;; Show CSV format
  (println "=== CSV Output ===\n")
  (println "timestamp,pid,comm,syscall,ret,duration_ns")
  (doseq [event (take 2 (get-events))]
    (println (format-event event :csv)))

  (println)

  ;; Summary
  (let [events (get-events)
        errors (filter :error? events)]
    (println "=== Summary ===\n")
    (println (format "Total syscalls captured: %d" (count events)))
    (println (format "Errors detected: %d" (count errors)))
    (println (format "Active (incomplete) calls: %d" (count @active-calls)))))

;;; ============================================================================
;;; Part 10: Main
;;; ============================================================================

(defn -main [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      (do
        (println "Usage: clojure -M -m lab-15-1-syscall-capture <command>")
        (println "Commands:")
        (println "  test  - Run tests")
        (println "  demo  - Run demonstration")))))
