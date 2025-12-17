(ns lab-5-4-pure-clojure-kprobe
  "Lab 5.4 Solution: Pure Clojure Kprobe

   This lab demonstrates building BPF kprobe programs entirely in Clojure
   using the high-level DSL, without external compilers."
  (:require [clojure.test :refer [deftest testing is]]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.kprobe :as kprobe]
            [clj-ebpf.dsl.structs :as structs]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Part 1: Event Structure Definition
;; ============================================================================

;; Task 1.1: Define ProcessExecEvent
(structs/defevent ProcessExecEvent
  [:timestamp :u64]    ; 8 bytes, offset 0
  [:pid :u32]          ; 4 bytes, offset 8
  [:tgid :u32]         ; 4 bytes, offset 12
  [:uid :u32]          ; 4 bytes, offset 16
  [:ppid :u32]         ; 4 bytes, offset 20
  [:comm :char 16])    ; 16 bytes, offset 24
;; Total: 40 bytes

;; Task 1.2: Query the structure
(defn verify-structure []
  (println "ProcessExecEvent structure:")
  (println "  Total size:" (structs/event-size ProcessExecEvent) "bytes")
  (println "  Fields:" (structs/event-fields ProcessExecEvent))
  (println)
  (println "Field offsets:")
  (doseq [field (structs/event-fields ProcessExecEvent)]
    (printf "  %-12s offset=%2d size=%2d type=%s\n"
            (name field)
            (structs/event-field-offset ProcessExecEvent field)
            (structs/event-field-size ProcessExecEvent field)
            (name (structs/event-field-type ProcessExecEvent field)))))

;; ============================================================================
;; Part 2: Building the Kprobe Program
;; ============================================================================

;; Task 2.1: Create the prologue
(defn build-exec-tracer-prologue []
  ;; Save pt_regs to r9, read arg1 (filename) into r7
  (kprobe/kprobe-prologue :r9 [:r7]))

;; Task 2.2: Build the complete program
(defn build-exec-tracer
  "Build a kprobe program that traces execve calls.

   Parameters:
   - ringbuf-fd: File descriptor of the ring buffer map

   Returns: Assembled BPF bytecode"
  [ringbuf-fd]
  (let [event-size (structs/event-size ProcessExecEvent)]
    (dsl/assemble
     (vec (concat
           ;; === Prologue ===
           ;; Read filename (arg1) into r7, save pt_regs to r9
           (kprobe/kprobe-prologue :r9 [:r7])

           ;; === Get Timestamp ===
           (dsl/helper-ktime-get-ns)
           [(dsl/mov-reg :r8 :r0)]  ; Save timestamp in r8

           ;; === Get PID/TGID ===
           (dsl/helper-get-current-pid-tgid)
           ;; r0 = (tgid << 32) | pid
           ;; Store on stack for later extraction
           [(dsl/stx :dw :r10 :r0 -8)]

           ;; === Get UID/GID ===
           (dsl/helper-get-current-uid-gid)
           ;; r0 = (gid << 32) | uid
           [(dsl/stx :dw :r10 :r0 -16)]

           ;; === Reserve Ring Buffer Space ===
           (dsl/ringbuf-reserve :r6 ringbuf-fd event-size)

           ;; Check for NULL (reservation failed)
           ;; Jump forward 16 instructions to exit if r6 == 0
           [(dsl/jmp-imm :jeq :r6 0 16)]

           ;; === Fill Event Structure ===

           ;; Store timestamp (r8 contains timestamp)
           [(structs/store-event-field :r6 ProcessExecEvent :timestamp :r8)]

           ;; Extract and store PID (lower 32 bits of pid_tgid)
           [(dsl/ldx :dw :r1 :r10 -8)     ; Load pid_tgid from stack
            (dsl/mov-reg :r2 :r1)          ; Copy to r2
            (dsl/and-imm :r2 0xffffffff)   ; Mask lower 32 bits = PID
            (structs/store-event-field :r6 ProcessExecEvent :pid :r2)]

           ;; Extract and store TGID (upper 32 bits)
           [(dsl/rsh :r1 32)               ; Shift right by 32
            (structs/store-event-field :r6 ProcessExecEvent :tgid :r1)]

           ;; Extract and store UID (lower 32 bits of uid_gid)
           [(dsl/ldx :dw :r1 :r10 -16)    ; Load uid_gid from stack
            (dsl/mov-reg :r2 :r1)
            (dsl/and-imm :r2 0xffffffff)   ; Mask lower 32 bits = UID
            (structs/store-event-field :r6 ProcessExecEvent :uid :r2)]

           ;; Store ppid as 0 for now (would need task_struct access)
           [(structs/store-event-imm :r6 ProcessExecEvent :ppid 0)]

           ;; === Submit Event ===
           (dsl/ringbuf-submit :r6)

           ;; === Exit ===
           [(dsl/mov :r0 0)
            (dsl/exit-insn)])))))

;; ============================================================================
;; Part 3: Using defkprobe-instructions Macro
;; ============================================================================

;; Task 3.1: Refactor using the macro
(kprobe/defkprobe-instructions exec-entry-handler
  {:function "do_execveat_common"
   :args [:r7]}  ; filename in r7
  ;; Body - prologue is automatically generated
  (concat
   ;; Get timestamp
   (dsl/helper-ktime-get-ns)
   [(dsl/mov-reg :r8 :r0)]

   ;; Get PID
   (dsl/helper-get-current-pid-tgid)
   [(dsl/mov-reg :r7 :r0)]

   ;; Return success
   [(dsl/mov :r0 0)
    (dsl/exit-insn)]))

;; Task 3.2: Create kretprobe handler
(kprobe/defkretprobe-instructions exec-return-handler
  {:function "do_execveat_common"
   :ret-reg :r6}  ; Return value in r6
  (concat
   ;; Check if return value indicates error (< 0)
   ;; jsge = jump if signed greater or equal
   [(dsl/jsge-imm :r6 0 2)]  ; Skip next 2 insns if r6 >= 0

   ;; Error path - could increment error counter here
   ;; For now, just continue to exit

   ;; Success path and exit
   [(dsl/mov :r0 0)
    (dsl/exit-insn)]))

;; ============================================================================
;; Part 4: Integration Helpers
;; ============================================================================

(defn extract-u64
  "Extract unsigned 64-bit value from byte array at offset."
  [data offset]
  (utils/bytes->long (byte-array (take 8 (drop offset data)))))

(defn extract-u32
  "Extract unsigned 32-bit value from byte array at offset."
  [data offset]
  (utils/bytes->int (byte-array (take 4 (drop offset data)))))

(defn extract-string
  "Extract null-terminated string from byte array."
  [data offset max-len]
  (let [bytes (take max-len (drop offset data))
        end (or (some identity (map-indexed
                                (fn [i b] (when (zero? b) i))
                                bytes))
                max-len)]
    (String. (byte-array (take end bytes)) "UTF-8")))

(defn parse-exec-event
  "Parse a ProcessExecEvent from raw bytes."
  [data]
  (when (>= (count data) (structs/event-size ProcessExecEvent))
    {:timestamp (extract-u64 data (structs/event-field-offset ProcessExecEvent :timestamp))
     :pid (extract-u32 data (structs/event-field-offset ProcessExecEvent :pid))
     :tgid (extract-u32 data (structs/event-field-offset ProcessExecEvent :tgid))
     :uid (extract-u32 data (structs/event-field-offset ProcessExecEvent :uid))
     :ppid (extract-u32 data (structs/event-field-offset ProcessExecEvent :ppid))
     :comm (extract-string data
                          (structs/event-field-offset ProcessExecEvent :comm)
                          (structs/event-field-size ProcessExecEvent :comm))}))

(defn format-exec-event
  "Format event for display."
  [event]
  (format "[%d] pid=%d tgid=%d uid=%d ppid=%d comm=%s"
          (:timestamp event)
          (:pid event)
          (:tgid event)
          (:uid event)
          (:ppid event)
          (:comm event)))

;; ============================================================================
;; Tests
;; ============================================================================

(deftest test-event-structure
  (testing "ProcessExecEvent has correct size"
    (is (= 40 (structs/event-size ProcessExecEvent))))

  (testing "ProcessExecEvent has correct field offsets"
    (is (= 0 (structs/event-field-offset ProcessExecEvent :timestamp)))
    (is (= 8 (structs/event-field-offset ProcessExecEvent :pid)))
    (is (= 12 (structs/event-field-offset ProcessExecEvent :tgid)))
    (is (= 16 (structs/event-field-offset ProcessExecEvent :uid)))
    (is (= 20 (structs/event-field-offset ProcessExecEvent :ppid)))
    (is (= 24 (structs/event-field-offset ProcessExecEvent :comm))))

  (testing "ProcessExecEvent has correct field types"
    (is (= :u64 (structs/event-field-type ProcessExecEvent :timestamp)))
    (is (= :u32 (structs/event-field-type ProcessExecEvent :pid)))
    (is (= :char (structs/event-field-type ProcessExecEvent :comm))))

  (testing "ProcessExecEvent field list is correct"
    (is (= [:timestamp :pid :tgid :uid :ppid :comm]
           (structs/event-fields ProcessExecEvent)))))

(deftest test-kprobe-prologue
  (testing "kprobe-prologue generates correct instruction count"
    ;; With context save: 1 mov + N ldx
    (let [prologue (kprobe/kprobe-prologue :r9 [:r7])]
      (is (= 2 (count prologue))))

    ;; Without context save: just N ldx
    (let [prologue (kprobe/kprobe-prologue [:r6 :r7 :r8])]
      (is (= 3 (count prologue)))))

  (testing "kprobe-prologue works on current architecture"
    (is (keyword? arch/current-arch))
    (is (number? (arch/get-kprobe-arg-offset 0)))))

(deftest test-program-building
  (testing "build-exec-tracer produces valid bytecode"
    (let [prog (build-exec-tracer 5)]  ; dummy fd
      (is (bytes? prog))
      (is (pos? (count prog)))
      (is (zero? (mod (count prog) 8)))))  ; Multiple of 8 bytes

  (testing "exec-entry-handler produces instructions"
    (let [insns (exec-entry-handler)]
      (is (vector? insns))
      (is (pos? (count insns)))))

  (testing "exec-return-handler produces instructions"
    (let [insns (exec-return-handler)]
      (is (vector? insns))
      (is (pos? (count insns))))))

(deftest test-event-parsing
  (testing "parse-exec-event handles valid data"
    ;; Create test data matching ProcessExecEvent layout
    (let [test-data (byte-array 40)
          ;; Set timestamp (8 bytes at offset 0)
          _ (System/arraycopy (utils/long->bytes 1234567890) 0 test-data 0 8)
          ;; Set pid (4 bytes at offset 8)
          _ (System/arraycopy (utils/int->bytes 1234) 0 test-data 8 4)
          ;; Set tgid (4 bytes at offset 12)
          _ (System/arraycopy (utils/int->bytes 1234) 0 test-data 12 4)
          ;; Set uid (4 bytes at offset 16)
          _ (System/arraycopy (utils/int->bytes 1000) 0 test-data 16 4)
          ;; Set ppid (4 bytes at offset 20)
          _ (System/arraycopy (utils/int->bytes 1) 0 test-data 20 4)
          ;; Set comm (16 bytes at offset 24)
          _ (System/arraycopy (.getBytes "test") 0 test-data 24 4)

          event (parse-exec-event test-data)]

      (is (some? event))
      (is (= 1234567890 (:timestamp event)))
      (is (= 1234 (:pid event)))
      (is (= 1000 (:uid event)))
      (is (= "test" (:comm event)))))

  (testing "parse-exec-event returns nil for short data"
    (is (nil? (parse-exec-event (byte-array 10))))))

(deftest test-store-instructions
  (testing "store-event-field generates correct instruction"
    (let [insn (structs/store-event-field :r6 ProcessExecEvent :pid :r7)]
      (is (some? insn))
      (is (= 8 (:offset insn)))))  ; pid is at offset 8

  (testing "store-event-imm generates correct instruction"
    (let [insn (structs/store-event-imm :r6 ProcessExecEvent :uid 1000)]
      (is (some? insn))
      (is (= 1000 (:imm insn))))))

;; ============================================================================
;; Demo Runner
;; ============================================================================

(defn run-demo []
  (println "Lab 5.4: Pure Clojure Kprobe")
  (println "============================\n")

  ;; Part 1: Structure verification
  (println "Part 1: Event Structure")
  (verify-structure)
  (println)

  ;; Part 2: Program building
  (println "Part 2: Program Building")
  (println "Architecture:" arch/arch-name)
  (println "Arg0 offset:" (arch/get-kprobe-arg-offset 0))
  (let [prog (build-exec-tracer 5)]
    (println "Program size:" (count prog) "bytes")
    (println "Instructions:" (/ (count prog) 8)))
  (println)

  ;; Part 3: Macro usage
  (println "Part 3: Macro-defined Handlers")
  (println "exec-entry-handler instructions:" (count (exec-entry-handler)))
  (println "exec-return-handler instructions:" (count (exec-return-handler)))
  (println)

  (println "All demonstrations complete!"))

(defn -main [& args]
  (run-demo))

;; Run tests
(comment
  (clojure.test/run-tests 'lab-5-4-pure-clojure-kprobe)
  (run-demo)
  )
