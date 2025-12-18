(ns uprobe-dsl
  "Uprobe DSL Example

   This example demonstrates using the high-level Uprobe DSL to build
   BPF programs that trace userspace functions.

   Uprobes allow tracing:
   - Functions in executables
   - Functions in shared libraries (libc, libssl, etc.)
   - Language runtime functions (Python, Ruby, JVM)

   Common use cases:
   - Memory allocation tracing (malloc/free)
   - SSL/TLS inspection (SSL_read/SSL_write)
   - Database query tracing
   - Application profiling

   Usage:
     clojure -M:examples -m uprobe-dsl"
  (:require [clj-ebpf.dsl.uprobe :as up]
            [clj-ebpf.dsl.structs :as structs]
            [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Event Structure Definitions
;; ============================================================================

;; Define event structure for malloc tracing
(structs/defevent MallocEvent
  [:timestamp :u64]     ; 8 bytes, offset 0
  [:pid :u32]           ; 4 bytes, offset 8
  [:tid :u32]           ; 4 bytes, offset 12
  [:size :u64]          ; 8 bytes, offset 16 (malloc size argument)
  [:ptr :u64])          ; 8 bytes, offset 24 (returned pointer, filled by uretprobe)
;; Total: 32 bytes

;; Define event structure for SSL tracing
(structs/defevent SslEvent
  [:timestamp :u64]     ; 8 bytes, offset 0
  [:pid :u32]           ; 4 bytes, offset 8
  [:len :u32]           ; 4 bytes, offset 12 (data length)
  [:ssl_ptr :u64])      ; 8 bytes, offset 16 (SSL connection pointer)
;; Total: 24 bytes

;; ============================================================================
;; Example 1: Library Path Discovery
;; ============================================================================

(defn demo-library-discovery
  "Demonstrate library path discovery."
  []
  (println "\n=== Library Path Discovery ===\n")

  ;; Show common library paths
  (println "Common library search paths:")
  (doseq [path up/common-library-paths]
    (println "  " path))

  ;; Try to find libc
  (println "\nSearching for libc...")
  (if-let [libc-path (up/find-libc)]
    (println "  Found:" libc-path)
    (println "  Not found (normal in CI environment)"))

  ;; Try to find a library by name
  (println "\nSearching for libpthread...")
  (if-let [pthread-path (up/find-library "libpthread")]
    (println "  Found:" pthread-path)
    (println "  Not found")))

;; ============================================================================
;; Example 2: Common Functions to Trace
;; ============================================================================

(defn demo-common-functions
  "Show common functions useful for uprobe tracing."
  []
  (println "\n=== Common Functions to Trace ===\n")

  (println "Memory functions:")
  (doseq [func (:memory up/common-libc-functions)]
    (println "  " func))

  (println "\nFile I/O functions:")
  (doseq [func (:file-io up/common-libc-functions)]
    (println "  " func))

  (println "\nProcess functions:")
  (doseq [func (:process up/common-libc-functions)]
    (println "  " func))

  (println "\nNetwork functions:")
  (doseq [func (:network up/common-libc-functions)]
    (println "  " func))

  (println "\nOpenSSL functions:")
  (doseq [func (:openssl up/common-crypto-functions)]
    (println "  " func)))

;; ============================================================================
;; Example 3: Symbol Resolution
;; ============================================================================

(defn demo-symbol-resolution
  "Demonstrate symbol resolution from ELF binaries."
  []
  (println "\n=== Symbol Resolution ===\n")

  ;; Try to resolve malloc in libc (if available)
  (if-let [libc-path (up/find-libc)]
    (do
      (println "Resolving symbols in:" libc-path)

      ;; Resolve malloc
      (if-let [malloc-offset (up/resolve-symbol-offset libc-path "malloc")]
        (printf "  malloc offset: 0x%x\n" malloc-offset)
        (println "  malloc: not found"))

      ;; Get detailed info about free
      (if-let [free-info (up/get-symbol-info libc-path "free")]
        (do
          (println "  free info:")
          (printf "    offset: 0x%x\n" (:offset free-info))
          (printf "    size: %d bytes\n" (:size free-info))
          (printf "    type: %s\n" (name (:type free-info))))
        (println "  free: not found"))

      ;; List some function symbols
      (println "\n  First 10 function symbols:")
      (let [funcs (take 10 (up/list-symbols libc-path))]
        (doseq [f funcs]
          (printf "    %-30s 0x%x\n" (:name f) (:value f)))))

    (println "libc not found - skipping symbol resolution demo")))

;; ============================================================================
;; Example 4: Uprobe Prologue Generation
;; ============================================================================

(defn demo-prologue-generation
  "Demonstrate generating uprobe prologue instructions."
  []
  (println "\n=== Uprobe Prologue Generation ===\n")

  ;; Generate prologue with context save and 2 arguments
  (let [prologue (up/uprobe-prologue :r9 [:r6 :r7])]
    (println "Prologue with context save (r9) and 2 args (r6, r7):")
    (println "  Instructions:" (count prologue))
    (println "  Total bytes:" (* 8 (count prologue))))

  ;; Generate prologue without context save
  (let [prologue (up/uprobe-prologue [:r6 :r7 :r8])]
    (println "\nPrologue with 3 args (r6, r7, r8) no context save:")
    (println "  Instructions:" (count prologue))
    (println "  Total bytes:" (* 8 (count prologue))))

  ;; Generate return value extraction
  (println "\nUretprobe return value extraction:")
  (let [insn (up/uretprobe-get-return-value :r1 :r6)]
    (println "  Instruction bytes:" (count insn))
    (println "  Loads return value from pt_regs into r6")))

;; ============================================================================
;; Example 5: Using defuprobe-instructions Macro
;; ============================================================================

;; Define a malloc uprobe handler
(up/defuprobe-instructions malloc-probe
  {:binary "/lib/x86_64-linux-gnu/libc.so.6"
   :function "malloc"
   :args [:r6]           ; size argument in r6
   :ctx-reg :r9}
  ;; Body: get PID and exit
  (concat
   (dsl/helper-get-current-pid-tgid)
   [(dsl/mov-reg :r7 :r0)   ; r7 = pid_tgid
    (dsl/mov :r0 0)
    (dsl/exit-insn)]))

;; Define a malloc return probe handler
(up/defuretprobe-instructions malloc-ret-probe
  {:binary "/lib/x86_64-linux-gnu/libc.so.6"
   :function "malloc"
   :ret-reg :r6           ; returned pointer in r6
   :ctx-reg :r9}
  ;; Body: check for NULL and exit
  [(dsl/jmp-imm :jeq :r6 0 2)  ; Skip if NULL
   ;; Non-NULL handling would go here
   (dsl/mov :r0 0)
   (dsl/exit-insn)])

(defn demo-macro-usage
  "Demonstrate using defuprobe-instructions macro."
  []
  (println "\n=== defuprobe-instructions Macro ===\n")

  ;; Use the macro-defined handler
  (let [insns (malloc-probe)]
    (println "malloc-probe:")
    (println "  Function defined: yes")
    (println "  Instruction count:" (count insns))
    (println "  All bytes:" (every? bytes? insns)))

  (println)

  (let [insns (malloc-ret-probe)]
    (println "malloc-ret-probe:")
    (println "  Instruction count:" (count insns))
    (println "  Includes context save + return value load + exit")))

;; ============================================================================
;; Example 6: Program Building
;; ============================================================================

(defn demo-program-building
  "Demonstrate building complete uprobe programs."
  []
  (println "\n=== Program Building ===\n")

  ;; Build uprobe program
  (let [prog (up/build-uprobe-program
              {:args [:r6 :r7]     ; Two arguments
               :ctx-reg :r9
               :body [(dsl/mov-reg :r8 :r6)]  ; Copy arg0 to r8
               :return-value 0})]
    (println "Built uprobe program:")
    (println "  Bytecode size:" (count prog) "bytes")
    (println "  Instructions:" (/ (count prog) 8)))

  ;; Build uretprobe program
  (let [prog (up/build-uretprobe-program
              {:ret-reg :r6        ; Return value in r6
               :ctx-reg :r9
               :body [(dsl/mov-reg :r7 :r6)]  ; Copy retval to r7
               :return-value 0})]
    (println "\nBuilt uretprobe program:")
    (println "  Bytecode size:" (count prog) "bytes")
    (println "  Instructions:" (/ (count prog) 8))))

;; ============================================================================
;; Example 7: Section Names
;; ============================================================================

(defn demo-section-names
  "Demonstrate section name generation for uprobe programs."
  []
  (println "\n=== Section Names ===\n")

  (println "Uprobe section names:")
  (println "  " (up/uprobe-section-name "/lib/x86_64-linux-gnu/libc.so.6" "malloc"))
  (println "  " (up/uprobe-section-name "/usr/bin/python3" "PyObject_Call"))
  (println "  " (up/uprobe-section-name "/lib/libssl.so.3" "SSL_read"))

  (println "\nUretprobe section names:")
  (println "  " (up/uretprobe-section-name "/lib/x86_64-linux-gnu/libc.so.6" "malloc"))
  (println "  " (up/uretprobe-section-name "/usr/bin/myapp" "main")))

;; ============================================================================
;; Example 8: Program Metadata
;; ============================================================================

(defn demo-program-metadata
  "Demonstrate creating program metadata for loading."
  []
  (println "\n=== Program Metadata ===\n")

  ;; Create uprobe program info
  (let [insns (malloc-probe)
        info (up/make-uprobe-program-info
              "/lib/x86_64-linux-gnu/libc.so.6"
              "malloc"
              0x9d850  ; Example offset
              "malloc_tracer"
              insns)]
    (println "Uprobe Program Info:")
    (println "  Name:" (:name info))
    (println "  Section:" (:section info))
    (println "  Type:" (:type info))
    (println "  Binary:" (:binary info))
    (println "  Function:" (:function info))
    (printf "  Offset: 0x%x\n" (:offset info)))

  (println)

  ;; Create uretprobe program info
  (let [insns (malloc-ret-probe)
        info (up/make-uretprobe-program-info
              "/lib/x86_64-linux-gnu/libc.so.6"
              "malloc"
              0x9d850
              "malloc_ret_tracer"
              insns)]
    (println "Uretprobe Program Info:")
    (println "  Name:" (:name info))
    (println "  Section:" (:section info))
    (println "  Type:" (:type info))))

;; ============================================================================
;; Example 9: Attachment Info
;; ============================================================================

(defn demo-attachment-info
  "Demonstrate creating attachment information for uprobes."
  []
  (println "\n=== Attachment Info ===\n")

  ;; Uprobe with numeric offset
  (let [info (up/uprobe-attach-info "/lib/libc.so.6" 0x9d850)]
    (println "Uprobe with numeric offset:")
    (println "  Binary:" (:binary info))
    (printf "  Offset: 0x%x\n" (:offset info))
    (println "  Type:" (:type info)))

  (println)

  ;; Uretprobe with PID filter
  (let [info (up/uretprobe-attach-info "/lib/libc.so.6" 0x9d850 :pid 1234)]
    (println "Uretprobe with PID filter:")
    (println "  Binary:" (:binary info))
    (printf "  Offset: 0x%x\n" (:offset info))
    (println "  Type:" (:type info))
    (println "  PID:" (:pid info))))

;; ============================================================================
;; Example 10: Complete Malloc Tracer with Ring Buffer
;; ============================================================================

(defn build-malloc-tracer
  "Build a complete malloc tracer program.

   This shows how to:
   1. Capture the size argument on entry
   2. Get process info (PID/TID)
   3. Submit event to ring buffer

   Note: Returns bytecode, actual loading requires BPF privileges."
  [ringbuf-fd]
  (let [event-size (structs/event-size MallocEvent)]
    (dsl/assemble
     (vec (concat
           ;; Prologue: save context, load size argument
           (up/uprobe-prologue :r9 [:r6])  ; r6 = size argument

           ;; Get timestamp
           (dsl/helper-ktime-get-ns)
           [(dsl/mov-reg :r7 :r0)]  ; r7 = timestamp

           ;; Get PID/TGID
           (dsl/helper-get-current-pid-tgid)
           [(dsl/mov-reg :r8 :r0)]  ; r8 = pid_tgid

           ;; Reserve ring buffer space
           (dsl/ringbuf-reserve :r5 ringbuf-fd event-size)

           ;; Check for NULL
           [(dsl/jmp-imm :jeq :r5 0 10)]  ; Jump to exit if r5 == 0

           ;; Fill event structure
           [(structs/store-event-field :r5 MallocEvent :timestamp :r7)]

           ;; Extract and store PID (lower 32 bits of pid_tgid)
           [(dsl/mov-reg :r0 :r8)
            (dsl/and :r0 0xffffffff)
            (structs/store-event-field :r5 MallocEvent :pid :r0)]

           ;; Extract and store TID (upper 32 bits of pid_tgid)
           [(dsl/mov-reg :r0 :r8)
            (dsl/rsh :r0 32)
            (structs/store-event-field :r5 MallocEvent :tid :r0)]

           ;; Store size
           [(structs/store-event-field :r5 MallocEvent :size :r6)]

           ;; ptr will be filled by uretprobe, set to 0 for now
           [(dsl/mov :r0 0)
            (structs/store-event-field :r5 MallocEvent :ptr :r0)]

           ;; Submit to ring buffer
           (dsl/ringbuf-submit :r5)

           ;; Exit successfully
           [(dsl/mov :r0 0)
            (dsl/exit-insn)])))))

(defn demo-complete-tracer
  "Demonstrate building a complete tracer program."
  []
  (println "\n=== Complete Malloc Tracer ===\n")

  (let [bytecode (build-malloc-tracer 5)]  ; dummy fd
    (println "Built complete malloc tracer:")
    (println "  Event structure size:" (structs/event-size MallocEvent) "bytes")
    (println "  Program bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))
    (println)
    (println "Event fields:")
    (doseq [field (structs/event-fields MallocEvent)]
      (printf "  %-12s offset=%-2d size=%-2d\n"
              (name field)
              (structs/event-field-offset MallocEvent field)
              (structs/event-field-size MallocEvent field)))))

;; ============================================================================
;; Example 11: Assembly of Macro-Defined Programs
;; ============================================================================

(defn demo-program-assembly
  "Demonstrate assembling complete uprobe programs."
  []
  (println "\n=== Program Assembly ===\n")

  ;; Assemble the macro-defined malloc probe
  (let [bytecode (dsl/assemble (malloc-probe))]
    (println "Assembled malloc-probe:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8)))

  ;; Assemble the macro-defined malloc return probe
  (let [bytecode (dsl/assemble (malloc-ret-probe))]
    (println "\nAssembled malloc-ret-probe:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all uprobe DSL demonstrations."
  [& args]
  (println "==============================================")
  (println "  Uprobe DSL Examples")
  (println "==============================================")

  (demo-library-discovery)
  (demo-common-functions)
  (demo-symbol-resolution)
  (demo-prologue-generation)
  (demo-macro-usage)
  (demo-program-building)
  (demo-section-names)
  (demo-program-metadata)
  (demo-attachment-info)
  (demo-complete-tracer)
  (demo-program-assembly)

  (println "\n==============================================")
  (println "  All demonstrations complete!")
  (println "=============================================="))

;; ============================================================================
;; REPL Usage
;; ============================================================================

(comment
  ;; Run all demos
  (-main)

  ;; Find libc
  (up/find-libc)

  ;; Resolve symbol (if libc available)
  (when-let [libc (up/find-libc)]
    (up/resolve-symbol-offset libc "malloc"))

  ;; Get symbol info
  (when-let [libc (up/find-libc)]
    (up/get-symbol-info libc "free"))

  ;; List symbols
  (when-let [libc (up/find-libc)]
    (take 20 (up/list-symbols libc)))

  ;; Generate prologue
  (up/uprobe-prologue :r9 [:r6 :r7])

  ;; Use macro-defined handlers
  (malloc-probe)
  (malloc-ret-probe)

  ;; Build programs
  (up/build-uprobe-program {:args [:r6] :return-value 0})
  (up/build-uretprobe-program {:ret-reg :r6 :return-value 0})

  ;; Create attachment info
  (up/uprobe-attach-info "/lib/libc.so.6" 0x12345)
  (up/uretprobe-attach-info "/lib/libc.so.6" 0x12345 :pid 1234)
  )
