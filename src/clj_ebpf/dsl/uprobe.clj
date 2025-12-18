(ns clj-ebpf.dsl.uprobe
  "High-level uprobe definition macros for BPF programs.

   Provides the defuprobe macro for defining uprobe handlers that trace
   userspace functions with automatic argument extraction.

   Uprobes are like kprobes but for userspace applications. They allow
   tracing functions in user binaries, shared libraries, and interpreters.

   Example:
     (defuprobe-instructions malloc-tracer
       {:binary \"/lib/x86_64-linux-gnu/libc.so.6\"
        :function \"malloc\"
        :args [:r6]}  ; size argument
       (concat
         (helper-get-current-pid-tgid)
         [(mov-reg :r7 :r0)]
         [(exit-insn)]))"
  (:require [clj-ebpf.arch :as arch]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.utils :as utils]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Uprobe Argument Handling
;; ============================================================================

;; Uprobe uses the same pt_regs structure as kprobe for argument access
;; The calling convention determines which registers hold arguments

(defn uprobe-read-args
  "Generate instructions to read uprobe arguments into registers.

   In uprobe handlers, r1 contains a pointer to pt_regs. This function
   generates instructions to load function arguments from pt_regs into
   the specified destination registers.

   Note: Uses the same offsets as kprobe since both use pt_regs.

   Parameters:
   - ctx-reg: Register containing pt_regs pointer (typically :r1)
   - arg-bindings: Vector of [arg-index dest-reg] pairs

   Returns vector of ldx instructions.

   Example:
     (uprobe-read-args :r1 [[0 :r6] [1 :r7]])
     ;; Generates instructions to load first two arguments"
  [ctx-reg arg-bindings]
  (vec (for [[arg-index dest-reg] arg-bindings]
         (dsl/read-kprobe-arg ctx-reg arg-index dest-reg))))

(defn uprobe-prologue
  "Generate standard uprobe prologue instructions.

   Saves the pt_regs pointer and reads specified arguments.
   Uses the same mechanism as kprobe since both access pt_regs.

   Parameters:
   - ctx-save-reg: Register to save pt_regs pointer (optional)
   - arg-regs: Vector of registers for arguments, e.g., [:r6 :r7 :r8]
               Arg 0 goes to first register, arg 1 to second, etc.

   Returns vector of instructions.

   Example:
     (uprobe-prologue :r9 [:r6 :r7])
     ;; Generates:
     ;; mov r9, r1          ; Save pt_regs pointer
     ;; ldxdw r6, [r1 + offset] ; Load arg0
     ;; ldxdw r7, [r1 + offset] ; Load arg1"
  ([arg-regs]
   (uprobe-prologue nil arg-regs))
  ([ctx-save-reg arg-regs]
   (vec (concat
         (when ctx-save-reg
           [(dsl/mov-reg ctx-save-reg :r1)])
         (uprobe-read-args :r1
                          (map-indexed (fn [idx reg] [idx reg]) arg-regs))))))

;; ============================================================================
;; Uretprobe Handling
;; ============================================================================

(defn uretprobe-get-return-value
  "Generate instruction to read the return value in uretprobe.

   In uretprobe handlers, the function return value is accessed via
   the same mechanism as kretprobe (PT_REGS_RC).

   Parameters:
   - ctx-reg: Register containing pt_regs pointer
   - dst-reg: Destination register for return value

   Returns ldx instruction.

   Example:
     (uretprobe-get-return-value :r1 :r6)
     ;; r6 = function return value"
  [ctx-reg dst-reg]
  ;; Same offsets as kretprobe - return value in architecture-specific register
  (let [ret-offset (case arch/current-arch
                    :x86_64 80   ; rax offset
                    :arm64  0    ; x0 offset
                    :s390x  16   ; r2 offset
                    :ppc64le 24  ; r3 offset
                    :riscv64 80  ; a0 offset
                    80)]  ; Default to x86_64
    (dsl/ldx :dw dst-reg ctx-reg ret-offset)))

;; ============================================================================
;; ELF Symbol Parsing (for shared libraries and executables)
;; ============================================================================

;; ELF constants
(def ^:private ELF_MAGIC (byte-array [0x7f 0x45 0x4c 0x46]))  ; \x7fELF
(def ^:private SHT_SYMTAB 2)
(def ^:private SHT_DYNSYM 11)
(def ^:private SHT_STRTAB 3)
(def ^:private STT_FUNC 2)

(defn- elf-64bit?
  "Check if ELF file is 64-bit (ei_class == 2)"
  [^bytes data]
  (= 2 (aget data 4)))

(defn- elf-little-endian?
  "Check if ELF file is little-endian (ei_data == 1)"
  [^bytes data]
  (= 1 (aget data 5)))

(defn- make-buffer
  "Create ByteBuffer with correct endianness for ELF data"
  [^bytes data]
  (let [buf (ByteBuffer/wrap data)]
    (if (elf-little-endian? data)
      (.order buf ByteOrder/LITTLE_ENDIAN)
      (.order buf ByteOrder/BIG_ENDIAN))
    buf))

(defn- read-section-headers-64
  "Read 64-bit ELF section headers"
  [^ByteBuffer buf shoff shentsize shnum]
  (.position buf (int shoff))
  (vec
   (for [_ (range shnum)]
     (let [start (.position buf)
           name-offset (.getInt buf)
           type (.getInt buf)
           flags (.getLong buf)
           addr (.getLong buf)
           offset (.getLong buf)
           size (.getLong buf)
           link (.getInt buf)
           info (.getInt buf)]
       (.position buf (+ start shentsize))
       {:name-offset name-offset
        :type type
        :flags flags
        :addr addr
        :offset offset
        :size size
        :link link
        :info info}))))

(defn- read-string-at
  "Read null-terminated string from data at offset"
  [^bytes data offset]
  (when (and offset (>= offset 0) (< offset (alength data)))
    (let [sb (StringBuilder.)]
      (loop [i offset]
        (if (< i (alength data))
          (let [b (aget data i)]
            (if (zero? b)
              (.toString sb)
              (do
                (.append sb (char (bit-and 0xff b)))
                (recur (inc i)))))
          (.toString sb))))))

(defn- parse-symbol-64
  "Parse a single 64-bit ELF symbol entry"
  [^ByteBuffer buf strtab]
  (let [name-idx (.getInt buf)
        info (bit-and 0xff (.get buf))
        _other (.get buf)
        shndx (.getShort buf)
        value (.getLong buf)
        size (.getLong buf)
        sym-type (bit-and info 0x0f)
        sym-name (read-string-at strtab name-idx)]
    {:name sym-name
     :value value
     :size size
     :type (case sym-type
             0 :notype
             1 :object
             2 :func
             3 :section
             4 :file
             :other)
     :shndx shndx}))

(defn- parse-elf-symbols
  "Parse ELF file and extract symbols

   Returns map with :symbols vector or nil on error"
  [binary-path]
  (try
    (let [data (utils/read-file-bytes binary-path)
          _ (when (< (alength data) 64)
              (throw (ex-info "File too small" {})))
          _ (when-not (java.util.Arrays/equals
                       ^bytes ELF_MAGIC
                       ^bytes (java.util.Arrays/copyOfRange data 0 4))
              (throw (ex-info "Not an ELF file" {})))
          _ (when-not (elf-64bit? data)
              (throw (ex-info "Only 64-bit ELF supported" {})))
          buf (make-buffer data)

          ;; Read ELF header fields
          _ (.position buf 40)  ; e_shoff
          shoff (.getLong buf)
          _ (.position buf 58)  ; e_shentsize
          shentsize (bit-and 0xffff (.getShort buf))
          shnum (bit-and 0xffff (.getShort buf))
          shstrndx (bit-and 0xffff (.getShort buf))

          ;; Parse section headers
          sections (read-section-headers-64 buf shoff shentsize shnum)

          ;; Find section name string table
          shstrtab-section (nth sections shstrndx)
          shstrtab (java.util.Arrays/copyOfRange
                    data
                    (int (:offset shstrtab-section))
                    (int (+ (:offset shstrtab-section) (:size shstrtab-section))))

          ;; Add names to sections
          sections (mapv #(assoc % :name (read-string-at shstrtab (:name-offset %)))
                         sections)

          ;; Find symbol tables (.dynsym is most useful for shared libs)
          dynsym-section (first (filter #(= (:type %) SHT_DYNSYM) sections))
          symtab-section (first (filter #(= (:type %) SHT_SYMTAB) sections))

          ;; Parse symbols from both tables
          parse-symtab (fn [sym-section]
                         (when sym-section
                           (let [strtab-section (nth sections (:link sym-section))
                                 strtab (java.util.Arrays/copyOfRange
                                         data
                                         (int (:offset strtab-section))
                                         (int (+ (:offset strtab-section)
                                                 (:size strtab-section))))
                                 sym-buf (make-buffer data)
                                 _ (.position sym-buf (int (:offset sym-section)))
                                 entry-size 24  ; sizeof(Elf64_Sym)
                                 num-syms (/ (:size sym-section) entry-size)]
                             (vec (for [_ (range num-syms)]
                                    (parse-symbol-64 sym-buf strtab))))))

          dynsym-symbols (parse-symtab dynsym-section)
          symtab-symbols (parse-symtab symtab-section)]

      {:symbols (vec (concat (or dynsym-symbols [])
                             (or symtab-symbols [])))})
    (catch Exception e
      {:error (.getMessage e)})))

;; ============================================================================
;; Symbol Resolution Public API
;; ============================================================================

(defn resolve-symbol-offset
  "Resolve the offset of a symbol within a binary.

   Uses ELF parsing to find the symbol's virtual address and converts
   it to an offset suitable for uprobe attachment.

   Parameters:
   - binary-path: Path to the ELF binary or shared library
   - symbol-name: Name of the function/symbol to find

   Returns the symbol offset, or nil if not found.

   Example:
     (resolve-symbol-offset \"/lib/x86_64-linux-gnu/libc.so.6\" \"malloc\")
     ;; => 0x9d850 (actual offset varies by libc version)"
  [binary-path symbol-name]
  (let [result (parse-elf-symbols binary-path)]
    (if (:error result)
      (throw (ex-info "Failed to resolve symbol"
                     {:binary binary-path
                      :symbol symbol-name
                      :cause (:error result)}))
      (when-let [sym (first (filter #(= (:name %) symbol-name) (:symbols result)))]
        (:value sym)))))

(defn get-symbol-info
  "Get detailed information about a symbol in a binary.

   Parameters:
   - binary-path: Path to the ELF binary
   - symbol-name: Name of the symbol

   Returns map with :name, :offset, :size, :type, or nil if not found."
  [binary-path symbol-name]
  (let [result (parse-elf-symbols binary-path)]
    (when-not (:error result)
      (when-let [sym (first (filter #(= (:name %) symbol-name) (:symbols result)))]
        {:name (:name sym)
         :offset (:value sym)
         :size (:size sym)
         :type (:type sym)}))))

(defn list-symbols
  "List all function symbols in a binary.

   Parameters:
   - binary-path: Path to the ELF binary
   - filter-fn: Optional predicate to filter symbols

   Returns vector of symbol maps."
  ([binary-path]
   (list-symbols binary-path (constantly true)))
  ([binary-path filter-fn]
   (let [result (parse-elf-symbols binary-path)]
     (if (:error result)
       []
       (->> (:symbols result)
            (filter #(= (:type %) :func))
            (filter filter-fn)
            (map #(select-keys % [:name :value :size]))
            vec)))))

;; ============================================================================
;; Binary Path Utilities
;; ============================================================================

(def common-library-paths
  "Common paths for system libraries."
  ["/lib/x86_64-linux-gnu"
   "/lib64"
   "/usr/lib/x86_64-linux-gnu"
   "/usr/lib64"
   "/lib/aarch64-linux-gnu"
   "/usr/lib/aarch64-linux-gnu"])

(defn find-library
  "Find a library by name in common system paths.

   Parameters:
   - lib-name: Library name (e.g., \"libc.so.6\" or just \"libc\")

   Returns full path or nil if not found."
  [lib-name]
  (let [names (if (str/includes? lib-name ".so")
                [lib-name]
                [(str lib-name ".so.6")
                 (str lib-name ".so")
                 (str "lib" lib-name ".so.6")
                 (str "lib" lib-name ".so")])]
    (first
     (for [path common-library-paths
           name names
           :let [full-path (str path "/" name)]
           :when (.exists (java.io.File. full-path))]
       full-path))))

(defn find-libc
  "Find the system's libc library.

   Returns path to libc.so.6 or similar."
  []
  (or (find-library "libc.so.6")
      (find-library "libc")))

;; ============================================================================
;; Complete Uprobe Builder
;; ============================================================================

(defn build-uprobe-program
  "Build a complete uprobe program with standard structure.

   Combines prologue, body instructions, and epilogue.

   Parameters:
   - opts: Map with:
     :args - Vector of destination registers for function arguments
     :ctx-reg - Register to save pt_regs pointer (optional)
     :body - Vector of body instructions
     :return-value - Value to return (default 0)

   Returns assembled program bytes.

   Example:
     (build-uprobe-program
       {:args [:r6 :r7]
        :body [(mov :r0 42)]
        :return-value 0})"
  [{:keys [args ctx-reg body return-value]
    :or {args [] return-value 0}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue: save context and load arguments
         (uprobe-prologue ctx-reg args)
         ;; Body instructions
         body
         ;; Epilogue: set return value and exit
         [(dsl/mov :r0 return-value)
          (dsl/exit-insn)]))))

(defn build-uretprobe-program
  "Build a complete uretprobe program with standard structure.

   Similar to build-uprobe-program but for return probes.

   Parameters:
   - opts: Map with:
     :ret-reg - Register to store return value
     :ctx-reg - Register to save pt_regs pointer (optional)
     :body - Vector of body instructions
     :return-value - Value to return (default 0)

   Returns assembled program bytes.

   Example:
     (build-uretprobe-program
       {:ret-reg :r6
        :body [(jmp-imm :jeq :r6 0 skip)
               (mov :r0 0)
               (exit-insn)]})"
  [{:keys [ret-reg ctx-reg body return-value]
    :or {return-value 0}}]
  (dsl/assemble
   (vec (concat
         ;; Prologue: save context and get return value
         (when ctx-reg
           [(dsl/mov-reg ctx-reg :r1)])
         (when ret-reg
           [(uretprobe-get-return-value :r1 ret-reg)])
         ;; Body instructions
         body
         ;; Epilogue
         [(dsl/mov :r0 return-value)
          (dsl/exit-insn)]))))

;; ============================================================================
;; Uprobe Program Definition Macros
;; ============================================================================

(defmacro defuprobe-instructions
  "Define a uprobe program as a function returning instructions.

   This macro creates a function that returns a vector of BPF instructions
   for a uprobe handler. It sets up automatic argument loading.

   Parameters:
   - name: Name for the defined function
   - options: Map with:
     :binary - Path to the binary or library
     :function - Function name to probe (or :offset for raw offset)
     :offset - Raw offset if not using symbol name
     :args - Vector of arg register bindings [:r6 :r7 ...]
     :ctx-reg - Register to save context (optional)
   - body: Body instructions (should return vector of instructions)

   Example:
     (defuprobe-instructions malloc-probe
       {:binary \"/lib/x86_64-linux-gnu/libc.so.6\"
        :function \"malloc\"
        :args [:r6]}  ; r6 = size argument
       (concat
         (helper-get-current-pid-tgid)
         [(mov-reg :r7 :r0)]
         [(mov :r0 0)
          (exit-insn)]))"
  [name options & body]
  (let [args (or (:args options) [])
        binary (:binary options)
        function (:function options)]
    `(defn ~name
       ~(str "Uprobe handler for " (or function "userspace function")
             " in " (or binary "binary") ".\n"
             "Arguments: " (pr-str args))
       []
       (vec (concat
             (uprobe-prologue ~(:ctx-reg options) ~args)
             ~@body)))))

(defmacro defuretprobe-instructions
  "Define a uretprobe program as a function returning instructions.

   Similar to defuprobe-instructions but for return probes.
   Automatically loads the return value into the specified register.

   Parameters:
   - name: Name for the defined function
   - options: Map with:
     :binary - Path to the binary
     :function - Function name to probe
     :ret-reg - Register for return value
     :ctx-reg - Register to save context (optional)
   - body: Body instructions

   Example:
     (defuretprobe-instructions malloc-ret-probe
       {:binary \"/lib/x86_64-linux-gnu/libc.so.6\"
        :function \"malloc\"
        :ret-reg :r6}  ; r6 = returned pointer
       (concat
         [(jmp-imm :jeq :r6 0 skip)]  ; Skip if NULL
         ;; ... handle success case
         [(mov :r0 0)
          (exit-insn)]))"
  [name options & body]
  (let [ret-reg (:ret-reg options)
        binary (:binary options)
        function (:function options)]
    `(defn ~name
       ~(str "Uretprobe handler for " (or function "userspace function")
             " in " (or binary "binary") ".\n"
             "Return value in: " (pr-str ret-reg))
       []
       (vec (concat
             ~(when (:ctx-reg options)
                `[(dsl/mov-reg ~(:ctx-reg options) :r1)])
             ~(when ret-reg
                `[(uretprobe-get-return-value :r1 ~ret-reg)])
             ~@body)))))

;; ============================================================================
;; Utility Functions
;; ============================================================================

(defn uprobe-section-name
  "Generate ELF section name for a uprobe program.

   Parameters:
   - binary: Path to the binary
   - function-or-offset: Function name or numeric offset

   Returns section name like \"uprobe/libc.so.6:malloc\""
  [binary function-or-offset]
  (let [binary-name (last (str/split binary #"/"))]
    (str "uprobe/" binary-name ":" function-or-offset)))

(defn uretprobe-section-name
  "Generate ELF section name for a uretprobe program.

   Parameters:
   - binary: Path to the binary
   - function-or-offset: Function name or numeric offset

   Returns section name like \"uretprobe/libc.so.6:malloc\""
  [binary function-or-offset]
  (let [binary-name (last (str/split binary #"/"))]
    (str "uretprobe/" binary-name ":" function-or-offset)))

(defn make-uprobe-program-info
  "Create program metadata for a uprobe.

   Parameters:
   - binary: Path to the binary
   - function: Function name
   - offset: Symbol offset (optional, will be resolved if nil)
   - program-name: Name for the BPF program
   - instructions: Program instructions

   Returns map with program metadata for loading."
  [binary function offset program-name instructions]
  {:name program-name
   :section (uprobe-section-name binary function)
   :type :uprobe
   :binary binary
   :function function
   :offset (or offset (resolve-symbol-offset binary function))
   :instructions instructions})

(defn make-uretprobe-program-info
  "Create program metadata for a uretprobe.

   Parameters:
   - binary: Path to the binary
   - function: Function name
   - offset: Symbol offset (optional)
   - program-name: Name for the BPF program
   - instructions: Program instructions

   Returns map with program metadata for loading."
  [binary function offset program-name instructions]
  {:name program-name
   :section (uretprobe-section-name binary function)
   :type :uretprobe
   :binary binary
   :function function
   :offset (or offset (resolve-symbol-offset binary function))
   :instructions instructions})

;; ============================================================================
;; Common Uprobe Targets
;; ============================================================================

(def common-libc-functions
  "Common libc functions that are useful to trace."
  {:memory ["malloc" "free" "calloc" "realloc" "mmap" "munmap" "brk"]
   :file-io ["open" "close" "read" "write" "lseek" "fopen" "fclose"]
   :process ["fork" "exec" "execve" "exit" "_exit" "wait" "waitpid"]
   :network ["socket" "connect" "bind" "listen" "accept" "send" "recv"]
   :string ["strlen" "strcpy" "strncpy" "strcmp" "strncmp" "memcpy" "memset"]
   :thread ["pthread_create" "pthread_join" "pthread_mutex_lock" "pthread_mutex_unlock"]})

(def common-crypto-functions
  "Common crypto library functions."
  {:openssl ["SSL_connect" "SSL_accept" "SSL_read" "SSL_write"
             "EVP_EncryptUpdate" "EVP_DecryptUpdate"
             "RSA_public_encrypt" "RSA_private_decrypt"]
   :gnutls ["gnutls_record_send" "gnutls_record_recv"]})

(defn get-libc-function-offset
  "Get the offset of a common libc function.

   Parameters:
   - function: Function name (e.g., \"malloc\")

   Returns offset or throws if libc or function not found."
  [function]
  (if-let [libc-path (find-libc)]
    (or (resolve-symbol-offset libc-path function)
        (throw (ex-info "Function not found in libc"
                       {:function function :libc libc-path})))
    (throw (ex-info "libc not found on system" {}))))

;; ============================================================================
;; Attachment Info Builders
;; ============================================================================

(defn uprobe-attach-info
  "Build attachment information for a uprobe.

   Parameters:
   - binary: Path to binary
   - target: Either a function name (string) or offset (number)
   - pid: Optional PID to filter (nil for all processes)

   Returns map suitable for attachment functions."
  [binary target & {:keys [pid]}]
  (let [offset (if (number? target)
                 target
                 (resolve-symbol-offset binary target))]
    (cond-> {:binary binary
             :offset offset
             :type :uprobe}
      (string? target) (assoc :function target)
      pid (assoc :pid pid))))

(defn uretprobe-attach-info
  "Build attachment information for a uretprobe.

   Parameters:
   - binary: Path to binary
   - target: Either a function name (string) or offset (number)
   - pid: Optional PID to filter

   Returns map suitable for attachment functions."
  [binary target & {:keys [pid]}]
  (let [offset (if (number? target)
                 target
                 (resolve-symbol-offset binary target))]
    (cond-> {:binary binary
             :offset offset
             :type :uretprobe}
      (string? target) (assoc :function target)
      pid (assoc :pid pid))))
