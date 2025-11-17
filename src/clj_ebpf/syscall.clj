(ns clj-ebpf.syscall
  "Low-level BPF syscall interface using Java Panama FFI (Java 21+)"
  (:require [clj-ebpf.constants :as const]
            [clojure.tools.logging :as log])
  (:import [java.lang.foreign Arena MemorySegment SymbolLookup Linker FunctionDescriptor ValueLayout]
           [java.lang.invoke MethodHandle]))

;; Panama FFI setup
;; Arena for memory allocation (auto-managed by GC)
(def ^:private ^:dynamic *arena* (Arena/ofAuto))

(def ^:private linker (Linker/nativeLinker))
(def ^:private libc-lookup
  (or
   ;; Try common libc paths on Linux
   (try (SymbolLookup/libraryLookup "/lib/x86_64-linux-gnu/libc.so.6" *arena*) (catch Exception _ nil))
   (try (SymbolLookup/libraryLookup "libc.so.6" *arena*) (catch Exception _ nil))
   (try (SymbolLookup/libraryLookup "c" *arena*) (catch Exception _ nil))
   ;; Fallback to loader lookup
   (SymbolLookup/loaderLookup)))

;; Value layouts for common types
(def ^:private C_INT ValueLayout/JAVA_INT)
(def ^:private C_LONG ValueLayout/JAVA_LONG)
(def ^:private C_POINTER (ValueLayout/ADDRESS))

;; Helper to create FunctionDescriptor with varargs
(defn- make-function-descriptor
  "Create a FunctionDescriptor - helper to avoid reflection issues"
  ^java.lang.foreign.FunctionDescriptor
  [^java.lang.foreign.MemoryLayout return-layout & arg-layouts]
  (let [^"[Ljava.lang.foreign.MemoryLayout;" layouts-array (into-array java.lang.foreign.MemoryLayout (or arg-layouts []))]
    (java.lang.foreign.FunctionDescriptor/of return-layout layouts-array)))

;; Get errno from libc
(def ^:private errno-location
  (let [sym (.find libc-lookup "__errno_location")]
    (when (.isPresent sym)
      ;; Function with no parameters returning a pointer
      (let [^java.lang.foreign.MemorySegment mem-seg (.get sym)
            ^java.lang.foreign.FunctionDescriptor desc (make-function-descriptor C_POINTER)
            ^java.lang.foreign.Linker lnk linker]
        (.downcallHandle lnk mem-seg desc (into-array java.lang.foreign.Linker$Option []))))))


(defn get-errno
  "Get the last errno value"
  []
  (if errno-location
    (let [errno-ptr (.invokeWithArguments ^java.lang.invoke.MethodHandle errno-location [])
          ;; Reinterpret the zero-sized segment to have size of int
          errno-seg (.reinterpret ^MemorySegment errno-ptr 4)]
      (.get errno-seg C_INT 0))
    0))

(defn errno->keyword
  "Convert errno number to keyword"
  [errno-num]
  (or (some (fn [[k v]] (when (= v errno-num) k)) const/errno)
      :unknown))

;; Syscall function
(def ^:private syscall-fn
  (let [sym (.find libc-lookup "syscall")]
    (if (.isPresent sym)
      ;; syscall(long number, ...) - in our case: syscall(BPF_NR, cmd:int, attr:ptr, size:int)
      (let [^java.lang.foreign.MemorySegment mem-seg (.get sym)
            ^java.lang.foreign.FunctionDescriptor desc (make-function-descriptor C_LONG C_LONG C_INT C_POINTER C_INT)
            ^java.lang.foreign.Linker lnk linker]
        (.downcallHandle lnk mem-seg desc (into-array java.lang.foreign.Linker$Option [])))
      (throw (ex-info "Cannot find syscall function in libc. Native access may need to be enabled with --enable-native-access=ALL-UNNAMED"
                      {:libc-lookup libc-lookup})))))

;; Helper to allocate and zero memory
(defn allocate-zeroed
  "Allocate zeroed memory segment"
  [size]
  (let [segment (.allocate *arena* (long size) 8)]
    (.fill segment (byte 0))
    segment))

;; BPF attribute structures

(defrecord MapCreateAttr
  [^int map-type
   ^int key-size
   ^int value-size
   ^int max-entries
   ^int map-flags
   ^Integer inner-map-fd        ;; Optional - nullable
   ^Integer numa-node           ;; Optional - nullable
   ^String map-name             ;; Optional - nullable
   ^Integer map-ifindex         ;; Optional - nullable
   ^Integer btf-fd              ;; Optional - nullable
   ^Integer btf-key-type-id     ;; Optional - nullable
   ^Integer btf-value-type-id   ;; Optional - nullable
   ^Integer btf-vmlinux-value-type-id  ;; Optional - nullable
   ^Long map-extra])            ;; Optional - nullable

(defn map-create-attr->segment
  "Convert MapCreateAttr to MemorySegment for syscall"
  [attr]
  (let [mem (allocate-zeroed 128)]
    (.set mem C_INT 0 (:map-type attr))
    (.set mem C_INT 4 (:key-size attr))
    (.set mem C_INT 8 (:value-size attr))
    (.set mem C_INT 12 (:max-entries attr))
    (.set mem C_INT 16 (:map-flags attr))
    (when (:inner-map-fd attr)
      (.set mem C_INT 20 (:inner-map-fd attr)))
    (when (:numa-node attr)
      (.set mem C_INT 24 (:numa-node attr)))
    (when (:map-name attr)
      (let [name-bytes (.getBytes (:map-name attr) "UTF-8")
            len (min (count name-bytes) (dec const/BPF_OBJ_NAME_LEN))
            src (MemorySegment/ofArray name-bytes)]
        (MemorySegment/copy src 0 mem 28 len)))
    (when (:map-ifindex attr)
      (.set mem C_INT 44 (:map-ifindex attr)))
    (when (:btf-fd attr)
      (.set mem C_INT 48 (:btf-fd attr)))
    (when (:btf-key-type-id attr)
      (.set mem C_INT 52 (:btf-key-type-id attr)))
    (when (:btf-value-type-id attr)
      (.set mem C_INT 56 (:btf-value-type-id attr)))
    (when (:btf-vmlinux-value-type-id attr)
      (.set mem C_INT 60 (:btf-vmlinux-value-type-id attr)))
    (when (:map-extra attr)
      (.set mem C_LONG 64 (:map-extra attr)))
    mem))

(defrecord MapElemAttr
  [^int map-fd
   ^MemorySegment key
   ^MemorySegment value
   ^long flags])

(defn map-elem-attr->segment
  "Convert MapElemAttr to MemorySegment for syscall"
  [attr]
  (let [mem (allocate-zeroed 128)]
    (.set mem C_INT 0 (:map-fd attr))
    (.set mem C_POINTER 8 (:key attr))
    (.set mem C_POINTER 16 (or (:value attr) MemorySegment/NULL))
    (.set mem C_LONG 24 (:flags attr))
    mem))

(defrecord MapNextKeyAttr
  [^int map-fd
   ^MemorySegment key
   ^MemorySegment next-key])

(defn map-next-key-attr->segment
  "Convert MapNextKeyAttr to MemorySegment for syscall"
  [attr]
  (let [mem (allocate-zeroed 128)]
    (.set mem C_INT 0 (:map-fd attr))
    (.set mem C_POINTER 8 (or (:key attr) MemorySegment/NULL))
    (.set mem C_POINTER 16 (:next-key attr))
    mem))

(defrecord ProgLoadAttr
  [^int prog-type
   ^int insn-cnt
   ^MemorySegment insns
   ^String license
   ^Integer log-level           ;; Optional - nullable
   ^Integer log-size            ;; Optional - nullable
   ^MemorySegment log-buf       ;; Optional - nullable
   ^Integer kern-version        ;; Optional - nullable
   ^Integer prog-flags          ;; Optional - nullable
   ^String prog-name            ;; Optional - nullable
   ^Integer prog-ifindex        ;; Optional - nullable
   ^Integer expected-attach-type ;; Optional - nullable
   ^Integer prog-btf-fd         ;; Optional - nullable
   ^Integer func-info-rec-size  ;; Optional - nullable
   ^MemorySegment func-info     ;; Optional - nullable
   ^Integer func-info-cnt       ;; Optional - nullable
   ^Integer line-info-rec-size  ;; Optional - nullable
   ^MemorySegment line-info     ;; Optional - nullable
   ^Integer line-info-cnt       ;; Optional - nullable
   ^Integer attach-btf-id       ;; Optional - nullable
   ^Integer attach-prog-fd])    ;; Optional - nullable

(defn prog-load-attr->segment
  "Convert ProgLoadAttr to MemorySegment for syscall"
  [attr]
  (let [mem (allocate-zeroed 128)]
    (.set mem C_INT 0 (:prog-type attr))
    (.set mem C_INT 4 (:insn-cnt attr))
    (.set mem C_POINTER 8 (:insns attr))
    (when (:license attr)
      (let [lic-bytes (.getBytes (:license attr) "UTF-8")
            lic-mem (.allocate *arena* (inc (count lic-bytes)) 1)
            src (MemorySegment/ofArray lic-bytes)]
        (MemorySegment/copy src 0 lic-mem 0 (count lic-bytes))
        (.set mem C_POINTER 16 lic-mem)))
    (.set mem C_INT 24 (or (:log-level attr) 0))
    (.set mem C_INT 28 (or (:log-size attr) 0))
    (.set mem C_POINTER 32 (or (:log-buf attr) MemorySegment/NULL))
    (.set mem C_INT 40 (or (:kern-version attr) 0))
    (.set mem C_INT 44 (or (:prog-flags attr) 0))
    (when (:prog-name attr)
      (let [name-bytes (.getBytes (:prog-name attr) "UTF-8")
            len (min (count name-bytes) (dec const/BPF_OBJ_NAME_LEN))
            src (MemorySegment/ofArray name-bytes)]
        (MemorySegment/copy src 0 mem 48 len)))
    (when (:prog-ifindex attr)
      (.set mem C_INT 64 (:prog-ifindex attr)))
    (when (:expected-attach-type attr)
      (.set mem C_INT 68 (:expected-attach-type attr)))
    (when (:prog-btf-fd attr)
      (.set mem C_INT 72 (:prog-btf-fd attr)))
    mem))

(defrecord ObjPinAttr
  [^String pathname
   ^int bpf-fd
   ^Integer file-flags])  ;; Optional - nullable

(defn obj-pin-attr->segment
  "Convert ObjPinAttr to MemorySegment for syscall"
  [attr]
  (let [mem (allocate-zeroed 128)
        path-bytes (.getBytes (:pathname attr) "UTF-8")
        path-mem (.allocate *arena* (inc (count path-bytes)) 1)
        src (MemorySegment/ofArray path-bytes)]
    (MemorySegment/copy src 0 path-mem 0 (count path-bytes))
    (.set mem C_POINTER 0 path-mem)
    (.set mem C_INT 8 (:bpf-fd attr))
    (.set mem C_INT 12 (or (:file-flags attr) 0))
    mem))

(defrecord RawTracepointAttr
  [^String name
   ^int prog-fd])

(defn raw-tracepoint-attr->segment
  "Convert RawTracepointAttr to MemorySegment for syscall"
  [attr]
  (let [mem (allocate-zeroed 128)
        name-bytes (.getBytes (:name attr) "UTF-8")
        name-mem (.allocate *arena* (inc (count name-bytes)) 1)
        src (MemorySegment/ofArray name-bytes)]
    (MemorySegment/copy src 0 name-mem 0 (count name-bytes))
    (.set mem C_POINTER 0 name-mem)
    (.set mem C_INT 8 (:prog-fd attr))
    mem))

;; Main syscall function
(defn bpf-syscall
  "Make a BPF syscall with the given command and attributes"
  [cmd attr-mem]
  (let [cmd-num (if (keyword? cmd)
                  (const/cmd->num cmd)
                  cmd)
        result (.invokeWithArguments ^java.lang.invoke.MethodHandle syscall-fn
                                    [(long const/BPF_SYSCALL_NR)
                                     (int cmd-num)
                                     attr-mem
                                     (int 128)])]
    (if (< (long result) 0)
      (let [errno (get-errno)
            errno-kw (errno->keyword errno)]
        (log/error "BPF syscall failed:" cmd "errno:" errno errno-kw)
        (throw (ex-info (str "BPF syscall failed: " cmd " - " errno-kw)
                        {:command cmd
                         :errno errno
                         :errno-keyword errno-kw})))
      (long result))))

;; High-level syscall wrappers

(defn map-create
  "Create a BPF map"
  [{:keys [map-type key-size value-size max-entries map-flags
           inner-map-fd numa-node map-name map-ifindex
           btf-fd btf-key-type-id btf-value-type-id
           btf-vmlinux-value-type-id map-extra]
    :or {map-flags 0}}]
  (let [attr (->MapCreateAttr
               (if (keyword? map-type)
                 (const/map-type->num map-type)
                 map-type)
               key-size
               value-size
               max-entries
               map-flags
               inner-map-fd
               numa-node
               map-name
               map-ifindex
               btf-fd
               btf-key-type-id
               btf-value-type-id
               btf-vmlinux-value-type-id
               map-extra)
        mem (map-create-attr->segment attr)]
    (int (bpf-syscall :map-create mem))))

(defn map-lookup-elem
  "Lookup element in BPF map"
  [map-fd key-seg value-seg]
  (let [attr (->MapElemAttr map-fd key-seg value-seg 0)
        mem (map-elem-attr->segment attr)]
    (bpf-syscall :map-lookup-elem mem)))

(defn map-update-elem
  "Update element in BPF map"
  [map-fd key-seg value-seg flags]
  (let [attr (->MapElemAttr map-fd key-seg value-seg flags)
        mem (map-elem-attr->segment attr)]
    (bpf-syscall :map-update-elem mem)))

(defn map-delete-elem
  "Delete element from BPF map"
  [map-fd key-seg]
  (let [attr (->MapElemAttr map-fd key-seg nil 0)
        mem (map-elem-attr->segment attr)]
    (bpf-syscall :map-delete-elem mem)))

(defn map-get-next-key
  "Get next key in BPF map (for iteration)"
  [map-fd key-seg next-key-seg]
  (let [attr (->MapNextKeyAttr map-fd key-seg next-key-seg)
        mem (map-next-key-attr->segment attr)]
    (bpf-syscall :map-get-next-key mem)))

(defn prog-load
  "Load a BPF program"
  [{:keys [prog-type insn-cnt insns license log-level log-size log-buf
           kern-version prog-flags prog-name prog-ifindex expected-attach-type
           prog-btf-fd func-info-rec-size func-info func-info-cnt
           line-info-rec-size line-info line-info-cnt attach-btf-id
           attach-prog-fd]
    :or {log-level 0 log-size 0 kern-version 0 prog-flags 0}}]
  (let [attr (->ProgLoadAttr
               (if (keyword? prog-type)
                 (const/prog-type->num prog-type)
                 prog-type)
               insn-cnt
               insns
               license
               log-level
               log-size
               log-buf
               kern-version
               prog-flags
               prog-name
               prog-ifindex
               expected-attach-type
               prog-btf-fd
               func-info-rec-size
               func-info
               func-info-cnt
               line-info-rec-size
               line-info
               line-info-cnt
               attach-btf-id
               attach-prog-fd)
        mem (prog-load-attr->segment attr)]
    (int (bpf-syscall :prog-load mem))))

(defn obj-pin
  "Pin BPF object to filesystem"
  [pathname bpf-fd & {:keys [file-flags] :or {file-flags 0}}]
  (let [attr (->ObjPinAttr pathname bpf-fd file-flags)
        mem (obj-pin-attr->segment attr)]
    (bpf-syscall :obj-pin mem)))

(defn obj-get
  "Get BPF object from filesystem"
  [pathname & {:keys [file-flags] :or {file-flags 0}}]
  (let [attr (->ObjPinAttr pathname 0 file-flags)
        mem (obj-pin-attr->segment attr)]
    (int (bpf-syscall :obj-get mem))))

(defn raw-tracepoint-open
  "Open a raw tracepoint and attach BPF program"
  [name prog-fd]
  (let [attr (->RawTracepointAttr name prog-fd)
        mem (raw-tracepoint-attr->segment attr)]
    (int (bpf-syscall :raw-tracepoint-open mem))))

;; Perf event syscall (needed for kprobes)
;; perf_event_open syscall wrapper
(def ^:private perf-event-open-syscall-fn
  (let [sym (.find libc-lookup "syscall")]
    (if (.isPresent sym)
      ;; syscall(long number, ...) for perf_event_open:
      ;; syscall(298, struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
      (let [^java.lang.foreign.MemorySegment mem-seg (.get sym)
            ^java.lang.foreign.FunctionDescriptor desc (make-function-descriptor C_LONG C_LONG C_POINTER C_INT C_INT C_INT C_LONG)
            ^java.lang.foreign.Linker lnk linker]
        (.downcallHandle lnk mem-seg desc (into-array java.lang.foreign.Linker$Option [])))
      (throw (ex-info "Cannot find syscall function in libc"
                      {:libc-lookup libc-lookup})))))

(defn perf-event-open
  "Open a perf event (used for kprobes/uprobes)"
  [event-type config pid cpu group-fd flags]
  (let [attr-size 128
        attr-mem (allocate-zeroed attr-size)]
    ;; type
    (.set attr-mem C_INT 0 event-type)
    ;; size
    (.set attr-mem C_INT 4 attr-size)
    ;; config
    (.set attr-mem C_LONG 8 config)
    ;; sample_period / sample_freq union - set to 1
    (.set attr-mem C_LONG 16 1)
    ;; sample_type
    (.set attr-mem C_LONG 24 0)
    ;; read_format
    (.set attr-mem C_LONG 32 0)
    ;; flags as bitfield (disabled=1)
    (.set attr-mem C_LONG 40 1)

    (let [result (.invokeWithArguments ^java.lang.invoke.MethodHandle perf-event-open-syscall-fn
                                      [(long const/PERF_EVENT_OPEN_SYSCALL_NR)
                                       attr-mem
                                       (int pid)
                                       (int cpu)
                                       (int group-fd)
                                       (long flags)])
          result-int (int result)]
      (log/info "perf_event_open result:" result "int:" result-int "errno:" (when (< result-int 0) (get-errno)))
      (if (< result-int 0)
        (let [errno (get-errno)
              errno-kw (errno->keyword errno)]
          (log/error "perf_event_open failed, errno:" errno errno-kw)
          (throw (ex-info (str "perf_event_open failed: " errno-kw)
                          {:errno errno
                           :errno-keyword errno-kw
                           :event-type event-type
                           :config config})))
        (int result)))))

;; IOCTL syscall
(def ^:private ioctl-fn
  (let [sym (.find libc-lookup "ioctl")]
    (when (.isPresent sym)
      (let [^java.lang.foreign.MemorySegment mem-seg (.get sym)
            ^java.lang.foreign.FunctionDescriptor desc (make-function-descriptor C_INT C_INT C_LONG C_INT)
            ^java.lang.foreign.Linker lnk linker]
        (.downcallHandle lnk mem-seg desc (into-array java.lang.foreign.Linker$Option []))))))

(defn ioctl
  "Make an ioctl syscall"
  ([fd request]
   (ioctl fd request 0))
  ([fd request arg]
   (let [result (.invokeWithArguments ^java.lang.invoke.MethodHandle ioctl-fn
                                     [(int fd)
                                      (long request)
                                      (int arg)])]
     (when (< (int result) 0)
       (let [errno (get-errno)
             errno-kw (errno->keyword errno)]
         (log/error "ioctl failed, errno:" errno errno-kw)
         (throw (ex-info (str "ioctl failed: " errno-kw)
                         {:fd fd
                          :request request
                          :errno errno
                          :errno-keyword errno-kw}))))
     (int result))))

;; BPF_LINK_CREATE syscall
(defn bpf-link-create-kprobe
  "Create a BPF link for kprobe using BPF_LINK_CREATE (modern method)
   Returns link FD"
  [prog-fd function-name retprobe?]
  (let [attr-mem (allocate-zeroed 128)
            ;; Allocate memory for the symbol name
        func-name-bytes (.getBytes (str function-name "\0") "UTF-8")
        func-name-mem (.allocate *arena* (alength func-name-bytes) 1)]
    (java.lang.foreign.MemorySegment/copy func-name-bytes 0 func-name-mem (java.lang.foreign.ValueLayout/JAVA_BYTE) 0 (alength func-name-bytes))

    ;; Build bpf_attr for BPF_LINK_CREATE with kprobe_multi
    ;; prog_fd (offset 0)
    (.set attr-mem C_INT 0 prog-fd)
    ;; attach_type (offset 8) - BPF_TRACE_KPROBE_MULTI = 42
    (.set attr-mem C_INT 8 (const/attach-type->num :trace-kprobe-multi))
    ;; flags (offset 12)
    (.set attr-mem C_INT 12 (if retprobe? 1 0)) ; BPF_F_KPROBE_MULTI_RETURN = 1

    ;; kprobe_multi substruct starts at offset 16
    ;; kprobe_multi.flags (offset 16)
    (.set attr-mem C_INT 16 0)
    ;; kprobe_multi.cnt (offset 20)
    (.set attr-mem C_INT 20 1)  ; attaching to 1 symbol
    ;; kprobe_multi.syms (offset 24) - address of array of string pointers
    ;; We need to create an array containing one pointer to our function name
    (let [sym-ptr-array (.allocate *arena* 8 8)]  ; array of 1 pointer
      (.set sym-ptr-array C_POINTER 0 func-name-mem) ; array[0] = func_name_mem
      (.set attr-mem C_LONG 24 (.address sym-ptr-array)))  ; syms = address of array

    (let [result (int (bpf-syscall :link-create attr-mem))]
      (if (< result 0)
        (let [errno (get-errno)
              errno-kw (errno->keyword errno)]
          (log/error "BPF_LINK_CREATE failed for kprobe, errno:" errno errno-kw)
          (throw (ex-info (str "BPF_LINK_CREATE failed: " errno-kw)
                          {:errno errno
                           :errno-keyword errno-kw
                           :function function-name
                           :retprobe? retprobe?})))
        (do
          (log/info "Created BPF link for" (if retprobe? "kretprobe" "kprobe")
                    "on" function-name "link-fd:" result)
          result)))))

;; Close file descriptor
(def ^:private close-fn
  (let [sym (.find libc-lookup "close")]
    (when (.isPresent sym)
      (let [^java.lang.foreign.MemorySegment mem-seg (.get sym)
            ^java.lang.foreign.FunctionDescriptor desc (make-function-descriptor C_INT C_INT)
            ^java.lang.foreign.Linker lnk linker]
        (.downcallHandle lnk mem-seg desc (into-array java.lang.foreign.Linker$Option []))))))

(defn close-fd
  "Close a file descriptor"
  [fd]
  (when (and fd (>= fd 0))
    (.invokeWithArguments ^java.lang.invoke.MethodHandle close-fn [(int fd)])))

;; Arena management for scoped allocations
(defn with-arena
  "Execute function with a confined arena for memory allocations"
  [f]
  (let [arena (Arena/ofConfined)]
    (try
      (binding [*arena* arena]
        (f))
      (finally
        (.close arena)))))
