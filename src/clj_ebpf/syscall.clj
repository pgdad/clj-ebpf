(ns clj-ebpf.syscall
  "Low-level BPF syscall interface using Java Panama FFI (Java 21+)"
  (:require [clj-ebpf.arch :as arch]
            [clj-ebpf.constants :as const]
            [clojure.tools.logging :as log])
  (:import [java.lang.foreign Arena MemorySegment SymbolLookup Linker FunctionDescriptor ValueLayout]
           [java.lang.invoke MethodHandle]))

;; Panama FFI setup
;; Arena for memory allocation (auto-managed by GC)
(def ^:private ^:dynamic *arena* (Arena/ofAuto))

(def ^:private linker (Linker/nativeLinker))

(defn- find-libc-lookup
  "Find libc using architecture-aware path discovery"
  []
  (or
   ;; Try architecture-specific path first
   (when-let [libc-path (arch/find-libc-path)]
     (try
       (SymbolLookup/libraryLookup libc-path *arena*)
       (catch Exception e
         (log/warn "Failed to load libc from" libc-path ":" (.getMessage e))
         nil)))
   ;; Fallback to generic names
   (try (SymbolLookup/libraryLookup "libc.so.6" *arena*) (catch Exception _ nil))
   (try (SymbolLookup/libraryLookup "c" *arena*) (catch Exception _ nil))
   ;; Final fallback to loader lookup
   (SymbolLookup/loaderLookup)))

(def ^:private libc-lookup (find-libc-lookup))

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
  (get const/errno-num->keyword errno-num :unknown))

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

(defrecord MapBatchAttr
  [^int map-fd
   ^MemorySegment in-batch      ;; For lookup_and_delete: input keys
   ^MemorySegment out-batch     ;; For lookup: output keys after last processed
   ^MemorySegment keys          ;; Keys array
   ^MemorySegment values        ;; Values array
   ^int count                   ;; Number of elements
   ^long elem-flags])           ;; Flags for elements

(defn map-batch-attr->segment
  "Convert MapBatchAttr to MemorySegment for syscall

  Layout (offsets for batch operations):
  - map_fd: offset 0 (u32)
  - batch union: offset 8 (u64)
    - in_batch: pointer
    - out_batch: pointer
    - keys: pointer
  - values: offset 16 (u64 pointer)
  - count: offset 24 (u32)
  - elem_flags: offset 32 (u64)"
  [attr]
  (let [mem (allocate-zeroed 128)]
    (.set mem C_INT 0 (:map-fd attr))
    ;; For batch operations, the union at offset 8 can be in_batch, out_batch, or keys
    ;; We'll use in_batch/out_batch for lookup operations, keys for update/delete
    (when (:in-batch attr)
      (.set mem C_POINTER 8 (:in-batch attr)))
    (when (:out-batch attr)
      (.set mem C_POINTER 8 (:out-batch attr)))
    (when (:keys attr)
      (.set mem C_POINTER 8 (:keys attr)))
    (when (:values attr)
      (.set mem C_POINTER 16 (:values attr)))
    (.set mem C_INT 24 (:count attr))
    (.set mem C_LONG 32 (:elem-flags attr))
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

(defn map-lookup-and-delete-elem
  "Atomically lookup and delete element from BPF map.

  This is required for stack and queue maps where pop operations
  must be atomic. Regular maps can also use this for atomic
  lookup-and-delete operations."
  [map-fd key-seg value-seg]
  (let [attr (->MapElemAttr map-fd key-seg value-seg 0)
        mem (map-elem-attr->segment attr)]
    (bpf-syscall :map-lookup-and-delete-elem mem)))

(defn map-get-next-key
  "Get next key in BPF map (for iteration)"
  [map-fd key-seg next-key-seg]
  (let [attr (->MapNextKeyAttr map-fd key-seg next-key-seg)
        mem (map-next-key-attr->segment attr)]
    (bpf-syscall :map-get-next-key mem)))

;; Batch operations

(defn map-lookup-batch
  "Batch lookup elements in BPF map

  Parameters:
  - map-fd: Map file descriptor
  - keys-seg: MemorySegment for keys array
  - values-seg: MemorySegment for values array
  - count: Number of elements to lookup
  - elem-flags: Flags for elements (default 0)

  Returns the number of elements successfully looked up.
  The count field in the attr structure is updated with the actual count."
  [map-fd keys-seg values-seg count & {:keys [elem-flags] :or {elem-flags 0}}]
  (let [attr (->MapBatchAttr map-fd nil nil keys-seg values-seg count elem-flags)
        mem (map-batch-attr->segment attr)
        result (bpf-syscall :map-lookup-batch mem)]
    ;; Return the actual count of elements processed
    ;; The kernel updates the count field at offset 24
    (.get mem C_INT 24)))

(defn map-lookup-and-delete-batch
  "Batch lookup and delete elements in BPF map

  Parameters:
  - map-fd: Map file descriptor
  - keys-seg: MemorySegment for keys array
  - values-seg: MemorySegment for values array
  - count: Number of elements to lookup and delete
  - elem-flags: Flags for elements (default 0)

  Returns the number of elements successfully processed.
  Elements are deleted from the map after being read."
  [map-fd keys-seg values-seg count & {:keys [elem-flags] :or {elem-flags 0}}]
  (let [attr (->MapBatchAttr map-fd nil nil keys-seg values-seg count elem-flags)
        mem (map-batch-attr->segment attr)
        result (bpf-syscall :map-lookup-and-delete-batch mem)]
    (.get mem C_INT 24)))

(defn map-update-batch
  "Batch update elements in BPF map

  Parameters:
  - map-fd: Map file descriptor
  - keys-seg: MemorySegment for keys array
  - values-seg: MemorySegment for values array
  - count: Number of elements to update
  - elem-flags: Flags for elements (default 0, can be BPF_ANY, BPF_NOEXIST, BPF_EXIST)

  Returns the number of elements successfully updated."
  [map-fd keys-seg values-seg count & {:keys [elem-flags] :or {elem-flags 0}}]
  (let [attr (->MapBatchAttr map-fd nil nil keys-seg values-seg count elem-flags)
        mem (map-batch-attr->segment attr)
        result (bpf-syscall :map-update-batch mem)]
    (.get mem C_INT 24)))

(defn map-delete-batch
  "Batch delete elements from BPF map

  Parameters:
  - map-fd: Map file descriptor
  - keys-seg: MemorySegment for keys array
  - count: Number of elements to delete
  - elem-flags: Flags for elements (default 0)

  Returns the number of elements successfully deleted."
  [map-fd keys-seg count & {:keys [elem-flags] :or {elem-flags 0}}]
  (let [attr (->MapBatchAttr map-fd nil nil keys-seg nil count elem-flags)
        mem (map-batch-attr->segment attr)
        result (bpf-syscall :map-delete-batch mem)]
    (.get mem C_INT 24)))

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
    ;; target_fd (offset 4) - not used for kprobe_multi, set to 0
    (.set attr-mem C_INT 4 0)
    ;; attach_type (offset 8) - BPF_TRACE_KPROBE_MULTI = 42
    (.set attr-mem C_INT 8 (const/attach-type->num :trace-kprobe-multi))
    ;; flags (offset 12) - main link flags, not kprobe_multi specific
    (.set attr-mem C_INT 12 0)

    ;; kprobe_multi substruct starts at offset 16
    ;; kprobe_multi.flags (offset 16) - BPF_F_KPROBE_MULTI_RETURN = 1
    (.set attr-mem C_INT 16 (if retprobe? 1 0))
    ;; kprobe_multi.cnt (offset 20)
    (.set attr-mem C_INT 20 1)  ; attaching to 1 symbol
    ;; kprobe_multi.syms (offset 24) - address of array of string pointers
    ;; We need to create an array containing one pointer to our function name
    (let [sym-ptr-array (.allocate *arena* 8 8)]  ; array of 1 pointer
      (.set sym-ptr-array C_POINTER 0 func-name-mem) ; array[0] = func_name_mem
      (.set attr-mem C_LONG 24 (.address sym-ptr-array)))  ; syms = address of array

    ;; Debug logging
    (log/info "BPF_LINK_CREATE debug:"
              "\n  prog_fd:" prog-fd
              "\n  attach_type:" (const/attach-type->num :trace-kprobe-multi)
              "\n  function:" function-name
              "\n  retprobe?:" retprobe?
              "\n  func_name_mem addr:" (.address func-name-mem)
              "\n  syms field value:" (.get attr-mem C_LONG 24))

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

;; Raw syscall bindings for XDP/netlink support

(def ^:private raw-syscall-fn
  "General-purpose syscall function for variable argument syscalls"
  (let [sym (.find libc-lookup "syscall")]
    (when (.isPresent sym)
      (let [^java.lang.foreign.MemorySegment mem-seg (.get sym)]
        ;; We'll create different handles for different signatures as needed
        {:syscall-1arg (.downcallHandle linker mem-seg
                                       (make-function-descriptor C_LONG C_LONG C_LONG)
                                       (into-array java.lang.foreign.Linker$Option []))
         :syscall-2args (.downcallHandle linker mem-seg
                                        (make-function-descriptor C_LONG C_LONG C_LONG C_LONG)
                                        (into-array java.lang.foreign.Linker$Option []))
         :syscall-3args (.downcallHandle linker mem-seg
                                        (make-function-descriptor C_LONG C_LONG C_LONG C_LONG C_LONG)
                                        (into-array java.lang.foreign.Linker$Option []))
         :syscall-4args (.downcallHandle linker mem-seg
                                        (make-function-descriptor C_LONG C_LONG C_LONG C_LONG C_LONG C_LONG)
                                        (into-array java.lang.foreign.Linker$Option []))
         :syscall-5args (.downcallHandle linker mem-seg
                                        (make-function-descriptor C_LONG C_LONG C_LONG C_LONG C_LONG C_LONG C_LONG)
                                        (into-array java.lang.foreign.Linker$Option []))
         :syscall-6args (.downcallHandle linker mem-seg
                                        (make-function-descriptor C_LONG C_LONG C_LONG C_LONG C_LONG C_LONG C_LONG C_LONG)
                                        (into-array java.lang.foreign.Linker$Option []))
         :syscall-ptr-args (.downcallHandle linker mem-seg
                                           (make-function-descriptor C_LONG C_LONG C_LONG C_POINTER C_LONG)
                                           (into-array java.lang.foreign.Linker$Option []))
         :syscall-4ptr-args (.downcallHandle linker mem-seg
                                            (make-function-descriptor C_LONG C_LONG C_LONG C_LONG C_LONG C_POINTER)
                                            (into-array java.lang.foreign.Linker$Option []))}))))

(defn raw-syscall
  "Make a raw syscall with variable arguments.

  Parameters:
  - nr: syscall number
  - args: variable arguments (integers or MemorySegments)

  Returns the syscall result (may be negative on error)"
  [nr & args]
  (when-not raw-syscall-fn
    (throw (ex-info "syscall function not available" {})))

  (let [arg-count (count args)
        has-pointer? (some #(instance? MemorySegment %) args)]
    (try
      (cond
        ;; 0 arguments (e.g., epoll_create1 with flags in nr)
        (= arg-count 0)
        (.invokeWithArguments (:syscall-1arg raw-syscall-fn)
                             [(long nr)])

        ;; 1 argument
        (and (= arg-count 1) (not has-pointer?))
        (.invokeWithArguments (:syscall-1arg raw-syscall-fn)
                             [(long nr) (long (nth args 0))])

        ;; 2 arguments (e.g., munmap)
        (and (= arg-count 2) (not has-pointer?))
        (.invokeWithArguments (:syscall-2args raw-syscall-fn)
                             [(long nr) (long (nth args 0)) (long (nth args 1))])

        ;; 3 integer arguments (e.g., socket)
        (and (= arg-count 3) (not has-pointer?))
        (.invokeWithArguments (:syscall-3args raw-syscall-fn)
                             [(long nr) (long (nth args 0)) (long (nth args 1)) (long (nth args 2))])

        ;; 4 integer arguments (e.g., epoll_wait)
        (and (= arg-count 4) (not has-pointer?))
        (.invokeWithArguments (:syscall-4args raw-syscall-fn)
                             [(long nr) (long (nth args 0)) (long (nth args 1)) (long (nth args 2)) (long (nth args 3))])

        ;; 5 integer arguments
        (and (= arg-count 5) (not has-pointer?))
        (.invokeWithArguments (:syscall-5args raw-syscall-fn)
                             [(long nr) (long (nth args 0)) (long (nth args 1)) (long (nth args 2)) (long (nth args 3)) (long (nth args 4))])

        ;; 6 integer arguments (e.g., mmap: addr, length, prot, flags, fd, offset)
        (and (= arg-count 6) (not has-pointer?))
        (.invokeWithArguments (:syscall-6args raw-syscall-fn)
                             [(long nr) (long (nth args 0)) (long (nth args 1)) (long (nth args 2)) (long (nth args 3)) (long (nth args 4)) (long (nth args 5))])

        ;; 3 arguments with pointer (e.g., bind)
        (and (= arg-count 3) (instance? MemorySegment (nth args 1)))
        (.invokeWithArguments (:syscall-ptr-args raw-syscall-fn)
                             [(long nr) (long (nth args 0)) (nth args 1) (long (nth args 2))])

        ;; 4 arguments with pointer at position 1 (e.g., sendto, recvfrom)
        (and (= arg-count 4) (instance? MemorySegment (nth args 1)))
        (.invokeWithArguments (:syscall-ptr-args raw-syscall-fn)
                             [(long nr) (long (nth args 0)) (nth args 1) (long (nth args 2))])

        ;; 4 arguments with pointer at position 3 (e.g., epoll_ctl, epoll_wait)
        (and (= arg-count 4) (instance? MemorySegment (nth args 3)))
        (.invokeWithArguments (:syscall-4ptr-args raw-syscall-fn)
                             [(long nr) (long (nth args 0)) (long (nth args 1)) (long (nth args 2)) (nth args 3)])

        :else
        (throw (ex-info "Unsupported syscall signature"
                       {:nr nr :arg-count arg-count :args args :has-pointer has-pointer?})))
      (catch Exception e
        (throw (ex-info "Syscall failed" {:nr nr :args args :cause e}))))))

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

;; ============================================================================
;; BPF_PROG_TEST_RUN Support
;; ============================================================================
;;
;; BPF_PROG_TEST_RUN (command 10) allows running BPF programs in test mode
;; without attaching them to hooks. This is essential for:
;; - Unit testing BPF programs
;; - CI/CD integration
;; - Validating program behavior with synthetic inputs

(defrecord ProgTestRunAttr
  [^int prog-fd
   ^int retval              ;; Output: return value from program
   ^int data-size-in        ;; Input: size of data_in
   ^int data-size-out       ;; Input/Output: size of data_out buffer / actual size
   ^MemorySegment data-in   ;; Input: packet/context data
   ^MemorySegment data-out  ;; Output: modified data
   ^int repeat              ;; Number of times to run (for benchmarking)
   ^long duration           ;; Output: execution time in nanoseconds
   ^int ctx-size-in         ;; Input: size of ctx_in
   ^int ctx-size-out        ;; Input/Output: size of ctx_out buffer / actual size
   ^MemorySegment ctx-in    ;; Input: context data
   ^MemorySegment ctx-out   ;; Output: modified context
   ^int flags               ;; Flags
   ^int cpu])               ;; CPU to run on (-1 for any)

(defn prog-test-run-attr->segment
  "Convert ProgTestRunAttr to MemorySegment for syscall.

   bpf_attr for BPF_PROG_TEST_RUN layout:
   offset 0:  prog_fd (u32)
   offset 4:  retval (u32) - output
   offset 8:  data_size_in (u32)
   offset 12: data_size_out (u32) - input/output
   offset 16: data_in (u64 pointer)
   offset 24: data_out (u64 pointer)
   offset 32: repeat (u32)
   offset 36: duration (u32) - output, nanoseconds
   offset 40: ctx_size_in (u32)
   offset 44: ctx_size_out (u32) - input/output
   offset 48: ctx_in (u64 pointer)
   offset 56: ctx_out (u64 pointer)
   offset 64: flags (u32)
   offset 68: cpu (u32)"
  [attr]
  (let [mem (allocate-zeroed 128)]
    ;; prog_fd
    (.set mem C_INT 0 (:prog-fd attr))
    ;; data_size_in
    (.set mem C_INT 8 (:data-size-in attr))
    ;; data_size_out
    (.set mem C_INT 12 (:data-size-out attr))
    ;; data_in pointer
    (when (:data-in attr)
      (.set mem C_LONG 16 (.address ^MemorySegment (:data-in attr))))
    ;; data_out pointer
    (when (:data-out attr)
      (.set mem C_LONG 24 (.address ^MemorySegment (:data-out attr))))
    ;; repeat
    (.set mem C_INT 32 (:repeat attr))
    ;; ctx_size_in
    (.set mem C_INT 40 (:ctx-size-in attr))
    ;; ctx_size_out
    (.set mem C_INT 44 (:ctx-size-out attr))
    ;; ctx_in pointer
    (when (:ctx-in attr)
      (.set mem C_LONG 48 (.address ^MemorySegment (:ctx-in attr))))
    ;; ctx_out pointer
    (when (:ctx-out attr)
      (.set mem C_LONG 56 (.address ^MemorySegment (:ctx-out attr))))
    ;; flags
    (.set mem C_INT 64 (:flags attr))
    ;; cpu
    (.set mem C_INT 68 (:cpu attr))
    mem))

(defn prog-test-run
  "Run a BPF program in test mode with synthetic input.

   This uses the BPF_PROG_TEST_RUN command to execute a BPF program
   without attaching it to a real hook.

   Parameters:
   - prog-fd: Program file descriptor
   - opts: Map with:
     - :data-in - Input data as byte array (e.g., packet data)
     - :data-size-out - Size of output buffer (default: size of data-in or 256)
     - :ctx-in - Context data as byte array (program-type specific)
     - :ctx-size-out - Size of context output buffer (default: 0)
     - :repeat - Number of times to run (default: 1, for benchmarking)
     - :flags - Test run flags (default: 0)
     - :cpu - CPU to run on (default: 0, use -1 for any)

   Returns a map with:
   - :retval - Return value from BPF program (e.g., XDP_PASS=2, XDP_DROP=1)
   - :data-out - Output data (byte array, modified packet)
   - :ctx-out - Output context (byte array, if ctx-size-out > 0)
   - :duration-ns - Execution time in nanoseconds (average if repeat > 1)
   - :data-size-out - Actual size of output data

   Example:
   ```clojure
   ;; Test an XDP program
   (let [packet (byte-array [...])
         result (prog-test-run prog-fd {:data-in packet :repeat 1000})]
     (println \"Return value:\" (:retval result))
     (println \"Duration:\" (:duration-ns result) \"ns\"))
   ```

   Supported program types:
   - XDP (xdp_md context)
   - Sched CLS/ACT (sk_buff context)
   - Socket filter
   - Raw tracepoint
   - Flow dissector"
  [prog-fd {:keys [data-in data-size-out ctx-in ctx-size-out repeat flags cpu]
            :or {data-size-out nil
                 ctx-in nil
                 ctx-size-out 0
                 repeat 1
                 flags 0
                 cpu 0}}]
  (let [;; Calculate sizes
        data-in-size (if data-in (count data-in) 0)
        data-out-size (or data-size-out (max data-in-size 256))
        ctx-in-size (if ctx-in (count ctx-in) 0)
        ctx-out-size (or ctx-size-out 0)

        ;; Allocate memory segments
        data-in-mem (when (pos? data-in-size)
                      (let [mem (allocate-zeroed data-in-size)]
                        (MemorySegment/copy (MemorySegment/ofArray data-in) 0
                                           mem 0 data-in-size)
                        mem))
        data-out-mem (when (pos? data-out-size)
                       (allocate-zeroed data-out-size))
        ctx-in-mem (when (pos? ctx-in-size)
                     (let [mem (allocate-zeroed ctx-in-size)]
                       (MemorySegment/copy (MemorySegment/ofArray ctx-in) 0
                                          mem 0 ctx-in-size)
                       mem))
        ctx-out-mem (when (pos? ctx-out-size)
                      (allocate-zeroed ctx-out-size))

        ;; Build attr structure
        attr (->ProgTestRunAttr
              prog-fd
              0                    ; retval (output)
              data-in-size
              data-out-size
              data-in-mem
              data-out-mem
              repeat
              0                    ; duration (output)
              ctx-in-size
              ctx-out-size
              ctx-in-mem
              ctx-out-mem
              flags
              cpu)
        attr-mem (prog-test-run-attr->segment attr)]

    ;; Execute syscall
    (bpf-syscall :prog-test-run attr-mem)

    ;; Read results from attr structure
    (let [retval (.get attr-mem C_INT 4)
          actual-data-size-out (.get attr-mem C_INT 12)
          duration (.get attr-mem C_INT 36)
          actual-ctx-size-out (.get attr-mem C_INT 44)

          ;; Extract output data
          data-out (when (and data-out-mem (pos? actual-data-size-out))
                     (let [out (byte-array actual-data-size-out)]
                       (MemorySegment/copy data-out-mem 0
                                          (MemorySegment/ofArray out) 0
                                          actual-data-size-out)
                       out))
          ctx-out (when (and ctx-out-mem (pos? actual-ctx-size-out))
                    (let [out (byte-array actual-ctx-size-out)]
                      (MemorySegment/copy ctx-out-mem 0
                                         (MemorySegment/ofArray out) 0
                                         actual-ctx-size-out)
                      out))]

      {:retval retval
       :data-out data-out
       :data-size-out actual-data-size-out
       :ctx-out ctx-out
       :ctx-size-out actual-ctx-size-out
       :duration-ns duration})))
