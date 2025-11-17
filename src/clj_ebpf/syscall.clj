(ns clj-ebpf.syscall
  "Low-level BPF syscall interface using JNA"
  (:require [clj-ebpf.constants :as const]
            [clojure.tools.logging :as log])
  (:import [com.sun.jna Native Pointer Memory Structure Platform]
           [com.sun.jna.ptr IntByReference LongByReference PointerByReference]))

;; Load libc for syscall
(def ^:private libc
  (com.sun.jna.NativeLibrary/getInstance
    (if (Platform/isMac) "c" "c")))

(def ^:private syscall-fn
  (.getFunction libc "syscall"))

;; Get errno
(defn get-errno
  "Get the last errno value"
  []
  (Native/getLastError))

(defn errno->keyword
  "Convert errno number to keyword"
  [errno-num]
  (or (some (fn [[k v]] (when (= v errno-num) k)) const/errno)
      :unknown))

;; BPF attribute structures
;; These mirror the C union bpf_attr from linux/bpf.h

(defrecord MapCreateAttr
  [^int map-type
   ^int key-size
   ^int value-size
   ^int max-entries
   ^int map-flags
   ^int inner-map-fd
   ^int numa-node
   ^String map-name
   ^int map-ifindex
   ^int btf-fd
   ^int btf-key-type-id
   ^int btf-value-type-id
   ^int btf-vmlinux-value-type-id
   ^long map-extra])

(defn map-create-attr->array
  "Convert MapCreateAttr to byte array for syscall"
  [attr]
  (let [mem (Memory. 128)] ; bpf_attr is 128 bytes
    (.setInt mem 0 (:map-type attr))
    (.setInt mem 4 (:key-size attr))
    (.setInt mem 8 (:value-size attr))
    (.setInt mem 12 (:max-entries attr))
    (.setInt mem 16 (:map-flags attr))
    (when (:inner-map-fd attr)
      (.setInt mem 20 (:inner-map-fd attr)))
    (when (:numa-node attr)
      (.setInt mem 24 (:numa-node attr)))
    (when (:map-name attr)
      (let [name-bytes (.getBytes (:map-name attr) "UTF-8")
            len (min (count name-bytes) (dec const/BPF_OBJ_NAME_LEN))]
        (.write mem 28 name-bytes 0 len)
        (.setByte mem (+ 28 len) 0))) ; null terminate
    (when (:map-ifindex attr)
      (.setInt mem 44 (:map-ifindex attr)))
    (when (:btf-fd attr)
      (.setInt mem 48 (:btf-fd attr)))
    (when (:btf-key-type-id attr)
      (.setInt mem 52 (:btf-key-type-id attr)))
    (when (:btf-value-type-id attr)
      (.setInt mem 56 (:btf-value-type-id attr)))
    (when (:btf-vmlinux-value-type-id attr)
      (.setInt mem 60 (:btf-vmlinux-value-type-id attr)))
    (when (:map-extra attr)
      (.setLong mem 64 (:map-extra attr)))
    mem))

(defrecord MapElemAttr
  [^int map-fd
   ^Pointer key
   ^Pointer value
   ^long flags])

(defn map-elem-attr->array
  "Convert MapElemAttr to byte array for syscall"
  [attr]
  (let [mem (Memory. 128)]
    (.setInt mem 0 (:map-fd attr))
    (.setLong mem 8 (Pointer/nativeValue (:key attr)))
    (.setLong mem 16 (Pointer/nativeValue (or (:value attr) Pointer/NULL)))
    (.setLong mem 24 (:flags attr))
    mem))

(defrecord MapNextKeyAttr
  [^int map-fd
   ^Pointer key
   ^Pointer next-key])

(defn map-next-key-attr->array
  "Convert MapNextKeyAttr to byte array for syscall"
  [attr]
  (let [mem (Memory. 128)]
    (.setInt mem 0 (:map-fd attr))
    (.setLong mem 8 (Pointer/nativeValue (or (:key attr) Pointer/NULL)))
    (.setLong mem 16 (Pointer/nativeValue (:next-key attr)))
    mem))

(defrecord ProgLoadAttr
  [^int prog-type
   ^int insn-cnt
   ^Pointer insns
   ^String license
   ^int log-level
   ^int log-size
   ^Pointer log-buf
   ^int kern-version
   ^int prog-flags
   ^String prog-name
   ^int prog-ifindex
   ^int expected-attach-type
   ^int prog-btf-fd
   ^int func-info-rec-size
   ^Pointer func-info
   ^int func-info-cnt
   ^int line-info-rec-size
   ^Pointer line-info
   ^int line-info-cnt
   ^int attach-btf-id
   ^int attach-prog-fd])

(defn prog-load-attr->array
  "Convert ProgLoadAttr to byte array for syscall"
  [attr]
  (let [mem (Memory. 128)]
    (.setInt mem 0 (:prog-type attr))
    (.setInt mem 4 (:insn-cnt attr))
    (.setLong mem 8 (Pointer/nativeValue (:insns attr)))
    (when (:license attr)
      (let [lic-bytes (.getBytes (:license attr) "UTF-8")
            lic-mem (Memory. (inc (count lic-bytes)))]
        (.write lic-mem 0 lic-bytes 0 (count lic-bytes))
        (.setByte lic-mem (count lic-bytes) 0)
        (.setLong mem 16 (Pointer/nativeValue lic-mem))))
    (.setInt mem 24 (or (:log-level attr) 0))
    (.setInt mem 28 (or (:log-size attr) 0))
    (.setLong mem 32 (Pointer/nativeValue (or (:log-buf attr) Pointer/NULL)))
    (.setInt mem 40 (or (:kern-version attr) 0))
    (.setInt mem 44 (or (:prog-flags attr) 0))
    (when (:prog-name attr)
      (let [name-bytes (.getBytes (:prog-name attr) "UTF-8")
            len (min (count name-bytes) (dec const/BPF_OBJ_NAME_LEN))]
        (.write mem 48 name-bytes 0 len)
        (.setByte mem (+ 48 len) 0)))
    (when (:prog-ifindex attr)
      (.setInt mem 64 (:prog-ifindex attr)))
    (when (:expected-attach-type attr)
      (.setInt mem 68 (:expected-attach-type attr)))
    (when (:prog-btf-fd attr)
      (.setInt mem 72 (:prog-btf-fd attr)))
    (when (:func-info-rec-size attr)
      (.setInt mem 76 (:func-info-rec-size attr)))
    (when (:func-info attr)
      (.setLong mem 80 (Pointer/nativeValue (:func-info attr))))
    (when (:func-info-cnt attr)
      (.setInt mem 88 (:func-info-cnt attr)))
    (when (:line-info-rec-size attr)
      (.setInt mem 92 (:line-info-rec-size attr)))
    (when (:line-info attr)
      (.setLong mem 96 (Pointer/nativeValue (:line-info attr))))
    (when (:line-info-cnt attr)
      (.setInt mem 104 (:line-info-cnt attr)))
    (when (:attach-btf-id attr)
      (.setInt mem 108 (:attach-btf-id attr)))
    (when (:attach-prog-fd attr)
      (.setInt mem 112 (:attach-prog-fd attr)))
    mem))

(defrecord ObjPinAttr
  [^String pathname
   ^int bpf-fd
   ^int file-flags])

(defn obj-pin-attr->array
  "Convert ObjPinAttr to byte array for syscall"
  [attr]
  (let [mem (Memory. 128)
        path-bytes (.getBytes (:pathname attr) "UTF-8")
        path-mem (Memory. (inc (count path-bytes)))]
    (.write path-mem 0 path-bytes 0 (count path-bytes))
    (.setByte path-mem (count path-bytes) 0)
    (.setLong mem 0 (Pointer/nativeValue path-mem))
    (.setInt mem 8 (:bpf-fd attr))
    (.setInt mem 12 (or (:file-flags attr) 0))
    mem))

(defrecord RawTracepointAttr
  [^String name
   ^int prog-fd])

(defn raw-tracepoint-attr->array
  "Convert RawTracepointAttr to byte array for syscall"
  [attr]
  (let [mem (Memory. 128)
        name-bytes (.getBytes (:name attr) "UTF-8")
        name-mem (Memory. (inc (count name-bytes)))]
    (.write name-mem 0 name-bytes 0 (count name-bytes))
    (.setByte name-mem (count name-bytes) 0)
    (.setLong mem 0 (Pointer/nativeValue name-mem))
    (.setInt mem 8 (:prog-fd attr))
    mem))

;; Main syscall function
(defn bpf-syscall
  "Make a BPF syscall with the given command and attributes"
  [cmd attr-mem]
  (let [cmd-num (if (keyword? cmd)
                  (const/cmd->num cmd)
                  cmd)
        result (.invokeLong syscall-fn
                           (into-array Object
                                      [Long (long const/BPF_SYSCALL_NR)
                                       Integer (int cmd-num)
                                       Pointer attr-mem
                                       Integer (int 128)]))] ; attr size
    (if (< result 0)
      (let [errno (get-errno)
            errno-kw (errno->keyword errno)]
        (log/error "BPF syscall failed:" cmd "errno:" errno errno-kw)
        (throw (ex-info (str "BPF syscall failed: " cmd " - " errno-kw)
                        {:command cmd
                         :errno errno
                         :errno-keyword errno-kw})))
      result)))

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
        mem (map-create-attr->array attr)]
    (int (bpf-syscall :map-create mem))))

(defn map-lookup-elem
  "Lookup element in BPF map"
  [map-fd key-ptr value-ptr]
  (let [attr (->MapElemAttr map-fd key-ptr value-ptr 0)
        mem (map-elem-attr->array attr)]
    (bpf-syscall :map-lookup-elem mem)))

(defn map-update-elem
  "Update element in BPF map"
  [map-fd key-ptr value-ptr flags]
  (let [attr (->MapElemAttr map-fd key-ptr value-ptr flags)
        mem (map-elem-attr->array attr)]
    (bpf-syscall :map-update-elem mem)))

(defn map-delete-elem
  "Delete element from BPF map"
  [map-fd key-ptr]
  (let [attr (->MapElemAttr map-fd key-ptr nil 0)
        mem (map-elem-attr->array attr)]
    (bpf-syscall :map-delete-elem mem)))

(defn map-get-next-key
  "Get next key in BPF map (for iteration)"
  [map-fd key-ptr next-key-ptr]
  (let [attr (->MapNextKeyAttr map-fd key-ptr next-key-ptr)
        mem (map-next-key-attr->array attr)]
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
        mem (prog-load-attr->array attr)]
    (int (bpf-syscall :prog-load mem))))

(defn obj-pin
  "Pin BPF object to filesystem"
  [pathname bpf-fd & {:keys [file-flags] :or {file-flags 0}}]
  (let [attr (->ObjPinAttr pathname bpf-fd file-flags)
        mem (obj-pin-attr->array attr)]
    (bpf-syscall :obj-pin mem)))

(defn obj-get
  "Get BPF object from filesystem"
  [pathname & {:keys [file-flags] :or {file-flags 0}}]
  (let [attr (->ObjPinAttr pathname 0 file-flags)
        mem (obj-pin-attr->array attr)]
    (int (bpf-syscall :obj-get mem))))

(defn raw-tracepoint-open
  "Open a raw tracepoint and attach BPF program"
  [name prog-fd]
  (let [attr (->RawTracepointAttr name prog-fd)
        mem (raw-tracepoint-attr->array attr)]
    (int (bpf-syscall :raw-tracepoint-open mem))))

;; Perf event syscall (needed for kprobes)
(def ^:private perf-event-open-fn
  (.getFunction libc "perf_event_open"))

(defn perf-event-open
  "Open a perf event (used for kprobes/uprobes)"
  [event-type config pid cpu group-fd flags]
  (let [attr-mem (Memory. 128)] ; struct perf_event_attr
    ;; Initialize the structure
    (.clear attr-mem)
    ;; type
    (.setInt attr-mem 0 event-type)
    ;; size
    (.setInt attr-mem 4 128)
    ;; config
    (.setLong attr-mem 8 config)
    ;; sample_period / sample_freq union - set to 1
    (.setLong attr-mem 16 1)
    ;; sample_type
    (.setLong attr-mem 24 0)
    ;; read_format
    (.setLong attr-mem 32 0)
    ;; flags as bitfield (disabled=1, others=0)
    (.setLong attr-mem 40 1) ; disabled flag

    (let [result (.invokeInt perf-event-open-fn
                             (into-array Object
                                        [Pointer attr-mem
                                         Integer (int pid)
                                         Integer (int cpu)
                                         Integer (int group-fd)
                                         Long (long flags)]))]
      (if (< result 0)
        (let [errno (get-errno)
              errno-kw (errno->keyword errno)]
          (log/error "perf_event_open failed, errno:" errno errno-kw)
          (throw (ex-info (str "perf_event_open failed: " errno-kw)
                          {:errno errno
                           :errno-keyword errno-kw
                           :event-type event-type
                           :config config})))
        result))))

;; IOCTL syscall (needed for enabling perf events and attaching BPF)
(def ^:private ioctl-fn
  (.getFunction libc "ioctl"))

(defn ioctl
  "Make an ioctl syscall"
  ([fd request]
   (ioctl fd request nil))
  ([fd request arg]
   (let [result (if arg
                  (.invokeInt ioctl-fn
                             (into-array Object [Integer (int fd)
                                                Long (long request)
                                                Integer (int arg)]))
                  (.invokeInt ioctl-fn
                             (into-array Object [Integer (int fd)
                                                Long (long request)])))]
     (when (< result 0)
       (let [errno (get-errno)
             errno-kw (errno->keyword errno)]
         (log/error "ioctl failed, errno:" errno errno-kw)
         (throw (ex-info (str "ioctl failed: " errno-kw)
                         {:fd fd
                          :request request
                          :errno errno
                          :errno-keyword errno-kw}))))
     result)))

;; Close file descriptor
(def ^:private close-fn
  (.getFunction libc "close"))

(defn close-fd
  "Close a file descriptor"
  [fd]
  (when (and fd (>= fd 0))
    (.invokeInt close-fn (into-array Object [Integer (int fd)]))))
