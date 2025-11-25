(ns clj-ebpf.internal.memory
  "Low-level memory management using Panama FFI.

   This namespace provides the foundational memory primitives used throughout
   clj-ebpf. It wraps Java's Foreign Function & Memory API (Panama) to provide
   a Clojure-friendly interface for:

   - Memory allocation and deallocation
   - Reading and writing primitive types
   - Memory segment manipulation
   - Buffer management for BPF operations

   INTERNAL: This namespace is for internal use only. Public APIs should use
   clj-ebpf.utils for memory operations."
  (:import [java.lang.foreign Arena MemorySegment ValueLayout MemoryLayout]
           [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; Arena Management
;; ============================================================================

(def ^:private ^:dynamic *arena*
  "Default arena for memory allocations. Uses auto-managed arena by default."
  (Arena/ofAuto))

(defn create-confined-arena
  "Create a confined arena for explicit memory management.
   Must be closed when done."
  []
  (Arena/ofConfined))

(defn create-shared-arena
  "Create a shared arena for multi-threaded access.
   Must be closed when done."
  []
  (Arena/ofShared))

(defn create-auto-arena
  "Create an auto-managed arena (GC-collected)."
  []
  (Arena/ofAuto))

(defmacro with-confined-arena
  "Execute body with a confined arena that is closed after execution."
  [& body]
  `(let [arena# (Arena/ofConfined)]
     (try
       (binding [*arena* arena#]
         ~@body)
       (finally
         (.close arena#)))))

(defmacro with-shared-arena
  "Execute body with a shared arena that is closed after execution."
  [& body]
  `(let [arena# (Arena/ofShared)]
     (try
       (binding [*arena* arena#]
         ~@body)
       (finally
         (.close arena#)))))

;; ============================================================================
;; Value Layouts
;; ============================================================================

(def ^ValueLayout C_BYTE ValueLayout/JAVA_BYTE)
(def ^ValueLayout C_SHORT ValueLayout/JAVA_SHORT)
(def ^ValueLayout C_INT ValueLayout/JAVA_INT)
(def ^ValueLayout C_LONG ValueLayout/JAVA_LONG)
(def ^ValueLayout C_FLOAT ValueLayout/JAVA_FLOAT)
(def ^ValueLayout C_DOUBLE ValueLayout/JAVA_DOUBLE)
(def ^ValueLayout C_POINTER ValueLayout/ADDRESS)

;; Native-endian layouts
(def ^ValueLayout C_SHORT_LE (.withOrder ValueLayout/JAVA_SHORT ByteOrder/LITTLE_ENDIAN))
(def ^ValueLayout C_INT_LE (.withOrder ValueLayout/JAVA_INT ByteOrder/LITTLE_ENDIAN))
(def ^ValueLayout C_LONG_LE (.withOrder ValueLayout/JAVA_LONG ByteOrder/LITTLE_ENDIAN))
(def ^ValueLayout C_SHORT_BE (.withOrder ValueLayout/JAVA_SHORT ByteOrder/BIG_ENDIAN))
(def ^ValueLayout C_INT_BE (.withOrder ValueLayout/JAVA_INT ByteOrder/BIG_ENDIAN))
(def ^ValueLayout C_LONG_BE (.withOrder ValueLayout/JAVA_LONG ByteOrder/BIG_ENDIAN))

;; ============================================================================
;; Memory Allocation
;; ============================================================================

(defn allocate
  "Allocate native memory of given size with optional alignment.
   Returns a MemorySegment."
  ([size]
   (.allocate *arena* (long size) 8))
  ([size alignment]
   (.allocate *arena* (long size) (long alignment))))

(defn allocate-zeroed
  "Allocate zeroed native memory of given size."
  [size]
  (let [seg (allocate size)]
    (.fill seg (byte 0))
    seg))

(defn allocate-array
  "Allocate an array of elements with the given layout."
  [^MemoryLayout element-layout count]
  (.allocate *arena* element-layout (long count)))

;; ============================================================================
;; Memory Reading
;; ============================================================================

(defn read-byte
  "Read a byte from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_BYTE (long offset)))

(defn read-short
  "Read a short from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_SHORT (long offset)))

(defn read-short-le
  "Read a little-endian short from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_SHORT_LE (long offset)))

(defn read-short-be
  "Read a big-endian short from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_SHORT_BE (long offset)))

(defn read-int
  "Read an int from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_INT (long offset)))

(defn read-int-le
  "Read a little-endian int from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_INT_LE (long offset)))

(defn read-int-be
  "Read a big-endian int from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_INT_BE (long offset)))

(defn read-long
  "Read a long from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_LONG (long offset)))

(defn read-long-le
  "Read a little-endian long from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_LONG_LE (long offset)))

(defn read-long-be
  "Read a big-endian long from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_LONG_BE (long offset)))

(defn read-pointer
  "Read a pointer from memory segment at offset."
  [^MemorySegment seg offset]
  (.get seg C_POINTER (long offset)))

;; ============================================================================
;; Memory Writing
;; ============================================================================

(defn write-byte
  "Write a byte to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_BYTE (long offset) (byte value)))

(defn write-short
  "Write a short to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_SHORT (long offset) (short value)))

(defn write-short-le
  "Write a little-endian short to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_SHORT_LE (long offset) (short value)))

(defn write-short-be
  "Write a big-endian short to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_SHORT_BE (long offset) (short value)))

(defn write-int
  "Write an int to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_INT (long offset) (int value)))

(defn write-int-le
  "Write a little-endian int to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_INT_LE (long offset) (int value)))

(defn write-int-be
  "Write a big-endian int to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_INT_BE (long offset) (int value)))

(defn write-long
  "Write a long to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_LONG (long offset) (long value)))

(defn write-long-le
  "Write a little-endian long to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_LONG_LE (long offset) (long value)))

(defn write-long-be
  "Write a big-endian long to memory segment at offset."
  [^MemorySegment seg offset value]
  (.set seg C_LONG_BE (long offset) (long value)))

(defn write-pointer
  "Write a pointer to memory segment at offset."
  [^MemorySegment seg offset ^MemorySegment value]
  (.set seg C_POINTER (long offset) value))

;; ============================================================================
;; Bulk Operations
;; ============================================================================

(defn copy-segment
  "Copy bytes from src segment to dst segment."
  [^MemorySegment dst dst-offset ^MemorySegment src src-offset length]
  (MemorySegment/copy src (long src-offset) dst (long dst-offset) (long length)))

(defn segment->bytes
  "Read bytes from a memory segment into a byte array."
  [^MemorySegment seg size]
  (when (and seg (not= seg MemorySegment/NULL))
    (let [bytes (byte-array size)]
      (MemorySegment/copy seg 0 (MemorySegment/ofArray bytes) 0 size)
      bytes)))

(defn bytes->segment
  "Write bytes from a byte array to a new memory segment."
  [^bytes bytes]
  (when bytes
    (let [seg (allocate (count bytes) 1)
          src (MemorySegment/ofArray bytes)]
      (MemorySegment/copy src 0 seg 0 (count bytes))
      seg)))

(defn zero-memory
  "Zero out memory segment."
  [^MemorySegment seg size]
  (.fill (.asSlice seg 0 (long size)) (byte 0)))

(defn fill-memory
  "Fill memory segment with a byte value."
  [^MemorySegment seg size value]
  (.fill (.asSlice seg 0 (long size)) (byte value)))

;; ============================================================================
;; Segment Slicing
;; ============================================================================

(defn slice
  "Create a slice of a memory segment."
  [^MemorySegment seg offset size]
  (.asSlice seg (long offset) (long size)))

(defn reinterpret
  "Reinterpret a memory segment with a new size."
  [^MemorySegment seg new-size]
  (.reinterpret seg (long new-size)))

(defn segment-size
  "Get the size of a memory segment."
  [^MemorySegment seg]
  (.byteSize seg))

(defn null-segment?
  "Check if a memory segment is NULL."
  [^MemorySegment seg]
  (or (nil? seg) (= seg MemorySegment/NULL)))

(def NULL-SEGMENT MemorySegment/NULL)

;; ============================================================================
;; Buffer Conversions
;; ============================================================================

(defn segment->buffer
  "Create a ByteBuffer view of a memory segment."
  [^MemorySegment seg]
  (.asByteBuffer seg))

(defn wrap-bytes
  "Wrap a byte array as a memory segment (no copy)."
  [^bytes bytes]
  (MemorySegment/ofArray bytes))

;; ============================================================================
;; String Operations
;; ============================================================================

(defn string->segment
  "Convert a string to a null-terminated memory segment."
  [^String s]
  (when s
    (let [bytes (.getBytes s "UTF-8")
          seg (allocate (inc (count bytes)) 1)]
      (MemorySegment/copy (MemorySegment/ofArray bytes) 0 seg 0 (count bytes))
      (write-byte seg (count bytes) 0)  ; null terminator
      seg)))

(defn segment->string
  "Read a null-terminated string from a memory segment."
  ([^MemorySegment seg]
   (segment->string seg 256))
  ([^MemorySegment seg max-len]
   (when (and seg (not= seg MemorySegment/NULL))
     (let [bytes (byte-array max-len)]
       (loop [i 0]
         (if (< i max-len)
           (let [b (read-byte seg i)]
             (if (zero? b)
               (String. bytes 0 i "UTF-8")
               (do (aset bytes i b)
                   (recur (inc i)))))
           (String. bytes "UTF-8")))))))

;; ============================================================================
;; Address Operations
;; ============================================================================

(defn segment-address
  "Get the native address of a memory segment."
  [^MemorySegment seg]
  (.address seg))

(defn from-address
  "Create a memory segment from a native address.
   Warning: This is unsafe and should be used carefully."
  [address size]
  (MemorySegment/ofAddress address))
