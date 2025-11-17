(ns clj-ebpf.utils
  "Utility functions for BPF programming using Panama FFI"
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.lang.foreign Arena MemorySegment ValueLayout]
           [java.nio ByteBuffer ByteOrder]))

;; Arena for memory allocation (auto-managed by GC)
(def ^:private ^:dynamic *arena* (Arena/ofAuto))

;; Value layouts
(def ^:private C_INT ValueLayout/JAVA_INT)
(def ^:private C_LONG ValueLayout/JAVA_LONG)
(def ^:private C_SHORT ValueLayout/JAVA_SHORT)
(def ^:private C_BYTE ValueLayout/JAVA_BYTE)

;; Memory allocation and management

(defn allocate-memory
  "Allocate native memory of given size"
  [size]
  (.allocate *arena* (long size) 8))

(defn segment->bytes
  "Read bytes from a memory segment"
  [^MemorySegment seg size]
  (when (and seg (not= seg MemorySegment/NULL))
    (let [bytes (byte-array size)]
      (MemorySegment/copy seg 0 (MemorySegment/ofArray bytes) 0 size)
      bytes)))

(defn bytes->segment
  "Write bytes to a newly allocated memory segment"
  [^bytes bytes]
  (when bytes
    (let [seg (.allocate *arena* (long (count bytes)) 1)
          src (MemorySegment/ofArray bytes)]
      (MemorySegment/copy src 0 seg 0 (count bytes))
      seg)))

(defn zero-memory
  "Zero out memory segment"
  [^MemorySegment seg size]
  (.fill (.asSlice seg 0 size) (byte 0)))

;; Endianness utilities

(defn host-endian?
  "Check if host is little-endian"
  []
  (= (.order (ByteBuffer/allocate 1)) ByteOrder/LITTLE_ENDIAN))

;; Integer encoding/decoding

(defn int->bytes
  "Convert 32-bit integer to byte array (little-endian)"
  [^long n]
  (let [bb (ByteBuffer/allocate 4)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.putInt bb (int n))
    (.array bb)))

(defn bytes->int
  "Convert byte array to 32-bit integer (little-endian)"
  [^bytes bytes]
  (let [bb (ByteBuffer/wrap bytes)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getInt bb)))

(defn long->bytes
  "Convert 64-bit long to byte array (little-endian)"
  [^long n]
  (let [bb (ByteBuffer/allocate 8)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.putLong bb n)
    (.array bb)))

(defn bytes->long
  "Convert byte array to 64-bit long (little-endian)"
  [^bytes bytes]
  (let [bb (ByteBuffer/wrap bytes)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getLong bb)))

(defn short->bytes
  "Convert 16-bit short to byte array (little-endian)"
  [^long n]
  (let [bb (ByteBuffer/allocate 2)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.putShort bb (short n))
    (.array bb)))

(defn bytes->short
  "Convert byte array to 16-bit short (little-endian)"
  [^bytes bytes]
  (let [bb (ByteBuffer/wrap bytes)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getShort bb)))

;; CPU detection

(defn get-cpu-count
  "Get the number of CPUs available on the system.

  This is used for per-CPU map operations, where each CPU has its own
  independent value for each key. Returns the number of available processors."
  []
  (.availableProcessors (Runtime/getRuntime)))

;; Per-CPU serialization helpers

(defn percpu-values->bytes
  "Serialize a vector of per-CPU values into a flat byte array.

  Parameters:
  - values: Vector of values, one per CPU (or single value to replicate to all CPUs)
  - value-serializer: Function to serialize each value to bytes
  - value-size: Size of each value in bytes
  - num-cpus: Number of CPUs (defaults to system CPU count)

  Returns a byte array of size (value-size * num-cpus)"
  [values value-serializer value-size & {:keys [num-cpus] :or {num-cpus (get-cpu-count)}}]
  (let [values-vec (if (vector? values) values (vec (repeat num-cpus values)))
        _ (when (not= (count values-vec) num-cpus)
            (throw (ex-info "Per-CPU values vector size must match CPU count"
                           {:expected num-cpus :got (count values-vec)})))
        result (byte-array (* value-size num-cpus))]
    (doseq [cpu (range num-cpus)]
      (let [value-bytes (value-serializer (nth values-vec cpu))
            offset (* cpu value-size)]
        (System/arraycopy value-bytes 0 result offset value-size)))
    result))

(defn bytes->percpu-values
  "Deserialize a flat byte array into a vector of per-CPU values.

  Parameters:
  - bytes: Byte array of size (value-size * num-cpus)
  - value-deserializer: Function to deserialize bytes to value
  - value-size: Size of each value in bytes
  - num-cpus: Number of CPUs (defaults to system CPU count)

  Returns a vector of values, one per CPU"
  [^bytes bytes value-deserializer value-size & {:keys [num-cpus] :or {num-cpus (get-cpu-count)}}]
  (let [expected-size (* value-size num-cpus)]
    (when (not= (alength bytes) expected-size)
      (throw (ex-info "Per-CPU byte array size mismatch"
                     {:expected expected-size :got (alength bytes)})))
    (vec (for [cpu (range num-cpus)]
           (let [offset (* cpu value-size)
                 value-bytes (byte-array value-size)]
             (System/arraycopy bytes offset value-bytes 0 value-size)
             (value-deserializer value-bytes))))))

;; MemorySegment helpers

(defn int->segment
  "Convert integer to memory segment"
  [^long n]
  (let [seg (.allocate *arena* C_INT)]
    (.set seg C_INT 0 (int n))
    seg))

(defn segment->int
  "Read integer from memory segment"
  [^MemorySegment seg]
  (when (and seg (not= seg MemorySegment/NULL))
    (.get seg C_INT 0)))

(defn long->segment
  "Convert long to memory segment"
  [^long n]
  (let [seg (.allocate *arena* C_LONG)]
    (.set seg C_LONG 0 n)
    seg))

(defn segment->long
  "Read long from memory segment"
  [^MemorySegment seg]
  (when (and seg (not= seg MemorySegment/NULL))
    (.get seg C_LONG 0)))

;; Compatibility aliases for code that used pointer names
(def pointer->bytes segment->bytes)
(def bytes->pointer bytes->segment)
(def pointer->int segment->int)
(def int->pointer int->segment)
(def pointer->long segment->long)
(def long->pointer long->segment)

;; String utilities

(defn string->segment
  "Convert string to null-terminated memory segment"
  [^String s]
  (when s
    (let [bytes (.getBytes s "UTF-8")
          seg (.allocate *arena* (inc (count bytes)) 1)
          src (MemorySegment/ofArray bytes)]
      (MemorySegment/copy src 0 seg 0 (count bytes))
      ;; Set null terminator at the last byte
      (let [null-bytes (byte-array 1)]
        (aset null-bytes 0 (byte 0))
        (MemorySegment/copy (MemorySegment/ofArray null-bytes) 0 seg (count bytes) 1))
      seg)))

(defn segment->string
  "Read null-terminated string from memory segment"
  [^MemorySegment seg max-len]
  (when (and seg (not= seg MemorySegment/NULL))
    (let [actual-len (min (.byteSize seg) max-len)
          bytes (segment->bytes seg actual-len)
          null-idx (or (first (keep-indexed #(when (zero? %2) %1) bytes))
                      actual-len)]
      (String. bytes 0 null-idx "UTF-8"))))

;; Compatibility alias
(def pointer->string segment->string)
(def string->pointer string->segment)

;; File system utilities

(defn file-exists?
  "Check if file exists"
  [path]
  (.exists (io/file path)))

(defn read-file-bytes
  "Read entire file as byte array"
  [path]
  (with-open [in (io/input-stream path)]
    (let [bytes (byte-array (.available in))]
      (.read in bytes)
      bytes)))

(defn bpf-fs-mounted?
  "Check if BPF filesystem is mounted"
  []
  (try
    (let [mounts (slurp "/proc/mounts")
          lines (str/split-lines mounts)]
      (some #(str/includes? % "bpf") lines))
    (catch Exception _ false)))

(defn get-bpf-fs-path
  "Get BPF filesystem mount path"
  []
  (try
    (let [mounts (slurp "/proc/mounts")
          lines (str/split-lines mounts)
          bpf-line (first (filter #(str/includes? % "bpf") lines))]
      (when bpf-line
        (second (str/split bpf-line #"\s+"))))
    (catch Exception _ nil)))

(defn ensure-bpf-fs
  "Ensure BPF filesystem is mounted, return path"
  []
  (or (get-bpf-fs-path)
      (throw (ex-info "BPF filesystem not mounted. Please mount with: sudo mount -t bpf bpf /sys/fs/bpf"
                      {:type :bpf-fs-not-mounted}))))

;; Kernel version utilities

(defn parse-kernel-version
  "Parse kernel version string into integer (e.g., '5.15.0' -> 0x050f00)"
  [version-str]
  (let [parts (str/split version-str #"\.")
        major (Integer/parseInt (first parts))
        minor (Integer/parseInt (second parts))
        patch (if (> (count parts) 2)
                (Integer/parseInt (nth parts 2))
                0)]
    (bit-or (bit-shift-left major 16)
            (bit-or (bit-shift-left minor 8) patch))))

(defn get-kernel-version
  "Get current kernel version as integer"
  []
  (try
    (let [version-str (str/trim (slurp "/proc/sys/kernel/osrelease"))
          version-str (first (str/split version-str #"-"))] ; Remove distro suffix
      (parse-kernel-version version-str))
    (catch Exception e
      (throw (ex-info "Failed to get kernel version" {:cause e})))))

;; Capability checking

(defn has-cap-bpf?
  "Check if process has CAP_BPF capability"
  []
  ;; This is a simplified check - we try to create a map and see if it works
  ;; A more robust implementation would parse /proc/self/status
  (try
    (let [status (slurp "/proc/self/status")
          cap-eff-line (first (filter #(str/starts-with? % "CapEff:") (str/split-lines status)))
          cap-hex (str/trim (subs cap-eff-line 7))
          cap-val (Long/parseLong cap-hex 16)
          ;; CAP_BPF is bit 39
          cap-bpf-bit 39]
      (not= 0 (bit-and cap-val (bit-shift-left 1 cap-bpf-bit))))
    (catch Exception _ false)))

(defn check-bpf-available
  "Check if BPF is available and accessible"
  []
  (let [checks {:kernel-version (try (get-kernel-version) (catch Exception _ nil))
                :bpf-fs-mounted (bpf-fs-mounted?)
                :bpf-fs-path (get-bpf-fs-path)
                :has-cap-bpf (has-cap-bpf?)}]
    (when-not (:kernel-version checks)
      (throw (ex-info "Cannot determine kernel version" checks)))
    (when (< (:kernel-version checks) 0x040e00) ; 4.14.0
      (throw (ex-info "Kernel version too old, need at least 4.14" checks)))
    checks))

;; Hex dump utilities (for debugging)

(defn hex-dump
  "Create hex dump of bytes"
  [bytes & {:keys [offset limit] :or {offset 0 limit 256}}]
  (let [bytes (if (instance? MemorySegment bytes)
                (segment->bytes bytes limit)
                bytes)
        end (min (count bytes) (+ offset limit))]
    (str/join "\n"
              (for [i (range offset end 16)]
                (let [line-bytes (take 16 (drop i bytes))
                      hex-part (str/join " " (map #(format "%02x" %) line-bytes))
                      ascii-part (str/join (map #(if (and (>= % 32) (< % 127))
                                                   (char %)
                                                   ".")
                                               line-bytes))]
                  (format "%08x  %-48s  %s" i hex-part ascii-part))))))

;; Resource management

(defmacro with-memory
  "Allocate memory and ensure it's cleaned up"
  [[binding size] & body]
  `(let [~binding (allocate-memory ~size)]
     (try
       ~@body
       (finally
         ;; Memory is automatically GC'd by Arena
         nil))))

(defmacro with-fd
  "Ensure file descriptor is closed after use"
  [[binding expr] & body]
  `(let [~binding ~expr]
     (try
       ~@body
       (finally
         (when (and ~binding (>= ~binding 0))
           (clj-ebpf.syscall/close-fd ~binding))))))

;; Struct packing utilities

(defn pack-struct
  "Pack a struct definition into bytes
   Spec is a vector of [type value] pairs where type is :u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64"
  [spec]
  (let [total-size (reduce (fn [acc [type _]]
                            (+ acc (case type
                                    (:u8 :i8) 1
                                    (:u16 :i16) 2
                                    (:u32 :i32) 4
                                    (:u64 :i64) 8
                                    0)))
                          0 spec)
        bb (ByteBuffer/allocate total-size)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (doseq [[type value] spec]
      (case type
        :u8 (.put bb (byte value))
        :i8 (.put bb (byte value))
        :u16 (.putShort bb (short value))
        :i16 (.putShort bb (short value))
        :u32 (.putInt bb (int value))
        :i32 (.putInt bb (int value))
        :u64 (.putLong bb (long value))
        :i64 (.putLong bb (long value))))
    (.array bb)))

(defn unpack-struct
  "Unpack bytes into struct values according to spec
   Spec is a vector of types: :u8, :u16, :u32, :u64, :i8, :i16, :i32, :i64"
  [bytes spec]
  (let [bb (ByteBuffer/wrap bytes)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (mapv (fn [type]
           (case type
             :u8 (bit-and 0xff (.get bb))
             :i8 (.get bb)
             :u16 (bit-and 0xffff (.getShort bb))
             :i16 (.getShort bb)
             :u32 (bit-and 0xffffffff (.getInt bb))
             :i32 (.getInt bb)
             :u64 (.getLong bb)
             :i64 (.getLong bb)))
         spec)))

;; Arena management
(defn with-arena
  "Execute function with a confined arena for memory allocations"
  [f]
  (let [arena (Arena/ofConfined)]
    (try
      (binding [*arena* arena]
        (f))
      (finally
        (.close arena)))))
