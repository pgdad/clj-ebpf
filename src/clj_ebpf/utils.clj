(ns clj-ebpf.utils
  "Utility functions for BPF programming"
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [com.sun.jna Memory Pointer]
           [java.nio ByteBuffer ByteOrder]))

;; Memory allocation and management

(defn allocate-memory
  "Allocate native memory of given size"
  [size]
  (Memory. (long size)))

(defn pointer->bytes
  "Read bytes from a pointer"
  [^Pointer ptr size]
  (when (and ptr (not= ptr Pointer/NULL))
    (let [bytes (byte-array size)]
      (.read ptr 0 bytes 0 size)
      bytes)))

(defn bytes->pointer
  "Write bytes to a newly allocated pointer"
  [^bytes bytes]
  (when bytes
    (let [ptr (allocate-memory (count bytes))]
      (.write ptr 0 bytes 0 (count bytes))
      ptr)))

(defn zero-memory
  "Zero out memory at pointer"
  [^Pointer ptr size]
  (.clear ptr size))

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

;; Pointer helpers

(defn int->pointer
  "Convert integer to pointer"
  [^long n]
  (let [ptr (allocate-memory 4)]
    (.setInt ptr 0 (int n))
    ptr))

(defn pointer->int
  "Read integer from pointer"
  [^Pointer ptr]
  (when (and ptr (not= ptr Pointer/NULL))
    (.getInt ptr 0)))

(defn long->pointer
  "Convert long to pointer"
  [^long n]
  (let [ptr (allocate-memory 8)]
    (.setLong ptr 0 n)
    ptr))

(defn pointer->long
  "Read long from pointer"
  [^Pointer ptr]
  (when (and ptr (not= ptr Pointer/NULL))
    (.getLong ptr 0)))

;; String utilities

(defn string->pointer
  "Convert string to null-terminated pointer"
  [^String s]
  (when s
    (let [bytes (.getBytes s "UTF-8")
          ptr (allocate-memory (inc (count bytes)))]
      (.write ptr 0 bytes 0 (count bytes))
      (.setByte ptr (count bytes) 0)
      ptr)))

(defn pointer->string
  "Read null-terminated string from pointer"
  [^Pointer ptr max-len]
  (when (and ptr (not= ptr Pointer/NULL))
    (.getString ptr 0 "UTF-8")))

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
  (let [bytes (if (instance? Pointer bytes)
                (pointer->bytes bytes limit)
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
         ;; Memory is automatically GC'd by JNA
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
