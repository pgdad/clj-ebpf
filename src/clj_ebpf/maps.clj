(ns clj-ebpf.maps
  "BPF map operations and abstractions"
  (:require [clj-ebpf.syscall :as syscall]
            [clj-ebpf.constants :as const]
            [clj-ebpf.utils :as utils]
            [clojure.tools.logging :as log])
  (:import [java.lang.foreign MemorySegment]))

;; Map lifecycle management

(defrecord BpfMap
  [fd               ; File descriptor
   type             ; Map type keyword
   key-size         ; Size of key in bytes
   value-size       ; Size of value in bytes
   max-entries      ; Maximum number of entries
   flags            ; Map flags
   name             ; Map name (optional)
   key-serializer   ; Function to serialize key to bytes
   key-deserializer ; Function to deserialize bytes to key
   value-serializer ; Function to serialize value to bytes
   value-deserializer]) ; Function to deserialize bytes to value

(defn create-map
  "Create a new BPF map

  Options:
  - :map-type - Type of map (:hash, :array, :ringbuf, etc.)
  - :key-size - Size of key in bytes
  - :value-size - Size of value in bytes
  - :max-entries - Maximum number of entries
  - :map-flags - Optional flags (default 0)
  - :map-name - Optional name
  - :key-serializer - Optional function to convert key to bytes
  - :key-deserializer - Optional function to convert bytes to key
  - :value-serializer - Optional function to convert value to bytes
  - :value-deserializer - Optional function to convert bytes to value"
  [{:keys [map-type key-size value-size max-entries map-flags map-name
           key-serializer key-deserializer value-serializer value-deserializer
           inner-map-fd numa-node map-ifindex btf-fd btf-key-type-id
           btf-value-type-id btf-vmlinux-value-type-id map-extra]
    :or {map-flags 0
         key-serializer identity
         key-deserializer identity
         value-serializer identity
         value-deserializer identity}}]
  (let [fd (syscall/map-create
             {:map-type map-type
              :key-size key-size
              :value-size value-size
              :max-entries max-entries
              :map-flags map-flags
              :inner-map-fd inner-map-fd
              :numa-node numa-node
              :map-name map-name
              :map-ifindex map-ifindex
              :btf-fd btf-fd
              :btf-key-type-id btf-key-type-id
              :btf-value-type-id btf-value-type-id
              :btf-vmlinux-value-type-id btf-vmlinux-value-type-id
              :map-extra map-extra})]
    (log/info "Created BPF map:" map-name "type:" map-type "fd:" fd)
    (->BpfMap fd map-type key-size value-size max-entries map-flags map-name
              key-serializer key-deserializer value-serializer value-deserializer)))

(defn close-map
  "Close a BPF map"
  [^BpfMap bpf-map]
  (when-let [fd (:fd bpf-map)]
    (syscall/close-fd fd)
    (log/info "Closed BPF map:" (:name bpf-map) "fd:" fd)))

(defn map-from-fd
  "Create a BpfMap record from an existing file descriptor
   (e.g., from a pinned map retrieved with obj-get)

   Required keyword arguments:
   - :key-size - Size of key in bytes
   - :value-size - Size of value in bytes
   - :key-serializer - Function to serialize keys to bytes
   - :key-deserializer - Function to deserialize bytes to keys
   - :value-serializer - Function to serialize values to bytes
   - :value-deserializer - Function to deserialize bytes to values

   Optional keyword arguments:
   - :map-type - Type of map (optional, for documentation)
   - :max-entries - Maximum entries (optional, for documentation)

   Note: The FD is assumed to be valid. Since the kernel doesn't provide
   a way to query map metadata, you must provide sizes and serializers."
  [fd & {:keys [key-size value-size map-type max-entries
                key-serializer key-deserializer value-serializer value-deserializer]
         :or {key-serializer identity
              key-deserializer identity
              value-serializer identity
              value-deserializer identity}}]
  (->BpfMap fd map-type key-size value-size max-entries nil nil
            key-serializer key-deserializer
            value-serializer value-deserializer))

;; Map operations

(defn- key->segment
  "Convert key to memory segment using map's serializer"
  [^BpfMap bpf-map key]
  (let [serializer (:key-serializer bpf-map)
        key-bytes (serializer key)]
    (if (instance? MemorySegment key-bytes)
      key-bytes
      (utils/bytes->segment key-bytes))))

(defn- value->segment
  "Convert value to memory segment using map's serializer"
  [^BpfMap bpf-map value]
  (let [serializer (:value-serializer bpf-map)
        value-bytes (serializer value)]
    (if (instance? MemorySegment value-bytes)
      value-bytes
      (utils/bytes->segment value-bytes))))

(defn- segment->key
  "Convert memory segment to key using map's deserializer"
  [^BpfMap bpf-map ^MemorySegment seg]
  (let [deserializer (:key-deserializer bpf-map)
        key-bytes (utils/segment->bytes seg (:key-size bpf-map))]
    (deserializer key-bytes)))

(defn- segment->value
  "Convert memory segment to value using map's deserializer"
  [^BpfMap bpf-map ^MemorySegment seg]
  (let [deserializer (:value-deserializer bpf-map)
        value-bytes (utils/segment->bytes seg (:value-size bpf-map))]
    (deserializer value-bytes)))

(defn map-lookup
  "Lookup value by key in map"
  [^BpfMap bpf-map key]
  (let [key-seg (key->segment bpf-map key)
        value-seg (utils/allocate-memory (:value-size bpf-map))]
    (try
      (syscall/map-lookup-elem (:fd bpf-map) key-seg value-seg)
      (segment->value bpf-map value-seg)
      (catch clojure.lang.ExceptionInfo e
        (if (= :noent (:errno-keyword (ex-data e)))
          nil ; Key not found
          (throw e))))))

(defn map-update
  "Update or insert key-value pair in map

  Flags:
  - :any - Create new element or update existing (default)
  - :noexist - Create new element, fail if exists
  - :exist - Update existing element, fail if not exists"
  [^BpfMap bpf-map key value & {:keys [flags] :or {flags :any}}]
  (let [key-seg (key->segment bpf-map key)
        value-seg (value->segment bpf-map value)
        flag-bits (if (keyword? flags)
                    (get const/map-update-flags flags 0)
                    flags)]
    (syscall/map-update-elem (:fd bpf-map) key-seg value-seg flag-bits)
    nil))

(defn map-delete
  "Delete entry by key from map"
  [^BpfMap bpf-map key]
  (let [key-seg (key->segment bpf-map key)]
    (try
      (syscall/map-delete-elem (:fd bpf-map) key-seg)
      true
      (catch clojure.lang.ExceptionInfo e
        (if (= :noent (:errno-keyword (ex-data e)))
          false ; Key not found
          (throw e))))))

(defn map-get-next-key
  "Get next key in map (for iteration)
  Pass nil as key to get first key"
  [^BpfMap bpf-map key]
  (let [key-seg (if key (key->segment bpf-map key) MemorySegment/NULL)
        next-key-seg (utils/allocate-memory (:key-size bpf-map))]
    (try
      (syscall/map-get-next-key (:fd bpf-map) key-seg next-key-seg)
      (segment->key bpf-map next-key-seg)
      (catch clojure.lang.ExceptionInfo e
        (if (= :noent (:errno-keyword (ex-data e)))
          nil ; No more keys
          (throw e))))))

;; Higher-level map operations

(defn map-keys
  "Get all keys from map as a lazy sequence"
  [^BpfMap bpf-map]
  (take-while some?
              (iterate #(map-get-next-key bpf-map %)
                      (map-get-next-key bpf-map nil))))

(defn map-entries
  "Get all key-value pairs from map as a lazy sequence"
  [^BpfMap bpf-map]
  (map (fn [k] [k (map-lookup bpf-map k)])
       (map-keys bpf-map)))

(defn map-values
  "Get all values from map as a lazy sequence"
  [^BpfMap bpf-map]
  (map second (map-entries bpf-map)))

(defn map-count
  "Count number of entries in map"
  [^BpfMap bpf-map]
  (count (map-keys bpf-map)))

(defn map-clear
  "Delete all entries from map"
  [^BpfMap bpf-map]
  (doseq [k (map-keys bpf-map)]
    (map-delete bpf-map k)))

;; Map pinning

(defn pin-map
  "Pin map to BPF filesystem"
  [^BpfMap bpf-map path]
  (syscall/obj-pin path (:fd bpf-map))
  (log/info "Pinned map" (:name bpf-map) "to" path))

(defn get-pinned-map
  "Get a pinned map from BPF filesystem
  You must provide the map metadata (type, key-size, value-size, etc.)"
  [path {:keys [map-type key-size value-size max-entries map-flags map-name
                key-serializer key-deserializer value-serializer value-deserializer]
         :or {map-flags 0
              key-serializer identity
              key-deserializer identity
              value-serializer identity
              value-deserializer identity}}]
  (let [fd (syscall/obj-get path)]
    (log/info "Retrieved pinned map from" path "fd:" fd)
    (->BpfMap fd map-type key-size value-size max-entries map-flags map-name
              key-serializer key-deserializer value-serializer value-deserializer)))

;; Clojure map-like interface

(defn assoc-map!
  "Associate key-value pair in BPF map (mutable operation)"
  [^BpfMap bpf-map key value]
  (map-update bpf-map key value)
  bpf-map)

(defn dissoc-map!
  "Dissociate key from BPF map (mutable operation)"
  [^BpfMap bpf-map key]
  (map-delete bpf-map key)
  bpf-map)

(defn get-map
  "Get value from BPF map, with optional default"
  ([^BpfMap bpf-map key]
   (map-lookup bpf-map key))
  ([^BpfMap bpf-map key default]
   (or (map-lookup bpf-map key) default)))

;; Type-specific map helpers

(defn create-hash-map
  "Create a hash map with integer keys and values"
  [max-entries & {:keys [key-size value-size map-name]
                  :or {key-size 4 value-size 4}}]
  (create-map {:map-type :hash
               :key-size key-size
               :value-size value-size
               :max-entries max-entries
               :map-name map-name
               :key-serializer utils/int->bytes
               :key-deserializer utils/bytes->int
               :value-serializer utils/int->bytes
               :value-deserializer utils/bytes->int}))

(defn create-array-map
  "Create an array map (array-indexed)
  Keys are 0-based indices"
  [max-entries & {:keys [value-size map-name]
                  :or {value-size 4}}]
  (create-map {:map-type :array
               :key-size 4  ; Array maps use 32-bit index
               :value-size value-size
               :max-entries max-entries
               :map-name map-name
               :key-serializer utils/int->bytes
               :key-deserializer utils/bytes->int
               :value-serializer utils/int->bytes
               :value-deserializer utils/bytes->int}))

(defn create-ringbuf-map
  "Create a ring buffer map
  max-entries must be a power of 2 and page-aligned"
  [max-entries & {:keys [map-name]}]
  (create-map {:map-type :ringbuf
               :key-size 0
               :value-size 0
               :max-entries max-entries
               :map-name map-name}))

;; Macro for resource management

(defmacro with-map
  "Create a map and ensure it's closed after use"
  [[binding map-spec] & body]
  `(let [~binding (create-map ~map-spec)]
     (try
       ~@body
       (finally
         (close-map ~binding)))))

;; Pretty printing

(defn dump-map
  "Dump all entries in map for debugging"
  [^BpfMap bpf-map]
  (println "Map:" (or (:name bpf-map) "unnamed")
           "type:" (:type bpf-map)
           "fd:" (:fd bpf-map))
  (println "Entries:")
  (doseq [[k v] (map-entries bpf-map)]
    (println "  " k "=>" v)))
