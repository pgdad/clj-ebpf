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
   value-size       ; Size of value in bytes (total size, including per-CPU if applicable)
   max-entries      ; Maximum number of entries
   flags            ; Map flags
   name             ; Map name (optional)
   key-serializer   ; Function to serialize key to bytes
   key-deserializer ; Function to deserialize bytes to key
   value-serializer ; Function to serialize value to bytes
   value-deserializer ; Function to deserialize bytes to value
   percpu?          ; Whether this is a per-CPU map
   percpu-value-size]) ; Size of value per CPU (if per-CPU map)

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
           btf-value-type-id btf-vmlinux-value-type-id map-extra
           percpu? percpu-value-size]
    :or {map-flags 0
         key-serializer identity
         key-deserializer identity
         value-serializer identity
         value-deserializer identity
         percpu? false
         percpu-value-size nil}}]
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
              key-serializer key-deserializer value-serializer value-deserializer
              percpu? percpu-value-size)))

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
            value-serializer value-deserializer
            false nil))  ; Not a per-CPU map by default

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
  (utils/with-bpf-arena
    (let [key-seg (key->segment bpf-map key)
          value-seg (utils/allocate-memory (:value-size bpf-map))]
      (try
        (syscall/map-lookup-elem (:fd bpf-map) key-seg value-seg)
        (segment->value bpf-map value-seg)
        (catch clojure.lang.ExceptionInfo e
          (if (= :enoent (:errno-keyword (ex-data e)))
            nil ; Key not found
            (throw e)))))))

(defn map-update
  "Update or insert key-value pair in map

  Flags:
  - :any - Create new element or update existing (default)
  - :noexist - Create new element, fail if exists
  - :exist - Update existing element, fail if not exists"
  [^BpfMap bpf-map key value & {:keys [flags] :or {flags :any}}]
  (utils/with-bpf-arena
    (let [key-seg (key->segment bpf-map key)
          value-seg (value->segment bpf-map value)
          flag-bits (if (keyword? flags)
                      (get const/map-update-flags flags 0)
                      flags)]
      (syscall/map-update-elem (:fd bpf-map) key-seg value-seg flag-bits)
      nil)))

(defn map-delete
  "Delete entry by key from map"
  [^BpfMap bpf-map key]
  (utils/with-bpf-arena
    (let [key-seg (key->segment bpf-map key)]
      (try
        (syscall/map-delete-elem (:fd bpf-map) key-seg)
        true
        (catch clojure.lang.ExceptionInfo e
          (if (= :enoent (:errno-keyword (ex-data e)))
            false ; Key not found
            (throw e)))))))

(defn map-get-next-key
  "Get next key in map (for iteration)
  Pass nil as key to get first key"
  [^BpfMap bpf-map key]
  (utils/with-bpf-arena
    (let [key-seg (if key (key->segment bpf-map key) MemorySegment/NULL)
          next-key-seg (utils/allocate-memory (:key-size bpf-map))]
      (try
        (syscall/map-get-next-key (:fd bpf-map) key-seg next-key-seg)
        (segment->key bpf-map next-key-seg)
        (catch clojure.lang.ExceptionInfo e
          (if (= :enoent (:errno-keyword (ex-data e)))
            nil ; No more keys
            (throw e)))))))

;; ============================================================================
;; Map Existence Predicates
;; ============================================================================

(defn map-exists?
  "Check if a BPF map is still valid and exists in the kernel.

  Returns true if the map FD is valid and the map exists.
  Returns false if the map has been closed or deleted.

  This performs a simple get-next-key operation which will fail
  if the map FD is invalid."
  [^BpfMap bpf-map]
  (when-let [fd (:fd bpf-map)]
    (when (pos? fd)
      (utils/with-bpf-arena
        (try
          ;; Try a simple operation - this will fail with EBADF if FD is invalid
          ;; Use get-next-key with NULL key to check if map is accessible
          (let [key-seg MemorySegment/NULL
                next-key-seg (utils/allocate-memory (max (:key-size bpf-map) 4))]
            (syscall/map-get-next-key fd key-seg next-key-seg)
            true)
          (catch clojure.lang.ExceptionInfo e
            ;; ENOENT means map is empty but valid, EBADF means invalid
            (let [errno-kw (:errno-keyword (ex-data e))]
              (not= errno-kw :ebadf)))
          (catch Exception _
            false))))))

(defn map-pinned?
  "Check if a map is pinned to the BPF filesystem.

  Note: This only checks if the map was created with pinning info
  in this session. To check if a map file exists on disk, use
  clojure.java.io/file."
  [^BpfMap bpf-map]
  (boolean (:pin-path bpf-map)))

(defn map-empty?
  "Check if a BPF map has no entries.

  Returns true if the map has no entries, false otherwise.
  Returns nil if the map doesn't exist or is inaccessible."
  [^BpfMap bpf-map]
  (when (map-exists? bpf-map)
    (nil? (map-get-next-key bpf-map nil))))

;; Higher-level map operations

(defn map-keys
  "Get all keys from map as a lazy sequence.

   The sequence is generated on-demand using BPF's get_next_key syscall,
   making it memory-efficient for large maps.

   Example:
   (take 10 (map-keys my-map))  ; Get first 10 keys without loading all"
  [^BpfMap bpf-map]
  (take-while some?
              (iterate #(map-get-next-key bpf-map %)
                      (map-get-next-key bpf-map nil))))

(defn map-entries
  "Get all key-value pairs from map as a lazy sequence.

   Returns a lazy sequence of [key value] vectors. Values are looked up
   on-demand, making this efficient for large maps.

   Example:
   (doseq [[k v] (take 100 (map-entries my-map))]
     (process k v))"
  [^BpfMap bpf-map]
  (map (fn [k] [k (map-lookup bpf-map k)])
       (map-keys bpf-map)))

(defn map-values
  "Get all values from map as a lazy sequence"
  [^BpfMap bpf-map]
  (map second (map-entries bpf-map)))

(defn map-count
  "Count number of entries in map.

   Note: This iterates through all keys, which can be slow for large maps.
   Consider using a separate counter if you need frequent count queries."
  [^BpfMap bpf-map]
  (count (map-keys bpf-map)))

(defn map-clear
  "Delete all entries from map"
  [^BpfMap bpf-map]
  (doseq [k (map-keys bpf-map)]
    (map-delete bpf-map k)))

;; Chunked/batched iteration for better performance

(defn map-entries-chunked
  "Get map entries in chunks for better performance.

   Returns a lazy sequence of [key value] vectors, but fetches
   entries in batches to reduce syscall overhead.

   Parameters:
   - bpf-map: The BPF map
   - chunk-size: Number of entries to fetch per batch (default 100)

   Example:
   (doseq [[k v] (map-entries-chunked my-map 1000)]
     (process k v))"
  ([^BpfMap bpf-map]
   (map-entries-chunked bpf-map 100))
  ([^BpfMap bpf-map chunk-size]
   (letfn [(fetch-chunk [start-key]
             (lazy-seq
               (let [keys (if start-key
                           (take chunk-size
                                 (take-while some?
                                             (iterate #(map-get-next-key bpf-map %)
                                                     (map-get-next-key bpf-map start-key))))
                           (take chunk-size (map-keys bpf-map)))]
                 (when (seq keys)
                   (let [entries (map (fn [k] [k (map-lookup bpf-map k)]) keys)]
                     (concat entries
                             (when (= (count keys) chunk-size)
                               (fetch-chunk (last keys)))))))))]
     (fetch-chunk nil))))

(defn reduce-map
  "Reduce over map entries without creating intermediate sequences.

   More memory-efficient than (reduce f init (map-entries m)) for
   very large maps as it processes entries one at a time.

   Parameters:
   - f: Reducing function (fn [acc [key value]] ...)
   - init: Initial accumulator value
   - bpf-map: The BPF map

   Example:
   (reduce-map (fn [sum [k v]] (+ sum v)) 0 my-map)"
  [f init ^BpfMap bpf-map]
  (loop [acc init
         key (map-get-next-key bpf-map nil)]
    (if key
      (let [value (map-lookup bpf-map key)]
        (recur (f acc [key value])
               (map-get-next-key bpf-map key)))
      acc)))

(defn map-filter
  "Return a lazy sequence of entries matching predicate.

   Parameters:
   - pred: Predicate function (fn [[key value]] ...) returning true to include
   - bpf-map: The BPF map

   Example:
   (map-filter (fn [[k v]] (> v 100)) my-map)"
  [pred ^BpfMap bpf-map]
  (filter pred (map-entries bpf-map)))

(defn map-some
  "Returns the first entry where pred returns logical true.

   Short-circuits as soon as a match is found.

   Parameters:
   - pred: Predicate function (fn [[key value]] ...)
   - bpf-map: The BPF map

   Example:
   (map-some (fn [[k v]] (when (> v 1000) [k v])) my-map)"
  [pred ^BpfMap bpf-map]
  (some pred (map-entries bpf-map)))

(defn map-every?
  "Returns true if pred returns true for all entries.

   Short-circuits on first false.

   Parameters:
   - pred: Predicate function (fn [[key value]] ...)
   - bpf-map: The BPF map"
  [pred ^BpfMap bpf-map]
  (every? pred (map-entries bpf-map)))

(defn into-clj-map
  "Convert BPF map entries into a Clojure persistent map.

   Caution: This loads all entries into memory. Only use for
   maps you know are small enough to fit.

   Parameters:
   - bpf-map: The BPF map

   Returns a Clojure map with all entries."
  [^BpfMap bpf-map]
  (into {} (map-entries bpf-map)))

;; Batch operations

(defn map-lookup-batch
  "Batch lookup multiple keys from map

  Parameters:
  - bpf-map: BpfMap instance
  - keys: Sequence of keys to lookup

  Returns a sequence of [key value] pairs for keys that exist.
  Missing keys are omitted from the result."
  [^BpfMap bpf-map keys]
  (utils/with-bpf-arena
    (let [key-size (:key-size bpf-map)
          value-size (:value-size bpf-map)
          key-serializer (:key-serializer bpf-map)
          value-deserializer (:value-deserializer bpf-map)
          keys-vec (vec keys)
          count (count keys-vec)

          ;; Allocate arrays for keys and values
          keys-array (utils/allocate-memory (* count key-size))
          values-array (utils/allocate-memory (* count value-size))]

      ;; Serialize keys into array
      (doseq [[i k] (map-indexed vector keys-vec)]
        (let [key-bytes (key-serializer k)
              key-seg (if (instance? MemorySegment key-bytes)
                        key-bytes
                        (utils/bytes->segment key-bytes))
              offset (* i key-size)]
          (MemorySegment/copy key-seg 0 keys-array offset key-size)))

      (try
        ;; Perform batch lookup
        (let [actual-count (syscall/map-lookup-batch (:fd bpf-map) keys-array values-array count)]
          ;; Deserialize results
          (doall
            (for [i (range actual-count)]
              (let [key (nth keys-vec i)
                    value-offset (* i value-size)
                    value-seg (.asSlice keys-array value-offset value-size)
                    value-bytes (utils/segment->bytes value-seg value-size)
                    value (value-deserializer value-bytes)]
                [key value]))))
        (catch Exception e
          ;; If batch operation not supported, fall back to individual lookups
          (if (= :einval (:errno-keyword (ex-data e)))
            (do
              (log/warn "Batch lookup not supported, falling back to individual lookups")
              (doall
                (keep (fn [k]
                        (when-let [v (map-lookup bpf-map k)]
                          [k v]))
                      keys)))
            (throw e)))))))

(defn map-update-batch
  "Batch update multiple key-value pairs in map

  Parameters:
  - bpf-map: BpfMap instance
  - entries: Sequence of [key value] pairs to update
  - flags: Update flags (:any, :noexist, :exist), default :any

  Returns the number of entries successfully updated."
  [^BpfMap bpf-map entries & {:keys [flags] :or {flags :any}}]
  (utils/with-bpf-arena
    (let [key-size (:key-size bpf-map)
          value-size (:value-size bpf-map)
          key-serializer (:key-serializer bpf-map)
          value-serializer (:value-serializer bpf-map)
          entries-vec (vec entries)
          count (count entries-vec)
          flag-bits (if (keyword? flags)
                      (get const/map-update-flags flags 0)
                      flags)

          ;; Allocate arrays for keys and values
          keys-array (utils/allocate-memory (* count key-size))
          values-array (utils/allocate-memory (* count value-size))]

      ;; Serialize keys and values into arrays
      (doseq [[i [k v]] (map-indexed vector entries-vec)]
        (let [key-bytes (key-serializer k)
              value-bytes (value-serializer v)
              key-seg (if (instance? MemorySegment key-bytes)
                        key-bytes
                        (utils/bytes->segment key-bytes))
              value-seg (if (instance? MemorySegment value-bytes)
                          value-bytes
                          (utils/bytes->segment value-bytes))
              key-offset (* i key-size)
              value-offset (* i value-size)]
          (MemorySegment/copy key-seg 0 keys-array key-offset key-size)
          (MemorySegment/copy value-seg 0 values-array value-offset value-size)))

      (try
        ;; Perform batch update
        (syscall/map-update-batch (:fd bpf-map) keys-array values-array count :elem-flags flag-bits)
        (catch Exception e
          ;; If batch operation not supported, fall back to individual updates
          (if (= :einval (:errno-keyword (ex-data e)))
            (do
              (log/warn "Batch update not supported, falling back to individual updates")
              (doseq [[k v] entries]
                (map-update bpf-map k v :flags flags))
              count)
            (throw e)))))))

(defn map-delete-batch
  "Batch delete multiple keys from map

  Parameters:
  - bpf-map: BpfMap instance
  - keys: Sequence of keys to delete

  Returns the number of keys successfully deleted."
  [^BpfMap bpf-map keys]
  (utils/with-bpf-arena
    (let [key-size (:key-size bpf-map)
          key-serializer (:key-serializer bpf-map)
          keys-vec (vec keys)
          count (count keys-vec)

          ;; Allocate array for keys
          keys-array (utils/allocate-memory (* count key-size))]

      ;; Serialize keys into array
      (doseq [[i k] (map-indexed vector keys-vec)]
        (let [key-bytes (key-serializer k)
              key-seg (if (instance? MemorySegment key-bytes)
                        key-bytes
                        (utils/bytes->segment key-bytes))
              offset (* i key-size)]
          (MemorySegment/copy key-seg 0 keys-array offset key-size)))

      (try
        ;; Perform batch delete
        (syscall/map-delete-batch (:fd bpf-map) keys-array count)
        (catch Exception e
          ;; If batch operation not supported, fall back to individual deletes
          (if (= :einval (:errno-keyword (ex-data e)))
            (do
              (log/warn "Batch delete not supported, falling back to individual deletes")
              (reduce (fn [cnt k]
                        (if (map-delete bpf-map k)
                          (inc cnt)
                          cnt))
                      0
                      keys))
            (throw e)))))))

(defn map-lookup-and-delete-batch
  "Batch lookup and delete multiple keys from map atomically

  Parameters:
  - bpf-map: BpfMap instance
  - keys: Sequence of keys to lookup and delete

  Returns a sequence of [key value] pairs for keys that existed.
  Keys are deleted from the map after being read."
  [^BpfMap bpf-map keys]
  (utils/with-bpf-arena
    (let [key-size (:key-size bpf-map)
          value-size (:value-size bpf-map)
          key-serializer (:key-serializer bpf-map)
          value-deserializer (:value-deserializer bpf-map)
          keys-vec (vec keys)
          count (count keys-vec)

          ;; Allocate arrays for keys and values
          keys-array (utils/allocate-memory (* count key-size))
          values-array (utils/allocate-memory (* count value-size))]

      ;; Serialize keys into array
      (doseq [[i k] (map-indexed vector keys-vec)]
        (let [key-bytes (key-serializer k)
              key-seg (if (instance? MemorySegment key-bytes)
                        key-bytes
                        (utils/bytes->segment key-bytes))
              offset (* i key-size)]
          (MemorySegment/copy key-seg 0 keys-array offset key-size)))

      (try
        ;; Perform batch lookup and delete
        (let [actual-count (syscall/map-lookup-and-delete-batch (:fd bpf-map) keys-array values-array count)]
          ;; Deserialize results
          (doall
            (for [i (range actual-count)]
              (let [key (nth keys-vec i)
                    value-offset (* i value-size)
                    value-seg (.asSlice keys-array value-offset value-size)
                    value-bytes (utils/segment->bytes value-seg value-size)
                    value (value-deserializer value-bytes)]
                [key value]))))
        (catch Exception e
          ;; If batch operation not supported, fall back to individual operations
          (if (= :einval (:errno-keyword (ex-data e)))
            (do
              (log/warn "Batch lookup-and-delete not supported, falling back to individual operations")
              (doall
                (keep (fn [k]
                        (when-let [v (map-lookup bpf-map k)]
                          (map-delete bpf-map k)
                          [k v]))
                      keys)))
            (throw e)))))))

;; Stack and Queue map operations

(defn stack-push
  "Push a value onto a stack map

  Parameters:
  - bpf-map: Stack map instance
  - value: Value to push

  Returns nil on success, throws on error."
  [^BpfMap bpf-map value]
  (utils/with-bpf-arena
    (let [value-seg (value->segment bpf-map value)]
      (syscall/map-update-elem (:fd bpf-map) MemorySegment/NULL value-seg 0)
      nil)))

(defn stack-pop
  "Pop a value from a stack map (LIFO)

  Parameters:
  - bpf-map: Stack map instance

  Returns the popped value, or nil if stack is empty."
  [^BpfMap bpf-map]
  (utils/with-bpf-arena
    (let [value-seg (utils/allocate-memory (:value-size bpf-map))]
      (try
        ;; Use atomic lookup-and-delete for stack/queue maps
        (syscall/map-lookup-and-delete-elem (:fd bpf-map) MemorySegment/NULL value-seg)
        (segment->value bpf-map value-seg)
        (catch clojure.lang.ExceptionInfo e
          (if (= :enoent (:errno-keyword (ex-data e)))
            nil  ; Stack is empty
            (throw e)))))))

(defn stack-peek
  "Peek at the top value of a stack map without removing it

  Parameters:
  - bpf-map: Stack map instance

  Returns the top value, or nil if stack is empty."
  [^BpfMap bpf-map]
  (utils/with-bpf-arena
    (let [value-seg (utils/allocate-memory (:value-size bpf-map))]
      (try
        (syscall/map-lookup-elem (:fd bpf-map) MemorySegment/NULL value-seg)
        (segment->value bpf-map value-seg)
        (catch clojure.lang.ExceptionInfo e
          (if (= :enoent (:errno-keyword (ex-data e)))
            nil  ; Stack is empty
            (throw e)))))))

(defn queue-push
  "Push a value onto a queue map (enqueue)

  Parameters:
  - bpf-map: Queue map instance
  - value: Value to push

  Returns nil on success, throws on error."
  [^BpfMap bpf-map value]
  (utils/with-bpf-arena
    (let [value-seg (value->segment bpf-map value)]
      (syscall/map-update-elem (:fd bpf-map) MemorySegment/NULL value-seg 0)
      nil)))

(defn queue-pop
  "Pop a value from a queue map (dequeue, FIFO)

  Parameters:
  - bpf-map: Queue map instance

  Returns the popped value, or nil if queue is empty."
  [^BpfMap bpf-map]
  (utils/with-bpf-arena
    (let [value-seg (utils/allocate-memory (:value-size bpf-map))]
      (try
        ;; Use atomic lookup-and-delete for stack/queue maps
        (syscall/map-lookup-and-delete-elem (:fd bpf-map) MemorySegment/NULL value-seg)
        (segment->value bpf-map value-seg)
        (catch clojure.lang.ExceptionInfo e
          (if (= :enoent (:errno-keyword (ex-data e)))
            nil  ; Queue is empty
            (throw e)))))))

(defn queue-peek
  "Peek at the front value of a queue map without removing it

  Parameters:
  - bpf-map: Queue map instance

  Returns the front value, or nil if queue is empty."
  [^BpfMap bpf-map]
  (utils/with-bpf-arena
    (let [value-seg (utils/allocate-memory (:value-size bpf-map))]
      (try
        (syscall/map-lookup-elem (:fd bpf-map) MemorySegment/NULL value-seg)
        (segment->value bpf-map value-seg)
        (catch clojure.lang.ExceptionInfo e
          (if (= :enoent (:errno-keyword (ex-data e)))
            nil  ; Queue is empty
            (throw e)))))))

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
                key-serializer key-deserializer value-serializer value-deserializer
                percpu? percpu-value-size]
         :or {map-flags 0
              key-serializer identity
              key-deserializer identity
              value-serializer identity
              value-deserializer identity
              percpu? false
              percpu-value-size nil}}]
  (let [fd (syscall/obj-get path)]
    (log/info "Retrieved pinned map from" path "fd:" fd)
    (->BpfMap fd map-type key-size value-size max-entries map-flags map-name
              key-serializer key-deserializer value-serializer value-deserializer
              percpu? percpu-value-size)))

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

(defn create-lru-hash-map
  "Create an LRU (Least Recently Used) hash map with integer keys and values

  LRU maps automatically evict the least recently used entries when full,
  making them ideal for caching scenarios.

  Parameters:
  - max-entries: Maximum number of entries (also the LRU cache size)

  Optional keyword arguments:
  - :key-size - Size of key in bytes (default: 4)
  - :value-size - Size of value in bytes (default: 4)
  - :map-name - Name for the map"
  [max-entries & {:keys [key-size value-size map-name]
                  :or {key-size 4 value-size 4}}]
  (create-map {:map-type :lru-hash
               :key-size key-size
               :value-size value-size
               :max-entries max-entries
               :map-name map-name
               :key-serializer utils/int->bytes
               :key-deserializer utils/bytes->int
               :value-serializer utils/int->bytes
               :value-deserializer utils/bytes->int}))

(defn create-percpu-hash-map
  "Create a per-CPU hash map with integer keys

  Each CPU core has its own independent value for each key, eliminating
  contention between CPUs. Lookups return a vector of values (one per CPU).

  Parameters:
  - max-entries: Maximum number of entries

  Optional keyword arguments:
  - :key-size - Size of key in bytes (default: 4)
  - :value-size - Size of value in bytes per CPU (default: 4)
  - :map-name - Name for the map

  Note: The actual value size in the kernel is (value-size * num-cpus)"
  [max-entries & {:keys [key-size value-size map-name]
                  :or {key-size 4 value-size 4}}]
  (let [num-cpus (utils/get-cpu-count)
        actual-value-size (* value-size num-cpus)
        per-cpu-val-size value-size  ; Capture in local var
        cpus num-cpus]               ; Capture in local var
    (create-map {:map-type :percpu-hash
                 :key-size key-size
                 :value-size actual-value-size
                 :max-entries max-entries
                 :map-name map-name
                 :key-serializer utils/int->bytes
                 :key-deserializer utils/bytes->int
                 :value-serializer (fn [v] (utils/percpu-values->bytes v utils/int->bytes per-cpu-val-size :num-cpus cpus))
                 :value-deserializer (fn [b] (utils/bytes->percpu-values b utils/bytes->int per-cpu-val-size :num-cpus cpus))
                 :percpu? true
                 :percpu-value-size value-size})))

(defn create-percpu-array-map
  "Create a per-CPU array map

  Like array maps but each CPU has its own independent values. Array keys
  are indices from 0 to (max-entries - 1). Lookups return vectors of values.

  Parameters:
  - max-entries: Number of array entries (keys are 0 to max-entries-1)

  Optional keyword arguments:
  - :value-size - Size of value in bytes per CPU (default: 4)
  - :map-name - Name for the map"
  [max-entries & {:keys [value-size map-name]
                  :or {value-size 4}}]
  (let [num-cpus (utils/get-cpu-count)
        actual-value-size (* value-size num-cpus)]
    (create-map {:map-type :percpu-array
                 :key-size 4
                 :value-size actual-value-size
                 :max-entries max-entries
                 :map-name map-name
                 :key-serializer utils/int->bytes
                 :key-deserializer utils/bytes->int
                 :value-serializer (fn [v] (utils/percpu-values->bytes v utils/int->bytes value-size :num-cpus num-cpus))
                 :value-deserializer (fn [b] (utils/bytes->percpu-values b utils/bytes->int value-size :num-cpus num-cpus))
                 :percpu? true
                 :percpu-value-size value-size})))

(defn create-lru-percpu-hash-map
  "Create a per-CPU LRU hash map with integer keys and values

  Like LRU hash maps, but each CPU has its own separate LRU cache,
  providing better performance for multi-core systems.

  Parameters:
  - max-entries: Maximum number of entries per CPU

  Optional keyword arguments:
  - :key-size - Size of key in bytes (default: 4)
  - :value-size - Size of value in bytes per CPU (default: 4)
  - :map-name - Name for the map"
  [max-entries & {:keys [key-size value-size map-name]
                  :or {key-size 4 value-size 4}}]
  (let [num-cpus (utils/get-cpu-count)
        actual-value-size (* value-size num-cpus)]
    (create-map {:map-type :lru-percpu-hash
                 :key-size key-size
                 :value-size actual-value-size
                 :max-entries max-entries
                 :map-name map-name
                 :key-serializer utils/int->bytes
                 :key-deserializer utils/bytes->int
                 :value-serializer (fn [v] (utils/percpu-values->bytes v utils/int->bytes value-size :num-cpus num-cpus))
                 :value-deserializer (fn [b] (utils/bytes->percpu-values b utils/bytes->int value-size :num-cpus num-cpus))
                 :percpu? true
                 :percpu-value-size value-size})))

;; Per-CPU value aggregation helpers

(defn percpu-sum
  "Sum values across all CPUs.

  Parameters:
  - percpu-values: Vector of values, one per CPU

  Returns the sum of all per-CPU values."
  [percpu-values]
  (reduce + percpu-values))

(defn percpu-max
  "Get maximum value across all CPUs.

  Parameters:
  - percpu-values: Vector of values, one per CPU

  Returns the maximum value among all CPUs."
  [percpu-values]
  (apply max percpu-values))

(defn percpu-min
  "Get minimum value across all CPUs.

  Parameters:
  - percpu-values: Vector of values, one per CPU

  Returns the minimum value among all CPUs."
  [percpu-values]
  (apply min percpu-values))

(defn percpu-avg
  "Calculate average value across all CPUs.

  Parameters:
  - percpu-values: Vector of values, one per CPU

  Returns the average (mean) of all per-CPU values."
  [percpu-values]
  (/ (percpu-sum percpu-values) (count percpu-values)))

(defn create-stack-map
  "Create a stack (LIFO) map

  Stack maps provide Last-In-First-Out semantics. Values are pushed and popped
  without explicit keys. Useful for maintaining call stacks or LIFO queues.

  Parameters:
  - max-entries: Maximum number of entries in the stack

  Optional keyword arguments:
  - :value-size - Size of value in bytes (default: 4)
  - :map-name - Name for the map

  Operations:
  - Push: Use map-update with nil key
  - Pop: Use special stack/queue operations (not standard map-lookup)
  - Peek: Look at top without removing

  Note: Stack maps use special operations, not standard key-value operations."
  [max-entries & {:keys [value-size map-name]
                  :or {value-size 4}}]
  (create-map {:map-type :stack
               :key-size 0  ; Stack maps don't use keys
               :value-size value-size
               :max-entries max-entries
               :map-name map-name
               :value-serializer utils/int->bytes
               :value-deserializer utils/bytes->int}))

(defn create-queue-map
  "Create a queue (FIFO) map

  Queue maps provide First-In-First-Out semantics. Values are pushed and popped
  without explicit keys. Useful for work queues or message passing.

  Parameters:
  - max-entries: Maximum number of entries in the queue

  Optional keyword arguments:
  - :value-size - Size of value in bytes (default: 4)
  - :map-name - Name for the map

  Operations:
  - Push: Use map-update with nil key
  - Pop: Use special stack/queue operations (not standard map-lookup)
  - Peek: Look at front without removing

  Note: Queue maps use special operations, not standard key-value operations."
  [max-entries & {:keys [value-size map-name]
                  :or {value-size 4}}]
  (create-map {:map-type :queue
               :key-size 0  ; Queue maps don't use keys
               :value-size value-size
               :max-entries max-entries
               :map-name map-name
               :value-serializer utils/int->bytes
               :value-deserializer utils/bytes->int}))

(defn create-lpm-trie-map
  "Create an LPM (Longest Prefix Match) trie map

  LPM trie maps are specialized for longest prefix matching, commonly used
  for IP routing tables and CIDR block lookups.

  Parameters:
  - max-entries: Maximum number of prefixes

  Optional keyword arguments:
  - :key-size - Size of key in bytes including prefix length (default: 8)
                First 4 bytes are prefix length, rest is the prefix data
  - :value-size - Size of value in bytes (default: 4)
  - :map-name - Name for the map
  - :map-flags - Must include BPF_F_NO_PREALLOC for LPM tries

  Example key structure for IPv4:
  - Bytes 0-3: Prefix length (32 bits)
  - Bytes 4-7: IPv4 address (32 bits)

  Note: Keys must include prefix length as first 4 bytes."
  [max-entries & {:keys [key-size value-size map-name]
                  :or {key-size 8 value-size 4}}]
  (create-map {:map-type :lpm-trie
               :key-size key-size
               :value-size value-size
               :max-entries max-entries
               :map-flags 1  ; BPF_F_NO_PREALLOC required for LPM tries
               :map-name map-name}))

(defn create-ringbuf-map
  "Create a ring buffer map
  max-entries must be a power of 2 and page-aligned"
  [max-entries & {:keys [map-name]}]
  (create-map {:map-type :ringbuf
               :key-size 0
               :value-size 0
               :max-entries max-entries
               :map-name map-name}))

;; ============================================================================
;; DEVMAP and CPUMAP - XDP Redirect Maps
;; ============================================================================

(defn create-dev-map
  "Create a DEVMAP for XDP packet redirection to network interfaces.

   DEVMAP is an array-based map used by XDP programs to redirect packets
   to specific network interfaces. Each entry maps an index to an interface
   index (ifindex).

   Parameters:
   - max-entries: Maximum number of entries (interfaces)

   Optional keyword arguments:
   - :map-name - Name for the map
   - :value-size - Size of value in bytes (default: 4 for ifindex only,
                   use 8 for bpf_devmap_val with XDP program FD)

   Usage with XDP programs:
   1. Create devmap and populate with interface indices
   2. XDP program calls bpf_redirect_map(devmap, index, flags)
   3. Packets are redirected to the interface at that index

   Example:
     (def dev-map (create-dev-map 64 :map-name \"tx_ports\"))
     (map-update dev-map 0 (if-nametoindex \"eth0\"))
     ;; In XDP program: bpf_redirect_map(&dev_map, 0, 0)"
  [max-entries & {:keys [map-name value-size]
                  :or {value-size 4}}]
  (create-map {:map-type :devmap
               :key-size 4        ; Array index (u32)
               :value-size value-size
               :max-entries max-entries
               :map-name map-name
               :key-serializer utils/int->bytes
               :key-deserializer utils/bytes->int
               :value-serializer utils/int->bytes
               :value-deserializer utils/bytes->int}))

(defn create-dev-map-hash
  "Create a DEVMAP_HASH for XDP packet redirection with hash-based lookup.

   Unlike regular DEVMAP (array-based), DEVMAP_HASH allows sparse or
   non-contiguous indexing using arbitrary keys. This is useful when
   you need to map by interface index directly rather than by array position.

   Parameters:
   - max-entries: Maximum number of entries

   Optional keyword arguments:
   - :key-size - Size of key in bytes (default: 4)
   - :value-size - Size of value in bytes (default: 4 for ifindex only)
   - :map-name - Name for the map

   Example:
     (def dev-map (create-dev-map-hash 256 :map-name \"if_redirect\"))
     (let [eth0-idx (if-nametoindex \"eth0\")]
       (map-update dev-map eth0-idx eth0-idx))
     ;; In XDP: bpf_redirect_map(&dev_map, ifindex, 0)"
  [max-entries & {:keys [key-size value-size map-name]
                  :or {key-size 4 value-size 4}}]
  (create-map {:map-type :devmap-hash
               :key-size key-size
               :value-size value-size
               :max-entries max-entries
               :map-name map-name
               :key-serializer utils/int->bytes
               :key-deserializer utils/bytes->int
               :value-serializer utils/int->bytes
               :value-deserializer utils/bytes->int}))

(defn create-cpu-map
  "Create a CPUMAP for XDP packet redirection to specific CPUs.

   CPUMAP allows XDP programs to redirect packets to specific CPUs for
   processing by the kernel networking stack. This enables custom RSS
   (Receive Side Scaling) logic and load distribution.

   Parameters:
   - max-entries: Number of CPUs to support (typically num-cpus)

   Optional keyword arguments:
   - :map-name - Name for the map
   - :value-size - Size of value in bytes (default: 8 for bpf_cpumap_val
                   which includes qsize and optional bpf_prog fd)

   The value is a bpf_cpumap_val struct:
   - qsize (u32): Queue size for the target CPU
   - bpf_prog.fd (u32): Optional XDP program to run on target CPU

   Example:
     (def cpu-map (create-cpu-map 8 :map-name \"cpu_redirect\"))
     ;; Set CPU 0 with queue size 2048
     (map-update cpu-map 0 2048)
     ;; In XDP: bpf_redirect_map(&cpu_map, target_cpu, 0)"
  [max-entries & {:keys [map-name value-size]
                  :or {value-size 8}}]
  (create-map {:map-type :cpumap
               :key-size 4        ; CPU index (u32)
               :value-size value-size
               :max-entries max-entries
               :map-name map-name
               :key-serializer utils/int->bytes
               :key-deserializer utils/bytes->int
               :value-serializer utils/long->bytes
               :value-deserializer utils/bytes->long}))

;; ============================================================================
;; SOCKMAP and SOCKHASH - Socket Redirect Maps
;; ============================================================================

(defn create-sock-map
  "Create a SOCKMAP for socket redirection (SK_SKB and SK_MSG programs).

   SOCKMAP is an array-based map that stores socket references. It's used
   by SK_SKB programs (stream parser and verdict) and SK_MSG programs to
   redirect data between sockets at the kernel level, bypassing the TCP/IP
   stack for high-performance proxying.

   Parameters:
   - max-entries: Maximum number of sockets to store

   Optional keyword arguments:
   - :map-name - Name for the map
   - :key-size - Size of key in bytes (default: 4)

   Usage pattern:
   1. Create SOCKMAP
   2. Load SK_SKB parser and verdict programs
   3. Attach programs to the map with bpf_prog_attach
   4. Add socket FDs to the map from userspace
   5. Programs redirect data between sockets in the map

   Note: Values are socket file descriptors (u32) from userspace perspective,
   but the kernel converts them to internal socket structures.

   Example:
     (def sock-map (create-sock-map 256 :map-name \"sock_redirect\"))
     ;; After accepting connections:
     (map-update sock-map key socket-fd)
     ;; SK_SKB verdict can redirect to sockets in this map"
  [max-entries & {:keys [map-name key-size]
                  :or {key-size 4}}]
  (create-map {:map-type :sockmap
               :key-size key-size
               :value-size 4       ; Socket FD (u32)
               :max-entries max-entries
               :map-name map-name
               :key-serializer utils/int->bytes
               :key-deserializer utils/bytes->int
               :value-serializer utils/int->bytes
               :value-deserializer utils/bytes->int}))

(defn create-sock-hash
  "Create a SOCKHASH for hash-based socket redirection.

   SOCKHASH is similar to SOCKMAP but uses hash-based lookup instead of
   array indices. This is useful when you need to map arbitrary keys
   (like connection tuples) to sockets.

   Parameters:
   - max-entries: Maximum number of sockets to store

   Optional keyword arguments:
   - :key-size - Size of key in bytes (default: 4, but often larger for
                 connection tuples)
   - :map-name - Name for the map

   Common key formats:
   - 4 bytes: Simple index or single identifier
   - 12 bytes: Source IP + dest IP + port (IPv4)
   - 36 bytes: Full 5-tuple (src/dst IP + src/dst port + protocol)

   Example:
     (def sock-hash (create-sock-hash 1024
                      :key-size 12
                      :map-name \"conn_sock_hash\"))
     ;; Key could be (pack src-ip dst-ip port)
     (map-update sock-hash conn-key socket-fd)"
  [max-entries & {:keys [key-size map-name]
                  :or {key-size 4}}]
  (create-map {:map-type :sockhash
               :key-size key-size
               :value-size 4       ; Socket FD (u32)
               :max-entries max-entries
               :map-name map-name
               :key-serializer utils/int->bytes
               :key-deserializer utils/bytes->int
               :value-serializer utils/int->bytes
               :value-deserializer utils/bytes->int}))

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

;; ============================================================================
;; Map-in-Map Support
;; ============================================================================
;;
;; BPF supports nested maps where an outer map contains references to inner maps.
;; This is useful for:
;; - Per-CPU data structures with dynamic keys
;; - Multi-level routing tables
;; - Hierarchical configuration
;;
;; Two types of map-in-map:
;; - :array-of-maps - Outer map is an array, indexed by integer
;; - :hash-of-maps - Outer map is a hash, keyed by arbitrary data

(defrecord MapInMap
  [outer-map           ; The outer map (array-of-maps or hash-of-maps)
   inner-template      ; Template specification for inner maps
   inner-maps          ; Atom containing map of index/key -> BpfMap
   inner-fd])          ; FD of template inner map (required for creation)

(defn- create-inner-template
  "Create a template inner map for map-in-map.

  The template is used to define the structure of inner maps.
  It's created but not used directly - its FD is passed when
  creating the outer map."
  [inner-spec]
  (create-map inner-spec))

(defn create-map-in-map
  "Create a map-in-map structure (outer map containing inner maps).

  Map-in-map allows dynamic creation of inner maps at runtime,
  useful for per-entity data structures or hierarchical configs.

  Parameters:
  - outer-type: :array-of-maps or :hash-of-maps
  - max-entries: Maximum entries in outer map
  - inner-spec: Specification for inner maps (same as create-map options)

  Options:
  - :outer-key-size - Key size for outer map (default: 4 for array, required for hash)
  - :name - Name prefix for maps

  Returns a MapInMap record.

  Example:
    ;; Create array of hash maps (e.g., per-CPU connection tables)
    (create-map-in-map
      :array-of-maps 64
      {:map-type :hash
       :key-size 16      ; Connection tuple
       :value-size 32    ; Connection state
       :max-entries 1024}
      :name \"conn_table\")"
  [outer-type max-entries inner-spec & {:keys [outer-key-size name]
                                        :or {name "map_in_map"}}]
  (let [;; Create template inner map
        inner-template (create-inner-template
                         (assoc inner-spec :map-name (str name "_inner_template")))

        ;; Determine outer key size
        key-size (case outer-type
                   :array-of-maps 4  ; Arrays use u32 index
                   :hash-of-maps (or outer-key-size
                                     (throw (ex-info "outer-key-size required for hash-of-maps"
                                                     {:outer-type outer-type}))))

        ;; Create outer map with inner map FD
        outer-map (create-map
                    {:map-type outer-type
                     :key-size key-size
                     :value-size 4  ; Inner map FDs are u32
                     :max-entries max-entries
                     :inner-map-fd (:fd inner-template)
                     :map-name (str name "_outer")
                     :key-serializer utils/int->bytes
                     :key-deserializer utils/bytes->int
                     :value-serializer utils/int->bytes
                     :value-deserializer utils/bytes->int})]

    (->MapInMap outer-map inner-spec (atom {0 inner-template}) (:fd inner-template))))

(defn add-inner-map
  "Add a new inner map at the specified index/key.

  Creates a new inner map matching the template and registers it
  in the outer map at the given location.

  Parameters:
  - mim: MapInMap record
  - key: Index (for array-of-maps) or key (for hash-of-maps)

  Returns the newly created inner BpfMap."
  [^MapInMap mim key]
  (let [;; Create new inner map matching template
        inner-map (create-map
                    (assoc (:inner-template mim)
                           :map-name (str "inner_" key)))

        ;; Register in outer map
        _ (map-update (:outer-map mim) key (:fd inner-map))

        ;; Track in our inner-maps atom
        _ (swap! (:inner-maps mim) assoc key inner-map)]

    (log/info "Added inner map at key" key "fd:" (:fd inner-map))
    inner-map))

(defn get-inner-map
  "Get the inner map at the specified index/key.

  Returns the BpfMap if it exists in our tracking, or nil."
  [^MapInMap mim key]
  (get @(:inner-maps mim) key))

(defn remove-inner-map
  "Remove an inner map at the specified index/key.

  Deletes the entry from the outer map and closes the inner map.

  Parameters:
  - mim: MapInMap record
  - key: Index or key to remove

  Returns true if removed, false if not found."
  [^MapInMap mim key]
  (when-let [inner-map (get @(:inner-maps mim) key)]
    ;; Remove from outer map
    (map-delete (:outer-map mim) key)
    ;; Close inner map
    (close-map inner-map)
    ;; Remove from tracking
    (swap! (:inner-maps mim) dissoc key)
    (log/info "Removed inner map at key" key)
    true))

(defn inner-map-lookup
  "Look up a value in an inner map.

  Convenience function for nested lookup.

  Parameters:
  - mim: MapInMap record
  - outer-key: Key for outer map
  - inner-key: Key for inner map

  Returns the value or nil if not found."
  [^MapInMap mim outer-key inner-key]
  (when-let [inner-map (get-inner-map mim outer-key)]
    (map-lookup inner-map inner-key)))

(defn inner-map-update
  "Update a value in an inner map.

  Convenience function for nested update. Creates the inner map
  if it doesn't exist.

  Parameters:
  - mim: MapInMap record
  - outer-key: Key for outer map
  - inner-key: Key for inner map
  - value: Value to store"
  [^MapInMap mim outer-key inner-key value]
  (let [inner-map (or (get-inner-map mim outer-key)
                      (add-inner-map mim outer-key))]
    (map-update inner-map inner-key value)))

(defn close-map-in-map
  "Close a map-in-map structure and all its inner maps.

  Parameters:
  - mim: MapInMap record"
  [^MapInMap mim]
  ;; Close all inner maps
  (doseq [[_key inner-map] @(:inner-maps mim)]
    (try
      (close-map inner-map)
      (catch Exception e
        (log/warn "Failed to close inner map:" e))))
  ;; Close outer map
  (close-map (:outer-map mim))
  (log/info "Closed map-in-map"))

(defn inner-map-count
  "Get the number of inner maps currently registered."
  [^MapInMap mim]
  (count @(:inner-maps mim)))

(defn inner-map-keys
  "Get all keys that have inner maps registered."
  [^MapInMap mim]
  (keys @(:inner-maps mim)))

(defmacro with-map-in-map
  "Create a map-in-map and ensure it's closed after use.

  Example:
    (with-map-in-map [mim :array-of-maps 64
                          {:map-type :hash :key-size 4 :value-size 8 :max-entries 100}]
      (add-inner-map mim 0)
      (inner-map-update mim 0 42 12345)
      (println (inner-map-lookup mim 0 42)))"
  [[binding outer-type max-entries inner-spec & opts] & body]
  `(let [~binding (create-map-in-map ~outer-type ~max-entries ~inner-spec ~@opts)]
     (try
       ~@body
       (finally
         (close-map-in-map ~binding)))))

;; ============================================================================
;; Bloom Filter Support
;; ============================================================================
;;
;; Bloom filters are probabilistic data structures for membership testing.
;; They can have false positives but never false negatives.

(defn create-bloom-filter
  "Create a bloom filter map.

  Bloom filters are space-efficient probabilistic data structures
  used for membership testing. They may return false positives
  but never false negatives.

  Parameters:
  - max-entries: Number of entries (affects false positive rate)
  - value-size: Size of values to store (typically hash size)

  Options:
  - :map-name - Name for the map
  - :nr-hash-funcs - Number of hash functions (default: kernel decides)

  Example:
    (def bloom (create-bloom-filter 10000 4))
    (bloom-add bloom (hash-bytes some-data))
    (bloom-check bloom (hash-bytes some-data)) ; => true or false"
  [max-entries value-size & {:keys [map-name nr-hash-funcs]}]
  (create-map {:map-type :bloom-filter
               :key-size 0  ; Bloom filters don't use keys
               :value-size value-size
               :max-entries max-entries
               :map-name map-name
               ;; Note: nr-hash-funcs would be set via map_extra in newer kernels
               :value-serializer identity
               :value-deserializer identity}))

(defn bloom-add
  "Add an element to a bloom filter.

  Parameters:
  - bloom-map: Bloom filter map
  - value: Value bytes to add (must match value-size)"
  [^BpfMap bloom-map value]
  (utils/with-bpf-arena
    (let [value-seg (if (instance? MemorySegment value)
                      value
                      (utils/bytes->segment value))]
      ;; Bloom filters use update with NULL key
      (syscall/map-update-elem (:fd bloom-map) MemorySegment/NULL value-seg 0))))

(defn bloom-check
  "Check if an element might be in the bloom filter.

  Returns:
  - true: Element might be in the set (could be false positive)
  - false: Element is definitely not in the set

  Parameters:
  - bloom-map: Bloom filter map
  - value: Value bytes to check"
  [^BpfMap bloom-map value]
  (utils/with-bpf-arena
    (let [value-seg (if (instance? MemorySegment value)
                      value
                      (utils/bytes->segment value))]
      (try
        ;; Bloom filters use lookup with value in the key position
        (syscall/map-lookup-elem (:fd bloom-map) value-seg
                                 (utils/allocate-memory (:value-size bloom-map)))
        true  ; Found (might be false positive)
        (catch clojure.lang.ExceptionInfo e
          (if (= :enoent (:errno-keyword (ex-data e)))
            false  ; Definitely not in set
            (throw e)))))))
