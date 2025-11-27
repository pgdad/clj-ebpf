(ns clj-ebpf.refs
  "Idiomatic Clojure references for BPF data structures.

   This namespace provides Clojure reference types that implement standard
   protocols (IDeref, IBlockingDeref, IAtom, ITransientCollection), enabling
   natural use of @, deref, reset!, swap!, and conj! with BPF maps.

   == Read-Only References ==

   1. RingBufRef - Blocking reads from ring buffers
      @ref                    ; blocks until event available
      (deref ref 1000 nil)    ; 1s timeout

   2. QueueRef/StackRef - Blocking pops from queue/stack maps
      @ref                    ; blocks until item available

   3. MapWatcher - Watch for a key to appear/change
      @ref                    ; blocks until key exists

   == Writable References ==

   4. MapEntryRef - Atom-like access to map entries
      @ref                    ; read value
      (reset! ref val)        ; write value
      (swap! ref inc)         ; read-modify-write

   5. QueueWriter/StackWriter - Push to queues/stacks
      (conj! ref val)         ; push value
      @ref                    ; peek (non-blocking)

   6. QueueChannel/StackChannel - Bidirectional access
      (conj! ref val)         ; push
      @ref                    ; blocking pop"
  (:require [clj-ebpf.maps :as maps]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.utils :as utils])
  (:import [java.lang.foreign MemorySegment ValueLayout Arena]
           [java.util.concurrent.atomic AtomicBoolean AtomicReference]
           [clj_ebpf.maps BpfMap]))

;; ============================================================================
;; Ring Buffer Memory Layout (duplicated from events.clj for independence)
;; ============================================================================

(def ^:private page-size 4096)

(defn- mmap
  "Memory map a file descriptor"
  [fd length prot flags offset]
  (let [mmap-nr (arch/get-syscall-nr :mmap)
        result (syscall/raw-syscall mmap-nr 0 length prot flags fd offset)]
    (when (neg? result)
      (throw (ex-info "mmap failed" {:errno (- result) :fd fd :length length})))
    result))

(defn- munmap
  "Unmap memory"
  [addr length]
  (let [munmap-nr (arch/get-syscall-nr :munmap)
        result (syscall/raw-syscall munmap-nr addr length)]
    (when (neg? result)
      (throw (ex-info "munmap failed" {:errno (- result)})))))

(defrecord RingBufLayout
  [consumer-seg     ; MemorySegment for consumer position
   producer-seg     ; MemorySegment for producer position
   data-seg         ; MemorySegment for data area
   data-size        ; Size of data area in bytes
   base-addr        ; Base address for cleanup
   total-size])     ; Total mapped size for cleanup

(defn- map-ringbuf-internal
  "Memory-map a ring buffer map for internal use"
  [^BpfMap ringbuf-map]
  (let [fd (:fd ringbuf-map)
        max-entries (:max-entries ringbuf-map)
        total-size (+ (* 2 page-size) max-entries)
        addr (mmap fd total-size 3 1 0)  ; PROT_READ|PROT_WRITE, MAP_SHARED
        base-seg (.reinterpret (MemorySegment/ofAddress addr) total-size)
        consumer-seg (.asSlice base-seg 0 page-size)
        producer-seg (.asSlice base-seg page-size page-size)
        data-seg (.asSlice base-seg (* 2 page-size) max-entries)]
    (->RingBufLayout consumer-seg producer-seg data-seg max-entries addr total-size)))

(defn- unmap-ringbuf-internal
  "Unmap a ring buffer"
  [^RingBufLayout layout]
  (munmap (:base-addr layout) (:total-size layout)))

(defn- get-consumer-pos [^RingBufLayout layout]
  (.get (:consumer-seg layout) ValueLayout/JAVA_LONG 0))

(defn- set-consumer-pos! [^RingBufLayout layout pos]
  (.set (:consumer-seg layout) ValueLayout/JAVA_LONG 0 (long pos)))

(defn- get-producer-pos [^RingBufLayout layout]
  (.get (:producer-seg layout) ValueLayout/JAVA_LONG 0))

(defn- ring-buf-available [^RingBufLayout layout]
  (- (get-producer-pos layout) (get-consumer-pos layout)))

(defn- read-ring-buf-record
  "Read a single record from ring buffer"
  [^RingBufLayout layout]
  (let [available (ring-buf-available layout)]
    (when (>= available 8)  ; Need at least header (8 bytes with alignment)
      (let [consumer-pos (get-consumer-pos layout)
            data-seg (:data-seg layout)
            data-size (:data-size layout)
            offset (mod consumer-pos data-size)

            ;; Read record header - length is in first 4 bytes
            ;; BPF ring buffer header: u32 len (with flags in upper bits)
            len-byte-0 (.get data-seg ValueLayout/JAVA_BYTE (mod offset data-size))
            len-byte-1 (.get data-seg ValueLayout/JAVA_BYTE (mod (+ offset 1) data-size))
            len-byte-2 (.get data-seg ValueLayout/JAVA_BYTE (mod (+ offset 2) data-size))
            len-byte-3 (.get data-seg ValueLayout/JAVA_BYTE (mod (+ offset 3) data-size))

            ;; Combine bytes (little-endian)
            raw-len (bit-or (bit-and (int len-byte-0) 0xFF)
                           (bit-shift-left (bit-and (int len-byte-1) 0xFF) 8)
                           (bit-shift-left (bit-and (int len-byte-2) 0xFF) 16)
                           (bit-shift-left (bit-and (int len-byte-3) 0xFF) 24))

            ;; Extract length (lower 28 bits) and check busy/discard flags
            BPF_RINGBUF_BUSY_BIT 0x80000000
            BPF_RINGBUF_DISCARD_BIT 0x40000000
            record-len (bit-and raw-len 0x0FFFFFFF)
            is-busy? (not (zero? (bit-and raw-len BPF_RINGBUF_BUSY_BIT)))
            is-discard? (not (zero? (bit-and raw-len BPF_RINGBUF_DISCARD_BIT)))]

        (when (and (not is-busy?) (pos? record-len))
          ;; Round up to 8-byte alignment
          (let [aligned-len (bit-and (+ record-len 7) (bit-not 7))
                total-record-size (+ 8 aligned-len)]  ; 8 byte header + aligned data

            (when (<= total-record-size available)
              (if is-discard?
                ;; Skip discarded record
                (do
                  (set-consumer-pos! layout (+ consumer-pos total-record-size))
                  :discarded)
                ;; Read record data (after 8-byte header)
                (let [data (byte-array record-len)]
                  (doseq [i (range record-len)]
                    (aset data i
                      (.get data-seg ValueLayout/JAVA_BYTE
                            (mod (+ offset 8 i) data-size))))

                  ;; Update consumer position
                  (set-consumer-pos! layout (+ consumer-pos total-record-size))

                  {:data data :size record-len})))))))))

;; ============================================================================
;; Epoll Support
;; ============================================================================

(def ^:private EPOLL_CTL_ADD 1)
(def ^:private EPOLL_CTL_DEL 2)
(def ^:private EPOLLIN 0x001)

(defn- epoll-create []
  (let [epoll-create1-nr (arch/get-syscall-nr :epoll-create1)
        result (syscall/raw-syscall epoll-create1-nr 0)]
    (when (neg? result)
      (throw (ex-info "epoll_create1 failed" {:errno (- result)})))
    result))

(defn- epoll-ctl [epfd op fd events]
  (let [epoll-ctl-nr (arch/get-syscall-nr :epoll-ctl)
        event-bytes (utils/pack-struct [[:u32 events] [:u64 fd]])
        event-seg (utils/bytes->segment event-bytes)
        result (syscall/raw-syscall epoll-ctl-nr epfd op fd event-seg)]
    (when (neg? result)
      (throw (ex-info "epoll_ctl failed" {:errno (- result) :op op :fd fd})))))

(defn- epoll-wait-single
  "Wait for events on epoll instance, returns true if fd is ready"
  [epfd timeout-ms]
  (let [epoll-pwait-nr (arch/get-syscall-nr :epoll-pwait)
        events-seg (utils/allocate-memory 12)  ; Single event
        result (syscall/raw-syscall epoll-pwait-nr epfd events-seg 1 timeout-ms 0)]
    (if (neg? result)
      (if (= (- result) 4)  ; EINTR
        false
        (throw (ex-info "epoll_pwait failed" {:errno (- result)})))
      (pos? result))))

;; ============================================================================
;; RingBufRef - Deref-able Ring Buffer Reference
;; ============================================================================

(deftype RingBufRef [^BpfMap ringbuf-map
                     ^:volatile-mutable layout
                     ^:volatile-mutable epoll-fd
                     deserializer
                     ^AtomicBoolean closed?]

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  clojure.lang.IBlockingDeref
  (deref [this timeout-ms timeout-val]
    (when (.get closed?)
      (throw (ex-info "RingBufRef is closed" {:map (:name ringbuf-map)})))

    (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
      (loop []
        (when (.get closed?)
          (throw (ex-info "RingBufRef closed during deref" {})))

        ;; Try to read a record
        (let [record (read-ring-buf-record layout)]
          (cond
            ;; Got data
            (and (map? record) (:data record))
            (deserializer (:data record))

            ;; Discarded record, try again immediately
            (= record :discarded)
            (recur)

            ;; No data available - wait with epoll
            :else
            (let [remaining (- deadline (System/currentTimeMillis))]
              (if (pos? remaining)
                (do
                  (epoll-wait-single epoll-fd (min remaining 100))
                  (recur))
                timeout-val)))))))

  java.io.Closeable
  (close [this]
    (when (compare-and-set! closed? false true)
      (try
        (epoll-ctl epoll-fd EPOLL_CTL_DEL (:fd ringbuf-map) 0)
        (catch Exception _))
      (syscall/close-fd epoll-fd)
      (unmap-ringbuf-internal layout))))

(defn ringbuf-ref
  "Create a deref-able reference to a ring buffer.

   The returned reference supports the @ reader macro for blocking reads:

     @ref                    ; blocks indefinitely until event available
     (deref ref 1000 nil)    ; waits up to 1000ms, returns nil on timeout

   Options:
   - :deserializer - Function to transform raw event bytes (default: identity)

   The reference must be closed when done to release resources:

     (.close ref)

   Example:
     (let [ref (ringbuf-ref my-ringbuf :deserializer parse-event)]
       (try
         (loop []
           (when-let [event (deref ref 5000 nil)]
             (process event)
             (recur)))
         (finally
           (.close ref))))"
  [ringbuf-map & {:keys [deserializer] :or {deserializer identity}}]
  (let [layout (map-ringbuf-internal ringbuf-map)
        epoll-fd (epoll-create)
        _ (epoll-ctl epoll-fd EPOLL_CTL_ADD (:fd ringbuf-map) EPOLLIN)]
    (->RingBufRef ringbuf-map layout epoll-fd deserializer (AtomicBoolean. false))))

(defn ringbuf-seq
  "Returns a lazy sequence of ring buffer events.

   Each call to the sequence blocks until an event is available.
   The sequence is infinite - use take or other limiting functions.

   Options:
   - :deserializer - Function to transform raw event bytes
   - :timeout-ms - Timeout for each read (default: infinite)
   - :timeout-val - Value returned on timeout (stops sequence if nil)

   Example:
     ;; Process 100 events
     (let [ref (ringbuf-ref my-ringbuf)]
       (try
         (doseq [event (take 100 (ringbuf-seq ref))]
           (process event))
         (finally
           (.close ref))))

     ;; With timeout - sequence ends on timeout
     (doseq [event (ringbuf-seq ref :timeout-ms 5000)]
       (process event))"
  [^RingBufRef ref & {:keys [timeout-ms timeout-val]
                      :or {timeout-ms Long/MAX_VALUE
                           timeout-val ::timeout}}]
  (take-while
    #(not= % ::timeout)
    (repeatedly #(deref ref timeout-ms timeout-val))))

;; ============================================================================
;; QueueRef - Deref-able Queue/Stack Reference
;; ============================================================================

(deftype QueueRef [^BpfMap bpf-map
                   pop-fn
                   poll-interval-ms
                   ^AtomicBoolean closed?]

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  clojure.lang.IBlockingDeref
  (deref [this timeout-ms timeout-val]
    (when (.get closed?)
      (throw (ex-info "QueueRef is closed" {:map (:name bpf-map)})))

    (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
      (loop []
        (when (.get closed?)
          (throw (ex-info "QueueRef closed during deref" {})))

        (if-let [value (pop-fn bpf-map)]
          value
          (let [remaining (- deadline (System/currentTimeMillis))]
            (if (pos? remaining)
              (do
                (Thread/sleep (min poll-interval-ms remaining))
                (recur))
              timeout-val))))))

  java.io.Closeable
  (close [this]
    (.set closed? true)))

(defn queue-ref
  "Create a deref-able reference to a queue map.

   The returned reference supports blocking pop operations via deref:

     @ref                    ; blocks until item available (FIFO pop)
     (deref ref 1000 nil)    ; waits up to 1000ms, returns nil on timeout

   Options:
   - :poll-interval-ms - How often to check for items (default: 10ms)

   Example:
     (let [ref (queue-ref my-queue)]
       (try
         (loop []
           (when-let [item @ref]
             (process item)
             (recur)))
         (finally
           (.close ref))))"
  [bpf-map & {:keys [poll-interval-ms] :or {poll-interval-ms 10}}]
  (->QueueRef bpf-map maps/queue-pop poll-interval-ms (AtomicBoolean. false)))

(defn stack-ref
  "Create a deref-able reference to a stack map.

   The returned reference supports blocking pop operations via deref:

     @ref                    ; blocks until item available (LIFO pop)
     (deref ref 1000 nil)    ; waits up to 1000ms, returns nil on timeout

   Options:
   - :poll-interval-ms - How often to check for items (default: 10ms)

   Example:
     (let [ref (stack-ref my-stack)]
       (try
         (when-let [item (deref ref 5000 :empty)]
           (process item))
         (finally
           (.close ref))))"
  [bpf-map & {:keys [poll-interval-ms] :or {poll-interval-ms 10}}]
  (->QueueRef bpf-map maps/stack-pop poll-interval-ms (AtomicBoolean. false)))

(defn queue-seq
  "Returns a lazy sequence that pops items from a queue.

   Each element retrieval blocks until an item is available.

   Options:
   - :timeout-ms - Timeout for each pop (default: infinite)
   - :timeout-val - Value returned on timeout (stops sequence if ::timeout)

   Example:
     (let [ref (queue-ref my-queue)]
       (try
         (doseq [item (take 50 (queue-seq ref))]
           (process item))
         (finally
           (.close ref))))"
  [^QueueRef ref & {:keys [timeout-ms timeout-val]
                    :or {timeout-ms Long/MAX_VALUE
                         timeout-val ::timeout}}]
  (take-while
    #(not= % ::timeout)
    (repeatedly #(deref ref timeout-ms timeout-val))))

;; ============================================================================
;; MapWatcher - Watch for Key Changes
;; ============================================================================

(deftype MapWatcher [^BpfMap bpf-map
                     key
                     poll-interval-ms
                     ^AtomicReference last-value
                     ^AtomicBoolean closed?]

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  clojure.lang.IBlockingDeref
  (deref [this timeout-ms timeout-val]
    (when (.get closed?)
      (throw (ex-info "MapWatcher is closed" {:map (:name bpf-map) :key key})))

    (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
      (loop []
        (when (.get closed?)
          (throw (ex-info "MapWatcher closed during deref" {})))

        (if-let [value (maps/map-lookup bpf-map key)]
          (do
            (.set last-value value)
            value)
          (let [remaining (- deadline (System/currentTimeMillis))]
            (if (pos? remaining)
              (do
                (Thread/sleep (min poll-interval-ms remaining))
                (recur))
              timeout-val))))))

  java.io.Closeable
  (close [this]
    (.set closed? true)))

(defn map-watch
  "Create a deref-able watcher for a specific key in a BPF map.

   The returned reference blocks until the key has a value:

     @ref                    ; blocks until key exists in map
     (deref ref 1000 nil)    ; waits up to 1000ms, returns nil on timeout

   Options:
   - :poll-interval-ms - How often to check the map (default: 10ms)

   Example:
     ;; Wait for a counter to be initialized
     (let [watcher (map-watch stats-map :packet-count)]
       (try
         (let [initial-count (deref watcher 5000 0)]
           (println \"Initial count:\" initial-count))
         (finally
           (.close watcher))))"
  [bpf-map key & {:keys [poll-interval-ms] :or {poll-interval-ms 10}}]
  (->MapWatcher bpf-map key poll-interval-ms (AtomicReference. nil) (AtomicBoolean. false)))

(deftype MapChangeWatcher [^BpfMap bpf-map
                           key
                           poll-interval-ms
                           ^AtomicReference last-value
                           ^AtomicBoolean closed?]

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  clojure.lang.IBlockingDeref
  (deref [this timeout-ms timeout-val]
    (when (.get closed?)
      (throw (ex-info "MapChangeWatcher is closed" {:map (:name bpf-map) :key key})))

    (let [deadline (+ (System/currentTimeMillis) timeout-ms)
          current-last (.get last-value)]
      (loop []
        (when (.get closed?)
          (throw (ex-info "MapChangeWatcher closed during deref" {})))

        (let [value (maps/map-lookup bpf-map key)]
          (if (and (some? value) (not= value current-last))
            (do
              (.set last-value value)
              value)
            (let [remaining (- deadline (System/currentTimeMillis))]
              (if (pos? remaining)
                (do
                  (Thread/sleep (min poll-interval-ms remaining))
                  (recur))
                timeout-val)))))))

  java.io.Closeable
  (close [this]
    (.set closed? true)))

(defn map-watch-changes
  "Create a watcher that blocks until a map value changes.

   Unlike map-watch which returns when any value exists, this watcher
   only returns when the value differs from the last observed value.

     @ref                    ; blocks until value changes
     (deref ref 1000 nil)    ; waits up to 1000ms for change

   Options:
   - :poll-interval-ms - How often to check the map (default: 10ms)
   - :initial-value - Consider this the 'last' value initially

   Example:
     ;; Watch for counter updates
     (let [watcher (map-watch-changes stats-map :counter)]
       (try
         (loop [count 0]
           (when (< count 10)
             (let [new-val @watcher]
               (println \"Counter changed to:\" new-val)
               (recur (inc count)))))
         (finally
           (.close watcher))))"
  [bpf-map key & {:keys [poll-interval-ms initial-value]
                  :or {poll-interval-ms 10 initial-value nil}}]
  (->MapChangeWatcher bpf-map key poll-interval-ms
                      (AtomicReference. initial-value)
                      (AtomicBoolean. false)))

;; ============================================================================
;; Convenience Macros
;; ============================================================================

(defmacro with-ringbuf-ref
  "Create a ring buffer reference with automatic cleanup.

   Example:
     (with-ringbuf-ref [ref my-ringbuf :deserializer parse-event]
       (dotimes [_ 10]
         (println @ref)))"
  [[binding ringbuf-map & opts] & body]
  `(let [~binding (ringbuf-ref ~ringbuf-map ~@opts)]
     (try
       ~@body
       (finally
         (.close ~binding)))))

(defmacro with-queue-ref
  "Create a queue reference with automatic cleanup.

   Example:
     (with-queue-ref [ref my-queue]
       (when-let [item (deref ref 5000 nil)]
         (process item)))"
  [[binding queue-map & opts] & body]
  `(let [~binding (queue-ref ~queue-map ~@opts)]
     (try
       ~@body
       (finally
         (.close ~binding)))))

(defmacro with-stack-ref
  "Create a stack reference with automatic cleanup.

   Example:
     (with-stack-ref [ref my-stack]
       (when-let [item @ref]
         (process item)))"
  [[binding stack-map & opts] & body]
  `(let [~binding (stack-ref ~stack-map ~@opts)]
     (try
       ~@body
       (finally
         (.close ~binding)))))

(defmacro with-map-watcher
  "Create a map watcher with automatic cleanup.

   Example:
     (with-map-watcher [w stats-map :packet-count]
       (println \"Packets:\" @w))"
  [[binding bpf-map key & opts] & body]
  `(let [~binding (map-watch ~bpf-map ~key ~@opts)]
     (try
       ~@body
       (finally
         (.close ~binding)))))

;; ============================================================================
;; Writable References - Atom-like Semantics for BPF Maps
;; ============================================================================

(deftype MapEntryRef [^BpfMap bpf-map
                      key
                      ^AtomicReference cached-value
                      validator-fn
                      ^AtomicBoolean closed?]

  clojure.lang.IDeref
  (deref [_]
    (when (.get closed?)
      (throw (ex-info "MapEntryRef is closed" {:map (:name bpf-map) :key key})))
    (let [val (maps/map-lookup bpf-map key)]
      (.set cached-value val)
      val))

  clojure.lang.IRef
  (setValidator [_ f]
    (throw (UnsupportedOperationException. "Use map-entry-ref :validator option")))
  (getValidator [_]
    validator-fn)
  (getWatches [_]
    {})  ; Watches not supported for BPF maps
  (addWatch [_ _ _]
    (throw (UnsupportedOperationException. "Watches not supported for BPF maps")))
  (removeWatch [_ _]
    (throw (UnsupportedOperationException. "Watches not supported for BPF maps")))

  clojure.lang.IAtom
  (reset [this new-val]
    (when (.get closed?)
      (throw (ex-info "MapEntryRef is closed" {:map (:name bpf-map) :key key})))
    (when (and validator-fn (not (validator-fn new-val)))
      (throw (IllegalStateException. "Invalid reference state")))
    (maps/map-update bpf-map key new-val)
    (.set cached-value new-val)
    new-val)

  (swap [this f]
    (when (.get closed?)
      (throw (ex-info "MapEntryRef is closed" {:map (:name bpf-map) :key key})))
    (loop []
      (let [old-val (maps/map-lookup bpf-map key)
            new-val (f old-val)]
        (when (and validator-fn (not (validator-fn new-val)))
          (throw (IllegalStateException. "Invalid reference state")))
        ;; Note: This is not truly atomic at the kernel level for hash maps
        ;; For true atomicity, use atomic operations in BPF programs
        (maps/map-update bpf-map key new-val)
        (.set cached-value new-val)
        new-val)))

  (swap [this f arg1]
    (.swap this #(f % arg1)))

  (swap [this f arg1 arg2]
    (.swap this #(f % arg1 arg2)))

  (swap [this f arg1 arg2 args]
    (.swap this #(apply f % arg1 arg2 args)))

  (compareAndSet [this old-val new-val]
    (when (.get closed?)
      (throw (ex-info "MapEntryRef is closed" {:map (:name bpf-map) :key key})))
    (when (and validator-fn (not (validator-fn new-val)))
      (throw (IllegalStateException. "Invalid reference state")))
    (let [current (maps/map-lookup bpf-map key)]
      (if (= current old-val)
        (do
          (maps/map-update bpf-map key new-val)
          (.set cached-value new-val)
          true)
        false)))

  java.io.Closeable
  (close [_]
    (.set closed? true)))

(defn map-entry-ref
  "Create an atom-like reference to a specific key in a BPF map.

   Supports standard Clojure atom operations:
   - @ref / (deref ref) - read current value
   - (reset! ref val) - set new value
   - (swap! ref f) - read-modify-write
   - (compare-and-set! ref old new) - conditional update

   Note: swap! and compare-and-set! are NOT truly atomic at the kernel level
   for hash maps. For true atomicity with concurrent BPF programs, use
   atomic BPF map operations within the BPF program itself.

   Options:
   - :validator - Function to validate new values (throws on invalid)

   Example:
     (let [counter (map-entry-ref stats-map :packet-count)]
       ;; Read
       (println \"Count:\" @counter)

       ;; Write
       (reset! counter 0)

       ;; Read-modify-write
       (swap! counter inc)
       (swap! counter + 10)

       (.close counter))"
  [bpf-map key & {:keys [validator]}]
  (->MapEntryRef bpf-map key (AtomicReference. nil) validator (AtomicBoolean. false)))

(defmacro with-map-entry-ref
  "Create a map entry reference with automatic cleanup.

   Example:
     (with-map-entry-ref [counter stats-map :packet-count]
       (println \"Before:\" @counter)
       (swap! counter inc)
       (println \"After:\" @counter))"
  [[binding bpf-map key & opts] & body]
  `(let [~binding (map-entry-ref ~bpf-map ~key ~@opts)]
     (try
       ~@body
       (finally
         (.close ~binding)))))

;; ============================================================================
;; Writable Queue/Stack References
;; ============================================================================

(deftype QueueWriter [^BpfMap bpf-map
                      ^AtomicBoolean closed?]

  clojure.lang.IDeref
  (deref [_]
    (when (.get closed?)
      (throw (ex-info "QueueWriter is closed" {:map (:name bpf-map)})))
    ;; Peek at front without removing
    (maps/queue-peek bpf-map))

  clojure.lang.ITransientCollection
  (conj [this val]
    (when (.get closed?)
      (throw (ex-info "QueueWriter is closed" {:map (:name bpf-map)})))
    (maps/queue-push bpf-map val)
    this)

  (persistent [_]
    (throw (UnsupportedOperationException. "BPF queues cannot be made persistent")))

  java.io.Closeable
  (close [_]
    (.set closed? true)))

(defn queue-writer
  "Create a writable reference to a BPF queue map.

   Supports conj! for adding items:
   - (conj! ref val) - push value to queue (enqueue)
   - @ref - peek at front value without removing

   For blocking pop, use queue-ref instead.

   Example:
     (let [q (queue-writer my-queue)]
       ;; Add items
       (-> q
           (conj! {:event :start})
           (conj! {:event :data :value 42})
           (conj! {:event :end}))

       ;; Peek (non-blocking)
       (println \"Front:\" @q)

       (.close q))"
  [bpf-map]
  (->QueueWriter bpf-map (AtomicBoolean. false)))

(deftype StackWriter [^BpfMap bpf-map
                      ^AtomicBoolean closed?]

  clojure.lang.IDeref
  (deref [_]
    (when (.get closed?)
      (throw (ex-info "StackWriter is closed" {:map (:name bpf-map)})))
    ;; Peek at top without removing
    (maps/stack-peek bpf-map))

  clojure.lang.ITransientCollection
  (conj [this val]
    (when (.get closed?)
      (throw (ex-info "StackWriter is closed" {:map (:name bpf-map)})))
    (maps/stack-push bpf-map val)
    this)

  (persistent [_]
    (throw (UnsupportedOperationException. "BPF stacks cannot be made persistent")))

  java.io.Closeable
  (close [_]
    (.set closed? true)))

(defn stack-writer
  "Create a writable reference to a BPF stack map.

   Supports conj! for adding items:
   - (conj! ref val) - push value to stack
   - @ref - peek at top value without removing

   For blocking pop, use stack-ref instead.

   Example:
     (let [s (stack-writer my-stack)]
       ;; Push items
       (conj! s :first)
       (conj! s :second)
       (conj! s :third)

       ;; Peek (non-blocking)
       (println \"Top:\" @s)  ; => :third

       (.close s))"
  [bpf-map]
  (->StackWriter bpf-map (AtomicBoolean. false)))

(defmacro with-queue-writer
  "Create a queue writer with automatic cleanup.

   Example:
     (with-queue-writer [q my-queue]
       (conj! q {:event :start})
       (conj! q {:event :end}))"
  [[binding queue-map] & body]
  `(let [~binding (queue-writer ~queue-map)]
     (try
       ~@body
       (finally
         (.close ~binding)))))

(defmacro with-stack-writer
  "Create a stack writer with automatic cleanup.

   Example:
     (with-stack-writer [s my-stack]
       (conj! s :a)
       (conj! s :b))"
  [[binding stack-map] & body]
  `(let [~binding (stack-writer ~stack-map)]
     (try
       ~@body
       (finally
         (.close ~binding)))))

;; ============================================================================
;; Combined Read/Write References
;; ============================================================================

(deftype QueueChannel [^BpfMap bpf-map
                       poll-interval-ms
                       ^AtomicBoolean closed?]

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  clojure.lang.IBlockingDeref
  (deref [_ timeout-ms timeout-val]
    (when (.get closed?)
      (throw (ex-info "QueueChannel is closed" {:map (:name bpf-map)})))
    (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
      (loop []
        (when (.get closed?)
          (throw (ex-info "QueueChannel closed during deref" {})))
        (if-let [value (maps/queue-pop bpf-map)]
          value
          (let [remaining (- deadline (System/currentTimeMillis))]
            (if (pos? remaining)
              (do
                (Thread/sleep (min poll-interval-ms remaining))
                (recur))
              timeout-val))))))

  clojure.lang.ITransientCollection
  (conj [this val]
    (when (.get closed?)
      (throw (ex-info "QueueChannel is closed" {:map (:name bpf-map)})))
    (maps/queue-push bpf-map val)
    this)

  (persistent [_]
    (throw (UnsupportedOperationException. "BPF queues cannot be made persistent")))

  java.io.Closeable
  (close [_]
    (.set closed? true)))

(defn queue-channel
  "Create a bidirectional channel-like reference to a BPF queue.

   Combines reading and writing:
   - @ref / (deref ref timeout val) - blocking pop (FIFO)
   - (conj! ref val) - push to queue

   This is useful for producer-consumer patterns where userspace
   both reads and writes to the same queue.

   Options:
   - :poll-interval-ms - How often to poll when waiting (default: 10ms)

   Example:
     (let [ch (queue-channel work-queue)]
       ;; Producer thread
       (future
         (dotimes [i 100]
           (conj! ch {:task i})))

       ;; Consumer thread
       (future
         (loop []
           (when-let [task (deref ch 5000 nil)]
             (process task)
             (recur))))

       (.close ch))"
  [bpf-map & {:keys [poll-interval-ms] :or {poll-interval-ms 10}}]
  (->QueueChannel bpf-map poll-interval-ms (AtomicBoolean. false)))

(deftype StackChannel [^BpfMap bpf-map
                       poll-interval-ms
                       ^AtomicBoolean closed?]

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  clojure.lang.IBlockingDeref
  (deref [_ timeout-ms timeout-val]
    (when (.get closed?)
      (throw (ex-info "StackChannel is closed" {:map (:name bpf-map)})))
    (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
      (loop []
        (when (.get closed?)
          (throw (ex-info "StackChannel closed during deref" {})))
        (if-let [value (maps/stack-pop bpf-map)]
          value
          (let [remaining (- deadline (System/currentTimeMillis))]
            (if (pos? remaining)
              (do
                (Thread/sleep (min poll-interval-ms remaining))
                (recur))
              timeout-val))))))

  clojure.lang.ITransientCollection
  (conj [this val]
    (when (.get closed?)
      (throw (ex-info "StackChannel is closed" {:map (:name bpf-map)})))
    (maps/stack-push bpf-map val)
    this)

  (persistent [_]
    (throw (UnsupportedOperationException. "BPF stacks cannot be made persistent")))

  java.io.Closeable
  (close [_]
    (.set closed? true)))

(defn stack-channel
  "Create a bidirectional channel-like reference to a BPF stack.

   Combines reading and writing:
   - @ref / (deref ref timeout val) - blocking pop (LIFO)
   - (conj! ref val) - push to stack

   Options:
   - :poll-interval-ms - How often to poll when waiting (default: 10ms)

   Example:
     (let [ch (stack-channel undo-stack)]
       ;; Push operations
       (conj! ch {:action :insert :pos 0 :text \"Hello\"})
       (conj! ch {:action :insert :pos 5 :text \" World\"})

       ;; Pop to undo (LIFO)
       (let [last-op @ch]
         (undo last-op))

       (.close ch))"
  [bpf-map & {:keys [poll-interval-ms] :or {poll-interval-ms 10}}]
  (->StackChannel bpf-map poll-interval-ms (AtomicBoolean. false)))

(defmacro with-queue-channel
  "Create a queue channel with automatic cleanup.

   Example:
     (with-queue-channel [ch work-queue]
       (conj! ch {:task :process})
       (let [result @ch]
         (handle result)))"
  [[binding queue-map & opts] & body]
  `(let [~binding (queue-channel ~queue-map ~@opts)]
     (try
       ~@body
       (finally
         (.close ~binding)))))

(defmacro with-stack-channel
  "Create a stack channel with automatic cleanup.

   Example:
     (with-stack-channel [ch undo-stack]
       (conj! ch {:op :insert})
       (when-let [op (deref ch 1000 nil)]
         (undo op)))"
  [[binding stack-map & opts] & body]
  `(let [~binding (stack-channel ~stack-map ~@opts)]
     (try
       ~@body
       (finally
         (.close ~binding)))))
