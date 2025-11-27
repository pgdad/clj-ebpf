(ns clj-ebpf.refs
  "Deref-able references for BPF data structures.

   This namespace provides Clojure reference types that implement IDeref
   and IBlockingDeref, allowing natural use of the @ reader macro for
   blocking reads from BPF data structures.

   Three reference types are provided:

   1. RingBufRef - Blocking reads from ring buffers
      @ref           ; blocks until event available
      (deref ref 1000 nil)  ; 1s timeout, nil on timeout

   2. QueueRef - Blocking pops from queue/stack maps
      @ref           ; blocks until item available
      (deref ref 500 :empty)  ; 500ms timeout

   3. MapWatcher - Watch for a key to appear/change in a map
      @ref           ; blocks until key has a value
      (deref ref 2000 :missing)  ; 2s timeout"
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
