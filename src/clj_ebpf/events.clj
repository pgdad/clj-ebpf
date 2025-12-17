(ns clj-ebpf.events
  "Enhanced BPF event reading from ring buffers with memory mapping and epoll support"
  (:require [clj-ebpf.syscall :as syscall]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.constants :as const]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.maps :as maps])
  (:import [java.lang.foreign Arena MemorySegment ValueLayout]
           [java.nio ByteBuffer ByteOrder]
           [java.util.concurrent ArrayBlockingQueue TimeUnit]
           [java.util.concurrent.atomic AtomicBoolean AtomicLong]
           [clj_ebpf.maps BpfMap]))

;; ============================================================================
;; Ring Buffer Memory Layout
;; ============================================================================

;; Ring buffer structure (from kernel):
;; struct bpf_ringbuf {
;;   u32 consumer_pos;  // Consumer position (offset 0)
;;   u32 producer_pos;  // Producer position (offset 4096, on separate page)
;;   char data[];       // Data area (starts at offset 8192, size = page_size * page_cnt)
;; }

(def ^:private page-size 4096)

(defrecord RingBufLayout
  [consumer-seg     ; MemorySegment for consumer position
   producer-seg     ; MemorySegment for producer position
   data-seg         ; MemorySegment for data area
   data-size])      ; Size of data area in bytes

;; ============================================================================
;; Memory Mapping
;; ============================================================================

(defn- mmap
  "Memory map a file descriptor

  Parameters:
  - fd: File descriptor
  - length: Length in bytes
  - prot: Protection flags (PROT_READ=1, PROT_WRITE=2)
  - flags: Mapping flags (MAP_SHARED=1)
  - offset: Offset in file"
  [fd length prot flags offset]
  (let [mmap-nr (arch/get-syscall-nr :mmap)
        result (syscall/raw-syscall mmap-nr 0 length prot flags fd offset)]
    (when (neg? result)
      (throw (ex-info "mmap failed" {:errno (- result) :fd fd :length length})))
    result))

(defn- munmap
  "Unmap memory

  Parameters:
  - addr: Address to unmap
  - length: Length in bytes"
  [addr length]
  (let [munmap-nr (arch/get-syscall-nr :munmap)
        result (syscall/raw-syscall munmap-nr addr length)]
    (when (neg? result)
      (throw (ex-info "munmap failed" {:errno (- result)})))))

(defn map-ringbuf
  "Memory-map a ring buffer map

  Parameters:
  - ringbuf-map: BPF ring buffer map

  Returns RingBufLayout with memory segments for consumer, producer, and data"
  [^BpfMap ringbuf-map]
  (let [fd (:fd ringbuf-map)
        max-entries (:max-entries ringbuf-map)

        ;; Ring buffer layout (requires two separate mmaps):
        ;; - Page 0: consumer_pos (writable by consumer)
        ;; - Page 1: producer_pos (read-only)
        ;; - Page 2+: data area (read-only, size = max-entries)
        ;;
        ;; BPF ring buffers require:
        ;; 1. Consumer page mapped with PROT_READ | PROT_WRITE
        ;; 2. Producer + data pages mapped with PROT_READ only

        ;; PROT_READ=1, PROT_WRITE=2, MAP_SHARED=1

        ;; Map consumer page (read/write) at offset 0
        consumer-addr (mmap fd page-size 3 1 0)  ; PROT_READ | PROT_WRITE

        ;; Map producer + data pages (read-only) at offset page-size
        ;; The data area needs to be mapped twice its size for wraparound reads
        producer-data-size (+ page-size (* 2 max-entries))
        producer-addr (mmap fd producer-data-size 1 1 page-size)  ; PROT_READ only

        ;; Create MemorySegments for each region
        consumer-seg (.reinterpret (MemorySegment/ofAddress consumer-addr) page-size)
        producer-seg (.reinterpret (MemorySegment/ofAddress producer-addr) page-size)
        data-seg (.reinterpret (MemorySegment/ofAddress (+ producer-addr page-size)) max-entries)]

    (->RingBufLayout consumer-seg producer-seg data-seg max-entries)))

(defn unmap-ringbuf
  "Unmap a ring buffer

  Parameters:
  - layout: RingBufLayout from map-ringbuf"
  [^RingBufLayout layout]
  (let [consumer-addr (.address (:consumer-seg layout))
        producer-addr (.address (:producer-seg layout))
        producer-data-size (+ page-size (* 2 (:data-size layout)))]
    ;; Unmap both mappings
    (munmap consumer-addr page-size)
    (munmap producer-addr producer-data-size)))

;; ============================================================================
;; Ring Buffer Operations
;; ============================================================================

(defn- get-consumer-pos
  "Get current consumer position (read by user-space)"
  [^RingBufLayout layout]
  (.get (:consumer-seg layout) ValueLayout/JAVA_LONG 0))

(defn- set-consumer-pos!
  "Set consumer position (written by user-space)"
  [^RingBufLayout layout pos]
  (.set (:consumer-seg layout) ValueLayout/JAVA_LONG 0 (long pos)))

(defn- get-producer-pos
  "Get current producer position (written by kernel/BPF)"
  [^RingBufLayout layout]
  (.get (:producer-seg layout) ValueLayout/JAVA_LONG 0))

(defn- ring-buf-available
  "Get number of bytes available to read"
  [^RingBufLayout layout]
  (let [consumer (get-consumer-pos layout)
        producer (get-producer-pos layout)]
    (- producer consumer)))

(defn- read-ring-buf-record
  "Read a single record from ring buffer

  Ring buffer record format:
  - u32 len: Length of record (including header)
  - u8 data[len-4]: Record data

  Returns:
  - {:data byte-array :size int} or nil if no data available"
  [^RingBufLayout layout]
  (let [available (ring-buf-available layout)]
    (when (>= available 4) ; Need at least header
      (let [consumer-pos (get-consumer-pos layout)
            data-seg (:data-seg layout)
            data-size (:data-size layout)

            ;; Ring buffer wraps around
            offset (mod consumer-pos data-size)

            ;; Read record length (first 4 bytes)
            len-bytes (byte-array 4)
            _ (doseq [i (range 4)]
                (aset len-bytes i
                  (.get data-seg ValueLayout/JAVA_BYTE (mod (+ offset i) data-size))))

            record-len (utils/bytes->int len-bytes)
            data-len (- record-len 4)]

        (when (and (pos? record-len) (<= record-len available))
          ;; Read record data
          (let [data (byte-array data-len)]
            (doseq [i (range data-len)]
              (aset data i
                (.get data-seg ValueLayout/JAVA_BYTE (mod (+ offset 4 i) data-size))))

            ;; Update consumer position
            (set-consumer-pos! layout (+ consumer-pos record-len))

            {:data data :size record-len}))))))

(defn read-ringbuf-events
  "Read multiple events from ring buffer

  Parameters:
  - layout: RingBufLayout
  - max-events: Maximum number of events to read (default: all available)

  Returns vector of event byte arrays"
  [^RingBufLayout layout & {:keys [max-events] :or {max-events Integer/MAX_VALUE}}]
  (loop [events []
         count 0]
    (if (and (< count max-events)
             (pos? (ring-buf-available layout)))
      (if-let [record (read-ring-buf-record layout)]
        (recur (conj events (:data record)) (inc count))
        events)
      events)))

;; ============================================================================
;; Epoll Support
;; ============================================================================

(def ^:private EPOLL_CTL_ADD 1)
(def ^:private EPOLL_CTL_DEL 2)
(def ^:private EPOLL_CTL_MOD 3)
(def ^:private EPOLLIN 0x001)
(def ^:private EPOLLOUT 0x004)

(defn- epoll-create
  "Create an epoll instance

  Returns epoll file descriptor"
  []
  (let [epoll-create1-nr (arch/get-syscall-nr :epoll-create1)
        result (syscall/raw-syscall epoll-create1-nr 1)]
    (when (neg? result)
      (throw (ex-info "epoll_create1 failed" {:errno (- result)})))
    result))

(defn- epoll-ctl
  "Control epoll instance

  Parameters:
  - epfd: Epoll file descriptor
  - op: Operation (EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD)
  - fd: File descriptor to add/remove/modify
  - events: Event mask (EPOLLIN, EPOLLOUT, etc.)"
  [epfd op fd events]
  (let [epoll-ctl-nr (arch/get-syscall-nr :epoll-ctl)
        ;; struct epoll_event { u32 events; u64 data; }
        event-bytes (utils/pack-struct [[:u32 events] [:u64 fd]])
        event-seg (utils/bytes->segment event-bytes)
        result (syscall/raw-syscall epoll-ctl-nr epfd op fd event-seg)]
    (when (neg? result)
      (throw (ex-info "epoll_ctl failed" {:errno (- result) :op op :fd fd})))))

(defn- epoll-wait
  "Wait for events on epoll instance

  Parameters:
  - epfd: Epoll file descriptor
  - timeout-ms: Timeout in milliseconds (-1 = infinite)

  Returns vector of ready file descriptors"
  [epfd timeout-ms]
  (let [epoll-pwait-nr (arch/get-syscall-nr :epoll-pwait)
        max-events 64
        ;; Allocate buffer for events (12 bytes per event: 4 bytes events + 8 bytes data)
        events-seg (utils/allocate-memory (* max-events 12))
        ;; Use epoll_pwait with NULL sigmask for portability (arm64/riscv64 don't have epoll_wait)
        result (syscall/raw-syscall epoll-pwait-nr epfd events-seg max-events timeout-ms 0)]
    (if (neg? result)
      (throw (ex-info "epoll_pwait failed" {:errno (- result)}))
      ;; Parse ready fds
      (vec (for [i (range result)]
             (let [offset (* i 12)
                   ;; Read data field (fd)
                   fd-bytes (utils/segment->bytes (.asSlice events-seg (+ offset 4) 8) 8)]
               (utils/bytes->long fd-bytes)))))))

;; ============================================================================
;; Ring Buffer Consumer
;; ============================================================================

(defrecord RingBufConsumer
  [map              ; The ringbuf map
   layout           ; RingBufLayout (memory-mapped)
   epoll-fd         ; Epoll file descriptor
   running?         ; AtomicBoolean for running state
   poll-thread      ; Thread for polling
   callback         ; Callback function for events
   deserializer     ; Function to deserialize event data
   stats])          ; Atom with statistics

(defn create-ringbuf-consumer
  "Create an enhanced ring buffer consumer with memory mapping and epoll

  Options:
  - :map - The ring buffer map (required)
  - :callback - Function called for each event (receives event data)
  - :deserializer - Optional function to deserialize event bytes
  - :batch-size - Number of events to read in each batch (default: 64)"
  [{:keys [map callback deserializer batch-size]
    :or {deserializer identity
         batch-size 64}}]
  (let [layout (map-ringbuf map)
        epoll-fd (epoll-create)
        _ (epoll-ctl epoll-fd EPOLL_CTL_ADD (:fd map) EPOLLIN)
        running? (AtomicBoolean. false)
        stats (atom {:events-read 0
                    :events-processed 0
                    :batches-read 0
                    :errors 0
                    :start-time nil
                    :last-event-time nil})]
    (->RingBufConsumer map layout epoll-fd running? nil callback deserializer stats)))

(defn start-ringbuf-consumer
  "Start consuming events from ring buffer with epoll-based notification"
  [^RingBufConsumer consumer]
  (.set (:running? consumer) true)
  (swap! (:stats consumer) assoc :start-time (System/currentTimeMillis))

  (let [poll-thread
        (Thread.
          (fn []
            (try
              (while (.get (:running? consumer))
                (try
                  ;; Wait for events with epoll (100ms timeout)
                  (let [ready-fds (epoll-wait (:epoll-fd consumer) 100)]
                    (when (seq ready-fds)
                      ;; Read batch of events
                      (let [events (read-ringbuf-events (:layout consumer)
                                                        :max-events 64)]
                        (when (seq events)
                          (swap! (:stats consumer)
                                update :batches-read inc)
                          (swap! (:stats consumer)
                                update :events-read + (count events))

                          ;; Process each event
                          (doseq [event-bytes events]
                            (try
                              (let [deserialized ((:deserializer consumer) event-bytes)]
                                ((:callback consumer) deserialized)
                                (swap! (:stats consumer)
                                      update :events-processed inc)
                                (swap! (:stats consumer)
                                      assoc :last-event-time (System/currentTimeMillis)))
                              (catch Exception e
                                (swap! (:stats consumer) update :errors inc)
                                (throw e))))))))

                  (catch Exception e
                    (swap! (:stats consumer) update :errors inc))))

              (finally
                (.set (:running? consumer) false))))
          "ringbuf-consumer")]

    (.setDaemon poll-thread true)
    (.start poll-thread)
    (assoc consumer :poll-thread poll-thread)))

(defn stop-ringbuf-consumer
  "Stop consuming events from ring buffer"
  [^RingBufConsumer consumer]
  (.set (:running? consumer) false)
  (when-let [thread (:poll-thread consumer)]
    (.join thread 5000)) ; Wait up to 5 seconds

  ;; Cleanup
  (epoll-ctl (:epoll-fd consumer) EPOLL_CTL_DEL (:fd (:map consumer)) 0)
  (syscall/close-fd (:epoll-fd consumer))
  (unmap-ringbuf (:layout consumer))
  consumer)

(defn get-consumer-stats
  "Get statistics from ring buffer consumer

  Returns map with:
  - :events-read - Total events read from ring buffer
  - :events-processed - Total events successfully processed
  - :batches-read - Number of batches read
  - :errors - Number of errors encountered
  - :events-per-second - Average events per second
  - :uptime-ms - Consumer uptime in milliseconds"
  [^RingBufConsumer consumer]
  (let [stats @(:stats consumer)
        uptime-ms (if (:start-time stats)
                   (- (System/currentTimeMillis) (:start-time stats))
                   0)
        events-per-sec (if (pos? uptime-ms)
                        (/ (* (:events-processed stats) 1000.0) uptime-ms)
                        0.0)]
    (assoc stats
           :events-per-second events-per-sec
           :uptime-ms uptime-ms)))

;; ============================================================================
;; High-level Event Processing
;; ============================================================================

(defn process-events
  "Process events from a ring buffer synchronously

  Parameters:
  - ringbuf-map: Ring buffer map
  - callback: Function called for each event
  - :max-events - Maximum number of events to process (default: all available)
  - :timeout-ms - Timeout in milliseconds (default: 1000)
  - :deserializer - Function to deserialize event bytes

  Returns number of events processed"
  [ringbuf-map callback & {:keys [max-events timeout-ms deserializer]
                          :or {max-events Integer/MAX_VALUE
                               timeout-ms 1000
                               deserializer identity}}]
  (let [layout (map-ringbuf ringbuf-map)
        start-time (System/currentTimeMillis)
        events-processed (atom 0)]
    (try
      (while (and (< @events-processed max-events)
                 (< (- (System/currentTimeMillis) start-time) timeout-ms))
        ;; Check if events available
        (when (pos? (ring-buf-available layout))
          (let [batch (read-ringbuf-events layout :max-events (- max-events @events-processed))]
            (doseq [event-bytes batch]
              (callback (deserializer event-bytes))
              (swap! events-processed inc))))

        ;; Short sleep if no events
        (when (zero? (ring-buf-available layout))
          (Thread/sleep 10)))

      @events-processed

      (finally
        (unmap-ringbuf layout)))))

(defn peek-ringbuf-events
  "Peek at available events without consuming them

  Parameters:
  - ringbuf-map: Ring buffer map
  - :max-events - Maximum events to peek (default: 10)
  - :deserializer - Function to deserialize event bytes

  Returns vector of events (without removing from ring buffer)"
  [ringbuf-map & {:keys [max-events deserializer]
                 :or {max-events 10
                      deserializer identity}}]
  (let [layout (map-ringbuf ringbuf-map)
        original-consumer (get-consumer-pos layout)]
    (try
      ;; Read events
      (let [events (read-ringbuf-events layout :max-events max-events)
            deserialized (mapv deserializer events)]
        ;; Restore consumer position (peek doesn't consume)
        (set-consumer-pos! layout original-consumer)
        deserialized)
      (finally
        (unmap-ringbuf layout)))))

;; ============================================================================
;; Utility Macros
;; ============================================================================

(defmacro with-ringbuf-consumer
  "Create and manage a ring buffer consumer with automatic cleanup

  Example:
    (with-ringbuf-consumer [consumer {:map ringbuf-map
                                      :callback #(println %)
                                      :deserializer parse-event}]
      (Thread/sleep 5000)
      (println \"Stats:\" (get-consumer-stats consumer)))"
  [[binding consumer-spec] & body]
  `(let [consumer# (create-ringbuf-consumer ~consumer-spec)
         ~binding (start-ringbuf-consumer consumer#)]
     (try
       ~@body
       (finally
         (stop-ringbuf-consumer ~binding)))))

;; ============================================================================
;; Event Data Helpers
;; ============================================================================

(defn make-event-parser
  "Create an event parser from a struct spec

  Example:
    (def parse-event (make-event-parser [:u32 :u64 :u32]))
    (parse-event event-bytes)
    ;; => [123 456789 42]"
  [spec]
  (fn [^bytes event-bytes]
    (utils/unpack-struct event-bytes spec)))

(defn make-event-serializer
  "Create an event serializer from a struct spec

  Example:
    (def serialize-event (make-event-serializer [:u32 :u64 :u32]))
    (serialize-event [123 456789 42])
    ;; => byte-array"
  [spec]
  (fn [values]
    (utils/pack-struct (map vector spec values))))

(defn make-event-handler
  "Create an event handler with deserialization and filtering

  Parameters:
  - :parser - Parser function (from make-event-parser)
  - :filter - Optional predicate to filter events
  - :transform - Optional transformation function
  - :handler - Final handler function

  Example:
    (make-event-handler
      :parser (make-event-parser [:u32 :u64])
      :filter (fn [[pid ts]] (> pid 1000))
      :transform (fn [[pid ts]] {:pid pid :timestamp ts})
      :handler println)"
  [& {:keys [parser filter transform handler]
      :or {parser identity
           filter (constantly true)
           transform identity
           handler println}}]
  (fn [event-bytes]
    (let [parsed (parser event-bytes)]
      (when (filter parsed)
        (handler (transform parsed))))))

;; ============================================================================
;; Ring Buffer Consumer with Backpressure
;; ============================================================================
;;
;; The backpressure consumer adds flow control to prevent unbounded memory
;; growth when the consumer cannot keep up with the producer. It uses a
;; bounded queue and tracks dropped events for monitoring.

(defrecord BackpressureConsumer
  [map                  ; The ringbuf map
   layout               ; RingBufLayout (memory-mapped)
   epoll-fd             ; Epoll file descriptor
   running?             ; AtomicBoolean for running state
   reader-thread        ; Thread for reading from ring buffer
   processor-thread     ; Thread for processing events
   queue                ; ArrayBlockingQueue for backpressure
   callback             ; Callback function for events
   deserializer         ; Function to deserialize event data
   drop-handler         ; Optional handler for dropped events
   stats])              ; Atom with statistics

(defn create-backpressure-consumer
  "Create a ring buffer consumer with backpressure support.

  When the processing queue fills up, new events are dropped rather than
  causing unbounded memory growth. Dropped events can be tracked via
  statistics or handled via an optional drop handler.

  Options:
  - :map - The ring buffer map (required)
  - :callback - Function called for each event (receives deserialized event)
  - :deserializer - Optional function to deserialize event bytes (default: identity)
  - :max-pending - Maximum events in processing queue before dropping (default: 10000)
  - :drop-handler - Optional function called when events are dropped (receives event bytes)
  - :batch-size - Number of events to read in each batch (default: 64)

  Returns a BackpressureConsumer record.

  Example:
    (def consumer
      (create-backpressure-consumer
        {:map ringbuf-map
         :callback process-event
         :deserializer parse-event
         :max-pending 5000
         :drop-handler (fn [_] (log/warn \"Event dropped\"))}))"
  [{:keys [map callback deserializer max-pending drop-handler batch-size]
    :or {deserializer identity
         max-pending 10000
         drop-handler nil
         batch-size 64}}]
  (let [layout (map-ringbuf map)
        epoll-fd (epoll-create)
        _ (epoll-ctl epoll-fd EPOLL_CTL_ADD (:fd map) EPOLLIN)
        running? (AtomicBoolean. false)
        queue (ArrayBlockingQueue. (int max-pending))
        stats (atom {:events-read 0
                     :events-processed 0
                     :events-dropped 0
                     :queue-full-count 0
                     :batches-read 0
                     :errors 0
                     :max-queue-size 0
                     :start-time nil
                     :last-event-time nil
                     :last-drop-time nil})]
    (->BackpressureConsumer map layout epoll-fd running? nil nil queue
                            callback deserializer drop-handler stats)))

(defn start-backpressure-consumer
  "Start the backpressure consumer.

  Creates two threads:
  1. Reader thread: Reads events from ring buffer and queues them
  2. Processor thread: Processes events from the queue

  This separation allows the reader to keep up with the kernel while
  the processor handles potentially slow callbacks.

  Returns the updated consumer with threads started."
  [^BackpressureConsumer consumer]
  (.set (:running? consumer) true)
  (swap! (:stats consumer) assoc :start-time (System/currentTimeMillis))

  (let [;; Reader thread - reads from ring buffer and enqueues
        reader-thread
        (Thread.
          (fn []
            (try
              (while (.get (:running? consumer))
                (try
                  ;; Wait for events with epoll (100ms timeout)
                  (let [ready-fds (epoll-wait (:epoll-fd consumer) 100)]
                    (when (seq ready-fds)
                      ;; Read batch of events
                      (let [events (read-ringbuf-events (:layout consumer)
                                                        :max-events 64)]
                        (when (seq events)
                          (swap! (:stats consumer) update :batches-read inc)
                          (swap! (:stats consumer) update :events-read + (count events))

                          ;; Try to enqueue each event
                          (doseq [event-bytes events]
                            (if (.offer (:queue consumer) event-bytes)
                              ;; Successfully queued
                              (let [queue-size (.size (:queue consumer))]
                                (swap! (:stats consumer)
                                       update :max-queue-size max queue-size))
                              ;; Queue full - drop event
                              (do
                                (swap! (:stats consumer) update :events-dropped inc)
                                (swap! (:stats consumer) update :queue-full-count inc)
                                (swap! (:stats consumer) assoc :last-drop-time
                                       (System/currentTimeMillis))
                                (when-let [drop-handler (:drop-handler consumer)]
                                  (try
                                    (drop-handler event-bytes)
                                    (catch Exception _))))))))))
                  (catch Exception e
                    (swap! (:stats consumer) update :errors inc))))
              (finally
                (.set (:running? consumer) false))))
          "ringbuf-reader")

        ;; Processor thread - processes queued events
        processor-thread
        (Thread.
          (fn []
            (try
              (while (or (.get (:running? consumer))
                         (not (.isEmpty (:queue consumer))))
                (try
                  ;; Poll with timeout to allow checking running state
                  (when-let [event-bytes (.poll (:queue consumer) 100 TimeUnit/MILLISECONDS)]
                    (let [deserialized ((:deserializer consumer) event-bytes)]
                      ((:callback consumer) deserialized)
                      (swap! (:stats consumer) update :events-processed inc)
                      (swap! (:stats consumer) assoc :last-event-time
                             (System/currentTimeMillis))))
                  (catch Exception e
                    (swap! (:stats consumer) update :errors inc))))
              (catch InterruptedException _
                ;; Thread interrupted, exit gracefully
                nil)))
          "ringbuf-processor")]

    (.setDaemon reader-thread true)
    (.setDaemon processor-thread true)
    (.start reader-thread)
    (.start processor-thread)
    (assoc consumer
           :reader-thread reader-thread
           :processor-thread processor-thread)))

(defn stop-backpressure-consumer
  "Stop the backpressure consumer and clean up resources.

  Waits for the processor to drain remaining queued events (up to 5 seconds)
  before forcefully terminating.

  Returns the consumer with threads stopped."
  [^BackpressureConsumer consumer]
  (.set (:running? consumer) false)

  ;; Wait for reader thread
  (when-let [thread (:reader-thread consumer)]
    (.join thread 2000))

  ;; Wait for processor to drain queue (with timeout)
  (when-let [thread (:processor-thread consumer)]
    (.join thread 5000)
    (when (.isAlive thread)
      (.interrupt thread)))

  ;; Cleanup
  (try
    (epoll-ctl (:epoll-fd consumer) EPOLL_CTL_DEL (:fd (:map consumer)) 0)
    (catch Exception _))
  (syscall/close-fd (:epoll-fd consumer))
  (unmap-ringbuf (:layout consumer))
  consumer)

(defn get-backpressure-stats
  "Get detailed statistics from the backpressure consumer.

  Returns a map with:
  - :events-read - Total events read from ring buffer
  - :events-processed - Total events successfully processed
  - :events-dropped - Total events dropped due to backpressure
  - :queue-full-count - Number of times queue was full
  - :batches-read - Number of batches read
  - :errors - Number of errors encountered
  - :current-queue-size - Current number of events in queue
  - :max-queue-size - Maximum queue size reached
  - :drop-rate - Percentage of events dropped
  - :events-per-second - Average events processed per second
  - :uptime-ms - Consumer uptime in milliseconds"
  [^BackpressureConsumer consumer]
  (let [stats @(:stats consumer)
        uptime-ms (if (:start-time stats)
                    (- (System/currentTimeMillis) (:start-time stats))
                    0)
        events-per-sec (if (pos? uptime-ms)
                         (/ (* (:events-processed stats) 1000.0) uptime-ms)
                         0.0)
        total-events (+ (:events-processed stats) (:events-dropped stats))
        drop-rate (if (pos? total-events)
                    (* 100.0 (/ (:events-dropped stats) total-events))
                    0.0)]
    (assoc stats
           :current-queue-size (.size (:queue consumer))
           :drop-rate drop-rate
           :events-per-second events-per-sec
           :uptime-ms uptime-ms)))

(defn backpressure-healthy?
  "Check if the backpressure consumer is healthy.

  Returns true if:
  - Drop rate is below threshold (default 5%)
  - Queue utilization is below threshold (default 80%)

  Options:
  - :max-drop-rate - Maximum acceptable drop rate percentage (default: 5.0)
  - :max-queue-utilization - Maximum acceptable queue fill percentage (default: 80.0)"
  [^BackpressureConsumer consumer & {:keys [max-drop-rate max-queue-utilization]
                                     :or {max-drop-rate 5.0
                                          max-queue-utilization 80.0}}]
  (let [stats (get-backpressure-stats consumer)
        queue-capacity (.remainingCapacity (:queue consumer))
        queue-size (:current-queue-size stats)
        queue-total (+ queue-size queue-capacity)
        queue-utilization (if (pos? queue-total)
                            (* 100.0 (/ queue-size queue-total))
                            0.0)]
    (and (< (:drop-rate stats) max-drop-rate)
         (< queue-utilization max-queue-utilization))))

(defmacro with-backpressure-consumer
  "Create and manage a backpressure consumer with automatic cleanup.

  Example:
    (with-backpressure-consumer [consumer {:map ringbuf-map
                                           :callback #(println %)
                                           :max-pending 5000}]
      (Thread/sleep 10000)
      (println \"Stats:\" (get-backpressure-stats consumer))
      (println \"Healthy?\" (backpressure-healthy? consumer)))"
  [[binding consumer-spec] & body]
  `(let [consumer# (create-backpressure-consumer ~consumer-spec)
         ~binding (start-backpressure-consumer consumer#)]
     (try
       ~@body
       (finally
         (stop-backpressure-consumer ~binding)))))

;; ============================================================================
;; Sampling Consumer for High-Volume Streams
;; ============================================================================

(defn create-sampling-consumer
  "Create a consumer that samples events at a configurable rate.

  Useful for high-volume event streams where processing every event
  is not necessary (e.g., statistical sampling, debugging).

  Options:
  - :map - The ring buffer map (required)
  - :callback - Function called for sampled events
  - :sample-rate - Fraction of events to sample (0.0 to 1.0, default: 0.1 = 10%)
  - :deserializer - Optional function to deserialize event bytes

  Note: Uses the backpressure consumer internally with a sampling filter."
  [{:keys [map callback sample-rate deserializer]
    :or {sample-rate 0.1
         deserializer identity}}]
  (let [sample-counter (AtomicLong. 0)
        sample-threshold (long (* sample-rate 1000000))  ; Convert to micros for precision

        sampling-callback
        (fn [event]
          (let [counter (.incrementAndGet sample-counter)]
            ;; Use modular arithmetic for uniform sampling
            (when (< (mod (* counter 1000000) 1000000) sample-threshold)
              (callback event))))]

    (create-backpressure-consumer
      {:map map
       :callback sampling-callback
       :deserializer deserializer
       :max-pending 1000})))  ; Smaller queue since we're sampling
