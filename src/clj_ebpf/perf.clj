(ns clj-ebpf.perf
  "Perf event buffer support for BPF event streaming"
  (:require [clj-ebpf.constants :as const]
            [clj-ebpf.syscall :as syscall]
            [clj-ebpf.utils :as utils]
            [clj-ebpf.maps :as maps])
  (:import [java.lang.foreign Arena MemorySegment ValueLayout]
           [java.util.concurrent.atomic AtomicBoolean AtomicLong]))

;; ============================================================================
;; Perf Event Constants
;; ============================================================================

(def ^:const PERF_EVENT_OPEN_SYSCALL_NR 298)

;; Perf event flags
(def perf-event-flags
  {:fd-cloexec 0x80000
   :fd-output 0x100
   :pid-cgroup 0x200
   :fd-no-group 0x400})

;; Perf event record types
(def perf-record-type
  {:sample 9
   :lost 2
   :throttle 5
   :unthrottle 6})

;; Page size
(def ^:const page-size 4096)

;; ============================================================================
;; Perf Event Attribute Structure
;; ============================================================================

(defn- perf-event-attr->bytes
  "Create perf_event_attr structure.

  Structure (simplified for BPF usage):
  struct perf_event_attr {
    __u32 type;           // Type of event
    __u32 size;           // Size of attribute structure
    __u64 config;         // Event-specific configuration
    __u64 sample_period;  // Period of sampling
    __u64 sample_type;    // Sample data format
    __u64 read_format;    // Read format
    __u64 flags;          // Event flags (bitfield)
    __u32 wakeup_events;  // Wakeup every n events
    __u32 bp_type;
    __u64 config1;
    __u64 config2;
    // ... (128 bytes total, rest is padding/reserved)
  }"
  [{:keys [type config sample-period sample-type wakeup-events]
    :or {type :software
         config :bpf-output
         sample-period 1
         sample-type 0
         wakeup-events 1}}]
  (let [type-val (get const/perf-type type 1)
        config-val (get const/perf-sw-config config 10)
        ;; Flags: disabled | inherit | inherit_stat | enable_on_exec | sample_id_all | watermark
        flags-bits (bit-or (bit-shift-left 1 0)  ; disabled
                          (bit-shift-left 1 1)  ; inherit
                          (bit-shift-left 1 2)  ; pinned (not inherit_stat)
                          (bit-shift-left 1 13)) ; watermark
        attr (utils/pack-struct [[:u32 type-val]           ; type
                                 [:u32 128]                ; size (full struct size)
                                 [:u64 config-val]         ; config
                                 [:u64 sample-period]      ; sample_period / sample_freq
                                 [:u64 sample-type]        ; sample_type
                                 [:u64 0]                  ; read_format
                                 [:u64 flags-bits]         ; flags bitfield
                                 [:u32 wakeup-events]      ; wakeup_events
                                 [:u32 0]                  ; bp_type
                                 [:u64 0]                  ; config1
                                 [:u64 0]                  ; config2
                                 [:u64 0]                  ; branch_sample_type
                                 [:u64 0]                  ; sample_regs_user
                                 [:u32 0]                  ; sample_stack_user
                                 [:u32 0]                  ; clockid
                                 [:u64 0]                  ; sample_regs_intr
                                 [:u32 0]                  ; aux_watermark
                                 [:u32 0]])]              ; sample_max_stack + padding
    ;; Pad to 128 bytes
    (let [padding-needed (- 128 (count attr))]
      (byte-array (concat attr (repeat padding-needed 0))))))

;; ============================================================================
;; Perf Event Open Syscall
;; ============================================================================

(defn perf-event-open
  "Open a perf event file descriptor.

  Parameters:
  - attr: Perf event attribute map (see perf-event-attr->bytes)
  - pid: Process ID (-1 for all processes)
  - cpu: CPU number (-1 for all CPUs)
  - group-fd: Group leader FD (-1 for no group)
  - flags: Additional flags (default 0)

  Returns the perf event file descriptor.

  Example:
    (perf-event-open {:type :software :config :bpf-output} -1 0 -1 0)"
  [attr pid cpu group-fd flags]
  (let [attr-bytes (perf-event-attr->bytes attr)
        attr-seg (utils/bytes->segment attr-bytes)
        result (syscall/raw-syscall PERF_EVENT_OPEN_SYSCALL_NR
                                   attr-seg
                                   (int pid)
                                   (int cpu)
                                   (int group-fd)
                                   (int flags))]
    (when (neg? result)
      (throw (ex-info "perf_event_open failed"
                     {:errno (- result)
                      :pid pid
                      :cpu cpu})))
    result))

;; ============================================================================
;; Perf Event Buffer Memory Mapping
;; ============================================================================

(defrecord PerfBuffer
  [fd                    ; Perf event file descriptor
   cpu                   ; CPU number
   mmap-addr             ; Base address of mmap region
   mmap-size             ; Total mmap size (metadata page + data pages)
   data-offset           ; Offset to data area (after metadata page)
   data-size             ; Size of data area
   metadata-seg          ; MemorySegment for metadata page
   data-seg])            ; MemorySegment for data area

(defn- mmap-perf-buffer
  "Memory-map a perf event buffer.

  The buffer consists of:
  - 1 page: metadata (control page with head/tail pointers)
  - N pages: data (ring buffer)

  Parameters:
  - fd: Perf event file descriptor
  - page-count: Number of data pages (must be power of 2)

  Returns PerfBuffer record."
  [fd page-count]
  (when-not (pos? (Integer/bitCount page-count))
    (throw (ex-info "page-count must be a power of 2" {:page-count page-count})))

  (let [data-size (* page-count page-size)
        total-size (+ page-size data-size) ; metadata page + data pages
        ;; mmap syscall: addr, length, prot, flags, fd, offset
        ;; PROT_READ|PROT_WRITE = 3, MAP_SHARED = 1
        addr (syscall/raw-syscall 9 0 total-size 3 1 fd 0)] ; mmap syscall
    (when (neg? addr)
      (throw (ex-info "mmap perf buffer failed" {:errno (- addr) :fd fd})))

    (let [arena (Arena/ofAuto)
          base-seg (.reinterpret (MemorySegment/ofAddress addr) total-size)
          metadata-seg (.asSlice base-seg 0 page-size)
          data-seg (.asSlice base-seg page-size data-size)]
      (->PerfBuffer fd -1 addr total-size page-size data-size
                   metadata-seg data-seg))))

(defn- munmap-perf-buffer
  "Unmap perf event buffer."
  [^PerfBuffer perf-buf]
  (let [result (syscall/raw-syscall 11 (:mmap-addr perf-buf) (:mmap-size perf-buf))]
    (when (neg? result)
      (throw (ex-info "munmap perf buffer failed" {:errno (- result)})))))

;; ============================================================================
;; Perf Event Buffer Reading
;; ============================================================================

(defn- read-u64-from-segment
  "Read u64 from MemorySegment at offset."
  [^MemorySegment seg offset]
  (.get seg ValueLayout/JAVA_LONG_UNALIGNED offset))

(defn- read-u32-from-segment
  "Read u32 from MemorySegment at offset."
  [^MemorySegment seg offset]
  (let [val (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)]
    (bit-and val 0xFFFFFFFF)))

(defn- read-u16-from-segment
  "Read u16 from MemorySegment at offset."
  [^MemorySegment seg offset]
  (let [val (.get seg ValueLayout/JAVA_SHORT_UNALIGNED offset)]
    (bit-and val 0xFFFF)))

(defn- get-perf-buffer-head
  "Get current head (write) position from perf buffer metadata."
  [^PerfBuffer perf-buf]
  (read-u64-from-segment (:metadata-seg perf-buf) 0))

(defn- get-perf-buffer-tail
  "Get current tail (read) position from perf buffer metadata."
  [^PerfBuffer perf-buf]
  (read-u64-from-segment (:metadata-seg perf-buf) 8))

(defn- set-perf-buffer-tail!
  "Update tail (read) position in perf buffer metadata."
  [^PerfBuffer perf-buf tail]
  (.set (:metadata-seg perf-buf) ValueLayout/JAVA_LONG_UNALIGNED 8 tail))

(defn- read-perf-event-header
  "Read perf event record header.

  Header structure:
  struct perf_event_header {
    __u32 type;
    __u16 misc;
    __u16 size;
  };"
  [^MemorySegment data-seg offset]
  (let [type (read-u32-from-segment data-seg offset)
        misc (read-u16-from-segment data-seg (+ offset 4))
        size (read-u16-from-segment data-seg (+ offset 6))]
    {:type type :misc misc :size size}))

(defn read-perf-events
  "Read available events from perf buffer.

  Returns a vector of event maps, each containing:
  - :type - Event record type
  - :size - Record size
  - :data - Raw event data (byte array)

  Parameters:
  - perf-buf: PerfBuffer record
  - max-events: Maximum number of events to read (default 128)

  Example:
    (read-perf-events perf-buf 64)"
  ([^PerfBuffer perf-buf] (read-perf-events perf-buf 128))
  ([^PerfBuffer perf-buf max-events]
   (let [head (get-perf-buffer-head perf-buf)
         tail (get-perf-buffer-tail perf-buf)
         data-size (:data-size perf-buf)
         data-seg (:data-seg perf-buf)]

     (loop [current-tail tail
            events []
            event-count 0]
       (if (or (>= current-tail head)
               (>= event-count max-events))
         (do
           ;; Update tail pointer to mark events as consumed
           (when (> current-tail tail)
             (set-perf-buffer-tail! perf-buf current-tail))
           events)

         (let [offset (mod current-tail data-size)
               header (read-perf-event-header data-seg offset)
               record-size (:size header)

               ;; Read event data (after 8-byte header)
               data-offset (+ offset 8)
               data-size-bytes (- record-size 8)
               data (byte-array data-size-bytes)]

           ;; Copy data from ring buffer (handle wrapping)
           (loop [bytes-read 0]
             (when (< bytes-read data-size-bytes)
               (let [pos (mod (+ data-offset bytes-read) data-size)
                     byte-val (.get data-seg ValueLayout/JAVA_BYTE pos)]
                 (aset data bytes-read byte-val)
                 (recur (inc bytes-read)))))

           (let [event {:type (:type header)
                       :size record-size
                       :data data}]
             (recur (+ current-tail record-size)
                    (conj events event)
                    (inc event-count)))))))))

;; ============================================================================
;; Perf Event Array Map
;; ============================================================================

(defn create-perf-event-array
  "Create a perf event array map for collecting BPF events.

  A perf event array map is used to send events from BPF programs
  to userspace via perf event buffers.

  Parameters:
  - max-entries: Maximum number of entries (typically number of CPUs)
  - map-name: Optional map name

  Returns a BPF map.

  Example:
    (create-perf-event-array (get-cpu-count) :map-name \"events\")"
  [max-entries & {:keys [map-name]
                  :or {map-name "perf_event_array"}}]
  (maps/create-map :map-type :perf-event-array
                  :key-size 4        ; CPU index
                  :value-size 4      ; Perf event FD
                  :max-entries max-entries
                  :map-name map-name))

;; ============================================================================
;; Perf Event Consumer
;; ============================================================================

(defrecord PerfEventConsumer
  [map                   ; Perf event array map
   buffers               ; Vector of PerfBuffer (one per CPU)
   running?              ; AtomicBoolean
   consumer-thread       ; Thread reference
   callback              ; Event callback function
   deserializer          ; Event deserializer function
   stats])               ; Atom with statistics

(defn create-perf-consumer
  "Create a perf event consumer for BPF event streaming.

  Parameters:
  - map: Perf event array map
  - callback: Function to call for each event (receives deserialized event)
  - deserializer: Function to deserialize event bytes (default identity)
  - buffer-pages: Number of pages per buffer (default 64, must be power of 2)
  - cpu-count: Number of CPUs (default: all CPUs)

  Returns PerfEventConsumer record.

  Example:
    (create-perf-consumer
      {:map perf-map
       :callback (fn [event] (println \"Event:\" event))
       :deserializer parse-my-event
       :buffer-pages 64})"
  [& {:keys [map callback deserializer buffer-pages cpu-count]
      :or {deserializer identity buffer-pages 64 cpu-count (utils/get-cpu-count)}}]
  (let [buffers (vec
                 (for [cpu (range cpu-count)]
                   (let [;; Open perf event for this CPU
                         perf-fd (perf-event-open
                                  {:type :software
                                   :config :bpf-output
                                   :sample-period 1
                                   :wakeup-events 1}
                                  -1 cpu -1 0)
                         ;; Map the perf buffer
                         perf-buf (mmap-perf-buffer perf-fd buffer-pages)]

                     ;; Enable the perf event
                     (syscall/ioctl perf-fd (:enable const/perf-event-ioc) 0)

                     ;; Update perf event array map with this FD
                     (maps/map-update map cpu perf-fd)

                     (assoc perf-buf :cpu cpu))))

        running? (AtomicBoolean. false)
        stats (atom {:events-read 0
                    :events-processed 0
                    :polls 0
                    :errors 0
                    :start-time (System/currentTimeMillis)
                    :last-event-time 0})]

    (->PerfEventConsumer map buffers running? nil callback deserializer stats)))

(defn start-perf-consumer
  "Start consuming events from perf buffers in a background thread.

  Parameters:
  - consumer: PerfEventConsumer record
  - poll-interval-ms: Polling interval in milliseconds (default 100)

  Returns updated consumer with thread reference.

  Example:
    (start-perf-consumer consumer 50)"
  ([consumer] (start-perf-consumer consumer 100))
  ([^PerfEventConsumer consumer poll-interval-ms]
   (when (.get (:running? consumer))
     (throw (ex-info "Consumer already running" {})))

   (.set (:running? consumer) true)

   (let [thread (Thread.
                 (fn []
                   (while (.get (:running? consumer))
                     (try
                       (swap! (:stats consumer) update :polls inc)

                       ;; Read from all CPU buffers
                       (doseq [perf-buf (:buffers consumer)]
                         (let [events (read-perf-events perf-buf 128)]
                           (swap! (:stats consumer) update :events-read + (count events))

                           ;; Process each event
                           (doseq [event events]
                             (try
                               (when (= (:type event) (:sample perf-record-type))
                                 (let [deserialized ((:deserializer consumer) (:data event))]
                                   ((:callback consumer) deserialized)
                                   (swap! (:stats consumer) update :events-processed inc)
                                   (swap! (:stats consumer) assoc :last-event-time (System/currentTimeMillis))))
                               (catch Exception e
                                 (swap! (:stats consumer) update :errors inc))))))

                       ;; Sleep between polls
                       (Thread/sleep poll-interval-ms)

                       (catch Exception e
                         (swap! (:stats consumer) update :errors inc))))))]

     (.start thread)
     (assoc consumer :consumer-thread thread))))

(defn stop-perf-consumer
  "Stop the perf event consumer thread.

  Parameters:
  - consumer: PerfEventConsumer record

  Example:
    (stop-perf-consumer consumer)"
  [^PerfEventConsumer consumer]
  (when (.get (:running? consumer))
    (.set (:running? consumer) false)
    (when-let [thread (:consumer-thread consumer)]
      (.join thread 5000)))  ; Wait up to 5 seconds

  ;; Cleanup buffers
  (doseq [perf-buf (:buffers consumer)]
    (try
      (munmap-perf-buffer perf-buf)
      (syscall/close-fd (:fd perf-buf))
      (catch Exception _))))

(defn get-perf-stats
  "Get statistics from perf event consumer.

  Returns a map with:
  - :events-read - Total events read from buffers
  - :events-processed - Total events successfully processed
  - :polls - Number of polling cycles
  - :errors - Number of errors
  - :uptime-ms - Consumer uptime in milliseconds
  - :events-per-second - Average events processed per second

  Example:
    (get-perf-stats consumer)"
  [^PerfEventConsumer consumer]
  (let [stats @(:stats consumer)
        current-time (System/currentTimeMillis)
        uptime-ms (- current-time (:start-time stats))
        events-per-sec (if (pos? uptime-ms)
                        (/ (* (:events-processed stats) 1000.0) uptime-ms)
                        0.0)]
    (assoc stats
           :uptime-ms uptime-ms
           :events-per-second events-per-sec)))

;; ============================================================================
;; Convenience Macros
;; ============================================================================

(defmacro with-perf-consumer
  "Create and manage a perf event consumer with automatic cleanup.

  Example:
    (with-perf-consumer [consumer {:map perf-map :callback println}]
      (start-perf-consumer consumer)
      (Thread/sleep 5000))"
  [[binding config-expr] & body]
  `(let [~binding (create-perf-consumer ~@(apply concat config-expr))]
     (try
       ~@body
       (finally
         (stop-perf-consumer ~binding)))))
