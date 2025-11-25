(ns clj-ebpf.mock
  "Mock syscall layer for unprivileged testing.

   Provides:
   - Dynamic bindings to enable mock mode
   - Configurable mock responses for BPF operations
   - In-memory map simulation
   - Test fixtures for common scenarios

   Usage:
   ```clojure
   (with-mock-bpf
     (let [m (maps/create-map :hash 100 4 8)]
       (maps/map-update m key-seg val-seg)
       (is (= val-bytes (maps/map-lookup m key-seg)))))
   ```"
  (:require [clojure.test :refer [is]])
  (:import [java.util.concurrent.atomic AtomicInteger AtomicLong]))

;; ============================================================================
;; Mock State
;; ============================================================================

(def ^:dynamic *mock-enabled*
  "When true, syscalls are intercepted and mocked"
  false)

(def ^:dynamic *mock-config*
  "Configuration for mock behavior"
  {:auto-fd true           ; Automatically generate FDs
   :fail-on nil            ; Keyword to force failure (:map-create, :prog-load, etc.)
   :errno nil              ; errno to return on failure
   :verifier-log nil       ; Verifier log to return
   :latency-ms 0})         ; Simulated latency

(def ^:private fd-counter
  "Counter for generating mock file descriptors"
  (AtomicInteger. 100))

(def ^:private mock-maps
  "In-memory storage for mock maps: {fd -> {:type :key-size :value-size :data {key -> value}}}"
  (atom {}))

(def ^:private mock-programs
  "In-memory storage for mock programs: {fd -> {:type :insns :attached}}"
  (atom {}))

(def ^:private mock-stats
  "Statistics for mock operations"
  (atom {:syscalls 0
         :map-creates 0
         :map-lookups 0
         :map-updates 0
         :map-deletes 0
         :prog-loads 0
         :prog-attaches 0}))

;; ============================================================================
;; Mock FD Management
;; ============================================================================

(defn next-fd
  "Generate next mock file descriptor"
  []
  (.getAndIncrement fd-counter))

(defn reset-mock-state!
  "Reset all mock state. Call between tests."
  []
  (.set fd-counter 100)
  (reset! mock-maps {})
  (reset! mock-programs {})
  (reset! mock-stats {:syscalls 0
                      :map-creates 0
                      :map-lookups 0
                      :map-updates 0
                      :map-deletes 0
                      :prog-loads 0
                      :prog-attaches 0}))

(defn get-mock-stats
  "Get current mock statistics"
  []
  @mock-stats)

(defn- inc-stat! [key]
  (swap! mock-stats update key inc))

;; ============================================================================
;; Mock Map Operations
;; ============================================================================

(defn mock-map-create
  "Create a mock BPF map"
  [{:keys [map-type key-size value-size max-entries flags name]}]
  (inc-stat! :syscalls)
  (inc-stat! :map-creates)
  (when (= (:fail-on *mock-config*) :map-create)
    (throw (ex-info "Mock map creation failed"
                    {:error-type :map-error
                     :errno (or (:errno *mock-config*) 1)
                     :errno-keyword (or (:errno-keyword *mock-config*) :eperm)})))
  (let [fd (next-fd)]
    (swap! mock-maps assoc fd {:type map-type
                               :key-size key-size
                               :value-size value-size
                               :max-entries max-entries
                               :flags flags
                               :name name
                               :data {}})
    fd))

(defn mock-map-lookup
  "Look up a value in a mock map"
  [fd key-bytes]
  (inc-stat! :syscalls)
  (inc-stat! :map-lookups)
  (when (= (:fail-on *mock-config*) :map-lookup)
    (throw (ex-info "Mock map lookup failed"
                    {:error-type :map-error
                     :errno 2
                     :errno-keyword :enoent})))
  (when-let [m (get @mock-maps fd)]
    (get-in m [:data (vec key-bytes)])))

(defn mock-map-update
  "Update a value in a mock map"
  [fd key-bytes value-bytes flags]
  (inc-stat! :syscalls)
  (inc-stat! :map-updates)
  (when (= (:fail-on *mock-config*) :map-update)
    (throw (ex-info "Mock map update failed"
                    {:error-type :map-error
                     :errno (or (:errno *mock-config*) 1)
                     :errno-keyword (or (:errno-keyword *mock-config*) :eperm)})))
  (if-let [m (get @mock-maps fd)]
    (let [key-vec (vec key-bytes)
          exists? (contains? (:data m) key-vec)
          ;; Check flags
          _ (when (and (= flags 1) exists?)  ; BPF_NOEXIST
              (throw (ex-info "Key already exists"
                              {:error-type :map-error
                               :errno 17
                               :errno-keyword :eexist})))
          _ (when (and (= flags 2) (not exists?))  ; BPF_EXIST
              (throw (ex-info "Key does not exist"
                              {:error-type :map-error
                               :errno 2
                               :errno-keyword :enoent})))
          ;; Check max entries
          _ (when (and (not exists?)
                       (>= (count (:data m)) (:max-entries m)))
              (throw (ex-info "Map is full"
                              {:error-type :map-error
                               :errno 7
                               :errno-keyword :e2big})))]
      (swap! mock-maps assoc-in [fd :data key-vec] (vec value-bytes))
      0)
    (throw (ex-info "Invalid map fd" {:fd fd :errno 9 :errno-keyword :ebadf}))))

(defn mock-map-delete
  "Delete a key from a mock map"
  [fd key-bytes]
  (inc-stat! :syscalls)
  (inc-stat! :map-deletes)
  (when (= (:fail-on *mock-config*) :map-delete)
    (throw (ex-info "Mock map delete failed"
                    {:error-type :map-error
                     :errno 2
                     :errno-keyword :enoent})))
  (if-let [m (get @mock-maps fd)]
    (let [key-vec (vec key-bytes)]
      (if (contains? (:data m) key-vec)
        (do (swap! mock-maps update-in [fd :data] dissoc key-vec)
            0)
        (throw (ex-info "Key not found"
                        {:error-type :map-error
                         :errno 2
                         :errno-keyword :enoent}))))
    (throw (ex-info "Invalid map fd" {:fd fd :errno 9 :errno-keyword :ebadf}))))

(defn mock-map-get-next-key
  "Get next key in mock map iteration"
  [fd prev-key-bytes]
  (if-let [m (get @mock-maps fd)]
    (let [keys (sort (keys (:data m)))
          prev-key (when prev-key-bytes (vec prev-key-bytes))]
      (if (nil? prev-key)
        (first keys)
        (let [idx (.indexOf keys prev-key)]
          (when (and (>= idx 0) (< (inc idx) (count keys)))
            (nth keys (inc idx))))))
    (throw (ex-info "Invalid map fd" {:fd fd :errno 9 :errno-keyword :ebadf}))))

(defn mock-map-close
  "Close a mock map"
  [fd]
  (swap! mock-maps dissoc fd)
  0)

;; ============================================================================
;; Mock Program Operations
;; ============================================================================

(defn mock-prog-load
  "Load a mock BPF program"
  [{:keys [prog-type insns license log-level]}]
  (inc-stat! :syscalls)
  (inc-stat! :prog-loads)
  (when (= (:fail-on *mock-config*) :prog-load)
    (throw (ex-info "Mock program load failed"
                    {:error-type :verifier-error
                     :errno 22
                     :errno-keyword :einval
                     :verifier-log (or (:verifier-log *mock-config*)
                                       "mock verifier rejection")})))
  (let [fd (next-fd)]
    (swap! mock-programs assoc fd {:type prog-type
                                   :insns insns
                                   :license license
                                   :attached nil})
    fd))

(defn mock-prog-attach
  "Attach a mock BPF program"
  [prog-fd attach-type target]
  (inc-stat! :syscalls)
  (inc-stat! :prog-attaches)
  (when (= (:fail-on *mock-config*) :prog-attach)
    (throw (ex-info "Mock program attach failed"
                    {:error-type :attachment-error
                     :errno 22
                     :errno-keyword :einval})))
  (if (get @mock-programs prog-fd)
    (do (swap! mock-programs assoc-in [prog-fd :attached]
               {:type attach-type :target target})
        0)
    (throw (ex-info "Invalid program fd" {:fd prog-fd :errno 9 :errno-keyword :ebadf}))))

(defn mock-prog-detach
  "Detach a mock BPF program"
  [prog-fd]
  (if (get @mock-programs prog-fd)
    (do (swap! mock-programs assoc-in [prog-fd :attached] nil)
        0)
    (throw (ex-info "Invalid program fd" {:fd prog-fd :errno 9 :errno-keyword :ebadf}))))

(defn mock-prog-close
  "Close a mock program"
  [fd]
  (swap! mock-programs dissoc fd)
  0)

;; ============================================================================
;; Mock Query Functions
;; ============================================================================

(defn get-mock-map
  "Get the mock map data for inspection in tests"
  [fd]
  (get @mock-maps fd))

(defn get-mock-program
  "Get the mock program data for inspection in tests"
  [fd]
  (get @mock-programs fd))

(defn mock-map-entries
  "Get all entries from a mock map"
  [fd]
  (when-let [m (get @mock-maps fd)]
    (:data m)))

(defn mock-map-count
  "Get entry count for a mock map"
  [fd]
  (when-let [m (get @mock-maps fd)]
    (count (:data m))))

;; ============================================================================
;; Test Fixtures and Macros
;; ============================================================================

(defmacro with-mock-bpf
  "Execute body with BPF syscalls mocked.

   Example:
   ```clojure
   (with-mock-bpf
     (let [m (maps/create-map :hash 100 4 8)]
       (is (pos? (:fd m)))))
   ```"
  [& body]
  `(binding [*mock-enabled* true
             *mock-config* {:auto-fd true}]
     (reset-mock-state!)
     (try
       ~@body
       (finally
         (reset-mock-state!)))))

(defmacro with-mock-config
  "Execute body with custom mock configuration.

   Example:
   ```clojure
   (with-mock-config {:fail-on :map-create :errno 1}
     (is (thrown? Exception (maps/create-map :hash 100 4 8))))
   ```"
  [config & body]
  `(binding [*mock-enabled* true
             *mock-config* (merge {:auto-fd true} ~config)]
     (reset-mock-state!)
     (try
       ~@body
       (finally
         (reset-mock-state!)))))

(defmacro with-mock-failure
  "Execute body with a specific operation configured to fail.

   Example:
   ```clojure
   (with-mock-failure :prog-load {:errno 22 :verifier-log \"bad insn\"}
     (is (thrown? Exception (programs/load-program ...))))
   ```"
  [op opts & body]
  `(with-mock-config (assoc ~opts :fail-on ~op)
     ~@body))

;; ============================================================================
;; Mock Syscall Dispatcher
;; ============================================================================

(defn mock-syscall
  "Dispatch a mock syscall based on command.

   This is the main entry point that syscall.clj will call when mocking is enabled."
  [cmd & args]
  (when (pos? (:latency-ms *mock-config*))
    (Thread/sleep (:latency-ms *mock-config*)))
  (case cmd
    :map-create (apply mock-map-create args)
    :map-lookup (apply mock-map-lookup args)
    :map-update (apply mock-map-update args)
    :map-delete (apply mock-map-delete args)
    :map-get-next-key (apply mock-map-get-next-key args)
    :map-close (apply mock-map-close args)
    :prog-load (apply mock-prog-load args)
    :prog-attach (apply mock-prog-attach args)
    :prog-detach (apply mock-prog-detach args)
    :prog-close (apply mock-prog-close args)
    (throw (ex-info (str "Unknown mock syscall: " cmd) {:cmd cmd :args args}))))

;; ============================================================================
;; Test Helpers
;; ============================================================================

(defn assert-map-contains
  "Assert that a mock map contains the expected key-value pair"
  [fd key-bytes expected-value-bytes]
  (let [actual (mock-map-lookup fd key-bytes)]
    (is (= (vec expected-value-bytes) actual)
        (str "Expected map to contain key " (vec key-bytes)))))

(defn assert-map-empty
  "Assert that a mock map is empty"
  [fd]
  (is (zero? (mock-map-count fd))
      "Expected map to be empty"))

(defn assert-map-size
  "Assert that a mock map has the expected number of entries"
  [fd expected-size]
  (is (= expected-size (mock-map-count fd))
      (str "Expected map size " expected-size " but got " (mock-map-count fd))))

(defn assert-syscall-count
  "Assert the number of syscalls made"
  [expected-count]
  (is (= expected-count (:syscalls @mock-stats))
      (str "Expected " expected-count " syscalls but got " (:syscalls @mock-stats))))

(defn populate-mock-map
  "Populate a mock map with test data.

   Arguments:
   - fd: Mock map file descriptor
   - entries: Sequence of [key-bytes value-bytes] pairs"
  [fd entries]
  (doseq [[k v] entries]
    (mock-map-update fd k v 0)))

(defn generate-test-entries
  "Generate n test entries with 4-byte keys and 8-byte values"
  [n]
  (for [i (range n)]
    [(vec (map unchecked-byte [(bit-and i 0xff)
                               (bit-and (bit-shift-right i 8) 0xff)
                               (bit-and (bit-shift-right i 16) 0xff)
                               (bit-and (bit-shift-right i 24) 0xff)]))
     (vec (repeat 8 (unchecked-byte (mod i 256))))]))
