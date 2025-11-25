(ns clj-ebpf.errors
  "Structured error handling for clj-ebpf.

   Provides:
   - Typed exception hierarchy for BPF operations
   - Automatic retry for transient errors
   - Rich error context and diagnostics"
  (:require [clj-ebpf.constants :as const]))

;; ============================================================================
;; Error Types
;; ============================================================================

(def error-types
  "Hierarchy of BPF error types"
  #{:bpf-error           ; Base error type
    :map-error           ; Map operation errors
    :program-error       ; Program load/attach errors
    :syscall-error       ; Low-level syscall failures
    :verifier-error      ; BPF verifier rejection
    :permission-error    ; Permission/capability issues
    :resource-error      ; Resource exhaustion
    :attachment-error    ; Attachment failures
    :arch-error})        ; Architecture/platform issues

(defn bpf-error
  "Create a BPF exception with structured data.

   Arguments:
   - error-type: One of the error-types keywords
   - message: Human-readable error message
   - data: Map of additional context

   Returns an ExceptionInfo with :error-type key."
  [error-type message data]
  (ex-info message (assoc data :error-type error-type)))

(defn map-error
  "Create a map operation error."
  [message data]
  (bpf-error :map-error message data))

(defn program-error
  "Create a program operation error."
  [message data]
  (bpf-error :program-error message data))

(defn syscall-error
  "Create a syscall error."
  [message data]
  (bpf-error :syscall-error message data))

(defn verifier-error
  "Create a verifier rejection error."
  [message data]
  (bpf-error :verifier-error message data))

(defn permission-error
  "Create a permission error."
  [message data]
  (bpf-error :permission-error message data))

(defn resource-error
  "Create a resource exhaustion error."
  [message data]
  (bpf-error :resource-error message data))

(defn attachment-error
  "Create an attachment error."
  [message data]
  (bpf-error :attachment-error message data))

(defn arch-error
  "Create an architecture/platform error."
  [message data]
  (bpf-error :arch-error message data))

;; ============================================================================
;; Error Classification
;; ============================================================================

(def transient-errnos
  "Errno values that indicate transient failures worth retrying"
  #{:eagain      ; Resource temporarily unavailable
    :eintr       ; Interrupted system call
    :ebusy       ; Device or resource busy
    :enomem      ; Out of memory (sometimes transient)
    :enobufs})   ; No buffer space available

(def permission-errnos
  "Errno values that indicate permission issues"
  #{:eperm       ; Operation not permitted
    :eacces})    ; Permission denied

(def resource-errnos
  "Errno values that indicate resource exhaustion"
  #{:enomem      ; Out of memory
    :enospc      ; No space left
    :emfile      ; Too many open files
    :enfile      ; File table overflow
    :enobufs})   ; No buffer space

(defn transient-error?
  "Returns true if the exception represents a transient error worth retrying."
  [e]
  (when-let [data (ex-data e)]
    (contains? transient-errnos (:errno-keyword data))))

(defn permission-error?
  "Returns true if the exception represents a permission error."
  [e]
  (when-let [data (ex-data e)]
    (or (= :permission-error (:error-type data))
        (contains? permission-errnos (:errno-keyword data)))))

(defn resource-error?
  "Returns true if the exception represents a resource exhaustion error."
  [e]
  (when-let [data (ex-data e)]
    (or (= :resource-error (:error-type data))
        (contains? resource-errnos (:errno-keyword data)))))

(defn verifier-error?
  "Returns true if the exception is a BPF verifier rejection."
  [e]
  (when-let [data (ex-data e)]
    (= :verifier-error (:error-type data))))

;; ============================================================================
;; Error Context Enhancement
;; ============================================================================

(defn enhance-error
  "Enhance an exception with additional context.

   Arguments:
   - e: The original exception
   - additional-data: Map of additional context to merge

   Returns a new exception with merged data."
  [e additional-data]
  (let [original-data (or (ex-data e) {})]
    (ex-info (.getMessage e)
             (merge original-data additional-data)
             e)))

(defn errno->error-type
  "Map an errno keyword to the most appropriate error type."
  [errno-kw]
  (cond
    (contains? permission-errnos errno-kw) :permission-error
    (contains? resource-errnos errno-kw)   :resource-error
    :else                                  :syscall-error))

(defn classify-syscall-error
  "Create a typed error from a syscall failure.

   Arguments:
   - operation: String describing the operation (e.g., \"map-create\")
   - errno: The errno number
   - errno-kw: The errno keyword
   - additional-data: Optional additional context

   Returns an ExceptionInfo with appropriate error type."
  ([operation errno errno-kw]
   (classify-syscall-error operation errno errno-kw {}))
  ([operation errno errno-kw additional-data]
   (let [error-type (errno->error-type errno-kw)
         message (format "BPF %s failed: %s (errno %d)"
                         operation (name errno-kw) errno)]
     (bpf-error error-type message
                (merge {:operation operation
                        :errno errno
                        :errno-keyword errno-kw}
                       additional-data)))))

;; ============================================================================
;; Retry Logic
;; ============================================================================

(def ^:dynamic *max-retries*
  "Default maximum number of retries for transient errors"
  3)

(def ^:dynamic *retry-delay-ms*
  "Default delay between retries in milliseconds"
  100)

(def ^:dynamic *retry-backoff-factor*
  "Multiplier for exponential backoff"
  2.0)

(defn with-retry
  "Execute a function with automatic retry on transient errors.

   Arguments:
   - f: Zero-argument function to execute
   - opts: Optional map with:
     - :max-retries (default 3)
     - :delay-ms (default 100)
     - :backoff-factor (default 2.0)
     - :on-retry (fn [attempt delay-ms exception] ...) - callback on retry

   Returns the result of f, or throws after max retries."
  ([f] (with-retry f {}))
  ([f {:keys [max-retries delay-ms backoff-factor on-retry]
       :or {max-retries *max-retries*
            delay-ms *retry-delay-ms*
            backoff-factor *retry-backoff-factor*
            on-retry (fn [_ _ _] nil)}}]
   (loop [attempt 1
          current-delay delay-ms]
     (let [result (try
                    {:value (f)}
                    (catch Exception e
                      {:error e}))]
       (if-let [e (:error result)]
         (if (and (< attempt max-retries)
                  (transient-error? e))
           (do
             (on-retry attempt current-delay e)
             (Thread/sleep (long current-delay))
             (recur (inc attempt)
                    (* current-delay backoff-factor)))
           (throw e))
         (:value result))))))

(defmacro retrying
  "Macro form of with-retry for more convenient usage.

   Example:
   (retrying {:max-retries 5}
     (syscall/map-create ...))"
  [opts & body]
  `(with-retry (fn [] ~@body) ~opts))

;; ============================================================================
;; Error Formatting
;; ============================================================================

(defn format-error
  "Format an exception for display.

   Returns a multi-line string with error details."
  [e]
  (let [data (ex-data e)
        lines [(str "Error: " (.getMessage e))]]
    (if data
      (let [lines (cond-> lines
                    (:error-type data)
                    (conj (str "  Type: " (name (:error-type data))))

                    (:errno data)
                    (conj (str "  Errno: " (:errno data)
                               (when (:errno-keyword data)
                                 (str " (" (name (:errno-keyword data)) ")"))))

                    (:operation data)
                    (conj (str "  Operation: " (:operation data)))

                    (:verifier-log data)
                    (conj (str "  Verifier log:\n" (:verifier-log data))))]
        (clojure.string/join "\n" lines))
      (.getMessage e))))

(defn error-summary
  "Get a one-line summary of an exception."
  [e]
  (let [data (ex-data e)]
    (if data
      (str (when (:error-type data) (str "[" (name (:error-type data)) "] "))
           (.getMessage e))
      (.getMessage e))))

;; ============================================================================
;; Assertion Helpers
;; ============================================================================

(defn check-result
  "Check a syscall result and throw an appropriate error if negative.

   Arguments:
   - result: The syscall result (typically an int or long)
   - operation: String describing the operation
   - get-errno-fn: Zero-arg function to get current errno
   - errno->kw-fn: Function to convert errno to keyword

   Returns result if non-negative, throws otherwise."
  [result operation get-errno-fn errno->kw-fn]
  (if (neg? result)
    (let [errno (get-errno-fn)
          errno-kw (errno->kw-fn errno)]
      (throw (classify-syscall-error operation errno errno-kw)))
    result))

(defn assert-map-fd
  "Assert that a map file descriptor is valid."
  [fd context]
  (when (or (nil? fd) (neg? fd))
    (throw (map-error "Invalid map file descriptor"
                      {:fd fd :context context}))))

(defn assert-program-fd
  "Assert that a program file descriptor is valid."
  [fd context]
  (when (or (nil? fd) (neg? fd))
    (throw (program-error "Invalid program file descriptor"
                          {:fd fd :context context}))))
