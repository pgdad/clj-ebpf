(ns examples.refs-examples
  "Examples demonstrating clj-ebpf reference types.

   These examples show idiomatic Clojure patterns for accessing BPF data
   structures using @, reset!, swap!, and conj!.

   NOTE: These examples require root/CAP_BPF privileges to run with real
   BPF maps. The mock examples can run without privileges."
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.refs :as refs]))

;; ============================================================================
;; Example 1: Basic Ring Buffer Reading
;; ============================================================================

(defn example-ringbuf-basic
  "Demonstrates basic ring buffer reading with @"
  []
  (println "\n=== Example 1: Basic Ring Buffer Reading ===\n")

  ;; In real use, you'd create a ring buffer and have a BPF program write to it
  ;; For demonstration, we show the API patterns

  (println "Creating ring buffer reference:")
  (println "  (def events (bpf/ringbuf-ref rb :deserializer parse-event))")
  (println)

  (println "Reading single event (blocking):")
  (println "  (let [event @events]")
  (println "    (process event))")
  (println)

  (println "Reading with timeout:")
  (println "  (when-let [event (deref events 5000 nil)]")
  (println "    (process event))")
  (println)

  (println "Processing as lazy sequence:")
  (println "  (doseq [event (take 100 (bpf/ringbuf-seq events))]")
  (println "    (process event))")
  (println)

  (println "With automatic cleanup:")
  (println "  (bpf/with-ringbuf-ref [events rb]")
  (println "    (dotimes [_ 10]")
  (println "      (println @events)))"))

;; ============================================================================
;; Example 2: Atom-like Map Access
;; ============================================================================

(defn example-map-entry-ref
  "Demonstrates atom-like access to BPF map entries"
  []
  (println "\n=== Example 2: Atom-like Map Access ===\n")

  (println "Creating map and entry reference:")
  (println "  (def stats-map (bpf/create-hash-map {...}))")
  (println "  (def counter (bpf/map-entry-ref stats-map :packet-count))")
  (println)

  (println "Reading value with @:")
  (println "  @counter  ; => current value")
  (println)

  (println "Setting value with reset!:")
  (println "  (reset! counter 0)  ; => 0")
  (println)

  (println "Read-modify-write with swap!:")
  (println "  (swap! counter inc)     ; increment")
  (println "  (swap! counter + 10)    ; add 10")
  (println "  (swap! counter * 2)     ; double")
  (println)

  (println "Conditional update with compare-and-set!:")
  (println "  (compare-and-set! counter 100 0)  ; reset if value is 100")
  (println)

  (println "With validator:")
  (println "  (def counter (bpf/map-entry-ref stats-map :count")
  (println "                 :validator pos?))  ; only allow positive values")
  (println "  (reset! counter -1)  ; throws IllegalStateException"))

;; ============================================================================
;; Example 3: Queue Operations
;; ============================================================================

(defn example-queue-operations
  "Demonstrates queue writer and channel patterns"
  []
  (println "\n=== Example 3: Queue Operations ===\n")

  (println "Producer with queue-writer:")
  (println "  (def producer (bpf/queue-writer work-queue))")
  (println "  (-> producer")
  (println "      (conj! {:task :start})")
  (println "      (conj! {:task :process})")
  (println "      (conj! {:task :end}))")
  (println "  (println \"Next:\" @producer)  ; peek without removing")
  (println)

  (println "Consumer with queue-ref:")
  (println "  (def consumer (bpf/queue-ref work-queue))")
  (println "  (let [task @consumer]  ; blocking pop")
  (println "    (execute task))")
  (println)

  (println "Bidirectional with queue-channel:")
  (println "  (def ch (bpf/queue-channel work-queue))")
  (println "  (conj! ch {:task 1})  ; push")
  (println "  (let [task @ch]       ; blocking pop (FIFO)")
  (println "    (execute task))"))

;; ============================================================================
;; Example 4: Stack Operations (LIFO)
;; ============================================================================

(defn example-stack-operations
  "Demonstrates stack writer and channel patterns"
  []
  (println "\n=== Example 4: Stack Operations ===\n")

  (println "Building undo stack:")
  (println "  (def recorder (bpf/stack-writer undo-stack))")
  (println "  (conj! recorder {:action :insert :text \"A\"})")
  (println "  (conj! recorder {:action :insert :text \"B\"})")
  (println "  (conj! recorder {:action :insert :text \"C\"})")
  (println "  (println \"Last:\" @recorder)  ; peek => {:action :insert :text \"C\"}")
  (println)

  (println "Pop for undo (LIFO):")
  (println "  (def undo-ref (bpf/stack-ref undo-stack))")
  (println "  (let [last-action @undo-ref]  ; pops \"C\" first")
  (println "    (undo last-action))")
  (println)

  (println "Bidirectional stack channel:")
  (println "  (def ch (bpf/stack-channel undo-stack))")
  (println "  (conj! ch {:op 1})  ; push")
  (println "  (conj! ch {:op 2})  ; push")
  (println "  @ch                  ; blocking pop => {:op 2} (LIFO)"))

;; ============================================================================
;; Example 5: Map Watching
;; ============================================================================

(defn example-map-watching
  "Demonstrates watching for map key existence and changes"
  []
  (println "\n=== Example 5: Map Watching ===\n")

  (println "Wait for key to exist:")
  (println "  (let [watcher (bpf/map-watch stats-map :initialized)]")
  (println "    (let [value (deref watcher 10000 :not-ready)]")
  (println "      (if (= value :not-ready)")
  (println "        (println \"BPF program not ready\")")
  (println "        (println \"Ready! Value:\" value))))")
  (println)

  (println "Watch for value changes:")
  (println "  (let [watcher (bpf/map-watch-changes stats-map :counter)]")
  (println "    (loop [n 0]")
  (println "      (when (< n 10)")
  (println "        (let [new-val @watcher]  ; blocks until change")
  (println "          (println \"Counter changed:\" new-val)")
  (println "          (recur (inc n))))))")
  (println)

  (println "With initial value:")
  (println "  (bpf/map-watch-changes stats-map :counter")
  (println "    :initial-value 0)  ; won't trigger until different from 0"))

;; ============================================================================
;; Example 6: Complete Producer-Consumer Pattern
;; ============================================================================

(defn example-producer-consumer
  "Demonstrates a complete producer-consumer pattern"
  []
  (println "\n=== Example 6: Producer-Consumer Pattern ===\n")

  (println "(defn start-producer-consumer []")
  (println "  (let [queue (bpf/create-queue-map {:value-size 64 :max-entries 1000})")
  (println "        ch (bpf/queue-channel queue)")
  (println "        running (atom true)]")
  (println)
  (println "    ;; Producer thread")
  (println "    (future")
  (println "      (dotimes [i 100]")
  (println "        (when @running")
  (println "          (conj! ch {:task i :data (str \"item-\" i)})")
  (println "          (Thread/sleep 100))))")
  (println)
  (println "    ;; Consumer thread")
  (println "    (future")
  (println "      (loop []")
  (println "        (when @running")
  (println "          (when-let [task (deref ch 1000 nil)]")
  (println "            (println \"Processing:\" task)")
  (println "            (recur)))))")
  (println)
  (println "    ;; Return stop function")
  (println "    (fn []")
  (println "      (reset! running false)")
  (println "      (.close ch))))"))

;; ============================================================================
;; Example 7: Event Processing Pipeline
;; ============================================================================

(defn example-event-pipeline
  "Demonstrates a multi-stage event processing pipeline"
  []
  (println "\n=== Example 7: Event Processing Pipeline ===\n")

  (println "(defn create-pipeline []")
  (println "  (let [;; Data structures")
  (println "        events-rb (bpf/create-ringbuf-map {:max-entries (* 256 1024)})")
  (println "        work-queue (bpf/create-queue-map {:value-size 128 :max-entries 1000})")
  (println "        stats-map (bpf/create-hash-map {:key-size 4 :value-size 8})")
  (println)
  (println "        ;; References")
  (println "        events (bpf/ringbuf-ref events-rb :deserializer parse-event)")
  (println "        work-ch (bpf/queue-channel work-queue)")
  (println "        event-count (bpf/map-entry-ref stats-map :count)]")
  (println)
  (println "    ;; Initialize")
  (println "    (reset! event-count 0)")
  (println)
  (println "    ;; Event reader -> filter -> queue")
  (println "    (future")
  (println "      (loop []")
  (println "        (when-let [event (deref events 1000 nil)]")
  (println "          (swap! event-count inc)")
  (println "          (when (important? event)")
  (println "            (conj! work-ch event))")
  (println "          (recur))))")
  (println)
  (println "    ;; Worker")
  (println "    (future")
  (println "      (loop []")
  (println "        (when-let [work @work-ch]")
  (println "          (process work)")
  (println "          (recur))))))")
  (println)
  (println "Usage: Combines ringbuf-ref, queue-channel, and map-entry-ref"))

;; ============================================================================
;; Example 8: Resource Management Patterns
;; ============================================================================

(defn example-resource-management
  "Demonstrates proper resource management patterns"
  []
  (println "\n=== Example 8: Resource Management ===\n")

  (println "Pattern 1: with-* macros (preferred)")
  (println "  (bpf/with-ringbuf-ref [events rb]")
  (println "    (doseq [e (take 100 (bpf/ringbuf-seq events))]")
  (println "      (process e)))")
  (println "  ;; Automatically closed")
  (println)

  (println "Pattern 2: try/finally")
  (println "  (let [ref (bpf/queue-ref queue)]")
  (println "    (try")
  (println "      (loop []")
  (println "        (when-let [item @ref]")
  (println "          (process item)")
  (println "          (recur)))")
  (println "      (finally")
  (println "        (.close ref))))")
  (println)

  (println "Pattern 3: Component lifecycle")
  (println "  (defrecord EventProcessor [refs running]")
  (println "    java.io.Closeable")
  (println "    (close [this]")
  (println "      (reset! running false)")
  (println "      (doseq [ref (vals refs)]")
  (println "        (.close ref))))")
  (println)

  (println "Anti-pattern: DON'T forget to close!")
  (println "  (def events (bpf/ringbuf-ref rb))  ; resource leak if not closed"))

;; ============================================================================
;; Run All Examples
;; ============================================================================

(defn run-all-examples
  "Run all examples to display patterns and usage"
  []
  (println "========================================")
  (println "clj-ebpf Reference Types Examples")
  (println "========================================")

  (example-ringbuf-basic)
  (example-map-entry-ref)
  (example-queue-operations)
  (example-stack-operations)
  (example-map-watching)
  (example-producer-consumer)
  (example-event-pipeline)
  (example-resource-management)

  (println "\n========================================")
  (println "Reference Type Summary")
  (println "========================================")
  (println)
  (println "Read-Only References:")
  (println "  ringbuf-ref     @ref = blocking pop from ring buffer")
  (println "  queue-ref       @ref = blocking pop from queue (FIFO)")
  (println "  stack-ref       @ref = blocking pop from stack (LIFO)")
  (println "  map-watch       @ref = block until key exists")
  (println "  map-watch-changes  @ref = block until value changes")
  (println)
  (println "Writable References:")
  (println "  map-entry-ref   @ref, (reset! ref v), (swap! ref f)")
  (println "  queue-writer    (conj! ref v), @ref = peek")
  (println "  stack-writer    (conj! ref v), @ref = peek")
  (println)
  (println "Bidirectional:")
  (println "  queue-channel   (conj! ref v), @ref = blocking pop (FIFO)")
  (println "  stack-channel   (conj! ref v), @ref = blocking pop (LIFO)"))

;; Run examples when loaded
(comment
  (run-all-examples))
