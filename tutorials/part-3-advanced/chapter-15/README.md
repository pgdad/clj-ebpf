# Chapter 15: Idiomatic Clojure References for BPF

**Duration**: 2-3 hours | **Difficulty**: Intermediate

This chapter introduces clj-ebpf's reference types that provide idiomatic Clojure access to BPF data structures using standard protocols like `IDeref`, `IAtom`, and `ITransientCollection`.

## Learning Objectives

By the end of this chapter, you will:
- Understand how Clojure reference semantics map to BPF operations
- Use `@` (deref) for blocking reads from ring buffers and queues
- Use `reset!` and `swap!` for atom-like map access
- Use `conj!` for pushing to queues and stacks
- Build producer-consumer patterns with BPF channels

## Prerequisites

- Completed Chapter 2 (BPF Maps)
- Familiarity with Clojure reference types (atoms, refs)
- Understanding of blocking I/O patterns

---

## 15.1 Why Clojure References for BPF?

Traditional BPF map access uses explicit function calls:

```clojure
;; Traditional approach
(bpf/map-lookup my-map key)
(bpf/map-update my-map key new-value)
(bpf/queue-pop my-queue)
(bpf/ringbuf-read rb handler)
```

While functional, this doesn't leverage Clojure's powerful reference abstractions. The `clj-ebpf.refs` namespace provides reference types that feel native to Clojure:

```clojure
;; Idiomatic Clojure approach
@counter                          ; Read map value
(reset! counter 0)                ; Write map value
(swap! counter inc)               ; Read-modify-write
@ring-buffer                      ; Block until event available
(conj! queue {:event :data})      ; Push to queue
```

### Benefits

1. **Familiar Semantics**: Use the same patterns you know from atoms and refs
2. **Composability**: Works with standard Clojure functions expecting IDeref
3. **Blocking Operations**: Natural blocking reads with timeout support
4. **Resource Management**: Automatic cleanup with `with-*` macros

---

## 15.2 Read-Only References

### 15.2.1 Ring Buffer References (`ringbuf-ref`)

Ring buffers are the primary mechanism for BPF programs to send events to userspace. `ringbuf-ref` creates a blocking, deref-able reference:

```clojure
(require '[clj-ebpf.core :as bpf])

;; Create a ring buffer map
(def events-rb (bpf/create-ringbuf-map {:max-entries (* 256 1024)}))

;; Create a deref-able reference
(def events (bpf/ringbuf-ref events-rb
              :deserializer (fn [bytes]
                              (parse-event bytes))))

;; Block until event available
(let [event @events]
  (println "Got event:" event))

;; With timeout (1 second, returns nil on timeout)
(when-let [event (deref events 1000 nil)]
  (process-event event))

;; Always close when done
(.close events)
```

#### Lazy Event Sequences

For processing multiple events, use `ringbuf-seq`:

```clojure
;; Process exactly 100 events
(let [ref (bpf/ringbuf-ref events-rb)]
  (try
    (doseq [event (take 100 (bpf/ringbuf-seq ref))]
      (process-event event))
    (finally
      (.close ref))))

;; Process events until timeout
(doseq [event (bpf/ringbuf-seq ref :timeout-ms 5000)]
  (process-event event))
;; Sequence ends when timeout occurs
```

#### Resource Management

Use `with-ringbuf-ref` for automatic cleanup:

```clojure
(bpf/with-ringbuf-ref [events my-ringbuf :deserializer parse-event]
  (dotimes [_ 10]
    (println "Event:" @events)))
;; Reference automatically closed
```

### 15.2.2 Queue/Stack References (`queue-ref`, `stack-ref`)

For blocking pops from queue and stack maps:

```clojure
;; Create queue map
(def work-queue (bpf/create-queue-map {:value-size 64 :max-entries 1000}))

;; Blocking pop reference
(def worker (bpf/queue-ref work-queue))

;; Block until item available
(let [task @worker]
  (execute-task task))

;; With timeout
(when-let [task (deref worker 5000 :no-work)]
  (unless (= task :no-work)
    (execute-task task)))

(.close worker)
```

Stack references work identically but pop in LIFO order:

```clojure
(def undo-stack (bpf/create-stack-map {:value-size 32 :max-entries 100}))
(def undo-ref (bpf/stack-ref undo-stack))

;; Pop most recent (LIFO)
(let [last-action @undo-ref]
  (undo-action last-action))
```

### 15.2.3 Map Watchers (`map-watch`, `map-watch-changes`)

Wait for a specific key to appear or change in a map:

```clojure
;; Wait for BPF program to initialize a counter
(def stats-map (bpf/create-hash-map {:key-size 4 :value-size 8 :max-entries 100}))

(let [watcher (bpf/map-watch stats-map :packet-count)]
  (try
    ;; Block until :packet-count key exists
    (let [initial-count (deref watcher 10000 0)]
      (println "Initial packet count:" initial-count))
    (finally
      (.close watcher))))
```

To watch for value changes:

```clojure
(let [watcher (bpf/map-watch-changes stats-map :counter)]
  (try
    (loop [changes 0]
      (when (< changes 10)
        ;; Block until value changes from last seen
        (let [new-val @watcher]
          (println "Counter changed to:" new-val)
          (recur (inc changes)))))
    (finally
      (.close watcher))))
```

---

## 15.3 Writable References

### 15.3.1 Map Entry References (`map-entry-ref`)

`map-entry-ref` provides atom-like semantics for a specific key in a BPF map:

```clojure
(def stats-map (bpf/create-hash-map {:key-size 4 :value-size 8 :max-entries 100}))

;; Create atom-like reference to a specific key
(def packet-count (bpf/map-entry-ref stats-map :packets))

;; Read current value
(println "Packets:" @packet-count)

;; Set new value
(reset! packet-count 0)

;; Read-modify-write
(swap! packet-count inc)
(swap! packet-count + 100)

;; Conditional update
(when (compare-and-set! packet-count 100 0)
  (println "Reset counter from 100 to 0"))

(.close packet-count)
```

#### With Validators

```clojure
;; Only allow non-negative values
(def counter (bpf/map-entry-ref stats-map :count
               :validator #(and (number? %) (>= % 0))))

(reset! counter 10)   ; OK
(reset! counter -1)   ; Throws IllegalStateException
```

#### Important Note on Atomicity

`swap!` and `compare-and-set!` are NOT truly atomic at the kernel level for hash maps. They perform read-modify-write in userspace. For true atomicity with concurrent BPF program access, use atomic BPF map operations within the BPF program itself:

```clojure
;; In BPF program - truly atomic
(bpf/atomic-add :dw :r10 :r1 -8)  ; Atomic add to map value
```

### 15.3.2 Queue/Stack Writers (`queue-writer`, `stack-writer`)

Push values to queues and stacks using `conj!`:

```clojure
;; Create a work queue
(def work-queue (bpf/create-queue-map {:value-size 64 :max-entries 1000}))

;; Writer reference
(def producer (bpf/queue-writer work-queue))

;; Push values (returns the writer for chaining)
(-> producer
    (conj! {:task :process-file :path "/var/log/syslog"})
    (conj! {:task :process-file :path "/var/log/auth.log"})
    (conj! {:task :cleanup}))

;; Peek at front (non-blocking, doesn't remove)
(println "Next task:" @producer)

(.close producer)
```

Stack writers work the same way:

```clojure
(def undo-stack (bpf/create-stack-map {:value-size 32 :max-entries 100}))
(def recorder (bpf/stack-writer undo-stack))

;; Record operations
(conj! recorder {:action :insert :pos 0 :text "Hello"})
(conj! recorder {:action :insert :pos 5 :text " World"})

;; Peek at top
(println "Last action:" @recorder)  ; => {:action :insert :pos 5 ...}

(.close recorder)
```

---

## 15.4 Bidirectional Channels

### 15.4.1 Queue Channels (`queue-channel`)

Combines reading and writing in a single reference:

```clojure
(def work-queue (bpf/create-queue-map {:value-size 64 :max-entries 1000}))

;; Create bidirectional channel
(def channel (bpf/queue-channel work-queue))

;; Producer pushes work
(conj! channel {:task 1 :data "process-this"})
(conj! channel {:task 2 :data "and-this"})

;; Consumer pops work (blocking)
(let [task @channel]
  (println "Processing:" task))

;; With timeout
(when-let [task (deref channel 5000 nil)]
  (process task))

(.close channel)
```

### 15.4.2 Stack Channels (`stack-channel`)

Same as queue channels but with LIFO semantics:

```clojure
(def undo-stack (bpf/create-stack-map {:value-size 32 :max-entries 100}))
(def ch (bpf/stack-channel undo-stack))

;; Push operations
(conj! ch {:op :insert :text "A"})
(conj! ch {:op :insert :text "B"})
(conj! ch {:op :insert :text "C"})

;; Pop for undo (LIFO - gets C first)
(let [last-op @ch]
  (println "Undoing:" last-op))  ; => {:op :insert :text "C"}

(.close ch)
```

---

## 15.5 Complete Example: Event Processing Pipeline

Here's a complete example combining multiple reference types:

```clojure
(ns my-app.bpf-pipeline
  (:require [clj-ebpf.core :as bpf]))

;; === Map Creation ===
(def events-rb (bpf/create-ringbuf-map {:max-entries (* 256 1024)}))
(def stats-map (bpf/create-hash-map {:key-size 4 :value-size 8 :max-entries 10}))
(def work-queue (bpf/create-queue-map {:value-size 128 :max-entries 1000}))

;; === Event Parser ===
(defn parse-event [bytes]
  {:timestamp (bpf/bytes->long bytes 0)
   :pid (bpf/bytes->int bytes 8)
   :event-type (bpf/bytes->int bytes 12)})

;; === Processing Pipeline ===
(defn start-pipeline []
  (let [;; Ring buffer for kernel events
        events (bpf/ringbuf-ref events-rb :deserializer parse-event)
        ;; Counter for statistics
        event-count (bpf/map-entry-ref stats-map :event-count)
        ;; Work queue for downstream processing
        work-ch (bpf/queue-channel work-queue)]

    ;; Initialize counter
    (reset! event-count 0)

    ;; Event processing loop
    (future
      (try
        (loop []
          (when-let [event (deref events 1000 nil)]
            ;; Increment counter
            (swap! event-count inc)

            ;; Enqueue for further processing if important
            (when (= (:event-type event) :important)
              (conj! work-ch event))

            (recur)))
        (finally
          (.close events)
          (.close event-count)
          (.close work-ch))))

    ;; Worker processing loop
    (future
      (try
        (loop []
          (when-let [work (deref work-ch 1000 nil)]
            (println "Processing important event:" work)
            (recur)))
        (catch Exception e
          (println "Worker error:" e))))))

;; === Statistics Reporter ===
(defn report-stats []
  (let [count-ref (bpf/map-entry-ref stats-map :event-count)]
    (try
      (println "Events processed:" @count-ref)
      (finally
        (.close count-ref)))))
```

---

## 15.6 Reference Type Summary

| Type | Read (`@`) | Write | Protocol | Use Case |
|------|-----------|-------|----------|----------|
| `ringbuf-ref` | Blocking pop | N/A | IBlockingDeref | Kernel-to-user events |
| `queue-ref` | Blocking pop | N/A | IBlockingDeref | Consumer from queue |
| `stack-ref` | Blocking pop | N/A | IBlockingDeref | Consumer from stack |
| `map-watch` | Block until exists | N/A | IBlockingDeref | Wait for initialization |
| `map-watch-changes` | Block until changed | N/A | IBlockingDeref | Monitor value changes |
| `map-entry-ref` | Read value | `reset!`, `swap!` | IAtom | Atom-like map access |
| `queue-writer` | Peek | `conj!` | ITransientCollection | Producer to queue |
| `stack-writer` | Peek | `conj!` | ITransientCollection | Producer to stack |
| `queue-channel` | Blocking pop | `conj!` | Both | Bidirectional queue |
| `stack-channel` | Blocking pop | `conj!` | Both | Bidirectional stack |

---

## 15.7 Best Practices

### Resource Management

Always close references when done:

```clojure
;; Preferred: use with-* macros
(bpf/with-ringbuf-ref [ref rb]
  (process @ref))

;; Manual: use try/finally
(let [ref (bpf/ringbuf-ref rb)]
  (try
    (process @ref)
    (finally
      (.close ref))))
```

### Timeout Handling

Always use timeouts in production to avoid indefinite blocking:

```clojure
;; Don't do this in production
@ref  ; Could block forever

;; Do this instead
(if-let [val (deref ref 5000 nil)]
  (process val)
  (handle-timeout))
```

### Lazy Sequences

When processing many events, prefer lazy sequences with limits:

```clojure
;; Process up to 1000 events or until timeout
(doseq [event (take 1000 (bpf/ringbuf-seq ref :timeout-ms 30000))]
  (process event))
```

### Thread Safety

Reference types are thread-safe for concurrent access, but BPF maps have their own concurrency semantics:

```clojure
;; Multiple threads can safely deref the same reference
(let [ref (bpf/ringbuf-ref rb)]
  (dotimes [_ 4]
    (future
      (loop []
        (when-let [e (deref ref 1000 nil)]
          (process e)
          (recur))))))
```

---

## Labs

### Lab 15.1: Event Counter Dashboard
Build a real-time dashboard using map-entry-ref and map-watch-changes.
[Go to Lab 15.1](labs/lab-15-1-event-counter.md)

### Lab 15.2: Producer-Consumer Pipeline
Implement a multi-stage processing pipeline using queue channels.
[Go to Lab 15.2](labs/lab-15-2-producer-consumer.md)

### Lab 15.3: Undo System with Stack Channels
Build an undo/redo system using bidirectional stack channels.
[Go to Lab 15.3](labs/lab-15-3-undo-system.md)

---

## Key Takeaways

1. **Familiar Patterns**: clj-ebpf reference types use standard Clojure protocols
2. **Blocking Reads**: `@` and `deref` provide natural blocking semantics
3. **Atom-like Maps**: `reset!` and `swap!` work on map entries
4. **Collection Writes**: `conj!` pushes to queues and stacks
5. **Resource Safety**: Always use `with-*` macros or explicit `.close`
6. **Production Ready**: Always use timeouts to avoid indefinite blocking
