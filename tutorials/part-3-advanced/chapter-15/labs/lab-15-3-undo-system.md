# Lab 15.3: Undo/Redo System with Stack Channels

**Duration**: 45-60 minutes | **Difficulty**: Intermediate

## Objective

Build an undo/redo system using stack channels that demonstrates:
- LIFO (Last-In-First-Out) semantics with stack channels
- Bidirectional stack access with `conj!` and `@`
- Managing two stacks (undo and redo) together
- Practical use of `stack-writer` and `stack-channel`

## Prerequisites

- Completed Lab 15.1 and 15.2
- Understanding of undo/redo patterns
- Familiarity with stack data structures

## Scenario

You're building a text editor with undo/redo support. Each operation is recorded to an undo stack. When the user undoes, the operation moves to the redo stack. This pattern is common in editors, drawing applications, and state management systems.

---

## Part 1: Infrastructure Setup

### Step 1.1: Create Stack Maps

```clojure
(ns lab-15-3.undo-system
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.refs :as refs]))

;; Operation stack - holds operations that can be undone
(def undo-stack
  (bpf/create-stack-map {:value-size 256 :max-entries 100}))

;; Redo stack - holds undone operations that can be redone
(def redo-stack
  (bpf/create-stack-map {:value-size 256 :max-entries 100}))

;; Current document state (simulated with a map)
(def document-map
  (bpf/create-hash-map {:key-size 4 :value-size 1024 :max-entries 1}))
```

### Step 1.2: Operation Types

```clojure
;; Operation types
(def OP-INSERT 1)
(def OP-DELETE 2)
(def OP-REPLACE 3)

(defn make-operation [op-type position text & [old-text]]
  {:type op-type
   :position position
   :text text
   :old-text (or old-text "")
   :timestamp (System/currentTimeMillis)})

;; Serialization
(defn serialize-operation [op]
  (let [buf (byte-array 256)]
    (bpf/int->bytes! buf 0 (:type op))
    (bpf/int->bytes! buf 4 (:position op))
    (bpf/long->bytes! buf 8 (:timestamp op))
    (bpf/string->bytes! buf 16 (:text op) 100)
    (bpf/string->bytes! buf 116 (:old-text op) 100)
    buf))

(defn deserialize-operation [bytes]
  {:type (bpf/bytes->int bytes 0)
   :position (bpf/bytes->int bytes 4)
   :timestamp (bpf/bytes->long bytes 8)
   :text (bpf/bytes->string bytes 16 100)
   :old-text (bpf/bytes->string bytes 116 100)})
```

---

## Part 2: Undo/Redo Manager

### Step 2.1: Core Manager

```clojure
(defrecord UndoManager [undo-ch redo-ch doc-ref])

(defn create-undo-manager []
  "Create an undo manager with stack channels"
  (let [;; Initialize document
        _ (bpf/map-update document-map 0 "")
        doc-ref (bpf/map-entry-ref document-map 0)
        ;; Create bidirectional stack channels
        undo-ch (bpf/stack-channel undo-stack)
        redo-ch (bpf/stack-channel redo-stack)]
    (->UndoManager undo-ch redo-ch doc-ref)))

(defn close-undo-manager [manager]
  (.close (:undo-ch manager))
  (.close (:redo-ch manager))
  (.close (:doc-ref manager)))
```

### Step 2.2: Document Operations

```clojure
(defn get-document [manager]
  "Get current document content"
  @(:doc-ref manager))

(defn apply-operation [manager op]
  "Apply an operation to the document"
  (let [doc (get-document manager)
        new-doc (case (:type op)
                  1 ; INSERT
                  (str (subs doc 0 (:position op))
                       (:text op)
                       (subs doc (:position op)))

                  2 ; DELETE
                  (str (subs doc 0 (:position op))
                       (subs doc (+ (:position op) (count (:text op)))))

                  3 ; REPLACE
                  (str (subs doc 0 (:position op))
                       (:text op)
                       (subs doc (+ (:position op) (count (:old-text op)))))

                  doc)]
    (reset! (:doc-ref manager) new-doc)
    new-doc))

(defn reverse-operation [op]
  "Create the reverse of an operation"
  (case (:type op)
    1 ; INSERT -> DELETE
    (make-operation OP-DELETE (:position op) (:text op))

    2 ; DELETE -> INSERT
    (make-operation OP-INSERT (:position op) (:text op))

    3 ; REPLACE -> reverse REPLACE
    (make-operation OP-REPLACE (:position op) (:old-text op) (:text op))

    op))
```

### Step 2.3: Execute with Undo Support

```clojure
(defn execute! [manager op]
  "Execute an operation with undo support"
  (println (format "Executing: %s at %d: '%s'"
                   (case (:type op) 1 "INSERT" 2 "DELETE" 3 "REPLACE" "?")
                   (:position op)
                   (:text op)))

  ;; Apply the operation
  (apply-operation manager op)

  ;; Push to undo stack
  (conj! (:undo-ch manager) (serialize-operation op))

  ;; Clear redo stack (new operation invalidates redo history)
  ;; In real implementation, you'd clear the entire stack
  ;; For simplicity, we just note this should happen

  (println "Document:" (get-document manager)))
```

---

## Part 3: Undo and Redo

### Step 3.1: Undo Operation

```clojure
(defn undo! [manager]
  "Undo the last operation"
  ;; Pop from undo stack (blocking with short timeout)
  (if-let [op-bytes (deref (:undo-ch manager) 100 nil)]
    (let [op (deserialize-operation op-bytes)
          reverse-op (reverse-operation op)]
      (println (format "Undoing: %s at %d"
                       (case (:type op) 1 "INSERT" 2 "DELETE" 3 "REPLACE" "?")
                       (:position op)))

      ;; Apply reverse operation
      (apply-operation manager reverse-op)

      ;; Push original operation to redo stack
      (conj! (:redo-ch manager) op-bytes)

      (println "Document:" (get-document manager))
      true)
    (do
      (println "Nothing to undo")
      false)))
```

### Step 3.2: Redo Operation

```clojure
(defn redo! [manager]
  "Redo the last undone operation"
  ;; Pop from redo stack
  (if-let [op-bytes (deref (:redo-ch manager) 100 nil)]
    (let [op (deserialize-operation op-bytes)]
      (println (format "Redoing: %s at %d"
                       (case (:type op) 1 "INSERT" 2 "DELETE" 3 "REPLACE" "?")
                       (:position op)))

      ;; Apply operation again
      (apply-operation manager op)

      ;; Push back to undo stack
      (conj! (:undo-ch manager) op-bytes)

      (println "Document:" (get-document manager))
      true)
    (do
      (println "Nothing to redo")
      false)))
```

---

## Part 4: High-Level API

### Step 4.1: Convenient Operations

```clojure
(defn insert! [manager position text]
  "Insert text at position"
  (execute! manager (make-operation OP-INSERT position text)))

(defn delete! [manager position length]
  "Delete text at position"
  (let [doc (get-document manager)
        deleted-text (subs doc position (+ position length))]
    (execute! manager (make-operation OP-DELETE position deleted-text))))

(defn replace! [manager position old-text new-text]
  "Replace text at position"
  (execute! manager (make-operation OP-REPLACE position new-text old-text)))
```

### Step 4.2: Peek Operations

```clojure
(defn peek-undo [manager]
  "Peek at the next operation to undo without removing it"
  ;; Use stack-writer's peek functionality
  (let [writer (bpf/stack-writer undo-stack)]
    (try
      (when-let [bytes @writer]
        (deserialize-operation bytes))
      (finally
        (.close writer)))))

(defn peek-redo [manager]
  "Peek at the next operation to redo without removing it"
  (let [writer (bpf/stack-writer redo-stack)]
    (try
      (when-let [bytes @writer]
        (deserialize-operation bytes))
      (finally
        (.close writer)))))
```

---

## Part 5: Interactive Demo

### Step 5.1: Demo Application

```clojure
(defn demo-undo-system []
  (println "=== Undo/Redo System Demo ===\n")

  (let [manager (create-undo-manager)]
    (try
      ;; Start with empty document
      (println "Initial document:" (get-document manager))
      (println)

      ;; Build up some text
      (insert! manager 0 "Hello")
      (println)

      (insert! manager 5 " World")
      (println)

      (insert! manager 11 "!")
      (println)

      ;; Document is now "Hello World!"
      (println "--- After insertions ---")
      (println "Document:" (get-document manager))
      (println)

      ;; Undo the last insertion
      (println "--- Undo ---")
      (undo! manager)
      (println)

      ;; Undo another
      (println "--- Undo ---")
      (undo! manager)
      (println)

      ;; Document is now "Hello"
      (println "--- After undos ---")
      (println "Document:" (get-document manager))
      (println)

      ;; Redo one operation
      (println "--- Redo ---")
      (redo! manager)
      (println)

      ;; Document is now "Hello World"
      (println "--- Final ---")
      (println "Document:" (get-document manager))

      (finally
        (close-undo-manager manager)))))

;; Run the demo
(demo-undo-system)
```

### Step 5.2: Interactive REPL Session

```clojure
(defn start-interactive-session []
  "Start an interactive editing session"
  (let [manager (create-undo-manager)]
    (println "Interactive Undo/Redo Session")
    (println "Commands:")
    (println "  (insert! manager pos text)")
    (println "  (delete! manager pos len)")
    (println "  (undo! manager)")
    (println "  (redo! manager)")
    (println "  (get-document manager)")
    (println "  (close-undo-manager manager) to end")
    (println)
    manager))

;; Usage:
;; (def m (start-interactive-session))
;; (insert! m 0 "Hello")
;; (insert! m 5 " World")
;; (undo! m)
;; (redo! m)
;; (close-undo-manager m)
```

---

## Part 6: Exercises

### Exercise 1: Multi-Level Undo

Add support for undoing multiple operations at once:

```clojure
(defn undo-n! [manager n]
  "Undo n operations at once"
  ;; TODO: Implement
  ;; Pop n items from undo stack
  ;; Apply reverse operations in order
  ;; Push all to redo stack
  )
```

### Exercise 2: Transaction Grouping

Group multiple operations as a single undo unit:

```clojure
(defmacro with-transaction [manager & body]
  "Group operations as a single undoable transaction"
  ;; TODO: Implement
  ;; Collect all operations during body
  ;; Store as a compound operation
  )

;; Usage:
;; (with-transaction manager
;;   (insert! manager 0 "A")
;;   (insert! manager 1 "B")
;;   (insert! manager 2 "C"))
;; ;; Single undo removes all three
```

### Exercise 3: Undo History Browser

Build a viewer for the undo/redo history:

```clojure
(defn get-undo-history [manager max-items]
  "Get list of operations in undo stack without modifying it"
  ;; TODO: Implement
  ;; This is tricky with stacks - you'd need to pop and re-push
  ;; Or maintain a separate history list
  )

(defn display-history [manager]
  "Display undo/redo history"
  ;; TODO: Implement
  )
```

### Exercise 4: Persistent Undo History

Save and restore undo history:

```clojure
(defn save-history [manager filename]
  "Save undo/redo stacks to file"
  ;; TODO: Implement
  )

(defn restore-history [manager filename]
  "Restore undo/redo stacks from file"
  ;; TODO: Implement
  )
```

---

## Part 7: Testing

### Unit Tests

```clojure
(defn test-undo-system []
  (println "Testing undo system...")

  (let [manager (create-undo-manager)]
    (try
      ;; Test insert
      (insert! manager 0 "Test")
      (assert (= "Test" (get-document manager)))

      ;; Test undo
      (undo! manager)
      (assert (= "" (get-document manager)))

      ;; Test redo
      (redo! manager)
      (assert (= "Test" (get-document manager)))

      ;; Test multiple operations
      (insert! manager 4 "ing")
      (assert (= "Testing" (get-document manager)))

      (insert! manager 7 " 123")
      (assert (= "Testing 123" (get-document manager)))

      ;; Multiple undos
      (undo! manager)
      (assert (= "Testing" (get-document manager)))

      (undo! manager)
      (assert (= "Test" (get-document manager)))

      ;; Multiple redos
      (redo! manager)
      (assert (= "Testing" (get-document manager)))

      (redo! manager)
      (assert (= "Testing 123" (get-document manager)))

      (println "All tests passed!")

      (finally
        (close-undo-manager manager)))))

(test-undo-system)
```

---

## Summary

In this lab you learned:
- Using `stack-channel` for bidirectional stack access
- LIFO semantics with `conj!` (push) and `@` (pop)
- Building undo/redo with two coordinated stacks
- Reversing operations for proper undo behavior
- Peeking at stack contents without removal

## Key Patterns

1. **Two-Stack Undo**: Undo stack + Redo stack pattern
2. **Operation Reversal**: Each operation knows how to reverse itself
3. **Stack Channel**: Single reference for both push and pop
4. **Non-Blocking Peek**: Use `stack-writer` with `@` for peek

## Design Considerations

1. **Redo Invalidation**: New operations should clear the redo stack
2. **Memory Limits**: BPF stacks have max-entries limit
3. **Serialization**: Operations must be serializable to bytes
4. **Atomicity**: Complex operations may need transaction grouping

## Next Steps

- Explore using these patterns for state management
- Combine with event sourcing for persistence
- Add branching undo (tree-based history)
