;; Lab 15.3 Solution: Undo/Redo System with Stack Channels
;; Demonstrates LIFO semantics with stack channels for undo/redo functionality
;;
;; Learning Goals:
;; - Use stack-channel for bidirectional stack access
;; - LIFO semantics with conj! (push) and @ (pop)
;; - Build undo/redo with two coordinated stacks
;; - Reverse operations for proper undo behavior

(ns lab-15-3-undo-system
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.utils :as utils])
  (:import [java.util Stack]
           [java.util.concurrent LinkedBlockingDeque TimeUnit]
           [java.time LocalTime]))

;; ============================================================================
;; Operation Types
;; ============================================================================

(def OP-INSERT 1)
(def OP-DELETE 2)
(def OP-REPLACE 3)

(def op-names
  {OP-INSERT "INSERT"
   OP-DELETE "DELETE"
   OP-REPLACE "REPLACE"})

;; ============================================================================
;; Simulated Stack Channel
;; ============================================================================

(defrecord MockStackChannel [stack max-entries]
  clojure.lang.IBlockingDeref
  (deref [_ timeout-ms timeout-val]
    (try
      (if-let [item (.pollLast stack timeout-ms TimeUnit/MILLISECONDS)]
        item
        timeout-val)
      (catch InterruptedException _
        timeout-val)))

  clojure.lang.IDeref
  (deref [this]
    (.deref this Long/MAX_VALUE nil))

  clojure.lang.ITransientCollection
  (conj [this val]
    (when (>= (.size stack) max-entries)
      (.pollFirst stack))  ; Remove oldest if full
    (.offerLast stack val)
    this)

  java.io.Closeable
  (close [_]
    (.clear stack)))

(defn stack-channel
  "Create a mock stack channel (LIFO queue)"
  [max-entries]
  (->MockStackChannel (LinkedBlockingDeque. max-entries) max-entries))

(defn stack-size
  "Get current stack size"
  [channel]
  (.size (:stack channel)))

(defn stack-peek
  "Peek at top without removing"
  [channel]
  (.peekLast (:stack channel)))

(defn stack-clear!
  "Clear all items from stack"
  [channel]
  (.clear (:stack channel)))

;; ============================================================================
;; Document Reference
;; ============================================================================

(defrecord MockDocRef [content]
  clojure.lang.IDeref
  (deref [_]
    @content)

  clojure.lang.IAtom
  (reset [_ newval]
    (reset! content newval)
    newval)
  (swap [_ f]
    (swap! content f))
  (swap [_ f x]
    (swap! content #(f % x)))
  (swap [_ f x y]
    (swap! content #(f % x y)))
  (swap [_ f x y more]
    (swap! content #(apply f % x y more)))
  (compareAndSet [_ oldval newval]
    (compare-and-set! content oldval newval))

  java.io.Closeable
  (close [_] nil))

(defn doc-ref
  "Create a document reference"
  [initial-content]
  (->MockDocRef (atom initial-content)))

;; ============================================================================
;; Operation Creation
;; ============================================================================

(defn make-operation
  "Create an operation record"
  [op-type position text & [old-text]]
  {:type op-type
   :position position
   :text text
   :old-text (or old-text "")
   :timestamp (System/currentTimeMillis)})

(defn operation-str
  "String representation of operation"
  [op]
  (format "%s at %d: '%s'"
          (get op-names (:type op) "?")
          (:position op)
          (:text op)))

;; ============================================================================
;; Undo Manager
;; ============================================================================

(defrecord UndoManager [undo-ch redo-ch doc-ref])

(defn create-undo-manager
  "Create an undo manager with stack channels"
  []
  (->UndoManager
   (stack-channel 100)
   (stack-channel 100)
   (doc-ref "")))

(defn close-undo-manager
  "Clean up undo manager resources"
  [manager]
  (.close (:undo-ch manager))
  (.close (:redo-ch manager))
  (.close (:doc-ref manager)))

;; ============================================================================
;; Document Operations
;; ============================================================================

(defn get-document
  "Get current document content"
  [manager]
  @(:doc-ref manager))

(defn safe-subs
  "Safe substring that handles edge cases"
  [s start & [end]]
  (let [len (count s)
        start (max 0 (min start len))
        end (if end (max start (min end len)) len)]
    (subs s start end)))

(defn apply-operation
  "Apply an operation to the document"
  [manager op]
  (let [doc (get-document manager)
        new-doc (case (:type op)
                  1 ; INSERT
                  (str (safe-subs doc 0 (:position op))
                       (:text op)
                       (safe-subs doc (:position op)))

                  2 ; DELETE
                  (str (safe-subs doc 0 (:position op))
                       (safe-subs doc (+ (:position op) (count (:text op)))))

                  3 ; REPLACE
                  (str (safe-subs doc 0 (:position op))
                       (:text op)
                       (safe-subs doc (+ (:position op) (count (:old-text op)))))

                  doc)]
    (reset! (:doc-ref manager) new-doc)
    new-doc))

(defn reverse-operation
  "Create the reverse of an operation"
  [op]
  (case (:type op)
    1 ; INSERT -> DELETE
    (make-operation OP-DELETE (:position op) (:text op))

    2 ; DELETE -> INSERT
    (make-operation OP-INSERT (:position op) (:text op))

    3 ; REPLACE -> reverse REPLACE
    (make-operation OP-REPLACE (:position op) (:old-text op) (:text op))

    op))

;; ============================================================================
;; Execute with Undo Support
;; ============================================================================

(defn execute!
  "Execute an operation with undo support"
  [manager op]
  (println (format "Executing: %s" (operation-str op)))

  ;; Apply the operation
  (apply-operation manager op)

  ;; Push to undo stack
  (conj! (:undo-ch manager) op)

  ;; Clear redo stack (new operation invalidates redo history)
  (stack-clear! (:redo-ch manager))

  (println (format "Document: \"%s\"" (get-document manager))))

;; ============================================================================
;; Undo and Redo
;; ============================================================================

(defn undo!
  "Undo the last operation"
  [manager]
  (if-let [op (.deref (:undo-ch manager) 100 nil)]
    (let [reverse-op (reverse-operation op)]
      (println (format "Undoing: %s" (operation-str op)))

      ;; Apply reverse operation
      (apply-operation manager reverse-op)

      ;; Push original operation to redo stack
      (conj! (:redo-ch manager) op)

      (println (format "Document: \"%s\"" (get-document manager)))
      true)
    (do
      (println "Nothing to undo")
      false)))

(defn redo!
  "Redo the last undone operation"
  [manager]
  (if-let [op (.deref (:redo-ch manager) 100 nil)]
    (do
      (println (format "Redoing: %s" (operation-str op)))

      ;; Apply operation again
      (apply-operation manager op)

      ;; Push back to undo stack
      (conj! (:undo-ch manager) op)

      (println (format "Document: \"%s\"" (get-document manager)))
      true)
    (do
      (println "Nothing to redo")
      false)))

;; ============================================================================
;; High-Level API
;; ============================================================================

(defn insert!
  "Insert text at position"
  [manager position text]
  (execute! manager (make-operation OP-INSERT position text)))

(defn delete!
  "Delete text at position"
  [manager position length]
  (let [doc (get-document manager)
        deleted-text (safe-subs doc position (+ position length))]
    (execute! manager (make-operation OP-DELETE position deleted-text))))

(defn replace!
  "Replace text at position"
  [manager position old-text new-text]
  (execute! manager (make-operation OP-REPLACE position new-text old-text)))

;; ============================================================================
;; Multi-Level Undo (Exercise 1)
;; ============================================================================

(defn undo-n!
  "Undo n operations at once"
  [manager n]
  (println (format "Undoing %d operations..." n))
  (loop [count 0]
    (when (and (< count n)
               (pos? (stack-size (:undo-ch manager))))
      (when (undo! manager)
        (recur (inc count)))))
  (println (format "Undid %d operations" (min n (stack-size (:redo-ch manager))))))

(defn redo-n!
  "Redo n operations at once"
  [manager n]
  (println (format "Redoing %d operations..." n))
  (loop [count 0]
    (when (and (< count n)
               (pos? (stack-size (:redo-ch manager))))
      (when (redo! manager)
        (recur (inc count))))))

;; ============================================================================
;; Transaction Grouping (Exercise 2)
;; ============================================================================

(defrecord CompoundOperation [operations])

(defn start-transaction!
  "Start a transaction for grouping operations"
  [manager]
  (assoc manager :transaction (atom [])))

(defn commit-transaction!
  "Commit a transaction as a single undoable unit"
  [manager]
  (when-let [tx-ops @(:transaction manager)]
    (when (seq tx-ops)
      ;; Create compound operation
      (let [compound {:type :compound
                      :operations tx-ops
                      :timestamp (System/currentTimeMillis)}]
        (conj! (:undo-ch manager) compound)
        (stack-clear! (:redo-ch manager))))
    (dissoc manager :transaction)))

(defn apply-compound-operation
  "Apply a compound operation"
  [manager compound]
  (doseq [op (:operations compound)]
    (apply-operation manager op)))

(defn reverse-compound-operation
  "Reverse a compound operation"
  [compound]
  {:type :compound
   :operations (reverse (map reverse-operation (:operations compound)))
   :timestamp (System/currentTimeMillis)})

;; ============================================================================
;; History Browser (Exercise 3)
;; ============================================================================

(defn get-undo-history
  "Get list of operations in undo stack (non-destructive peek)"
  [manager max-items]
  (let [stack (:stack (:undo-ch manager))
        items (vec stack)]
    (take max-items (reverse items))))

(defn get-redo-history
  "Get list of operations in redo stack"
  [manager max-items]
  (let [stack (:stack (:redo-ch manager))
        items (vec stack)]
    (take max-items (reverse items))))

(defn display-history
  "Display undo/redo history"
  [manager]
  (println "\n=== Undo History ===")
  (let [undo-items (get-undo-history manager 10)]
    (if (empty? undo-items)
      (println "  (empty)")
      (doseq [[idx op] (map-indexed vector undo-items)]
        (println (format "  %d: %s" (inc idx) (operation-str op))))))

  (println "\n=== Redo History ===")
  (let [redo-items (get-redo-history manager 10)]
    (if (empty? redo-items)
      (println "  (empty)")
      (doseq [[idx op] (map-indexed vector redo-items)]
        (println (format "  %d: %s" (inc idx) (operation-str op)))))))

;; ============================================================================
;; Status Display
;; ============================================================================

(defn display-status
  "Display current document and stack status"
  [manager]
  (println "\n=== Document Status ===")
  (println (format "Content: \"%s\"" (get-document manager)))
  (println (format "Length:  %d characters" (count (get-document manager))))
  (println (format "Undo stack: %d operations" (stack-size (:undo-ch manager))))
  (println (format "Redo stack: %d operations" (stack-size (:redo-ch manager)))))

;; ============================================================================
;; Testing
;; ============================================================================

(defn test-undo-system
  "Test undo system functionality"
  []
  (println "\n=== Testing Undo System ===\n")

  (let [manager (create-undo-manager)]
    (try
      ;; Test insert
      (insert! manager 0 "Test")
      (assert (= "Test" (get-document manager)) "Insert failed")
      (println "Insert: PASS")

      ;; Test undo
      (undo! manager)
      (assert (= "" (get-document manager)) "Undo failed")
      (println "Undo: PASS")

      ;; Test redo
      (redo! manager)
      (assert (= "Test" (get-document manager)) "Redo failed")
      (println "Redo: PASS")

      ;; Test multiple operations
      (insert! manager 4 "ing")
      (assert (= "Testing" (get-document manager)))
      (println "Multiple insert: PASS")

      (insert! manager 7 " 123")
      (assert (= "Testing 123" (get-document manager)))

      ;; Multiple undos
      (undo! manager)
      (assert (= "Testing" (get-document manager)))
      (undo! manager)
      (assert (= "Test" (get-document manager)))
      (println "Multiple undo: PASS")

      ;; Multiple redos
      (redo! manager)
      (assert (= "Testing" (get-document manager)))
      (redo! manager)
      (assert (= "Testing 123" (get-document manager)))
      (println "Multiple redo: PASS")

      ;; Test delete
      (delete! manager 7 4)
      (assert (= "Testing" (get-document manager)))
      (println "Delete: PASS")

      (undo! manager)
      (assert (= "Testing 123" (get-document manager)))
      (println "Undo delete: PASS")

      (println "\nAll tests passed!")

      (finally
        (close-undo-manager manager)))))

;; ============================================================================
;; Interactive Demo
;; ============================================================================

(defn demo-undo-system
  "Demonstrate the undo/redo system"
  []
  (println "=== Undo/Redo System Demo ===\n")

  (let [manager (create-undo-manager)]
    (try
      (println "Initial document: (empty)")
      (println)

      ;; Build up some text
      (insert! manager 0 "Hello")
      (println)

      (insert! manager 5 " World")
      (println)

      (insert! manager 11 "!")
      (println)

      (println "\n--- After insertions ---")
      (display-status manager)

      ;; Undo sequence
      (println "\n--- Undo sequence ---")
      (undo! manager)
      (println)
      (undo! manager)
      (println)

      (display-status manager)

      ;; Redo
      (println "\n--- Redo ---")
      (redo! manager)
      (println)

      (display-status manager)

      ;; New operation after undo (clears redo)
      (println "\n--- New operation (clears redo) ---")
      (insert! manager 5 "?")
      (println)

      (display-status manager)

      ;; Show history
      (display-history manager)

      (finally
        (close-undo-manager manager)))))

(defn demo-multi-level-undo
  "Demonstrate multi-level undo"
  []
  (println "\n=== Multi-Level Undo Demo ===\n")

  (let [manager (create-undo-manager)]
    (try
      ;; Create many operations
      (insert! manager 0 "A")
      (insert! manager 1 "B")
      (insert! manager 2 "C")
      (insert! manager 3 "D")
      (insert! manager 4 "E")

      (println (format "\nDocument: \"%s\"" (get-document manager)))

      ;; Undo 3 at once
      (println "\n--- Undo 3 operations ---")
      (undo-n! manager 3)

      (println (format "Document: \"%s\"" (get-document manager)))

      ;; Redo 2
      (println "\n--- Redo 2 operations ---")
      (redo-n! manager 2)

      (println (format "Document: \"%s\"" (get-document manager)))

      (finally
        (close-undo-manager manager)))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run the undo/redo system lab"
  [& args]
  (let [command (first args)]
    (case command
      "test"
      (test-undo-system)

      "demo"
      (demo-undo-system)

      "multi"
      (demo-multi-level-undo)

      ;; Default: full demo
      (do
        (println "Lab 15.3: Undo/Redo System with Stack Channels")
        (println "===============================================")
        (println "\nUsage:")
        (println "  test   - Run unit tests")
        (println "  demo   - Run interactive demo")
        (println "  multi  - Demo multi-level undo")
        (println)

        (test-undo-system)
        (demo-undo-system)
        (demo-multi-level-undo)

        (println "\n=== Key Takeaways ===")
        (println "1. Stack channels provide LIFO semantics")
        (println "2. conj! pushes, deref pops from stack")
        (println "3. Two stacks (undo/redo) work together")
        (println "4. Operations know how to reverse themselves")
        (println "5. New operations invalidate redo history")))))

;; Run with: clj -M -m lab-15-3-undo-system
;; Or:       clj -M -m lab-15-3-undo-system demo
