(ns lab-19-1-span-management
  "Lab 19.1: Span Management for Distributed Tracing

   Implements span creation and management for distributed traces."
  (:require [clojure.string :as str])
  (:import [java.util UUID]))

;;; ============================================================================
;;; Part 1: ID Generation
;;; ============================================================================

(defn generate-trace-id
  "Generate a 128-bit trace ID as hex string"
  []
  (let [uuid (UUID/randomUUID)]
    (format "%016x%016x"
            (.getMostSignificantBits uuid)
            (.getLeastSignificantBits uuid))))

(defn generate-span-id
  "Generate a 64-bit span ID as hex string"
  []
  (format "%016x" (.getMostSignificantBits (UUID/randomUUID))))

;;; ============================================================================
;;; Part 2: Span Data Structure
;;; ============================================================================

(defrecord Span
  [trace-id
   span-id
   parent-span-id
   operation-name
   service-name
   start-time-ns
   end-time-ns
   duration-ns
   status           ; :ok, :error
   tags             ; map of string->string
   logs])           ; vector of {:timestamp :message}

(defn create-span
  "Create a new span"
  [operation-name service-name & {:keys [trace-id parent-span-id]
                                   :or {trace-id (generate-trace-id)
                                        parent-span-id nil}}]
  (->Span
    trace-id
    (generate-span-id)
    parent-span-id
    operation-name
    service-name
    (System/nanoTime)
    nil
    nil
    :ok
    {}
    []))

(defn finish-span
  "Finish a span and calculate duration"
  [span]
  (let [end-time (System/nanoTime)
        duration (- end-time (:start-time-ns span))]
    (assoc span
           :end-time-ns end-time
           :duration-ns duration)))

(defn set-status
  "Set span status"
  [span status]
  (assoc span :status status))

(defn set-tag
  "Add a tag to the span"
  [span key value]
  (update span :tags assoc key value))

(defn add-log
  "Add a log entry to the span"
  [span message]
  (update span :logs conj {:timestamp (System/nanoTime)
                           :message message}))

;;; ============================================================================
;;; Part 3: Span Store
;;; ============================================================================

(def span-store
  "Store for completed spans"
  (atom []))

(def active-spans
  "Currently active spans by span-id"
  (atom {}))

(defn start-span!
  "Start a new span and register it as active"
  [operation-name service-name & opts]
  (let [span (apply create-span operation-name service-name opts)]
    (swap! active-spans assoc (:span-id span) span)
    span))

(defn finish-span!
  "Finish a span and move to completed store"
  [span-id]
  (when-let [span (get @active-spans span-id)]
    (let [finished (finish-span span)]
      (swap! active-spans dissoc span-id)
      (swap! span-store conj finished)
      finished)))

(defn get-active-span
  "Get an active span by ID"
  [span-id]
  (get @active-spans span-id))

(defn get-completed-spans
  "Get all completed spans"
  []
  @span-store)

(defn get-spans-by-trace
  "Get all completed spans for a trace"
  [trace-id]
  (filter #(= trace-id (:trace-id %)) @span-store))

(defn clear-spans!
  "Clear all spans"
  []
  (reset! span-store [])
  (reset! active-spans {}))

;;; ============================================================================
;;; Part 4: Span Hierarchy
;;; ============================================================================

(defn create-child-span
  "Create a child span from a parent"
  [parent-span operation-name service-name]
  (create-span operation-name service-name
               :trace-id (:trace-id parent-span)
               :parent-span-id (:span-id parent-span)))

(defn get-root-spans
  "Get root spans (no parent) for a trace"
  [trace-id]
  (filter #(and (= trace-id (:trace-id %))
                (nil? (:parent-span-id %)))
          @span-store))

(defn get-child-spans
  "Get child spans for a parent"
  [parent-span-id]
  (filter #(= parent-span-id (:parent-span-id %)) @span-store))

(defn build-span-tree
  "Build a tree structure from spans"
  [trace-id]
  (let [spans (get-spans-by-trace trace-id)
        root-spans (filter #(nil? (:parent-span-id %)) spans)]
    (letfn [(build-subtree [span]
              {:span span
               :children (map build-subtree
                              (filter #(= (:span-id span) (:parent-span-id %))
                                      spans))})]
      (map build-subtree root-spans))))

;;; ============================================================================
;;; Part 5: Span Statistics
;;; ============================================================================

(defn span-duration-ms
  "Get span duration in milliseconds"
  [span]
  (when (:duration-ns span)
    (/ (:duration-ns span) 1000000.0)))

(defn trace-duration-ms
  "Get total trace duration (root span duration)"
  [trace-id]
  (when-let [root (first (get-root-spans trace-id))]
    (span-duration-ms root)))

(defn span-statistics
  "Calculate statistics for spans"
  [spans]
  (let [durations (keep :duration-ns spans)]
    (when (seq durations)
      {:count (count durations)
       :total-ns (reduce + durations)
       :min-ns (apply min durations)
       :max-ns (apply max durations)
       :avg-ns (/ (reduce + durations) (count durations))})))

(defn service-statistics
  "Calculate per-service statistics"
  []
  (let [by-service (group-by :service-name @span-store)]
    (into {}
          (map (fn [[service spans]]
                 [service (span-statistics spans)])
               by-service))))

;;; ============================================================================
;;; Part 6: Span Formatting
;;; ============================================================================

(defn format-span
  "Format span for display"
  [span]
  (format "%s [%s] %s (%.2fms) %s"
          (:service-name span)
          (:span-id span)
          (:operation-name span)
          (or (span-duration-ms span) 0.0)
          (name (:status span))))

(defn print-trace-tree
  "Print trace as a tree"
  [trace-id]
  (let [tree (build-span-tree trace-id)]
    (letfn [(print-node [node indent]
              (println (str (apply str (repeat indent "  "))
                           "└─ "
                           (format-span (:span node))))
              (doseq [child (:children node)]
                (print-node child (inc indent))))]
      (doseq [root tree]
        (print-node root 0)))))

;;; ============================================================================
;;; Part 7: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 19.1 Tests ===\n")

  ;; Test 1: ID generation
  (println "Test 1: ID Generation")
  (let [trace-id (generate-trace-id)
        span-id (generate-span-id)]
    (assert (= 32 (count trace-id)) "trace ID is 32 hex chars")
    (assert (= 16 (count span-id)) "span ID is 16 hex chars")
    (assert (not= trace-id (generate-trace-id)) "unique trace IDs"))
  (println "  ID generation works correctly")
  (println "  PASSED\n")

  ;; Test 2: Span creation
  (println "Test 2: Span Creation")
  (let [span (create-span "GET /users" "api-service")]
    (assert (some? (:trace-id span)) "has trace ID")
    (assert (some? (:span-id span)) "has span ID")
    (assert (nil? (:parent-span-id span)) "no parent")
    (assert (= "GET /users" (:operation-name span)) "operation set")
    (assert (= "api-service" (:service-name span)) "service set")
    (assert (some? (:start-time-ns span)) "start time set"))
  (println "  Span creation works correctly")
  (println "  PASSED\n")

  ;; Test 3: Span finishing
  (println "Test 3: Span Finishing")
  (let [span (create-span "test-op" "test-service")
        _ (Thread/sleep 10)
        finished (finish-span span)]
    (assert (some? (:end-time-ns finished)) "end time set")
    (assert (some? (:duration-ns finished)) "duration calculated")
    (assert (> (:duration-ns finished) 0) "duration > 0"))
  (println "  Span finishing works correctly")
  (println "  PASSED\n")

  ;; Test 4: Tags and logs
  (println "Test 4: Tags and Logs")
  (let [span (-> (create-span "test-op" "test-service")
                 (set-tag "http.method" "GET")
                 (set-tag "http.status" "200")
                 (add-log "Request received")
                 (add-log "Processing complete"))]
    (assert (= "GET" (get-in span [:tags "http.method"])) "tag set")
    (assert (= 2 (count (:logs span))) "two logs"))
  (println "  Tags and logs work correctly")
  (println "  PASSED\n")

  ;; Test 5: Span store
  (println "Test 5: Span Store")
  (clear-spans!)
  (let [span1 (start-span! "op1" "svc1")
        span2 (start-span! "op2" "svc2")]
    (assert (= 2 (count @active-spans)) "two active spans")
    (finish-span! (:span-id span1))
    (assert (= 1 (count @active-spans)) "one active span")
    (assert (= 1 (count @span-store)) "one completed span")
    (finish-span! (:span-id span2))
    (assert (= 0 (count @active-spans)) "no active spans")
    (assert (= 2 (count @span-store)) "two completed spans"))
  (println "  Span store works correctly")
  (println "  PASSED\n")

  ;; Test 6: Child spans
  (println "Test 6: Child Spans")
  (clear-spans!)
  (let [parent (create-span "parent-op" "parent-svc")
        child (create-child-span parent "child-op" "child-svc")]
    (assert (= (:trace-id parent) (:trace-id child)) "same trace ID")
    (assert (= (:span-id parent) (:parent-span-id child)) "parent linked"))
  (println "  Child spans work correctly")
  (println "  PASSED\n")

  ;; Test 7: Span tree
  (println "Test 7: Span Tree")
  (clear-spans!)
  (let [root (start-span! "root" "svc-a")
        child1 (start-span! "child1" "svc-b"
                            :trace-id (:trace-id root)
                            :parent-span-id (:span-id root))
        child2 (start-span! "child2" "svc-c"
                            :trace-id (:trace-id root)
                            :parent-span-id (:span-id root))
        grandchild (start-span! "grandchild" "svc-d"
                                :trace-id (:trace-id root)
                                :parent-span-id (:span-id child1))]
    (finish-span! (:span-id grandchild))
    (finish-span! (:span-id child1))
    (finish-span! (:span-id child2))
    (finish-span! (:span-id root))
    (let [tree (build-span-tree (:trace-id root))]
      (assert (= 1 (count tree)) "one root")
      (assert (= 2 (count (:children (first tree)))) "two children")))
  (println "  Span tree works correctly")
  (println "  PASSED\n")

  ;; Test 8: Statistics
  (println "Test 8: Statistics")
  (clear-spans!)
  (dotimes [i 5]
    (let [span (start-span! (str "op-" i) "test-service")]
      (Thread/sleep 5)
      (finish-span! (:span-id span))))
  (let [stats (span-statistics @span-store)]
    (assert (= 5 (:count stats)) "five spans")
    (assert (> (:avg-ns stats) 0) "positive avg"))
  (println "  Statistics work correctly")
  (println "  PASSED\n")

  ;; Test 9: Status handling
  (println "Test 9: Status Handling")
  (let [span (-> (create-span "test-op" "test-service")
                 (set-status :error))]
    (assert (= :error (:status span)) "status set to error"))
  (println "  Status handling works correctly")
  (println "  PASSED\n")

  ;; Test 10: Service statistics
  (println "Test 10: Service Statistics")
  (clear-spans!)
  (doseq [svc ["svc-a" "svc-a" "svc-b"]]
    (let [span (start-span! "op" svc)]
      (Thread/sleep 5)
      (finish-span! (:span-id span))))
  (let [stats (service-statistics)]
    (assert (= 2 (:count (get stats "svc-a"))) "two svc-a spans")
    (assert (= 1 (:count (get stats "svc-b"))) "one svc-b span"))
  (println "  Service statistics work correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 8: Demo
;;; ============================================================================

(defn demo
  "Demonstrate span management"
  []
  (println "\n=== Span Management Demo ===\n")
  (clear-spans!)

  ;; Simulate a distributed trace
  (let [root (start-span! "GET /orders" "api-gateway")]
    (Thread/sleep 10)

    ;; Auth service call
    (let [auth (start-span! "validateToken" "auth-service"
                            :trace-id (:trace-id root)
                            :parent-span-id (:span-id root))]
      (Thread/sleep 5)
      (finish-span! (:span-id auth)))

    ;; Order service call
    (let [order (start-span! "getOrders" "order-service"
                             :trace-id (:trace-id root)
                             :parent-span-id (:span-id root))]
      (Thread/sleep 15)

      ;; Database call
      (let [db (start-span! "SELECT orders" "mysql"
                            :trace-id (:trace-id root)
                            :parent-span-id (:span-id order))]
        (Thread/sleep 10)
        (finish-span! (:span-id db)))

      (finish-span! (:span-id order)))

    (finish-span! (:span-id root))

    ;; Display trace
    (println "Trace Tree:")
    (print-trace-tree (:trace-id root))

    (println "\nService Statistics:")
    (doseq [[svc stats] (service-statistics)]
      (println (format "  %s: %d calls, avg %.2fms"
                       svc
                       (:count stats)
                       (/ (:avg-ns stats) 1000000.0))))))

;;; ============================================================================
;;; Part 9: Main
;;; ============================================================================

(defn -main
  [& args]
  (case (first args)
    "test" (run-tests)
    "demo" (demo)
    (do
      (println "Usage: clojure -M -m lab-19-1-span-management [test|demo]")
      (System/exit 1))))
