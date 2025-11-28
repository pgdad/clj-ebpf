(ns lab-20-1-query-capture
  "Lab 20.1: Query Capture and Parsing

   Implements query capture, parsing, and normalization."
  (:require [clojure.string :as str]))

;;; ============================================================================
;;; Part 1: Query Data Structure
;;; ============================================================================

(defrecord QueryEvent
  [query-id
   timestamp-ns
   pid
   tid
   db-type        ; :mysql, :postgres, :sqlite
   query-type     ; :select, :insert, :update, :delete, :other
   raw-query
   normalized-query
   tables
   duration-ns])

(defn generate-query-id
  "Generate unique query ID"
  []
  (str (java.util.UUID/randomUUID)))

;;; ============================================================================
;;; Part 2: Query Type Detection
;;; ============================================================================

(defn detect-query-type
  "Detect SQL query type"
  [query]
  (let [trimmed (str/trim (str/upper-case query))]
    (cond
      (str/starts-with? trimmed "SELECT") :select
      (str/starts-with? trimmed "INSERT") :insert
      (str/starts-with? trimmed "UPDATE") :update
      (str/starts-with? trimmed "DELETE") :delete
      (str/starts-with? trimmed "CREATE") :create
      (str/starts-with? trimmed "DROP") :drop
      (str/starts-with? trimmed "ALTER") :alter
      :else :other)))

;;; ============================================================================
;;; Part 3: Query Normalization
;;; ============================================================================

(defn normalize-numbers
  "Replace numeric literals with ?"
  [query]
  (str/replace query #"\b\d+\b" "?"))

(defn normalize-strings
  "Replace string literals with ?"
  [query]
  (-> query
      (str/replace #"'[^']*'" "?")
      (str/replace #"\"[^\"]*\"" "?")))

(defn normalize-in-clauses
  "Normalize IN clauses"
  [query]
  (str/replace query #"IN\s*\([^)]+\)" "IN (?)"))

(defn normalize-query
  "Normalize query by replacing literals with placeholders"
  [query]
  (-> query
      str/trim
      normalize-strings
      normalize-numbers
      normalize-in-clauses
      (str/replace #"\s+" " ")))

(defn query-hash
  "Generate hash for normalized query"
  [normalized-query]
  (hash normalized-query))

;;; ============================================================================
;;; Part 4: Table Extraction
;;; ============================================================================

(defn extract-tables-from-select
  "Extract tables from SELECT query"
  [query]
  (let [upper (str/upper-case query)
        ;; Extract FROM clause
        from-match (re-find #"FROM\s+([^\s,]+(?:\s*,\s*[^\s,]+)*)" upper)
        ;; Extract JOIN tables
        join-matches (re-seq #"JOIN\s+([^\s]+)" upper)]
    (concat
     (when from-match
       (map str/trim (str/split (second from-match) #",")))
     (map second join-matches))))

(defn extract-tables-from-insert
  "Extract table from INSERT query"
  [query]
  (let [upper (str/upper-case query)
        match (re-find #"INSERT\s+INTO\s+([^\s(]+)" upper)]
    (when match [(second match)])))

(defn extract-tables-from-update
  "Extract table from UPDATE query"
  [query]
  (let [upper (str/upper-case query)
        match (re-find #"UPDATE\s+([^\s]+)" upper)]
    (when match [(second match)])))

(defn extract-tables-from-delete
  "Extract table from DELETE query"
  [query]
  (let [upper (str/upper-case query)
        match (re-find #"DELETE\s+FROM\s+([^\s]+)" upper)]
    (when match [(second match)])))

(defn extract-tables
  "Extract all tables referenced in query"
  [query]
  (let [query-type (detect-query-type query)]
    (vec (distinct
          (case query-type
            :select (extract-tables-from-select query)
            :insert (extract-tables-from-insert query)
            :update (extract-tables-from-update query)
            :delete (extract-tables-from-delete query)
            [])))))

;;; ============================================================================
;;; Part 5: Query Event Creation
;;; ============================================================================

(defn create-query-event
  "Create a query event from raw query"
  [raw-query db-type pid tid]
  (let [normalized (normalize-query raw-query)
        query-type (detect-query-type raw-query)
        tables (extract-tables raw-query)]
    (->QueryEvent
     (generate-query-id)
     (System/nanoTime)
     pid
     tid
     db-type
     query-type
     raw-query
     normalized
     tables
     nil)))

(defn finish-query-event
  "Finish query event with duration"
  [event duration-ns]
  (assoc event :duration-ns duration-ns))

;;; ============================================================================
;;; Part 6: Query Store
;;; ============================================================================

(def query-store
  "Store for captured queries"
  (atom []))

(defn record-query!
  "Record a query event"
  [event]
  (swap! query-store conj event)
  event)

(defn get-queries
  "Get all recorded queries"
  []
  @query-store)

(defn get-queries-by-type
  "Get queries filtered by type"
  [query-type]
  (filter #(= query-type (:query-type %)) @query-store))

(defn get-queries-by-table
  "Get queries that reference a table"
  [table]
  (let [upper-table (str/upper-case table)]
    (filter #(some (fn [t] (= upper-table (str/upper-case t))) (:tables %))
            @query-store)))

(defn clear-queries!
  "Clear all recorded queries"
  []
  (reset! query-store []))

;;; ============================================================================
;;; Part 7: Query Grouping
;;; ============================================================================

(defn group-by-normalized
  "Group queries by normalized form"
  []
  (group-by :normalized-query @query-store))

(defn unique-queries
  "Get count of unique normalized queries"
  []
  (count (distinct (map :normalized-query @query-store))))

(defn query-frequency
  "Get frequency of each normalized query"
  []
  (->> @query-store
       (group-by :normalized-query)
       (map (fn [[q events]] {:query q :count (count events)}))
       (sort-by :count >)))

;;; ============================================================================
;;; Part 8: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 20.1 Tests ===\n")

  ;; Test 1: Query type detection
  (println "Test 1: Query Type Detection")
  (assert (= :select (detect-query-type "SELECT * FROM users")) "select detected")
  (assert (= :insert (detect-query-type "INSERT INTO users VALUES (1)")) "insert detected")
  (assert (= :update (detect-query-type "UPDATE users SET name='x'")) "update detected")
  (assert (= :delete (detect-query-type "DELETE FROM users")) "delete detected")
  (println "  Query type detection works correctly")
  (println "  PASSED\n")

  ;; Test 2: Query normalization - numbers
  (println "Test 2: Number Normalization")
  (let [normalized (normalize-numbers "SELECT * FROM users WHERE id = 123")]
    (assert (str/includes? normalized "?") "number replaced")
    (assert (not (str/includes? normalized "123")) "original removed"))
  (println "  Number normalization works correctly")
  (println "  PASSED\n")

  ;; Test 3: Query normalization - strings
  (println "Test 3: String Normalization")
  (let [normalized (normalize-strings "SELECT * FROM users WHERE name = 'John'")]
    (assert (str/includes? normalized "?") "string replaced")
    (assert (not (str/includes? normalized "John")) "original removed"))
  (println "  String normalization works correctly")
  (println "  PASSED\n")

  ;; Test 4: Full normalization
  (println "Test 4: Full Normalization")
  (let [q1 "SELECT * FROM users WHERE id = 123 AND name = 'John'"
        q2 "SELECT * FROM users WHERE id = 456 AND name = 'Jane'"
        n1 (normalize-query q1)
        n2 (normalize-query q2)]
    (assert (= n1 n2) "different literals normalize to same query"))
  (println "  Full normalization works correctly")
  (println "  PASSED\n")

  ;; Test 5: Table extraction - SELECT
  (println "Test 5: Table Extraction (SELECT)")
  (let [tables (extract-tables "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id")]
    (assert (some #(str/includes? (str/upper-case %) "USERS") tables) "users found")
    (assert (some #(str/includes? (str/upper-case %) "ORDERS") tables) "orders found"))
  (println "  Table extraction (SELECT) works correctly")
  (println "  PASSED\n")

  ;; Test 6: Table extraction - INSERT/UPDATE/DELETE
  (println "Test 6: Table Extraction (DML)")
  (assert (= ["USERS"] (extract-tables "INSERT INTO users VALUES (1, 'John')")) "insert table")
  (assert (= ["USERS"] (extract-tables "UPDATE users SET name = 'Jane'")) "update table")
  (assert (= ["USERS"] (extract-tables "DELETE FROM users WHERE id = 1")) "delete table")
  (println "  Table extraction (DML) works correctly")
  (println "  PASSED\n")

  ;; Test 7: Query event creation
  (println "Test 7: Query Event Creation")
  (let [event (create-query-event "SELECT * FROM users WHERE id = 1" :mysql 1234 5678)]
    (assert (some? (:query-id event)) "has query ID")
    (assert (= :select (:query-type event)) "correct type")
    (assert (= :mysql (:db-type event)) "correct db type")
    (assert (= 1234 (:pid event)) "correct pid"))
  (println "  Query event creation works correctly")
  (println "  PASSED\n")

  ;; Test 8: Query store
  (println "Test 8: Query Store")
  (clear-queries!)
  (record-query! (create-query-event "SELECT * FROM users" :mysql 1 1))
  (record-query! (create-query-event "INSERT INTO orders VALUES (1)" :mysql 1 1))
  (assert (= 2 (count (get-queries))) "two queries recorded")
  (assert (= 1 (count (get-queries-by-type :select))) "one select")
  (assert (= 1 (count (get-queries-by-type :insert))) "one insert")
  (println "  Query store works correctly")
  (println "  PASSED\n")

  ;; Test 9: Query grouping
  (println "Test 9: Query Grouping")
  (clear-queries!)
  (dotimes [i 3]
    (record-query! (create-query-event (str "SELECT * FROM users WHERE id = " i) :mysql 1 1)))
  (record-query! (create-query-event "SELECT * FROM orders" :mysql 1 1))
  (assert (= 2 (unique-queries)) "two unique queries")
  (let [freq (query-frequency)]
    (assert (= 3 (:count (first freq))) "most frequent has 3"))
  (println "  Query grouping works correctly")
  (println "  PASSED\n")

  ;; Test 10: IN clause normalization
  (println "Test 10: IN Clause Normalization")
  (let [q1 "SELECT * FROM users WHERE id IN (1, 2, 3)"
        q2 "SELECT * FROM users WHERE id IN (4, 5, 6, 7, 8)"
        n1 (normalize-query q1)
        n2 (normalize-query q2)]
    (assert (= n1 n2) "IN clauses normalize to same query"))
  (println "  IN clause normalization works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 9: Demo
;;; ============================================================================

(defn demo
  "Demonstrate query capture"
  []
  (println "\n=== Query Capture Demo ===\n")
  (clear-queries!)

  ;; Simulate captured queries
  (let [queries ["SELECT * FROM users WHERE id = 1"
                 "SELECT * FROM users WHERE id = 2"
                 "SELECT * FROM users WHERE id = 3"
                 "SELECT u.*, o.* FROM users u JOIN orders o ON u.id = o.user_id WHERE u.id = 1"
                 "INSERT INTO audit_log VALUES (1, 'login', '2024-01-01')"
                 "UPDATE users SET last_login = '2024-01-01' WHERE id = 1"
                 "DELETE FROM sessions WHERE expires < '2024-01-01'"]]

    (doseq [q queries]
      (let [event (create-query-event q :mysql 1234 5678)]
        (record-query! event)))

    (println "Captured Queries:")
    (doseq [[i event] (map-indexed vector (get-queries))]
      (println (format "  %d. [%s] %s"
                       (inc i)
                       (name (:query-type event))
                       (:raw-query event))))

    (println "\nQuery Frequency:")
    (doseq [{:keys [query count]} (take 5 (query-frequency))]
      (println (format "  %dx: %s" count query)))

    (println "\nTables Referenced:")
    (doseq [[table queries] (group-by #(first (:tables %)) (get-queries))]
      (println (format "  %s: %d queries" table (count queries))))))

;;; ============================================================================
;;; Part 10: Main
;;; ============================================================================

(defn -main
  [& args]
  (case (first args)
    "test" (run-tests)
    "demo" (demo)
    (do
      (println "Usage: clojure -M -m lab-20-1-query-capture [test|demo]")
      (System/exit 1))))
