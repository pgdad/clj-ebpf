(ns lab-21-1-audit-logging
  "Lab 21.1: Audit Event Logging

   Implements security audit event capture and logging."
  (:require [clojure.string :as str])
  (:import [java.security MessageDigest]
           [java.util UUID]))

;;; ============================================================================
;;; Part 1: Audit Event Structure
;;; ============================================================================

(def severity-levels
  "Severity levels for audit events"
  {:debug 0
   :info 1
   :warning 2
   :high 3
   :critical 4})

(def event-types
  "Types of audit events"
  #{:file-access :file-modify :file-delete
    :process-exec :process-kill
    :auth-success :auth-failure
    :privilege-escalation
    :network-connect :network-listen
    :config-change :policy-violation})

(defrecord AuditEvent
  [event-id
   timestamp
   event-type
   severity
   user-id
   process-id
   process-name
   success
   resource
   details
   hash])         ; Hash of event for tamper detection

;;; ============================================================================
;;; Part 2: Event ID and Hashing
;;; ============================================================================

(defn generate-event-id
  "Generate unique event ID"
  []
  (str (UUID/randomUUID)))

(defn sha256
  "Calculate SHA-256 hash of string"
  [s]
  (let [digest (MessageDigest/getInstance "SHA-256")
        hash-bytes (.digest digest (.getBytes s "UTF-8"))]
    (apply str (map #(format "%02x" %) hash-bytes))))

(defn calculate-event-hash
  "Calculate hash for event (excluding hash field)"
  [event]
  (sha256 (str (:event-id event)
               (:timestamp event)
               (:event-type event)
               (:user-id event)
               (:process-id event)
               (:resource event)
               (:details event))))

;;; ============================================================================
;;; Part 3: Event Creation
;;; ============================================================================

(defn create-audit-event
  "Create a new audit event"
  [event-type severity & {:keys [user-id process-id process-name
                                  success resource details]
                           :or {success true
                                resource ""
                                details ""}}]
  (let [event (->AuditEvent
               (generate-event-id)
               (System/currentTimeMillis)
               event-type
               severity
               user-id
               process-id
               process-name
               success
               resource
               details
               nil)]
    (assoc event :hash (calculate-event-hash event))))

(defn verify-event-integrity
  "Verify event has not been tampered with"
  [event]
  (= (:hash event) (calculate-event-hash event)))

;;; ============================================================================
;;; Part 4: Audit Log Store
;;; ============================================================================

(def audit-log
  "Tamper-evident audit log"
  (atom []))

(def previous-hash
  "Hash of previous event for chain integrity"
  (atom nil))

(defn chain-hash
  "Calculate chain hash including previous hash"
  [event prev-hash]
  (sha256 (str (:hash event) (or prev-hash "genesis"))))

(defn log-event!
  "Log an audit event to the store"
  [event]
  (let [chained (assoc event :chain-hash (chain-hash event @previous-hash))]
    (swap! audit-log conj chained)
    (reset! previous-hash (:chain-hash chained))
    chained))

(defn get-audit-log
  "Get all audit log entries"
  []
  @audit-log)

(defn verify-chain-integrity
  "Verify the entire audit log chain hasn't been tampered with"
  []
  (loop [events @audit-log
         prev-hash nil]
    (if (empty? events)
      true
      (let [event (first events)
            expected-chain (chain-hash event prev-hash)]
        (if (= expected-chain (:chain-hash event))
          (recur (rest events) (:chain-hash event))
          false)))))

(defn clear-audit-log!
  "Clear the audit log (for testing)"
  []
  (reset! audit-log [])
  (reset! previous-hash nil))

;;; ============================================================================
;;; Part 5: Event Filtering and Querying
;;; ============================================================================

(defn filter-by-severity
  "Get events at or above severity level"
  [min-severity]
  (let [min-level (get severity-levels min-severity 0)]
    (filter #(>= (get severity-levels (:severity %) 0) min-level)
            @audit-log)))

(defn filter-by-type
  "Get events of specific type"
  [event-type]
  (filter #(= event-type (:event-type %)) @audit-log))

(defn filter-by-user
  "Get events for specific user"
  [user-id]
  (filter #(= user-id (:user-id %)) @audit-log))

(defn filter-by-time-range
  "Get events within time range"
  [start-ms end-ms]
  (filter #(and (>= (:timestamp %) start-ms)
                (<= (:timestamp %) end-ms))
          @audit-log))

(defn filter-failures
  "Get all failed events"
  []
  (filter #(not (:success %)) @audit-log))

;;; ============================================================================
;;; Part 6: Audit Statistics
;;; ============================================================================

(defn event-count-by-type
  "Count events by type"
  []
  (frequencies (map :event-type @audit-log)))

(defn event-count-by-severity
  "Count events by severity"
  []
  (frequencies (map :severity @audit-log)))

(defn failure-rate
  "Calculate failure rate"
  []
  (let [total (count @audit-log)
        failures (count (filter-failures))]
    (if (zero? total)
      0.0
      (* 100.0 (/ failures total)))))

(defn events-per-user
  "Count events per user"
  []
  (frequencies (map :user-id @audit-log)))

(defn top-resources
  "Get most accessed resources"
  [n]
  (->> @audit-log
       (map :resource)
       (filter (complement str/blank?))
       frequencies
       (sort-by val >)
       (take n)))

;;; ============================================================================
;;; Part 7: Event Formatting
;;; ============================================================================

(defn format-timestamp
  "Format timestamp for display"
  [ms]
  (let [sdf (java.text.SimpleDateFormat. "yyyy-MM-dd HH:mm:ss.SSS")]
    (.format sdf (java.util.Date. ms))))

(defn format-event
  "Format event for display"
  [event]
  (format "[%s] [%s] [%s] user=%s pid=%s resource=%s %s"
          (format-timestamp (:timestamp event))
          (str/upper-case (name (:severity event)))
          (name (:event-type event))
          (or (:user-id event) "-")
          (or (:process-id event) "-")
          (or (:resource event) "-")
          (if (:success event) "OK" "FAILED")))

(defn print-audit-log
  "Print the audit log"
  []
  (doseq [event @audit-log]
    (println (format-event event))))

;;; ============================================================================
;;; Part 8: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 21.1 Tests ===\n")

  ;; Test 1: Event creation
  (println "Test 1: Event Creation")
  (let [event (create-audit-event :file-access :info
                                  :user-id 1000
                                  :process-id 1234
                                  :resource "/etc/passwd")]
    (assert (some? (:event-id event)) "has event ID")
    (assert (some? (:timestamp event)) "has timestamp")
    (assert (= :file-access (:event-type event)) "correct type")
    (assert (= :info (:severity event)) "correct severity")
    (assert (some? (:hash event)) "has hash"))
  (println "  Event creation works correctly")
  (println "  PASSED\n")

  ;; Test 2: Event integrity
  (println "Test 2: Event Integrity")
  (let [event (create-audit-event :auth-failure :warning :user-id 1000)]
    (assert (verify-event-integrity event) "original event valid")
    (assert (not (verify-event-integrity (assoc event :user-id 9999))) "tampered event invalid"))
  (println "  Event integrity works correctly")
  (println "  PASSED\n")

  ;; Test 3: Audit log
  (println "Test 3: Audit Log")
  (clear-audit-log!)
  (log-event! (create-audit-event :file-access :info))
  (log-event! (create-audit-event :auth-success :info))
  (assert (= 2 (count (get-audit-log))) "two events logged")
  (println "  Audit log works correctly")
  (println "  PASSED\n")

  ;; Test 4: Chain integrity
  (println "Test 4: Chain Integrity")
  (clear-audit-log!)
  (dotimes [_ 5]
    (log-event! (create-audit-event :file-access :info)))
  (assert (verify-chain-integrity) "chain is valid")
  ;; Tamper with middle event's chain-hash (breaks the chain)
  (swap! audit-log assoc-in [2 :chain-hash] "TAMPERED_HASH")
  (assert (not (verify-chain-integrity)) "tampering detected")
  (println "  Chain integrity works correctly")
  (println "  PASSED\n")

  ;; Test 5: Severity filtering
  (println "Test 5: Severity Filtering")
  (clear-audit-log!)
  (log-event! (create-audit-event :file-access :debug))
  (log-event! (create-audit-event :file-access :info))
  (log-event! (create-audit-event :auth-failure :warning))
  (log-event! (create-audit-event :privilege-escalation :critical))
  (assert (= 4 (count (filter-by-severity :debug))) "all events >= debug")
  (assert (= 2 (count (filter-by-severity :warning))) "two events >= warning")
  (assert (= 1 (count (filter-by-severity :critical))) "one critical event")
  (println "  Severity filtering works correctly")
  (println "  PASSED\n")

  ;; Test 6: Type filtering
  (println "Test 6: Type Filtering")
  (clear-audit-log!)
  (log-event! (create-audit-event :file-access :info))
  (log-event! (create-audit-event :file-access :info))
  (log-event! (create-audit-event :auth-success :info))
  (assert (= 2 (count (filter-by-type :file-access))) "two file-access")
  (assert (= 1 (count (filter-by-type :auth-success))) "one auth-success")
  (println "  Type filtering works correctly")
  (println "  PASSED\n")

  ;; Test 7: User filtering
  (println "Test 7: User Filtering")
  (clear-audit-log!)
  (log-event! (create-audit-event :file-access :info :user-id 1000))
  (log-event! (create-audit-event :file-access :info :user-id 1000))
  (log-event! (create-audit-event :file-access :info :user-id 2000))
  (assert (= 2 (count (filter-by-user 1000))) "two for user 1000")
  (assert (= 1 (count (filter-by-user 2000))) "one for user 2000")
  (println "  User filtering works correctly")
  (println "  PASSED\n")

  ;; Test 8: Failure filtering
  (println "Test 8: Failure Filtering")
  (clear-audit-log!)
  (log-event! (create-audit-event :auth-success :info :success true))
  (log-event! (create-audit-event :auth-failure :warning :success false))
  (log-event! (create-audit-event :auth-failure :warning :success false))
  (assert (= 2 (count (filter-failures))) "two failures")
  (println "  Failure filtering works correctly")
  (println "  PASSED\n")

  ;; Test 9: Statistics
  (println "Test 9: Statistics")
  (clear-audit-log!)
  (log-event! (create-audit-event :file-access :info :success true))
  (log-event! (create-audit-event :auth-failure :warning :success false))
  (let [by-type (event-count-by-type)
        by-sev (event-count-by-severity)]
    (assert (= 1 (get by-type :file-access)) "one file-access")
    (assert (= 1 (get by-sev :info)) "one info")
    (assert (= 50.0 (failure-rate)) "50% failure rate"))
  (println "  Statistics work correctly")
  (println "  PASSED\n")

  ;; Test 10: Top resources
  (println "Test 10: Top Resources")
  (clear-audit-log!)
  (dotimes [_ 5]
    (log-event! (create-audit-event :file-access :info :resource "/etc/passwd")))
  (dotimes [_ 3]
    (log-event! (create-audit-event :file-access :info :resource "/etc/shadow")))
  (let [top (top-resources 2)]
    (assert (= "/etc/passwd" (first (first top))) "passwd most accessed")
    (assert (= 5 (second (first top))) "accessed 5 times"))
  (println "  Top resources works correctly")
  (println "  PASSED\n")

  (println "=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 9: Demo
;;; ============================================================================

(defn demo
  "Demonstrate audit logging"
  []
  (println "\n=== Audit Logging Demo ===\n")
  (clear-audit-log!)

  ;; Simulate audit events
  (log-event! (create-audit-event :auth-success :info
                                  :user-id 1000
                                  :process-name "sshd"
                                  :resource "192.168.1.100"))
  (log-event! (create-audit-event :file-access :info
                                  :user-id 1000
                                  :process-id 5678
                                  :resource "/home/user/.ssh/config"))
  (log-event! (create-audit-event :privilege-escalation :high
                                  :user-id 1000
                                  :process-name "sudo"
                                  :details "sudo su -"))
  (log-event! (create-audit-event :file-modify :warning
                                  :user-id 0
                                  :process-name "vim"
                                  :resource "/etc/passwd"))
  (log-event! (create-audit-event :auth-failure :warning
                                  :user-id 1001
                                  :success false
                                  :resource "192.168.1.200"
                                  :details "Invalid password"))

  (println "Audit Log:")
  (print-audit-log)

  (println "\nStatistics:")
  (println (format "  Total events: %d" (count (get-audit-log))))
  (println (format "  High severity+: %d" (count (filter-by-severity :high))))
  (println (format "  Failures: %d (%.1f%%)" (count (filter-failures)) (failure-rate)))

  (println "\nChain Integrity:" (if (verify-chain-integrity) "VALID" "INVALID")))

;;; ============================================================================
;;; Part 10: Main
;;; ============================================================================

(defn -main
  [& args]
  (case (first args)
    "test" (run-tests)
    "demo" (demo)
    (do
      (println "Usage: clojure -M -m lab-21-1-audit-logging [test|demo]")
      (System/exit 1))))
