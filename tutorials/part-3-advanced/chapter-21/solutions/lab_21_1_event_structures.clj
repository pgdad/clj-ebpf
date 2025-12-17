(ns lab-21-1-event-structures
  "Lab 21.1 Solution: Event Structure Definition

   This lab demonstrates defining BPF event structures using the defevent
   macro, querying structure metadata, and generating store instructions."
  (:require [clojure.test :refer [deftest testing is]]
            [clj-ebpf.dsl.structs :as structs]))

;; ============================================================================
;; Part 1: Basic Structure Definition
;; ============================================================================

;; Task 1.1: Simple Process Event
(structs/defevent SimpleProcessEvent
  [:timestamp :u64]    ; 8 bytes, offset 0
  [:pid :u32]          ; 4 bytes, offset 8
  [:uid :u32])         ; 4 bytes, offset 12
;; Total: 16 bytes

;; Task 1.2: Network Connection Event
(structs/defevent NetworkConnEvent
  [:timestamp :u64]    ; 8 bytes, offset 0
  [:pid :u32]          ; 4 bytes, offset 8
  [:tgid :u32]         ; 4 bytes, offset 12
  [:saddr :u32]        ; 4 bytes, offset 16
  [:daddr :u32]        ; 4 bytes, offset 20
  [:sport :u16]        ; 2 bytes, offset 24
  [:dport :u16]        ; 2 bytes, offset 26
  [:protocol :u8]      ; 1 byte, offset 28
  [:flags :u8]         ; 1 byte, offset 29
  [:padding :u8 2]     ; 2 bytes, offset 30
  [:comm :char 16])    ; 16 bytes, offset 32
;; Total: 48 bytes

;; Task 1.3: File System Event
(structs/defevent FileOpEvent
  [:timestamp :u64]    ; 8 bytes, offset 0
  [:pid :u32]          ; 4 bytes, offset 8
  [:operation :u32]    ; 4 bytes, offset 12
  [:inode :u64]        ; 8 bytes, offset 16
  [:size :u64]         ; 8 bytes, offset 24
  [:ret_code :i32]     ; 4 bytes, offset 32
  [:flags :u32]        ; 4 bytes, offset 36
  [:filename :char 64]); 64 bytes, offset 40
;; Total: 104 bytes

;; ============================================================================
;; Part 2: Structure Queries
;; ============================================================================

;; Task 2.1: Query All Fields
(defn print-event-layout
  "Print detailed layout information for an event structure."
  [event-def]
  (println "Event:" (:name event-def))
  (println "Total size:" (structs/event-size event-def) "bytes")
  (println)
  (println "Fields:")
  (println (format "  %-15s %-8s %-6s %-8s" "Name" "Offset" "Size" "Type"))
  (println (format "  %-15s %-8s %-6s %-8s" "----" "------" "----" "----"))
  (doseq [field (:fields event-def)]
    (println (format "  %-15s %-8d %-6d %-8s"
                     (name (:name field))
                     (:offset field)
                     (:size field)
                     (name (:type field))))))

;; Task 2.2: Alignment Checker
(defn natural-alignment
  "Get natural alignment for a type (min of size and 8)."
  [type-size]
  (min type-size 8))

(defn check-alignment
  "Check if all fields in an event structure are properly aligned."
  [event-def]
  (println "Alignment check for:" (:name event-def))
  (let [issues (atom [])]
    (doseq [field (:fields event-def)]
      (let [offset (:offset field)
            size (:size field)
            align (natural-alignment (min size 8))
            aligned? (zero? (mod offset align))]
        (if aligned?
          (println (format "  %-15s offset %-3d - OK (%d-byte aligned)"
                          (name (:name field)) offset align))
          (do
            (println (format "  %-15s offset %-3d - MISALIGNED (needs %d-byte)"
                            (name (:name field)) offset align))
            (swap! issues conj (:name field))))))
    (if (empty? @issues)
      (println "All fields properly aligned!")
      (println "Misaligned fields:" @issues))))

;; ============================================================================
;; Part 3: Store Instructions
;; ============================================================================

;; Task 3.1: Generate Individual Stores
(def store-timestamp
  "Store timestamp from register r8 to event at r6."
  (structs/store-event-field :r6 NetworkConnEvent :timestamp :r8))

(def store-protocol
  "Store protocol = 6 (TCP) as immediate."
  (structs/store-event-imm :r6 NetworkConnEvent :protocol 6))

;; Task 3.2: Batch Store
(def batch-stores
  "Store multiple fields in one call."
  (structs/store-event-fields :r6 NetworkConnEvent
    {:timestamp {:reg :r8}
     :pid {:reg :r7}
     :protocol {:imm 6}
     :flags {:imm 0}}))

;; ============================================================================
;; Part 4: Design Challenge
;; ============================================================================

;; Task 4.1: Security Audit Event
;; Design principles:
;; 1. 8-byte fields first (timestamp, args)
;; 2. 4-byte fields next (pid, syscall, etc.)
;; 3. Smaller fields grouped with padding
;; 4. Total size: 128 bytes

(structs/defevent SecurityAuditEvent
  ;; When (8 bytes)
  [:timestamp :u64]        ; offset 0

  ;; Syscall arguments (48 bytes, offsets 8-55)
  [:arg0 :u64]             ; offset 8
  [:arg1 :u64]             ; offset 16
  [:arg2 :u64]             ; offset 24
  [:arg3 :u64]             ; offset 32
  [:arg4 :u64]             ; offset 40
  [:arg5 :u64]             ; offset 48

  ;; Who - identifiers (20 bytes, offsets 56-75)
  [:pid :u32]              ; offset 56
  [:tgid :u32]             ; offset 60
  [:uid :u32]              ; offset 64
  [:gid :u32]              ; offset 68
  [:euid :u32]             ; offset 72

  ;; What (8 bytes, offsets 76-83)
  [:syscall_nr :u32]       ; offset 76
  [:ret_code :i32]         ; offset 80

  ;; Metadata (4 bytes, offsets 84-87)
  [:cpu :u16]              ; offset 84
  [:audit_type :u8]        ; offset 86
  [:severity :u8]          ; offset 87

  ;; Where - process info (24 bytes, offsets 88-111)
  [:comm :char 16]         ; offset 88
  [:ppid :u32]             ; offset 104
  [:session_id :u32]       ; offset 108

  ;; Padding to 128 bytes (16 bytes)
  [:reserved :u8 16])      ; offset 112
;; Total: 128 bytes

;; ============================================================================
;; Tests
;; ============================================================================

(deftest test-simple-process-event
  (testing "SimpleProcessEvent has correct size and layout"
    (is (= 16 (structs/event-size SimpleProcessEvent)))
    (is (= 0 (structs/event-field-offset SimpleProcessEvent :timestamp)))
    (is (= 8 (structs/event-field-offset SimpleProcessEvent :pid)))
    (is (= 12 (structs/event-field-offset SimpleProcessEvent :uid)))))

(deftest test-network-conn-event
  (testing "NetworkConnEvent has correct size"
    (is (= 48 (structs/event-size NetworkConnEvent))))

  (testing "NetworkConnEvent has correct field offsets"
    (is (= 0 (structs/event-field-offset NetworkConnEvent :timestamp)))
    (is (= 8 (structs/event-field-offset NetworkConnEvent :pid)))
    (is (= 24 (structs/event-field-offset NetworkConnEvent :sport)))
    (is (= 28 (structs/event-field-offset NetworkConnEvent :protocol)))
    (is (= 32 (structs/event-field-offset NetworkConnEvent :comm)))))

(deftest test-file-op-event
  (testing "FileOpEvent has correct size"
    (is (= 104 (structs/event-size FileOpEvent))))

  (testing "FileOpEvent has correct layout"
    (is (= 16 (structs/event-field-offset FileOpEvent :inode)))
    (is (= 40 (structs/event-field-offset FileOpEvent :filename)))
    (is (= 64 (structs/event-field-size FileOpEvent :filename)))))

(deftest test-store-instructions
  (testing "Individual store instructions"
    (is (some? store-timestamp))
    (is (= 0 (:offset store-timestamp)))

    (is (some? store-protocol))
    (is (= 6 (:imm store-protocol))))

  (testing "Batch store generates correct count"
    (is (= 4 (count batch-stores)))))

(deftest test-security-audit-event
  (testing "SecurityAuditEvent is 128 bytes"
    (is (= 128 (structs/event-size SecurityAuditEvent))))

  (testing "SecurityAuditEvent fields are properly aligned"
    ;; 8-byte fields
    (is (zero? (mod (structs/event-field-offset SecurityAuditEvent :timestamp) 8)))
    (is (zero? (mod (structs/event-field-offset SecurityAuditEvent :arg0) 8)))

    ;; 4-byte fields
    (is (zero? (mod (structs/event-field-offset SecurityAuditEvent :pid) 4)))
    (is (zero? (mod (structs/event-field-offset SecurityAuditEvent :syscall_nr) 4)))

    ;; 2-byte fields
    (is (zero? (mod (structs/event-field-offset SecurityAuditEvent :cpu) 2)))))

;; ============================================================================
;; Demo Runner
;; ============================================================================

(defn run-demo []
  (println "Lab 21.1: Event Structure Definition")
  (println "=====================================\n")

  ;; Part 1
  (println "Part 1: Basic Structures")
  (println "------------------------")
  (println "SimpleProcessEvent:" (structs/event-size SimpleProcessEvent) "bytes")
  (println "NetworkConnEvent:" (structs/event-size NetworkConnEvent) "bytes")
  (println "FileOpEvent:" (structs/event-size FileOpEvent) "bytes")
  (println)

  ;; Part 2
  (println "Part 2: Structure Queries")
  (println "-------------------------")
  (print-event-layout NetworkConnEvent)
  (println)
  (check-alignment NetworkConnEvent)
  (println)

  ;; Part 3
  (println "Part 3: Store Instructions")
  (println "--------------------------")
  (println "store-timestamp:" store-timestamp)
  (println "store-protocol:" store-protocol)
  (println "batch-stores count:" (count batch-stores))
  (println)

  ;; Part 4
  (println "Part 4: Security Audit Event")
  (println "----------------------------")
  (print-event-layout SecurityAuditEvent)
  (println)
  (check-alignment SecurityAuditEvent)

  (println)
  (println "Demo complete!"))

(defn -main [& args]
  (run-demo))

;; ============================================================================
;; REPL Examples
;; ============================================================================

(comment
  ;; Run demo
  (run-demo)

  ;; Run tests
  (clojure.test/run-tests 'lab-21-1-event-structures)

  ;; Interactive exploration
  (structs/event-size SimpleProcessEvent)
  (structs/event-fields NetworkConnEvent)
  (structs/event-field-offset FileOpEvent :filename)

  ;; Generate store instruction
  (structs/store-event-field :r6 NetworkConnEvent :dport :r7)
  )
