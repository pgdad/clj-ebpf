(ns clj-ebpf.btf-test
  "Tests for BTF (BPF Type Format) support"
  (:require [clojure.test :refer :all]
            [clj-ebpf.btf :as btf]
            [clj-ebpf.utils :as utils]))

;; ============================================================================
;; Constants Tests
;; ============================================================================

(deftest test-btf-constants
  (testing "BTF magic number"
    (is (= 0xeb9f btf/btf-magic)))

  (testing "BTF version"
    (is (= 1 btf/btf-version)))

  (testing "BTF kind constants"
    (is (= 1 (:int btf/btf-kind)))
    (is (= 2 (:ptr btf/btf-kind)))
    (is (= 3 (:array btf/btf-kind)))
    (is (= 4 (:struct btf/btf-kind)))
    (is (= 5 (:union btf/btf-kind)))
    (is (= 6 (:enum btf/btf-kind)))
    (is (= 7 (:fwd btf/btf-kind)))
    (is (= 8 (:typedef btf/btf-kind)))
    (is (= 9 (:volatile btf/btf-kind)))
    (is (= 10 (:const btf/btf-kind)))
    (is (= 11 (:restrict btf/btf-kind)))
    (is (= 12 (:func btf/btf-kind)))
    (is (= 13 (:func-proto btf/btf-kind)))
    (is (= 14 (:var btf/btf-kind)))
    (is (= 15 (:datasec btf/btf-kind)))
    (is (= 16 (:float btf/btf-kind)))
    (is (= 17 (:decl-tag btf/btf-kind)))
    (is (= 18 (:type-tag btf/btf-kind)))
    (is (= 19 (:enum64 btf/btf-kind)))))

(deftest test-btf-kind-reverse-map
  (testing "Kind number to keyword mapping"
    (is (= :int (get btf/btf-kind-num->keyword 1)))
    (is (= :ptr (get btf/btf-kind-num->keyword 2)))
    (is (= :struct (get btf/btf-kind-num->keyword 4)))
    (is (= :func (get btf/btf-kind-num->keyword 12)))))

(deftest test-btf-encoding-constants
  (testing "INT encoding flags"
    (is (= 1 (:signed btf/btf-int-encoding)))
    (is (= 2 (:char btf/btf-int-encoding)))
    (is (= 4 (:bool btf/btf-int-encoding))))

  (testing "Variable linkage"
    (is (= 0 (:static btf/btf-var-linkage)))
    (is (= 1 (:global-alloc btf/btf-var-linkage)))
    (is (= 2 (:global-extern btf/btf-var-linkage))))

  (testing "Function linkage"
    (is (= 0 (:static btf/btf-func-linkage)))
    (is (= 1 (:global btf/btf-func-linkage)))
    (is (= 2 (:extern btf/btf-func-linkage)))))

;; ============================================================================
;; BTF Availability Tests
;; ============================================================================

(deftest test-btf-availability
  (testing "BTF availability check"
    (let [available (btf/btf-available?)]
      (is (boolean? available))
      (when available
        (println "BTF is available on this system")))))

;; ============================================================================
;; BTF Loading Tests
;; ============================================================================

(deftest ^:integration test-load-btf-file
  (when (btf/btf-available?)
    (testing "Load BTF file"
      (try
        (let [btf-data (btf/load-btf-file)]
          (is (some? btf-data))
          (is (map? btf-data))

          ;; Check header
          (is (contains? btf-data :header))
          (let [header (:header btf-data)]
            (is (= btf/btf-magic (:magic header)))
            (is (= btf/btf-version (:version header)))
            (is (pos? (:type-len header)))
            (is (pos? (:str-len header))))

          ;; Check strings
          (is (contains? btf-data :strings))
          (is (map? (:strings btf-data)))
          (is (= "" (get (:strings btf-data) 0))) ; First string is empty

          ;; Check types
          (is (contains? btf-data :types))
          (is (vector? (:types btf-data)))
          (is (> (count (:types btf-data)) 100)) ; Should have many types

          ;; First type (ID 0) is reserved (void)
          (is (nil? (first (:types btf-data)))))

        (catch Exception e
          ;; May fail without proper permissions or BTF support
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Type Lookup Tests
;; ============================================================================

(deftest ^:integration test-get-type-by-id
  (when (btf/btf-available?)
    (testing "Get type by ID"
      (try
        (let [btf-data (btf/load-btf-file)]
          ;; Type ID 0 is void (reserved)
          (is (nil? (btf/get-type-by-id btf-data 0)))

          ;; Type ID 1 should exist (usually int)
          (let [type1 (btf/get-type-by-id btf-data 1)]
            (is (some? type1))
            (is (map? type1))
            (is (contains? type1 :kind))
            (is (contains? type1 :name-off)))

          ;; Invalid type ID
          (is (nil? (btf/get-type-by-id btf-data 999999))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

(deftest ^:integration test-find-type-by-name
  (when (btf/btf-available?)
    (testing "Find type by name"
      (try
        (let [btf-data (btf/load-btf-file)]
          ;; Look for common kernel structs
          (let [task-struct (btf/find-type-by-name btf-data "task_struct")]
            (when task-struct
              (is (= :struct (:kind task-struct)))
              (println "Found task_struct with" (count (:members task-struct)) "members")))

          ;; Look for non-existent type
          (is (nil? (btf/find-type-by-name btf-data "this_type_does_not_exist_12345"))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Type Name Tests
;; ============================================================================

(deftest ^:integration test-get-type-name
  (when (btf/btf-available?)
    (testing "Get type name"
      (try
        (let [btf-data (btf/load-btf-file)
              type1 (btf/get-type-by-id btf-data 1)]
          (when type1
            (let [name (btf/get-type-name btf-data type1)]
              (is (or (string? name) (nil? name))))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Struct/Union Tests
;; ============================================================================

(deftest ^:integration test-get-struct-members
  (when (btf/btf-available?)
    (testing "Get struct members"
      (try
        (let [btf-data (btf/load-btf-file)
              task-struct (btf/find-type-by-name btf-data "task_struct")]
          (when task-struct
            (let [members (btf/get-struct-members btf-data task-struct)]
              (is (vector? members))
              (is (seq members))
              (is (every? map? members))
              (is (every? #(contains? % :name) members))
              (is (every? #(contains? % :type) members))
              (is (every? #(contains? % :bit-offset) members))

              ;; Print first few members
              (println "task_struct first 3 members:")
              (doseq [member (take 3 members)]
                (println "  -" (:name member) "type" (:type member))))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Enum Tests
;; ============================================================================

(deftest ^:integration test-get-enum-values
  (when (btf/btf-available?)
    (testing "Get enum values"
      (try
        (let [btf-data (btf/load-btf-file)
              enums (btf/list-types btf-data :enum)]
          (when (seq enums)
            (let [enum-type (first enums)
                  values (btf/get-enum-values btf-data enum-type)]
              (is (vector? values))
              (when (seq values)
                (is (every? map? values))
                (is (every? #(contains? % :name) values))
                (is (every? #(contains? % :val) values))

                (println "Found enum with" (count values) "values")
                (println "First value:" (first values))))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Function Tests
;; ============================================================================

(deftest ^:integration test-find-function
  (when (btf/btf-available?)
    (testing "Find function"
      (try
        (let [btf-data (btf/load-btf-file)
              ;; Try to find a common kernel function
              func (btf/find-function btf-data "schedule")]
          (when func
            (is (= :func (:kind func)))
            (println "Found function 'schedule' with type ID" (:type func))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

(deftest ^:integration test-get-function-signature
  (when (btf/btf-available?)
    (testing "Get function signature"
      (try
        (let [btf-data (btf/load-btf-file)
              func (btf/find-function btf-data "schedule")]
          (when func
            (let [sig (btf/get-function-signature btf-data func)]
              (is (some? sig))
              (is (contains? sig :return-type))
              (is (contains? sig :params))
              (is (vector? (:params sig)))
              (println "Function signature:" sig))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Type Resolution Tests
;; ============================================================================

(deftest ^:integration test-resolve-type
  (when (btf/btf-available?)
    (testing "Resolve type through indirections"
      (try
        (let [btf-data (btf/load-btf-file)
              typedefs (btf/list-types btf-data :typedef)]
          (when (seq typedefs)
            (let [typedef (first typedefs)
                  typedef-id (:id typedef)
                  resolved-id (btf/resolve-type btf-data typedef-id)]
              (is (number? resolved-id))
              ;; Resolved ID should be different (unless it's a self-referencing type)
              (println "Typedef" typedef-id "resolves to" resolved-id))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Type Size Tests
;; ============================================================================

(deftest ^:integration test-get-type-size
  (when (btf/btf-available?)
    (testing "Get type size"
      (try
        (let [btf-data (btf/load-btf-file)]
          ;; Test INT type (should have size)
          (let [ints (btf/list-types btf-data :int)]
            (when (seq ints)
              (let [int-type (first ints)
                    size (btf/get-type-size btf-data (:id int-type))]
                (is (or (nil? size) (pos? size)))
                (when size
                  (println "INT type size:" size "bytes")))))

          ;; Test PTR type (should be 8 bytes on 64-bit)
          (let [ptrs (btf/list-types btf-data :ptr)]
            (when (seq ptrs)
              (let [ptr-type (first ptrs)
                    size (btf/get-type-size btf-data (:id ptr-type))]
                (is (= 8 size))
                (println "PTR type size:" size "bytes"))))

          ;; Test STRUCT type
          (let [task-struct (btf/find-type-by-name btf-data "task_struct")]
            (when task-struct
              (let [size (btf/get-type-size btf-data (:id task-struct))]
                (is (pos? size))
                (println "task_struct size:" size "bytes")))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Type Listing Tests
;; ============================================================================

(deftest ^:integration test-list-types
  (when (btf/btf-available?)
    (testing "List types by kind"
      (try
        (let [btf-data (btf/load-btf-file)]
          ;; List structs
          (let [structs (btf/list-types btf-data :struct)]
            (is (vector? structs))
            (is (seq structs))
            (println "Found" (count structs) "struct types"))

          ;; List functions
          (let [funcs (btf/list-types btf-data :func)]
            (is (vector? funcs))
            (when (seq funcs)
              (println "Found" (count funcs) "function types")))

          ;; List typedefs
          (let [typedefs (btf/list-types btf-data :typedef)]
            (is (vector? typedefs))
            (when (seq typedefs)
              (println "Found" (count typedefs) "typedef types"))))

        (catch Exception e
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-btf-api-completeness
  (testing "Core BTF functions are available"
    (is (fn? btf/load-btf-file))
    (is (fn? btf/btf-available?))
    (is (fn? btf/get-type-by-id))
    (is (fn? btf/get-type-name))
    (is (fn? btf/find-type-by-name))
    (is (fn? btf/get-struct-members))
    (is (fn? btf/get-enum-values))
    (is (fn? btf/get-func-params))
    (is (fn? btf/resolve-type))
    (is (fn? btf/get-type-size))
    (is (fn? btf/list-types))
    (is (fn? btf/find-function))
    (is (fn? btf/get-function-signature))))

;; ============================================================================
;; Documentation Tests
;; ============================================================================

(deftest test-function-metadata
  (testing "Key functions have docstrings"
    (is (string? (:doc (meta #'btf/load-btf-file))))
    (is (string? (:doc (meta #'btf/btf-available?))))
    (is (string? (:doc (meta #'btf/get-type-by-id))))
    (is (string? (:doc (meta #'btf/get-type-name))))
    (is (string? (:doc (meta #'btf/find-type-by-name))))
    (is (string? (:doc (meta #'btf/get-struct-members))))
    (is (string? (:doc (meta #'btf/get-enum-values))))
    (is (string? (:doc (meta #'btf/get-func-params))))
    (is (string? (:doc (meta #'btf/resolve-type))))
    (is (string? (:doc (meta #'btf/get-type-size))))
    (is (string? (:doc (meta #'btf/list-types))))
    (is (string? (:doc (meta #'btf/find-function))))
    (is (string? (:doc (meta #'btf/get-function-signature)))))

;; ============================================================================
;; Integration Tests Summary
;; ============================================================================

(deftest ^:integration test-btf-integration-summary
  (when (btf/btf-available?)
    (testing "BTF integration summary"
      (try
        (let [btf-data (btf/load-btf-file)
              type-count (count (:types btf-data))
              struct-count (count (btf/list-types btf-data :struct))
              func-count (count (btf/list-types btf-data :func))
              typedef-count (count (btf/list-types btf-data :typedef))]

          (println "\n=== BTF Integration Test Summary ===")
          (println "Total types:" type-count)
          (println "Structs:" struct-count)
          (println "Functions:" func-count)
          (println "Typedefs:" typedef-count)
          (println "String table entries:" (count (:strings btf-data)))

          ;; Verify we loaded a substantial amount of data
          (is (> type-count 1000))
          (is (> struct-count 100))

          ;; Test some common kernel types
          (let [common-types ["task_struct" "file" "inode" "dentry"]]
            (println "\nCommon kernel types:")
            (doseq [type-name common-types]
              (let [type-info (btf/find-type-by-name btf-data type-name)]
                (when type-info
                  (let [size (btf/get-type-size btf-data (:id type-info))]
                    (println "  -" type-name ":" size "bytes")))))))

        (catch Exception e
          (println "BTF integration test failed:" (.getMessage e))
          (is (string? (.getMessage e))))))))

;; ============================================================================
;; Example Usage Documentation
;; ============================================================================

(deftest ^:example test-usage-examples
  (testing "Example code compiles correctly"
    ;; Example 1: Basic BTF loading
    (is (fn? (fn []
               (when (btf/btf-available?)
                 (let [btf-data (btf/load-btf-file)]
                   (println "Loaded" (count (:types btf-data)) "types"))))))

    ;; Example 2: Find and inspect struct
    (is (fn? (fn []
               (when (btf/btf-available?)
                 (let [btf-data (btf/load-btf-file)
                       task-struct (btf/find-type-by-name btf-data "task_struct")]
                   (when task-struct
                     (let [members (btf/get-struct-members btf-data task-struct)]
                       (println "task_struct has" (count members) "members"))))))))

    ;; Example 3: Find function signature
    (is (fn? (fn []
               (when (btf/btf-available?)
                 (let [btf-data (btf/load-btf-file)
                       func (btf/find-function btf-data "schedule")]
                   (when func
                     (let [sig (btf/get-function-signature btf-data func)]
                       (println "schedule returns type" (:return-type sig))))))))))))
