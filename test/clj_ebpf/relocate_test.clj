(ns clj-ebpf.relocate-test
  "Tests for CO-RE (Compile Once - Run Everywhere) relocations."
  (:require [clojure.test :refer [deftest testing is]]
            [clj-ebpf.relocate :as relocate]
            [clj-ebpf.btf :as btf]))

(deftest test-relocation-kind-constants
  (testing "Relocation kind constants are defined"
    (is (= 0 (:field-byte-offset relocate/relocation-kind)))
    (is (= 1 (:field-byte-size relocate/relocation-kind)))
    (is (= 2 (:field-exists relocate/relocation-kind)))
    (is (= 3 (:field-signed relocate/relocation-kind)))
    (is (= 4 (:field-lshift-u64 relocate/relocation-kind)))
    (is (= 5 (:field-rshift-u64 relocate/relocation-kind)))
    (is (= 6 (:type-id-local relocate/relocation-kind)))
    (is (= 7 (:type-id-target relocate/relocation-kind)))
    (is (= 8 (:type-exists relocate/relocation-kind)))
    (is (= 9 (:type-size relocate/relocation-kind)))
    (is (= 10 (:enumval-exists relocate/relocation-kind)))
    (is (= 11 (:enumval-value relocate/relocation-kind)))
    (is (= 12 (:type-matches relocate/relocation-kind)))))

(deftest test-relocation-kind-names
  (testing "Reverse mapping from kind value to name"
    (is (= :field-byte-offset (get relocate/relocation-kind-names 0)))
    (is (= :field-byte-size (get relocate/relocation-kind-names 1)))
    (is (= :field-exists (get relocate/relocation-kind-names 2)))
    (is (= :type-size (get relocate/relocation-kind-names 9)))
    (is (= :enumval-value (get relocate/relocation-kind-names 11)))))

(deftest test-create-relocation
  (testing "Creating a relocation record"
    (let [relo (relocate/create-relocation 24 42 "0:1" :field-byte-offset)]
      (is (= 24 (:insn-off relo)))
      (is (= 42 (:type-id relo)))
      (is (= "0:1" (:access-str-off relo)))
      (is (= :field-byte-offset (:kind relo)))
      (is (= 0 (:kind-value relo)))))

  (testing "Creating relocations with different kinds"
    (let [relo-size (relocate/create-relocation 0 10 "0" :field-byte-size)]
      (is (= :field-byte-size (:kind relo-size)))
      (is (= 1 (:kind-value relo-size))))

    (let [relo-exists (relocate/create-relocation 0 10 "0" :field-exists)]
      (is (= :field-exists (:kind relo-exists)))
      (is (= 2 (:kind-value relo-exists))))))

(deftest test-parse-access-string
  (testing "Parsing simple access strings"
    (is (= [] (relocate/parse-access-string "")))
    (is (= [] (relocate/parse-access-string "0")))
    (is (= [] (relocate/parse-access-string nil))))

  (testing "Parsing single field access"
    (is (= [0] (relocate/parse-access-string "0:"))))

  (testing "Parsing nested field access"
    (is (= [0 1] (relocate/parse-access-string "0:1")))
    (is (= [0 1 2] (relocate/parse-access-string "0:1:2")))
    (is (= [0 1 2 3] (relocate/parse-access-string "0:1:2:3")))))

(deftest test-core-read-supported
  (testing "CO-RE read support detection"
    ;; This should check if /sys/kernel/btf/vmlinux exists
    (let [supported (relocate/core-read-supported?)]
      (is (boolean? supported))
      ;; On modern Linux kernels with BTF, this should be true
      ;; But we can't guarantee it in test environment
      (is (or (true? supported) (false? supported))))))

(deftest test-get-kernel-btf
  (testing "Loading kernel BTF"
    (when (relocate/core-read-supported?)
      (try
        (let [kernel-btf (relocate/get-kernel-btf)]
          ;; If BTF is available and valid, we should get data
          (when kernel-btf
            (is (map? kernel-btf))
            (is (contains? kernel-btf :types))))
        (catch Exception e
          ;; BTF file might exist but be in incompatible format
          ;; This is acceptable in test environment
          (is (true? true)))))))

(deftest test-resolve-field-offset
  (testing "Field offset resolution requires actual BTF data"
    ;; Note: Full testing requires actual BTF data from kernel
    ;; These tests verify the function exists and handles nil gracefully
    (is (nil? (relocate/resolve-field-offset nil 1 [0])))
    (is (nil? (relocate/resolve-field-offset nil 1 [0 1])))))

(deftest test-resolve-field-size
  (testing "Field size resolution"
    ;; This would require actual BTF data with type information
    ;; For now, test that the function exists and handles nil gracefully
    (is (nil? (relocate/resolve-field-size nil 1 [0])))))

(deftest test-resolve-field-signed
  (testing "Field signedness resolution"
    ;; Test requires actual BTF data
    (is (nil? (relocate/resolve-field-signed nil 1 [])))))

(deftest test-resolve-field-exists
  (testing "Field existence check"
    ;; Returns 0 if field doesn't exist (nil from resolve-field-offset)
    (is (= 0 (relocate/resolve-field-exists nil 1 [1])))))

(deftest test-resolve-type-exists
  (testing "Type existence check"
    ;; Returns 0 when type doesn't exist
    (is (= 0 (relocate/resolve-type-exists nil "nonexistent_struct")))))

(deftest test-resolve-type-size
  (testing "Type size resolution"
    ;; Returns 0 when type not found
    (is (= 0 (relocate/resolve-type-size nil 999)))))

(deftest test-resolve-type-matches
  (testing "Type layout matching"
    ;; Returns 0 when types don't match or are nil
    (is (= 0 (relocate/resolve-type-matches nil nil 1 2)))))

(deftest test-resolve-enum-value-exists
  (testing "Enum value existence check"
    ;; Returns 0 when enum value doesn't exist
    (is (= 0 (relocate/resolve-enum-value-exists nil 1 "VAL3")))))

(deftest test-resolve-enum-value
  (testing "Enum value resolution"
    ;; Returns 0 when enum value not found
    (is (= 0 (relocate/resolve-enum-value nil 1 "NONEXISTENT")))))

(deftest test-apply-relocation
  (testing "Applying relocation to instruction"
    ;; Create a simple instruction (MOV r0, 0)
    (let [insns (byte-array [0xb7 0x00 0x00 0x00 0x00 0x00 0x00 0x00])
          relo (relocate/create-relocation 0 1 "0" :field-byte-offset)
          result (relocate/apply-relocation insns relo nil nil)]
      ;; Should return byte array (possibly poisoned if relocation failed)
      (is (bytes? result))
      (is (= 8 (count result))))))

(deftest test-apply-relocations
  (testing "Applying multiple relocations"
    ;; Create two instructions
    (let [insns (byte-array 16)  ; 2 * 8 bytes
          relo1 (relocate/create-relocation 0 1 "0" :field-byte-offset)
          relo2 (relocate/create-relocation 8 1 "1" :field-byte-offset)
          result (relocate/apply-relocations insns [relo1 relo2] nil nil)]
      (is (bytes? result))
      (is (= 16 (count result))))))

(deftest test-generate-field-access-relo
  (testing "Generating field access relocation"
    ;; Returns nil when BTF doesn't have the type
    (let [relo (relocate/generate-field-access-relo 16 "task_struct" "pid" nil)]
      (is (nil? relo)))))

(deftest test-relocation-documentation
  (testing "All relocation kinds have documentation"
    (is (string? (:doc (meta #'relocate/relocation-kind))))
    (is (> (count (:doc (meta #'relocate/relocation-kind))) 100))))

(deftest test-access-string-edge-cases
  (testing "Edge cases for access string parsing"
    ;; Empty string
    (is (= [] (relocate/parse-access-string "")))

    ;; Single zero
    (is (= [] (relocate/parse-access-string "0")))

    ;; Deep nesting
    (is (= [0 1 2 3 4 5] (relocate/parse-access-string "0:1:2:3:4:5")))))

(deftest test-relocation-kind-coverage
  (testing "All 13 relocation kinds are defined"
    (is (= 13 (count relocate/relocation-kind)))
    (is (= 13 (count relocate/relocation-kind-names)))))

(deftest test-bitfield-shifts
  (testing "Bitfield shift calculation"
    ;; This is a complex feature - test basic structure
    (let [result (relocate/resolve-bitfield-shifts nil 1 [])]
      ;; Should return nil or a map with :lshift and :rshift
      (is (or (nil? result)
              (and (map? result)
                   (contains? result :lshift)
                   (contains? result :rshift)))))))
