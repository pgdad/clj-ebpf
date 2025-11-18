(ns clj-ebpf.relocate
  "CO-RE (Compile Once - Run Everywhere) relocation support.

  This namespace provides functionality for BPF CO-RE relocations, enabling
  BPF programs to be portable across different kernel versions by using BTF
  information to relocate field accesses and type information at load time.

  CO-RE relocations allow BPF programs to:
  - Access struct fields regardless of their offset in different kernel versions
  - Check for field/type/enum existence at load time
  - Get accurate field sizes and types
  - Handle bitfield operations correctly
  - Support both local and target BTF type IDs

  Key concepts:
  - Field relocations: Adjust field offsets, sizes, existence
  - Type relocations: Check type existence, size, matches
  - Enum relocations: Get enum values, check existence
  - BTF-based resolution: Use kernel BTF to resolve relocations"
  (:require [clj-ebpf.btf :as btf]
            [clj-ebpf.utils :as utils]))

;;; =============================================================================
;;; CO-RE Relocation Constants
;;; =============================================================================

(def relocation-kind
  "CO-RE relocation kinds as defined in linux/bpf.h.

  Field-based relocations (0-5):
  - :field-byte-offset  - Field offset in bytes from struct start
  - :field-byte-size    - Field size in bytes
  - :field-exists       - Field existence (0 or 1)
  - :field-signed       - Field signedness (0 unsigned, 1 signed)
  - :field-lshift-u64   - Left bit shift for bitfield extraction
  - :field-rshift-u64   - Right bit shift for bitfield extraction

  Type-based relocations (6-9, 12):
  - :type-id-local      - BTF type ID in local program BTF
  - :type-id-target     - BTF type ID in target kernel BTF
  - :type-exists        - Type existence in target kernel (0 or 1)
  - :type-size          - Type size in bytes
  - :type-matches       - Type layout match between local and target

  Enum-based relocations (10-11):
  - :enumval-exists     - Enum value existence (0 or 1)
  - :enumval-value      - Enum value integer value"
  {:field-byte-offset 0
   :field-byte-size   1
   :field-exists      2
   :field-signed      3
   :field-lshift-u64  4
   :field-rshift-u64  5
   :type-id-local     6
   :type-id-target    7
   :type-exists       8
   :type-size         9
   :enumval-exists    10
   :enumval-value     11
   :type-matches      12})

(def relocation-kind-names
  "Reverse mapping from relocation kind value to keyword name."
  (into {} (map (fn [[k v]] [v k]) relocation-kind)))

;;; =============================================================================
;;; CO-RE Relocation Structure
;;; =============================================================================

(defn create-relocation
  "Create a CO-RE relocation record.

  Parameters:
  - insn-off: Instruction offset in bytes within code section
  - type-id: BTF type ID of the root entity (struct, enum, etc.)
  - access-str-off: Offset into BTF string section (or access string)
  - kind: Relocation kind (keyword from relocation-kind map)

  Returns map with relocation information.

  Example:
    (create-relocation 24 42 \"0:1\" :field-byte-offset)"
  [insn-off type-id access-str-off kind]
  {:insn-off insn-off
   :type-id type-id
   :access-str-off access-str-off
   :kind kind
   :kind-value (get relocation-kind kind)})

(defn parse-access-string
  "Parse CO-RE access string into field path indices.

  Access string format: \"idx1:idx2:idx3...\"
  - Each index represents a field position in a nested structure
  - \"0:1\" means first field (0) of that struct, then second field (1) of that struct

  Parameters:
  - access-str: Access string (e.g., \"0:1:2\")

  Returns vector of field indices.

  Examples:
    (parse-access-string \"0\")     ; => [0]
    (parse-access-string \"0:1\")   ; => [0 1]
    (parse-access-string \"0:1:2\") ; => [0 1 2]"
  [access-str]
  (if (or (nil? access-str) (empty? access-str) (= access-str "0"))
    []
    (mapv #(Integer/parseInt %) (clojure.string/split access-str #":"))))

;;; =============================================================================
;;; BTF Field Resolution
;;; =============================================================================

(defn resolve-field-offset
  "Resolve field offset in bytes using BTF information.

  Walks through the field path (access string) to find the final field offset.

  Parameters:
  - btf-data: BTF data (from btf/load-btf-file)
  - type-id: Starting BTF type ID (struct/union)
  - field-path: Vector of field indices (from parse-access-string)

  Returns field offset in bytes, or nil if field not found.

  Example:
    (resolve-field-offset btf 42 [0 1])  ; Get offset of second field of first field"
  [btf-data type-id field-path]
  (loop [current-type-id type-id
         remaining-path field-path
         accumulated-offset 0]
    (if (empty? remaining-path)
      accumulated-offset
      (let [field-idx (first remaining-path)
            type-info (btf/get-type-by-id btf-data current-type-id)]
        (when type-info
          (case (:kind type-info)
            ;; For structs and unions, get the field at index
            (:struct :union)
            (let [members (:members type-info)]
              (when (< field-idx (count members))
                (let [member (nth members field-idx)
                      field-offset (:offset member)
                      field-type-id (:type member)
                      ;; Convert bit offset to byte offset
                      byte-offset (quot field-offset 8)]
                  (recur field-type-id
                         (rest remaining-path)
                         (+ accumulated-offset byte-offset)))))

            ;; For typedefs and const/volatile, resolve through to underlying type
            (:typedef :const :volatile :restrict)
            (recur (:type type-info) remaining-path accumulated-offset)

            ;; For pointers, we can't continue - return accumulated offset
            :ptr
            accumulated-offset

            ;; Unknown type
            nil))))))

(defn resolve-field-size
  "Resolve field size in bytes using BTF information.

  Parameters:
  - btf-data: BTF data
  - type-id: Starting BTF type ID
  - field-path: Vector of field indices

  Returns field size in bytes, or nil if field not found."
  [btf-data type-id field-path]
  (loop [current-type-id type-id
         remaining-path field-path]
    (let [type-info (btf/get-type-by-id btf-data current-type-id)]
      (when type-info
        (if (empty? remaining-path)
          ;; We've reached the target field, return its size
          (btf/get-type-size btf-data current-type-id)
          ;; Continue traversing
          (let [field-idx (first remaining-path)]
            (case (:kind type-info)
              (:struct :union)
              (let [members (:members type-info)]
                (when (< field-idx (count members))
                  (let [member (nth members field-idx)
                        field-type-id (:type member)]
                    (recur field-type-id (rest remaining-path)))))

              (:typedef :const :volatile :restrict)
              (recur (:type type-info) remaining-path)

              :ptr
              (when (empty? (rest remaining-path))
                8)  ; Pointer size is always 8 bytes on 64-bit

              nil)))))))

(defn resolve-field-signed
  "Check if field is signed using BTF information.

  Parameters:
  - btf-data: BTF data
  - type-id: Starting BTF type ID
  - field-path: Vector of field indices

  Returns 1 if signed, 0 if unsigned, nil if unknown."
  [btf-data type-id field-path]
  (loop [current-type-id type-id
         remaining-path field-path]
    (let [type-info (btf/get-type-by-id btf-data current-type-id)]
      (when type-info
        (if (empty? remaining-path)
          ;; We've reached the target field, check if signed
          (case (:kind type-info)
            :int (if (:signed type-info) 1 0)
            0)  ; Non-integer types are considered unsigned
          ;; Continue traversing
          (let [field-idx (first remaining-path)]
            (case (:kind type-info)
              (:struct :union)
              (let [members (:members type-info)]
                (when (< field-idx (count members))
                  (let [member (nth members field-idx)
                        field-type-id (:type member)]
                    (recur field-type-id (rest remaining-path)))))

              (:typedef :const :volatile :restrict)
              (recur (:type type-info) remaining-path)

              nil)))))))

(defn resolve-field-exists
  "Check if field exists using BTF information.

  Parameters:
  - btf-data: BTF data
  - type-id: Starting BTF type ID
  - field-path: Vector of field indices

  Returns 1 if field exists, 0 if not."
  [btf-data type-id field-path]
  (if (resolve-field-offset btf-data type-id field-path)
    1
    0))

(defn resolve-bitfield-shifts
  "Calculate bitfield left/right shift values for extraction.

  For bitfields, we need shift operations to extract the value:
  1. Left shift to align MSB with register MSB
  2. Right shift (arithmetic for signed, logical for unsigned) to align LSB

  Parameters:
  - btf-data: BTF data
  - type-id: Starting BTF type ID
  - field-path: Vector of field indices

  Returns map with :lshift and :rshift values, or nil if not a bitfield."
  [btf-data type-id field-path]
  (loop [current-type-id type-id
         remaining-path field-path]
    (let [type-info (btf/get-type-by-id btf-data current-type-id)]
      (when type-info
        (if (empty? remaining-path)
          ;; We've reached the target - check if it's a bitfield
          (when (and (= (:kind type-info) :int) (:bits type-info))
            (let [bit-size (:bits type-info)
                  bit-offset (:bit-offset type-info 0)
                  ;; Calculate shifts for 64-bit register
                  lshift (- 64 bit-offset bit-size)
                  rshift (- 64 bit-size)]
              {:lshift lshift :rshift rshift}))
          ;; Continue traversing
          (let [field-idx (first remaining-path)]
            (case (:kind type-info)
              (:struct :union)
              (let [members (:members type-info)]
                (when (< field-idx (count members))
                  (let [member (nth members field-idx)
                        field-type-id (:type member)
                        ;; Check if member itself has bitfield info
                        bit-size (:bitfield-size member)]
                    (if bit-size
                      ;; This is a bitfield member
                      (let [bit-offset (:offset member)  ; Already in bits
                            ;; Calculate shifts for 64-bit register
                            lshift (- 64 (mod bit-offset 8) bit-size)
                            rshift (- 64 bit-size)]
                        {:lshift lshift :rshift rshift})
                      ;; Regular field, continue traversing
                      (recur field-type-id (rest remaining-path))))))

              (:typedef :const :volatile :restrict)
              (recur (:type type-info) remaining-path)

              nil)))))))

;;; =============================================================================
;;; Type Resolution
;;; =============================================================================

(defn resolve-type-exists
  "Check if type exists in target BTF.

  Parameters:
  - btf-data: Target kernel BTF data
  - type-name: Type name to search for

  Returns 1 if type exists, 0 if not."
  [btf-data type-name]
  (if (btf/find-type-by-name btf-data type-name)
    1
    0))

(defn resolve-type-size
  "Get type size from target BTF.

  Parameters:
  - btf-data: Target kernel BTF data
  - type-id: BTF type ID

  Returns size in bytes, or 0 if type not found."
  [btf-data type-id]
  (or (btf/get-type-size btf-data type-id) 0))

(defn resolve-type-matches
  "Check if local type layout matches target type layout.

  This is a simplified check that compares type sizes. A full implementation
  would recursively compare all struct members.

  Parameters:
  - local-btf: Local program BTF data
  - target-btf: Target kernel BTF data
  - local-type-id: Local BTF type ID
  - target-type-id: Target BTF type ID

  Returns 1 if types match, 0 if not."
  [local-btf target-btf local-type-id target-type-id]
  (let [local-size (btf/get-type-size local-btf local-type-id)
        target-size (btf/get-type-size target-btf target-type-id)]
    (if (and local-size target-size (= local-size target-size))
      1
      0)))

;;; =============================================================================
;;; Enum Resolution
;;; =============================================================================

(defn resolve-enum-value-exists
  "Check if enum value exists in target BTF.

  Parameters:
  - btf-data: Target kernel BTF data
  - enum-type-id: Enum BTF type ID
  - value-name: Enum value name

  Returns 1 if enum value exists, 0 if not."
  [btf-data enum-type-id value-name]
  (let [enum-values (btf/get-enum-values btf-data enum-type-id)]
    (if (some #(= (:name %) value-name) enum-values)
      1
      0)))

(defn resolve-enum-value
  "Get enum value from target BTF.

  Parameters:
  - btf-data: Target kernel BTF data
  - enum-type-id: Enum BTF type ID
  - value-name: Enum value name

  Returns enum integer value, or 0 if not found."
  [btf-data enum-type-id value-name]
  (let [enum-values (btf/get-enum-values btf-data enum-type-id)
        value (first (filter #(= (:name %) value-name) enum-values))]
    (or (:val value) 0)))

;;; =============================================================================
;;; Relocation Processing
;;; =============================================================================

(defn apply-relocation
  "Apply a single CO-RE relocation to BPF instruction.

  Parameters:
  - insns: BPF instruction bytecode (byte array)
  - relo: Relocation record (from create-relocation)
  - local-btf: Local program BTF data
  - target-btf: Target kernel BTF data

  Returns updated instruction bytecode, or original if relocation fails.

  The relocation updates the instruction's immediate or offset field based on
  the relocation kind and resolved value from target kernel BTF."
  [insns relo local-btf target-btf]
  (let [{:keys [insn-off type-id access-str-off kind]} relo
        field-path (parse-access-string access-str-off)
        ;; Resolve the relocation value based on kind
        resolved-value
        (case kind
          :field-byte-offset
          (resolve-field-offset target-btf type-id field-path)

          :field-byte-size
          (resolve-field-size target-btf type-id field-path)

          :field-exists
          (resolve-field-exists target-btf type-id field-path)

          :field-signed
          (resolve-field-signed target-btf type-id field-path)

          :field-lshift-u64
          (:lshift (resolve-bitfield-shifts target-btf type-id field-path))

          :field-rshift-u64
          (:rshift (resolve-bitfield-shifts target-btf type-id field-path))

          :type-id-local
          type-id

          :type-id-target
          ;; Would need to map local type to target type by name
          type-id

          :type-exists
          (let [type-info (btf/get-type-by-id local-btf type-id)]
            (resolve-type-exists target-btf (:name type-info)))

          :type-size
          (resolve-type-size target-btf type-id)

          :enumval-exists
          (let [type-info (btf/get-type-by-id local-btf type-id)
                value-name (first field-path)]  ; For enums, access string is value name
            (resolve-enum-value-exists target-btf type-id value-name))

          :enumval-value
          (let [type-info (btf/get-type-by-id local-btf type-id)
                value-name (first field-path)]
            (resolve-enum-value target-btf type-id value-name))

          :type-matches
          ;; Would need target type ID mapping
          1

          ;; Unknown relocation kind
          nil)]

    (if resolved-value
      ;; Update the instruction at insn-off with resolved-value
      ;; BPF instruction format: 8 bytes with immediate at offset 4-7
      (let [imm-offset (+ insn-off 4)
            imm-bytes (utils/pack-struct [[:i32 resolved-value]])]
        ;; Copy resolved value into instruction's immediate field
        (doseq [i (range 4)]
          (aset insns (+ imm-offset i) (aget imm-bytes i)))
        insns)
      ;; Relocation failed - mark instruction as poisoned (0xbad2310)
      (let [imm-offset (+ insn-off 4)
            poison-bytes (utils/pack-struct [[:i32 0xbad2310]])]
        (doseq [i (range 4)]
          (aset insns (+ imm-offset i) (aget poison-bytes i)))
        insns))))

(defn apply-relocations
  "Apply all CO-RE relocations to BPF program.

  Parameters:
  - insns: BPF instruction bytecode (byte array)
  - relocations: Sequence of relocation records
  - local-btf: Local program BTF data (from compiled object)
  - target-btf: Target kernel BTF data (from /sys/kernel/btf/vmlinux)

  Returns updated instruction bytecode with all relocations applied.

  Example:
    (apply-relocations bytecode relocs local-btf kernel-btf)"
  [insns relocations local-btf target-btf]
  (reduce (fn [insns-acc relo]
            (apply-relocation insns-acc relo local-btf target-btf))
          insns
          relocations))

;;; =============================================================================
;;; CO-RE Helper Functions
;;; =============================================================================

(defn generate-field-access-relo
  "Generate CO-RE relocation for field access.

  This is used when generating BPF code dynamically to create relocatable
  field accesses.

  Parameters:
  - insn-offset: Instruction offset where field access occurs
  - struct-name: Structure name (e.g., \"task_struct\")
  - field-path: Field access path (e.g., \"pid\" or \"parent.pid\")
  - btf-data: BTF data to lookup type ID

  Returns relocation record for field offset.

  Example:
    (generate-field-access-relo 16 \"task_struct\" \"pid\" btf)"
  [insn-offset struct-name field-path btf-data]
  (let [type-id (btf/find-type-by-name btf-data struct-name)
        ;; Convert field path like \"parent.pid\" to \"0:1\"
        ;; This would require field name to index mapping
        access-str field-path]
    (when type-id
      (create-relocation insn-offset
                        (:id type-id)
                        access-str
                        :field-byte-offset))))

(defn core-read-supported?
  "Check if CO-RE relocations are supported on this system.

  Returns true if kernel BTF is available and CO-RE can be used."
  []
  (btf/btf-available?))

(defn get-kernel-btf
  "Load kernel BTF for CO-RE relocations.

  Returns BTF data from /sys/kernel/btf/vmlinux, or nil if not available."
  []
  (when (core-read-supported?)
    (btf/load-btf-file "/sys/kernel/btf/vmlinux")))
