(ns clj-ebpf.dsl.structs
  "Event structure definition DSL for BPF programs.

   Provides macros and functions for defining event structures that can
   be used with ring buffers. The defevent macro creates structure definitions
   with automatic offset calculation and store function generation.

   Example:
     (defevent ConnectionEvent
       [:timestamp :u64]
       [:pid :u32]
       [:saddr :u32]
       [:daddr :u32]
       [:sport :u16]
       [:dport :u16]
       [:protocol :u8]
       [:direction :u8]
       [:padding :u8 2]
       [:comm :char 16])

     ;; Get size: (event-size ConnectionEvent) => 44
     ;; Get offset: (event-field-offset ConnectionEvent :pid) => 8
     ;; Generate store: (store-event-field :r6 ConnectionEvent :pid :r7)"
  (:require [clj-ebpf.dsl.mem :as mem]))

;; ============================================================================
;; Type Size Definitions
;; ============================================================================

(def type-sizes
  "Size in bytes for each supported type"
  {:u8    1
   :i8    1
   :u16   2
   :i16   2
   :u32   4
   :i32   4
   :u64   8
   :i64   8
   :char  1
   :ptr   8})

(def type-load-store-size
  "Map type to load/store size keyword for BPF instructions"
  {:u8    :b
   :i8    :b
   :u16   :h
   :i16   :h
   :u32   :w
   :i32   :w
   :u64   :dw
   :i64   :dw
   :char  :b
   :ptr   :dw})

;; ============================================================================
;; Event Structure Definition
;; ============================================================================

(defn- parse-field-spec
  "Parse a field specification into a normalized map.

   Input formats:
   - [:name :type]           - Simple field
   - [:name :type count]     - Array field

   Returns {:name :type :count :size}"
  [[field-name field-type & [count]]]
  (let [count (or count 1)
        base-size (get type-sizes field-type 8)
        total-size (* base-size count)]
    {:name field-name
     :type field-type
     :count count
     :size total-size}))

(defn- calculate-field-offsets
  "Calculate offsets for all fields in a structure.

   Returns vector of field maps with :offset added."
  [field-specs]
  (loop [fields []
         offset 0
         remaining field-specs]
    (if (empty? remaining)
      fields
      (let [field (first remaining)
            parsed (parse-field-spec field)
            field-with-offset (assoc parsed :offset offset)
            new-offset (+ offset (:size parsed))]
        (recur (conj fields field-with-offset)
               new-offset
               (rest remaining))))))

(defn make-event-def
  "Create an event structure definition from field specifications.

   Returns a map with:
   - :name - Event name
   - :fields - Vector of field definitions with offsets
   - :size - Total structure size
   - :field-map - Map of field name to field info for quick lookup"
  [event-name field-specs]
  (let [fields (calculate-field-offsets field-specs)
        total-size (reduce + 0 (map :size fields))
        field-map (into {} (map (juxt :name identity) fields))]
    {:name event-name
     :fields fields
     :size total-size
     :field-map field-map}))

(defmacro defevent
  "Define an event structure for BPF programs.

   Creates a var containing the event definition that can be used with
   event-size, event-field-offset, and store-event-field functions.

   Field specifications are vectors of [name type] or [name type count].

   Supported types:
   - :u8, :i8     - 8-bit unsigned/signed
   - :u16, :i16   - 16-bit unsigned/signed
   - :u32, :i32   - 32-bit unsigned/signed
   - :u64, :i64   - 64-bit unsigned/signed
   - :char        - 8-bit character (for arrays)
   - :ptr         - 64-bit pointer

   Example:
     (defevent MyEvent
       [:field1 :u64]
       [:field2 :u32]
       [:name :char 16])"
  [event-name & field-specs]
  `(def ~event-name
     (make-event-def '~event-name '~(vec field-specs))))

;; ============================================================================
;; Event Structure Queries
;; ============================================================================

(defn event-size
  "Get the total size of an event structure in bytes.

   Parameters:
   - event-def: Event definition from defevent

   Example:
     (event-size ConnectionEvent) => 44"
  [event-def]
  (:size event-def))

(defn event-field-offset
  "Get the byte offset of a field within an event structure.

   Parameters:
   - event-def: Event definition from defevent
   - field-name: Field name keyword

   Example:
     (event-field-offset ConnectionEvent :pid) => 8"
  [event-def field-name]
  (get-in event-def [:field-map field-name :offset]))

(defn event-field-size
  "Get the size of a field in bytes.

   Parameters:
   - event-def: Event definition from defevent
   - field-name: Field name keyword

   Example:
     (event-field-size ConnectionEvent :comm) => 16"
  [event-def field-name]
  (get-in event-def [:field-map field-name :size]))

(defn event-field-type
  "Get the type of a field.

   Parameters:
   - event-def: Event definition from defevent
   - field-name: Field name keyword

   Example:
     (event-field-type ConnectionEvent :pid) => :u32"
  [event-def field-name]
  (get-in event-def [:field-map field-name :type]))

(defn event-fields
  "Get list of all field names in an event.

   Parameters:
   - event-def: Event definition from defevent

   Example:
     (event-fields ConnectionEvent) => [:timestamp :pid ...]"
  [event-def]
  (mapv :name (:fields event-def)))

;; ============================================================================
;; Event Store Operations
;; ============================================================================

(defn store-event-field
  "Generate instruction to store a value to an event field.

   Stores the value from value-reg to the field at event-reg + offset.

   Parameters:
   - event-reg: Register containing event buffer pointer
   - event-def: Event definition from defevent
   - field-name: Field name keyword
   - value-reg: Register containing value to store

   Returns a single stx instruction.

   Example:
     (store-event-field :r6 ConnectionEvent :pid :r7)
     ;; Stores r7 to r6 + 8 (pid offset)"
  [event-reg event-def field-name value-reg]
  (let [field-info (get-in event-def [:field-map field-name])
        _ (when-not field-info
            (throw (ex-info (str "Unknown field: " field-name)
                           {:event (:name event-def)
                            :field field-name
                            :available-fields (event-fields event-def)})))
        offset (:offset field-info)
        field-type (:type field-info)
        size-kw (get type-load-store-size field-type :dw)]
    (mem/stx size-kw event-reg value-reg offset)))

(defn store-event-imm
  "Generate instruction to store an immediate value to an event field.

   Stores the immediate value to the field at event-reg + offset.

   Parameters:
   - event-reg: Register containing event buffer pointer
   - event-def: Event definition from defevent
   - field-name: Field name keyword
   - imm-value: Immediate value to store

   Returns a single st instruction.

   Example:
     (store-event-imm :r6 ConnectionEvent :protocol 6)
     ;; Stores immediate 6 to protocol field"
  [event-reg event-def field-name imm-value]
  (let [field-info (get-in event-def [:field-map field-name])
        _ (when-not field-info
            (throw (ex-info (str "Unknown field: " field-name)
                           {:event (:name event-def) :field field-name})))
        offset (:offset field-info)
        field-type (:type field-info)
        size-kw (get type-load-store-size field-type :dw)]
    (mem/st size-kw event-reg offset imm-value)))

(defn zero-event-field
  "Generate instruction to zero an event field.

   Parameters:
   - event-reg: Register containing event buffer pointer
   - event-def: Event definition from defevent
   - field-name: Field name keyword

   Returns st instruction storing 0.

   Example:
     (zero-event-field :r6 ConnectionEvent :padding)"
  [event-reg event-def field-name]
  (store-event-imm event-reg event-def field-name 0))

(defn store-event-fields
  "Generate instructions to store multiple fields at once.

   Parameters:
   - event-reg: Register containing event buffer pointer
   - event-def: Event definition from defevent
   - field-values: Map of field-name to {:reg reg} or {:imm value}

   Returns vector of store instructions.

   Example:
     (store-event-fields :r6 ConnectionEvent
       {:pid {:reg :r7}
        :protocol {:imm 6}
        :direction {:imm 0}})"
  [event-reg event-def field-values]
  (vec (for [[field-name value-spec] field-values]
         (if-let [reg (:reg value-spec)]
           (store-event-field event-reg event-def field-name reg)
           (store-event-imm event-reg event-def field-name (:imm value-spec))))))
