(ns clj-ebpf.btf
  "BTF (BPF Type Format) parsing and type introspection"
  (:require [clj-ebpf.utils :as utils])
  (:import [java.nio.file Files Paths]
           [java.nio.file StandardOpenOption]
           [java.lang.foreign MemorySegment ValueLayout Arena]))

;; ============================================================================
;; BTF Constants
;; ============================================================================

(def btf-magic 0xeb9f)

(def btf-version 1)

(def btf-kind
  "BTF type kinds (19 types)"
  {:unknown 0
   :int 1
   :ptr 2
   :array 3
   :struct 4
   :union 5
   :enum 6
   :fwd 7
   :typedef 8
   :volatile 9
   :const 10
   :restrict 11
   :func 12
   :func-proto 13
   :var 14
   :datasec 15
   :float 16
   :decl-tag 17
   :type-tag 18
   :enum64 19})

(def btf-kind-num->keyword
  "Reverse map: kind number to keyword"
  (into {} (map (fn [[k v]] [v k]) btf-kind)))

(def btf-int-encoding
  "INT type encoding flags"
  {:signed 1
   :char 2
   :bool 4})

(def btf-var-linkage
  "Variable linkage types"
  {:static 0
   :global-alloc 1
   :global-extern 2})

(def btf-func-linkage
  "Function linkage types"
  {:static 0
   :global 1
   :extern 2})

;; ============================================================================
;; BTF Header
;; ============================================================================

(defn- read-btf-header
  "Read BTF header from memory segment.

  Header structure (24 bytes):
  - magic:    u16 (0xeb9f)
  - version:  u8
  - flags:    u8
  - hdr_len:  u32 (typically 24)
  - type_off: u32 (offset to type section, usually 0)
  - type_len: u32 (length of type section)
  - str_off:  u32 (offset to string section)
  - str_len:  u32 (length of string section)"
  [seg]
  (let [magic (.get seg ValueLayout/JAVA_SHORT_UNALIGNED 0)
        version (.get seg ValueLayout/JAVA_BYTE 2)
        flags (.get seg ValueLayout/JAVA_BYTE 3)
        hdr-len (.get seg ValueLayout/JAVA_INT_UNALIGNED 4)
        type-off (.get seg ValueLayout/JAVA_INT_UNALIGNED 8)
        type-len (.get seg ValueLayout/JAVA_INT_UNALIGNED 12)
        str-off (.get seg ValueLayout/JAVA_INT_UNALIGNED 16)
        str-len (.get seg ValueLayout/JAVA_INT_UNALIGNED 20)]
    {:magic magic
     :version version
     :flags flags
     :hdr-len hdr-len
     :type-off type-off
     :type-len type-len
     :str-off str-off
     :str-len str-len}))

;; ============================================================================
;; String Section
;; ============================================================================

(defn- read-btf-string
  "Read null-terminated string from BTF string section at offset."
  [seg base-offset str-offset]
  (when (>= str-offset 0)
    (let [start (+ base-offset str-offset)
          max-len 4096  ; Safety limit
          bytes (loop [i 0
                      result []]
                  (if (>= i max-len)
                    result
                    (let [b (.get seg ValueLayout/JAVA_BYTE (+ start i))]
                      (if (zero? b)
                        result
                        (recur (inc i) (conj result b))))))]
      (when (seq bytes)
        (String. (byte-array bytes) "UTF-8")))))

(defn- parse-string-section
  "Parse BTF string section into a lookup map."
  [seg base-offset str-len]
  (loop [offset 0
         strings {0 ""}]  ; First string is always empty
    (if (>= offset str-len)
      strings
      (let [str (read-btf-string seg base-offset offset)]
        (if (or (nil? str) (empty? str))
          (recur (inc offset) strings)
          (let [str-len (count (.getBytes str "UTF-8"))]
            (recur (+ offset str-len 1)  ; +1 for null terminator
                   (assoc strings offset str))))))))

;; ============================================================================
;; BTF Type Parsing
;; ============================================================================

(defn- parse-info-field
  "Parse BTF type info field.

  Info field packing:
  - bits 0-15:  vlen (variable length, e.g., number of struct members)
  - bits 16-23: unused
  - bits 24-28: kind (type kind)
  - bits 29-30: unused
  - bit 31:     kind_flag (used by some types for extra info)"
  [info]
  (let [vlen (bit-and info 0xFFFF)
        kind (bit-and (bit-shift-right info 24) 0x1F)
        kind-flag (if (bit-test info 31) 1 0)]
    {:vlen vlen
     :kind kind
     :kind-keyword (get btf-kind-num->keyword kind :unknown)
     :kind-flag kind-flag}))

(defn- read-btf-type-header
  "Read common BTF type header (12 bytes).

  Structure:
  - name_off: u32 (offset into string section)
  - info:     u32 (kind, vlen, flags)
  - size/type: u32 (size for sized types, type ID for references)"
  [seg offset]
  (let [name-off (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)
        info (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 4))
        size-or-type (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 8))
        info-parsed (parse-info-field info)]
    (merge info-parsed
           {:name-off name-off
            :size-or-type size-or-type})))

(defn- parse-btf-int
  "Parse BTF INT type (extra 4 bytes after header).

  INT data encoding:
  - bits 0-15:  offset (bit offset within byte, usually 0)
  - bits 16-23: bits (actual bit size, can be < byte-aligned)
  - bits 24-31: encoding (signed=1, char=2, bool=4)"
  [seg offset]
  (let [int-data (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)
        bit-offset (bit-and int-data 0xFFFF)
        bits (bit-and (bit-shift-right int-data 16) 0xFF)
        encoding (bit-and (bit-shift-right int-data 24) 0xFF)]
    {:bit-offset bit-offset
     :bits bits
     :encoding encoding
     :signed? (bit-test encoding 0)
     :char? (bit-test encoding 1)
     :bool? (bit-test encoding 2)}))

(defn- parse-btf-array
  "Parse BTF ARRAY type (12 bytes after header).

  Array structure:
  - type:       u32 (element type ID)
  - index_type: u32 (index type ID)
  - nelems:     u32 (number of elements)"
  [seg offset]
  (let [elem-type (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)
        index-type (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 4))
        nelems (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 8))]
    {:type elem-type
     :index-type index-type
     :nelems nelems}))

(defn- parse-btf-member
  "Parse BTF struct/union member (12 bytes).

  Member structure:
  - name_off: u32 (offset into string section)
  - type:     u32 (member type ID)
  - offset:   u32 (bit offset, or bitfield info if kind_flag=1)"
  [seg offset kind-flag]
  (let [name-off (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)
        type-id (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 4))
        offset-data (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 8))]
    (if (= kind-flag 1)
      ;; Bitfield: bits 0-23 are bit offset, bits 24-31 are bit size
      {:name-off name-off
       :type type-id
       :bit-offset (bit-and offset-data 0xFFFFFF)
       :bit-size (bit-shift-right offset-data 24)
       :bitfield? true}
      ;; Regular member: full 32 bits are bit offset
      {:name-off name-off
       :type type-id
       :bit-offset offset-data
       :bitfield? false})))

(defn- parse-btf-enum
  "Parse BTF ENUM value (8 bytes).

  Enum value structure:
  - name_off: u32 (offset into string section)
  - val:      i32 (enum value)"
  [seg offset]
  (let [name-off (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)
        val (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 4))]
    {:name-off name-off
     :val val}))

(defn- parse-btf-enum64
  "Parse BTF ENUM64 value (12 bytes).

  Enum64 value structure:
  - name_off: u32 (offset into string section)
  - val_lo32: u32 (low 32 bits of value)
  - val_hi32: u32 (high 32 bits of value)"
  [seg offset]
  (let [name-off (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)
        val-lo (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 4))
        val-hi (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 8))
        val (bit-or (bit-shift-left (long val-hi) 32) (bit-and (long val-lo) 0xFFFFFFFF))]
    {:name-off name-off
     :val val}))

(defn- parse-btf-param
  "Parse BTF function parameter (8 bytes).

  Parameter structure:
  - name_off: u32 (offset into string section)
  - type:     u32 (parameter type ID)"
  [seg offset]
  (let [name-off (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)
        type-id (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 4))]
    {:name-off name-off
     :type type-id}))

(defn- parse-btf-var
  "Parse BTF VAR extra data (4 bytes).

  Var structure:
  - linkage: u32 (static=0, global-alloc=1, global-extern=2)"
  [seg offset]
  (let [linkage (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)]
    {:linkage linkage
     :linkage-keyword (get (into {} (map (fn [[k v]] [v k]) btf-var-linkage))
                          linkage :unknown)}))

(defn- parse-btf-datasec-var
  "Parse BTF DATASEC variable (12 bytes).

  Datasec var structure:
  - type:   u32 (variable type ID)
  - offset: u32 (section offset)
  - size:   u32 (size in bytes)"
  [seg offset]
  (let [type-id (.get seg ValueLayout/JAVA_INT_UNALIGNED offset)
        var-offset (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 4))
        size (.get seg ValueLayout/JAVA_INT_UNALIGNED (+ offset 8))]
    {:type type-id
     :offset var-offset
     :size size}))

(defn- parse-btf-type
  "Parse a single BTF type at the given offset.
  Returns [type-info bytes-consumed]"
  [seg offset]
  (let [header (read-btf-type-header seg offset)
        kind (:kind-keyword header)
        vlen (:vlen header)
        kind-flag (:kind-flag header)
        base-size 12  ; Common header size
        extra-offset (+ offset base-size)]

    (case kind
      :int
      (let [int-info (parse-btf-int seg extra-offset)]
        [{:kind kind
          :name-off (:name-off header)
          :size (:size-or-type header)
          :int-info int-info}
         (+ base-size 4)])

      :ptr
      [{:kind kind
        :name-off (:name-off header)
        :type (:size-or-type header)}
       base-size]

      :array
      (let [array-info (parse-btf-array seg extra-offset)]
        [{:kind kind
          :name-off (:name-off header)
          :array-info array-info}
         (+ base-size 12)])

      (:struct :union)
      (let [members (vec (for [i (range vlen)]
                          (parse-btf-member seg
                                           (+ extra-offset (* i 12))
                                           kind-flag)))]
        [{:kind kind
          :name-off (:name-off header)
          :size (:size-or-type header)
          :members members
          :kind-flag kind-flag}
         (+ base-size (* vlen 12))])

      :enum
      (let [values (vec (for [i (range vlen)]
                         (parse-btf-enum seg (+ extra-offset (* i 8)))))]
        [{:kind kind
          :name-off (:name-off header)
          :size (:size-or-type header)
          :values values}
         (+ base-size (* vlen 8))])

      :enum64
      (let [values (vec (for [i (range vlen)]
                         (parse-btf-enum64 seg (+ extra-offset (* i 12)))))]
        [{:kind kind
          :name-off (:name-off header)
          :size (:size-or-type header)
          :values values
          :signed? (= kind-flag 1)}
         (+ base-size (* vlen 12))])

      (:fwd :typedef :volatile :const :restrict :type-tag)
      [{:kind kind
        :name-off (:name-off header)
        :type (:size-or-type header)}
       base-size]

      :func
      [{:kind kind
        :name-off (:name-off header)
        :type (:size-or-type header)
        :linkage vlen  ; For FUNC, vlen is linkage
        :linkage-keyword (get (into {} (map (fn [[k v]] [v k]) btf-func-linkage))
                             vlen :unknown)}
       base-size]

      :func-proto
      (let [params (vec (for [i (range vlen)]
                         (parse-btf-param seg (+ extra-offset (* i 8)))))]
        [{:kind kind
          :name-off (:name-off header)
          :return-type (:size-or-type header)
          :params params}
         (+ base-size (* vlen 8))])

      :var
      (let [var-info (parse-btf-var seg extra-offset)]
        [{:kind kind
          :name-off (:name-off header)
          :type (:size-or-type header)
          :var-info var-info}
         (+ base-size 4)])

      :datasec
      (let [vars (vec (for [i (range vlen)]
                       (parse-btf-datasec-var seg (+ extra-offset (* i 12)))))]
        [{:kind kind
          :name-off (:name-off header)
          :size (:size-or-type header)
          :vars vars}
         (+ base-size (* vlen 12))])

      :float
      [{:kind kind
        :name-off (:name-off header)
        :size (:size-or-type header)}
       base-size]

      :decl-tag
      (let [component-idx (.get seg ValueLayout/JAVA_INT_UNALIGNED extra-offset)]
        [{:kind kind
          :name-off (:name-off header)
          :type (:size-or-type header)
          :component-idx component-idx}
         (+ base-size 4)])

      ;; Unknown or unsupported type
      [{:kind :unknown
        :name-off (:name-off header)
        :raw-header header}
       base-size])))

(defn- parse-type-section
  "Parse all types in BTF type section.
  Returns vector of types indexed by type ID (starting at 1)."
  [seg base-offset type-len]
  (loop [offset 0
         types [nil]  ; Type ID 0 is reserved (void)
         type-id 1]
    (if (>= offset type-len)
      types
      (let [[type-info bytes-consumed] (parse-btf-type seg (+ base-offset offset))]
        (recur (+ offset bytes-consumed)
               (conj types (assoc type-info :id type-id))
               (inc type-id))))))

;; ============================================================================
;; BTF File Loading
;; ============================================================================

(defn load-btf-file
  "Load and parse a BTF file.

  Parameters:
  - path: Path to BTF file (default: /sys/kernel/btf/vmlinux)

  Returns a map with:
  - :header - BTF header information
  - :strings - String section lookup map
  - :types - Vector of types indexed by type ID

  Example:
    (load-btf-file)
    (load-btf-file \"/sys/kernel/btf/vmlinux\")"
  ([]
   (load-btf-file "/sys/kernel/btf/vmlinux"))
  ([path]
   (let [file-path (Paths/get path (make-array String 0))
         bytes (Files/readAllBytes file-path)
         arena (Arena/ofConfined)
         seg (MemorySegment/ofArray bytes)]
     (try
       ;; Parse header
       (let [header (read-btf-header seg)
             magic (:magic header)]

         ;; Validate magic number
         (when (not= magic btf-magic)
           (throw (ex-info "Invalid BTF magic number"
                          {:expected btf-magic
                           :actual magic})))

         ;; Calculate section offsets
         (let [hdr-len (:hdr-len header)
               type-base (+ hdr-len (:type-off header))
               str-base (+ hdr-len (:str-off header))

               ;; Parse sections
               strings (parse-string-section seg str-base (:str-len header))
               types (parse-type-section seg type-base (:type-len header))]

           {:header header
            :strings strings
            :types types
            :path path}))
       (finally
         (.close arena))))))

;; ============================================================================
;; Type Introspection
;; ============================================================================

(defn get-type-by-id
  "Get type information by type ID.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - type-id: Type ID to look up

  Returns type information or nil if not found.

  Example:
    (get-type-by-id btf 42)"
  [btf type-id]
  (when (and (>= type-id 0) (< type-id (count (:types btf))))
    (get (:types btf) type-id)))

(defn get-type-name
  "Get the name of a type.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - type-info: Type information (from get-type-by-id)

  Returns the type name string or nil.

  Example:
    (get-type-name btf type-info)"
  [btf type-info]
  (when type-info
    (get (:strings btf) (:name-off type-info))))

(defn find-type-by-name
  "Find type by name.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - name: Type name to search for

  Returns type information or nil if not found.

  Example:
    (find-type-by-name btf \"task_struct\")"
  [btf name]
  (first (filter #(= (get-type-name btf %) name) (:types btf))))

(defn get-struct-members
  "Get struct or union members with names.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - type-info: Struct/union type information

  Returns vector of members with :name added.

  Example:
    (get-struct-members btf struct-type)"
  [btf type-info]
  (when (and type-info (#{:struct :union} (:kind type-info)))
    (vec (for [member (:members type-info)]
           (assoc member :name (get (:strings btf) (:name-off member)))))))

(defn get-enum-values
  "Get enum values with names.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - type-info: Enum type information

  Returns vector of enum values with :name added.

  Example:
    (get-enum-values btf enum-type)"
  [btf type-info]
  (when (and type-info (#{:enum :enum64} (:kind type-info)))
    (vec (for [value (:values type-info)]
           (assoc value :name (get (:strings btf) (:name-off value)))))))

(defn get-func-params
  "Get function parameters with names.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - type-info: Function prototype type information

  Returns vector of parameters with :name added.

  Example:
    (get-func-params btf func-proto-type)"
  [btf type-info]
  (when (and type-info (= :func-proto (:kind type-info)))
    (vec (for [param (:params type-info)]
           (assoc param :name (get (:strings btf) (:name-off param)))))))

(defn resolve-type
  "Resolve a type through typedef/const/volatile/restrict indirections.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - type-id: Type ID to resolve

  Returns the resolved type ID (may be the same if not an indirection).

  Example:
    (resolve-type btf typedef-id)"
  [btf type-id]
  (loop [id type-id
         visited #{}]
    (if (contains? visited id)
      id  ; Cycle detected, return current ID
      (let [type-info (get-type-by-id btf id)]
        (if (and type-info (#{:typedef :const :volatile :restrict} (:kind type-info)))
          (recur (:type type-info) (conj visited id))
          id)))))

(defn get-type-size
  "Get the size of a type in bytes.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - type-id: Type ID

  Returns size in bytes or nil if size is not defined.

  Example:
    (get-type-size btf type-id)"
  [btf type-id]
  (let [resolved-id (resolve-type btf type-id)
        type-info (get-type-by-id btf resolved-id)]
    (when type-info
      (case (:kind type-info)
        (:int :float :struct :union :enum :enum64 :datasec)
        (:size type-info)

        :ptr
        8  ; 64-bit pointers

        :array
        (let [elem-type-id (get-in type-info [:array-info :type])
              elem-size (get-type-size btf elem-type-id)
              nelems (get-in type-info [:array-info :nelems])]
          (when (and elem-size nelems)
            (* elem-size nelems)))

        nil))))

(defn btf-available?
  "Check if BTF is available on this system.

  Returns true if /sys/kernel/btf/vmlinux exists and is readable.

  Example:
    (btf-available?) => true"
  []
  (try
    (let [path (Paths/get "/sys/kernel/btf/vmlinux" (make-array String 0))]
      (and (Files/exists path (make-array java.nio.file.LinkOption 0))
           (Files/isReadable path)))
    (catch Exception _ false)))

(defn list-types
  "List all types of a specific kind.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - kind: Type kind keyword (e.g., :struct, :func, :typedef)

  Returns vector of matching types.

  Example:
    (list-types btf :struct)
    (list-types btf :func)"
  [btf kind]
  (filterv #(= (:kind %) kind) (:types btf)))

(defn find-function
  "Find a function by name.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - name: Function name

  Returns function type information or nil.

  Example:
    (find-function btf \"sys_read\")"
  [btf name]
  (first (filter #(and (= (:kind %) :func)
                      (= (get-type-name btf %) name))
                (:types btf))))

(defn get-function-signature
  "Get function signature with return type and parameter names/types.

  Parameters:
  - btf: BTF data (from load-btf-file)
  - func-type: Function type information

  Returns map with :return-type, :params.

  Example:
    (get-function-signature btf func-type)"
  [btf func-type]
  (when (= (:kind func-type) :func)
    (let [proto-id (:type func-type)
          proto (get-type-by-id btf proto-id)]
      (when (= (:kind proto) :func-proto)
        {:return-type (:return-type proto)
         :params (get-func-params btf proto)}))))
