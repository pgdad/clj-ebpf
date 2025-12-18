(ns clj-ebpf.dsl.tracepoint
  "High-level tracepoint definition macros for BPF programs.

   Provides the deftracepoint macro for defining tracepoint handlers with
   automatic field extraction from tracepoint format files.

   Tracepoints are static kernel instrumentation points that provide a
   stable ABI, unlike kprobes which depend on function signatures.

   Example:
     (deftracepoint-instructions sched-switch
       {:category \"sched\"
        :name \"sched_switch\"
        :fields [:prev_pid :next_pid]}
       (concat
         (helper-get-current-pid-tgid)
         [(mov-reg :r6 :r0)]
         [(exit-insn)]))"
  (:require [clj-ebpf.dsl :as dsl]
            [clojure.string :as str]))

;; ============================================================================
;; Tracepoint Format Parsing
;; ============================================================================

(def ^:private tracefs-paths
  "Possible paths to tracefs"
  ["/sys/kernel/debug/tracing"
   "/sys/kernel/tracing"])

(defn find-tracefs
  "Find the tracefs mount point.
   Returns the path or nil if not found."
  []
  (first (filter #(try
                    (.exists (java.io.File. (str % "/events")))
                    (catch Exception _ false))
                 tracefs-paths)))

(defn tracepoint-format-path
  "Get the path to a tracepoint's format file.

   Parameters:
   - category: Tracepoint category (e.g., \"sched\", \"syscalls\")
   - name: Tracepoint name (e.g., \"sched_switch\")

   Returns path string."
  [category name]
  (if-let [tracefs (find-tracefs)]
    (str tracefs "/events/" category "/" name "/format")
    (str "/sys/kernel/debug/tracing/events/" category "/" name "/format")))

(defn tracepoint-id-path
  "Get the path to a tracepoint's ID file.

   Parameters:
   - category: Tracepoint category
   - name: Tracepoint name

   Returns path string."
  [category name]
  (if-let [tracefs (find-tracefs)]
    (str tracefs "/events/" category "/" name "/id")
    (str "/sys/kernel/debug/tracing/events/" category "/" name "/id")))

(defn- parse-field-line
  "Parse a single field line from format file.

   Example line:
   '\\tfield:pid_t prev_pid;\\toffset:8;\\tsize:4;\\tsigned:1;'

   Returns map with :name, :offset, :size, :signed, :type or nil."
  [line]
  (when (and line (str/includes? line "field:"))
    (let [field-match (re-find #"field:([^;]+)" line)
          offset-match (re-find #"offset:(\d+)" line)
          size-match (re-find #"size:(\d+)" line)
          signed-match (re-find #"signed:(\d+)" line)]
      (when (and field-match offset-match size-match)
        (let [field-str (str/trim (second field-match))
              ;; Parse type and name from "type name" or "type name[N]"
              parts (str/split field-str #"\s+")
              field-name (last parts)
              field-type (str/join " " (butlast parts))
              ;; Extract array size if present
              array-match (re-find #"\[(\d+)\]" field-name)
              clean-name (str/replace field-name #"\[.*\]" "")]
          {:name (keyword clean-name)
           :offset (Long/parseLong (second offset-match))
           :size (Long/parseLong (second size-match))
           :signed (= "1" (second signed-match))
           :type field-type
           :array-size (when array-match (Long/parseLong (second array-match)))})))))

(defn parse-tracepoint-format
  "Parse a tracepoint format file and extract field information.

   Parameters:
   - category: Tracepoint category (e.g., \"sched\")
   - name: Tracepoint name (e.g., \"sched_switch\")

   Returns map with:
   - :category - Category name
   - :name - Tracepoint name
   - :id - Tracepoint ID (if available)
   - :fields - Vector of field maps with :name, :offset, :size, :type
   - :common-fields - Vector of common field maps

   Throws if format file cannot be read."
  [category tp-name]
  (let [format-path (tracepoint-format-path category tp-name)
        id-path (tracepoint-id-path category tp-name)]
    (try
      (let [content (slurp format-path)
            lines (str/split-lines content)
            id (try (Long/parseLong (str/trim (slurp id-path)))
                   (catch Exception _ nil))
            parsed-fields (keep parse-field-line lines)
            ;; Separate common fields (start with common_) from regular fields
            common-fields (filter #(str/starts-with? (name (:name %)) "common_") parsed-fields)
            user-fields (remove #(str/starts-with? (name (:name %)) "common_") parsed-fields)]
        {:category category
         :name tp-name
         :id id
         :common-fields (vec common-fields)
         :fields (vec user-fields)})
      (catch java.io.FileNotFoundException _
        (throw (ex-info "Tracepoint format file not found"
                       {:category category
                        :name tp-name
                        :path format-path})))
      (catch Exception e
        (throw (ex-info "Failed to parse tracepoint format"
                       {:category category
                        :name tp-name
                        :cause (.getMessage e)}))))))

(defn- format-cache
  "Atom for caching parsed format files."
  []
  (atom {}))

(def ^:private format-cache-atom (format-cache))

(defn get-tracepoint-format
  "Get parsed tracepoint format, using cache if available.

   Parameters:
   - category: Tracepoint category
   - name: Tracepoint name

   Returns parsed format map."
  [category tp-name]
  (let [cache-key [category tp-name]]
    (if-let [cached (get @format-cache-atom cache-key)]
      cached
      (let [parsed (parse-tracepoint-format category tp-name)]
        (swap! format-cache-atom assoc cache-key parsed)
        parsed))))

(defn clear-format-cache!
  "Clear the tracepoint format cache."
  []
  (reset! format-cache-atom {}))

;; ============================================================================
;; Field Access Functions
;; ============================================================================

(defn tracepoint-field-offset
  "Get the byte offset of a field in a tracepoint context.

   Parameters:
   - format: Parsed format map from parse-tracepoint-format
   - field-name: Keyword name of the field

   Returns offset as long, or throws if field not found."
  [format field-name]
  (let [all-fields (concat (:common-fields format) (:fields format))
        field (first (filter #(= (:name %) field-name) all-fields))]
    (if field
      (:offset field)
      (throw (ex-info "Tracepoint field not found"
                     {:field field-name
                      :available-fields (map :name all-fields)})))))

(defn tracepoint-field-size
  "Get the size in bytes of a field in a tracepoint context.

   Parameters:
   - format: Parsed format map
   - field-name: Keyword name of the field

   Returns size as long."
  [format field-name]
  (let [all-fields (concat (:common-fields format) (:fields format))
        field (first (filter #(= (:name %) field-name) all-fields))]
    (if field
      (:size field)
      (throw (ex-info "Tracepoint field not found"
                     {:field field-name})))))

(defn tracepoint-field-info
  "Get complete information about a tracepoint field.

   Parameters:
   - format: Parsed format map
   - field-name: Keyword name of the field

   Returns field map with :name, :offset, :size, :type, :signed."
  [format field-name]
  (let [all-fields (concat (:common-fields format) (:fields format))]
    (first (filter #(= (:name %) field-name) all-fields))))

(defn tracepoint-fields
  "Get all field names from a tracepoint format.

   Parameters:
   - format: Parsed format map
   - include-common?: Include common_ fields (default false)

   Returns vector of field name keywords."
  ([format] (tracepoint-fields format false))
  ([format include-common?]
   (if include-common?
     (mapv :name (concat (:common-fields format) (:fields format)))
     (mapv :name (:fields format)))))

;; ============================================================================
;; Instruction Generation
;; ============================================================================

(defn tracepoint-read-field
  "Generate instruction to read a field from tracepoint context.

   Parameters:
   - ctx-reg: Register containing context pointer (typically :r1)
   - format: Parsed format map
   - field-name: Keyword name of the field to read
   - dst-reg: Destination register

   Returns ldx instruction with appropriate size."
  [ctx-reg format field-name dst-reg]
  (let [field (tracepoint-field-info format field-name)
        offset (:offset field)
        size (:size field)]
    (case size
      1 (dsl/ldx :b dst-reg ctx-reg offset)
      2 (dsl/ldx :h dst-reg ctx-reg offset)
      4 (dsl/ldx :w dst-reg ctx-reg offset)
      8 (dsl/ldx :dw dst-reg ctx-reg offset)
      ;; For arrays or large fields, default to loading pointer/address
      (dsl/ldx :dw dst-reg ctx-reg offset))))

(defn tracepoint-read-fields
  "Generate instructions to read multiple fields into registers.

   Parameters:
   - ctx-reg: Register containing context pointer
   - format: Parsed format map
   - field-bindings: Map of {field-name dest-reg}

   Returns vector of ldx instructions."
  [ctx-reg format field-bindings]
  (vec (for [[field-name dest-reg] field-bindings]
         (tracepoint-read-field ctx-reg format field-name dest-reg))))

;; ============================================================================
;; Prologue Generation
;; ============================================================================

(defn tracepoint-prologue
  "Generate standard tracepoint prologue instructions.

   Saves the context pointer and reads specified fields.

   Parameters:
   - ctx-save-reg: Register to save context pointer (optional)
   - format: Parsed format map
   - field-bindings: Map of {field-name dest-reg}

   Returns vector of instructions.

   Example:
     (tracepoint-prologue :r9 format {:prev_pid :r6 :next_pid :r7})
     ;; Generates:
     ;; mov r9, r1          ; Save context pointer
     ;; ldxw r6, [r1 + 8]   ; Load prev_pid
     ;; ldxw r7, [r1 + 12]  ; Load next_pid"
  ([format field-bindings]
   (tracepoint-prologue nil format field-bindings))
  ([ctx-save-reg format field-bindings]
   (vec (concat
         (when ctx-save-reg
           [(dsl/mov-reg ctx-save-reg :r1)])
         (tracepoint-read-fields :r1 format field-bindings)))))

;; ============================================================================
;; Static Format Definitions (for common tracepoints)
;; ============================================================================

(def common-tracepoint-formats
  "Pre-defined formats for commonly used tracepoints.
   These can be used when tracefs is not available (e.g., in CI)."
  {:sched/sched_switch
   {:category "sched"
    :name "sched_switch"
    :fields [{:name :prev_comm :offset 8 :size 16 :type "char"}
             {:name :prev_pid :offset 24 :size 4 :type "pid_t" :signed true}
             {:name :prev_prio :offset 28 :size 4 :type "int" :signed true}
             {:name :prev_state :offset 32 :size 8 :type "long" :signed true}
             {:name :next_comm :offset 40 :size 16 :type "char"}
             {:name :next_pid :offset 56 :size 4 :type "pid_t" :signed true}
             {:name :next_prio :offset 60 :size 4 :type "int" :signed true}]
    :common-fields [{:name :common_type :offset 0 :size 2 :type "unsigned short"}
                    {:name :common_flags :offset 2 :size 1 :type "unsigned char"}
                    {:name :common_preempt_count :offset 3 :size 1 :type "unsigned char"}
                    {:name :common_pid :offset 4 :size 4 :type "int" :signed true}]}

   :sched/sched_process_exec
   {:category "sched"
    :name "sched_process_exec"
    :fields [{:name :filename :offset 8 :size 8 :type "char *"}
             {:name :pid :offset 16 :size 4 :type "pid_t" :signed true}
             {:name :old_pid :offset 20 :size 4 :type "pid_t" :signed true}]
    :common-fields [{:name :common_type :offset 0 :size 2 :type "unsigned short"}
                    {:name :common_flags :offset 2 :size 1 :type "unsigned char"}
                    {:name :common_preempt_count :offset 3 :size 1 :type "unsigned char"}
                    {:name :common_pid :offset 4 :size 4 :type "int" :signed true}]}

   :sched/sched_process_exit
   {:category "sched"
    :name "sched_process_exit"
    :fields [{:name :comm :offset 8 :size 16 :type "char"}
             {:name :pid :offset 24 :size 4 :type "pid_t" :signed true}
             {:name :prio :offset 28 :size 4 :type "int" :signed true}]
    :common-fields [{:name :common_type :offset 0 :size 2 :type "unsigned short"}
                    {:name :common_flags :offset 2 :size 1 :type "unsigned char"}
                    {:name :common_preempt_count :offset 3 :size 1 :type "unsigned char"}
                    {:name :common_pid :offset 4 :size 4 :type "int" :signed true}]}

   :syscalls/sys_enter_execve
   {:category "syscalls"
    :name "sys_enter_execve"
    :fields [{:name :__syscall_nr :offset 8 :size 4 :type "int" :signed true}
             {:name :filename :offset 16 :size 8 :type "const char *"}
             {:name :argv :offset 24 :size 8 :type "const char * const *"}
             {:name :envp :offset 32 :size 8 :type "const char * const *"}]
    :common-fields [{:name :common_type :offset 0 :size 2 :type "unsigned short"}
                    {:name :common_flags :offset 2 :size 1 :type "unsigned char"}
                    {:name :common_preempt_count :offset 3 :size 1 :type "unsigned char"}
                    {:name :common_pid :offset 4 :size 4 :type "int" :signed true}]}

   :syscalls/sys_exit_execve
   {:category "syscalls"
    :name "sys_exit_execve"
    :fields [{:name :__syscall_nr :offset 8 :size 4 :type "int" :signed true}
             {:name :ret :offset 16 :size 8 :type "long" :signed true}]
    :common-fields [{:name :common_type :offset 0 :size 2 :type "unsigned short"}
                    {:name :common_flags :offset 2 :size 1 :type "unsigned char"}
                    {:name :common_preempt_count :offset 3 :size 1 :type "unsigned char"}
                    {:name :common_pid :offset 4 :size 4 :type "int" :signed true}]}

   :raw_syscalls/sys_enter
   {:category "raw_syscalls"
    :name "sys_enter"
    :fields [{:name :id :offset 8 :size 8 :type "long" :signed true}
             {:name :args :offset 16 :size 48 :type "unsigned long" :array-size 6}]
    :common-fields [{:name :common_type :offset 0 :size 2 :type "unsigned short"}
                    {:name :common_flags :offset 2 :size 1 :type "unsigned char"}
                    {:name :common_preempt_count :offset 3 :size 1 :type "unsigned char"}
                    {:name :common_pid :offset 4 :size 4 :type "int" :signed true}]}

   :raw_syscalls/sys_exit
   {:category "raw_syscalls"
    :name "sys_exit"
    :fields [{:name :id :offset 8 :size 8 :type "long" :signed true}
             {:name :ret :offset 16 :size 8 :type "long" :signed true}]
    :common-fields [{:name :common_type :offset 0 :size 2 :type "unsigned short"}
                    {:name :common_flags :offset 2 :size 1 :type "unsigned char"}
                    {:name :common_preempt_count :offset 3 :size 1 :type "unsigned char"}
                    {:name :common_pid :offset 4 :size 4 :type "int" :signed true}]}})

(defn get-static-format
  "Get a static tracepoint format definition.

   Parameters:
   - category: Tracepoint category
   - name: Tracepoint name

   Returns format map or nil if not in static definitions."
  [category tp-name]
  (get common-tracepoint-formats (keyword category tp-name)))

(defn get-format
  "Get tracepoint format, preferring runtime parsing with static fallback.

   Parameters:
   - category: Tracepoint category
   - name: Tracepoint name

   Returns format map."
  [category tp-name]
  (try
    (get-tracepoint-format category tp-name)
    (catch Exception _
      (or (get-static-format category tp-name)
          (throw (ex-info "Tracepoint format not available"
                         {:category category
                          :name tp-name}))))))

;; ============================================================================
;; Complete Tracepoint Builder
;; ============================================================================

(defn build-tracepoint-program
  "Build a complete tracepoint program with standard structure.

   Parameters:
   - opts: Map with:
     :category - Tracepoint category
     :name - Tracepoint name
     :ctx-reg - Register to save context pointer (optional)
     :fields - Map of {field-name dest-reg} bindings
     :body - Vector of body instructions
     :return-value - Value to return (default 0)

   Returns assembled program bytes.

   Example:
     (build-tracepoint-program
       {:category \"sched\"
        :name \"sched_switch\"
        :fields {:prev_pid :r6 :next_pid :r7}
        :body [(mov :r0 0)]
        :return-value 0})"
  [{:keys [category name ctx-reg fields body return-value]
    :or {fields {} return-value 0}}]
  (let [format (get-format category name)]
    (dsl/assemble
     (vec (concat
           ;; Prologue: save context and load fields
           (tracepoint-prologue ctx-reg format fields)
           ;; Body instructions
           body
           ;; Epilogue: set return value and exit
           [(dsl/mov :r0 return-value)
            (dsl/exit-insn)])))))

;; ============================================================================
;; Tracepoint Program Definition Macro
;; ============================================================================

(defmacro deftracepoint-instructions
  "Define a tracepoint program as a function returning instructions.

   This macro creates a function that returns a vector of BPF instructions
   for a tracepoint handler. It sets up automatic field loading based on
   the tracepoint format.

   Parameters:
   - name: Name for the defined function
   - options: Map with:
     :category - Tracepoint category (e.g., \"sched\")
     :name - Tracepoint name (e.g., \"sched_switch\")
     :fields - Map of {field-name dest-reg} bindings
     :ctx-reg - Register to save context pointer (optional)
   - body: Body instructions (should return vector of instructions)

   Note: Uses static format definitions when tracefs is not available.

   Example:
     (deftracepoint-instructions sched-switch-handler
       {:category \"sched\"
        :name \"sched_switch\"
        :fields {:prev_pid :r6 :next_pid :r7}
        :ctx-reg :r9}
       (concat
         (helper-get-current-pid-tgid)
         [(mov-reg :r8 :r0)]
         [(mov :r0 0)
          (exit-insn)]))"
  [fn-name options & body]
  (let [category (:category options)
        tp-name (:name options)
        fields (:fields options {})
        ctx-reg (:ctx-reg options)]
    `(defn ~fn-name
       ~(str "Tracepoint handler for " category "/" tp-name ".\n"
             "Fields: " (pr-str fields))
       []
       (let [format# (get-format ~category ~tp-name)]
         (vec (concat
               (tracepoint-prologue ~ctx-reg format# ~fields)
               ~@body))))))

(defmacro defraw-tracepoint-instructions
  "Define a raw tracepoint program as a function returning instructions.

   Raw tracepoints have lower overhead but provide raw context access.
   The context structure depends on the specific tracepoint.

   Parameters:
   - name: Name for the defined function
   - options: Map with :name (raw tracepoint name), :ctx-reg
   - body: Body instructions

   Example:
     (defraw-tracepoint-instructions sys-enter-handler
       {:name \"sys_enter\"
        :ctx-reg :r9}
       (concat
         [(ldxdw :r6 :r1 0)]  ; Load syscall number
         [(mov :r0 0)
          (exit-insn)]))"
  [fn-name options & body]
  (let [tp-name (:name options)
        ctx-reg (:ctx-reg options)]
    `(defn ~fn-name
       ~(str "Raw tracepoint handler for " tp-name ".")
       []
       (vec (concat
             ~(when ctx-reg
                `[(dsl/mov-reg ~ctx-reg :r1)])
             ~@body)))))

;; ============================================================================
;; Utility Functions
;; ============================================================================

(defn tracepoint-section-name
  "Generate ELF section name for a tracepoint program.

   Parameters:
   - category: Tracepoint category
   - name: Tracepoint name

   Returns section name like \"tracepoint/sched/sched_switch\""
  [category tp-name]
  (str "tracepoint/" category "/" tp-name))

(defn raw-tracepoint-section-name
  "Generate ELF section name for a raw tracepoint program.

   Parameters:
   - name: Raw tracepoint name

   Returns section name like \"raw_tracepoint/sys_enter\""
  [tp-name]
  (str "raw_tracepoint/" tp-name))

(defn make-tracepoint-program-info
  "Create program metadata for a tracepoint.

   Parameters:
   - category: Tracepoint category
   - tp-name: Tracepoint name
   - program-name: Name for the BPF program
   - instructions: Program instructions

   Returns map with program metadata for loading."
  [category tp-name program-name instructions]
  {:name program-name
   :section (tracepoint-section-name category tp-name)
   :type :tracepoint
   :category category
   :tracepoint tp-name
   :instructions instructions})

(defn make-raw-tracepoint-program-info
  "Create program metadata for a raw tracepoint.

   Parameters:
   - tp-name: Raw tracepoint name
   - program-name: Name for the BPF program
   - instructions: Program instructions

   Returns map with program metadata for loading."
  [tp-name program-name instructions]
  {:name program-name
   :section (raw-tracepoint-section-name tp-name)
   :type :raw-tracepoint
   :tracepoint tp-name
   :instructions instructions})

;; ============================================================================
;; Tracepoint Discovery
;; ============================================================================

(defn list-tracepoint-categories
  "List available tracepoint categories.

   Returns vector of category names, or nil if tracefs not available."
  []
  (when-let [tracefs (find-tracefs)]
    (let [events-dir (java.io.File. (str tracefs "/events"))]
      (when (.exists events-dir)
        (->> (.listFiles events-dir)
             (filter #(.isDirectory %))
             (map #(.getName %))
             (remove #(str/starts-with? % "."))
             sort
             vec)))))

(defn list-tracepoints
  "List available tracepoints in a category.

   Parameters:
   - category: Category name (e.g., \"sched\")

   Returns vector of tracepoint names, or nil if not available."
  [category]
  (when-let [tracefs (find-tracefs)]
    (let [cat-dir (java.io.File. (str tracefs "/events/" category))]
      (when (.exists cat-dir)
        (->> (.listFiles cat-dir)
             (filter #(.isDirectory %))
             (map #(.getName %))
             (filter #(.exists (java.io.File. (str cat-dir "/" % "/id"))))
             sort
             vec)))))

(defn tracepoint-exists?
  "Check if a tracepoint exists.

   Parameters:
   - category: Tracepoint category
   - name: Tracepoint name

   Returns true if the tracepoint exists."
  [category tp-name]
  (let [id-path (tracepoint-id-path category tp-name)]
    (.exists (java.io.File. id-path))))
