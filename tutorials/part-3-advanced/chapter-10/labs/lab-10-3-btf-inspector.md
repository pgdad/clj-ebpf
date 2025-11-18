# Lab 10.3: BTF Structure Inspector

## Objective

Build a comprehensive BTF (BPF Type Format) inspector tool that explores kernel structures, generates CO-RE access code, and compares structures across kernel versions. This is a practical developer tool for CO-RE programming.

## Learning Goals

- Navigate BTF type information
- Query structure layouts programmatically
- Generate CO-RE access code
- Compare structures across kernels
- Build developer productivity tools

## Background

When developing CO-RE programs, you need to understand:
- Which fields exist in a structure
- Field offsets and sizes
- Field types and relationships
- How structures differ across kernel versions

A BTF inspector tool makes this easy, serving as both a learning aid and a development tool.

## Tool Architecture

```
┌──────────────────────────────────────┐
│  BTF Inspector CLI                   │
├──────────────────────────────────────┤
│  Commands:                           │
│  - inspect <struct>                  │
│  - compare <struct> <ver1> <ver2>    │
│  - generate-accessor <struct> <field>│
│  - list-structs [pattern]            │
│  - search-field <name>               │
│  - graph-deps <struct>               │
└──────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────┐
│  BTF Parser                          │
├──────────────────────────────────────┤
│  - Parse /sys/kernel/btf/vmlinux     │
│  - Extract type information          │
│  - Build type relationship graph     │
│  - Cache parsed data                 │
└──────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────┐
│  BTF Data (/sys/kernel/btf/vmlinux) │
└──────────────────────────────────────┘
```

## Implementation

```clojure
(ns btf-inspector.core
  (:require [clj-ebpf.btf :as btf]
            [clj-ebpf.core :as bpf]
            [clojure.string :as str]
            [clojure.pprint :as pp]
            [clojure.tools.cli :as cli]))

;; ============================================================================
;; BTF Data Access
;; ============================================================================

(defn check-btf!
  "Verify BTF is available"
  []
  (when-not (btf/btf-available?)
    (println "ERROR: BTF not available")
    (println "Ensure kernel was compiled with CONFIG_DEBUG_INFO_BTF=y")
    (System/exit 1)))

(defn get-kernel-info
  "Get kernel version information"
  []
  (let [ver (bpf/get-kernel-version)
        major (bit-shift-right ver 16)
        minor (bit-and (bit-shift-right ver 8) 0xFF)
        patch (bit-and ver 0xFF)]
    {:version ver
     :major major
     :minor minor
     :patch patch
     :string (format "%d.%d.%d" major minor patch)}))

;; ============================================================================
;; Structure Inspection
;; ============================================================================

(defn inspect-structure
  "Inspect a kernel structure and display detailed information"
  [struct-name]
  (if-let [struct-info (btf/get-struct-info struct-name)]
    (do
      (println (str "\n" (str/upper-case struct-name)))
      (println (str/join "" (repeat (count struct-name) "=")))
      (println (format "Size: %d bytes (0x%x)" (:size struct-info) (:size struct-info)))
      (println (format "Fields: %d" (count (:fields struct-info))))
      (println)

      ;; Display fields in a table
      (println "OFFSET   SIZE  TYPE                    NAME")
      (println "================================================================")
      (doseq [field (sort-by :offset (:fields struct-info))]
        (let [{:keys [name offset size type]} field
              type-str (if (coll? type)
                        (str (first type) " " (second type))
                        (str type))]
          (printf "%-8d %-5d %-23s %s\n"
                  offset
                  (or size 0)
                  (subs (str type-str "                    ") 0 23)
                  name)))
      (println))
    (println (format "Structure '%s' not found in BTF" struct-name))))

(defn inspect-structure-compact
  "Compact view of structure (field names only)"
  [struct-name]
  (if-let [struct-info (btf/get-struct-info struct-name)]
    (do
      (println (format "\n%s (%d bytes, %d fields):"
                       struct-name
                       (:size struct-info)
                       (count (:fields struct-info))))
      (let [fields (map :name (:fields struct-info))
            columns 4
            rows (partition-all columns fields)]
        (doseq [row rows]
          (println (str "  " (str/join ", " row))))))
    (println (format "Structure '%s' not found" struct-name))))

;; ============================================================================
;; Field Search
;; ============================================================================

(defn search-field
  "Search for a field name across all structures"
  [field-name]
  (println (format "\nSearching for field '%s'...\n" field-name))
  (let [all-structs (btf/list-all-structs)
        matches (atom [])]
    (doseq [struct-name all-structs]
      (when-let [struct-info (btf/get-struct-info struct-name)]
        (doseq [field (:fields struct-info)]
          (when (str/includes? (:name field) field-name)
            (swap! matches conj
                   {:struct struct-name
                    :field (:name field)
                    :offset (:offset field)
                    :type (:type field)})))))

    (if (seq @matches)
      (do
        (println "STRUCT                  FIELD               OFFSET  TYPE")
        (println "================================================================")
        (doseq [match (take 50 @matches)]
          (printf "%-23s %-20s %-7d %s\n"
                  (:struct match)
                  (:field match)
                  (:offset match)
                  (str (:type match))))
        (when (> (count @matches) 50)
          (println (format "\n... and %d more matches" (- (count @matches) 50)))))
      (println "No matches found"))))

;; ============================================================================
;; Structure Comparison
;; ============================================================================

(defn compare-structures
  "Compare structure layouts (simulated for different kernels)"
  [struct-name kernel-ver-1 kernel-ver-2]
  (println (format "\n=== Comparing %s ===\n" struct-name))
  (println (format "Kernel %s vs Kernel %s\n" kernel-ver-1 kernel-ver-2))

  ;; In practice, you'd load BTF from different kernel versions
  ;; Here we'll show the current kernel and simulate changes

  (if-let [struct-info (btf/get-struct-info struct-name)]
    (do
      (println "FIELD                OFFSET-1  OFFSET-2  DIFF    STATUS")
      (println "================================================================")
      (doseq [field (:fields struct-info)]
        (let [offset (:offset field)
              ;; Simulate offset changes (in real tool, load from actual BTF)
              offset-2 (+ offset (rand-int 8))
              diff (- offset-2 offset)
              status (cond
                       (zero? diff) "SAME"
                       (pos? diff) "MOVED +"
                       :else "MOVED -")]
          (printf "%-20s %-9d %-9d %-7d %s\n"
                  (:name field)
                  offset
                  offset-2
                  (Math/abs diff)
                  status))))
    (println (format "Structure '%s' not found" struct-name))))

;; ============================================================================
;; Code Generation
;; ============================================================================

(defn generate-field-accessor
  "Generate CO-RE accessor code for a field"
  [struct-name field-name]
  (println (format "\n=== CO-RE Accessor for %s->%s ===\n" struct-name field-name))

  (if-let [field-info (btf/get-field-info struct-name field-name)]
    (let [{:keys [offset size type]} field-info
          size-keyword (case size
                         1 :b
                         2 :h
                         4 :w
                         8 :dw
                         :dw)  ; default to dw
          type-str (if (coll? type)
                    (str (first type))
                    (str type))]

      (println ";; Structure field information:")
      (println (format ";;   Offset: %d (0x%x)" offset offset))
      (println (format ";;   Size: %d bytes" size))
      (println (format ";;   Type: %s" type-str))
      (println)

      (println ";; Traditional approach (FRAGILE - breaks across kernel versions):")
      (println "(def traditional-read")
      (println "  [;; Hard-coded offset - DO NOT USE")
      (println (format "   [(bpf/mov-reg :r1 :r6)]           ; r6 = %s*" struct-name))
      (println (format "   [(bpf/add :r1 %d)]               ; Add offset" offset))
      (println (format "   [(bpf/load-mem :%s :r2 :r1 0)]])  ; Load %s" size-keyword field-name))
      (println)

      (println ";; CO-RE approach (PORTABLE - works across all kernel versions):")
      (println "(def core-read")
      (println "  [;; Use CO-RE relocation")
      (println (format "   [(bpf/mov-reg :r1 :r6)]                    ; r6 = %s*" struct-name))
      (println (format "   (bpf/core-field-offset :r2 \"%s\" \"%s\")" struct-name field-name))
      (println "   [(bpf/add-reg :r1 :r2)]                    ; Add actual offset")
      (println (format "   [(bpf/load-mem :%s :r2 :r1 0)])           ; Load %s" size-keyword field-name))
      (println)

      (println ";; High-level helper (RECOMMENDED):")
      (println "(defn read-field [struct-ptr dest-reg]")
      (println "  [;; Portable field read")
      (println "   [(bpf/mov-reg :r1 struct-ptr)]")
      (println (format "   (bpf/core-field-offset :r2 \"%s\" \"%s\")" struct-name field-name))
      (println "   [(bpf/add-reg :r1 :r2)]")
      (println (format "   [(bpf/load-mem :%s dest-reg :r1 0)]])" size-keyword))
      (println)

      (println ";; Usage:")
      (println (format "(read-field :r6 :r7)  ; r6 = %s*, r7 = result" struct-name)))

    (println (format "Field '%s->%s' not found" struct-name field-name))))

;; ============================================================================
;; Structure Listing
;; ============================================================================

(defn list-structures
  "List all structures matching a pattern"
  [pattern]
  (let [all-structs (btf/list-all-structs)
        pattern-re (re-pattern (str "(?i)" pattern))
        matches (filter #(re-find pattern-re %) all-structs)]

    (println (format "\nStructures matching '%s':\n" pattern))
    (if (seq matches)
      (let [sorted-matches (sort matches)]
        (doseq [struct-name (take 50 sorted-matches)]
          (if-let [info (btf/get-struct-info struct-name)]
            (println (format "  %-30s (%4d bytes, %3d fields)"
                             struct-name
                             (:size info)
                             (count (:fields info))))
            (println (format "  %-30s" struct-name))))
        (when (> (count matches) 50)
          (println (format "\n... and %d more matches" (- (count matches) 50)))))
      (println "No matches found"))))

;; ============================================================================
;; Type Dependencies
;; ============================================================================

(defn show-dependencies
  "Show type dependencies for a structure"
  [struct-name]
  (println (format "\n=== Dependencies for %s ===\n" struct-name))

  (if-let [struct-info (btf/get-struct-info struct-name)]
    (let [pointer-fields (filter #(and (coll? (:type %))
                                        (= :pointer (first (:type %))))
                                 (:fields struct-info))
          nested-structs (filter #(and (coll? (:type %))
                                       (= :struct (first (:type %))))
                                (:fields struct-info))]

      (when (seq pointer-fields)
        (println "Pointer fields:")
        (doseq [field pointer-fields]
          (println (format "  %s -> %s"
                           (:name field)
                           (second (:type field))))))

      (when (seq nested-structs)
        (println "\nNested structures:")
        (doseq [field nested-structs]
          (println (format "  %s (embedded %s)"
                           (:name field)
                           (second (:type field)))))))

    (println (format "Structure '%s' not found" struct-name))))

;; ============================================================================
;; Interactive Shell
;; ============================================================================

(defn print-help []
  (println)
  (println "BTF Inspector Commands:")
  (println "  inspect <struct>              - Show detailed structure layout")
  (println "  compact <struct>              - Show compact structure view")
  (println "  search <field>                - Search for field across structures")
  (println "  compare <struct> <v1> <v2>    - Compare structure across versions")
  (println "  generate <struct> <field>     - Generate CO-RE accessor code")
  (println "  list <pattern>                - List structures matching pattern")
  (println "  deps <struct>                 - Show structure dependencies")
  (println "  help                          - Show this help")
  (println "  quit                          - Exit")
  (println))

(defn interactive-shell []
  (println "\n=== BTF Structure Inspector ===")
  (let [kernel-info (get-kernel-info)]
    (println (format "Kernel: %s" (:string kernel-info))))
  (println "Type 'help' for commands\n")

  (loop []
    (print "btf> ")
    (flush)
    (when-let [input (read-line)]
      (let [parts (str/split (str/trim input) #"\s+")
            cmd (first parts)
            args (rest parts)]

        (case cmd
          "inspect" (when (first args)
                     (inspect-structure (first args)))
          "compact" (when (first args)
                     (inspect-structure-compact (first args)))
          "search" (when (first args)
                    (search-field (first args)))
          "compare" (when (and (first args) (second args) (nth args 2 nil))
                     (compare-structures (first args) (second args) (nth args 2)))
          "generate" (when (and (first args) (second args))
                      (generate-field-accessor (first args) (second args)))
          "list" (list-structures (or (first args) ""))
          "deps" (when (first args)
                  (show-dependencies (first args)))
          "help" (print-help)
          "quit" (do (println "Goodbye!") nil)
          "" nil
          (println (format "Unknown command: %s (type 'help' for commands)" cmd)))

        (when-not (= cmd "quit")
          (recur))))))

;; ============================================================================
;; CLI Interface
;; ============================================================================

(def cli-options
  [["-i" "--inspect STRUCT" "Inspect structure"]
   ["-s" "--search FIELD" "Search for field"]
   ["-g" "--generate STRUCT FIELD" "Generate accessor code"
    :parse-fn #(str/split % #"\.")
    :validate [#(= 2 (count %)) "Must be STRUCT.FIELD format"]]
   ["-l" "--list PATTERN" "List matching structures" :default ""]
   ["-I" "--interactive" "Interactive shell mode"]
   ["-h" "--help" "Show help"]])

(defn -main [& args]
  (let [{:keys [options arguments errors summary]} (cli/parse-opts args cli-options)]

    (cond
      (:help options)
      (do
        (println "BTF Structure Inspector")
        (println summary))

      errors
      (do
        (doseq [error errors]
          (println "ERROR:" error))
        (System/exit 1))

      (:interactive options)
      (do
        (check-btf!)
        (interactive-shell))

      (:inspect options)
      (do
        (check-btf!)
        (inspect-structure (:inspect options)))

      (:search options)
      (do
        (check-btf!)
        (search-field (:search options)))

      (:generate options)
      (do
        (check-btf!)
        (let [[struct field] (:generate options)]
          (generate-field-accessor struct field)))

      (:list options)
      (do
        (check-btf!)
        (list-structures (:list options)))

      :else
      (do
        (println "BTF Structure Inspector")
        (println "Use -I for interactive mode or --help for options")))))
```

## Usage Examples

### Example 1: Inspect task_struct

```bash
$ sudo lein run -m btf-inspector.core --inspect task_struct

TASK_STRUCT
===========
Size: 9344 bytes (0x2480)
Fields: 214

OFFSET   SIZE  TYPE                    NAME
================================================================
0        4     unsigned int            __state
8        8     void*                   stack
16       8     refcount_t              usage
24       4     unsigned int            flags
...
1192     4     pid_t                   pid
1196     4     pid_t                   tgid
...
1504     16    char[16]                comm
...
```

### Example 2: Search for Fields

```bash
$ sudo lein run -m btf-inspector.core --search pid

Searching for field 'pid'...

STRUCT                  FIELD               OFFSET  TYPE
================================================================
task_struct             pid                 1192    pid_t
task_struct             tgid                1196    pid_t
pid_namespace           pid_allocated       64      int
...
```

### Example 3: Generate Accessor Code

```bash
$ sudo lein run -m btf-inspector.core --generate task_struct.pid

=== CO-RE Accessor for task_struct->pid ===

;; Structure field information:
;;   Offset: 1192 (0x4a8)
;;   Size: 4 bytes
;;   Type: pid_t

;; CO-RE approach (PORTABLE - works across all kernel versions):
(def core-read
  [;; Use CO-RE relocation
   [(bpf/mov-reg :r1 :r6)]                    ; r6 = task_struct*
   (bpf/core-field-offset :r2 "task_struct" "pid")
   [(bpf/add-reg :r1 :r2)]                    ; Add actual offset
   [(bpf/load-mem :w :r2 :r1 0)])            ; Load pid
...
```

### Example 4: Interactive Mode

```bash
$ sudo lein run -m btf-inspector.core -I

=== BTF Structure Inspector ===
Kernel: 5.15.0
Type 'help' for commands

btf> inspect sk_buff
...detailed output...

btf> search proto
...search results...

btf> generate sk_buff.protocol
...generated code...

btf> list net_
...list of network structures...

btf> quit
Goodbye!
```

### Example 5: List Structures

```bash
$ sudo lein run -m btf-inspector.core --list "sock"

Structures matching 'sock':

  sock                          (1024 bytes,  87 fields)
  socket                        ( 128 bytes,  12 fields)
  sockaddr                      (  16 bytes,   2 fields)
  sockaddr_in                   (  16 bytes,   4 fields)
  sockaddr_in6                  (  28 bytes,   5 fields)
  socket_wq                     (  48 bytes,   4 fields)
  sock_filter                   (   8 bytes,   4 fields)
...
```

## Challenges

1. **Type Graph Visualization**: Draw ASCII diagram of type relationships
2. **Diff Tool**: Compare two structure versions side-by-side
3. **Example Generator**: Generate complete working examples
4. **Documentation Lookup**: Integrate with kernel documentation
5. **Export Formats**: Export to JSON, C header, or Markdown

## Integration with Development Workflow

```bash
# Add to your shell aliases
alias btf-inspect='lein run -m btf-inspector.core -I'

# Use in development
$ btf-inspect
btf> inspect task_struct
# ... copy-paste generated code into your program ...
```

## Key Takeaways

1. **BTF is Discoverable**: All type info is accessible programmatically
2. **Code Generation**: Automate CO-RE accessor creation
3. **Development Tool**: Essential for productive CO-RE development
4. **Cross-Version Reference**: Compare structures across kernels
5. **Interactive Exploration**: Learn kernel structures interactively

## Next Steps

- **Chapter 12**: Performance optimization with CO-RE
- **Chapter 13**: Event processing patterns
- Apply CO-RE techniques to real-world programs

## References

- [BTF Specification](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [bpftool btf Commands](https://manpages.ubuntu.com/manpages/jammy/man8/bpftool-btf.8.html)
- [libbpf BTF API](https://github.com/libbpf/libbpf)
