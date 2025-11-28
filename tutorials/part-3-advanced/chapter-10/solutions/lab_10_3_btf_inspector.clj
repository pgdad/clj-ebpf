(ns lab-10-3-btf-inspector
  "Lab 10.3: BTF Structure Inspector

   This solution demonstrates:
   - BTF (BPF Type Format) navigation and inspection
   - Kernel structure layout analysis
   - CO-RE accessor code generation
   - Structure comparison across versions
   - Interactive exploration of kernel types

   Note: Real BTF parsing would read /sys/kernel/btf/vmlinux.
   This solution simulates BTF with a comprehensive type database.

   Run with: clojure -M -m lab-10-3-btf-inspector test"
  (:require [clj-ebpf.core :as ebpf]
            [clojure.string :as str]
            [clojure.pprint :as pp])
  (:import [java.io File BufferedReader InputStreamReader]))

;;; ============================================================================
;;; Part 1: BTF Type Database
;;; ============================================================================

;; Comprehensive simulated BTF database
(def btf-types
  "Simulated BTF type information for common kernel structures"
  {;; Process management
   :task_struct
   {:size 9344
    :kind :struct
    :description "Process descriptor (PCB)"
    :fields {:__state     {:offset 0     :size 4  :type :u32 :description "Task state (5.14+)"}
             :stack       {:offset 8     :size 8  :type :ptr :description "Kernel stack pointer"}
             :usage       {:offset 16    :size 4  :type :refcount_t :description "Reference count"}
             :flags       {:offset 24    :size 4  :type :u32 :description "Process flags (PF_*)"}
             :on_cpu      {:offset 108   :size 4  :type :u32 :description "CPU currently running on"}
             :wake_cpu    {:offset 112   :size 4  :type :s32 :description "CPU for wakeup"}
             :on_rq       {:offset 116   :size 4  :type :u32 :description "On runqueue?"}
             :prio        {:offset 120   :size 4  :type :s32 :description "Dynamic priority"}
             :static_prio {:offset 124   :size 4  :type :s32 :description "Static priority"}
             :normal_prio {:offset 128   :size 4  :type :s32 :description "Normal priority"}
             :policy      {:offset 132   :size 4  :type :u32 :description "Scheduling policy"}
             :se          {:offset 136   :size 264 :type :sched_entity :description "CFS scheduler entity"}
             :mm          {:offset 1048  :size 8  :type :ptr :description "Memory descriptor"}
             :active_mm   {:offset 1056  :size 8  :type :ptr :description "Active memory descriptor"}
             :pid         {:offset 1192  :size 4  :type :pid_t :description "Process ID"}
             :tgid        {:offset 1196  :size 4  :type :pid_t :description "Thread group ID"}
             :real_parent {:offset 1216  :size 8  :type :ptr :description "Real parent process"}
             :parent      {:offset 1224  :size 8  :type :ptr :description "Parent process"}
             :children    {:offset 1232  :size 16 :type :list_head :description "List of children"}
             :sibling     {:offset 1248  :size 16 :type :list_head :description "Sibling list"}
             :group_leader {:offset 1264 :size 8  :type :ptr :description "Thread group leader"}
             :comm        {:offset 1504  :size 16 :type :char-array :description "Command name"}
             :fs          {:offset 1696  :size 8  :type :ptr :description "Filesystem info"}
             :files       {:offset 1704  :size 8  :type :ptr :description "Open file table"}
             :nsproxy     {:offset 1712  :size 8  :type :ptr :description "Namespaces"}
             :signal      {:offset 1720  :size 8  :type :ptr :description "Signal handlers"}
             :cred        {:offset 1856  :size 8  :type :ptr :description "Credentials"}
             :loginuid    {:offset 1904  :size 4  :type :kuid_t :description "Login UID"}
             :start_time  {:offset 1928  :size 8  :type :u64 :description "Start time (ns)"}
             :utime       {:offset 1968  :size 8  :type :u64 :description "User CPU time"}
             :stime       {:offset 1976  :size 8  :type :u64 :description "System CPU time"}}}

   :cred
   {:size 176
    :kind :struct
    :description "Task credentials"
    :fields {:usage      {:offset 0  :size 4 :type :atomic_t :description "Reference count"}
             :uid        {:offset 4  :size 4 :type :kuid_t :description "Real UID"}
             :gid        {:offset 8  :size 4 :type :kgid_t :description "Real GID"}
             :suid       {:offset 12 :size 4 :type :kuid_t :description "Saved UID"}
             :sgid       {:offset 16 :size 4 :type :kgid_t :description "Saved GID"}
             :euid       {:offset 20 :size 4 :type :kuid_t :description "Effective UID"}
             :egid       {:offset 24 :size 4 :type :kgid_t :description "Effective GID"}
             :fsuid      {:offset 28 :size 4 :type :kuid_t :description "Filesystem UID"}
             :fsgid      {:offset 32 :size 4 :type :kgid_t :description "Filesystem GID"}
             :securebits {:offset 36 :size 4 :type :u32 :description "Security bits"}
             :cap_inheritable {:offset 40 :size 8 :type :kernel_cap_t :description "Inheritable caps"}
             :cap_permitted   {:offset 48 :size 8 :type :kernel_cap_t :description "Permitted caps"}
             :cap_effective   {:offset 56 :size 8 :type :kernel_cap_t :description "Effective caps"}
             :cap_bset        {:offset 64 :size 8 :type :kernel_cap_t :description "Cap bounding set"}
             :cap_ambient     {:offset 72 :size 8 :type :kernel_cap_t :description "Ambient caps"}}}

   :sched_entity
   {:size 264
    :kind :struct
    :description "CFS scheduler entity"
    :fields {:load         {:offset 0  :size 16 :type :load_weight :description "Load weight"}
             :run_node     {:offset 16 :size 24 :type :rb_node :description "Red-black tree node"}
             :on_rq        {:offset 44 :size 4  :type :u32 :description "On runqueue?"}
             :exec_start   {:offset 48 :size 8  :type :u64 :description "Exec start time"}
             :sum_exec_runtime {:offset 56 :size 8 :type :u64 :description "Total exec time"}
             :vruntime     {:offset 64 :size 8  :type :u64 :description "Virtual runtime"}
             :prev_sum_exec_runtime {:offset 72 :size 8 :type :u64 :description "Prev total"}
             :nr_migrations {:offset 80 :size 8 :type :u64 :description "Migration count"}}}

   :mm_struct
   {:size 1024
    :kind :struct
    :description "Memory descriptor"
    :fields {:mmap        {:offset 0   :size 8  :type :ptr :description "VMA list"}
             :mm_rb       {:offset 8   :size 8  :type :rb_root :description "VMA tree"}
             :vmacache_seqnum {:offset 16 :size 8 :type :u64 :description "VMA cache seq"}
             :mmap_base   {:offset 64  :size 8  :type :unsigned-long :description "Mmap base"}
             :task_size   {:offset 72  :size 8  :type :unsigned-long :description "Task size"}
             :highest_vm_end {:offset 80 :size 8 :type :unsigned-long :description "Highest VMA"}
             :pgd         {:offset 88  :size 8  :type :ptr :description "Page global dir"}
             :mm_users    {:offset 96  :size 4  :type :atomic_t :description "User count"}
             :mm_count    {:offset 100 :size 4  :type :atomic_t :description "Total count"}
             :map_count   {:offset 104 :size 4  :type :s32 :description "VMA count"}
             :start_code  {:offset 168 :size 8  :type :unsigned-long :description "Code start"}
             :end_code    {:offset 176 :size 8  :type :unsigned-long :description "Code end"}
             :start_data  {:offset 184 :size 8  :type :unsigned-long :description "Data start"}
             :end_data    {:offset 192 :size 8  :type :unsigned-long :description "Data end"}
             :start_brk   {:offset 200 :size 8  :type :unsigned-long :description "Heap start"}
             :brk         {:offset 208 :size 8  :type :unsigned-long :description "Heap end"}
             :start_stack {:offset 216 :size 8  :type :unsigned-long :description "Stack start"}
             :arg_start   {:offset 224 :size 8  :type :unsigned-long :description "Args start"}
             :arg_end     {:offset 232 :size 8  :type :unsigned-long :description "Args end"}
             :env_start   {:offset 240 :size 8  :type :unsigned-long :description "Env start"}
             :env_end     {:offset 248 :size 8  :type :unsigned-long :description "Env end"}}}

   :sk_buff
   {:size 232
    :kind :struct
    :description "Network socket buffer"
    :fields {:next        {:offset 0   :size 8  :type :ptr :description "Next buffer"}
             :prev        {:offset 8   :size 8  :type :ptr :description "Previous buffer"}
             :sk          {:offset 24  :size 8  :type :ptr :description "Socket owner"}
             :dev         {:offset 32  :size 8  :type :ptr :description "Network device"}
             :tstamp      {:offset 40  :size 8  :type :ktime_t :description "Timestamp"}
             :len         {:offset 104 :size 4  :type :u32 :description "Data length"}
             :data_len    {:offset 108 :size 4  :type :u32 :description "Data frags length"}
             :mac_len     {:offset 112 :size 2  :type :u16 :description "MAC header length"}
             :hdr_len     {:offset 114 :size 2  :type :u16 :description "Header length"}
             :queue_mapping {:offset 116 :size 2 :type :u16 :description "Queue mapping"}
             :protocol    {:offset 120 :size 2  :type :__be16 :description "Packet protocol"}
             :transport_header {:offset 124 :size 2 :type :u16 :description "Transport hdr offset"}
             :network_header   {:offset 126 :size 2 :type :u16 :description "Network hdr offset"}
             :mac_header      {:offset 128 :size 2 :type :u16 :description "MAC hdr offset"}
             :tail        {:offset 176 :size 4  :type :sk_buff_data_t :description "Tail pointer"}
             :end         {:offset 180 :size 4  :type :sk_buff_data_t :description "End pointer"}
             :head        {:offset 184 :size 8  :type :ptr :description "Head of buffer"}
             :data        {:offset 192 :size 8  :type :ptr :description "Data pointer"}
             :truesize    {:offset 200 :size 4  :type :u32 :description "True buffer size"}}}

   :sock
   {:size 1024
    :kind :struct
    :description "Network socket structure"
    :fields {:sk_family      {:offset 16  :size 2 :type :u16 :description "Address family"}
             :sk_type        {:offset 26  :size 2 :type :u16 :description "Socket type"}
             :sk_protocol    {:offset 28  :size 2 :type :u16 :description "Protocol"}
             :sk_bound_dev_if {:offset 32 :size 4 :type :s32 :description "Bound device"}
             :sk_rcvbuf      {:offset 56  :size 4 :type :s32 :description "Receive buffer"}
             :sk_sndbuf      {:offset 60  :size 4 :type :s32 :description "Send buffer"}
             :sk_wmem_queued {:offset 80  :size 4 :type :s32 :description "Write mem queued"}
             :sk_forward_alloc {:offset 84 :size 4 :type :s32 :description "Forward alloc"}
             :sk_drops       {:offset 96  :size 4 :type :atomic_t :description "Drop count"}
             :sk_rcvlowat    {:offset 100 :size 4 :type :s32 :description "Recv low water"}
             :sk_error_queue {:offset 104 :size 16 :type :sk_buff_head :description "Error queue"}
             :sk_receive_queue {:offset 120 :size 16 :type :sk_buff_head :description "Recv queue"}
             :sk_write_queue {:offset 136 :size 16 :type :sk_buff_head :description "Write queue"}}}

   :file
   {:size 256
    :kind :struct
    :description "Open file structure"
    :fields {:f_path      {:offset 0   :size 16 :type :path :description "File path"}
             :f_inode     {:offset 16  :size 8  :type :ptr :description "Inode pointer"}
             :f_op        {:offset 24  :size 8  :type :ptr :description "File operations"}
             :f_lock      {:offset 32  :size 4  :type :spinlock_t :description "File lock"}
             :f_count     {:offset 40  :size 8  :type :atomic64_t :description "Reference count"}
             :f_flags     {:offset 48  :size 4  :type :u32 :description "File flags"}
             :f_mode      {:offset 52  :size 4  :type :fmode_t :description "File mode"}
             :f_pos       {:offset 56  :size 8  :type :loff_t :description "File position"}
             :f_owner     {:offset 64  :size 24 :type :fown_struct :description "Owner info"}
             :f_cred      {:offset 88  :size 8  :type :ptr :description "File credentials"}}}

   :inode
   {:size 640
    :kind :struct
    :description "Inode structure"
    :fields {:i_mode      {:offset 0   :size 2  :type :umode_t :description "File mode"}
             :i_opflags   {:offset 2   :size 2  :type :u16 :description "Op flags"}
             :i_uid       {:offset 4   :size 4  :type :kuid_t :description "Owner UID"}
             :i_gid       {:offset 8   :size 4  :type :kgid_t :description "Owner GID"}
             :i_flags     {:offset 12  :size 4  :type :u32 :description "Inode flags"}
             :i_ino       {:offset 64  :size 8  :type :unsigned-long :description "Inode number"}
             :i_size      {:offset 80  :size 8  :type :loff_t :description "File size"}
             :i_atime     {:offset 88  :size 16 :type :timespec64 :description "Access time"}
             :i_mtime     {:offset 104 :size 16 :type :timespec64 :description "Modify time"}
             :i_ctime     {:offset 120 :size 16 :type :timespec64 :description "Change time"}
             :i_blocks    {:offset 152 :size 8  :type :blkcnt_t :description "Block count"}
             :i_bytes     {:offset 160 :size 4  :type :u32 :description "Bytes used"}}}})

;;; ============================================================================
;;; Part 2: BTF Query Functions
;;; ============================================================================

(defn btf-available?
  "Check if kernel BTF is available"
  []
  (try
    (.exists (File. "/sys/kernel/btf/vmlinux"))
    (catch Exception _ false)))

(defn get-struct-info
  "Get structure information"
  [struct-name]
  (get btf-types (keyword struct-name)))

(defn get-field-info
  "Get field information within a structure"
  [struct-name field-name]
  (get-in btf-types [(keyword struct-name) :fields (keyword field-name)]))

(defn list-all-structs
  "List all known structures"
  []
  (map name (keys btf-types)))

(defn field-exists?
  "Check if field exists in structure"
  [struct-name field-name]
  (boolean (get-field-info struct-name field-name)))

(defn type-exists?
  "Check if type exists in BTF"
  [type-name]
  (boolean (get btf-types (keyword type-name))))

;;; ============================================================================
;;; Part 3: Structure Inspection
;;; ============================================================================

(defn inspect-structure
  "Display detailed structure information"
  [struct-name]
  (if-let [struct-info (get-struct-info struct-name)]
    (do
      (println)
      (println (str/upper-case struct-name))
      (println (str/join "" (repeat (count struct-name) "=")))
      (println (format "Size: %d bytes (0x%x)" (:size struct-info) (:size struct-info)))
      (println (format "Kind: %s" (name (:kind struct-info))))
      (println (format "Description: %s" (:description struct-info)))
      (println (format "Fields: %d" (count (:fields struct-info))))
      (println)
      (println "OFFSET   SIZE  TYPE                    NAME                 DESCRIPTION")
      (println "=========================================================================================")
      (doseq [[field-name field-info] (sort-by (comp :offset val) (:fields struct-info))]
        (printf "%-8d %-5d %-23s %-20s %s\n"
                (:offset field-info)
                (:size field-info)
                (name (:type field-info))
                (name field-name)
                (:description field-info ""))))
    (println (format "Structure '%s' not found in BTF database" struct-name))))

(defn inspect-structure-compact
  "Display compact structure overview"
  [struct-name]
  (if-let [struct-info (get-struct-info struct-name)]
    (let [fields (map name (keys (:fields struct-info)))
          columns 4
          rows (partition-all columns (sort fields))]
      (println (format "\n%s (%d bytes, %d fields):"
                       struct-name
                       (:size struct-info)
                       (count fields)))
      (doseq [row rows]
        (println (str "  " (str/join ", " row)))))
    (println (format "Structure '%s' not found" struct-name))))

;;; ============================================================================
;;; Part 4: Field Search
;;; ============================================================================

(defn search-field
  "Search for field across all structures"
  [field-pattern]
  (println (format "\nSearching for '%s'...\n" field-pattern))
  (let [pattern (re-pattern (str "(?i)" field-pattern))
        matches (for [[struct-name struct-info] btf-types
                      [field-name field-info] (:fields struct-info)
                      :when (re-find pattern (name field-name))]
                  {:struct (name struct-name)
                   :field (name field-name)
                   :offset (:offset field-info)
                   :size (:size field-info)
                   :type (:type field-info)})]
    (if (seq matches)
      (do
        (println "STRUCT           FIELD                OFFSET  SIZE  TYPE")
        (println "================================================================")
        (doseq [match (take 50 (sort-by (juxt :struct :offset) matches))]
          (printf "%-16s %-20s %-7d %-5d %s\n"
                  (:struct match)
                  (:field match)
                  (:offset match)
                  (:size match)
                  (name (:type match))))
        (when (> (count matches) 50)
          (println (format "\n... and %d more matches" (- (count matches) 50)))))
      (println "No matches found"))))

;;; ============================================================================
;;; Part 5: CO-RE Code Generation
;;; ============================================================================

(defn generate-field-accessor
  "Generate CO-RE accessor code for a field"
  [struct-name field-name]
  (println (format "\n=== CO-RE Accessor for %s->%s ===\n" struct-name field-name))

  (if-let [field-info (get-field-info struct-name field-name)]
    (let [{:keys [offset size type description]} field-info
          size-keyword (case size
                         1 "b"
                         2 "h"
                         4 "w"
                         8 "dw"
                         "dw")]

      (println ";; Field Information:")
      (println (format ";;   Offset: %d (0x%x)" offset offset))
      (println (format ";;   Size: %d bytes" size))
      (println (format ";;   Type: %s" (name type)))
      (when description
        (println (format ";;   Description: %s" description)))
      (println)

      (println ";;; TRADITIONAL APPROACH (FRAGILE - DO NOT USE)")
      (println ";;; This breaks across kernel versions!")
      (println ";; (def hardcoded-read")
      (println (format ";;   [(bpf/mov-reg :r1 :r6)                ; r6 = %s*" struct-name))
      (println (format ";;    (bpf/add :r1 %d)                     ; Add hardcoded offset" offset))
      (println (format ";;    (bpf/load-mem :%s :r2 :r1 0)])       ; Load %s" size-keyword field-name))
      (println)

      (println ";;; CO-RE APPROACH (PORTABLE - RECOMMENDED)")
      (println ";;; Works across all kernel versions with BTF")
      (println "(defn read-field [struct-ptr dest-reg]")
      (println "  \"Read field using CO-RE relocation\"")
      (println "  [;; Get field offset at load time via BTF")
      (println (format "   (bpf/core-field-offset :r1 \"%s\" \"%s\")" struct-name field-name))
      (println "   ;; Add offset to struct pointer")
      (println "   [(bpf/mov-reg :r2 struct-ptr)]")
      (println "   [(bpf/add-reg :r2 :r1)]")
      (println "   ;; Load the field value")
      (println (format "   [(bpf/load-mem :%s dest-reg :r2 0)]])" size-keyword))
      (println)

      (println ";;; USAGE EXAMPLE")
      (println (format ";; (read-field :r6 :r7)  ; r6 = %s*, result in r7" struct-name))
      (println)

      (when (= type :ptr)
        (println ";;; NOTE: This field is a pointer")
        (println ";;; After reading, you may need to dereference it:"
        (println ";; (bpf/probe-read-kernel :r8 dest-size :r7)"))))

    (println (format "Field '%s->%s' not found in BTF database" struct-name field-name))))

(defn generate-nested-accessor
  "Generate CO-RE accessor for nested field (e.g., task->cred->uid)"
  [& path]
  (println (format "\n=== CO-RE Accessor for %s ===\n" (str/join "->" path)))

  (let [pairs (partition 2 1 path)]
    (println "(defn read-nested-field [base-ptr]")
    (println "  \"Read nested field using CO-RE relocations\"")
    (println "  [")

    (doseq [[idx [struct-name field-name]] (map-indexed vector pairs)]
      (let [reg (keyword (str "r" (+ 6 idx)))]
        (println (format "   ;; Step %d: Read %s.%s" (inc idx) struct-name field-name))
        (println (format "   (bpf/core-field-offset :r1 \"%s\" \"%s\")" struct-name field-name))
        (if (zero? idx)
          (println "   [(bpf/mov-reg :r2 base-ptr)]")
          (println (format "   [(bpf/mov-reg :r2 %s)]" (keyword (str "r" (+ 5 idx))))))
        (println "   [(bpf/add-reg :r2 :r1)]")
        (println (format "   [(bpf/load-mem :dw %s :r2 0)]" reg))
        (println)))

    (println "   ])")))

;;; ============================================================================
;;; Part 6: Structure Listing
;;; ============================================================================

(defn list-structures
  "List structures matching a pattern"
  [pattern]
  (let [all-structs (list-all-structs)
        pattern-re (re-pattern (str "(?i)" pattern))
        matches (filter #(re-find pattern-re %) all-structs)]

    (println (format "\nStructures matching '%s':\n" pattern))
    (if (seq matches)
      (let [sorted-matches (sort matches)]
        (doseq [struct-name sorted-matches]
          (when-let [info (get-struct-info struct-name)]
            (printf "  %-20s %5d bytes, %3d fields  - %s\n"
                    struct-name
                    (:size info)
                    (count (:fields info))
                    (:description info "")))))
      (println "No matches found"))))

;;; ============================================================================
;;; Part 7: Type Dependencies
;;; ============================================================================

(defn show-dependencies
  "Show type dependencies for a structure"
  [struct-name]
  (println (format "\n=== Dependencies for %s ===\n" struct-name))

  (if-let [struct-info (get-struct-info struct-name)]
    (let [all-fields (:fields struct-info)
          pointer-fields (filter (fn [[_ v]] (= :ptr (:type v))) all-fields)
          struct-fields (filter (fn [[_ v]]
                                 (and (not= :ptr (:type v))
                                      (type-exists? (name (:type v))))) all-fields)
          other-types (->> all-fields
                          (map (fn [[_ v]] (:type v)))
                          (remove #{:ptr :u8 :u16 :u32 :u64 :s8 :s16 :s32 :s64
                                   :char-array :unsigned-long :long})
                          (distinct))]

      (when (seq pointer-fields)
        (println "Pointer fields (require dereference):")
        (doseq [[field-name field-info] pointer-fields]
          (printf "  %-20s (offset %d) - %s\n"
                  (name field-name)
                  (:offset field-info)
                  (:description field-info ""))))

      (when (seq struct-fields)
        (println "\nEmbedded structures:")
        (doseq [[field-name field-info] struct-fields]
          (printf "  %-20s (offset %d) - %s [%s]\n"
                  (name field-name)
                  (:offset field-info)
                  (name (:type field-info))
                  (:description field-info ""))))

      (when (seq other-types)
        (println "\nOther types used:")
        (doseq [t (sort (map name other-types))]
          (printf "  %s\n" t))))

    (println (format "Structure '%s' not found" struct-name))))

;;; ============================================================================
;;; Part 8: Version Comparison (Simulated)
;;; ============================================================================

(def version-layouts
  "Simulated field offsets across kernel versions"
  {:task_struct
   {"5.4"  {:pid 1176 :comm 1472 :cred 1824 :state-field "state"}
    "5.10" {:pid 1184 :comm 1488 :cred 1840 :state-field "state"}
    "5.15" {:pid 1192 :comm 1504 :cred 1856 :state-field "__state"}
    "6.0"  {:pid 1200 :comm 1520 :cred 1872 :state-field "__state"}
    "6.5"  {:pid 1208 :comm 1528 :cred 1880 :state-field "__state"}}})

(defn compare-structures
  "Compare structure layouts across kernel versions"
  [struct-name]
  (println (format "\n=== %s Layout Comparison ===\n" struct-name))

  (if-let [layouts (get version-layouts (keyword struct-name))]
    (let [fields (distinct (mapcat keys (vals layouts)))
          versions (sort (keys layouts))]

      ;; Print header
      (print (format "%-15s" "FIELD"))
      (doseq [v versions]
        (print (format "%-10s" v)))
      (println)
      (println (str/join "" (repeat (+ 15 (* 10 (count versions))) "-")))

      ;; Print each field
      (doseq [field (sort (map name fields))]
        (print (format "%-15s" field))
        (let [offsets (map #(get-in layouts [% (keyword field)]) versions)
              base (first offsets)]
          (doseq [[v offset] (map vector versions offsets)]
            (if offset
              (if (= offset base)
                (print (format "%-10d" offset))
                (print (format "%-10s" (format "%d (+%d)" offset (- offset base)))))
              (print (format "%-10s" "-")))))
        (println)))

    (println (format "No version comparison data for '%s'" struct-name))))

;;; ============================================================================
;;; Part 9: Interactive Shell
;;; ============================================================================

(defn print-help
  "Print help information"
  []
  (println)
  (println "BTF Inspector Commands:")
  (println "  inspect <struct>           - Show detailed structure layout")
  (println "  compact <struct>           - Show compact structure view")
  (println "  search <pattern>           - Search for field across structures")
  (println "  generate <struct> <field>  - Generate CO-RE accessor code")
  (println "  nested <struct.field...>   - Generate nested accessor (e.g., task.cred.uid)")
  (println "  list [pattern]             - List structures (optionally filtered)")
  (println "  deps <struct>              - Show structure dependencies")
  (println "  compare <struct>           - Compare across kernel versions")
  (println "  help                       - Show this help")
  (println "  quit                       - Exit")
  (println))

(defn interactive-shell
  "Run interactive BTF inspector shell"
  []
  (println "\n=== BTF Structure Inspector ===")
  (println (format "BTF Database: %d structures" (count btf-types)))
  (println (format "Kernel BTF: %s" (if (btf-available?) "Available" "Not found (using simulated)")))
  (println "Type 'help' for commands\n")

  (loop []
    (print "btf> ")
    (flush)
    (when-let [input (try (read-line) (catch Exception _ nil))]
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
          "generate" (when (and (first args) (second args))
                      (generate-field-accessor (first args) (second args)))
          "nested" (when (first args)
                    (let [path (str/split (first args) #"\.")]
                      (apply generate-nested-accessor path)))
          "list" (list-structures (or (first args) ""))
          "deps" (when (first args)
                  (show-dependencies (first args)))
          "compare" (when (first args)
                     (compare-structures (first args)))
          "help" (print-help)
          "quit" nil
          "" nil
          (println (format "Unknown command: %s (type 'help' for commands)" cmd)))

        (when-not (= cmd "quit")
          (recur))))))

;;; ============================================================================
;;; Part 10: Tests
;;; ============================================================================

(defn run-tests
  "Run all tests"
  []
  (println "\n=== Lab 10.3 Tests ===\n")

  ;; Test 1: Structure lookup
  (println "Test 1: Structure Information Lookup")
  (let [info (get-struct-info "task_struct")]
    (assert info "Should find task_struct")
    (assert (pos? (:size info)) "Should have positive size")
    (assert (pos? (count (:fields info))) "Should have fields")
    (println (format "  task_struct: %d bytes, %d fields" (:size info) (count (:fields info))))
    (println "  PASSED"))

  ;; Test 2: Field lookup
  (println "\nTest 2: Field Information Lookup")
  (let [field (get-field-info "task_struct" "pid")]
    (assert field "Should find pid field")
    (assert (number? (:offset field)) "Should have offset")
    (assert (number? (:size field)) "Should have size")
    (println (format "  task_struct.pid: offset=%d, size=%d" (:offset field) (:size field)))
    (println "  PASSED"))

  ;; Test 3: Field existence check
  (println "\nTest 3: Field Existence Check")
  (let [has-pid (field-exists? "task_struct" "pid")
        has-fake (field-exists? "task_struct" "nonexistent")]
    (assert has-pid "pid should exist")
    (assert (not has-fake) "nonexistent should not exist")
    (println "  pid exists: true")
    (println "  nonexistent exists: false")
    (println "  PASSED"))

  ;; Test 4: Structure listing
  (println "\nTest 4: Structure Listing")
  (let [structs (list-all-structs)]
    (assert (seq structs) "Should have structures")
    (assert (some #{"task_struct"} structs) "Should include task_struct")
    (println (format "  Found %d structures" (count structs)))
    (println "  PASSED"))

  ;; Test 5: Field search
  (println "\nTest 5: Field Search")
  (let [matches (for [[struct-name struct-info] btf-types
                      [field-name _] (:fields struct-info)
                      :when (str/includes? (name field-name) "pid")]
                  {:struct struct-name :field field-name})]
    (assert (seq matches) "Should find pid-related fields")
    (println (format "  Found %d fields matching 'pid'" (count matches)))
    (println "  PASSED"))

  ;; Test 6: Nested structure traversal
  (println "\nTest 6: Nested Structure Traversal")
  (let [cred-offset (:offset (get-field-info "task_struct" "cred"))
        uid-offset (:offset (get-field-info "cred" "uid"))]
    (assert cred-offset "Should find cred in task_struct")
    (assert uid-offset "Should find uid in cred")
    (println (format "  task_struct.cred offset: %d" cred-offset))
    (println (format "  cred.uid offset: %d" uid-offset))
    (println (format "  Total path offset: %d (access via pointers)" (+ cred-offset uid-offset)))
    (println "  PASSED"))

  ;; Test 7: Type existence
  (println "\nTest 7: Type Existence Check")
  (let [has-task (type-exists? "task_struct")
        has-sk-buff (type-exists? "sk_buff")
        has-fake (type-exists? "fake_struct")]
    (assert has-task "task_struct should exist")
    (assert has-sk-buff "sk_buff should exist")
    (assert (not has-fake) "fake_struct should not exist")
    (println "  task_struct exists: true")
    (println "  sk_buff exists: true")
    (println "  fake_struct exists: false")
    (println "  PASSED"))

  ;; Test 8: Version comparison data
  (println "\nTest 8: Version Layout Comparison")
  (let [layouts (get version-layouts :task_struct)]
    (assert layouts "Should have task_struct version layouts")
    (assert (get layouts "5.15") "Should have 5.15 layout")
    (println (format "  %d kernel versions with layout data" (count layouts)))
    (println "  PASSED"))

  (println "\n=== All Tests Passed ==="))

;;; ============================================================================
;;; Part 11: Demo
;;; ============================================================================

(defn run-demo
  "Run interactive demonstration"
  []
  (println "\n" (str/join "" (repeat 60 "=")))
  (println "  Lab 10.3: BTF Structure Inspector")
  (println (str/join "" (repeat 60 "=")) "\n")

  (println (format "BTF Database: %d structures" (count btf-types)))
  (println (format "System BTF: %s" (if (btf-available?) "Available" "Using simulated")))

  ;; Show available structures
  (list-structures "")

  ;; Inspect key structures
  (inspect-structure "task_struct")
  (inspect-structure "cred")

  ;; Search for fields
  (search-field "pid")
  (search-field "uid")

  ;; Generate accessor
  (generate-field-accessor "task_struct" "pid")
  (generate-field-accessor "task_struct" "cred")

  ;; Show nested accessor
  (generate-nested-accessor "task_struct" "cred" "uid")

  ;; Show dependencies
  (show-dependencies "task_struct")

  ;; Compare versions
  (compare-structures "task_struct"))

;;; ============================================================================
;;; Part 12: Main
;;; ============================================================================

(defn -main
  "Main entry point"
  [& args]
  (let [cmd (first args)]
    (case cmd
      "test" (run-tests)
      "demo" (run-demo)
      "shell" (interactive-shell)
      "inspect" (if (second args)
                  (inspect-structure (second args))
                  (println "Usage: inspect <struct>"))
      "search" (if (second args)
                 (search-field (second args))
                 (println "Usage: search <pattern>"))
      "generate" (if (and (second args) (nth args 2 nil))
                   (generate-field-accessor (second args) (nth args 2))
                   (println "Usage: generate <struct> <field>"))
      "list" (list-structures (or (second args) ""))
      "deps" (if (second args)
               (show-dependencies (second args))
               (println "Usage: deps <struct>"))
      "compare" (if (second args)
                  (compare-structures (second args))
                  (println "Usage: compare <struct>"))
      ;; Default: run demo
      (run-demo))))
