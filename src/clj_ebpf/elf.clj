(ns clj-ebpf.elf
  "ELF (Executable and Linkable Format) parser for BPF programs"
  (:require [clj-ebpf.utils :as utils]
            [clj-ebpf.constants :as const]
            [clj-ebpf.programs :as programs]
            [clj-ebpf.maps :as maps])
  (:import [java.nio ByteBuffer ByteOrder]))

;; ============================================================================
;; ELF Constants
;; ============================================================================

;; ELF Magic number
(def ^:private ELF_MAGIC [0x7f 0x45 0x4c 0x46]) ; "\x7fELF"

;; ELF Class
(def ^:private ELFCLASS32 1)
(def ^:private ELFCLASS64 2)

;; ELF Data encoding
(def ^:private ELFDATA2LSB 1) ; Little endian
(def ^:private ELFDATA2MSB 2) ; Big endian

;; ELF Type
(def ^:private ET_NONE 0)
(def ^:private ET_REL 1)  ; Relocatable file
(def ^:private ET_EXEC 2)
(def ^:private ET_DYN 3)

;; ELF Machine
(def ^:private EM_BPF 247) ; BPF machine type

;; Section types
(def ^:private SHT_NULL 0)
(def ^:private SHT_PROGBITS 1)
(def ^:private SHT_SYMTAB 2)
(def ^:private SHT_STRTAB 3)
(def ^:private SHT_RELA 4)
(def ^:private SHT_REL 9)

;; Section flags
(def ^:private SHF_WRITE 0x1)
(def ^:private SHF_ALLOC 0x2)
(def ^:private SHF_EXECINSTR 0x4)

;; Symbol binding
(def ^:private STB_LOCAL 0)
(def ^:private STB_GLOBAL 1)
(def ^:private STB_WEAK 2)

;; Symbol types
(def ^:private STT_NOTYPE 0)
(def ^:private STT_OBJECT 1)
(def ^:private STT_FUNC 2)
(def ^:private STT_SECTION 3)

;; Relocation types (BPF specific)
(def ^:private R_BPF_NONE 0)
(def ^:private R_BPF_64_64 1)
(def ^:private R_BPF_64_32 10)

;; ============================================================================
;; ELF Records
;; ============================================================================

(defrecord ElfHeader
  [class          ; 32 or 64 bit
   data           ; Endianness
   version        ; ELF version
   type           ; Object file type
   machine        ; Machine type
   entry          ; Entry point
   phoff          ; Program header offset
   shoff          ; Section header offset
   flags          ; Processor flags
   ehsize         ; ELF header size
   phentsize      ; Program header entry size
   phnum          ; Program header count
   shentsize      ; Section header entry size
   shnum          ; Section header count
   shstrndx])     ; Section name string table index

(defrecord SectionHeader
  [name           ; Section name (string)
   name-idx       ; Section name index in string table
   type           ; Section type
   flags          ; Section flags
   addr           ; Section virtual address
   offset         ; Section file offset
   size           ; Section size
   link           ; Link to another section
   info           ; Additional section info
   addralign      ; Section alignment
   entsize])      ; Entry size for fixed-size entries

(defrecord Symbol
  [name           ; Symbol name
   name-idx       ; Name index in string table
   value          ; Symbol value
   size           ; Symbol size
   info           ; Symbol type and binding
   other          ; Symbol visibility
   shndx])        ; Section index

(defrecord Relocation
  [offset         ; Offset to apply relocation
   type           ; Relocation type
   symbol         ; Symbol index
   addend])       ; Relocation addend

(defrecord BpfProgram
  [name           ; Program name (from section name)
   section        ; Section name
   insns          ; BPF instructions (byte array)
   type           ; BPF program type (inferred from section name)
   license        ; License string
   relocations])  ; Vector of relocations

(defrecord BpfMapDef
  [name           ; Map name
   type           ; Map type
   key-size       ; Key size in bytes
   value-size     ; Value size in bytes
   max-entries    ; Maximum entries
   flags])        ; Map flags

(defrecord ElfFile
  [header         ; ELF header
   sections       ; Vector of section headers
   programs       ; Vector of BPF programs
   maps           ; Vector of BPF map definitions
   license        ; License string
   version])      ; Kernel version

;; ============================================================================
;; ELF Parsing Utilities
;; ============================================================================

(defn- read-bytes
  "Read bytes from byte array at offset"
  [^bytes data offset length]
  (let [result (byte-array length)]
    (System/arraycopy data offset result 0 length)
    result))

(defn- read-u8
  "Read unsigned 8-bit integer"
  [^bytes data offset]
  (bit-and 0xff (aget data offset)))

(defn- read-u16-le
  "Read unsigned 16-bit integer (little endian)"
  [^bytes data offset]
  (let [bb (ByteBuffer/wrap data offset 2)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (bit-and 0xffff (.getShort bb))))

(defn- read-u32-le
  "Read unsigned 32-bit integer (little endian)"
  [^bytes data offset]
  (let [bb (ByteBuffer/wrap data offset 4)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (bit-and 0xffffffff (.getInt bb))))

(defn- read-u64-le
  "Read unsigned 64-bit integer (little endian)"
  [^bytes data offset]
  (let [bb (ByteBuffer/wrap data offset 8)]
    (.order bb ByteOrder/LITTLE_ENDIAN)
    (.getLong bb)))

(defn- read-string-at
  "Read null-terminated string from offset"
  [^bytes data offset]
  (let [end (loop [i offset]
              (if (or (>= i (alength data))
                     (zero? (aget data i)))
                i
                (recur (inc i))))]
    (String. data offset (- end offset) "UTF-8")))

;; ============================================================================
;; ELF Header Parsing
;; ============================================================================

(defn- parse-elf-header
  "Parse ELF file header"
  [^bytes data]
  (when (< (alength data) 64)
    (throw (ex-info "File too small to be valid ELF" {:size (alength data)})))

  ;; Check magic number
  (when-not (= (vec (take 4 data)) (vec ELF_MAGIC))
    (throw (ex-info "Invalid ELF magic number"
                   {:expected ELF_MAGIC
                    :got (vec (take 4 data))})))

  (let [class (read-u8 data 4)
        data-enc (read-u8 data 5)
        version (read-u8 data 6)]

    (when-not (= class ELFCLASS64)
      (throw (ex-info "Only 64-bit ELF files supported" {:class class})))

    (when-not (= data-enc ELFDATA2LSB)
      (throw (ex-info "Only little-endian ELF files supported" {:encoding data-enc})))

    (->ElfHeader
      class
      data-enc
      version
      (read-u16-le data 16)   ; e_type
      (read-u16-le data 18)   ; e_machine
      (read-u32-le data 20)   ; e_version
      (read-u64-le data 24)   ; e_entry
      (read-u64-le data 32)   ; e_phoff
      (read-u64-le data 40)   ; e_shoff
      (read-u32-le data 48)   ; e_flags
      (read-u16-le data 52)   ; e_ehsize
      (read-u16-le data 54)   ; e_phentsize
      (read-u16-le data 56)   ; e_phnum
      (read-u16-le data 58)   ; e_shentsize
      (read-u16-le data 60)   ; e_shnum
      (read-u16-le data 62)))) ; e_shstrndx

;; ============================================================================
;; Section Header Parsing
;; ============================================================================

(defn- parse-section-header
  "Parse a single section header (64-bit)"
  [^bytes data offset]
  (->SectionHeader
    nil                        ; name (filled in later)
    (read-u32-le data offset)  ; sh_name
    (read-u32-le data (+ offset 4))   ; sh_type
    (read-u64-le data (+ offset 8))   ; sh_flags
    (read-u64-le data (+ offset 16))  ; sh_addr
    (read-u64-le data (+ offset 24))  ; sh_offset
    (read-u64-le data (+ offset 32))  ; sh_size
    (read-u32-le data (+ offset 40))  ; sh_link
    (read-u32-le data (+ offset 44))  ; sh_info
    (read-u64-le data (+ offset 48))  ; sh_addralign
    (read-u64-le data (+ offset 56)))) ; sh_entsize

(defn- parse-section-headers
  "Parse all section headers"
  [^bytes data header]
  (let [shoff (:shoff header)
        shnum (:shnum header)
        shentsize (:shentsize header)]
    (vec (for [i (range shnum)]
           (parse-section-header data (+ shoff (* i shentsize)))))))

(defn- get-section-data
  "Get data for a section"
  [^bytes data section]
  (read-bytes data (:offset section) (:size section)))

(defn- resolve-section-names
  "Resolve section names using string table"
  [^bytes data sections shstrndx]
  (let [strtab-section (nth sections shstrndx)
        strtab-data (get-section-data data strtab-section)]
    (mapv (fn [section]
            (assoc section :name
                  (read-string-at strtab-data (:name-idx section))))
          sections)))

;; ============================================================================
;; Symbol Table Parsing
;; ============================================================================

(defn- parse-symbol
  "Parse a single symbol table entry (64-bit)"
  [^bytes data offset]
  (->Symbol
    nil                        ; name (filled in later)
    (read-u32-le data offset)  ; st_name
    (read-u64-le data (+ offset 8))   ; st_value
    (read-u64-le data (+ offset 16))  ; st_size
    (read-u8 data (+ offset 4))       ; st_info
    (read-u8 data (+ offset 5))       ; st_other
    (read-u16-le data (+ offset 6)))) ; st_shndx

(defn- parse-symbols
  "Parse symbol table section"
  [^bytes data symtab-section strtab-section]
  (let [symtab-data (get-section-data data symtab-section)
        strtab-data (get-section-data data strtab-section)
        entsize (:entsize symtab-section)
        count (/ (:size symtab-section) entsize)]
    (vec (for [i (range count)]
           (let [sym (parse-symbol symtab-data (* i entsize))]
             (assoc sym :name
                   (read-string-at strtab-data (:name-idx sym))))))))

;; ============================================================================
;; Relocation Parsing
;; ============================================================================

(defn- parse-rela-entry
  "Parse a RELA relocation entry (64-bit)"
  [^bytes data offset]
  (let [r-offset (read-u64-le data offset)
        r-info (read-u64-le data (+ offset 8))
        r-addend (read-u64-le data (+ offset 16))
        r-sym (bit-shift-right r-info 32)
        r-type (bit-and r-info 0xffffffff)]
    (->Relocation r-offset r-type r-sym r-addend)))

(defn- parse-relocations
  "Parse relocation section"
  [^bytes data rela-section]
  (let [rela-data (get-section-data data rela-section)
        entsize (:entsize rela-section)
        count (/ (:size rela-section) entsize)]
    (vec (for [i (range count)]
           (parse-rela-entry rela-data (* i entsize))))))

;; ============================================================================
;; BPF Program Extraction
;; ============================================================================

(defn- infer-prog-type
  "Infer BPF program type from section name"
  [section-name]
  (cond
    (re-matches #"^kprobe/.*" section-name) :kprobe
    (re-matches #"^kretprobe/.*" section-name) :kprobe
    (re-matches #"^tracepoint/.*" section-name) :tracepoint
    (re-matches #"^raw_tracepoint/.*" section-name) :raw-tracepoint
    (re-matches #"^xdp.*" section-name) :xdp
    (re-matches #"^tc.*" section-name) :sched-cls
    (re-matches #"^classifier.*" section-name) :sched-cls
    (re-matches #"^action.*" section-name) :sched-act
    (re-matches #"^socket.*" section-name) :socket-filter
    (re-matches #"^cgroup/.*" section-name) :cgroup-skb
    (= section-name ".text") :socket-filter ; Default
    :else :socket-filter))

(defn- is-prog-section?
  "Check if section contains BPF program"
  [section]
  (and (= (:type section) SHT_PROGBITS)
       (not= 0 (bit-and (:flags section) SHF_EXECINSTR))
       (not (re-matches #"^\..*" (:name section))))) ; Not a special section

(defn- extract-programs
  "Extract BPF programs from sections"
  [^bytes data sections]
  (let [prog-sections (filter is-prog-section? sections)]
    (vec (for [section prog-sections]
           (->BpfProgram
             (:name section)
             (:name section)
             (get-section-data data section)
             (infer-prog-type (:name section))
             nil ; license (filled in later)
             []))))) ; relocations (filled in later)

;; ============================================================================
;; BPF Map Definition Parsing
;; ============================================================================

(defn- parse-map-def
  "Parse BPF map definition structure

  struct bpf_map_def {
    unsigned int type;        // 0-3
    unsigned int key_size;    // 4-7
    unsigned int value_size;  // 8-11
    unsigned int max_entries; // 12-15
    unsigned int map_flags;   // 16-19
  }"
  [^bytes data offset name]
  (->BpfMapDef
    name
    (read-u32-le data offset)
    (read-u32-le data (+ offset 4))
    (read-u32-le data (+ offset 8))
    (read-u32-le data (+ offset 12))
    (read-u32-le data (+ offset 16))))

(defn- extract-maps
  "Extract BPF map definitions from 'maps' section"
  [^bytes data sections symbols]
  (let [maps-section (first (filter #(= (:name %) "maps") sections))]
    (if maps-section
      (let [maps-data (get-section-data data maps-section)
            map-symbols (filter #(and (= (:shndx %) (.indexOf (vec sections) maps-section))
                                     (= (bit-and (:info %) 0xf) STT_OBJECT))
                              symbols)]
        (vec (for [sym map-symbols]
               (parse-map-def maps-data (:value sym) (:name sym)))))
      [])))

;; ============================================================================
;; License and Version Extraction
;; ============================================================================

(defn- extract-license
  "Extract license string from 'license' section"
  [^bytes data sections]
  (let [license-section (first (filter #(= (:name %) "license") sections))]
    (if license-section
      (let [license-data (get-section-data data license-section)]
        (read-string-at license-data 0))
      "GPL"))) ; Default to GPL

(defn- extract-version
  "Extract kernel version from 'version' section"
  [^bytes data sections]
  (let [version-section (first (filter #(= (:name %) "version") sections))]
    (if version-section
      (let [version-data (get-section-data data version-section)]
        (read-u32-le version-data 0))
      0)))

;; ============================================================================
;; Main ELF Parsing Function
;; ============================================================================

(defn parse-elf-file
  "Parse ELF file and extract BPF programs and maps

  Parameters:
  - path: Path to ELF file

  Returns ElfFile record with:
  - header: ELF header
  - sections: Vector of section headers
  - programs: Vector of BPF programs
  - maps: Vector of BPF map definitions
  - license: License string
  - version: Kernel version"
  [path]
  (let [data (utils/read-file-bytes path)
        header (parse-elf-header data)
        sections (parse-section-headers data header)
        sections (resolve-section-names data sections (:shstrndx header))

        ;; Parse symbol table
        symtab-section (first (filter #(= (:type %) SHT_SYMTAB) sections))
        strtab-section (when symtab-section
                        (nth sections (:link symtab-section)))
        symbols (if symtab-section
                 (parse-symbols data symtab-section strtab-section)
                 [])

        ;; Extract programs and maps
        programs (extract-programs data sections)
        maps (extract-maps data sections symbols)
        license (extract-license data sections)
        version (extract-version data sections)

        ;; Set license for all programs
        programs (mapv #(assoc % :license license) programs)]

    (->ElfFile header sections programs maps license version)))

(defn list-programs
  "List all BPF programs in ELF file

  Returns vector of maps with :name, :section, :type, :size"
  [elf-file]
  (mapv (fn [prog]
          {:name (:name prog)
           :section (:section prog)
           :type (:type prog)
           :size (alength (:insns prog))})
        (:programs elf-file)))

(defn list-maps
  "List all BPF map definitions in ELF file

  Returns vector of maps with :name, :type, :key-size, :value-size, :max-entries"
  [elf-file]
  (mapv (fn [m]
          {:name (:name m)
           :type (:type m)
           :key-size (:key-size m)
           :value-size (:value-size m)
           :max-entries (:max-entries m)})
        (:maps elf-file)))

(defn get-program
  "Get BPF program by name or index

  Parameters:
  - elf-file: Parsed ELF file
  - name-or-idx: Program name (string) or index (integer)

  Returns BpfProgram record or nil"
  [elf-file name-or-idx]
  (if (integer? name-or-idx)
    (nth (:programs elf-file) name-or-idx nil)
    (first (filter #(= (:name %) name-or-idx) (:programs elf-file)))))

(defn get-map-def
  "Get BPF map definition by name

  Parameters:
  - elf-file: Parsed ELF file
  - name: Map name

  Returns BpfMapDef record or nil"
  [elf-file name]
  (first (filter #(= (:name %) name) (:maps elf-file))))

;; ============================================================================
;; ELF Loading Helpers
;; ============================================================================

(defn load-program-from-elf
  "Load a BPF program from ELF file

  Parameters:
  - path: Path to ELF file
  - program-name: Name of program to load (or index)
  - options: Additional options for program loading

  Returns program file descriptor

  Example:
    (load-program-from-elf \"filter.o\" \"xdp_filter\")"
  [path program-name & options]
  (let [elf-file (parse-elf-file path)
        program (get-program elf-file program-name)]
    (when-not program
      (throw (ex-info "Program not found in ELF file"
                     {:program program-name
                      :available (mapv :name (:programs elf-file))})))

    ;; Load program using programs namespace
    (let [prog-options (merge {:prog-type (:type program)
                              :insns (:insns program)
                              :license (:license program)
                              :prog-name (:name program)}
                             (apply hash-map options))]
      (programs/load-program (:insns program)
                            :prog-type (:type program)
                            :license (:license program)
                            :prog-name (:name program)))))

(defn create-maps-from-elf
  "Create all BPF maps defined in ELF file

  Parameters:
  - path: Path to ELF file

  Returns map of {map-name -> BpfMap}

  Example:
    (create-maps-from-elf \"filter.o\")
    ;; => {\"my_map\" #clj_ebpf.maps.BpfMap{...}}"
  [path]
  (let [elf-file (parse-elf-file path)]
    (into {}
          (for [map-def (:maps elf-file)]
            [(:name map-def)
             (maps/create-map {:map-type (const/int->map-type (:type map-def))
                              :key-size (:key-size map-def)
                              :value-size (:value-size map-def)
                              :max-entries (:max-entries map-def)
                              :map-flags (:flags map-def)
                              :map-name (:name map-def)})]))))

(defn inspect-elf
  "Inspect ELF file and return summary information

  Parameters:
  - path: Path to ELF file

  Returns map with:
  - :programs - List of program info
  - :maps - List of map info
  - :license - License string
  - :version - Kernel version

  Example:
    (inspect-elf \"filter.o\")
    ;; => {:programs [{:name \"xdp_filter\" :type :xdp :size 128}]
    ;;     :maps [{:name \"my_map\" :type 1 :key-size 4 ...}]
    ;;     :license \"GPL\"
    ;;     :version 0}"
  [path]
  (let [elf-file (parse-elf-file path)]
    {:programs (list-programs elf-file)
     :maps (list-maps elf-file)
     :license (:license elf-file)
     :version (:version elf-file)}))

(defn load-elf-program-and-maps
  "Load BPF program and create all maps from ELF file

  Parameters:
  - path: Path to ELF file
  - program-name: Name of program to load

  Returns map with:
  - :program-fd - Program file descriptor
  - :maps - Map of {map-name -> BpfMap}

  Example:
    (let [{:keys [program-fd maps]} (load-elf-program-and-maps \"filter.o\" \"xdp_filter\")]
      (println \"Program FD:\" program-fd)
      (println \"Maps:\" (keys maps)))"
  [path program-name]
  (let [maps (create-maps-from-elf path)
        program-fd (load-program-from-elf path program-name)]
    {:program-fd program-fd
     :maps maps}))
