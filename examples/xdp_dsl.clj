(ns xdp-dsl
  "XDP DSL Example

   This example demonstrates using the high-level XDP DSL to build
   packet processing programs that run at the earliest point in
   the network stack.

   XDP (eXpress Data Path) provides:
   - Ultra-low latency packet processing
   - Runs before sk_buff allocation
   - Direct hardware access with driver support
   - High performance filtering and forwarding

   XDP Actions:
   - XDP_ABORTED (0): Error, drop with trace
   - XDP_DROP    (1): Silently drop packet
   - XDP_PASS    (2): Pass to normal network stack
   - XDP_TX      (3): Transmit back out same interface
   - XDP_REDIRECT(4): Redirect to another interface/CPU

   Usage:
     clojure -M:examples -m xdp-dsl"
  (:require [clj-ebpf.dsl.xdp :as xdp]
            [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; Example 1: XDP Actions
;; ============================================================================

(defn demo-xdp-actions
  "Demonstrate XDP action values."
  []
  (println "\n=== XDP Actions ===\n")

  (println "Available XDP actions:")
  (doseq [[action value] (sort-by val xdp/xdp-actions)]
    (printf "  XDP_%-8s = %d\n" (clojure.string/upper-case (name action)) value))

  (println "\nUsing xdp-action function:")
  (doseq [action [:aborted :drop :pass :tx :redirect]]
    (printf "  (xdp-action :%s) => %d\n" (name action) (xdp/xdp-action action))))

;; ============================================================================
;; Example 2: xdp_md Structure
;; ============================================================================

(defn demo-xdp-md-structure
  "Demonstrate xdp_md context structure."
  []
  (println "\n=== xdp_md Context Structure ===\n")

  (println "xdp_md fields and offsets:")
  (doseq [[field offset] (sort-by val xdp/xdp-md-offsets)]
    (printf "  %-20s offset=%d\n" (name field) offset))

  (println "\nUsing xdp-md-offset function:")
  (printf "  data offset:     %d\n" (xdp/xdp-md-offset :data))
  (printf "  data-end offset: %d\n" (xdp/xdp-md-offset :data-end)))

;; ============================================================================
;; Example 3: Protocol Header Offsets
;; ============================================================================

(defn demo-protocol-offsets
  "Show protocol header structures."
  []
  (println "\n=== Protocol Header Structures ===\n")

  (println "Ethernet header (14 bytes):")
  (doseq [[field offset] (sort-by val xdp/ethernet-offsets)]
    (printf "  %-12s offset=%d\n" (name field) offset))

  (println "\nIPv4 header (20+ bytes):")
  (doseq [[field offset] (sort-by val xdp/ipv4-offsets)]
    (printf "  %-14s offset=%d\n" (name field) offset))

  (println "\nTCP header (20+ bytes):")
  (doseq [[field offset] (sort-by val xdp/tcp-offsets)]
    (printf "  %-12s offset=%d\n" (name field) offset))

  (println "\nUDP header (8 bytes):")
  (doseq [[field offset] (sort-by val xdp/udp-offsets)]
    (printf "  %-12s offset=%d\n" (name field) offset)))

;; ============================================================================
;; Example 4: EtherTypes and IP Protocols
;; ============================================================================

(defn demo-protocol-values
  "Show common protocol values."
  []
  (println "\n=== Protocol Values ===\n")

  (println "EtherType values:")
  (doseq [[proto value] xdp/ethertypes]
    (printf "  %-6s = 0x%04X\n" (name proto) value))

  (println "\nIP protocol numbers:")
  (doseq [[proto value] xdp/ip-protocols]
    (printf "  %-8s = %d\n" (name proto) value))

  (println "\nTCP flags:")
  (doseq [[flag value] (sort-by val xdp/tcp-flags)]
    (printf "  %-4s = 0x%02X\n" (name flag) value)))

;; ============================================================================
;; Example 5: XDP Prologue Generation
;; ============================================================================

(defn demo-prologue
  "Demonstrate XDP prologue generation."
  []
  (println "\n=== XDP Prologue Generation ===\n")

  ;; Without context save
  (let [prologue (xdp/xdp-prologue :r2 :r3)]
    (println "Prologue without context save:")
    (println "  (xdp-prologue :r2 :r3)")
    (println "  Instructions:" (count prologue))
    (println "  Total bytes:" (* 8 (count prologue))))

  (println)

  ;; With context save
  (let [prologue (xdp/xdp-prologue :r9 :r2 :r3)]
    (println "Prologue with context save (r9):")
    (println "  (xdp-prologue :r9 :r2 :r3)")
    (println "  Instructions:" (count prologue))
    (println "  Total bytes:" (* 8 (count prologue)))))

;; ============================================================================
;; Example 6: Bounds Checking
;; ============================================================================

(defn demo-bounds-checking
  "Demonstrate bounds checking for packet access."
  []
  (println "\n=== Bounds Checking ===\n")

  (println "Bounds checking is CRITICAL in XDP programs!")
  (println "The verifier requires checks before any packet access.")
  (println)

  (let [insns (xdp/xdp-bounds-check :r2 :r3 14)]
    (println "Bounds check for 14-byte Ethernet header:")
    (println "  (xdp-bounds-check :r2 :r3 14)")
    (println "  Instructions:" (count insns))
    (println "  Default action on fail: XDP_PASS"))

  (println)

  (let [insns (xdp/xdp-bounds-check :r2 :r3 14 :drop)]
    (println "Bounds check with :drop on fail:")
    (println "  (xdp-bounds-check :r2 :r3 14 :drop)")
    (println "  Instructions:" (count insns))))

;; ============================================================================
;; Example 7: Packet Parsing
;; ============================================================================

(defn demo-packet-parsing
  "Demonstrate packet header parsing."
  []
  (println "\n=== Packet Parsing ===\n")

  (println "Parse Ethernet header:")
  (let [insns (xdp/xdp-parse-ethernet :r2 :r3 :r4)]
    (println "  (xdp-parse-ethernet :r2 :r3 :r4)")
    (println "  Instructions:" (count insns))
    (println "  r4 will contain EtherType"))

  (println)

  (println "Parse IPv4 header (at offset 14):")
  (let [insns (xdp/xdp-parse-ipv4 :r2 :r3 14 :r4)]
    (println "  (xdp-parse-ipv4 :r2 :r3 14 :r4)")
    (println "  Instructions:" (count insns))
    (println "  r4 will contain IP protocol"))

  (println)

  (println "Parse IPv4 with src/dst addresses:")
  (let [insns (xdp/xdp-parse-ipv4 :r2 :r3 14 :r4 :r5 :r6)]
    (println "  (xdp-parse-ipv4 :r2 :r3 14 :r4 :r5 :r6)")
    (println "  Instructions:" (count insns))
    (println "  r4=protocol, r5=src IP, r6=dst IP"))

  (println)

  (println "Parse TCP header (at L3 offset 34):")
  (let [insns (xdp/xdp-parse-tcp :r2 :r3 34 :src-port :r4 :dst-port :r5)]
    (println "  (xdp-parse-tcp :r2 :r3 34 :src-port :r4 :dst-port :r5)")
    (println "  Instructions:" (count insns))
    (println "  r4=src port, r5=dst port")))

;; ============================================================================
;; Example 8: Using defxdp-instructions Macro
;; ============================================================================

;; Define a simple drop-all program
(xdp/defxdp-instructions drop-all-prog
  {:default-action :drop}
  [])

;; Define a pass-all program with context save
(xdp/defxdp-instructions pass-all-prog
  {:ctx-reg :r9
   :default-action :pass}
  [(dsl/mov :r4 42)])

(defn demo-macro-usage
  "Demonstrate defxdp-instructions macro."
  []
  (println "\n=== defxdp-instructions Macro ===\n")

  (println "drop-all-prog:")
  (let [insns (drop-all-prog)]
    (println "  Instruction count:" (count insns))
    (println "  All bytes:" (every? bytes? insns)))

  (println)

  (println "pass-all-prog (with context save and body):")
  (let [insns (pass-all-prog)]
    (println "  Instruction count:" (count insns))
    ;; prologue (3) + body (1) + epilogue (2) = 6
    (println "  Expected: 6 instructions")))

;; ============================================================================
;; Example 9: Building Complete Programs
;; ============================================================================

(defn demo-program-building
  "Demonstrate building complete XDP programs."
  []
  (println "\n=== Building Complete XDP Programs ===\n")

  ;; Minimal program
  (let [prog (xdp/build-xdp-program
              {:body []
               :default-action :pass})]
    (println "Minimal XDP program:")
    (println "  Bytecode size:" (count prog) "bytes")
    (println "  Instructions:" (/ (count prog) 8)))

  (println)

  ;; Program with body
  (let [prog (xdp/build-xdp-program
              {:ctx-reg :r9
               :body [(dsl/mov :r4 0)]
               :default-action :drop})]
    (println "XDP program with body:")
    (println "  Bytecode size:" (count prog) "bytes")
    (println "  Instructions:" (/ (count prog) 8))))

;; ============================================================================
;; Example 10: Section Names
;; ============================================================================

(defn demo-section-names
  "Demonstrate section name generation."
  []
  (println "\n=== Section Names ===\n")

  (println "Without interface:")
  (println "  " (xdp/xdp-section-name))

  (println "\nWith interface:")
  (println "  " (xdp/xdp-section-name "eth0"))
  (println "  " (xdp/xdp-section-name "ens192"))
  (println "  " (xdp/xdp-section-name "lo")))

;; ============================================================================
;; Example 11: Program Metadata
;; ============================================================================

(defn demo-program-info
  "Demonstrate creating program metadata."
  []
  (println "\n=== Program Metadata ===\n")

  (let [insns (drop-all-prog)
        info (xdp/make-xdp-program-info "my_xdp_prog" insns)]
    (println "Program info without interface:")
    (println "  Name:" (:name info))
    (println "  Section:" (:section info))
    (println "  Type:" (:type info)))

  (println)

  (let [insns (pass-all-prog)
        info (xdp/make-xdp-program-info "eth0_filter" insns "eth0")]
    (println "Program info with interface:")
    (println "  Name:" (:name info))
    (println "  Section:" (:section info))
    (println "  Interface:" (:interface info))))

;; ============================================================================
;; Example 12: Common Patterns
;; ============================================================================

(defn demo-common-patterns
  "Demonstrate common XDP programming patterns."
  []
  (println "\n=== Common XDP Patterns ===\n")

  ;; Return action
  (println "Return XDP action:")
  (let [insns (xdp/xdp-return-action :drop)]
    (println "  (xdp-return-action :drop)")
    (println "  Instructions:" (count insns)))

  (println)

  ;; TCP-only filter
  (println "Pass only TCP packets:")
  (let [insns (xdp/xdp-pass-only-tcp :r2 :r3)]
    (println "  (xdp-pass-only-tcp :r2 :r3)")
    (println "  Instructions:" (count insns))))

;; ============================================================================
;; Example 13: IP Address Helpers
;; ============================================================================

(defn demo-ip-helpers
  "Demonstrate IP address helper functions."
  []
  (println "\n=== IP Address Helpers ===\n")

  (println "Converting IP strings to integers:")
  (doseq [ip ["10.0.0.1" "127.0.0.1" "192.168.1.1" "8.8.8.8"]]
    (printf "  %-15s => 0x%08X\n" ip (xdp/ipv4-to-int ip)))

  (println)

  (println "Matching source IP (10.0.0.1):")
  (let [insns (xdp/xdp-match-ipv4 :r2 :r3 (xdp/ipv4-to-int "10.0.0.1") true :drop)]
    (println "  (xdp-match-ipv4 :r2 :r3 0x0A000001 true :drop)")
    (println "  Instructions:" (count insns))))

;; ============================================================================
;; Example 14: Complete TCP Filter
;; ============================================================================

(defn build-tcp-port-filter
  "Build an XDP program that drops packets to a specific TCP port."
  [port]
  (dsl/assemble
   (vec (concat
         ;; Prologue: load data pointers
         (xdp/xdp-prologue :r9 :r2 :r3)

         ;; Parse Ethernet header
         (xdp/xdp-parse-ethernet :r2 :r3 :r4)

         ;; Check if IPv4 (EtherType 0x0800 in network byte order)
         [(dsl/jmp-imm :jne :r4 0x0008 2)  ; 0x0800 swapped
          (dsl/mov :r0 (xdp/xdp-action :pass))
          (dsl/exit-insn)]

         ;; Parse IPv4 header
         (xdp/xdp-parse-ipv4 :r2 :r3 14 :r4)

         ;; Check if TCP (protocol 6)
         [(dsl/jmp-imm :jne :r4 6 2)
          (dsl/mov :r0 (xdp/xdp-action :pass))
          (dsl/exit-insn)]

         ;; Parse TCP header (assume no IP options, offset 34)
         (xdp/xdp-parse-tcp :r2 :r3 34 :dst-port :r5)

         ;; Check destination port (port in network byte order)
         (let [port-be (bit-or (bit-shift-left (bit-and port 0xff) 8)
                               (bit-shift-right port 8))]
           [(dsl/jmp-imm :jne :r5 port-be 2)
            (dsl/mov :r0 (xdp/xdp-action :drop))
            (dsl/exit-insn)])

         ;; Default: pass
         [(dsl/mov :r0 (xdp/xdp-action :pass))
          (dsl/exit-insn)]))))

(defn demo-complete-filter
  "Demonstrate a complete TCP port filter."
  []
  (println "\n=== Complete TCP Port Filter ===\n")

  (let [bytecode (build-tcp-port-filter 80)]
    (println "TCP port 80 filter:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))
    (println)
    (println "This program:")
    (println "  1. Parses Ethernet header")
    (println "  2. Checks for IPv4")
    (println "  3. Parses IPv4 header")
    (println "  4. Checks for TCP")
    (println "  5. Parses TCP header")
    (println "  6. Drops packets to port 80")))

;; ============================================================================
;; Example 15: Assembly of Macro Programs
;; ============================================================================

(defn demo-assembly
  "Demonstrate assembling XDP programs."
  []
  (println "\n=== Program Assembly ===\n")

  (let [bytecode (dsl/assemble (drop-all-prog))]
    (println "Assembled drop-all-prog:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8)))

  (println)

  (let [bytecode (dsl/assemble (pass-all-prog))]
    (println "Assembled pass-all-prog:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all XDP DSL demonstrations."
  [& args]
  (println "==============================================")
  (println "  XDP DSL Examples")
  (println "==============================================")

  (demo-xdp-actions)
  (demo-xdp-md-structure)
  (demo-protocol-offsets)
  (demo-protocol-values)
  (demo-prologue)
  (demo-bounds-checking)
  (demo-packet-parsing)
  (demo-macro-usage)
  (demo-program-building)
  (demo-section-names)
  (demo-program-info)
  (demo-common-patterns)
  (demo-ip-helpers)
  (demo-complete-filter)
  (demo-assembly)

  (println "\n==============================================")
  (println "  All demonstrations complete!")
  (println "=============================================="))

;; ============================================================================
;; REPL Usage
;; ============================================================================

(comment
  ;; Run all demos
  (-main)

  ;; Get action values
  (xdp/xdp-action :drop)
  (xdp/xdp-action :pass)

  ;; Check offsets
  (xdp/xdp-md-offset :data)
  (xdp/xdp-md-offset :data-end)

  ;; Generate prologue
  (xdp/xdp-prologue :r2 :r3)
  (xdp/xdp-prologue :r9 :r2 :r3)

  ;; Bounds check
  (xdp/xdp-bounds-check :r2 :r3 14)

  ;; Parse headers
  (xdp/xdp-parse-ethernet :r2 :r3 :r4)
  (xdp/xdp-parse-ipv4 :r2 :r3 14 :r4)
  (xdp/xdp-parse-tcp :r2 :r3 34 :src-port :r4 :dst-port :r5)

  ;; IP conversion
  (xdp/ipv4-to-int "192.168.1.1")
  (xdp/ipv4-to-int "10.0.0.1")

  ;; Use macros
  (drop-all-prog)
  (pass-all-prog)

  ;; Build complete program
  (xdp/build-xdp-program {:body [] :default-action :drop})

  ;; Build port filter
  (build-tcp-port-filter 80)
  (build-tcp-port-filter 443)
  )
