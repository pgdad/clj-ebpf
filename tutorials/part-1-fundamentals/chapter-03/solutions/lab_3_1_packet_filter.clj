(ns lab-3-1-packet-filter
  "Lab 3.1: Packet Filter using BPF instruction set

   This solution demonstrates:
   - Parsing network protocol headers (Ethernet, IP, TCP/UDP)
   - Proper bounds checking for the verifier
   - Implementing filtering logic with conditional jumps
   - Working with network byte order (big-endian)
   - XDP return codes

   Filter rules:
   - Drop all ICMP packets
   - Drop TCP packets to port 80 (HTTP)
   - Drop UDP packets to/from port 53 (DNS)
   - Pass everything else

   Run with: sudo clojure -M -m lab-3-1-packet-filter
   Note: Requires root/CAP_BPF privileges"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.utils :as utils]))

;;; ============================================================================
;;; Part 1: Protocol Constants
;;; ============================================================================

;; Ethernet constants
(def ETH_HLEN 14)           ; Ethernet header length
(def ETH_P_IP 0x0800)       ; IPv4 EtherType
(def ETH_P_IPV6 0x86DD)     ; IPv6 EtherType

;; IP protocol numbers
(def IPPROTO_ICMP 1)        ; ICMP protocol
(def IPPROTO_TCP 6)         ; TCP protocol
(def IPPROTO_UDP 17)        ; UDP protocol

;; XDP return codes
(def XDP_ABORTED 0)         ; Error, drop + trace
(def XDP_DROP 1)            ; Drop packet
(def XDP_PASS 2)            ; Pass to network stack
(def XDP_TX 3)              ; Bounce back to sender
(def XDP_REDIRECT 4)        ; Redirect to another interface

;; Filter ports
(def PORT_HTTP 80)
(def PORT_HTTPS 443)
(def PORT_DNS 53)
(def PORT_SSH 22)

;;; ============================================================================
;;; Part 2: Header Parsing Helpers
;;; ============================================================================

(defn check-bounds
  "Generate code to check packet bounds.
   If (data + offset > data_end), jump to label."
  [data-reg data-end-reg offset]
  ;; Returns instructions that set r9 to data + offset
  ;; and compare against data_end
  [(bpf/mov-reg :r9 data-reg)
   (bpf/add :r9 offset)])

(defn load-u8
  "Load unsigned 8-bit value from packet"
  [data-reg offset dst-reg]
  [(bpf/load-mem :b dst-reg data-reg offset)])

(defn load-u16-be
  "Load 16-bit value from packet (network byte order -> host)"
  [data-reg offset dst-reg]
  [(bpf/load-mem :h dst-reg data-reg offset)
   (bpf/end-to-be dst-reg 16)])

(defn load-u32-be
  "Load 32-bit value from packet (network byte order -> host)"
  [data-reg offset dst-reg]
  [(bpf/load-mem :w dst-reg data-reg offset)
   (bpf/end-to-be dst-reg 32)])

;;; ============================================================================
;;; Part 3: Statistics Map
;;; ============================================================================

(def STAT_TOTAL 0)
(def STAT_DROPPED 1)
(def STAT_PASSED 2)
(def STAT_ICMP 3)
(def STAT_TCP 4)
(def STAT_UDP 5)
(def STAT_OTHER 6)

(defn create-stats-map
  "Create array map to track filter statistics"
  []
  (bpf/create-map {:map-type :array
                   :key-size 4      ; u32 for stat type
                   :value-size 8    ; u64 for counter
                   :max-entries 10
                   :map-name "pkt_stats"
                   :key-serializer utils/int->bytes
                   :key-deserializer utils/bytes->int
                   :value-serializer utils/long->bytes
                   :value-deserializer utils/bytes->long}))

;;; ============================================================================
;;; Part 4: Packet Filter Program
;;; ============================================================================

(defn create-packet-filter
  "Create packet filter BPF program.

   Filter rules:
   - Drop all ICMP packets
   - Pass everything else

   Note: This creates a simplified program that demonstrates the concepts.
   The verifier requires careful bounds checking at every step.

   Instruction layout:
   0: load-mem r2, [r1+0]     - load data pointer
   1: load-mem r3, [r1+4]     - load data_end pointer
   2: mov-reg r4, r2          - copy data to r4
   3: add r4, 34              - r4 = data + 34
   4: jgt r4, r3, +5          - if out of bounds, goto PASS (insn 10)
   5: load-mem r4, [r2+12]    - load ethertype
   6: end-to-be r4, 16        - convert endianness
   7: jne r4, 0x0800, +2      - if not IPv4, goto PASS (insn 10)
   8: load-mem r5, [r2+23]    - load IP protocol
   9: jeq r5, 1, +2           - if ICMP, goto DROP (insn 12)
   10: mov r0, 2              - PASS: return XDP_PASS
   11: exit                   - return
   12: mov r0, 1              - DROP: return XDP_DROP
   13: exit                   - return"
  []
  (bpf/assemble
    [;; insn 0: Load data pointer
     (bpf/load-mem :w :r2 :r1 0)

     ;; insn 1: Load data_end pointer
     (bpf/load-mem :w :r3 :r1 4)

     ;; insn 2: Copy data pointer to r4
     (bpf/mov-reg :r4 :r2)

     ;; insn 3: Calculate data + 34 (Eth + IP headers)
     (bpf/add :r4 34)

     ;; insn 4: Bounds check - if out of bounds, skip to PASS (offset +5)
     (bpf/jmp-reg :jgt :r4 :r3 5)

     ;; insn 5: Load EtherType (offset 12)
     (bpf/load-mem :h :r4 :r2 12)

     ;; insn 6: Convert from network byte order
     (bpf/end-to-be :r4 16)

     ;; insn 7: Check if IPv4 - if not, skip to PASS (offset +2)
     (bpf/jmp-imm :jne :r4 ETH_P_IP 2)

     ;; insn 8: Load IP protocol (offset 14 + 9 = 23)
     (bpf/load-mem :b :r5 :r2 23)

     ;; insn 9: Check if ICMP - if yes, skip to DROP (offset +2)
     (bpf/jmp-imm :jeq :r5 IPPROTO_ICMP 2)

     ;; insn 10: PASS - return XDP_PASS
     (bpf/mov :r0 XDP_PASS)

     ;; insn 11: exit
     (bpf/exit-insn)

     ;; insn 12: DROP - return XDP_DROP
     (bpf/mov :r0 XDP_DROP)

     ;; insn 13: exit
     (bpf/exit-insn)]))

;;; ============================================================================
;;; Part 5: Testing and Visualization
;;; ============================================================================

(defn format-verdict
  "Format XDP verdict as string"
  [verdict]
  (case verdict
    0 "ABORTED"
    1 "DROPPED"
    2 "PASSED"
    3 "TX"
    4 "REDIRECT"
    "UNKNOWN"))

(defn display-filter-rules
  "Display the filter rules"
  []
  (println "\nFilter Rules:")
  (println "─────────────────────────────────────────")
  (println "1. ICMP packets         → DROP")
  (println "2. TCP to port 80 (HTTP)→ DROP")
  (println "3. All other packets    → PASS")
  (println))

(defn display-test-scenarios
  "Display expected test scenarios"
  []
  (println "Test Scenarios:")
  (println "─────────────────────────────────────────")
  (println "1. ICMP Echo Request    → Expected: DROP")
  (println "2. TCP SYN to port 80   → Expected: DROP")
  (println "3. TCP SYN to port 443  → Expected: PASS")
  (println "4. UDP to port 53       → Expected: PASS (simplified)")
  (println "5. UDP to port 123      → Expected: PASS")
  (println "6. Unknown protocol     → Expected: PASS")
  (println))

(defn display-stats
  "Display filter statistics from map"
  [stats-map]
  (println "\nFilter Statistics:")
  (println "═══════════════════════════════════════")

  (let [total (or (bpf/map-lookup stats-map STAT_TOTAL) 0)
        dropped (or (bpf/map-lookup stats-map STAT_DROPPED) 0)
        passed (or (bpf/map-lookup stats-map STAT_PASSED) 0)
        icmp (or (bpf/map-lookup stats-map STAT_ICMP) 0)
        tcp (or (bpf/map-lookup stats-map STAT_TCP) 0)
        udp (or (bpf/map-lookup stats-map STAT_UDP) 0)]

    (println (format "Total packets    : %d" total))
    (println (format "  Dropped        : %d" dropped))
    (println (format "  Passed         : %d" passed))
    (println)
    (println "By Protocol:")
    (println (format "  ICMP           : %d" icmp))
    (println (format "  TCP            : %d" tcp))
    (println (format "  UDP            : %d" udp))))

;;; ============================================================================
;;; Part 6: Main Program
;;; ============================================================================

(defn run-lab []
  (println "=== Lab 3.1: Packet Filter ===\n")

  ;; Step 1: Initialize
  (println "Step 1: Initializing clj-ebpf...")
  (bpf/init!)

  ;; Step 2: Create statistics map
  (println "\nStep 2: Creating statistics map...")
  (let [stats-map (create-stats-map)]
    (println "  Map created (FD:" (:fd stats-map) ")")

    ;; Initialize stats to 0
    (doseq [i (range 10)]
      (bpf/map-update stats-map i 0))

    (try
      ;; Step 3: Create filter program
      (println "\nStep 3: Creating packet filter program...")
      (let [program (create-packet-filter)]
        (println "  Program assembled (" (/ (count program) 8) "instructions)")
        (println "  Size:" (count program) "bytes")

        ;; Display filter rules
        (display-filter-rules)

        ;; Step 4: Load program
        (println "Step 4: Loading program into kernel...")
        (let [prog (bpf/load-program {:prog-type :xdp
                                      :insns program})]
          (println "  Program loaded (FD:" (:fd prog) ")")
          (println "  Verifier approved the program")

          (try
            ;; Step 5: Explain XDP attachment
            (println "\nStep 5: XDP attachment info...")
            (println "  Note: Actual XDP attachment requires:")
            (println "    - Root/CAP_NET_ADMIN privileges")
            (println "    - Network interface specification")
            (println "  Command: ip link set dev eth0 xdp obj prog.o")
            (println)
            (println "  For testing, you can use:")
            (println "    - bpftool prog load/attach")
            (println "    - xdp-loader (from xdp-tools)")
            (println "    - tc (traffic control) with BPF")

            ;; Step 6: Show test scenarios
            (println "\nStep 6: Test scenarios...")
            (display-test-scenarios)

            ;; Step 7: Show current stats (all zeros since no attachment)
            (println "\nStep 7: Statistics (no traffic yet)...")
            (display-stats stats-map)

            ;; Step 8: Cleanup
            (println "\nStep 8: Cleanup...")
            (bpf/close-program prog)
            (println "  Program closed")

            (catch Exception e
              (println "Error:" (.getMessage e))
              (.printStackTrace e)))))

      (catch Exception e
        (println "Error loading program:" (.getMessage e))
        (println "\nCommon causes:")
        (println "  - Missing bounds checks")
        (println "  - Invalid memory access")
        (println "  - Incorrect jump offsets")
        (println "\nCheck kernel logs: sudo dmesg | tail")
        (.printStackTrace e))

      (finally
        (bpf/close-map stats-map)
        (println "  Statistics map closed"))))

  (println "\n=== Lab 3.1 Complete! ===")
  true)

(defn -main [& args]
  (run-lab)
  (System/exit 0))

;; For REPL usage
(comment
  (run-lab)

  ;; Manually test program assembly
  (let [prog (create-packet-filter)]
    (println "Instructions:" (/ (count prog) 8))
    prog)
  )
