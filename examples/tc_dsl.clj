(ns tc-dsl
  "Examples demonstrating the TC (Traffic Control) DSL.

   TC programs run on the traffic control layer and can be attached to
   qdisc (queueing discipline) ingress/egress points. They operate on
   __sk_buff which provides richer packet metadata than XDP.

   Usage: clj -M:dev -m tc-dsl
   Note: Some examples require root privileges for actual BPF loading."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.tc :as tc]))

;; ============================================================================
;; 1. TC Actions Demo
;; ============================================================================

(defn demo-tc-actions
  "Demonstrate TC action values.

   TC has more action types than XDP for traffic control:
   - TC_ACT_OK (0): Continue normal processing
   - TC_ACT_SHOT (2): Drop the packet
   - TC_ACT_REDIRECT (7): Redirect to another interface
   - TC_ACT_PIPE (3): Continue to next action in chain"
  []
  (println "\n=== TC Actions ===")
  (println "TC_ACT_OK:         " (tc/tc-action :ok))
  (println "TC_ACT_SHOT:       " (tc/tc-action :shot))
  (println "TC_ACT_REDIRECT:   " (tc/tc-action :redirect))
  (println "TC_ACT_PIPE:       " (tc/tc-action :pipe))
  (println "TC_ACT_UNSPEC:     " (tc/tc-action :unspec))
  (println "TC_ACT_RECLASSIFY: " (tc/tc-action :reclassify))
  (println "TC_ACT_STOLEN:     " (tc/tc-action :stolen))
  (println "TC_ACT_QUEUED:     " (tc/tc-action :queued))
  (println "TC_ACT_REPEAT:     " (tc/tc-action :repeat))
  (println "\nAll TC actions:" tc/tc-actions))

;; ============================================================================
;; 2. __sk_buff Structure Demo
;; ============================================================================

(defn demo-skb-offsets
  "Demonstrate __sk_buff structure field offsets.

   __sk_buff provides more metadata than XDP's xdp_md, including:
   - Packet mark (fwmark) - for firewall marking
   - Priority - for QoS
   - TC classid - for traffic classification
   - Interface indices - ingress and egress
   - Address information - IP addresses and ports"
  []
  (println "\n=== __sk_buff Structure Offsets ===")
  (println "Basic fields:")
  (println "  len:             " (tc/skb-offset :len))
  (println "  pkt_type:        " (tc/skb-offset :pkt-type))
  (println "  protocol:        " (tc/skb-offset :protocol))

  (println "\nMarking/Classification:")
  (println "  mark:            " (tc/skb-offset :mark))
  (println "  priority:        " (tc/skb-offset :priority))
  (println "  tc_classid:      " (tc/skb-offset :tc-classid))
  (println "  tc_index:        " (tc/skb-offset :tc-index))

  (println "\nInterface info:")
  (println "  ingress_ifindex: " (tc/skb-offset :ingress-ifindex))
  (println "  ifindex:         " (tc/skb-offset :ifindex))

  (println "\nVLAN info:")
  (println "  vlan_present:    " (tc/skb-offset :vlan-present))
  (println "  vlan_tci:        " (tc/skb-offset :vlan-tci))
  (println "  vlan_proto:      " (tc/skb-offset :vlan-proto))

  (println "\nData pointers:")
  (println "  data:            " (tc/skb-offset :data))
  (println "  data_end:        " (tc/skb-offset :data-end))
  (println "  data_meta:       " (tc/skb-offset :data-meta))

  (println "\nAddress info:")
  (println "  remote_ip4:      " (tc/skb-offset :remote-ip4))
  (println "  local_ip4:       " (tc/skb-offset :local-ip4))
  (println "  remote_port:     " (tc/skb-offset :remote-port))
  (println "  local_port:      " (tc/skb-offset :local-port))
  (println "  family:          " (tc/skb-offset :family))

  (println "\nMiscellaneous:")
  (println "  hash:            " (tc/skb-offset :hash))
  (println "  queue_mapping:   " (tc/skb-offset :queue-mapping))
  (println "  napi_id:         " (tc/skb-offset :napi-id))
  (println "  tstamp:          " (tc/skb-offset :tstamp)))

;; ============================================================================
;; 3. Context Field Access Demo
;; ============================================================================

(defn demo-context-access
  "Demonstrate accessing __sk_buff fields."
  []
  (println "\n=== Context Field Access ===")

  ;; Load data pointers
  (println "\nLoading data pointers:")
  (let [data-ptrs (tc/tc-load-data-pointers :r1 :r2 :r3)]
    (doseq [insn data-ptrs]
      (println " " (pr-str insn))))

  ;; TC prologue
  (println "\nTC prologue (save ctx to r6, data to r2, data_end to r3):")
  (let [prologue (tc/tc-prologue :r6 :r2 :r3)]
    (doseq [insn prologue]
      (println " " (pr-str insn))))

  ;; Individual field access
  (println "\nAccessing individual fields:")
  (println "  Mark:     " (pr-str (tc/tc-get-mark :r1 :r0)))
  (println "  Priority: " (pr-str (tc/tc-get-priority :r1 :r0)))
  (println "  TC Classid:" (pr-str (tc/tc-get-tc-classid :r1 :r0)))
  (println "  Protocol: " (pr-str (tc/tc-get-protocol :r1 :r0)))
  (println "  Ifindex:  " (pr-str (tc/tc-get-ifindex :r1 :r0)))
  (println "  Length:   " (pr-str (tc/tc-get-len :r1 :r0)))
  (println "  Hash:     " (pr-str (tc/tc-get-hash :r1 :r0))))

;; ============================================================================
;; 4. TC-Specific Operations Demo
;; ============================================================================

(defn demo-tc-operations
  "Demonstrate TC-specific operations like marking and classification."
  []
  (println "\n=== TC-Specific Operations ===")

  ;; Setting mark
  (println "\nSetting packet mark to 0x1234:")
  (let [mark-ops (tc/tc-mark-packet :r6 0x1234)]
    (doseq [insn mark-ops]
      (println " " (pr-str insn))))

  ;; Setting classid (major:minor format)
  (println "\nSetting TC classid 1:10:")
  (let [classify-ops (tc/tc-classify-packet :r6 1 10)]
    (doseq [insn classify-ops]
      (println " " (pr-str insn))))

  ;; Matching mark
  (println "\nMatching packet mark (drop if mark == 0xdead):")
  (let [match-ops (tc/tc-match-mark :r6 0xdead :shot)]
    (doseq [insn match-ops]
      (println " " (pr-str insn)))))

;; ============================================================================
;; 5. TC Helper Functions Demo
;; ============================================================================

(defn demo-tc-helpers
  "Demonstrate TC helper function calls."
  []
  (println "\n=== TC Helper Functions ===")

  ;; Redirect
  (println "\nRedirect to interface 3:")
  (let [redirect-ops (tc/tc-redirect 3 0)]
    (doseq [insn redirect-ops]
      (println " " (pr-str insn))))

  ;; Clone redirect
  (println "\nClone and redirect to interface 4:")
  (let [clone-ops (tc/tc-clone-redirect :r6 4 0)]
    (doseq [insn clone-ops]
      (println " " (pr-str insn))))

  ;; Load bytes
  (println "\nLoad 16 bytes from offset 0:")
  (let [load-ops (tc/tc-skb-load-bytes :r6 0 :r7 16)]
    (doseq [insn load-ops]
      (println " " (pr-str insn))))

  ;; Store bytes
  (println "\nStore 4 bytes at offset 12:")
  (let [store-ops (tc/tc-skb-store-bytes :r6 12 :r7 4 0)]
    (doseq [insn store-ops]
      (println " " (pr-str insn))))

  ;; Change head
  (println "\nAdjust packet headroom (add 14 bytes):")
  (let [head-ops (tc/tc-skb-change-head :r6 14 0)]
    (doseq [insn head-ops]
      (println " " (pr-str insn))))

  ;; L3 checksum replace
  (println "\nUpdate L3 checksum:")
  (let [csum-ops (tc/tc-l3-csum-replace :r6 24 0x1234 0x5678 4)]
    (doseq [insn csum-ops]
      (println " " (pr-str insn)))))

;; ============================================================================
;; 6. Protocol Parsing Demo
;; ============================================================================

(defn demo-protocol-parsing
  "Demonstrate protocol parsing (shared with XDP)."
  []
  (println "\n=== Protocol Parsing ===")

  (println "\nHeader sizes:")
  (println "  Ethernet: " tc/ethernet-header-size "bytes")
  (println "  IPv4 min: " tc/ipv4-header-min-size "bytes")
  (println "  IPv6:     " tc/ipv6-header-size "bytes")
  (println "  TCP min:  " tc/tcp-header-min-size "bytes")
  (println "  UDP:      " tc/udp-header-size "bytes")

  (println "\nEthernet header offsets:" tc/ethernet-offsets)
  (println "IPv4 header offsets:" tc/ipv4-offsets)
  (println "TCP header offsets:" tc/tcp-offsets)
  (println "UDP header offsets:" tc/udp-offsets)

  (println "\nEthertypes:" tc/ethertypes)
  (println "IP protocols:" tc/ip-protocols)
  (println "TCP flags:" tc/tcp-flags)

  ;; Parse ethernet
  (println "\nParse Ethernet header:")
  (let [eth-ops (tc/tc-parse-ethernet :r2 :r3 :r4 "drop")]
    (doseq [insn eth-ops]
      (println " " (pr-str insn))))

  ;; Parse IPv4
  (println "\nParse IPv4 header (after Ethernet):")
  (let [ipv4-ops (tc/tc-parse-ipv4 :r2 :r3 :r4 tc/ethernet-header-size "drop")]
    (doseq [insn ipv4-ops]
      (println " " (pr-str insn)))))

;; ============================================================================
;; 7. deftc-instructions Macro Demo
;; ============================================================================

;; Simple pass-through program
(tc/deftc-instructions tc-pass-all
  {:default-action :ok}
  [])

;; Drop all traffic program
(tc/deftc-instructions tc-drop-all
  {:default-action :shot}
  [])

;; Mark all packets
(tc/deftc-instructions tc-mark-all
  {:ctx-reg :r6
   :default-action :ok}
  (tc/tc-mark-packet :r6 0xCAFE))

;; Classify packets (set classid)
(tc/deftc-instructions tc-classify-all
  {:ctx-reg :r6
   :default-action :ok}
  (tc/tc-classify-packet :r6 1 100))

;; Drop packets with specific mark
(tc/deftc-instructions tc-drop-marked
  {:ctx-reg :r6
   :default-action :ok}
  (tc/tc-match-mark :r6 0xDEAD :shot))

(defn demo-tc-macros
  "Demonstrate the deftc-instructions macro."
  []
  (println "\n=== deftc-instructions Macro ===")

  (println "\nPass-through program:")
  (let [insns (tc-pass-all)]
    (println "  Instruction count:" (count insns))
    (doseq [insn insns]
      (println " " (pr-str insn))))

  (println "\nDrop-all program:")
  (let [insns (tc-drop-all)]
    (println "  Instruction count:" (count insns))
    (doseq [insn insns]
      (println " " (pr-str insn))))

  (println "\nMark-all program:")
  (let [insns (tc-mark-all)]
    (println "  Instruction count:" (count insns))
    (doseq [insn insns]
      (println " " (pr-str insn))))

  (println "\nClassify-all program:")
  (let [insns (tc-classify-all)]
    (println "  Instruction count:" (count insns))
    (doseq [insn insns]
      (println " " (pr-str insn))))

  (println "\nDrop-marked program:")
  (let [insns (tc-drop-marked)]
    (println "  Instruction count:" (count insns))
    (doseq [insn insns]
      (println " " (pr-str insn)))))

;; ============================================================================
;; 8. Section Names and Metadata Demo
;; ============================================================================

(defn demo-section-names
  "Demonstrate TC section name generation and program metadata."
  []
  (println "\n=== Section Names and Metadata ===")

  (println "\nSection name variants:")
  (println "  Basic:   " (tc/tc-section-name))
  (println "  Ingress: " (tc/tc-section-name :ingress))
  (println "  Egress:  " (tc/tc-section-name :egress))
  (println "  With iface:" (tc/tc-section-name :ingress "eth0"))

  (println "\nProgram metadata (basic):")
  (let [meta (tc/make-tc-program-info "my_tc_filter" (tc-pass-all))]
    (println "  Name:         " (:name meta))
    (println "  Section:      " (:section meta))
    (println "  Type:         " (:type meta))
    (println "  Insn count:   " (count (:instructions meta))))

  (println "\nProgram metadata (with direction):")
  (let [meta (tc/make-tc-program-info "ingress_filter" (tc-drop-all) :ingress)]
    (println "  Name:         " (:name meta))
    (println "  Section:      " (:section meta))
    (println "  Direction:    " (:direction meta)))

  (println "\nProgram metadata (with interface):")
  (let [meta (tc/make-tc-program-info "eth0_filter" (tc-mark-all) :egress "eth0")]
    (println "  Name:         " (:name meta))
    (println "  Section:      " (:section meta))
    (println "  Direction:    " (:direction meta))
    (println "  Interface:    " (:interface meta))))

;; ============================================================================
;; 9. Program Assembly Demo
;; ============================================================================

(defn demo-program-assembly
  "Demonstrate assembling TC programs to bytecode."
  []
  (println "\n=== Program Assembly ===")

  (println "\nAssembling pass-through program:")
  (let [insns (tc-pass-all)
        bytecode (dsl/assemble insns)]
    (println "  Instructions:" (count insns))
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  First 32 bytes:" (take 32 (seq bytecode))))

  (println "\nUsing build-tc-program:")
  (let [bytecode (tc/build-tc-program
                  {:ctx-reg :r6
                   :body [(tc/tc-get-mark :r6 :r0)
                          (dsl/jmp-imm :jne :r0 0x1234 2)
                          (dsl/mov :r0 (tc/tc-action :shot))
                          (dsl/exit-insn)]
                   :default-action :ok})]
    (println "  Bytecode size:" (count bytecode) "bytes")))

;; ============================================================================
;; 10. Comparison with XDP Demo
;; ============================================================================

(defn demo-xdp-comparison
  "Compare TC and XDP approaches."
  []
  (println "\n=== TC vs XDP Comparison ===")

  (println "\nTC advantages over XDP:")
  (println "  - Full socket buffer metadata (mark, priority, classid)")
  (println "  - Can run at both ingress and egress")
  (println "  - More helper functions available")
  (println "  - Works with all network interfaces")

  (println "\nXDP advantages over TC:")
  (println "  - Runs earlier in the stack (faster)")
  (println "  - Lower overhead")
  (println "  - Driver-level offload possible (XDP_OFFLOAD)")

  (println "\nContext structure comparison:")
  (println "  XDP uses xdp_md (5 fields)")
  (println "  TC uses __sk_buff (30+ fields)")

  (println "\nShared protocol parsing:")
  (println "  TC reuses XDP's protocol parsing functions")
  (println "  Same header offset constants")
  (println "  Same bounds checking patterns"))

;; ============================================================================
;; 11. Practical Example: Rate Limiter
;; ============================================================================

(defn demo-rate-limiter-pattern
  "Demonstrate a rate limiter pattern using TC mark.

   This pattern shows how to:
   1. Check packet mark (set by earlier stages)
   2. Apply rate limiting based on mark
   3. Use TC classid for traffic shaping"
  []
  (println "\n=== Rate Limiter Pattern ===")

  (println "\nRate limiter using mark-based classification:")
  (println "  1. Check if packet already marked")
  (println "  2. Mark new packets with priority class")
  (println "  3. Assign TC classid for traffic shaping")

  ;; Build a rate limiter program
  (let [program-insns
        (vec (concat
              ;; Prologue - save context, load data pointers
              (tc/tc-prologue :r6 :r2 :r3)

              ;; Check existing mark
              [(tc/tc-get-mark :r6 :r0)]

              ;; If mark is 0x1 (already marked as limited), assign to slow class
              [(dsl/jmp-imm :jne :r0 0x1 3)]
              ;; Set classid 1:100 (slow class)
              (tc/tc-classify-packet :r6 1 100)
              (tc/tc-return-action :ok)

              ;; If mark is 0x2 (priority traffic), assign to fast class
              [(dsl/jmp-imm :jne :r0 0x2 3)]
              ;; Set classid 1:10 (fast class)
              (tc/tc-classify-packet :r6 1 10)
              (tc/tc-return-action :ok)

              ;; Default: mark for tracking and pass
              (tc/tc-mark-packet :r6 0x1)
              (tc/tc-return-action :ok)))]

    (println "\nRate limiter program:")
    (println "  Instruction count:" (count program-insns))
    (println "  Bytecode size:" (count (dsl/assemble program-insns)) "bytes")
    (println "\nInstructions:")
    (doseq [insn program-insns]
      (println " " (pr-str insn)))))

;; ============================================================================
;; 12. Practical Example: VLAN Tagger
;; ============================================================================

(defn demo-vlan-tagger-pattern
  "Demonstrate a VLAN tagging pattern.

   This pattern shows how to:
   1. Check VLAN presence
   2. Read VLAN TCI
   3. Make routing decisions based on VLAN"
  []
  (println "\n=== VLAN Tagger Pattern ===")

  (println "\nVLAN-based routing program:")
  (println "  1. Check if VLAN tag present")
  (println "  2. Read VLAN ID")
  (println "  3. Route based on VLAN")

  ;; Build VLAN router
  (let [program-insns
        (vec (concat
              ;; Prologue
              (tc/tc-prologue :r6 :r2 :r3)

              ;; Check VLAN present
              [(tc/tc-load-ctx-field :r6 :vlan-present :r0)]
              [(dsl/jmp-imm :jeq :r0 0 4)]  ; No VLAN, skip ahead

              ;; Read VLAN TCI (contains VID in lower 12 bits)
              [(tc/tc-load-ctx-field :r6 :vlan-tci :r0)]
              [(dsl/alu-imm :and :r0 0x0FFF)]  ; Mask to get VID

              ;; VLAN 100 -> classid 1:100
              [(dsl/jmp-imm :jne :r0 100 3)]
              (tc/tc-classify-packet :r6 1 100)
              (tc/tc-return-action :ok)

              ;; VLAN 200 -> classid 1:200
              [(dsl/jmp-imm :jne :r0 200 3)]
              (tc/tc-classify-packet :r6 1 200)
              (tc/tc-return-action :ok)

              ;; Default action
              (tc/tc-return-action :ok)))]

    (println "\nVLAN router program:")
    (println "  Instruction count:" (count program-insns))
    (doseq [insn program-insns]
      (println " " (pr-str insn)))))

;; ============================================================================
;; 13. TC Return Actions Demo
;; ============================================================================

(defn demo-return-actions
  "Demonstrate TC return action patterns."
  []
  (println "\n=== TC Return Actions ===")

  (println "\nReturn action instructions:")
  (println "  Return OK:       " (pr-str (tc/tc-return-action :ok)))
  (println "  Return SHOT:     " (pr-str (tc/tc-return-action :shot)))
  (println "  Return REDIRECT: " (pr-str (tc/tc-return-action :redirect)))
  (println "  Return PIPE:     " (pr-str (tc/tc-return-action :pipe)))

  (println "\nConditional return pattern:")
  (let [cond-return
        [;; Check condition (e.g., packet length > 1500)
         (tc/tc-get-len :r6 :r0)
         (dsl/jmp-imm :jle :r0 1500 2)  ; If len <= 1500, skip drop
         (dsl/mov :r0 (tc/tc-action :shot))
         (dsl/exit-insn)
         ;; Continue normal processing
         (dsl/mov :r0 (tc/tc-action :ok))
         (dsl/exit-insn)]]
    (doseq [insn cond-return]
      (println " " (pr-str insn)))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all TC DSL demonstrations."
  [& args]
  (println "============================================")
  (println "  TC (Traffic Control) DSL Examples")
  (println "============================================")

  (demo-tc-actions)
  (demo-skb-offsets)
  (demo-context-access)
  (demo-tc-operations)
  (demo-tc-helpers)
  (demo-protocol-parsing)
  (demo-tc-macros)
  (demo-section-names)
  (demo-program-assembly)
  (demo-xdp-comparison)
  (demo-rate-limiter-pattern)
  (demo-vlan-tagger-pattern)
  (demo-return-actions)

  (println "\n============================================")
  (println "  All TC DSL demonstrations complete!")
  (println "============================================"))
