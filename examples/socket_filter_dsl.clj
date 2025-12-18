(ns socket-filter-dsl
  "Examples demonstrating the Socket Filter DSL.

   Socket filter programs can be attached to sockets to filter
   incoming packets. They run on each packet and decide whether
   to pass or drop it.

   Usage: clj -M:dev -m socket-filter-dsl
   Note: Some examples require root privileges for actual BPF loading."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.socket :as socket]))

;; ============================================================================
;; 1. Socket Filter Basics
;; ============================================================================

(defn demo-basics
  "Demonstrate socket filter return values."
  []
  (println "\n=== Socket Filter Basics ===")
  (println "Return values:")
  (println "  0:    Drop the packet")
  (println "  >0:   Number of bytes to pass")
  (println "        (use packet length to pass entire packet)")

  (println "\nAction constants:")
  (println "  :reject" (socket/socket-action :reject))
  (println "  :accept" (socket/socket-action :accept) "(marker, use pkt len)"))

;; ============================================================================
;; 2. Return Patterns Demo
;; ============================================================================

(defn demo-return-patterns
  "Demonstrate socket filter return patterns."
  []
  (println "\n=== Return Patterns ===")

  (println "\nAccept entire packet (return length):")
  (let [insns (socket/socket-accept :r6)]
    (println "  Instruction count:" (count insns)))

  (println "\nAccept specific bytes:")
  (let [insns (socket/socket-accept-bytes 100)]
    (println "  Instruction count:" (count insns)))

  (println "\nReject packet (return 0):")
  (let [insns (socket/socket-reject)]
    (println "  Instruction count:" (count insns))))

;; ============================================================================
;; 3. Context Access Demo
;; ============================================================================

(defn demo-context-access
  "Demonstrate __sk_buff context access."
  []
  (println "\n=== Context Access ===")
  (println "Socket filters use __sk_buff (same as TC)")

  (println "\nKey field offsets:")
  (println "  len:       " (socket/skb-offset :len))
  (println "  protocol:  " (socket/skb-offset :protocol))
  (println "  data:      " (socket/skb-offset :data))
  (println "  data_end:  " (socket/skb-offset :data-end)))

;; ============================================================================
;; 4. Prologue Demo
;; ============================================================================

(defn demo-prologue
  "Demonstrate socket filter prologue."
  []
  (println "\n=== Prologue ===")

  (println "\nBasic prologue (data pointers only):")
  (let [insns (socket/socket-prologue :r2 :r3)]
    (println "  Instruction count:" (count insns)))

  (println "\nPrologue with context save:")
  (let [insns (socket/socket-prologue :r6 :r2 :r3)]
    (println "  Instruction count:" (count insns))))

;; ============================================================================
;; 5. Macro Demo
;; ============================================================================

(socket/defsocket-filter-instructions accept-all
  {:default-action :accept}
  [])

(socket/defsocket-filter-instructions reject-all
  {:default-action :reject}
  [])

(defn demo-macros
  "Demonstrate defsocket-filter-instructions macro."
  []
  (println "\n=== DSL Macros ===")

  (println "\nAccept-all filter:")
  (let [insns (accept-all)]
    (println "  Instruction count:" (count insns)))

  (println "\nReject-all filter:")
  (let [insns (reject-all)]
    (println "  Instruction count:" (count insns))))

;; ============================================================================
;; 6. Protocol Constants Demo
;; ============================================================================

(defn demo-protocol-constants
  "Demonstrate protocol constants available in socket filter."
  []
  (println "\n=== Protocol Constants ===")

  (println "\nHeader sizes:")
  (println "  Ethernet:" socket/ethernet-header-size "bytes")
  (println "  IPv4 min:" socket/ipv4-header-min-size "bytes")
  (println "  IPv6:    " socket/ipv6-header-size "bytes")
  (println "  TCP min: " socket/tcp-header-min-size "bytes")
  (println "  UDP:     " socket/udp-header-size "bytes")

  (println "\nEthertypes:" socket/ethertypes)
  (println "IP protocols:" socket/ip-protocols))

;; ============================================================================
;; 7. Section Names Demo
;; ============================================================================

(defn demo-section-names
  "Demonstrate section name generation."
  []
  (println "\n=== Section Names ===")
  (println "Default:  " (socket/socket-filter-section-name))
  (println "Named:    " (socket/socket-filter-section-name "my_filter")))

;; ============================================================================
;; 8. Program Assembly Demo
;; ============================================================================

(defn demo-assembly
  "Demonstrate program assembly."
  []
  (println "\n=== Program Assembly ===")

  (println "\nUsing build-socket-filter:")
  (let [bytecode (socket/build-socket-filter
                  {:body []
                   :default-action :accept})]
    (println "  Bytecode size:" (count bytecode) "bytes"))

  (println "\nUsing macro-defined program:")
  (let [bytecode (dsl/assemble (accept-all))]
    (println "  Bytecode size:" (count bytecode) "bytes")))

;; ============================================================================
;; 9. Use Cases Demo
;; ============================================================================

(defn demo-use-cases
  "Demonstrate common socket filter use cases."
  []
  (println "\n=== Common Use Cases ===")

  (println "\n1. Packet capture filtering (like tcpdump)")
  (println "   - Attach to raw socket")
  (println "   - Filter by protocol, port, IP address")
  (println "   - Return bytes to capture or 0 to skip")

  (println "\n2. Application-level firewall")
  (println "   - Attach to application socket")
  (println "   - Block unwanted connections")

  (println "\n3. Load balancing")
  (println "   - Filter packets by hash")
  (println "   - Distribute to different processes"))

;; ============================================================================
;; Main
;; ============================================================================

(defn -main
  "Run all Socket Filter DSL demonstrations."
  [& args]
  (println "============================================")
  (println "  Socket Filter DSL Examples")
  (println "============================================")

  (demo-basics)
  (demo-return-patterns)
  (demo-context-access)
  (demo-prologue)
  (demo-macros)
  (demo-protocol-constants)
  (demo-section-names)
  (demo-assembly)
  (demo-use-cases)

  (println "\n============================================")
  (println "  All Socket Filter demonstrations complete!")
  (println "============================================"))
