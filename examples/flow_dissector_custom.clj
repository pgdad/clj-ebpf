(ns examples.flow-dissector-custom
  "Example: FLOW_DISSECTOR Custom Packet Parsing

   This example demonstrates FLOW_DISSECTOR programs for custom packet
   parsing for flow hashing (RSS, ECMP routing). FLOW_DISSECTOR programs
   override the kernel's built-in flow dissector for packets in the
   attached network namespace.

   Use cases demonstrated:
   1. Basic Ethernet/IPv4 flow dissection
   2. TCP/UDP port extraction for flow keys
   3. Custom protocol handling patterns

   NOTE: Actual FLOW_DISSECTOR programs require:
   - Root privileges (CAP_NET_ADMIN + CAP_BPF)
   - Kernel 4.2+ for basic support, 5.0+ for BPF link

   This example focuses on program construction patterns.

   Run with: clj -M:examples -e \"(load-file \\\"examples/flow_dissector_custom.clj\\\")\"
             or: clj -M -m examples.flow-dissector-custom"
  (:require [clj-ebpf.constants :as const]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.flow-dissector :as fd]
            [clj-ebpf.macros :refer [defprogram defmap-spec]]))

;; ============================================================================
;; FLOW_DISSECTOR Architecture
;; ============================================================================
;;
;; When the kernel needs flow information for RSS or ECMP:
;;
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │                       Incoming Packet                               │
;;   │              (needs flow classification)                            │
;;   └──────────────────────────────┬──────────────────────────────────────┘
;;                                  │
;;                                  v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │                  FLOW_DISSECTOR BPF Program                         │
;;   │                                                                     │
;;   │  Input Context (__sk_buff):                                        │
;;   │    - data (packet data pointer)                                    │
;;   │    - data_end (end of packet)                                      │
;;   │    - flow_keys (pointer to output structure)                       │
;;   │                                                                     │
;;   │  Output (bpf_flow_keys):                                           │
;;   │    - nhoff (network header offset)                                 │
;;   │    - thoff (transport header offset)                               │
;;   │    - addr_proto (ETH_P_IP, ETH_P_IPV6)                            │
;;   │    - ip_proto (TCP, UDP, etc.)                                     │
;;   │    - ipv4_src, ipv4_dst (or ipv6_*)                               │
;;   │    - sport, dport (source/dest ports)                              │
;;   │                                                                     │
;;   │  Actions:                                                          │
;;   │    - BPF_OK (0): Success, use filled flow_keys                    │
;;   │    - BPF_DROP (-1): Stop dissection                                │
;;   └─────────────────────────────┬───────────────────────────────────────┘
;;                                 │
;;                    ┌────────────┴────────────┐
;;                    │                         │
;;                    v                         v
;;   ┌────────────────────────────┐   ┌───────────────────────────────────┐
;;   │   BPF_DROP                 │   │   BPF_OK                           │
;;   │   Use built-in dissector   │   │   Use program's flow_keys          │
;;   └────────────────────────────┘   │   for RSS/ECMP hashing            │
;;                                    └───────────────────────────────────┘

;; ============================================================================
;; Example 1: Minimal Passthrough Dissector
;; ============================================================================
;;
;; This program does minimal setup and returns OK, letting the kernel
;; use the flow_keys we've (partially) filled.

(println "\n=== Example 1: Minimal Passthrough Dissector ===")

(def minimal-dissector-instructions
  "FLOW_DISSECTOR that just returns BPF_OK."
  (vec (concat
        ;; Prologue - save context, load data pointers
        (fd/flow-dissector-prologue :r6 :r2 :r3)

        ;; Return OK - let kernel use whatever flow_keys has
        (fd/flow-dissector-ok))))

(println "Minimal dissector instructions:" (count minimal-dissector-instructions))
(println "Assembled bytecode size:" (count (dsl/assemble minimal-dissector-instructions)) "bytes")

;; ============================================================================
;; Example 2: Ethernet Header Parser
;; ============================================================================
;;
;; This program parses the Ethernet header and sets nhoff/n_proto.

(println "\n=== Example 2: Ethernet Header Parser ===")

(def ethernet-parser-instructions
  "FLOW_DISSECTOR that parses Ethernet header."
  (vec (concat
        ;; Prologue
        (fd/flow-dissector-prologue :r6 :r2 :r3)

        ;; Get flow_keys pointer
        [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

        ;; Parse Ethernet header (sets nhoff and n_proto)
        (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)

        ;; Return OK
        (fd/flow-dissector-ok))))

(println "Ethernet parser instructions:" (count ethernet-parser-instructions))
(println "Assembled bytecode size:" (count (dsl/assemble ethernet-parser-instructions)) "bytes")

;; ============================================================================
;; Example 3: IPv4 Flow Dissector
;; ============================================================================
;;
;; Complete dissector that parses Ethernet + IPv4 headers.

(println "\n=== Example 3: IPv4 Flow Dissector ===")

(def ipv4-dissector-instructions
  "FLOW_DISSECTOR for IPv4 packets."
  (vec (concat
        ;; Prologue
        (fd/flow-dissector-prologue :r6 :r2 :r3)

        ;; Get flow_keys pointer
        [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

        ;; Parse Ethernet header
        (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)

        ;; Parse IPv4 header (sets addr_proto, ip_proto, addresses, thoff)
        (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)

        ;; Return OK
        (fd/flow-dissector-ok))))

(println "IPv4 dissector instructions:" (count ipv4-dissector-instructions))
(println "Assembled bytecode size:" (count (dsl/assemble ipv4-dissector-instructions)) "bytes")

;; ============================================================================
;; Example 4: Complete TCP/IPv4 Flow Dissector
;; ============================================================================
;;
;; Full dissector parsing Ethernet, IPv4, and TCP ports.

(println "\n=== Example 4: Complete TCP/IPv4 Dissector ===")

(def tcp-ipv4-dissector-instructions
  "Complete FLOW_DISSECTOR for TCP/IPv4 packets."
  (vec (concat
        ;; Prologue
        (fd/flow-dissector-prologue :r6 :r2 :r3)

        ;; Get flow_keys pointer
        [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

        ;; Parse Ethernet header
        (fd/flow-dissector-parse-ethernet :r2 :r3 :r7 :r0)

        ;; Parse IPv4 header
        (fd/flow-dissector-parse-ipv4 :r2 :r3 :r7 14 :r0 :r1)

        ;; Parse TCP ports (at offset 34 = 14 ethernet + 20 ip min)
        (fd/flow-dissector-parse-tcp-ports :r2 :r3 :r7 34 :r0)

        ;; Return OK
        (fd/flow-dissector-ok))))

(println "TCP/IPv4 dissector instructions:" (count tcp-ipv4-dissector-instructions))
(println "Assembled bytecode size:" (count (dsl/assemble tcp-ipv4-dissector-instructions)) "bytes")

;; ============================================================================
;; Example 5: Using Program Builder
;; ============================================================================

(println "\n=== Example 5: Using Program Builder ===")

(def built-dissector
  (fd/build-flow-dissector-program
   {:ctx-reg :r6
    :data-reg :r2
    :data-end-reg :r3
    :body [;; Get flow_keys pointer
           (fd/flow-dissector-get-flow-keys-ptr :r6 :r7)
           ;; Set nhoff = 14 (Ethernet header size)
           (dsl/mov :r0 14)
           (fd/flow-keys-set-nhoff :r7 :r0)]
    :default-action :ok}))

(println "Built dissector bytecode size:" (count built-dissector) "bytes")

;; ============================================================================
;; Example 6: defprogram Macro Usage
;; ============================================================================

(println "\n=== Example 6: Using defprogram Macro ===")

(defprogram flow-dissector-simple
  "Simple FLOW_DISSECTOR using defprogram macro."
  :type :flow-dissector
  :license "GPL"
  :body (vec (concat
              ;; Prologue
              (fd/flow-dissector-prologue :r6 :r2 :r3)
              ;; Get flow_keys pointer
              [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]
              ;; Set network header offset to 14 (after Ethernet)
              [(dsl/mov :r0 14)
               (fd/flow-keys-set-nhoff :r7 :r0)]
              ;; Return OK
              (fd/flow-dissector-ok))))

(println "defprogram spec created:" (:name flow-dissector-simple))
(println "Program type:" (:type flow-dissector-simple))
(println "License:" (:license flow-dissector-simple))

;; ============================================================================
;; Example 7: Flow Keys Structure Demo
;; ============================================================================

(println "\n=== Example 7: bpf_flow_keys Structure ===")

(println "\nbpf_flow_keys field offsets:")
(doseq [[field offset] (sort-by val fd/flow-keys-offsets)]
  (println (format "  %-15s offset %2d" (name field) offset)))

(println "\nKey fields for 5-tuple flow identification:")
(println "  - addr_proto: Address family (0x0800=IPv4, 0x86DD=IPv6)")
(println "  - ip_proto:   L4 protocol (6=TCP, 17=UDP)")
(println "  - ipv4_src/dst or ipv6_src/dst: IP addresses")
(println "  - sport/dport: Source and destination ports")

;; ============================================================================
;; Example 8: Protocol Constants Demo
;; ============================================================================

(println "\n=== Example 8: Protocol Constants ===")

(println "\nEthernet protocol values (ETH_P_*):")
(doseq [[proto value] (sort-by val fd/ethernet-protocols)]
  (println (format "  %-6s 0x%04X" (name proto) value)))

(println "\nIP protocol values:")
(doseq [[proto value] (sort-by val fd/ip-protocols)]
  (println (format "  %-7s %3d" (name proto) value)))

;; ============================================================================
;; Example 9: Header Size Constants
;; ============================================================================

(println "\n=== Example 9: Header Size Constants ===")

(println "\nStandard header sizes:")
(println (format "  Ethernet header:  %d bytes" fd/ethernet-header-size))
(println (format "  IPv4 min header:  %d bytes" fd/ipv4-header-min-size))
(println (format "  IPv6 header:      %d bytes" fd/ipv6-header-size))
(println (format "  TCP min header:   %d bytes" fd/tcp-header-min-size))
(println (format "  UDP header:       %d bytes" fd/udp-header-size))

(println "\nCommon transport header offsets (after Ethernet):")
(println (format "  IPv4/TCP:  %d (14 + 20)" (+ 14 20)))
(println (format "  IPv4/UDP:  %d (14 + 20)" (+ 14 20)))
(println (format "  IPv6/TCP:  %d (14 + 40)" (+ 14 40)))
(println (format "  IPv6/UDP:  %d (14 + 40)" (+ 14 40)))

;; ============================================================================
;; Example 10: Manual Field Setting Demo
;; ============================================================================

(println "\n=== Example 10: Manual Field Setting ===")

(def manual-set-instructions
  "Demonstrate manual field setting in flow_keys."
  (vec (concat
        ;; Prologue
        (fd/flow-dissector-prologue :r6 :r2 :r3)

        ;; Get flow_keys pointer
        [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)]

        ;; Set nhoff = 14 (after Ethernet header)
        [(dsl/mov :r0 14)
         (fd/flow-keys-set-nhoff :r7 :r0)]

        ;; Set thoff = 34 (after IPv4 header)
        [(dsl/mov :r0 34)
         (fd/flow-keys-set-thoff :r7 :r0)]

        ;; Set addr_proto = ETH_P_IP (0x0800)
        [(dsl/mov :r0 0x0800)
         (fd/flow-keys-set-addr-proto :r7 :r0)]

        ;; Set ip_proto = TCP (6)
        [(dsl/mov :r0 6)
         (fd/flow-keys-set-ip-proto :r7 :r0)]

        ;; Return OK
        (fd/flow-dissector-ok))))

(println "Manual field setting bytecode size:" (count (dsl/assemble manual-set-instructions)) "bytes")

;; ============================================================================
;; Example 11: Byte Order Utilities Demo
;; ============================================================================

(println "\n=== Example 11: Byte Order Utilities ===")

(println "\nPort byte order conversion:")
(let [port 8080]
  (println (format "  Port %d -> network order: 0x%04X" port (fd/htons port))))

(let [port 443]
  (println (format "  Port %d -> network order: 0x%04X" port (fd/htons port))))

(println "\nIP address byte order conversion:")
(let [ip 0xC0A80101]  ; 192.168.1.1
  (println (format "  0x%08X (192.168.1.1) -> network: 0x%08X" ip (fd/htonl ip))))

;; ============================================================================
;; Example 12: Section Names for ELF Output
;; ============================================================================

(println "\n=== Example 12: Section Names ===")

(println "Default section:" (fd/flow-dissector-section-name))
(println "Named section:" (fd/flow-dissector-section-name "my_dissector"))

;; ============================================================================
;; Conceptual Usage Example (Not Runnable Without Root)
;; ============================================================================

(println "\n=== Conceptual Usage (Requires Root + Kernel 5.0+) ===")

(println "
;; Real-world usage would look like:

(require '[clj-ebpf.programs :as progs])

;; 1. Build FLOW_DISSECTOR program bytecode
(def dissector-bytecode
  (fd/build-flow-dissector-program
    {:ctx-reg :r6
     :data-reg :r2
     :data-end-reg :r3
     :body [(fd/flow-dissector-get-flow-keys-ptr :r6 :r7)
            ;; ... parsing logic ...
            ]
     :default-action :ok}))

;; 2. Load the program
(def dissector-prog
  (progs/load-program
    {:prog-type :flow-dissector
     :insns dissector-bytecode
     :license \"GPL\"
     :prog-name \"my_dissector\"}))

;; 3. Attach to network namespace
(def attached-prog
  (progs/attach-flow-dissector dissector-prog
    {:netns-path \"/proc/self/ns/net\"}))

;; Now all packets in this netns will use our dissector
;; for flow hashing decisions (RSS, ECMP routing)

;; 4. Cleanup when done
(progs/close-program attached-prog)
")

;; ============================================================================
;; Use Case: Custom GRE Handling
;; ============================================================================

(println "\n=== Use Case: Custom Protocol Handling ===")

(println "
FLOW_DISSECTOR excels at custom protocol handling:

1. GRE Tunnels:
   - Default dissector may not handle all GRE variants
   - Custom dissector can parse inner headers
   - Enables proper flow hashing for encapsulated traffic

2. Custom Encapsulation:
   - Proprietary tunnel formats
   - Non-standard header layouts
   - Vendor-specific extensions

3. Application-Layer Protocols:
   - Hash on application-specific fields
   - Custom load balancing keys
   - Protocol-aware RSS

Example: Custom 4-byte header after Ethernet:

  ┌──────────────────┬──────────────────┬─────────────────┐
  │   Ethernet (14)  │ Custom hdr (4)   │  IPv4 (20+)     │
  └──────────────────┴──────────────────┴─────────────────┘

  // Set nhoff to skip custom header
  nhoff = 14 + 4 = 18
")

;; ============================================================================
;; Performance Considerations
;; ============================================================================

(println "\n=== Performance Considerations ===")

(println "
FLOW_DISSECTOR programs affect packet processing performance:

1. Keep programs small:
   - Every packet may trigger the dissector
   - Minimize instruction count
   - Use early exits for unsupported protocols

2. Bounds check efficiently:
   - Single bounds check for multiple fields when possible
   - Fail fast on invalid packets

3. Avoid complex logic:
   - Simple conditional chains preferred
   - Minimize branches
   - No loops if possible

4. Use built-in dissector as fallback:
   - Return BPF_DROP to use kernel's dissector
   - Only override when needed
")

;; ============================================================================
;; Summary
;; ============================================================================

(println "\n=== Summary ===")
(println "
FLOW_DISSECTOR programs provide custom packet parsing for:
- RSS (Receive Side Scaling) hash computation
- ECMP routing decisions
- Flow-based load balancing

Key components:
- __sk_buff context with packet data pointers
- bpf_flow_keys output structure
- Attach to network namespace

Kernel requirements:
- Linux 4.2+ for basic FLOW_DISSECTOR support
- Linux 5.0+ for BPF link attachment
- CAP_NET_ADMIN + CAP_BPF capabilities

This example demonstrated:
- Packet parsing patterns (Ethernet, IPv4, TCP/UDP)
- Flow keys field access
- Manual vs helper-based dissection
- Program construction with builders and macros
")

(defn -main [& _args]
  (println "\n=== FLOW_DISSECTOR Example Complete ==="))
