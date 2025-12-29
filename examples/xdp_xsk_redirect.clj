(ns examples.xdp-xsk-redirect
  "Example: AF_XDP Zero-Copy Packet Processing with XSKMAP

   This example demonstrates how to use XSKMAP for high-performance
   packet delivery to userspace using AF_XDP (XDP Sockets).

   AF_XDP Architecture:
   ┌─────────────────────────────────────────────────────────────┐
   │                       Userspace                              │
   │  ┌─────────────────────────────────────────────────────┐    │
   │  │              Application                             │    │
   │  │   ┌─────────┐  ┌─────────┐  ┌─────────┐            │    │
   │  │   │  Fill   │  │Completion│  │   RX    │  │   TX    │    │
   │  │   │  Ring   │  │  Ring   │  │  Ring   │  │  Ring   │    │
   │  │   └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘    │
   │  └────────┼───────────┼───────────┼───────────┼─────────┘    │
   │           │           │           │           │              │
   │           └───────────┴───────────┴───────────┘              │
   │                           │                                   │
   │                      UMEM (Shared Memory)                    │
   └───────────────────────────┼───────────────────────────────────┘
                               │
   ┌───────────────────────────┼───────────────────────────────────┐
   │                       Kernel                                   │
   │  ┌─────────────────────────────────────────────────────────┐  │
   │  │                    XDP Program                           │  │
   │  │     if (match) bpf_redirect_map(&xskmap, queue, 0)     │  │
   │  └────────────────────────┬────────────────────────────────┘  │
   │                           │                                    │
   │  ┌────────────────────────┼────────────────────────────────┐  │
   │  │                     XSKMAP                               │  │
   │  │  [0] -> XSK socket for queue 0                         │  │
   │  │  [1] -> XSK socket for queue 1                         │  │
   │  │  ...                                                    │  │
   │  └─────────────────────────────────────────────────────────┘  │
   │                           │                                    │
   │  ┌────────────────────────┼────────────────────────────────┐  │
   │  │                     NIC Driver                          │  │
   │  │               RX Queue 0  RX Queue 1  ...              │  │
   │  └─────────────────────────────────────────────────────────┘  │
   └────────────────────────────────────────────────────────────────┘

   Key Benefits:
   - Zero-copy: Packets delivered directly to userspace memory
   - Kernel bypass: No TCP/IP stack overhead for matched packets
   - High throughput: Millions of packets per second possible
   - Low latency: Sub-microsecond packet delivery

   Note: This example shows the BPF/XDP side. Full AF_XDP requires:
   - Creating AF_XDP sockets (socket(AF_XDP, SOCK_RAW, 0))
   - Setting up UMEM shared memory
   - Managing ring buffers (Fill, Completion, RX, TX)
   See kernel documentation or libxdp for complete AF_XDP setup."
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.xdp :as xdp]
            [clj-ebpf.macros :refer [defmap-spec defprogram]]))

;; ============================================================================
;; XSKMAP Definition
;; ============================================================================

(defmap-spec xsk-sockets
  "XSKMAP for AF_XDP socket redirection.
   Maps queue indices to XSK socket file descriptors."
  :type :xskmap
  :key-size 4          ; Queue index (u32)
  :value-size 4        ; XSK socket FD (u32)
  :max-entries 64)     ; Support up to 64 RX queues

;; ============================================================================
;; XDP Programs for XSKMAP
;; ============================================================================

(defprogram xdp-xsk-redirect-all
  "XDP program that redirects ALL packets to XSK.
   Every packet goes to the XSK socket for its RX queue."
  :type :xdp
  :license "GPL"
  :body [;; Save context (xdp_md pointer)
         (dsl/mov-reg :r6 :r1)
         ;; Load rx_queue_index from xdp_md (offset 16)
         (dsl/ldx :w :r4 :r6 16)
         ;; Redirect to XSK socket at queue index
         ;; bpf_redirect_map(&xskmap, rx_queue_index, XDP_PASS)
         (dsl/ld-map-fd :r1 0)      ; Map FD placeholder
         (dsl/mov-reg :r2 :r4)       ; key = queue index
         (dsl/mov :r3 2)             ; flags = XDP_PASS (fallback if no socket)
         (dsl/call 51)               ; bpf_redirect_map
         (dsl/exit-insn)])           ; Return redirect result

(defprogram xdp-xsk-redirect-queue0
  "XDP program that redirects only queue 0 to XSK.
   Other queues pass to kernel network stack."
  :type :xdp
  :license "GPL"
  :body [;; Save context
         (dsl/mov-reg :r6 :r1)
         ;; Load rx_queue_index
         (dsl/ldx :w :r4 :r6 16)
         ;; If queue != 0, pass to kernel stack
         (dsl/jmp-imm :jne :r4 0 5)
         ;; Queue 0: redirect to XSK
         (dsl/ld-map-fd :r1 0)
         (dsl/mov :r2 0)             ; key = 0
         (dsl/mov :r3 2)             ; flags = XDP_PASS
         (dsl/call 51)
         (dsl/exit-insn)
         ;; Other queues: XDP_PASS
         (dsl/mov :r0 2)
         (dsl/exit-insn)])

(defprogram xdp-xsk-filter-udp
  "XDP program that redirects only UDP packets to XSK.
   TCP and other protocols pass to kernel stack."
  :type :xdp
  :license "GPL"
  :body [(dsl/mov-reg :r6 :r1)
         ;; Load data pointers
         (dsl/ldx :w :r2 :r6 0)      ; data
         (dsl/ldx :w :r3 :r6 4)      ; data_end
         ;; Bounds check: need at least Ethernet + IP headers (34 bytes)
         (dsl/mov-reg :r0 :r2)
         (dsl/add :r0 34)
         (dsl/jmp-reg :jgt :r0 :r3 2)
         (dsl/mov :r0 2)             ; XDP_PASS
         (dsl/exit-insn)
         ;; Check EtherType (offset 12, 2 bytes) - must be IPv4 (0x0800)
         (dsl/ldx :h :r4 :r2 12)
         (dsl/jmp-imm :jne :r4 0x0800 2)
         (dsl/mov :r0 2)             ; XDP_PASS if not IPv4
         (dsl/exit-insn)
         ;; Check IP protocol (offset 14+9=23) - UDP is 17
         (dsl/ldx :b :r4 :r2 23)
         (dsl/jmp-imm :jne :r4 17 2)
         (dsl/mov :r0 2)             ; XDP_PASS if not UDP
         (dsl/exit-insn)
         ;; It's UDP - redirect to XSK
         (dsl/ldx :w :r4 :r6 16)     ; rx_queue_index
         (dsl/ld-map-fd :r1 0)
         (dsl/mov-reg :r2 :r4)
         (dsl/mov :r3 2)
         (dsl/call 51)
         (dsl/exit-insn)])

;; ============================================================================
;; DSL Helper Examples
;; ============================================================================

(defn example-dsl-helpers
  "Demonstrate XSK redirect DSL helpers."
  []
  (println "\n=== XSK Redirect DSL Helpers ===")

  (println "\n1. Basic redirect to XSK at specific queue:")
  (let [insns (xdp/xdp-redirect-to-xsk 5 0)]
    (println "   (xdp/xdp-redirect-to-xsk map-fd queue-index)")
    (println "   Generates" (count insns) "instructions,"
             (reduce + (map count insns)) "bytes"))

  (println "\n2. Redirect with register queue index:")
  (let [insns (xdp/xdp-redirect-to-xsk 5 :r4)]
    (println "   (xdp/xdp-redirect-to-xsk map-fd :r4)")
    (println "   Generates" (count insns) "instructions,"
             (reduce + (map count insns)) "bytes"))

  (println "\n3. Redirect by rx_queue_index (common pattern):")
  (let [insns (xdp/xdp-redirect-to-xsk-by-queue :r6 5)]
    (println "   (xdp/xdp-redirect-to-xsk-by-queue ctx-reg map-fd)")
    (println "   Generates" (count insns) "instructions,"
             (reduce + (map count insns)) "bytes"))

  (println "\n4. Load rx_queue_index from context:")
  (let [insn (xdp/xdp-load-ctx-field :r1 :rx-queue-index :r4)]
    (println "   (xdp/xdp-load-ctx-field ctx-reg :rx-queue-index dst-reg)")
    (println "   Generates 1 instruction," (count insn) "bytes")))

;; ============================================================================
;; Build Complete Programs
;; ============================================================================

(defn build-xsk-redirect-all
  "Build XDP program that redirects all packets to XSK."
  [map-fd]
  (dsl/assemble
   (vec (concat
         ;; Save context, load rx_queue_index
         [(dsl/mov-reg :r6 :r1)
          (dsl/ldx :w :r4 :r6 16)]
         ;; Redirect to XSK at queue index
         (xdp/xdp-redirect-to-xsk map-fd :r4)))))

(defn build-xsk-selective-redirect
  "Build XDP program that selectively redirects based on port.
   Only packets to specified port go to XSK."
  [map-fd dst-port]
  (dsl/assemble
   [(dsl/mov-reg :r6 :r1)
    ;; Load data pointers
    (dsl/ldx :w :r2 :r6 0)
    (dsl/ldx :w :r3 :r6 4)
    ;; Bounds check for Ethernet + IPv4 + UDP headers (42 bytes)
    (dsl/mov-reg :r0 :r2)
    (dsl/add :r0 42)
    (dsl/jmp-reg :jgt :r0 :r3 2)
    (dsl/mov :r0 2)
    (dsl/exit-insn)
    ;; Check if UDP (protocol at offset 23)
    (dsl/ldx :b :r4 :r2 23)
    (dsl/jmp-imm :jne :r4 17 2)
    (dsl/mov :r0 2)
    (dsl/exit-insn)
    ;; Check destination port (offset 36, 2 bytes, big-endian)
    (dsl/ldx :h :r4 :r2 36)
    (dsl/jmp-imm :jne :r4 dst-port 2)
    (dsl/mov :r0 2)
    (dsl/exit-insn)
    ;; Port matches - redirect to XSK
    (dsl/ldx :w :r4 :r6 16)
    (dsl/ld-map-fd :r1 map-fd)
    (dsl/mov-reg :r2 :r4)
    (dsl/mov :r3 2)
    (dsl/call 51)
    (dsl/exit-insn)]))

(defn example-build-programs
  "Example of building complete XSKMAP programs."
  []
  (println "\n=== Building Complete XSK Programs ===")

  (let [fake-map-fd 5]
    (println "\n1. XSK redirect all packets:")
    (let [bytecode (build-xsk-redirect-all fake-map-fd)]
      (println "   Program size:" (count bytecode) "bytes"))

    (println "\n2. XSK selective redirect (port 4789 - VXLAN):")
    (let [bytecode (build-xsk-selective-redirect fake-map-fd 4789)]
      (println "   Program size:" (count bytecode) "bytes"))))

;; ============================================================================
;; Conceptual Usage Examples
;; ============================================================================

(defn example-basic-xsk-setup
  "Conceptual example of basic XSKMAP setup."
  []
  (println "\n=== Basic XSKMAP Setup (Conceptual) ===")
  (println "
  ;; 1. Create XSKMAP for 4 RX queues
  (def xsk-map (maps/create-xsk-map 4 :map-name \"xsks_map\"))

  ;; 2. Build XDP program that redirects to XSK
  (def xdp-bytecode
    (build-xsk-redirect-all (:fd xsk-map)))

  ;; 3. Load and attach XDP program
  (def xdp-prog
    (bpf/load-program
      {:prog-type :xdp
       :insns xdp-bytecode
       :license \"GPL\"}))
  (bpf/attach-xdp xdp-prog \"eth0\" :mode :skb)

  ;; 4. Create AF_XDP sockets (requires external library or raw syscalls)
  ;; For each RX queue:
  ;;   - Create socket: socket(AF_XDP, SOCK_RAW, 0)
  ;;   - Set up UMEM: setsockopt(SO_XDP_UMEM_REG, ...)
  ;;   - Bind to interface/queue: bind(sockfd, ...)
  ;;   - Add to XSKMAP: (maps/map-update xsk-map queue-idx xsk-fd)

  ;; 5. Receive packets via XSK RX ring (zero-copy!)
  ;; poll(xsk_fd) -> read descriptors from RX ring -> process packets"))

(defn example-multi-app-xsk
  "Conceptual example of multiple apps sharing interface via XSK."
  []
  (println "\n=== Multi-Application XSK Setup (Conceptual) ===")
  (println "
  ;; Scenario: Different apps process different traffic types
  ;; App A: Process UDP port 53 (DNS)
  ;; App B: Process UDP port 4789 (VXLAN)
  ;; Default: Pass to kernel stack

  ;; 1. Create XSKMAPs for each application
  (def dns-xsk-map (maps/create-xsk-map 4 :map-name \"dns_xsks\"))
  (def vxlan-xsk-map (maps/create-xsk-map 4 :map-name \"vxlan_xsks\"))

  ;; 2. XDP program with traffic classification
  ;; (Simplified - real implementation would use proper bounds checks)
  ;;
  ;; if (is_udp && dst_port == 53)
  ;;   return bpf_redirect_map(&dns_xsk_map, queue_idx, XDP_PASS)
  ;; else if (is_udp && dst_port == 4789)
  ;;   return bpf_redirect_map(&vxlan_xsk_map, queue_idx, XDP_PASS)
  ;; else
  ;;   return XDP_PASS  // kernel stack

  ;; 3. Each app creates XSK sockets and registers with its map
  ;; App A registers XSK sockets in dns_xsk_map
  ;; App B registers XSK sockets in vxlan_xsk_map"))

(defn example-performance-tips
  "Performance optimization tips for AF_XDP."
  []
  (println "\n=== AF_XDP Performance Tips ===")
  (println "
  1. Use XDP native mode if driver supports it:
     (bpf/attach-xdp prog \"eth0\" :mode :native)

  2. Enable busy-polling for lowest latency:
     setsockopt(xsk_fd, SOL_SOCKET, SO_BUSY_POLL, ...)

  3. Use batched operations for ring buffers:
     - Process multiple packets per poll() wakeup
     - Submit multiple buffers to fill ring at once

  4. Pin XSK threads to CPUs matching RX queues:
     - Queue 0 XSK on CPU 0
     - Queue 1 XSK on CPU 1
     - Avoids cross-CPU cache bouncing

  5. Size UMEM appropriately:
     - More frames = less chance of drops
     - But more memory usage
     - Typical: 4096+ frames per queue

  6. Use copy mode for debugging, then switch to zero-copy:
     bind(..., XDP_COPY) // Debug
     bind(..., XDP_ZEROCOPY) // Production"))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all examples."
  [& args]
  (println "==============================================")
  (println "AF_XDP Zero-Copy Packet Processing with XSKMAP")
  (println "==============================================")

  (example-dsl-helpers)
  (example-build-programs)
  (example-basic-xsk-setup)
  (example-multi-app-xsk)
  (example-performance-tips)

  (println "\n=== Map Creation Function ===")
  (println "- create-xsk-map : Create XSKMAP for AF_XDP sockets")
  (println "  (maps/create-xsk-map max-entries :map-name \"name\")")

  (println "\n=== DSL Helpers ===")
  (println "- xdp/xdp-redirect-to-xsk        : Redirect to XSK at index")
  (println "- xdp/xdp-redirect-to-xsk-by-queue: Redirect based on rx_queue_index")
  (println "- xdp/xdp-redirect-map           : Generic redirect_map helper")
  (println "- xdp/xdp-load-ctx-field         : Load xdp_md fields")

  (println "\n=== xdp_md Context Fields ===")
  (println "- :data            (offset 0)  : Packet data start")
  (println "- :data-end        (offset 4)  : Packet data end")
  (println "- :data-meta       (offset 8)  : Metadata area")
  (println "- :ingress-ifindex (offset 12) : Ingress interface")
  (println "- :rx-queue-index  (offset 16) : RX queue index (for XSKMAP)")
  (println "- :egress-ifindex  (offset 20) : Egress interface")

  (println "\n=== Kernel Requirements ===")
  (println "- Linux 4.18+: Basic XSKMAP support")
  (println "- Linux 5.3+:  Need-wakeup flag, better performance")
  (println "- Linux 5.4+:  Shared UMEM between sockets")
  (println "- Linux 5.11+: Multi-buffer XDP")

  (println "\nDone!"))
