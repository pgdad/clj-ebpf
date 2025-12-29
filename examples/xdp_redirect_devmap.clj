(ns examples.xdp-redirect-devmap
  "Example: XDP Packet Redirection using DEVMAP

   This example demonstrates how to use DEVMAP for XDP packet redirection.
   DEVMAP allows XDP programs to redirect packets to specific network
   interfaces for high-performance layer 2 forwarding.

   Key concepts:
   - DEVMAP: Array-based map storing interface indices
   - DEVMAP_HASH: Hash-based map for sparse interface mappings
   - CPUMAP: Redirect packets to specific CPUs for processing
   - bpf_redirect_map: Helper function for map-based redirection

   Usage (requires root):
     clojure -M -m examples.xdp-redirect-devmap

   Note: This example shows the code structure but requires:
   - Root privileges to create BPF maps and load programs
   - At least two network interfaces for actual redirection"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.xdp :as xdp]
            [clj-ebpf.macros :refer [defmap-spec defprogram with-bpf-script]]))

;; ============================================================================
;; DEVMAP: Array-based Interface Redirect Map
;; ============================================================================

(defmap-spec tx-ports
  "DEVMAP for packet redirection to interfaces.
   Index 0 -> loopback (testing)
   Index 1 -> eth0 (or similar)
   etc."
  :type :devmap
  :key-size 4
  :value-size 4      ; Interface index (u32)
  :max-entries 64)

;; ============================================================================
;; DEVMAP_HASH: Hash-based Interface Mapping
;; ============================================================================

(defmap-spec interface-map
  "DEVMAP_HASH for sparse interface mappings.
   Keys can be arbitrary (e.g., source IP -> egress interface)."
  :type :devmap-hash
  :key-size 4
  :value-size 4
  :max-entries 256)

;; ============================================================================
;; CPUMAP: CPU Steering Map
;; ============================================================================

(defmap-spec cpu-redirect
  "CPUMAP for distributing packets across CPUs.
   Enables custom RSS (Receive Side Scaling) logic."
  :type :cpumap
  :key-size 4
  :value-size 8      ; bpf_cpumap_val: qsize (u32) + bpf_prog fd (u32)
  :max-entries 8)    ; 8 CPUs

;; ============================================================================
;; XDP Programs
;; ============================================================================

(defprogram xdp-redirect-all
  "XDP program that redirects ALL packets to index 0 in DEVMAP.
   Simple example for testing."
  :type :xdp
  :license "GPL"
  :body [;; Redirect all packets to map index 0
         (dsl/ld-map-fd :r1 0)  ; Map FD placeholder (filled at runtime)
         (dsl/mov :r2 0)         ; Key = 0
         (dsl/mov :r3 0)         ; Flags = 0
         (dsl/call 51)           ; bpf_redirect_map
         (dsl/exit-insn)])       ; Return redirect result

(defprogram xdp-pass-all
  "XDP program that passes all packets (for comparison)."
  :type :xdp
  :body [(dsl/mov :r0 2)         ; XDP_PASS
         (dsl/exit-insn)])

;; ============================================================================
;; Example 1: Simple DEVMAP Usage (Conceptual)
;; ============================================================================

(defn example-devmap-concept
  "Demonstrates the DEVMAP usage pattern (conceptual - won't actually run
   without proper setup and privileges)."
  []
  (println "\n=== DEVMAP Conceptual Example ===")
  (println "
  ;; 1. Create DEVMAP
  (def dev-map (maps/create-dev-map 64 :map-name \"tx_port\"))

  ;; 2. Get interface index for target interface
  ;; (def eth0-idx (bpf/if-name->index \"eth0\"))

  ;; 3. Populate map: index 0 -> loopback, index 1 -> eth0
  ;; (bpf/map-update dev-map 0 1)  ; lo = ifindex 1
  ;; (bpf/map-update dev-map 1 eth0-idx)

  ;; 4. XDP program uses bpf_redirect_map:
  ;;    r1 = map fd
  ;;    r2 = key (index into map)
  ;;    r3 = flags (0)
  ;;    call bpf_redirect_map (helper 51)
  ;;    return r0  ; XDP_REDIRECT on success
  ")
  (println "See the DSL helpers in clj-ebpf.dsl.xdp:"))

;; ============================================================================
;; Example 2: Using DSL Helpers
;; ============================================================================

(defn example-dsl-helpers
  "Shows available DSL helpers for redirect operations."
  []
  (println "\n=== XDP Redirect DSL Helpers ===")

  (println "\n1. Basic redirect (direct ifindex):")
  (println "   (xdp/xdp-redirect ifindex flags)")
  (let [insns (xdp/xdp-redirect 2 0)]
    (println "   Generates" (count insns) "instructions,"
             (reduce + (map count insns)) "bytes"))

  (println "\n2. Redirect via map (DEVMAP/CPUMAP/XSKMAP):")
  (println "   (xdp/xdp-redirect-map map-fd key flags)")
  (let [insns (xdp/xdp-redirect-map 5 0 0)]
    (println "   Generates" (count insns) "instructions,"
             (reduce + (map count insns)) "bytes"))

  (println "\n3. Convenience helpers:")
  (println "   (xdp/xdp-redirect-to-interface devmap-fd index)")
  (println "   (xdp/xdp-redirect-to-cpu cpumap-fd cpu-index)")
  (println "   These include the exit instruction.")

  (println "\n4. Building complete programs:")
  (let [prog-insns (vec (concat
                         (xdp/xdp-prologue :r9 :r2 :r3)
                         (xdp/xdp-redirect-to-interface 5 0)))
        bytecode (dsl/assemble prog-insns)]
    (println "   Complete program:" (count bytecode) "bytes")))

;; ============================================================================
;; Example 3: CPUMAP for Custom RSS
;; ============================================================================

(defn example-cpumap-concept
  "Shows CPUMAP usage for custom RSS (Receive Side Scaling)."
  []
  (println "\n=== CPUMAP for Custom RSS ===")
  (println "
  ;; CPUMAP allows steering packets to specific CPUs

  ;; 1. Create CPUMAP
  (def cpu-map (maps/create-cpu-map 8 :map-name \"cpu_redirect\"))

  ;; 2. Configure queues for each CPU
  ;; Value is bpf_cpumap_val: qsize (u32) + optional bpf_prog fd (u32)
  ;; (bpf/map-update cpu-map 0 2048)  ; CPU 0, queue size 2048
  ;; (bpf/map-update cpu-map 1 2048)  ; CPU 1, queue size 2048

  ;; 3. XDP program can steer based on hash, IP, port, etc:
  ;;    - Compute target CPU index
  ;;    - Call bpf_redirect_map(cpumap, cpu_idx, 0)

  ;; Benefits:
  ;; - Custom load balancing logic
  ;; - Isolate network processing to specific cores
  ;; - Override default RSS behavior
  "))

;; ============================================================================
;; Example 4: Complete Program with Map FD Injection
;; ============================================================================

(defn build-redirect-program
  "Build XDP program with actual map FD.

   This shows how to inject the map FD into the program bytecode.
   The ld_map_fd instruction needs the actual FD at load time."
  [map-fd target-index]
  (dsl/assemble
   (vec (concat
         ;; Standard XDP prologue (saves context, loads data pointers)
         (xdp/xdp-prologue :r9 :r2 :r3)
         ;; Redirect to target index in map
         (xdp/xdp-redirect-map map-fd target-index 0)
         ;; Exit (xdp-redirect-map-with-action includes exit, but
         ;; xdp-redirect-map does not, so we use explicit exit)
         ))))

(defn example-build-program
  "Example of building a program with map FD."
  []
  (println "\n=== Building Program with Map FD ===")
  (let [;; In real usage, this would be (:fd actual-map)
        fake-map-fd 5
        bytecode (build-redirect-program fake-map-fd 0)]
    (println "Built XDP redirect program:" (count bytecode) "bytes")
    (println "Program redirects all packets to index 0 in map FD" fake-map-fd)))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all examples."
  [& args]
  (println "========================================")
  (println "XDP Redirect with DEVMAP/CPUMAP Example")
  (println "========================================")

  (example-devmap-concept)
  (example-dsl-helpers)
  (example-cpumap-concept)
  (example-build-program)

  (println "\n=== Map Types Available ===")
  (println "- create-dev-map     : DEVMAP (array-based interface redirect)")
  (println "- create-dev-map-hash: DEVMAP_HASH (hash-based interface redirect)")
  (println "- create-cpu-map     : CPUMAP (CPU steering)")

  (println "\n=== DSL Helpers ===")
  (println "- xdp/xdp-redirect           : Direct ifindex redirect")
  (println "- xdp/xdp-redirect-map       : Map-based redirect")
  (println "- xdp/xdp-redirect-to-interface : Convenience for DEVMAP")
  (println "- xdp/xdp-redirect-to-cpu    : Convenience for CPUMAP")

  (println "\nDone!"))
