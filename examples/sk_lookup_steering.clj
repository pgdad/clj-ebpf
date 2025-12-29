(ns examples.sk-lookup-steering
  "Example: SK_LOOKUP Programmable Socket Lookup

   This example demonstrates SK_LOOKUP programs for programmable socket
   lookup. SK_LOOKUP programs run before the kernel's normal socket lookup
   and can select which socket handles incoming connections.

   Use cases demonstrated:
   1. Port-based socket steering (multiple services on same port)
   2. Protocol-based filtering
   3. Custom socket assignment

   NOTE: Actual SK_LOOKUP programs require:
   - Root privileges (CAP_NET_ADMIN + CAP_BPF)
   - Kernel 5.9+
   - Pre-existing listening sockets in a SOCKMAP

   This example focuses on program construction patterns.

   Run with: clj -M:examples -e \"(load-file \\\"examples/sk_lookup_steering.clj\\\")\"
             or: clj -M -m examples.sk-lookup-steering"
  (:require [clj-ebpf.constants :as const]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.sk-lookup :as sk-lookup]
            [clj-ebpf.macros :refer [defprogram defmap-spec]]))

;; ============================================================================
;; SK_LOOKUP Architecture
;; ============================================================================
;;
;; When a packet arrives that needs socket lookup:
;;
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │                          Incoming Packet                            │
;;   │                   (TCP SYN or UDP datagram)                         │
;;   └──────────────────────────────┬──────────────────────────────────────┘
;;                                  │
;;                                  v
;;   ┌─────────────────────────────────────────────────────────────────────┐
;;   │                     SK_LOOKUP BPF Program                           │
;;   │                                                                     │
;;   │  Context (bpf_sk_lookup):                                          │
;;   │    - family (AF_INET/AF_INET6)                                     │
;;   │    - protocol (TCP=6/UDP=17)                                       │
;;   │    - remote_ip4/remote_ip6                                         │
;;   │    - local_ip4/local_ip6                                           │
;;   │    - remote_port (network byte order)                              │
;;   │    - local_port (host byte order)                                  │
;;   │    - ingress_ifindex                                               │
;;   │                                                                     │
;;   │  Actions:                                                          │
;;   │    - bpf_sk_assign: Select specific socket                         │
;;   │    - SK_PASS: Continue with normal/assigned lookup                 │
;;   │    - SK_DROP: Drop the packet                                      │
;;   └─────────────────────────────┬───────────────────────────────────────┘
;;                                 │
;;                    ┌────────────┴────────────┐
;;                    │                         │
;;                    v                         v
;;   ┌────────────────────────┐   ┌───────────────────────────────────────┐
;;   │   SK_DROP              │   │   SK_PASS                              │
;;   │   Packet dropped       │   │   ┌──────────────────────────────┐    │
;;   └────────────────────────┘   │   │ Socket assigned?              │    │
;;                                │   └──────────────┬───────────────┘    │
;;                                │          Yes     │      No            │
;;                                │         ┌───────┴───────┐             │
;;                                │         │               │             │
;;                                │         v               v             │
;;                                │   ┌──────────┐   ┌──────────────┐    │
;;                                │   │ Use      │   │ Kernel does  │    │
;;                                │   │ assigned │   │ normal lookup│    │
;;                                │   │ socket   │   │              │    │
;;                                │   └──────────┘   └──────────────┘    │
;;                                └───────────────────────────────────────┘

;; ============================================================================
;; Example 1: Simple Port-Based Steering
;; ============================================================================
;;
;; This program checks the local port and returns SK_PASS for port 8080,
;; allowing the kernel to do normal lookup for that port.

(println "\n=== Example 1: Port-Based Filtering ===")

(def port-filter-instructions
  "SK_LOOKUP program that only allows connections to port 8080.

   All other ports are dropped."
  (vec (concat
        ;; Save context pointer
        (sk-lookup/sk-lookup-prologue :r6)

        ;; Load local port into r7
        [(sk-lookup/sk-lookup-get-local-port :r6 :r7)]

        ;; Check if port == 8080
        [(dsl/jmp-imm :jeq :r7 8080 2)]

        ;; Not port 8080 - drop the packet
        (sk-lookup/sk-lookup-drop)

        ;; Port 8080 - pass to normal lookup
        (sk-lookup/sk-lookup-pass))))

(println "Port filter program instructions:" (count port-filter-instructions))
(println "Assembled bytecode size:" (count (dsl/assemble port-filter-instructions)) "bytes")

;; ============================================================================
;; Example 2: Protocol-Based Filtering
;; ============================================================================
;;
;; This program only allows TCP connections, dropping UDP packets.

(println "\n=== Example 2: Protocol-Based Filtering ===")

(def tcp-only-instructions
  "SK_LOOKUP program that only allows TCP connections."
  (vec (concat
        ;; Save context
        (sk-lookup/sk-lookup-prologue :r6)

        ;; Load protocol
        [(sk-lookup/sk-lookup-get-protocol :r6 :r7)]

        ;; Check if TCP (protocol == 6)
        [(dsl/jmp-imm :jeq :r7 6 2)]

        ;; Not TCP - drop
        (sk-lookup/sk-lookup-drop)

        ;; TCP - pass
        (sk-lookup/sk-lookup-pass))))

(println "TCP-only program instructions:" (count tcp-only-instructions))
(println "Assembled bytecode size:" (count (dsl/assemble tcp-only-instructions)) "bytes")

;; ============================================================================
;; Example 3: Using check-port and check-protocol Helpers
;; ============================================================================

(println "\n=== Example 3: Using DSL Helpers ===")

(def helper-based-instructions
  "SK_LOOKUP using high-level DSL helpers."
  (vec (concat
        (sk-lookup/sk-lookup-prologue :r6)

        ;; Check if TCP using helper
        (sk-lookup/sk-lookup-check-protocol :r6 :r7 :tcp 2)
        ;; Not TCP - drop
        (sk-lookup/sk-lookup-drop)

        ;; TCP - check port
        (sk-lookup/sk-lookup-check-port :r6 :r7 8080 2)
        ;; Not port 8080 - drop
        (sk-lookup/sk-lookup-drop)

        ;; TCP on port 8080 - pass
        (sk-lookup/sk-lookup-pass))))

(println "Helper-based program instructions:" (count helper-based-instructions))

;; ============================================================================
;; Example 4: Using build-sk-lookup-program
;; ============================================================================

(println "\n=== Example 4: Using Program Builder ===")

(def built-program
  (sk-lookup/build-sk-lookup-program
   {:ctx-reg :r6
    :body [(sk-lookup/sk-lookup-get-local-port :r6 :r7)
           (dsl/jmp-imm :jne :r7 443 2)   ; Skip to default if not 443
           (dsl/mov :r0 1)                 ; SK_PASS for port 443
           (dsl/exit-insn)]
    :default-action :drop}))

(println "Built program bytecode size:" (count built-program) "bytes")

;; ============================================================================
;; Example 5: defprogram Macro Usage
;; ============================================================================

(println "\n=== Example 5: Using defprogram Macro ===")

(defprogram sk-lookup-https-only
  "SK_LOOKUP program that only allows HTTPS (port 443)."
  :type :sk-lookup
  :license "GPL"
  :body (vec (concat
              ;; Save context
              (sk-lookup/sk-lookup-prologue :r6)

              ;; Check local port == 443
              [(sk-lookup/sk-lookup-get-local-port :r6 :r7)]
              [(dsl/jmp-imm :jeq :r7 443 2)]

              ;; Not HTTPS - drop
              (sk-lookup/sk-lookup-drop)

              ;; HTTPS - pass
              (sk-lookup/sk-lookup-pass))))

(println "defprogram spec created:" (:name sk-lookup-https-only))
(println "Program type:" (:type sk-lookup-https-only))
(println "License:" (:license sk-lookup-https-only))

;; ============================================================================
;; Example 6: Context Field Access Demo
;; ============================================================================

(println "\n=== Example 6: Context Field Access ===")

(println "\nbpf_sk_lookup context offsets:")
(doseq [[field offset] (sort-by val sk-lookup/sk-lookup-offsets)]
  (println (format "  %-18s offset %2d" (name field) offset)))

(println "\nField access bytecode generation:")
(doseq [field [:family :protocol :local-port :remote-port :local-ip4 :remote-ip4]]
  (let [insn (sk-lookup/sk-lookup-load-field :r6 :r0 field)]
    (println (format "  %-12s -> %d bytes" (name field) (count insn)))))

;; ============================================================================
;; Example 7: Complete Multi-Port Service Dispatcher Concept
;; ============================================================================

(println "\n=== Example 7: Multi-Port Dispatcher Concept ===")

(println "
Conceptual SK_LOOKUP program for multi-port service dispatch:

  Program receives incoming connection info via bpf_sk_lookup context.
  It can:
  1. Check local_port to determine which service
  2. Look up appropriate socket from SOCKMAP
  3. Assign socket with bpf_sk_assign
  4. Return SK_PASS

  Example dispatch table:
    Port 80   -> HTTP server socket
    Port 443  -> HTTPS server socket
    Port 8080 -> API server socket
    Default   -> SK_DROP

  This allows multiple services to share the same IP address
  with custom routing logic that goes beyond SO_REUSEPORT.")

;; ============================================================================
;; Example 8: Byte Order Utilities Demo
;; ============================================================================

(println "\n=== Example 8: Byte Order Utilities ===")

(println "\nIP address conversion:")
(let [ip "192.168.1.1"]
  (println (format "  %s -> 0x%08X" ip (sk-lookup/ipv4-to-int ip))))

(let [ip "10.0.0.1"]
  (println (format "  %s -> 0x%08X" ip (sk-lookup/ipv4-to-int ip))))

(println "\nPort byte order conversion:")
(let [port 8080]
  (println (format "  Port %d -> network order: 0x%04X" port (sk-lookup/htons port))))

(let [port 443]
  (println (format "  Port %d -> network order: 0x%04X" port (sk-lookup/htons port))))

;; ============================================================================
;; Example 9: Section Names for ELF Output
;; ============================================================================

(println "\n=== Example 9: Section Names ===")

(println "Default section:" (sk-lookup/sk-lookup-section-name))
(println "Named section:" (sk-lookup/sk-lookup-section-name "my_dispatcher"))

;; ============================================================================
;; Example 10: Helper Function IDs
;; ============================================================================

(println "\n=== Example 10: BPF Helper Functions ===")

(println "
Relevant BPF helpers for SK_LOOKUP programs:

  bpf_sk_assign (ID 124):
    - Assigns a socket to handle the incoming connection
    - Signature: long bpf_sk_assign(ctx, sk, flags)
    - Returns 0 on success

  bpf_sk_lookup_tcp (ID 84):
    - Lookup TCP socket by 4-tuple
    - Returns socket pointer or NULL

  bpf_sk_lookup_udp (ID 85):
    - Lookup UDP socket by 4-tuple
    - Returns socket pointer or NULL

  bpf_sk_release (ID 86):
    - Release socket reference from lookup
    - Must call for sockets from bpf_sk_lookup_*")

;; ============================================================================
;; Conceptual Usage Example (Not Runnable Without Root)
;; ============================================================================

(println "\n=== Conceptual Usage (Requires Root + Kernel 5.9+) ===")

(println "
;; Real-world usage would look like:

(require '[clj-ebpf.programs :as progs]
         '[clj-ebpf.maps :as maps])

;; 1. Create SOCKMAP to hold listening sockets
(def sock-map (maps/create-sock-map 64 :map-name \"sockets\"))

;; 2. Build SK_LOOKUP program
(def sk-lookup-bytecode
  (sk-lookup/build-sk-lookup-program
    {:ctx-reg :r6
     :body [...]  ; Your dispatch logic
     :default-action :pass}))

;; 3. Load the program
(def sk-lookup-prog
  (progs/load-program
    {:prog-type :sk-lookup
     :insns sk-lookup-bytecode
     :license \"GPL\"
     :prog-name \"my_dispatcher\"}))

;; 4. Attach to network namespace
(def attached-prog
  (progs/attach-sk-lookup sk-lookup-prog
    {:netns-path \"/proc/self/ns/net\"}))

;; 5. Add listening sockets to SOCKMAP
;; (This part requires coordination with your socket setup)

;; 6. Cleanup when done
(progs/close-program attached-prog)
(maps/close-map sock-map)
")

;; ============================================================================
;; Summary
;; ============================================================================

(println "\n=== Summary ===")
(println "
SK_LOOKUP programs provide programmable socket lookup, enabling:
- Multi-tenant socket dispatch
- Custom load balancing
- Service mesh implementations
- Binding multiple services to same IP:port

Key components:
- bpf_sk_lookup context with connection info
- bpf_sk_assign helper to select socket
- Attach to network namespace via BPF link

Kernel requirements:
- Linux 5.9+ for SK_LOOKUP support
- CAP_NET_ADMIN + CAP_BPF capabilities

This example demonstrated:
- Context field access patterns
- Port and protocol filtering
- Using DSL helpers
- Program construction with builders and macros
")

(defn -main [& _args]
  (println "\n=== SK_LOOKUP Example Complete ==="))
