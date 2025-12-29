(ns examples.sockmap-redirect
  "Example: Socket Redirection using SOCKMAP and SOCKHASH

   This example demonstrates how to use SOCKMAP and SOCKHASH for
   high-performance socket redirection at the kernel level.

   Key concepts:
   - SOCKMAP: Array-based storage of socket references
   - SOCKHASH: Hash-based storage of socket references
   - SK_SKB: Stream parser and verdict programs for sk_buff redirection
   - SK_MSG: Message verdict programs for sendmsg/sendfile redirection

   Usage patterns:
   1. TCP Proxy: Redirect TCP streams between sockets without copying to userspace
   2. Load Balancer: Distribute connections across backend sockets
   3. Service Mesh Sidecar: Intercept and redirect application traffic

   Note: This example shows the code structure but requires:
   - Root privileges to create BPF maps and load programs
   - TCP sockets to add to the map for actual redirection"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.maps :as maps]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.socket :as socket]
            [clj-ebpf.macros :refer [defmap-spec defprogram with-bpf-script]]))

;; ============================================================================
;; SOCKMAP Definitions
;; ============================================================================

(defmap-spec echo-sock-map
  "SOCKMAP for echo server pattern.
   Stores TCP sockets that can be redirected to each other."
  :type :sockmap
  :key-size 4
  :value-size 4      ; Socket FD (kernel converts to socket pointer)
  :max-entries 256)

(defmap-spec proxy-sock-hash
  "SOCKHASH for proxy pattern.
   Keys can be connection identifiers (e.g., local port)."
  :type :sockhash
  :key-size 4        ; Could be larger for connection tuples
  :value-size 4
  :max-entries 1024)

;; ============================================================================
;; SK_SKB Programs (Stream Parser and Verdict)
;; ============================================================================

(defprogram sk-skb-parser-simple
  "Simple SK_SKB parser that returns full message length.
   This effectively treats each recv() worth of data as one message."
  :type :sk-skb
  :license "GPL"
  :body [;; r1 = __sk_buff context
         ;; Return skb->len to pass full buffer
         (dsl/mov-reg :r6 :r1)       ; Save context
         (dsl/ldx :w :r0 :r6 0)      ; r0 = skb->len (offset 0)
         (dsl/exit-insn)])

(defprogram sk-skb-verdict-pass
  "SK_SKB verdict that passes all data to the socket.
   Simple passthrough - no redirection."
  :type :sk-skb
  :license "GPL"
  :body [(dsl/mov :r0 1)             ; SK_PASS
         (dsl/exit-insn)])

(defprogram sk-skb-verdict-redirect
  "SK_SKB verdict that redirects to socket at index 0.
   Used for echo server pattern where socket redirects to itself."
  :type :sk-skb
  :license "GPL"
  :body [;; Redirect to socket at map index 0
         (dsl/ld-map-fd :r1 0)       ; Map FD placeholder
         (dsl/mov :r2 0)             ; Key = 0
         (dsl/mov :r3 0)             ; Flags = 0
         (dsl/call 52)               ; bpf_sk_redirect_map
         (dsl/exit-insn)])           ; Return redirect result

;; ============================================================================
;; SK_MSG Programs (Message Verdict)
;; ============================================================================

(defprogram sk-msg-verdict-pass
  "SK_MSG verdict that passes all messages.
   Messages are delivered to the destination socket normally."
  :type :sk-msg
  :license "GPL"
  :body [(dsl/mov :r0 1)             ; SK_PASS
         (dsl/exit-insn)])

(defprogram sk-msg-verdict-redirect
  "SK_MSG verdict that redirects messages to another socket.
   Used for proxy pattern where sender's messages go to a different socket."
  :type :sk-msg
  :license "GPL"
  :body [;; r1 = sk_msg_md context
         (dsl/mov-reg :r6 :r1)       ; Save context
         ;; Redirect message to socket at map index 0
         (dsl/mov-reg :r1 :r6)       ; r1 = context
         (dsl/ld-map-fd :r2 0)       ; Map FD placeholder
         (dsl/mov :r3 0)             ; Key = 0
         (dsl/mov :r4 0)             ; Flags = 0
         (dsl/call 60)               ; bpf_msg_redirect_map
         (dsl/exit-insn)])

;; ============================================================================
;; Example 1: Echo Server Concept
;; ============================================================================

(defn example-echo-server-concept
  "Demonstrates the echo server pattern using SOCKMAP.

   In an echo server, data received on a socket is sent back to the
   same socket. With SOCKMAP, this can be done entirely in the kernel."
  []
  (println "\n=== Echo Server Pattern with SOCKMAP ===")
  (println "
  The echo server pattern:
  1. Create SOCKMAP
  2. Load SK_SKB parser (returns message length)
  3. Load SK_SKB verdict (redirects to same socket)
  4. Attach both programs to the map
  5. Add socket to map (socket redirects to itself)

  Code structure:

  ;; Create the map
  (def sock-map (maps/create-sock-map 256 :map-name \"echo_map\"))

  ;; Load and attach parser
  (def parser (bpf/load-program parser-bytecode :sk-skb))
  (bpf/attach-sk-skb parser sock-map :stream-parser)

  ;; Load and attach verdict (redirects to index 0)
  (def verdict (bpf/load-program verdict-bytecode :sk-skb))
  (bpf/attach-sk-skb verdict sock-map :stream-verdict)

  ;; Add socket to map at index 0
  ;; When data arrives, it's redirected back to the same socket
  (bpf/map-update sock-map 0 socket-fd)
  "))

;; ============================================================================
;; Example 2: TCP Proxy Concept
;; ============================================================================

(defn example-tcp-proxy-concept
  "Demonstrates the TCP proxy pattern using SOCKMAP.

   A proxy has pairs of sockets (client<->proxy, proxy<->backend).
   Data from client socket is redirected to backend socket and vice versa."
  []
  (println "\n=== TCP Proxy Pattern with SOCKMAP ===")
  (println "
  The TCP proxy pattern:
  1. Create SOCKMAP with entries for socket pairs
  2. Load SK_MSG verdict (redirects to paired socket)
  3. Attach program to the map
  4. For each connection:
     - Accept client, connect to backend
     - Add client socket at index N
     - Add backend socket at index N+1
     - Set up redirect: client -> backend, backend -> client

  Benefits:
  - Zero-copy: Data never leaves kernel space
  - High performance: No userspace context switches
  - Low latency: Direct socket-to-socket transfer

  Code structure:

  ;; Create map for socket pairs
  (def proxy-map (maps/create-sock-map 512 :map-name \"proxy_socks\"))

  ;; Load SK_MSG verdict that redirects based on socket
  (def msg-prog (bpf/load-program msg-verdict-bytecode :sk-msg))
  (bpf/attach-sk-msg msg-prog proxy-map)

  ;; For each connection pair:
  (let [client-idx (* pair-id 2)
        backend-idx (inc client-idx)]
    ;; Client at even index redirects to backend at odd index
    (bpf/map-update proxy-map client-idx client-fd)
    ;; Backend at odd index redirects to client at even index
    (bpf/map-update proxy-map backend-idx backend-fd))
  "))

;; ============================================================================
;; Example 3: DSL Helpers Demo
;; ============================================================================

(defn example-dsl-helpers
  "Shows available DSL helpers for socket redirect operations."
  []
  (println "\n=== Socket Redirect DSL Helpers ===")

  (println "\n1. SK_SKB Prologue (same as socket filter):")
  (let [insns (socket/sk-skb-prologue :r2 :r3)]
    (println "   (socket/sk-skb-prologue :r2 :r3)")
    (println "   Generates" (count insns) "instructions"))

  (println "\n2. SK_SKB Redirect to SOCKMAP:")
  (let [insns (socket/sk-redirect-map 5 0 0)]
    (println "   (socket/sk-redirect-map map-fd key flags)")
    (println "   Generates" (count insns) "instruction components"))

  (println "\n3. SK_SKB Redirect with fallback:")
  (let [insns (socket/sk-redirect-map-with-fallback 5 0)]
    (println "   (socket/sk-redirect-map-with-fallback map-fd key)")
    (println "   Generates" (count insns) "instruction components (includes exit)"))

  (println "\n4. SK_MSG Prologue:")
  (let [insns (socket/sk-msg-prologue :r6 :r2 :r3)]
    (println "   (socket/sk-msg-prologue :r6 :r2 :r3)")
    (println "   Generates" (count insns) "instructions"))

  (println "\n5. SK_MSG Redirect to SOCKMAP:")
  (let [insns (socket/msg-redirect-map :r6 5 0 0)]
    (println "   (socket/msg-redirect-map ctx-reg map-fd key flags)")
    (println "   Generates" (count insns) "instruction components"))

  (println "\n6. Return patterns:")
  (println "   (socket/sk-skb-pass)  - Return SK_PASS")
  (println "   (socket/sk-skb-drop)  - Return SK_DROP")
  (println "   (socket/sk-msg-pass)  - Return SK_PASS")
  (println "   (socket/sk-msg-drop)  - Return SK_DROP"))

;; ============================================================================
;; Example 4: Building Complete Programs
;; ============================================================================

(defn build-echo-parser
  "Build SK_SKB parser that returns full message length."
  []
  (dsl/assemble
   [(dsl/mov-reg :r6 :r1)       ; Save context
    (dsl/ldx :w :r0 :r6 0)      ; r0 = skb->len
    (dsl/exit-insn)]))

(defn build-echo-verdict
  "Build SK_SKB verdict that redirects to index 0."
  [map-fd]
  (dsl/assemble
   (vec (concat
         (socket/sk-skb-prologue :r2 :r3)
         (socket/sk-redirect-map-with-fallback map-fd 0)))))

(defn build-msg-redirect-verdict
  "Build SK_MSG verdict that redirects based on local port."
  [map-fd]
  (dsl/assemble
   (vec (concat
         (socket/sk-msg-prologue :r6 :r2 :r3)
         ;; Load local port from context
         [(socket/sk-msg-load-field :r6 :r5 :local-port)]
         ;; Use local port as key (simplified - real code would compute proper key)
         [(dsl/mov-reg :r3 :r5)]
         ;; Redirect
         [(dsl/mov-reg :r1 :r6)]
         [(dsl/ld-map-fd :r2 map-fd)]
         [(dsl/mov :r4 0)]      ; flags
         [(dsl/call 60)]        ; bpf_msg_redirect_map
         [(dsl/exit-insn)]))))

(defn example-build-programs
  "Example of building complete SOCKMAP programs."
  []
  (println "\n=== Building Complete Programs ===")

  (let [parser-bytecode (build-echo-parser)]
    (println "\nEcho parser program:" (count parser-bytecode) "bytes"))

  (let [fake-map-fd 5
        verdict-bytecode (build-echo-verdict fake-map-fd)]
    (println "Echo verdict program:" (count verdict-bytecode) "bytes"))

  (let [fake-map-fd 5
        msg-bytecode (build-msg-redirect-verdict fake-map-fd)]
    (println "SK_MSG redirect program:" (count msg-bytecode) "bytes")))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all examples."
  [& args]
  (println "==========================================")
  (println "Socket Redirection with SOCKMAP/SOCKHASH")
  (println "==========================================")

  (example-echo-server-concept)
  (example-tcp-proxy-concept)
  (example-dsl-helpers)
  (example-build-programs)

  (println "\n=== Map Types Available ===")
  (println "- create-sock-map  : SOCKMAP (array-based socket storage)")
  (println "- create-sock-hash : SOCKHASH (hash-based socket storage)")

  (println "\n=== Program Types ===")
  (println "- SK_SKB (stream-parser): Parse message boundaries")
  (println "- SK_SKB (stream-verdict): Decide pass/drop/redirect for stream data")
  (println "- SK_MSG: Decide pass/drop/redirect for sendmsg operations")

  (println "\n=== Attachment Functions ===")
  (println "- attach-sk-skb : Attach SK_SKB program to SOCKMAP")
  (println "- attach-sk-msg : Attach SK_MSG program to SOCKMAP")
  (println "- detach-sk-skb : Detach SK_SKB program")
  (println "- detach-sk-msg : Detach SK_MSG program")

  (println "\n=== DSL Helpers ===")
  (println "- socket/sk-skb-prologue     : SK_SKB program prologue")
  (println "- socket/sk-redirect-map     : Redirect to SOCKMAP entry")
  (println "- socket/sk-redirect-hash    : Redirect to SOCKHASH entry")
  (println "- socket/sk-msg-prologue     : SK_MSG program prologue")
  (println "- socket/msg-redirect-map    : Redirect message to SOCKMAP")
  (println "- socket/msg-redirect-hash   : Redirect message to SOCKHASH")

  (println "\nDone!"))
