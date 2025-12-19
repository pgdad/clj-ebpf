(ns lab-3-4-solutions
  "Solutions for Lab 3.4: Label-Based Assembly Exercises"
  (:require [clj-ebpf.asm :as asm]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.programs :as prog]
            [clj-ebpf.xdp :as xdp]))

;; =============================================================================
;; Exercise 1: State Machine
;; =============================================================================
;;
;; Build a BPF program that implements a simple state machine:
;; - State 0: If input > 5, go to state 1; otherwise stay
;; - State 1: If input == 0, go to state 2; otherwise stay
;; - State 2: Exit with success
;;
;; The state is tracked in r2, input comes in r1.
;; Returns: 0 = still in state 0/1, 1 = reached state 2 (success)

(defn build-state-machine
  "State machine with 3 states.
   Input: r1 = input value
   Output: r0 = 1 if reached final state, 0 otherwise

   State transitions:
   State 0 -> State 1: when input > 5
   State 1 -> State 2: when input == 0
   State 2: terminal (success)"
  []
  (asm/assemble-with-labels
    [;; Initialize: r2 = state (starts at 0), r0 = result (starts at 0)
     (dsl/mov :r2 0)              ; state = 0
     (dsl/mov :r0 0)              ; result = 0 (not reached final state)

     ;; State dispatch - check current state and jump to handler
     (asm/label :dispatch)
     (asm/jmp-imm :jeq :r2 0 :state-0)
     (asm/jmp-imm :jeq :r2 1 :state-1)
     (asm/jmp-imm :jeq :r2 2 :state-2)
     ;; Invalid state - exit with failure
     (asm/jmp :exit)

     ;; State 0: If input > 5, go to state 1; otherwise stay
     (asm/label :state-0)
     (asm/jmp-imm :jgt :r1 5 :transition-0-to-1)
     ;; Stay in state 0
     (asm/jmp :exit)

     (asm/label :transition-0-to-1)
     (dsl/mov :r2 1)              ; state = 1
     (asm/jmp :dispatch)          ; re-evaluate with new state

     ;; State 1: If input == 0, go to state 2; otherwise stay
     (asm/label :state-1)
     (asm/jmp-imm :jeq :r1 0 :transition-1-to-2)
     ;; Stay in state 1
     (asm/jmp :exit)

     (asm/label :transition-1-to-2)
     (dsl/mov :r2 2)              ; state = 2
     (asm/jmp :dispatch)          ; re-evaluate with new state

     ;; State 2: Terminal state - success!
     (asm/label :state-2)
     (dsl/mov :r0 1)              ; result = 1 (success)

     ;; Exit
     (asm/label :exit)
     (dsl/exit-insn)]))

;; Alternative: Single-pass state machine (more realistic for BPF)
;; In practice, BPF programs process one input at a time, so state
;; would be stored in a map between invocations.

(defn build-state-machine-single-pass
  "Single-pass state machine - takes current state in r1, input in r2.
   Returns new state in r0.

   This is more realistic for BPF where state persists in maps."
  []
  (asm/assemble-with-labels
    [;; r1 = current state, r2 = input
     ;; Dispatch based on current state
     (asm/jmp-imm :jeq :r1 0 :state-0)
     (asm/jmp-imm :jeq :r1 1 :state-1)
     (asm/jmp-imm :jeq :r1 2 :state-2)
     ;; Invalid state - return state 0
     (dsl/mov :r0 0)
     (asm/jmp :exit)

     ;; State 0: If input > 5, transition to state 1
     (asm/label :state-0)
     (asm/jmp-imm :jgt :r2 5 :to-state-1)
     (dsl/mov :r0 0)              ; Stay in state 0
     (asm/jmp :exit)

     (asm/label :to-state-1)
     (dsl/mov :r0 1)              ; Transition to state 1
     (asm/jmp :exit)

     ;; State 1: If input == 0, transition to state 2
     (asm/label :state-1)
     (asm/jmp-imm :jeq :r2 0 :to-state-2)
     (dsl/mov :r0 1)              ; Stay in state 1
     (asm/jmp :exit)

     (asm/label :to-state-2)
     (dsl/mov :r0 2)              ; Transition to state 2
     (asm/jmp :exit)

     ;; State 2: Terminal - stay in state 2
     (asm/label :state-2)
     (dsl/mov :r0 2)

     (asm/label :exit)
     (dsl/exit-insn)]))


;; =============================================================================
;; Exercise 2: Binary Search Decision Tree
;; =============================================================================
;;
;; Implement a binary search decision tree using labels:
;; - Check if value < 50
;;   - If yes, check if < 25
;;   - If no, check if < 75
;; - Return the appropriate bucket (0-3)
;;
;; Buckets:
;;   0: value < 25
;;   1: 25 <= value < 50
;;   2: 50 <= value < 75
;;   3: value >= 75

(defn build-binary-search
  "Binary search decision tree.
   Input: r1 = value to classify
   Output: r0 = bucket (0-3)

   Decision tree:
                    [< 50?]
                   /       \\
               yes/         \\no
                 /           \\
            [< 25?]        [< 75?]
            /    \\         /    \\
         yes/    \\no    yes/    \\no
           /      \\       /      \\
        [0]      [1]    [2]      [3]"
  []
  (asm/assemble-with-labels
    [;; First split: is value < 50?
     (asm/jmp-imm :jlt :r1 50 :less-than-50)

     ;; value >= 50: check if < 75
     (asm/jmp-imm :jlt :r1 75 :bucket-2)
     ;; value >= 75
     (asm/jmp :bucket-3)

     ;; value < 50: check if < 25
     (asm/label :less-than-50)
     (asm/jmp-imm :jlt :r1 25 :bucket-0)
     ;; 25 <= value < 50
     (asm/jmp :bucket-1)

     ;; Bucket assignments
     (asm/label :bucket-0)
     (dsl/mov :r0 0)
     (asm/jmp :exit)

     (asm/label :bucket-1)
     (dsl/mov :r0 1)
     (asm/jmp :exit)

     (asm/label :bucket-2)
     (dsl/mov :r0 2)
     (asm/jmp :exit)

     (asm/label :bucket-3)
     (dsl/mov :r0 3)

     (asm/label :exit)
     (dsl/exit-insn)]))

;; Variant with configurable thresholds
(defn build-binary-search-configurable
  "Binary search with configurable thresholds.
   Returns a function that builds the program."
  [low mid high]
  (asm/assemble-with-labels
    [;; First split at mid
     (asm/jmp-imm :jlt :r1 mid :less-than-mid)

     ;; value >= mid: check if < high
     (asm/jmp-imm :jlt :r1 high :bucket-2)
     (asm/jmp :bucket-3)

     ;; value < mid: check if < low
     (asm/label :less-than-mid)
     (asm/jmp-imm :jlt :r1 low :bucket-0)
     (asm/jmp :bucket-1)

     (asm/label :bucket-0)
     (dsl/mov :r0 0)
     (asm/jmp :exit)

     (asm/label :bucket-1)
     (dsl/mov :r0 1)
     (asm/jmp :exit)

     (asm/label :bucket-2)
     (dsl/mov :r0 2)
     (asm/jmp :exit)

     (asm/label :bucket-3)
     (dsl/mov :r0 3)

     (asm/label :exit)
     (dsl/exit-insn)]))


;; =============================================================================
;; Exercise 3: Packet Type Counter
;; =============================================================================
;;
;; Build an XDP program that:
;; 1. Parses packets to identify protocol (TCP, UDP, ICMP, other)
;; 2. Uses labels for each protocol handler
;; 3. Passes all packets (just identifies them)
;;
;; In a real implementation, you would increment counters in a BPF map.
;; This solution demonstrates the label-based control flow.

(defn build-packet-type-identifier
  "XDP program that identifies packet protocol type.

   Parses Ethernet -> IPv4 -> Protocol
   Returns XDP_PASS for all packets.

   Protocol identification (would increment map counters in real use):
   - TCP (protocol 6)
   - UDP (protocol 17)
   - ICMP (protocol 1)
   - Other IPv4
   - Non-IPv4"
  []
  (asm/assemble-with-labels
    [;; Save context and load data pointers
     (dsl/mov-reg :r6 :r1)           ; Save xdp_md context
     (dsl/ldx :w :r7 :r6 0)          ; r7 = data
     (dsl/ldx :w :r8 :r6 4)          ; r8 = data_end

     ;; Check Ethernet header bounds (14 bytes)
     (asm/check-bounds :r7 :r8 14 :handle-other :r9)

     ;; Load EtherType (offset 12)
     (dsl/ldx :h :r9 :r7 12)

     ;; Check for IPv4 (0x0008 in network byte order = 0x0800)
     (asm/jmp-imm :jne :r9 0x0008 :handle-non-ipv4)

     ;; IPv4: Check IP header bounds (14 + 20 = 34 bytes minimum)
     (asm/check-bounds :r7 :r8 34 :handle-other :r9)

     ;; Get IP header pointer
     (dsl/mov-reg :r2 :r7)
     (dsl/add :r2 14)

     ;; Load IP protocol field (offset 9 in IP header)
     (dsl/ldx :b :r3 :r2 9)

     ;; Protocol dispatch
     (asm/jmp-imm :jeq :r3 6 :handle-tcp)    ; TCP = 6
     (asm/jmp-imm :jeq :r3 17 :handle-udp)   ; UDP = 17
     (asm/jmp-imm :jeq :r3 1 :handle-icmp)   ; ICMP = 1
     (asm/jmp :handle-other-ipv4)

     ;; TCP handler
     ;; In real code: increment TCP counter in map
     (asm/label :handle-tcp)
     ;; Could do further TCP parsing here (check port 80, etc.)
     (asm/jmp :pass)

     ;; UDP handler
     ;; In real code: increment UDP counter in map
     (asm/label :handle-udp)
     ;; Could do further UDP parsing here (check DNS port 53, etc.)
     (asm/jmp :pass)

     ;; ICMP handler
     ;; In real code: increment ICMP counter in map
     (asm/label :handle-icmp)
     ;; Could check ICMP type (echo request/reply, etc.)
     (asm/jmp :pass)

     ;; Other IPv4 protocol
     ;; In real code: increment other_ipv4 counter
     (asm/label :handle-other-ipv4)
     (asm/jmp :pass)

     ;; Non-IPv4 packet (ARP, IPv6, etc.)
     ;; In real code: increment non_ipv4 counter
     (asm/label :handle-non-ipv4)
     (asm/jmp :pass)

     ;; Catch-all for bounds check failures
     ;; In real code: increment malformed counter
     (asm/label :handle-other)

     ;; Pass all packets
     (asm/label :pass)
     (dsl/mov :r0 2)                 ; XDP_PASS
     (dsl/exit-insn)]))

;; Extended version with more protocol details
(defn build-packet-classifier-extended
  "Extended packet classifier with deeper protocol inspection.

   Identifies:
   - TCP with common ports (HTTP 80, HTTPS 443, SSH 22)
   - UDP with common ports (DNS 53, DHCP 67/68)
   - ICMP echo request/reply
   - Other protocols"
  []
  (asm/assemble-with-labels
    [;; Prologue
     (dsl/mov-reg :r6 :r1)
     (dsl/ldx :w :r7 :r6 0)          ; data
     (dsl/ldx :w :r8 :r6 4)          ; data_end

     ;; Ethernet bounds check
     (asm/check-bounds :r7 :r8 14 :pass :r9)

     ;; Load EtherType
     (dsl/ldx :h :r9 :r7 12)
     (asm/jmp-imm :jne :r9 0x0008 :pass)  ; Only process IPv4

     ;; IP bounds check (need at least IP + TCP/UDP headers)
     (asm/check-bounds :r7 :r8 54 :pass :r9)

     ;; Get IP header
     (dsl/mov-reg :r2 :r7)
     (dsl/add :r2 14)

     ;; Load protocol
     (dsl/ldx :b :r3 :r2 9)

     ;; Dispatch by protocol
     (asm/jmp-imm :jeq :r3 6 :tcp-handler)
     (asm/jmp-imm :jeq :r3 17 :udp-handler)
     (asm/jmp-imm :jeq :r3 1 :icmp-handler)
     (asm/jmp :pass)

     ;; TCP handler - check destination port
     (asm/label :tcp-handler)
     (dsl/mov-reg :r4 :r2)
     (dsl/add :r4 20)                ; TCP header
     (dsl/ldx :h :r5 :r4 2)          ; Dest port (network byte order)
     ;; Check common ports (values in network byte order)
     (asm/jmp-imm :jeq :r5 0x5000 :tcp-http)     ; 80 -> 0x5000
     (asm/jmp-imm :jeq :r5 0xBB01 :tcp-https)    ; 443 -> 0xBB01
     (asm/jmp-imm :jeq :r5 0x1600 :tcp-ssh)      ; 22 -> 0x1600
     (asm/jmp :tcp-other)

     (asm/label :tcp-http)
     ;; HTTP traffic identified
     (asm/jmp :pass)

     (asm/label :tcp-https)
     ;; HTTPS traffic identified
     (asm/jmp :pass)

     (asm/label :tcp-ssh)
     ;; SSH traffic identified
     (asm/jmp :pass)

     (asm/label :tcp-other)
     ;; Other TCP traffic
     (asm/jmp :pass)

     ;; UDP handler - check destination port
     (asm/label :udp-handler)
     (dsl/mov-reg :r4 :r2)
     (dsl/add :r4 20)                ; UDP header
     (dsl/ldx :h :r5 :r4 2)          ; Dest port
     (asm/jmp-imm :jeq :r5 0x3500 :udp-dns)      ; 53 -> 0x3500
     (asm/jmp-imm :jeq :r5 0x4300 :udp-dhcp)     ; 67 -> 0x4300
     (asm/jmp-imm :jeq :r5 0x4400 :udp-dhcp)     ; 68 -> 0x4400
     (asm/jmp :udp-other)

     (asm/label :udp-dns)
     ;; DNS traffic identified
     (asm/jmp :pass)

     (asm/label :udp-dhcp)
     ;; DHCP traffic identified
     (asm/jmp :pass)

     (asm/label :udp-other)
     ;; Other UDP traffic
     (asm/jmp :pass)

     ;; ICMP handler - check type
     (asm/label :icmp-handler)
     (dsl/mov-reg :r4 :r2)
     (dsl/add :r4 20)                ; ICMP header
     (dsl/ldx :b :r5 :r4 0)          ; ICMP type
     (asm/jmp-imm :jeq :r5 8 :icmp-echo-request)  ; Echo request
     (asm/jmp-imm :jeq :r5 0 :icmp-echo-reply)    ; Echo reply
     (asm/jmp :icmp-other)

     (asm/label :icmp-echo-request)
     ;; Ping request identified
     (asm/jmp :pass)

     (asm/label :icmp-echo-reply)
     ;; Ping reply identified
     (asm/jmp :pass)

     (asm/label :icmp-other)
     ;; Other ICMP type

     ;; Pass all packets
     (asm/label :pass)
     (dsl/mov :r0 2)
     (dsl/exit-insn)]))


;; =============================================================================
;; Test Runner
;; =============================================================================

(defn -main [& args]
  (let [run-xdp? (some #{"--run"} args)]
    (println "=== Lab 3.4 Exercise Solutions ===")
    (println)

    ;; Exercise 1: State Machine
    (println "Exercise 1: State Machine")
    (println "-------------------------")
    (let [bytecode (build-state-machine)]
      (println "State machine bytecode:" (count bytecode) "bytes,"
               (/ (count bytecode) 8) "instructions")
      (println "Labels: :dispatch, :state-0, :state-1, :state-2,")
      (println "        :transition-0-to-1, :transition-1-to-2, :exit"))
    (println)

    (let [bytecode (build-state-machine-single-pass)]
      (println "Single-pass variant:" (count bytecode) "bytes,"
               (/ (count bytecode) 8) "instructions")
      (println "Labels: :state-0, :state-1, :state-2, :to-state-1, :to-state-2, :exit"))
    (println)

    ;; Exercise 2: Binary Search
    (println "Exercise 2: Binary Search Decision Tree")
    (println "---------------------------------------")
    (let [bytecode (build-binary-search)]
      (println "Binary search bytecode:" (count bytecode) "bytes,"
               (/ (count bytecode) 8) "instructions")
      (println "Labels: :less-than-50, :bucket-0/1/2/3, :exit")
      (println)
      (println "Decision tree:")
      (println "  value < 25  -> bucket 0")
      (println "  25 <= value < 50  -> bucket 1")
      (println "  50 <= value < 75  -> bucket 2")
      (println "  value >= 75  -> bucket 3"))
    (println)

    ;; Exercise 3: Packet Type Counter
    (println "Exercise 3: Packet Type Identifier")
    (println "----------------------------------")
    (let [bytecode (build-packet-type-identifier)]
      (println "Basic identifier:" (count bytecode) "bytes,"
               (/ (count bytecode) 8) "instructions")
      (println "Labels: :handle-tcp, :handle-udp, :handle-icmp,")
      (println "        :handle-other-ipv4, :handle-non-ipv4, :handle-other, :pass"))
    (println)

    (let [bytecode (build-packet-classifier-extended)]
      (println "Extended classifier:" (count bytecode) "bytes,"
               (/ (count bytecode) 8) "instructions")
      (println "Labels: :tcp-handler, :udp-handler, :icmp-handler,")
      (println "        :tcp-http/https/ssh/other, :udp-dns/dhcp/other,")
      (println "        :icmp-echo-request/reply/other, :pass"))
    (println)

    ;; Run XDP program if requested
    (when run-xdp?
      (println "=== Running XDP Packet Identifier ===")
      (println)
      (try
        (let [bytecode (build-packet-type-identifier)
              prog-record (prog/load-program {:insns bytecode
                                              :prog-type :xdp
                                              :prog-name "pkt_id"
                                              :license "GPL"
                                              :log-level 1})]
          (println "Loaded XDP program, fd:" (:fd prog-record))

          (println "Attaching to 'lo'...")
          (try
            (xdp/attach-xdp "lo" (:fd prog-record) :skb-mode)
            (println "Attached. Running for 3 seconds...")
            (println "(Generate traffic with: ping -c 3 127.0.0.1)")
            (Thread/sleep 3000)
            (xdp/detach-xdp "lo")
            (println "Detached.")
            (catch Exception e
              (println "Error attaching:" (.getMessage e))))

          (prog/close-program prog-record)
          (println "Closed."))
        (catch Exception e
          (println "Error:" (.getMessage e))
          (.printStackTrace e)))
      (println))

    (println "=== Solutions Complete ===")))

(-main)
