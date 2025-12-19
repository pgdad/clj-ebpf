(ns asm-labels
  "Label-Based Assembly Examples

   This example demonstrates the clj-ebpf.asm namespace which provides
   symbolic label support for BPF programs, eliminating manual jump
   offset calculations.

   Benefits of label-based assembly:
   - No manual instruction counting
   - Labels automatically resolve to correct offsets
   - Adding/removing code doesn't break jumps
   - More readable and maintainable programs
   - Error detection for undefined/duplicate labels

   Usage:
     clojure -M:examples -m asm-labels

   Or for interactive testing (requires root):
     sudo clojure -M:examples -m asm-labels --run"
  (:require [clj-ebpf.asm :as asm]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.net :as net]
            [clj-ebpf.programs :as prog]
            [clj-ebpf.xdp :as xdp]
            [clj-ebpf.tc :as tc]))

;; ============================================================================
;; Example 1: Basic Label Usage
;; ============================================================================

(defn demo-basic-labels
  "Demonstrate basic label creation and resolution."
  []
  (println "\n=== Basic Label Usage ===\n")

  (println "Creating a label:")
  (println "  (asm/label :my-target)")
  (println "  =>" (asm/label :my-target))

  (println "\nLabel predicates:")
  (println "  (asm/label? (asm/label :foo)) =>" (asm/label? (asm/label :foo)))
  (println "  (asm/label? (dsl/mov :r0 0))  =>" (asm/label? (dsl/mov :r0 0)))

  (println "\nSymbolic jumps:")
  (println "  (asm/jmp :done)              => symbolic jump map")
  (println "  (asm/jmp 5)                  => bytecode (backwards compat)")
  (println "  (asm/jmp-imm :jeq :r0 0 :zero) => symbolic conditional"))

;; ============================================================================
;; Example 2: Simple Program with Labels
;; ============================================================================

(defn build-simple-labeled-program
  "Build a simple program demonstrating forward and backward jumps."
  []
  (asm/assemble-with-labels
    [;; Check if r1 is zero
     (asm/jmp-imm :jeq :r1 0 :is-zero)

     ;; r1 is non-zero: return 1
     (dsl/mov :r0 1)
     (asm/jmp :done)

     ;; r1 is zero: return 0
     (asm/label :is-zero)
     (dsl/mov :r0 0)

     ;; Common exit point
     (asm/label :done)
     (dsl/exit-insn)]))

(defn demo-simple-program
  "Demonstrate a simple program with labels."
  []
  (println "\n=== Simple Program with Labels ===\n")

  (println "Program logic:")
  (println "  if (r1 == 0) goto :is-zero")
  (println "  r0 = 1")
  (println "  goto :done")
  (println "  :is-zero:")
  (println "  r0 = 0")
  (println "  :done:")
  (println "  exit")

  (let [bytecode (build-simple-labeled-program)]
    (println "\nAssembled bytecode:")
    (println "  Size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))))

;; ============================================================================
;; Example 3: Comparison - Manual vs Label-Based
;; ============================================================================

(defn build-manual-offsets
  "Build program with manual offset calculations (old way)."
  []
  (dsl/assemble
    [(dsl/jmp-imm :jeq :r1 0 2)  ; offset 2 = jump to position 3 (0+2+1)
     (dsl/mov :r0 1)
     (dsl/jmp 1)                  ; offset 1 = jump to position 4 (2+1+1)
     (dsl/mov :r0 0)
     (dsl/exit-insn)]))

(defn build-with-labels
  "Build same program with labels (new way)."
  []
  (asm/assemble-with-labels
    [(asm/jmp-imm :jeq :r1 0 :is-zero)
     (dsl/mov :r0 1)
     (asm/jmp :done)
     (asm/label :is-zero)
     (dsl/mov :r0 0)
     (asm/label :done)
     (dsl/exit-insn)]))

(defn demo-comparison
  "Compare manual offsets vs label-based assembly."
  []
  (println "\n=== Manual vs Label-Based Comparison ===\n")

  (println "Manual offset calculation (OLD WAY):")
  (println "  (dsl/jmp-imm :jeq :r1 0 2)  ; offset = target_pos - current_pos - 1")
  (println "  (dsl/mov :r0 1)")
  (println "  (dsl/jmp 1)                  ; must recalculate if code changes!")
  (println "  (dsl/mov :r0 0)")
  (println "  (dsl/exit-insn)")

  (println "\nLabel-based (NEW WAY):")
  (println "  (asm/jmp-imm :jeq :r1 0 :is-zero)  ; just name the target")
  (println "  (dsl/mov :r0 1)")
  (println "  (asm/jmp :done)                     ; readable intent")
  (println "  (asm/label :is-zero)")
  (println "  (dsl/mov :r0 0)")
  (println "  (asm/label :done)")
  (println "  (dsl/exit-insn)")

  (let [manual (build-manual-offsets)
        labeled (build-with-labels)]
    (println "\nBoth produce identical bytecode:")
    (println "  Manual:  " (count manual) "bytes")
    (println "  Labeled: " (count labeled) "bytes")
    (println "  Equal:   " (java.util.Arrays/equals ^bytes manual ^bytes labeled))))

;; ============================================================================
;; Example 4: XDP Packet Filter with Labels
;; ============================================================================

(defn build-xdp-ipv4-filter
  "Build XDP program that passes only IPv4 packets.
   Demonstrates real-world label usage with bounds checking."
  []
  (asm/assemble-with-labels
    [;; Save context pointer
     (dsl/mov-reg :r6 :r1)

     ;; Load data pointers from XDP context
     (dsl/ldx :w :r7 :r6 0)    ; r7 = data
     (dsl/ldx :w :r8 :r6 4)    ; r8 = data_end

     ;; Check Ethernet header bounds (14 bytes)
     ;; asm/check-bounds generates a symbolic jump
     (asm/check-bounds :r7 :r8 14 :pass :r9)

     ;; Load EtherType (offset 12)
     (dsl/ldx :h :r9 :r7 12)

     ;; Check if IPv4 (0x0008 = 0x0800 in network byte order)
     (asm/jmp-imm :jne :r9 0x0008 :drop)

     ;; IPv4 packet - pass it
     (dsl/mov :r0 net/XDP-PASS)
     (asm/jmp :exit)

     ;; Non-IPv4 packet - drop it
     (asm/label :drop)
     (dsl/mov :r0 net/XDP-DROP)
     (asm/jmp :exit)

     ;; Bounds check failed - pass packet (safe default)
     (asm/label :pass)
     (dsl/mov :r0 net/XDP-PASS)

     ;; Common exit
     (asm/label :exit)
     (dsl/exit-insn)]))

(defn demo-xdp-filter
  "Demonstrate XDP packet filter with labels."
  []
  (println "\n=== XDP Packet Filter with Labels ===\n")

  (println "Program structure:")
  (println "  1. Load XDP context pointers")
  (println "  2. Bounds check -> :pass on failure")
  (println "  3. Load EtherType")
  (println "  4. If not IPv4 -> :drop")
  (println "  5. IPv4: return PASS -> :exit")
  (println "  6. :drop: return DROP -> :exit")
  (println "  7. :pass: return PASS (safe default)")
  (println "  8. :exit: exit program")

  (let [bytecode (build-xdp-ipv4-filter)]
    (println "\nAssembled XDP program:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))
    (println "\nLabels used: :pass, :drop, :exit")))

;; ============================================================================
;; Example 5: TC Classifier with Multiple Protocol Handlers
;; ============================================================================

(defn build-tc-protocol-classifier
  "Build TC classifier that handles different protocols.
   Demonstrates complex control flow with multiple labels."
  []
  (asm/assemble-with-labels
    [;; Save context
     (dsl/mov-reg :r6 :r1)

     ;; Load SKB data pointers
     (dsl/ldx :w :r7 :r6 76)   ; data
     (dsl/ldx :w :r8 :r6 80)   ; data_end

     ;; Check Ethernet bounds
     (asm/check-bounds :r7 :r8 14 :pass :r9)

     ;; Load EtherType
     (dsl/ldx :h :r9 :r7 12)

     ;; Dispatch based on protocol
     (asm/jmp-imm :jeq :r9 0x0008 :ipv4)    ; IPv4
     (asm/jmp-imm :jeq :r9 0xDD86 :ipv6)    ; IPv6
     (asm/jmp-imm :jeq :r9 0x0608 :arp)     ; ARP
     (asm/jmp :unknown)

     ;; IPv4 handler
     (asm/label :ipv4)
     (dsl/mov-reg :r2 :r7)
     (dsl/add :r2 14)
     (asm/check-bounds :r2 :r8 20 :pass :r9)
     ;; Load IP protocol
     (dsl/ldx :b :r3 :r2 9)
     (asm/jmp-imm :jeq :r3 6 :tcp)          ; TCP
     (asm/jmp-imm :jeq :r3 17 :udp)         ; UDP
     (asm/jmp-imm :jeq :r3 1 :icmp)         ; ICMP
     (asm/jmp :pass)

     ;; IPv6 handler - just pass for now
     (asm/label :ipv6)
     (asm/jmp :pass)

     ;; ARP handler - pass
     (asm/label :arp)
     (asm/jmp :pass)

     ;; Unknown protocol - pass
     (asm/label :unknown)
     (asm/jmp :pass)

     ;; TCP handler
     (asm/label :tcp)
     ;; Could add port filtering here
     (asm/jmp :pass)

     ;; UDP handler
     (asm/label :udp)
     ;; Could add port filtering here
     (asm/jmp :pass)

     ;; ICMP handler
     (asm/label :icmp)
     ;; Could filter ICMP types here
     (asm/jmp :pass)

     ;; Default: TC_ACT_OK (pass)
     (asm/label :pass)
     (dsl/mov :r0 net/TC-ACT-OK)
     (dsl/exit-insn)]))

(defn demo-tc-classifier
  "Demonstrate TC classifier with multiple protocol handlers."
  []
  (println "\n=== TC Protocol Classifier with Labels ===\n")

  (println "Protocol dispatch structure:")
  (println "  EtherType 0x0800 (IPv4) -> :ipv4")
  (println "    Protocol 6 (TCP)  -> :tcp")
  (println "    Protocol 17 (UDP) -> :udp")
  (println "    Protocol 1 (ICMP) -> :icmp")
  (println "  EtherType 0x86DD (IPv6) -> :ipv6")
  (println "  EtherType 0x0806 (ARP)  -> :arp")
  (println "  Unknown -> :unknown")
  (println "  All handlers -> :pass")

  (let [bytecode (build-tc-protocol-classifier)]
    (println "\nAssembled TC classifier:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))
    (println "\nLabels used: :ipv4, :ipv6, :arp, :unknown,")
    (println "             :tcp, :udp, :icmp, :pass")))

;; ============================================================================
;; Example 6: Backward Jump (Loop Pattern)
;; ============================================================================

(defn build-countdown-program
  "Build program with backward jump (loop).
   Counts down r1 to zero, returns final value in r0."
  []
  (asm/assemble-with-labels
    [;; Initialize r0 to count iterations
     (dsl/mov :r0 0)

     ;; Loop start
     (asm/label :loop)

     ;; Check if r1 is zero
     (asm/jmp-imm :jeq :r1 0 :done)

     ;; Decrement r1, increment r0
     (dsl/sub :r1 1)
     (dsl/add :r0 1)

     ;; Jump back to loop (backward jump!)
     (asm/jmp :loop)

     ;; Done
     (asm/label :done)
     (dsl/exit-insn)]))

(defn demo-backward-jump
  "Demonstrate backward jump for loops."
  []
  (println "\n=== Backward Jump (Loop) ===\n")

  (println "Loop pattern:")
  (println "  r0 = 0")
  (println "  :loop:")
  (println "  if (r1 == 0) goto :done")
  (println "  r1--")
  (println "  r0++")
  (println "  goto :loop    ; backward jump!")
  (println "  :done:")
  (println "  exit")

  (let [bytecode (build-countdown-program)]
    (println "\nAssembled loop program:")
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "  Instructions:" (/ (count bytecode) 8))
    (println "\nNote: Labels resolve forward AND backward jumps correctly!")))

;; ============================================================================
;; Example 7: Error Handling
;; ============================================================================

(defn demo-error-handling
  "Demonstrate error detection for label problems."
  []
  (println "\n=== Error Handling ===\n")

  (println "1. Undefined label detection:")
  (try
    (asm/resolve-labels
      [(asm/jmp :nonexistent)
       (dsl/exit-insn)])
    (println "   ERROR: Should have thrown!")
    (catch Exception e
      (println "   Caught:" (.getMessage e))))

  (println "\n2. Duplicate label detection:")
  (try
    (asm/resolve-labels
      [(asm/label :dup)
       (dsl/mov :r0 0)
       (asm/label :dup)
       (dsl/exit-insn)])
    (println "   ERROR: Should have thrown!")
    (catch Exception e
      (println "   Caught:" (.getMessage e))))

  (println "\n3. Jump range checking (16-bit signed offset):")
  (println "   Labels automatically check that offsets fit in [-32768, 32767]"))

;; ============================================================================
;; Example 8: Nested Instruction Sequences
;; ============================================================================

(defn demo-nested-sequences
  "Demonstrate how labels work with nested instruction sequences."
  []
  (println "\n=== Nested Instruction Sequences ===\n")

  (println "Labels work seamlessly with helper functions that return")
  (println "instruction sequences (like net/check-bounds):")
  (println)
  (println "  (asm/assemble-with-labels")
  (println "    [(dsl/mov-reg :r6 :r1)")
  (println "     (asm/check-bounds :r7 :r8 14 :error :r9)  ; returns 3 insns")
  (println "     (dsl/mov :r0 0)")
  (println "     (asm/jmp :done)")
  (println "     (asm/label :error)")
  (println "     (dsl/mov :r0 -1)")
  (println "     (asm/label :done)")
  (println "     (dsl/exit-insn)])")

  (let [bytecode (asm/assemble-with-labels
                   [(dsl/mov-reg :r6 :r1)
                    (asm/check-bounds :r7 :r8 14 :error :r9)
                    (dsl/mov :r0 0)
                    (asm/jmp :done)
                    (asm/label :error)
                    (dsl/mov :r0 -1)
                    (asm/label :done)
                    (dsl/exit-insn)])]
    (println "\nAssembled:")
    (println "  Instructions:" (/ (count bytecode) 8))
    (println "  (check-bounds expands to 3 instructions automatically)")))

;; ============================================================================
;; Interactive Testing (requires root)
;; ============================================================================

(defn run-xdp-test
  "Actually load and attach XDP program (requires root)."
  []
  (println "\n=== Running XDP Test (requires root) ===\n")

  (let [bytecode (build-xdp-ipv4-filter)]
    (println "Loading XDP program...")
    (try
      (let [prog-record (prog/load-program {:insns bytecode
                                            :prog-type :xdp
                                            :prog-name "label_xdp"
                                            :license "GPL"
                                            :log-level 1})]
        (println "SUCCESS: Loaded, fd:" (:fd prog-record))

        (println "Attaching to 'lo'...")
        (try
          (xdp/attach-xdp "lo" (:fd prog-record) :skb-mode)
          (println "SUCCESS: Attached")
          (println "Running for 2 seconds...")
          (Thread/sleep 2000)
          (xdp/detach-xdp "lo")
          (println "SUCCESS: Detached")
          (catch Exception e
            (println "ERROR:" (.getMessage e))))

        (prog/close-program prog-record)
        (println "SUCCESS: Closed"))
      (catch Exception e
        (println "ERROR:" (.getMessage e))))))

(defn run-tc-test
  "Actually load and attach TC program (requires root)."
  []
  (println "\n=== Running TC Test (requires root) ===\n")

  (let [bytecode (build-tc-protocol-classifier)]
    (println "Loading TC classifier...")
    (try
      (let [prog-record (prog/load-program {:insns bytecode
                                            :prog-type :sched-cls
                                            :prog-name "label_tc"
                                            :license "GPL"
                                            :log-level 1})]
        (println "SUCCESS: Loaded, fd:" (:fd prog-record))

        (println "Attaching to 'lo' ingress...")
        (try
          (tc/attach-tc-filter "lo" (:fd prog-record) :ingress
                               :prog-name "label_tc"
                               :priority 1)
          (println "SUCCESS: Attached")
          (println "Running for 2 seconds...")
          (Thread/sleep 2000)
          (tc/detach-tc-filter "lo" :ingress 1)
          (println "SUCCESS: Detached")
          (catch Exception e
            (println "ERROR:" (.getMessage e))))

        (prog/close-program prog-record)
        (println "SUCCESS: Closed"))
      (catch Exception e
        (println "ERROR:" (.getMessage e))))))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run label-based assembly demonstrations."
  [& args]
  (println "==============================================")
  (println "  Label-Based Assembly Examples")
  (println "  clj-ebpf.asm namespace")
  (println "==============================================")

  (demo-basic-labels)
  (demo-simple-program)
  (demo-comparison)
  (demo-xdp-filter)
  (demo-tc-classifier)
  (demo-backward-jump)
  (demo-error-handling)
  (demo-nested-sequences)

  ;; Run actual tests if --run flag provided
  (when (some #{"--run"} args)
    (run-xdp-test)
    (run-tc-test))

  (println "\n==============================================")
  (println "  All demonstrations complete!")
  (when-not (some #{"--run"} args)
    (println "  Run with --run flag to test actual loading"))
  (println "=============================================="))

;; ============================================================================
;; REPL Usage
;; ============================================================================

(comment
  ;; Run all demos
  (-main)

  ;; Run with actual program loading (requires root)
  (-main "--run")

  ;; Create labels
  (asm/label :my-label)

  ;; Symbolic jumps
  (asm/jmp :target)
  (asm/jmp-imm :jeq :r0 0 :is-zero)
  (asm/jmp-reg :jgt :r0 :r1 :greater)

  ;; Resolve labels manually
  (asm/resolve-labels
    [(asm/jmp-imm :jeq :r0 0 :zero)
     (dsl/mov :r0 1)
     (asm/label :zero)
     (dsl/mov :r0 0)
     (dsl/exit-insn)])

  ;; Assemble with labels
  (asm/assemble-with-labels
    [(dsl/mov :r0 42)
     (asm/jmp :done)
     (dsl/mov :r0 0)  ; dead code
     (asm/label :done)
     (dsl/exit-insn)])

  ;; Build example programs
  (build-simple-labeled-program)
  (build-xdp-ipv4-filter)
  (build-tc-protocol-classifier)
  (build-countdown-program)

  ;; Compare manual vs labels
  (java.util.Arrays/equals
    (build-manual-offsets)
    (build-with-labels))
  )
