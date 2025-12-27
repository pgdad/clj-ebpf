(ns clj-ebpf.net.bounds
  "Packet bounds checking helpers for BPF programs.

   These helpers generate BPF verifier-safe packet bounds checks.
   Every XDP/TC program must check packet bounds before accessing data.

   The BPF verifier requires specific instruction patterns to mark
   memory ranges as safe. These helpers generate compliant patterns.

   Usage:
     (require '[clj-ebpf.net.bounds :as bounds])

     ;; Check if we can read 14 bytes (Ethernet header)
     (bounds/build-bounds-check :r6 :r7 0 14 10)

     ;; With label-based jumps
     (bounds/build-bounds-check-label :r6 :r7 0 14 :drop)"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.asm :as asm]))

;; ============================================================================
;; Packet Bounds Checking
;; ============================================================================

(defn build-bounds-check
  "Generate instructions to check if accessing [data + offset, data + offset + size)
   is within packet bounds. Jumps forward by fail-offset if out of bounds.

   Register conventions (caller must set up):
     data-reg: Register containing packet data start (e.g., :r6)
     end-reg: Register containing packet data end (e.g., :r7)

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     offset: Byte offset from data start
     size: Number of bytes to access
     fail-offset: Instructions to jump forward on failure (numeric offset)

   Uses: :r8 as scratch (clobbered)

   Returns: Vector of 3 instructions

   Example:
     ;; Check if we can read 14 bytes (Ethernet header)
     (build-bounds-check :r6 :r7 0 14 10)
     ;; Generates:
     ;;   mov r8, r6        ; r8 = data
     ;;   add r8, 14        ; r8 = data + offset + size
     ;;   jgt r8, r7, +10   ; if r8 > data_end, jump forward 10"
  [data-reg end-reg offset size fail-offset]
  [(dsl/mov-reg :r8 data-reg)
   (dsl/add :r8 (+ offset size))
   (dsl/jmp-reg :jgt :r8 end-reg fail-offset)])

(defn build-bounds-check-label
  "Like build-bounds-check but uses a label for the failure target.
   Requires clj-ebpf.asm for label resolution.

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     offset: Byte offset from data start
     size: Number of bytes to access
     fail-label: Keyword label to jump to on failure

   Uses: :r8 as scratch (clobbered)

   Returns: Vector of 3 pseudo-instructions (resolve with asm/assemble-with-labels)

   Example:
     (build-bounds-check-label :r6 :r7 0 14 :drop)"
  [data-reg end-reg offset size fail-label]
  [(dsl/mov-reg :r8 data-reg)
   (dsl/add :r8 (+ offset size))
   (asm/jmp-reg :jgt :r8 end-reg fail-label)])

(defn build-bounds-check-with-scratch
  "Generate bounds check using a custom scratch register.

   Like build-bounds-check but allows specifying which register to use
   as scratch, in case :r8 is needed for something else.

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     offset: Byte offset from data start
     size: Number of bytes to access
     fail-offset: Instructions to jump forward on failure
     scratch-reg: Register to use as scratch (will be clobbered)

   Returns: Vector of 3 instructions"
  [data-reg end-reg offset size fail-offset scratch-reg]
  [(dsl/mov-reg scratch-reg data-reg)
   (dsl/add scratch-reg (+ offset size))
   (dsl/jmp-reg :jgt scratch-reg end-reg fail-offset)])

(defn build-bounds-check-label-with-scratch
  "Like build-bounds-check-with-scratch but uses a label for the failure target.

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     offset: Byte offset from data start
     size: Number of bytes to access
     fail-label: Keyword label to jump to on failure
     scratch-reg: Register to use as scratch

   Returns: Vector of 3 pseudo-instructions"
  [data-reg end-reg offset size fail-label scratch-reg]
  [(dsl/mov-reg scratch-reg data-reg)
   (dsl/add scratch-reg (+ offset size))
   (asm/jmp-reg :jgt scratch-reg end-reg fail-label)])

;; ============================================================================
;; Common Protocol Header Sizes
;; ============================================================================

(def ^:const ETH-HLEN 14)
(def ^:const IPV4-MIN-HLEN 20)
(def ^:const IPV6-HLEN 40)
(def ^:const TCP-MIN-HLEN 20)
(def ^:const UDP-HLEN 8)
(def ^:const ICMP-HLEN 8)

;; ============================================================================
;; Convenience Functions for Common Checks
;; ============================================================================

(defn check-eth-header
  "Generate bounds check for Ethernet header (14 bytes from data start).

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     fail-label: Label to jump to on failure

   Returns: Vector of instructions"
  [data-reg end-reg fail-label]
  (build-bounds-check-label data-reg end-reg 0 ETH-HLEN fail-label))

(defn check-ipv4-header
  "Generate bounds check for minimum IPv4 header (20 bytes after Ethernet).

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     fail-label: Label to jump to on failure

   Returns: Vector of instructions"
  [data-reg end-reg fail-label]
  (build-bounds-check-label data-reg end-reg ETH-HLEN IPV4-MIN-HLEN fail-label))

(defn check-ipv6-header
  "Generate bounds check for IPv6 header (40 bytes after Ethernet).

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     fail-label: Label to jump to on failure

   Returns: Vector of instructions"
  [data-reg end-reg fail-label]
  (build-bounds-check-label data-reg end-reg ETH-HLEN IPV6-HLEN fail-label))

(defn check-l4-ports
  "Generate bounds check for L4 port access (4 bytes at L4 offset).

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     l4-offset: Offset to L4 header from data start
     fail-label: Label to jump to on failure

   Returns: Vector of instructions"
  [data-reg end-reg l4-offset fail-label]
  (build-bounds-check-label data-reg end-reg l4-offset 4 fail-label))

(defn check-tcp-header
  "Generate bounds check for minimum TCP header (20 bytes at L4 offset).

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     l4-offset: Offset to TCP header from data start
     fail-label: Label to jump to on failure

   Returns: Vector of instructions"
  [data-reg end-reg l4-offset fail-label]
  (build-bounds-check-label data-reg end-reg l4-offset TCP-MIN-HLEN fail-label))

(defn check-udp-header
  "Generate bounds check for UDP header (8 bytes at L4 offset).

   Args:
     data-reg: Register with data pointer
     end-reg: Register with data_end pointer
     l4-offset: Offset to UDP header from data start
     fail-label: Label to jump to on failure

   Returns: Vector of instructions"
  [data-reg end-reg l4-offset fail-label]
  (build-bounds-check-label data-reg end-reg l4-offset UDP-HLEN fail-label))
