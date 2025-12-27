(ns clj-ebpf.ringbuf
  "Ring buffer helpers for BPF event streaming.

   Ring buffers are the modern way to stream events from BPF programs to
   userspace. They're more efficient than perf buffers and support
   variable-sized records.

   Usage:
     (require '[clj-ebpf.ringbuf :as rb])

     ;; Reserve space in ring buffer
     (rb/build-ringbuf-reserve event-ringbuf-fd 64)
     ;; r0 = pointer to reserved space, or NULL on failure

     ;; After writing data, submit
     (rb/build-ringbuf-submit :r9)

     ;; Or discard if not needed
     (rb/build-ringbuf-discard :r9)"
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; BPF Helper Function IDs
;; ============================================================================

(def ^:const BPF-FUNC-ringbuf-output 130)
(def ^:const BPF-FUNC-ringbuf-reserve 131)
(def ^:const BPF-FUNC-ringbuf-submit 132)
(def ^:const BPF-FUNC-ringbuf-discard 133)
(def ^:const BPF-FUNC-ringbuf-query 134)

;; ============================================================================
;; Ring Buffer Flags
;; ============================================================================

(def ^:const BPF-RB-NO-WAKEUP    (bit-shift-left 1 0))  ; Don't wake up reader
(def ^:const BPF-RB-FORCE-WAKEUP (bit-shift-left 1 1))  ; Force wake up reader

;; ============================================================================
;; Ring Buffer Query Flags
;; ============================================================================

(def ^:const BPF-RB-AVAIL-DATA  0)  ; Query available data for consumption
(def ^:const BPF-RB-RING-SIZE   1)  ; Query total ring buffer size
(def ^:const BPF-RB-CONS-POS    2)  ; Query consumer position
(def ^:const BPF-RB-PROD-POS    3)  ; Query producer position

;; ============================================================================
;; Core Ring Buffer Operations
;; ============================================================================

(defn build-ringbuf-reserve
  "Reserve space in a ring buffer.

   Args:
     ringbuf-fd: Ring buffer map file descriptor
     size: Number of bytes to reserve
     flags: Reserved flags, must be 0 (default)

   Returns: Vector of instructions
   Result: r0 = pointer to reserved space, or NULL on failure

   Example:
     (build-ringbuf-reserve event-ringbuf-fd 64)

   Usage pattern:
     1. Reserve space with build-ringbuf-reserve
     2. Check r0 for NULL (reservation failed)
     3. Save pointer to callee-saved register (e.g., r9)
     4. Write event data to reserved space
     5. Submit with build-ringbuf-submit"
  ([ringbuf-fd size]
   (build-ringbuf-reserve ringbuf-fd size 0))
  ([ringbuf-fd size flags]
   [(dsl/ld-map-fd :r1 ringbuf-fd)  ; 2 instruction slots
    (dsl/mov :r2 size)
    (dsl/mov :r3 flags)
    (dsl/call BPF-FUNC-ringbuf-reserve)]))

(defn build-ringbuf-submit
  "Submit a previously reserved ring buffer entry.

   After calling submit, the reserved pointer becomes invalid and
   should not be used.

   Args:
     ptr-reg: Register containing pointer from bpf_ringbuf_reserve
     flags: Submit flags (default 0):
            - 0: Normal submit
            - BPF-RB-NO-WAKEUP: Don't wake up reader
            - BPF-RB-FORCE-WAKEUP: Force wake up reader

   Returns: Vector of instructions"
  ([ptr-reg]
   (build-ringbuf-submit ptr-reg 0))
  ([ptr-reg flags]
   [(dsl/mov-reg :r1 ptr-reg)
    (dsl/mov :r2 flags)
    (dsl/call BPF-FUNC-ringbuf-submit)]))

(defn build-ringbuf-discard
  "Discard a previously reserved ring buffer entry.

   Use this when you decide not to send an event after reserving space.
   After calling discard, the reserved pointer becomes invalid.

   Args:
     ptr-reg: Register containing pointer from bpf_ringbuf_reserve
     flags: Discard flags (default 0):
            - 0: Normal discard
            - BPF-RB-NO-WAKEUP: Don't wake up reader

   Returns: Vector of instructions"
  ([ptr-reg]
   (build-ringbuf-discard ptr-reg 0))
  ([ptr-reg flags]
   [(dsl/mov-reg :r1 ptr-reg)
    (dsl/mov :r2 flags)
    (dsl/call BPF-FUNC-ringbuf-discard)]))

(defn build-ringbuf-output
  "Output data directly to ring buffer (combines reserve+copy+submit).

   This is simpler but less flexible than the reserve/submit pattern.
   Use this when you have the complete event data ready to send.

   Args:
     ringbuf-fd: Ring buffer map file descriptor
     data-reg: Register with pointer to data
     size: Size of data to output
     flags: Output flags:
            - 0: Normal output
            - BPF-RB-NO-WAKEUP: Don't wake up reader
            - BPF-RB-FORCE-WAKEUP: Force wake up reader

   Returns: Vector of instructions
   Result: r0 = 0 on success, negative on failure"
  [ringbuf-fd data-reg size flags]
  [(dsl/ld-map-fd :r1 ringbuf-fd)
   (dsl/mov-reg :r2 data-reg)
   (dsl/mov :r3 size)
   (dsl/mov :r4 flags)
   (dsl/call BPF-FUNC-ringbuf-output)])

(defn build-ringbuf-query
  "Query ring buffer properties.

   Args:
     ringbuf-fd: Ring buffer map file descriptor
     flags: Query type:
            - BPF-RB-AVAIL-DATA: Available data for consumption
            - BPF-RB-RING-SIZE: Total ring buffer size
            - BPF-RB-CONS-POS: Consumer position
            - BPF-RB-PROD-POS: Producer position

   Returns: Vector of instructions
   Result: r0 = queried value"
  [ringbuf-fd flags]
  [(dsl/ld-map-fd :r1 ringbuf-fd)
   (dsl/mov :r2 flags)
   (dsl/call BPF-FUNC-ringbuf-query)])

;; ============================================================================
;; High-Level Patterns
;; ============================================================================

(defn build-ringbuf-reserve-or-skip
  "Reserve ring buffer space, jumping to skip-label if reservation fails.

   This is a common pattern that combines reserve + NULL check.

   Args:
     ringbuf-fd: Ring buffer map file descriptor
     size: Number of bytes to reserve
     save-reg: Callee-saved register to save pointer (:r6-:r9)
     skip-label: Label to jump to if reservation fails

   Returns: Vector of instructions/pseudo-instructions
   Result: save-reg = pointer to reserved space (on success path)"
  [ringbuf-fd size save-reg skip-label]
  (concat
    (build-ringbuf-reserve ringbuf-fd size)
    ;; Check for NULL and skip if failed
    [(dsl/jmp-imm :jeq :r0 0 1)  ; jump past mov if NULL
     (dsl/mov-reg save-reg :r0)
     (dsl/jmp-imm :jne :r0 0 skip-label)]))

(defn build-write-u64-to-ringbuf
  "Write a 64-bit value to a reserved ring buffer location.

   Args:
     ptr-reg: Register containing pointer to ring buffer space
     offset: Offset within the reserved space
     value-reg: Register containing the value to write

   Returns: Vector of 1 instruction"
  [ptr-reg offset value-reg]
  [(dsl/stx :dw ptr-reg value-reg offset)])

(defn build-write-u32-to-ringbuf
  "Write a 32-bit value to a reserved ring buffer location.

   Args:
     ptr-reg: Register containing pointer to ring buffer space
     offset: Offset within the reserved space
     value-reg: Register containing the value to write

   Returns: Vector of 1 instruction"
  [ptr-reg offset value-reg]
  [(dsl/stx :w ptr-reg value-reg offset)])
