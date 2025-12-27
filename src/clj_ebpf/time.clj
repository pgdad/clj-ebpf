(ns clj-ebpf.time
  "Time and random number helpers for BPF programs.

   These helpers provide access to kernel time and pseudo-random numbers.
   Common uses include:
   - Connection tracking timestamps (created_at, last_seen)
   - Rate limiting (token bucket timing)
   - Load balancing (weighted random selection)
   - Metrics (latency measurement)

   Usage:
     (require '[clj-ebpf.time :as t])

     ;; Get current kernel time in nanoseconds
     (t/build-ktime-get-ns)

     ;; Get random number
     (t/build-get-prandom-u32)

     ;; Get random in range [0, 99]
     (t/build-random-mod 100)"
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; BPF Helper Function IDs
;; ============================================================================

(def ^:const BPF-FUNC-ktime-get-ns 5)
(def ^:const BPF-FUNC-get-prandom-u32 7)
(def ^:const BPF-FUNC-ktime-get-boot-ns 125)
(def ^:const BPF-FUNC-ktime-get-coarse-ns 190)
(def ^:const BPF-FUNC-ktime-get-tai-ns 208)
(def ^:const BPF-FUNC-jiffies64 118)

;; ============================================================================
;; Time Helpers
;; ============================================================================

(defn build-ktime-get-ns
  "Get current kernel time in nanoseconds.

   Returns: Vector of 1 instruction
   Result: r0 = current time in nanoseconds (monotonic)

   Note: This is CLOCK_MONOTONIC, suitable for measuring intervals.
   Does not include time spent in suspend. Not suitable for wall-clock time.

   Example:
     (build-ktime-get-ns)
     ;; r0 now contains nanosecond timestamp
     ;; Store for later comparison:
     [(dsl/stx :dw :r10 :r0 -16)]"
  []
  [(dsl/call BPF-FUNC-ktime-get-ns)])

(defn build-ktime-get-boot-ns
  "Get current kernel time including suspend time in nanoseconds.

   Returns: Vector of 1 instruction
   Result: r0 = current time in nanoseconds (boot time)

   Note: This is CLOCK_BOOTTIME. Includes time spent in suspend.
   Useful when you need monotonic time that advances during suspend.

   Minimum kernel: 5.7"
  []
  [(dsl/call BPF-FUNC-ktime-get-boot-ns)])

(defn build-ktime-get-coarse-ns
  "Get coarse-grained kernel time in nanoseconds.

   Returns: Vector of 1 instruction
   Result: r0 = current time in nanoseconds (coarse granularity)

   Note: Faster but less precise than ktime-get-ns.
   Resolution is typically around 1-4 milliseconds.
   Good for cases where precision isn't critical.

   Minimum kernel: 5.11"
  []
  [(dsl/call BPF-FUNC-ktime-get-coarse-ns)])

(defn build-ktime-get-tai-ns
  "Get International Atomic Time (TAI) in nanoseconds.

   Returns: Vector of 1 instruction
   Result: r0 = TAI time in nanoseconds

   Note: TAI is similar to UTC but without leap seconds.
   Useful for precise time synchronization.

   Minimum kernel: 6.1"
  []
  [(dsl/call BPF-FUNC-ktime-get-tai-ns)])

(defn build-jiffies64
  "Get jiffies64 value.

   Returns: Vector of 1 instruction
   Result: r0 = jiffies64 value

   Note: Jiffies is the kernel's tick counter.
   Resolution depends on CONFIG_HZ (typically 100, 250, or 1000).
   Not suitable for precise timing, but useful for coarse measurements.

   Minimum kernel: 5.5"
  []
  [(dsl/call BPF-FUNC-jiffies64)])

;; ============================================================================
;; Random Number Helpers
;; ============================================================================

(defn build-get-prandom-u32
  "Get a pseudo-random 32-bit number.

   Returns: Vector of 1 instruction
   Result: r0 = random 32-bit value in [0, 2^32-1]

   Note: This is a fast PRNG, suitable for load balancing.
   Not cryptographically secure.

   Example:
     (build-get-prandom-u32)
     ;; r0 contains random value"
  []
  [(dsl/call BPF-FUNC-get-prandom-u32)])

(defn build-random-mod
  "Generate random number in range [0, n-1].

   Uses BPF's native modulo operation.

   Args:
     n: Upper bound (exclusive)

   Returns: Vector of 2 instructions
   Result: r0 = random value in [0, n-1]

   Example:
     ;; Random percentage (0-99)
     (build-random-mod 100)

     ;; Random index into 4 backends
     (build-random-mod 4)"
  [n]
  [(dsl/call BPF-FUNC-get-prandom-u32)
   (dsl/mod :r0 n)])

(defn build-random-weighted-select
  "Generate random for weighted selection.

   Generates random in [0, 99] for use with cumulative weight tables.

   Returns: Vector of 2 instructions
   Result: r0 = value in [0, 99]

   Usage with weights:
     Weights: [30, 50, 20] (must sum to 100)
     Cumulative: [30, 80, 100]
     If random < 30: select backend 0
     If random < 80: select backend 1
     Else: select backend 2"
  []
  (build-random-mod 100))

;; ============================================================================
;; Convenience Patterns
;; ============================================================================

(defn build-store-timestamp
  "Get current time and store it on the stack.

   Args:
     stack-offset: Where to store the 64-bit timestamp

   Returns: Vector of 2 instructions
   Clobbers: r0"
  [stack-offset]
  (concat
    (build-ktime-get-ns)
    [(dsl/stx :dw :r10 :r0 stack-offset)]))

(defn build-load-elapsed-ns
  "Calculate elapsed time since a stored timestamp.

   Gets current time and subtracts the stored timestamp.

   Args:
     stack-offset: Stack offset of stored timestamp
     result-reg: Register to store elapsed time (not r0)

   Returns: Vector of instructions
   Result: result-reg = elapsed nanoseconds
   Clobbers: r0, result-reg"
  [stack-offset result-reg]
  (concat
    (build-ktime-get-ns)
    [(dsl/mov-reg result-reg :r0)            ; result-reg = now
     (dsl/ldx :dw :r0 :r10 stack-offset)     ; r0 = stored timestamp
     (dsl/sub-reg result-reg :r0)]))         ; result-reg = now - stored

(defn build-update-timestamp
  "Update a timestamp in a value pointed to by a register.

   Common pattern for connection tracking last_seen updates.

   Args:
     ptr-reg: Register pointing to structure containing timestamp
     offset: Offset within structure to timestamp field

   Returns: Vector of 2 instructions
   Clobbers: r0"
  [ptr-reg offset]
  (concat
    (build-ktime-get-ns)
    [(dsl/stx :dw ptr-reg :r0 offset)]))

(defn build-random-percentage
  "Generate random percentage (0-99).

   Convenience wrapper for percentage-based decisions.

   Returns: Vector of 2 instructions
   Result: r0 = value in [0, 99]"
  []
  (build-random-mod 100))

(defn build-random-bool
  "Generate random boolean (0 or 1).

   Returns: Vector of 2 instructions
   Result: r0 = 0 or 1"
  []
  (build-random-mod 2))
