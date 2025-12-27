(ns clj-ebpf.rate-limit
  "Token bucket rate limiting helpers for BPF programs.

   Provides comprehensive token bucket rate limiting implementation
   for XDP/TC programs. Common use cases include:
   - Source IP rate limiting (DDoS protection)
   - Backend rate limiting (overload protection)
   - API rate limiting
   - Connection rate limiting

   Token Bucket Algorithm:
   1. Each bucket has: tokens (current count), last_update (timestamp)
   2. Config has: rate (tokens per second), burst (max tokens)
   3. On each packet:
      a. Calculate elapsed time since last_update
      b. Add new tokens: elapsed_ns * rate / 1e9
      c. Cap tokens at burst
      d. If tokens >= 1, consume and allow
      e. Else, rate limit (drop)

   Data Structures:
   - Config map (array): 16 bytes per entry (rate: 8, burst: 8)
   - Bucket map (LRU hash): 16 bytes per entry (tokens: 8, last_update: 8)
   - Token scale: 1000 (for sub-second precision)

   Usage:
     (require '[clj-ebpf.rate-limit :as rl])

     ;; Build rate limit check
     (rl/build-rate-limit-check
       config-map-fd 0 bucket-map-fd -16 -48 :pass :drop)"
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.asm :as asm]
            [clj-ebpf.maps.helpers :as maps]
            [clj-ebpf.time :as time]))

;; ============================================================================
;; Constants
;; ============================================================================

(def ^:const TOKEN-SCALE 1000)           ; Scale factor for sub-second precision
(def ^:const NS-PER-SEC 1000000000)      ; Nanoseconds per second
(def ^:const NS-PER-US 1000)             ; Nanoseconds per microsecond
(def ^:const US-PER-SEC 1000000)         ; Microseconds per second
(def ^:const MAX-ELAPSED-US 10000000)    ; Max 10 seconds to prevent overflow

;; Config structure offsets (16 bytes total)
(def ^:const CONFIG-OFF-RATE 0)          ; tokens per second * TOKEN-SCALE (8 bytes)
(def ^:const CONFIG-OFF-BURST 8)         ; max tokens * TOKEN-SCALE (8 bytes)

;; Bucket structure offsets (16 bytes total)
(def ^:const BUCKET-OFF-TOKENS 0)        ; current tokens * TOKEN-SCALE (8 bytes)
(def ^:const BUCKET-OFF-LAST-UPDATE 8)   ; last update timestamp in ns (8 bytes)

;; ============================================================================
;; Core Rate Limiting
;; ============================================================================

(defn build-rate-limit-check
  "Generate BPF instructions for token bucket rate limit check.

   Implements token bucket algorithm:
   1. Load config from config-map at config-index
   2. If rate == 0, skip (rate limiting disabled)
   3. Load/create bucket from bucket-map using key at key-stack-off
   4. Calculate elapsed time since last update
   5. Add tokens: new_tokens = old_tokens + elapsed_us * rate / 1e6
   6. Cap at burst
   7. If tokens >= TOKEN-SCALE (1 token), consume and continue
   8. Else jump to drop-label

   Args:
     config-map-fd: FD for rate_limit_config array map
     config-index: Index in config map (e.g., 0 for source, 1 for backend)
     bucket-map-fd: FD for bucket LRU hash map
     key-stack-off: Stack offset where lookup key is stored
     scratch-stack-off: Stack offset for scratch space (needs 32 bytes)
     skip-label: Label to jump to if rate limiting disabled/passed
     drop-label: Label to jump to if rate limited

   Register usage:
     r0: Scratch, return values
     r1-r5: Helper call arguments
     r6: Saved bucket pointer
     r7: Saved tokens value
     r8: Rate/config values
     r9: Burst/temp values

   Stack usage (relative to scratch-stack-off):
     offset 0-7: config index for lookup
     offset 8-15: new bucket initialization (tokens)
     offset 16-23: new bucket initialization (last_update)

   Returns: Vector of instructions/pseudo-instructions"
  [config-map-fd config-index bucket-map-fd key-stack-off scratch-stack-off skip-label drop-label]
  (let [config-key-off scratch-stack-off
        init-tokens-off (+ scratch-stack-off 8)
        init-update-off (+ scratch-stack-off 16)]
    (concat
      ;; ========================================
      ;; Step 1: Load rate limit config
      ;; ========================================
      ;; Store config index on stack
      [(dsl/mov :r0 config-index)
       (dsl/stx :w :r10 :r0 config-key-off)]

      ;; Lookup config
      (maps/build-map-lookup config-map-fd config-key-off)

      ;; If config not found, skip rate limiting
      [(asm/jmp-imm :jeq :r0 0 skip-label)]

      ;; Load rate from config
      [(dsl/ldx :dw :r8 :r0 CONFIG-OFF-RATE)]

      ;; If rate == 0, rate limiting is disabled, skip
      [(asm/jmp-imm :jeq :r8 0 skip-label)]

      ;; Load burst from config
      [(dsl/ldx :dw :r9 :r0 CONFIG-OFF-BURST)]

      ;; ========================================
      ;; Step 2: Lookup or create bucket
      ;; ========================================
      ;; Lookup bucket
      (maps/build-map-lookup bucket-map-fd key-stack-off)

      ;; Check if bucket exists
      [(asm/jmp-imm :jne :r0 0 :bucket_exists)]

      ;; Bucket doesn't exist - create new one
      ;; Initialize with burst tokens and current timestamp

      ;; Get current time for initialization
      (time/build-ktime-get-ns)
      [(dsl/stx :dw :r10 :r0 init-update-off)]

      ;; Initialize tokens to (burst - TOKEN-SCALE) since we'll consume one
      [(dsl/mov-reg :r0 :r9)
       (dsl/sub :r0 TOKEN-SCALE)
       (dsl/stx :dw :r10 :r0 init-tokens-off)]

      ;; Insert new bucket
      (maps/build-map-update bucket-map-fd key-stack-off init-tokens-off maps/BPF-ANY)

      ;; Bucket created successfully (or update raced), jump to pass
      [(asm/jmp skip-label)]

      ;; ========================================
      ;; Step 3: Process existing bucket
      ;; ========================================
      [(asm/label :bucket_exists)]

      ;; Save bucket pointer
      [(dsl/mov-reg :r6 :r0)]

      ;; Load current tokens
      [(dsl/ldx :dw :r7 :r6 BUCKET-OFF-TOKENS)]

      ;; Load last_update
      [(dsl/ldx :dw :r0 :r6 BUCKET-OFF-LAST-UPDATE)]

      ;; Save last_update temporarily
      [(dsl/mov-reg :r1 :r0)]

      ;; Get current time
      (time/build-ktime-get-ns)

      ;; r0 = now, r1 = last_update
      ;; Calculate elapsed_ns = now - last_update
      [(dsl/sub-reg :r0 :r1)]

      ;; Convert to microseconds to avoid overflow: elapsed_us = elapsed_ns / 1000
      [(dsl/div :r0 NS-PER-US)]

      ;; Clamp elapsed_us to MAX_ELAPSED_US
      [(asm/jmp-imm :jle :r0 MAX-ELAPSED-US :elapsed_ok)
       (dsl/mov :r0 MAX-ELAPSED-US)
       (asm/label :elapsed_ok)]

      ;; Calculate new tokens: tokens_to_add = elapsed_us * rate / 1e6
      ;; r0 = elapsed_us, r8 = rate (scaled)
      [(dsl/mul-reg :r0 :r8)]           ; r0 = elapsed_us * rate
      [(dsl/div :r0 US-PER-SEC)]        ; r0 = tokens_to_add

      ;; Add to current tokens
      [(dsl/add-reg :r7 :r0)]           ; r7 = old_tokens + tokens_to_add

      ;; Cap at burst
      [(asm/jmp-reg :jle :r7 :r9 :tokens_ok)
       (dsl/mov-reg :r7 :r9)
       (asm/label :tokens_ok)]

      ;; Check if we have at least 1 token (TOKEN-SCALE)
      [(asm/jmp-imm :jlt :r7 TOKEN-SCALE drop-label)]

      ;; Consume 1 token
      [(dsl/sub :r7 TOKEN-SCALE)]

      ;; Update bucket: store new tokens
      [(dsl/stx :dw :r6 :r7 BUCKET-OFF-TOKENS)]

      ;; Update bucket: store current timestamp
      (time/build-ktime-get-ns)
      [(dsl/stx :dw :r6 :r0 BUCKET-OFF-LAST-UPDATE)]

      ;; Rate limit check passed
      [(asm/jmp skip-label)])))

;; ============================================================================
;; Simplified Rate Limiting
;; ============================================================================

(defn build-simple-rate-limit
  "Simplified rate limiting that doesn't use a config map.

   Rate and burst are hardcoded, suitable for single-purpose rate limiters.

   Args:
     bucket-map-fd: FD for bucket LRU hash map
     key-stack-off: Stack offset where lookup key is stored
     scratch-stack-off: Stack offset for scratch space (needs 24 bytes)
     rate: Tokens per second (unscaled, e.g., 100 for 100 req/s)
     burst: Maximum tokens (unscaled, e.g., 200)
     skip-label: Label to jump to on pass
     drop-label: Label to jump to on rate limit

   Returns: Vector of instructions/pseudo-instructions"
  [bucket-map-fd key-stack-off scratch-stack-off rate burst skip-label drop-label]
  (let [scaled-rate (* rate TOKEN-SCALE)
        scaled-burst (* burst TOKEN-SCALE)
        init-tokens-off scratch-stack-off
        init-update-off (+ scratch-stack-off 8)]
    (concat
      ;; ========================================
      ;; Step 1: Lookup bucket
      ;; ========================================
      (maps/build-map-lookup bucket-map-fd key-stack-off)

      ;; Check if bucket exists
      [(asm/jmp-imm :jne :r0 0 :simple_bucket_exists)]

      ;; Bucket doesn't exist - create new one
      (time/build-ktime-get-ns)
      [(dsl/stx :dw :r10 :r0 init-update-off)]

      ;; Initialize tokens to (burst - 1 token)
      [(dsl/mov :r0 (- scaled-burst TOKEN-SCALE))
       (dsl/stx :dw :r10 :r0 init-tokens-off)]

      ;; Insert new bucket
      (maps/build-map-update bucket-map-fd key-stack-off init-tokens-off maps/BPF-ANY)

      ;; Jump to pass
      [(asm/jmp skip-label)]

      ;; ========================================
      ;; Step 2: Process existing bucket
      ;; ========================================
      [(asm/label :simple_bucket_exists)]

      ;; Save bucket pointer
      [(dsl/mov-reg :r6 :r0)]

      ;; Load current tokens
      [(dsl/ldx :dw :r7 :r6 BUCKET-OFF-TOKENS)]

      ;; Load last_update
      [(dsl/ldx :dw :r8 :r6 BUCKET-OFF-LAST-UPDATE)]

      ;; Get current time
      (time/build-ktime-get-ns)

      ;; Calculate elapsed_ns = now - last_update
      [(dsl/sub-reg :r0 :r8)]

      ;; Convert to microseconds
      [(dsl/div :r0 NS-PER-US)]

      ;; Clamp elapsed_us
      [(asm/jmp-imm :jle :r0 MAX-ELAPSED-US :simple_elapsed_ok)
       (dsl/mov :r0 MAX-ELAPSED-US)
       (asm/label :simple_elapsed_ok)]

      ;; Calculate tokens_to_add = elapsed_us * rate / 1e6
      [(dsl/mov :r8 scaled-rate)
       (dsl/mul-reg :r0 :r8)
       (dsl/div :r0 US-PER-SEC)]

      ;; Add to current tokens
      [(dsl/add-reg :r7 :r0)]

      ;; Cap at burst
      [(dsl/mov :r9 scaled-burst)
       (asm/jmp-reg :jle :r7 :r9 :simple_tokens_ok)
       (dsl/mov-reg :r7 :r9)
       (asm/label :simple_tokens_ok)]

      ;; Check if we have at least 1 token
      [(asm/jmp-imm :jlt :r7 TOKEN-SCALE drop-label)]

      ;; Consume 1 token
      [(dsl/sub :r7 TOKEN-SCALE)]

      ;; Update bucket
      [(dsl/stx :dw :r6 :r7 BUCKET-OFF-TOKENS)]
      (time/build-ktime-get-ns)
      [(dsl/stx :dw :r6 :r0 BUCKET-OFF-LAST-UPDATE)]

      ;; Pass
      [(asm/jmp skip-label)])))

;; ============================================================================
;; Utility Functions
;; ============================================================================

(defn encode-rate-limit-config
  "Encode rate limit config for userspace map update.

   Args:
     rate: Tokens per second (unscaled)
     burst: Maximum tokens (unscaled)

   Returns: Byte array suitable for map update (16 bytes)"
  [rate burst]
  (let [scaled-rate (* rate TOKEN-SCALE)
        scaled-burst (* burst TOKEN-SCALE)
        buf (byte-array 16)]
    ;; Little-endian encoding (use unchecked-byte for values > 127)
    (doseq [i (range 8)]
      (aset-byte buf i (unchecked-byte (bit-and (bit-shift-right scaled-rate (* i 8)) 0xFF))))
    (doseq [i (range 8)]
      (aset-byte buf (+ 8 i) (unchecked-byte (bit-and (bit-shift-right scaled-burst (* i 8)) 0xFF))))
    buf))

(defn rate-disabled-config
  "Create config that disables rate limiting.

   Returns: Byte array with rate=0, burst=0"
  []
  (encode-rate-limit-config 0 0))
