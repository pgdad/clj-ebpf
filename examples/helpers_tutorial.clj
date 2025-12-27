(ns helpers-tutorial
  "BPF Helper Functions Tutorial

   This tutorial demonstrates the comprehensive set of helper functions
   available in clj-ebpf for building production-ready BPF programs.

   Helpers covered:
   1. Packet Bounds Checking (clj-ebpf.net.bounds)
   2. Checksum Calculation (clj-ebpf.net.checksum)
   3. Ring Buffer Operations (clj-ebpf.ringbuf)
   4. IPv6 Address Loading (clj-ebpf.net.ipv6)
   5. Time and Random Numbers (clj-ebpf.time)
   6. Token Bucket Rate Limiting (clj-ebpf.rate-limit)
   7. Memory Operations (clj-ebpf.memory)
   8. BPF Map Helpers (clj-ebpf.maps.helpers)

   Each section includes:
   - Overview of the helper's purpose
   - API documentation
   - Practical examples
   - Integration patterns

   Usage:
     clojure -M:examples -m helpers-tutorial"
  (:require [clj-ebpf.net.bounds :as bounds]
            [clj-ebpf.net.checksum :as checksum]
            [clj-ebpf.ringbuf :as ringbuf]
            [clj-ebpf.net.ipv6 :as ipv6]
            [clj-ebpf.time :as time]
            [clj-ebpf.rate-limit :as rate-limit]
            [clj-ebpf.memory :as mem]
            [clj-ebpf.maps.helpers :as maps]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.asm :as asm]))

;; ============================================================================
;; Section 1: Packet Bounds Checking
;; ============================================================================

(defn demo-bounds-checking
  "Demonstrate packet bounds checking helpers.

   Bounds checking is CRITICAL for BPF verifier acceptance.
   Every packet access must be verified to be within bounds."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 1: PACKET BOUNDS CHECKING")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Ensure packet accesses are within valid bounds")
  (println "         Required by BPF verifier for all packet reads\n")

  ;; Example 1: Basic bounds check
  (println "Example 1: Basic Bounds Check")
  (println "-----------------------------")
  (let [instrs (bounds/build-bounds-check :r6 :r7 0 14 10)]
    (println "Check if 14 bytes (Ethernet header) are available:")
    (println "  (bounds/build-bounds-check :r6 :r7 0 14 10)")
    (println "  Args: data-reg end-reg offset size fail-jump-offset")
    (println "  Generated" (count instrs) "instructions")
    (println "  Jumps forward 10 instructions if bounds check fails\n"))

  ;; Example 2: Bounds check with label jump
  (println "Example 2: Bounds Check with Label Jump")
  (println "----------------------------------------")
  (let [instrs (bounds/build-bounds-check-label :r6 :r7 0 40 :drop)]
    (println "Check for 40 bytes, jump to :drop if too small:")
    (println "  (bounds/build-bounds-check-label :r6 :r7 0 40 :drop)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 3: Convenience functions
  (println "Example 3: Convenience Functions")
  (println "--------------------------------")
  (println "Pre-defined header size checks:\n")

  (doseq [[name size func] [["Ethernet" 14 bounds/check-eth-header]
                            ["IPv4"     20 bounds/check-ipv4-header]
                            ["IPv6"     40 bounds/check-ipv6-header]]]
    (let [instrs (func :r6 :r7 :drop)]
      (printf "  %-10s (%2d bytes): %d instructions\n" name size (count instrs))))

  ;; Example 4: Complete XDP program pattern
  (println "\nExample 4: Complete XDP Pattern")
  (println "-------------------------------")
  (let [program (concat
                  ;; Load packet pointers
                  [(dsl/ldx :dw :r6 :r1 0)   ; data
                   (dsl/ldx :dw :r7 :r1 8)]  ; data_end

                  ;; Check Ethernet header bounds
                  (bounds/check-eth-header :r6 :r7 :drop)

                  ;; Check IP header bounds (ETH_HLEN + 20)
                  (bounds/build-bounds-check-label :r6 :r7 0 34 :drop)

                  ;; Pass packet
                  [(dsl/mov :r0 2)  ; XDP_PASS
                   (dsl/exit-insn)]

                  ;; Drop label
                  [(asm/label :drop)
                   (dsl/mov :r0 1)  ; XDP_DROP
                   (dsl/exit-insn)])
        bytecode (asm/assemble-with-labels program)]
    (println "XDP program with bounds checking:")
    (println "  Total instructions:" (/ (count bytecode) 8))
    (println "  Bytecode size:" (count bytecode) "bytes")))

;; ============================================================================
;; Section 2: Checksum Calculation
;; ============================================================================

(defn demo-checksum-helpers
  "Demonstrate checksum calculation helpers.

   Checksums are required when modifying packet headers.
   BPF provides efficient helper functions for this."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 2: CHECKSUM CALCULATION")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Calculate and update L3/L4 checksums")
  (println "         Required when modifying IP/TCP/UDP headers\n")

  ;; Constants
  (println "Checksum Constants:")
  (println "-------------------")
  (println "  BPF_F_PSEUDO_HDR:      " checksum/BPF-F-PSEUDO-HDR)
  (println "  BPF_F_MARK_MANGLED_0:  " checksum/BPF-F-MARK-MANGLED-0)
  (println "  BPF_F_MARK_ENFORCE:    " checksum/BPF-F-MARK-ENFORCE)
  (println "  BPF_F_RECOMPUTE_CSUM:  " checksum/BPF-F-RECOMPUTE-CSUM "\n")

  (println "BPF Helper Function IDs:")
  (println "  bpf_l3_csum_replace:   " checksum/BPF-FUNC-l3-csum-replace)
  (println "  bpf_l4_csum_replace:   " checksum/BPF-FUNC-l4-csum-replace)
  (println "  bpf_csum_diff:         " checksum/BPF-FUNC-csum-diff)
  (println "  bpf_csum_update:       " checksum/BPF-FUNC-csum-update "\n")

  ;; Example 1: L3 checksum (IP header)
  (println "Example 1: L3 Checksum (IP Header) - TC/SKB")
  (println "-------------------------------------------")
  (let [instrs (checksum/l3-csum-replace-4 :r6 24 :r2 :r3)]
    (println "Update IP checksum for 4-byte value change:")
    (println "  (checksum/l3-csum-replace-4 skb-reg csum-offset old-val-reg new-val-reg)")
    (println "  (checksum/l3-csum-replace-4 :r6 24 :r2 :r3)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 2: L4 checksum (TCP/UDP)
  (println "Example 2: L4 Checksum (TCP/UDP) - TC/SKB")
  (println "-----------------------------------------")
  (let [instrs (checksum/l4-csum-replace-4 :r6 50 :r2 :r3 true)]
    (println "Update TCP checksum with pseudo-header (for IP changes):")
    (println "  (checksum/l4-csum-replace-4 skb-reg csum-offset old-reg new-reg pseudo?)")
    (println "  (checksum/l4-csum-replace-4 :r6 50 :r2 :r3 true)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 3: csum_diff for XDP
  (println "Example 3: Checksum Diff (XDP compatible)")
  (println "-----------------------------------------")
  (let [instrs (checksum/csum-diff :r2 4 :r3 4 :r4)]
    (println "Calculate checksum difference for 4-byte change:")
    (println "  (checksum/csum-diff from-ptr from-size to-ptr to-size seed)")
    (println "  (checksum/csum-diff :r2 4 :r3 4 :r4)")
    (println "  Generated" (count instrs) "instructions")
    (println "  Result in r0 (can be used for incremental update)\n"))

  ;; Example 4: Practical NAT example
  (println "Example 4: NAT Checksum Update Pattern")
  (println "--------------------------------------")
  (println "When changing source IP in NAT (TC program):")
  (println "  1. Save old IP value before modification")
  (println "  2. Modify the IP address in packet")
  (println "  3. Call l3-csum-replace-4 to update IP checksum")
  (println "  4. Call l4-csum-replace-4 with pseudo-hdr flag for TCP/UDP"))

;; ============================================================================
;; Section 3: Ring Buffer Operations
;; ============================================================================

(defn demo-ringbuf-helpers
  "Demonstrate ring buffer helpers for event streaming.

   Ring buffers are the modern way to stream events from
   BPF to userspace, replacing perf buffers."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 3: RING BUFFER OPERATIONS")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Stream events efficiently from BPF to userspace")
  (println "         Modern replacement for perf buffers\n")

  ;; Constants
  (println "Ring Buffer Constants:")
  (println "----------------------")
  (println "  BPF_RB_NO_WAKEUP:      " ringbuf/BPF-RB-NO-WAKEUP)
  (println "  BPF_RB_FORCE_WAKEUP:   " ringbuf/BPF-RB-FORCE-WAKEUP)
  (println "  BPF_RB_AVAIL_DATA:     " ringbuf/BPF-RB-AVAIL-DATA)
  (println "  BPF_RB_RING_SIZE:      " ringbuf/BPF-RB-RING-SIZE)
  (println "  BPF_RB_CONS_POS:       " ringbuf/BPF-RB-CONS-POS)
  (println "  BPF_RB_PROD_POS:       " ringbuf/BPF-RB-PROD-POS "\n")

  ;; Example 1: Reserve space
  (println "Example 1: Reserve Space in Ring Buffer")
  (println "---------------------------------------")
  (let [instrs (ringbuf/build-ringbuf-reserve 10 64 0)]
    (println "Reserve 64 bytes in ring buffer (map fd=10):")
    (println "  (ringbuf/build-ringbuf-reserve map-fd size flags)")
    (println "  (ringbuf/build-ringbuf-reserve 10 64 0)")
    (println "  Generated" (count instrs) "instructions")
    (println "  Returns: pointer to reserved space in r0, or NULL\n"))

  ;; Example 2: Submit data
  (println "Example 2: Submit Reserved Data")
  (println "-------------------------------")
  (let [instrs (ringbuf/build-ringbuf-submit :r6 0)]
    (println "Submit the reserved data:")
    (println "  (ringbuf/build-ringbuf-submit data-ptr flags)")
    (println "  (ringbuf/build-ringbuf-submit :r6 0)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 3: Discard reserved data
  (println "Example 3: Discard Reserved Data")
  (println "--------------------------------")
  (let [instrs (ringbuf/build-ringbuf-discard :r6 0)]
    (println "Discard reserved data (e.g., on error):")
    (println "  (ringbuf/build-ringbuf-discard data-ptr flags)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 4: Direct output (reserve + copy + submit)
  (println "Example 4: Direct Ring Buffer Output")
  (println "------------------------------------")
  (let [instrs (ringbuf/build-ringbuf-output 10 -64 32 0)]
    (println "Copy data directly to ring buffer:")
    (println "  (ringbuf/build-ringbuf-output map-fd stack-off size flags)")
    (println "  (ringbuf/build-ringbuf-output 10 -64 32 0)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 5: Complete event streaming pattern
  (println "Example 5: Complete Event Streaming Pattern")
  (println "-------------------------------------------")
  (let [program (concat
                  ;; Reserve space for event (64 bytes)
                  (ringbuf/build-ringbuf-reserve 10 64 0)

                  ;; Check if reservation succeeded
                  [(asm/jmp-imm :jeq :r0 0 :no_space)]

                  ;; Save pointer
                  [(dsl/mov-reg :r6 :r0)]

                  ;; Fill event data (example: store timestamp)
                  (time/build-ktime-get-ns)
                  [(dsl/stx :dw :r6 :r0 0)]

                  ;; Submit event
                  (ringbuf/build-ringbuf-submit :r6 0)

                  ;; Success path
                  [(dsl/mov :r0 0)
                   (dsl/exit-insn)]

                  ;; No space path
                  [(asm/label :no_space)
                   (dsl/mov :r0 1)
                   (dsl/exit-insn)])
        bytecode (asm/assemble-with-labels program)]
    (println "Event emission program:")
    (println "  Total instructions:" (/ (count bytecode) 8))
    (println "  Bytecode size:" (count bytecode) "bytes")))

;; ============================================================================
;; Section 4: IPv6 Address Loading
;; ============================================================================

(defn demo-ipv6-helpers
  "Demonstrate IPv6 address loading helpers.

   IPv6 addresses are 128-bit and require special handling
   in BPF programs."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 4: IPv6 ADDRESS LOADING")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Load and manipulate 128-bit IPv6 addresses")
  (println "         Handle dual-stack (IPv4/IPv6) scenarios\n")

  ;; Constants
  (println "IPv6 Constants:")
  (println "---------------")
  (println "  IPv6 header length:    " ipv6/IPV6-HLEN "bytes")
  (println "  IPv6 address length:   " ipv6/IPV6-ADDR-LEN "bytes")
  (println "  IPv6 source offset:    " ipv6/IPV6-OFF-SRC "(in IPv6 header)")
  (println "  IPv6 dest offset:      " ipv6/IPV6-OFF-DST "(in IPv6 header)\n")

  ;; Example 1: Load IPv6 address from packet
  (println "Example 1: Load IPv6 Address from Packet")
  (println "----------------------------------------")
  (let [instrs (ipv6/build-load-ipv6-address :r6 22 -32)]
    (println "Load source IPv6 from packet to stack:")
    (println "  (ipv6/build-load-ipv6-address pkt-ptr offset stack-off)")
    (println "  (ipv6/build-load-ipv6-address :r6 22 -32)")
    (println "  Generated" (count instrs) "instructions")
    (println "  Loads 16 bytes (128 bits) using 4 x 32-bit loads\n"))

  ;; Example 2: Load IPv4 in unified format
  (println "Example 2: Load IPv4 as IPv4-mapped IPv6")
  (println "----------------------------------------")
  (let [instrs (ipv6/build-load-ipv4-unified :r6 26 -32)]
    (println "Load IPv4 address in IPv6-compatible format:")
    (println "  (ipv6/build-load-ipv4-unified pkt-ptr offset stack-off)")
    (println "  Creates ::ffff:x.x.x.x format for dual-stack")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 3: Copy IPv6 between stack locations
  (println "Example 3: Copy IPv6 Address on Stack")
  (println "-------------------------------------")
  (let [instrs (ipv6/build-copy-ipv6-address -32 -64)]
    (println "Copy IPv6 from stack[-32] to stack[-64]:")
    (println "  (ipv6/build-copy-ipv6-address src-off dst-off)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 4: Convenience loaders
  (println "Example 4: Convenience Loaders")
  (println "------------------------------")
  (let [src-instrs (ipv6/build-load-ipv6-src :r6 -32)
        dst-instrs (ipv6/build-load-ipv6-dst :r6 -48)]
    (println "Load source/dest from IPv6 header (r6 points to IPv6 header):")
    (println "  Source: (ipv6/build-load-ipv6-src :r6 -32)")
    (println "         " (count src-instrs) "instructions")
    (println "  Dest:   (ipv6/build-load-ipv6-dst :r6 -48)")
    (println "         " (count dst-instrs) "instructions\n"))

  ;; Example 5: Dual-stack pattern
  (println "Example 5: Dual-Stack Key Building")
  (println "----------------------------------")
  (println "Pattern for unified IPv4/IPv6 key lookup:")
  (println "  1. Check ethertype (IPv4 or IPv6)")
  (println "  2. For IPv4: use build-load-ipv4-unified")
  (println "  3. For IPv6: use build-load-ipv6-address")
  (println "  4. Both produce 16-byte key for map lookup"))

;; ============================================================================
;; Section 5: Time and Random Numbers
;; ============================================================================

(defn demo-time-helpers
  "Demonstrate time and random number helpers.

   Essential for rate limiting, timeouts, and load balancing."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 5: TIME AND RANDOM NUMBERS")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Get timestamps, calculate elapsed time, generate random numbers")
  (println "         Essential for rate limiting and load balancing\n")

  ;; Constants
  (println "BPF Helper Function IDs:")
  (println "------------------------")
  (println "  ktime_get_ns:        " time/BPF-FUNC-ktime-get-ns)
  (println "  get_prandom_u32:     " time/BPF-FUNC-get-prandom-u32)
  (println "  ktime_get_boot_ns:   " time/BPF-FUNC-ktime-get-boot-ns)
  (println "  ktime_get_coarse_ns: " time/BPF-FUNC-ktime-get-coarse-ns)
  (println "  ktime_get_tai_ns:    " time/BPF-FUNC-ktime-get-tai-ns)
  (println "  jiffies64:           " time/BPF-FUNC-jiffies64 "\n")

  ;; Example 1: Get current timestamp
  (println "Example 1: Get Current Timestamp")
  (println "--------------------------------")
  (let [instrs (time/build-ktime-get-ns)]
    (println "Get monotonic timestamp (nanoseconds):")
    (println "  (time/build-ktime-get-ns)")
    (println "  Generated" (count instrs) "instruction")
    (println "  Result in r0\n"))

  ;; Example 2: Different time sources
  (println "Example 2: Time Source Options")
  (println "------------------------------")
  (doseq [[name func desc] [["ktime_get_ns"        time/build-ktime-get-ns        "Monotonic, high precision"]
                            ["ktime_get_boot_ns"   time/build-ktime-get-boot-ns   "Includes suspend time"]
                            ["ktime_get_coarse_ns" time/build-ktime-get-coarse-ns "Lower overhead, less precise"]
                            ["ktime_get_tai_ns"    time/build-ktime-get-tai-ns    "TAI (no leap seconds)"]
                            ["jiffies64"           time/build-jiffies64           "Kernel jiffies counter"]]]
    (printf "  %-20s - %s\n" name desc))
  (println)

  ;; Example 3: Random number generation
  (println "Example 3: Random Number Generation")
  (println "-----------------------------------")
  (let [instrs (time/build-get-prandom-u32)]
    (println "Get random 32-bit value:")
    (println "  (time/build-get-prandom-u32)")
    (println "  Generated" (count instrs) "instruction")
    (println "  Result in r0\n"))

  ;; Example 4: Random with modulo
  (println "Example 4: Random with Modulo")
  (println "-----------------------------")
  (let [instrs (time/build-random-mod 100)]
    (println "Get random value in range [0, 99]:")
    (println "  (time/build-random-mod 100)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 5: Convenience patterns
  (println "Example 5: Convenience Patterns")
  (println "-------------------------------")
  (let [store-instrs (time/build-store-timestamp -16)
        elapsed-instrs (time/build-load-elapsed-ns -16 :r1)
        pct-instrs (time/build-random-percentage)
        bool-instrs (time/build-random-bool)]
    (println "Store timestamp to stack:")
    (println "  (time/build-store-timestamp -16) ->" (count store-instrs) "instructions")
    (println "Calculate elapsed time:")
    (println "  (time/build-load-elapsed-ns -16 :r1) ->" (count elapsed-instrs) "instructions")
    (println "Random percentage [0-99]:")
    (println "  (time/build-random-percentage) ->" (count pct-instrs) "instructions")
    (println "Random boolean:")
    (println "  (time/build-random-bool) ->" (count bool-instrs) "instructions\n"))

  ;; Example 6: Weighted load balancing
  (println "Example 6: Weighted Load Balancing Pattern")
  (println "------------------------------------------")
  (let [program (concat
                  ;; Get random percentage [0-99]
                  (time/build-random-weighted-select)

                  ;; Backend selection: 30% -> B0, 50% -> B1, 20% -> B2
                  ;; Cumulative: 30, 80, 100
                  [(dsl/jmp-imm :jlt :r0 30 4)   ; if r0 < 30, backend 0
                   (dsl/jmp-imm :jlt :r0 80 2)   ; if r0 < 80, backend 1
                   (dsl/mov :r0 2)               ; backend 2
                   (dsl/exit-insn)
                   (dsl/mov :r0 0)               ; backend 0
                   (dsl/exit-insn)
                   (dsl/mov :r0 1)               ; backend 1
                   (dsl/exit-insn)])
        bytecode (dsl/assemble program)]
    (println "Weighted backend selection (30/50/20%):")
    (println "  Total instructions:" (/ (count bytecode) 8))))

;; ============================================================================
;; Section 6: Token Bucket Rate Limiting
;; ============================================================================

(defn demo-rate-limit-helpers
  "Demonstrate token bucket rate limiting helpers.

   Comprehensive rate limiting for DDoS protection,
   API rate limiting, and traffic shaping."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 6: TOKEN BUCKET RATE LIMITING")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Implement per-key rate limiting in BPF")
  (println "         Essential for DDoS protection and traffic shaping\n")

  ;; Constants
  (println "Rate Limiting Constants:")
  (println "------------------------")
  (println "  TOKEN_SCALE:      " rate-limit/TOKEN-SCALE "(for sub-second precision)")
  (println "  NS_PER_SEC:       " rate-limit/NS-PER-SEC)
  (println "  US_PER_SEC:       " rate-limit/US-PER-SEC)
  (println "  MAX_ELAPSED_US:   " rate-limit/MAX-ELAPSED-US "(overflow protection)\n")

  (println "Data Structure Offsets:")
  (println "  Config: rate@" rate-limit/CONFIG-OFF-RATE ", burst@" rate-limit/CONFIG-OFF-BURST)
  (println "  Bucket: tokens@" rate-limit/BUCKET-OFF-TOKENS ", last_update@" rate-limit/BUCKET-OFF-LAST-UPDATE "\n")

  ;; Example 1: Simple rate limit check
  (println "Example 1: Simple Rate Limit (Hardcoded Rate)")
  (println "---------------------------------------------")
  (let [instrs (vec (rate-limit/build-simple-rate-limit
                      20      ; bucket map fd
                      -16     ; key stack offset
                      -32     ; scratch stack offset
                      100     ; 100 requests/second
                      200     ; burst of 200
                      :pass   ; label on pass
                      :drop))] ; label on rate limit
    (println "100 req/s with burst of 200:")
    (println "  (rate-limit/build-simple-rate-limit")
    (println "    bucket-fd key-off scratch-off rate burst pass-label drop-label)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 2: Configurable rate limit
  (println "Example 2: Configurable Rate Limit (Config Map)")
  (println "-----------------------------------------------")
  (let [instrs (vec (rate-limit/build-rate-limit-check
                      10      ; config map fd
                      0       ; config index
                      20      ; bucket map fd
                      -16     ; key stack offset
                      -48     ; scratch stack offset
                      :pass   ; pass label
                      :drop))] ; drop label
    (println "Rate limit with runtime-configurable rate:")
    (println "  (rate-limit/build-rate-limit-check")
    (println "    config-fd config-idx bucket-fd key-off scratch-off pass drop)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 3: Encode config for userspace
  (println "Example 3: Userspace Config Encoding")
  (println "------------------------------------")
  (let [config (rate-limit/encode-rate-limit-config 100 200)
        disabled (rate-limit/rate-disabled-config)]
    (println "Encode rate limit config for map update:")
    (println "  (rate-limit/encode-rate-limit-config 100 200)")
    (println "  Returns:" (count config) "byte array")
    (println "  Rate (scaled):" (* 100 rate-limit/TOKEN-SCALE))
    (println "  Burst (scaled):" (* 200 rate-limit/TOKEN-SCALE))
    (println "\nDisable rate limiting:")
    (println "  (rate-limit/rate-disabled-config)")
    (println "  Returns:" (count disabled) "bytes of zeros\n"))

  ;; Example 4: Complete XDP rate limiter
  (println "Example 4: Complete XDP Rate Limiter")
  (println "------------------------------------")
  (let [program (concat
                  ;; Save context
                  [(dsl/mov-reg :r6 :r1)]

                  ;; Load packet pointers
                  [(dsl/ldx :dw :r7 :r6 0)    ; data
                   (dsl/ldx :dw :r8 :r6 8)]   ; data_end

                  ;; Check bounds for IP header (34 bytes = ETH + IPv4 min)
                  (bounds/build-bounds-check-label :r7 :r8 0 34 :pass)

                  ;; Extract source IP as key (offset 26 = ETH_HLEN + 12)
                  [(dsl/ldx :w :r0 :r7 26)
                   (dsl/stx :w :r10 :r0 -16)]

                  ;; Apply rate limiting
                  (rate-limit/build-simple-rate-limit 20 -16 -32 100 200 :pass :drop)

                  ;; Pass
                  [(asm/label :pass)
                   (dsl/mov :r0 2)  ; XDP_PASS
                   (dsl/exit-insn)]

                  ;; Drop
                  [(asm/label :drop)
                   (dsl/mov :r0 1)  ; XDP_DROP
                   (dsl/exit-insn)])
        bytecode (asm/assemble-with-labels program)]
    (println "Source IP rate limiter (100 req/s, burst 200):")
    (println "  Total instructions:" (/ (count bytecode) 8))
    (println "  Bytecode size:" (count bytecode) "bytes")))

;; ============================================================================
;; Section 7: Memory Operations
;; ============================================================================

(defn demo-memory-helpers
  "Demonstrate memory operation helpers.

   Efficient memory operations for zeroing, copying,
   and initializing data structures."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 7: MEMORY OPERATIONS")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Zero memory, copy data, initialize structures")
  (println "         Generates optimized BPF instruction sequences\n")

  ;; Example 1: Zero memory
  (println "Example 1: Zero Memory Region")
  (println "-----------------------------")
  (let [instrs8 (mem/build-zero-bytes -16 8)
        instrs24 (mem/build-zero-bytes -32 24)
        instrs40 (mem/build-zero-bytes -64 40)]
    (println "Zero contiguous memory on stack:")
    (println "  (mem/build-zero-bytes -16 8)  ->" (count instrs8) "instructions (1 dword)")
    (println "  (mem/build-zero-bytes -32 24) ->" (count instrs24) "instructions (3 dwords)")
    (println "  (mem/build-zero-bytes -64 40) ->" (count instrs40) "instructions (5 dwords)")
    (println "\nUses 8-byte stores (stx dw) for efficiency\n"))

  ;; Example 2: Zero struct with alignment
  (println "Example 2: Zero Structure (Auto-aligned)")
  (println "----------------------------------------")
  (let [instrs (mem/build-zero-struct -64 41)]
    (println "Zero structure with automatic 4-byte alignment:")
    (println "  (mem/build-zero-struct -64 41)")
    (println "  Size 41 rounded to 44 bytes")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 3: Copy memory
  (println "Example 3: Memory Copy")
  (println "----------------------")
  (let [w-instrs (mem/build-memcpy-stack -32 -64 16)
        dw-instrs (mem/build-memcpy-stack-dw -32 -64 16)]
    (println "Copy 16 bytes between stack locations:")
    (println "  Word-based (4 bytes at a time):")
    (println "    (mem/build-memcpy-stack -32 -64 16) ->" (count w-instrs) "instructions")
    (println "  DWord-based (8 bytes at a time):")
    (println "    (mem/build-memcpy-stack-dw -32 -64 16) ->" (count dw-instrs) "instructions")
    (println "  DWord version is" (int (* 100 (- 1 (/ (count dw-instrs) (count w-instrs))))) "% more efficient\n"))

  ;; Example 4: Memory set
  (println "Example 4: Memory Set")
  (println "---------------------")
  (let [instrs (mem/build-memset -16 0x55 16)]
    (println "Fill memory with byte value:")
    (println "  (mem/build-memset -16 0x55 16)")
    (println "  Fills 16 bytes with 0x55")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 5: Store immediate values
  (println "Example 5: Store Immediate Values")
  (println "---------------------------------")
  (let [w-instrs (mem/build-store-immediate-w -16 0x12345678)
        dw-instrs (mem/build-store-immediate-dw -24 0x12345678)]
    (println "Store immediate value to stack:")
    (println "  32-bit: (mem/build-store-immediate-w -16 0x12345678)")
    (println "         " (count w-instrs) "instructions")
    (println "  64-bit: (mem/build-store-immediate-dw -24 value)")
    (println "         " (count dw-instrs) "instructions\n"))

  ;; Example 6: Initialize structure with fields
  (println "Example 6: Initialize Structure with Fields")
  (println "-------------------------------------------")
  (let [instrs (mem/build-init-struct -64 24 {0 1 8 0x12345678})]
    (println "Zero structure then set specific fields:")
    (println "  (mem/build-init-struct -64 24 {0 1, 8 0x12345678})")
    (println "  Zeros 24 bytes, then sets field@0=1, field@8=0x12345678")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 7: Struct field access
  (println "Example 7: Structure Field Access")
  (println "---------------------------------")
  (let [load-w (mem/build-load-struct-field-w :r6 8 :r0)
        load-dw (mem/build-load-struct-field-dw :r6 16 :r0)
        store-w (mem/build-store-struct-field-w :r6 8 :r0)
        store-dw (mem/build-store-struct-field-dw :r6 16 :r0)]
    (println "Load/store fields from structure pointer:")
    (println "  (mem/build-load-struct-field-w :r6 8 :r0)  ->" (count load-w) "instruction")
    (println "  (mem/build-load-struct-field-dw :r6 16 :r0) ->" (count load-dw) "instruction")
    (println "  (mem/build-store-struct-field-w :r6 8 :r0) ->" (count store-w) "instruction")
    (println "  (mem/build-store-struct-field-dw :r6 16 :r0) ->" (count store-dw) "instruction")))

;; ============================================================================
;; Section 8: BPF Map Helpers
;; ============================================================================

(defn demo-map-helpers
  "Demonstrate BPF map operation helpers.

   Helpers for map lookups, updates, and deletions
   within BPF programs."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Section 8: BPF MAP HELPERS")
  (println (apply str (repeat 70 "=")) "\n")

  (println "Purpose: Perform map operations from within BPF programs")
  (println "         Lookup, update, and delete map entries\n")

  ;; Constants
  (println "Map Update Flags:")
  (println "-----------------")
  (println "  BPF_ANY:     " maps/BPF-ANY "(create or update)")
  (println "  BPF_NOEXIST: " maps/BPF-NOEXIST "(create only)")
  (println "  BPF_EXIST:   " maps/BPF-EXIST "(update only)\n")

  ;; Example 1: Map lookup
  (println "Example 1: Map Lookup")
  (println "---------------------")
  (let [instrs (maps/build-map-lookup 10 -16)]
    (println "Lookup key at stack[-16] in map fd=10:")
    (println "  (maps/build-map-lookup map-fd key-stack-off)")
    (println "  (maps/build-map-lookup 10 -16)")
    (println "  Generated" (count instrs) "instructions")
    (println "  Returns: pointer to value in r0, or NULL\n"))

  ;; Example 2: Map update
  (println "Example 2: Map Update")
  (println "---------------------")
  (let [instrs (maps/build-map-update 10 -16 -32 maps/BPF-ANY)]
    (println "Update/insert entry:")
    (println "  (maps/build-map-update map-fd key-off value-off flags)")
    (println "  (maps/build-map-update 10 -16 -32 BPF-ANY)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 3: Map delete
  (println "Example 3: Map Delete")
  (println "---------------------")
  (let [instrs (maps/build-map-delete 10 -16)]
    (println "Delete entry by key:")
    (println "  (maps/build-map-delete map-fd key-stack-off)")
    (println "  (maps/build-map-delete 10 -16)")
    (println "  Generated" (count instrs) "instructions\n"))

  ;; Example 4: Lookup and update pattern
  (println "Example 4: Lookup-or-Create Pattern")
  (println "-----------------------------------")
  (let [program (concat
                  ;; Store key on stack
                  [(dsl/mov :r0 0x0A000001)  ; 10.0.0.1
                   (dsl/stx :w :r10 :r0 -16)]

                  ;; Initialize value
                  [(dsl/mov :r0 1)
                   (dsl/stx :dw :r10 :r0 -32)]

                  ;; Try to create new entry (NOEXIST)
                  (maps/build-map-update 10 -16 -32 maps/BPF-NOEXIST)

                  ;; Check result
                  [(asm/jmp-imm :jne :r0 0 :exists)]

                  ;; Entry created, continue
                  [(asm/jmp :done)]

                  ;; Entry exists, lookup and increment
                  [(asm/label :exists)]
                  (maps/build-map-lookup 10 -16)
                  [(asm/jmp-imm :jeq :r0 0 :done)]

                  ;; Increment counter
                  [(dsl/ldx :dw :r1 :r0 0)
                   (dsl/add :r1 1)
                   (dsl/stx :dw :r0 :r1 0)]

                  [(asm/label :done)
                   (dsl/mov :r0 0)
                   (dsl/exit-insn)])
        bytecode (asm/assemble-with-labels program)]
    (println "Lookup-or-create with atomic counter:")
    (println "  Total instructions:" (/ (count bytecode) 8))
    (println "  Bytecode size:" (count bytecode) "bytes")))

;; ============================================================================
;; Integration Example: Complete XDP Firewall
;; ============================================================================

(defn demo-complete-xdp-firewall
  "Demonstrate a complete XDP firewall combining multiple helpers.

   This example shows how all the helpers work together in a
   production-ready packet processing program."
  []
  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "INTEGRATION: COMPLETE XDP FIREWALL")
  (println (apply str (repeat 70 "=")) "\n")

  (println "This example combines:")
  (println "  - Bounds checking (verify packet access)")
  (println "  - IPv6 address loading (unified addressing)")
  (println "  - Map operations (blocklist lookup)")
  (println "  - Rate limiting (DDoS protection)")
  (println "  - Ring buffer (event logging)")
  (println "  - Memory operations (key initialization)")
  (println "  - Time helpers (connection tracking)\n")

  (let [program (concat
                  ;; ========================================
                  ;; Setup
                  ;; ========================================
                  [(dsl/mov-reg :r6 :r1)]          ; Save xdp_md
                  [(dsl/ldx :dw :r7 :r6 0)]        ; data
                  [(dsl/ldx :dw :r8 :r6 8)]        ; data_end

                  ;; ========================================
                  ;; Bounds Check: Ethernet + IPv4 minimum (34 bytes)
                  ;; ========================================
                  (bounds/build-bounds-check-label :r7 :r8 0 34 :pass)

                  ;; ========================================
                  ;; Check EtherType (offset 12)
                  ;; ========================================
                  [(dsl/ldx :h :r0 :r7 12)]        ; Load ethertype
                  [(asm/jmp-imm :jne :r0 0x0008 :pass)]  ; Skip if not IPv4 (big-endian)

                  ;; ========================================
                  ;; Initialize 16-byte key (zero first)
                  ;; ========================================
                  (mem/build-zero-bytes -32 16)

                  ;; ========================================
                  ;; Load source IP as unified address
                  ;; ========================================
                  (ipv6/build-load-ipv4-unified :r7 26 -32)

                  ;; ========================================
                  ;; Check blocklist map (fd=10)
                  ;; ========================================
                  (maps/build-map-lookup 10 -32)
                  [(asm/jmp-imm :jne :r0 0 :blocked)]

                  ;; ========================================
                  ;; Rate limiting (fd=20)
                  ;; ========================================
                  (rate-limit/build-simple-rate-limit 20 -32 -64 1000 2000 :pass :rate_limited)

                  ;; ========================================
                  ;; Pass path
                  ;; ========================================
                  [(asm/label :pass)
                   (dsl/mov :r0 2)                 ; XDP_PASS
                   (dsl/exit-insn)]

                  ;; ========================================
                  ;; Blocked path - log event
                  ;; ========================================
                  [(asm/label :blocked)]

                  ;; Reserve ring buffer space (fd=30, 32 bytes)
                  (ringbuf/build-ringbuf-reserve 30 32 0)
                  [(asm/jmp-imm :jeq :r0 0 :drop)]
                  [(dsl/mov-reg :r9 :r0)]          ; Save pointer

                  ;; Store event type (blocked = 1)
                  [(dsl/mov :r0 1)
                   (dsl/stx :w :r9 :r0 0)]

                  ;; Store timestamp
                  (time/build-ktime-get-ns)
                  [(dsl/stx :dw :r9 :r0 8)]

                  ;; Copy source IP to event
                  (mem/build-memcpy-stack -32 -96 16)  ; temp copy

                  ;; Submit event
                  (ringbuf/build-ringbuf-submit :r9 0)

                  [(asm/jmp :drop)]

                  ;; ========================================
                  ;; Rate limited path
                  ;; ========================================
                  [(asm/label :rate_limited)]

                  ;; Could also log rate limit events...

                  ;; ========================================
                  ;; Drop path
                  ;; ========================================
                  [(asm/label :drop)
                   (dsl/mov :r0 1)                 ; XDP_DROP
                   (dsl/exit-insn)])

        bytecode (asm/assemble-with-labels program)]

    (println "Complete XDP Firewall Program:")
    (println "  Total instructions:" (/ (count bytecode) 8))
    (println "  Bytecode size:" (count bytecode) "bytes")
    (println "\nFeatures:")
    (println "  - IPv4 packet parsing with bounds checking")
    (println "  - Unified IPv4/IPv6 address format for map keys")
    (println "  - Blocklist checking via BPF hash map")
    (println "  - Per-IP rate limiting (1000 req/s, burst 2000)")
    (println "  - Event logging via ring buffer")
    (println "  - Proper memory initialization")))

;; ============================================================================
;; Main Entry Point
;; ============================================================================

(defn -main
  "Run all helper demonstrations."
  [& args]
  (println "\n")
  (println (apply str (repeat 70 "#")))
  (println "#" (apply str (repeat 66 " ")) "#")
  (println "#    CLJ-EBPF HELPER FUNCTIONS TUTORIAL                              #")
  (println "#" (apply str (repeat 66 " ")) "#")
  (println (apply str (repeat 70 "#")))

  ;; Run all demos
  (demo-bounds-checking)
  (demo-checksum-helpers)
  (demo-ringbuf-helpers)
  (demo-ipv6-helpers)
  (demo-time-helpers)
  (demo-rate-limit-helpers)
  (demo-memory-helpers)
  (demo-map-helpers)
  (demo-complete-xdp-firewall)

  (println "\n" (apply str (repeat 70 "=")) "\n")
  (println "Tutorial Complete!")
  (println "\nFor more information:")
  (println "  - See docs/guides/helpers-guide.md")
  (println "  - Run individual examples in the examples/ directory")
  (println "  - Check test files for comprehensive API coverage")
  (println (apply str (repeat 70 "=")) "\n"))
